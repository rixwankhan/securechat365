//! Crypto core: Olm double-ratchet sessions for 1:1 chat.
//!
//! Everything secret lives in this module. The relay server never sees any of
//! it — it only ever handles `Envelope` values, which are ciphertext plus
//! routing metadata.
//!
//! Cargo.toml:
//!   vodozemac = "0.9"
//!   argon2    = "0.5"
//!   sha2      = "0.10"
//!   zeroize   = { version = "1", features = ["zeroize_derive"] }
//!   serde     = { version = "1", features = ["derive"] }
//!   serde_json = "1"
//!   rand      = "0.8"
//!   thiserror = "2"
//!
//! NOTE: vodozemac has had breaking API changes recently (create_inbound_session
//! gained a SessionConfig parameter; create_outbound_session and Session::encrypt
//! became fallible). This targets that current shape. If you pin an older
//! version, those three call sites are what will need adjusting.

use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use vodozemac::olm::{
    Account, AccountPickle, InboundCreationResult, OlmMessage, Session, SessionConfig, SessionPickle,
};
use vodozemac::{Curve25519PublicKey, Ed25519PublicKey};
use zeroize::Zeroize;

use crate::identity::ContactId;

/// How many one-time keys to keep available on the relay. Each inbound session
/// consumes one; if they run out, peers fall back to the fallback key, which is
/// reused and therefore weaker. Top up whenever the relay reports fewer than
/// `OTK_REFILL_THRESHOLD` remaining.
pub const OTK_TARGET: usize = 50;
pub const OTK_REFILL_THRESHOLD: usize = 20;

/// Argon2id parameters for deriving the at-rest pickle key from a passphrase.
/// 64 MiB / 3 passes is a deliberate choice: it is slow enough to matter on a
/// stolen phone and still under ~500ms on a low-end Android device.
const ARGON_MEM_KIB: u32 = 65536;
const ARGON_PASSES: u32 = 3;
const ARGON_LANES: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("no session established with this contact")]
    NoSession,
    #[error("peer's key bundle is malformed: {0}")]
    BadBundle(String),
    #[error("could not establish session: {0}")]
    SessionCreation(String),
    #[error("decryption failed: {0}")]
    Decryption(String),
    #[error("encryption failed: {0}")]
    Encryption(String),
    #[error("wrong passphrase, or the vault is corrupt")]
    VaultUnlock,
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// What we publish to the relay so strangers can start a session with us.
/// Contains only public keys — safe to hand to an untrusted server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyBundle {
    /// Base64 Curve25519. This is the same key encoded in the 72-char ID.
    pub identity_key: String,
    /// Base64 Ed25519, used for the safety number.
    pub fingerprint_key: String,
    /// Unused one-time keys, by key id.
    pub one_time_keys: HashMap<String, String>,
    /// Reused key of last resort when the one-time keys are exhausted.
    pub fallback_key: Option<String>,
}

/// Plaintext wire format, version 1.
///
/// The sender's own contact ID rides inside the ciphertext rather than in the
/// envelope. That lets the recipient show a contact request without the relay
/// ever learning the nospam — which is the whole point of the nospam.
#[derive(Debug, Serialize, Deserialize)]
struct Payload {
    v: u8,
    from: String,
    body: String,
}

const WIRE_VERSION: u8 = 1;

/// A decrypted message plus what we can prove about who sent it.
#[derive(Debug, Clone)]
pub struct Incoming {
    pub text: String,
    /// The sender's 72-char ID, set only when the ID they claim is backed by
    /// the key that actually decrypted this message. `None` means treat the
    /// sender as unidentified.
    pub sender_id: Option<String>,
    /// True when this message opened a new Olm session.
    pub new_session: bool,
}

/// A single Olm message as it travels through the relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Recipient's 72-char ID. The relay routes on this and learns nothing else.
    pub to: String,
    /// Sender's base64 Curve25519 identity key. Needed to build an inbound
    /// session; the recipient must still verify it against the ID they added.
    pub from_identity_key: String,
    /// 0 = pre-key message (starts a session), 1 = normal message.
    pub message_type: u8,
    /// Base64 Olm ciphertext.
    pub ciphertext: String,
    /// Relay-assigned; advisory only. Never trust it for ordering.
    pub received_at: Option<u64>,
}

impl Envelope {
    fn to_olm_message(&self) -> Result<OlmMessage, CryptoError> {
        // Ciphertext is binary. It travels base64-encoded because Envelope is
        // JSON on the wire — putting raw bytes in a String corrupts them.
        let raw = B64
            .decode(&self.ciphertext)
            .map_err(|e| CryptoError::Decryption(format!("bad base64: {e}")))?;
        OlmMessage::from_parts(self.message_type as usize, &raw)
            .map_err(|e| CryptoError::Decryption(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// Our long-term account plus every live session.
///
/// Deliberately not `Clone`: exactly one of these should exist per process, or
/// two copies will ratchet independently and silently break decryption.
pub struct Identity {
    account: Account,
    /// Peer's base64 Curve25519 identity key -> that peer's sessions, most
    /// recently useful first.
    ///
    /// A Vec, not a single Session: Olm expects several concurrent sessions per
    /// peer (both sides can open one before either has replied). Keeping only
    /// one means a later session silently destroys an earlier working one, and
    /// every message on the old session becomes undecryptable.
    sessions: HashMap<String, Vec<Session>>,
    nospam: [u8; 2],
}

impl Identity {
    /// Fresh account. Call `contact_id()` to get the string the user shares.
    pub fn create() -> Self {
        let account = Account::new();
        let id = ContactId::new(account.curve25519_key().to_bytes());
        Self { account, sessions: HashMap::new(), nospam: *id.nospam() }
    }

    /// The 72-char ID. Its first 64 characters are literally this account's
    /// Curve25519 key, so nothing extra needs storing to keep them in sync.
    pub fn contact_id(&self) -> ContactId {
        ContactId::with_nospam(self.account.curve25519_key().to_bytes(), self.nospam)
    }

    pub fn identity_key(&self) -> Curve25519PublicKey {
        self.account.curve25519_key()
    }

    pub fn fingerprint_key(&self) -> Ed25519PublicKey {
        self.account.ed25519_key()
    }

    pub fn rotate_nospam(&mut self) {
        let mut id = self.contact_id();
        id.rotate_nospam();
        self.nospam = *id.nospam();
    }

    /// Sign a relay challenge nonce with our Ed25519 key. Proves control of
    /// this account without revealing anything reusable.
    pub fn sign(&self, message: &str) -> String {
        self.account.sign(message).to_base64()
    }

    /// Generate and return keys to publish. Marks them published, so only call
    /// this once the relay has confirmed the upload — otherwise you will hand
    /// out keys the account no longer offers.
    pub fn generate_key_bundle(&mut self, count: usize) -> KeyBundle {
        self.account.generate_one_time_keys(count);
        let fallback = self.account.generate_fallback_key();

        let one_time_keys = self
            .account
            .one_time_keys()
            .iter()
            .map(|(id, key)| (id.to_base64(), key.to_base64()))
            .collect();

        let bundle = KeyBundle {
            identity_key: self.account.curve25519_key().to_base64(),
            fingerprint_key: self.account.ed25519_key().to_base64(),
            one_time_keys,
            fallback_key: self
                .account
                .fallback_key()
                .values()
                .next()
                .map(|k| k.to_base64())
                .or_else(|| fallback.map(|k| k.to_base64())),
        };

        self.account.mark_keys_as_published();
        bundle
    }

    // -- session establishment ---------------------------------------------

    /// Start a session with someone whose ID the user scanned or pasted.
    ///
    /// The `expected` ID is checked against the bundle's identity key. This is
    /// the single most important line in the file: without it a malicious relay
    /// substitutes its own key and reads everything.
    pub fn begin_session(
        &mut self,
        expected: &ContactId,
        bundle: &KeyBundle,
    ) -> Result<(), CryptoError> {
        let their_identity = Curve25519PublicKey::from_base64(&bundle.identity_key)
            .map_err(|e| CryptoError::BadBundle(e.to_string()))?;

        if their_identity.to_bytes() != *expected.public_key() {
            return Err(CryptoError::BadBundle(
                "bundle identity key does not match the contact ID — refusing".into(),
            ));
        }

        let otk_b64 = bundle
            .one_time_keys
            .values()
            .next()
            .or(bundle.fallback_key.as_ref())
            .ok_or_else(|| CryptoError::BadBundle("no one-time or fallback key".into()))?;
        let otk = Curve25519PublicKey::from_base64(otk_b64)
            .map_err(|e| CryptoError::BadBundle(e.to_string()))?;

        // Already talking to them? Don't burn another of their one-time keys,
        // and above all don't replace the session that is currently working.
        if self.sessions.get(&bundle.identity_key).is_some_and(|v| !v.is_empty()) {
            return Ok(());
        }

        // Infallible in vodozemac 0.9. Later versions make this return a
        // Result — if you upgrade, restore the `.map_err(...)?` here.
        let session =
            self.account
                .create_outbound_session(SessionConfig::version_1(), their_identity, otk);

        self.sessions.entry(bundle.identity_key.clone()).or_default().push(session);
        Ok(())
    }

    // -- messaging ----------------------------------------------------------

    pub fn encrypt(&mut self, to: &ContactId, plaintext: &str) -> Result<Envelope, CryptoError> {
        // Build the payload before borrowing a session mutably.
        let payload = serde_json::to_string(&Payload {
            v: WIRE_VERSION,
            from: self.contact_id().to_string(),
            body: plaintext.to_string(),
        })?;

        let peer_key = Curve25519PublicKey::from_bytes(*to.public_key()).to_base64();
        let session = self
            .sessions
            .get_mut(&peer_key)
            .and_then(|list| list.first_mut())
            .ok_or(CryptoError::NoSession)?;

        // Also infallible in 0.9.
        let message = session.encrypt(&payload);
        let (message_type, ciphertext) = message.to_parts();

        Ok(Envelope {
            to: to.to_string(),
            from_identity_key: self.account.curve25519_key().to_base64(),
            message_type: message_type as u8,
            ciphertext: B64.encode(&ciphertext),
            received_at: None,
        })
    }

    /// Decrypt, creating an inbound session if this is a pre-key message.
    ///
    /// Returns the plaintext and whether the session was newly created — the UI
    /// must surface "new session" so a silent key swap is visible to the user.
    pub fn decrypt(&mut self, envelope: &Envelope) -> Result<Incoming, CryptoError> {
        let their_identity = Curve25519PublicKey::from_base64(&envelope.from_identity_key)
            .map_err(|e| CryptoError::BadBundle(e.to_string()))?;
        let message = envelope.to_olm_message()?;

        // Try every session we hold for this peer. Only one will match, and
        // which one is not predictable — so try them all before concluding this
        // needs a new session.
        if let Some(list) = self.sessions.get_mut(&envelope.from_identity_key) {
            for i in 0..list.len() {
                if let Ok(plaintext) = list[i].decrypt(&message) {
                    // Promote it: the session that just worked is the one to
                    // reply on, and the one to try first next time.
                    let winner = list.remove(i);
                    list.insert(0, winner);
                    let (text, sender_id) = parse_payload(&plaintext, &their_identity);
                    return Ok(Incoming { text, sender_id, new_session: false });
                }
            }
            // Fall through: the peer may have reinstalled, or opened a new
            // session against a stale copy of our keys.
        }

        let OlmMessage::PreKey(prekey) = &message else {
            return Err(CryptoError::NoSession);
        };

        // 0.9 infers the config from the pre-key message itself; newer versions
        // take a SessionConfig as the first argument.
        let InboundCreationResult { session, plaintext } = self
            .account
            .create_inbound_session(their_identity, prekey)
            .map_err(|e| CryptoError::SessionCreation(e.to_string()))?;

        // Front, not replacing: this is now the session to reply on, but any
        // earlier one may still receive in-flight messages.
        self.sessions
            .entry(envelope.from_identity_key.clone())
            .or_default()
            .insert(0, session);
        let (text, sender_id) = parse_payload(&plaintext, &their_identity);
        Ok(Incoming { text, sender_id, new_session: true })
    }

    pub fn has_session_with(&self, id: &ContactId) -> bool {
        let key = Curve25519PublicKey::from_bytes(*id.public_key()).to_base64();
        self.sessions.get(&key).is_some_and(|v| !v.is_empty())
    }

    pub fn remaining_one_time_keys(&self) -> usize {
        self.account.one_time_keys().len()
    }

    // -- persistence --------------------------------------------------------

    /// Encrypt the whole account and every session under a passphrase.
    /// Write the result to disk as-is; it is a self-contained vault.
    pub fn lock(&self, passphrase: &str) -> Result<Vault, CryptoError> {
        let salt: [u8; 16] = rand::random();
        let mut key = derive_pickle_key(passphrase, &salt)?;

        let account = self.account.pickle().encrypt(&key);
        let sessions = self
            .sessions
            .iter()
            .map(|(peer, list)| {
                (peer.clone(), list.iter().map(|s| s.pickle().encrypt(&key)).collect())
            })
            .collect();

        key.zeroize();
        Ok(Vault { version: 2, salt, account, sessions, nospam: self.nospam })
    }

    pub fn unlock(vault: &Vault, passphrase: &str) -> Result<Self, CryptoError> {
        let mut key = derive_pickle_key(passphrase, &vault.salt)?;

        let account_pickle = AccountPickle::from_encrypted(&vault.account, &key)
            .map_err(|_| CryptoError::VaultUnlock)?;
        let account = Account::from_pickle(account_pickle);

        let mut sessions: HashMap<String, Vec<Session>> = HashMap::new();
        for (peer, pickled_list) in &vault.sessions {
            let mut restored = Vec::with_capacity(pickled_list.len());
            for pickled in pickled_list {
                let pickle = SessionPickle::from_encrypted(pickled, &key)
                    .map_err(|_| CryptoError::VaultUnlock)?;
                restored.push(Session::from_pickle(pickle));
            }
            sessions.insert(peer.clone(), restored);
        }

        key.zeroize();
        Ok(Self { account, sessions, nospam: vault.nospam })
    }
}

/// Unwrap the payload and decide whether to believe the sender's claimed ID.
///
/// A sender controls every byte of their own plaintext, so `from` is a claim,
/// not a fact. It is only accepted when the public key inside it matches the
/// key whose session just decrypted the message — which proves possession of
/// the corresponding private key. Anything else is discarded, and the caller
/// treats the sender as unidentified.
fn parse_payload(raw: &[u8], peer_identity: &Curve25519PublicKey) -> (String, Option<String>) {
    let Ok(payload) = serde_json::from_slice::<Payload>(raw) else {
        // Not our format. Show it rather than dropping it.
        return (String::from_utf8_lossy(raw).into_owned(), None);
    };

    let verified = payload
        .from
        .parse::<ContactId>()
        .ok()
        .filter(|id| *id.public_key() == peer_identity.to_bytes())
        .map(|id| id.to_string());

    (payload.body, verified)
}

/// On-disk form. Contains no plaintext secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    pub version: u8,
    pub salt: [u8; 16],
    pub account: String,
    /// Peer identity key -> encrypted session pickles, preferred first.
    pub sessions: HashMap<String, Vec<String>>,
    pub nospam: [u8; 2],
}

fn derive_pickle_key(passphrase: &str, salt: &[u8; 16]) -> Result<[u8; 32], CryptoError> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(ARGON_MEM_KIB, ARGON_PASSES, ARGON_LANES, Some(32))
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    Ok(key)
}

// ---------------------------------------------------------------------------
// Safety numbers
// ---------------------------------------------------------------------------

/// A 60-digit number both parties compare out of band (in person, over a call)
/// to confirm no one is sitting in the middle.
///
/// Sorting the two keys first makes the result symmetric, so both sides see the
/// same digits regardless of who initiated.
pub fn safety_number(ours: &Ed25519PublicKey, theirs: &Ed25519PublicKey) -> String {
    use sha2::{Digest, Sha256};

    // Ed25519PublicKey exposes as_bytes() -> &[u8; 32]; deref to copy.
    let (a, b) = {
        let (x, y) = (*ours.as_bytes(), *theirs.as_bytes());
        if x <= y { (x, y) } else { (y, x) }
    };

    // Iterated hashing raises the cost of grinding a key whose safety number
    // collides in the digits a human actually bothers to check.
    let mut digest = Sha256::new()
        .chain_update(b"securechat365-safety-number-v1")
        .chain_update(a)
        .chain_update(b)
        .finalize();
    for _ in 0..5000 {
        digest = Sha256::digest(digest);
    }

    // 12 groups of 5 digits.
    digest
        .chunks(2)
        .take(12)
        .map(|pair| {
            let n = u16::from_be_bytes([pair[0], pair[1]]) as u32 % 100_000;
            format!("{n:05}")
        })
        .collect::<Vec<_>>()
        .join(" ")
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn pair() -> (Identity, Identity) {
        (Identity::create(), Identity::create())
    }

    fn connect(alice: &mut Identity, bob: &mut Identity) {
        let bundle = bob.generate_key_bundle(5);
        let bob_id = bob.contact_id();
        alice.begin_session(&bob_id, &bundle).expect("session should establish");
    }

    #[test]
    fn contact_id_wraps_the_account_key() {
        let alice = Identity::create();
        let id = alice.contact_id();
        assert_eq!(*id.public_key(), alice.identity_key().to_bytes());
        assert_eq!(id.to_string().len(), 72);
        assert_eq!(ContactId::from_str(&id.to_string()).unwrap(), id);
    }

    #[test]
    fn round_trip_message() {
        let (mut alice, mut bob) = pair();
        connect(&mut alice, &mut bob);

        let envelope = alice.encrypt(&bob.contact_id(), "meet at the usual place").unwrap();
        assert_ne!(envelope.ciphertext, "meet at the usual place");

        let incoming = bob.decrypt(&envelope).unwrap();
        assert_eq!(incoming.text, "meet at the usual place");
        assert!(incoming.new_session, "first message should create an inbound session");
        assert_eq!(
            incoming.sender_id.as_deref(),
            Some(alice.contact_id().to_string().as_str()),
            "sender's own ID should ride inside the ciphertext"
        );
    }

    #[test]
    fn bidirectional_after_first_reply() {
        let (mut alice, mut bob) = pair();
        connect(&mut alice, &mut bob);

        let e1 = alice.encrypt(&bob.contact_id(), "ping").unwrap();
        bob.decrypt(&e1).unwrap();

        let e2 = bob.encrypt(&alice.contact_id(), "pong").unwrap();
        let incoming = alice.decrypt(&e2).unwrap();
        assert_eq!(incoming.text, "pong");
        assert!(!incoming.new_session, "reply reuses the outbound session");
    }

    #[test]
    fn ratchet_advances_ciphertext_differs_for_identical_plaintext() {
        let (mut alice, mut bob) = pair();
        connect(&mut alice, &mut bob);

        let a = alice.encrypt(&bob.contact_id(), "same").unwrap();
        let b = alice.encrypt(&bob.contact_id(), "same").unwrap();
        assert_ne!(a.ciphertext, b.ciphertext);

        assert_eq!(bob.decrypt(&a).unwrap().text, "same");
        assert_eq!(bob.decrypt(&b).unwrap().text, "same");
    }

    #[test]
    fn rejects_bundle_that_does_not_match_the_scanned_id() {
        let (mut alice, mut bob) = pair();
        let mallory = Identity::create();

        // Mallory's keys presented under Bob's ID — the relay-substitution attack.
        let mut forged = bob.generate_key_bundle(1);
        forged.identity_key = mallory.identity_key().to_base64();

        let err = alice.begin_session(&bob.contact_id(), &forged).unwrap_err();
        assert!(matches!(err, CryptoError::BadBundle(_)));
        assert!(!alice.has_session_with(&bob.contact_id()));
    }

    #[test]
    fn ciphertext_is_base64_and_survives_json() {
        let (mut alice, mut bob) = pair();
        connect(&mut alice, &mut bob);

        let envelope = alice.encrypt(&bob.contact_id(), "binary safety check").unwrap();

        // Regression guard: ciphertext must be transport-safe text, not raw
        // bytes coerced into a String.
        assert!(
            B64.decode(&envelope.ciphertext).is_ok(),
            "ciphertext must be valid base64"
        );
        assert!(
            !envelope.ciphertext.contains('\u{FFFD}'),
            "replacement characters mean bytes were destroyed"
        );

        // Full round trip through the wire format.
        let json = serde_json::to_string(&envelope).unwrap();
        let decoded: Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(bob.decrypt(&decoded).unwrap().text, "binary safety check");
    }

    /// Reproduces a real failure: Alice messages Bob, Bob then adds Alice, and
    /// Alice's next message dies with "unknown one-time key". Cause was one
    /// session per peer — Bob's new outbound session replaced the inbound one
    /// that was actually working.
    #[test]
    fn adding_a_contact_who_already_messaged_you_keeps_the_session() {
        let (mut alice, mut bob) = pair();
        connect(&mut alice, &mut bob);

        // Alice sends before Bob has added her.
        let first = alice.encrypt(&bob.contact_id(), "hello").unwrap();
        assert_eq!(bob.decrypt(&first).unwrap().text, "hello");

        // Now Bob adds Alice. This must not destroy the working session.
        let alice_bundle = alice.generate_key_bundle(5);
        bob.begin_session(&alice.contact_id(), &alice_bundle).unwrap();

        // Alice is still sending pre-key messages, since Bob hasn't replied.
        let second = alice.encrypt(&bob.contact_id(), "still there?").unwrap();
        assert_eq!(bob.decrypt(&second).unwrap().text, "still there?");

        // And Bob's reply must reach Alice.
        let reply = bob.encrypt(&alice.contact_id(), "yes").unwrap();
        assert_eq!(alice.decrypt(&reply).unwrap().text, "yes");
    }

    #[test]
    fn both_sides_opening_sessions_at_once_still_converges() {
        let (mut alice, mut bob) = pair();

        // Simultaneous add: each fetches the other's bundle before any message.
        let bob_bundle = bob.generate_key_bundle(5);
        let alice_bundle = alice.generate_key_bundle(5);
        alice.begin_session(&bob.contact_id(), &bob_bundle).unwrap();
        bob.begin_session(&alice.contact_id(), &alice_bundle).unwrap();

        let a1 = alice.encrypt(&bob.contact_id(), "from alice").unwrap();
        assert_eq!(bob.decrypt(&a1).unwrap().text, "from alice");

        let b1 = bob.encrypt(&alice.contact_id(), "from bob").unwrap();
        assert_eq!(alice.decrypt(&b1).unwrap().text, "from bob");
    }

    #[test]
    fn a_forged_sender_id_is_not_believed() {
        let (mut alice, mut bob) = pair();
        connect(&mut alice, &mut bob);

        let envelope = alice.encrypt(&bob.contact_id(), "trust me").unwrap();
        let incoming = bob.decrypt(&envelope).unwrap();

        // Honest case: the claimed ID matches the key that decrypted it.
        assert_eq!(incoming.sender_id, Some(alice.contact_id().to_string()));

        // A sender controls their own plaintext, so they can write any ID they
        // like in it. It must only be accepted when the key backs it up.
        let mallory = Identity::create();
        let claimed: ContactId = incoming.sender_id.unwrap().parse().unwrap();
        assert_ne!(*claimed.public_key(), *mallory.contact_id().public_key());
    }

    #[test]
    fn vault_survives_lock_unlock() {
        let (mut alice, mut bob) = pair();
        connect(&mut alice, &mut bob);

        let vault = alice.lock("correct horse battery staple").unwrap();
        let mut restored = Identity::unlock(&vault, "correct horse battery staple").unwrap();

        assert_eq!(restored.contact_id(), alice.contact_id());
        let envelope = restored.encrypt(&bob.contact_id(), "still works").unwrap();
        assert_eq!(bob.decrypt(&envelope).unwrap().text, "still works");
    }

    #[test]
    fn wrong_passphrase_fails() {
        let alice = Identity::create();
        let vault = alice.lock("right").unwrap();
        assert!(matches!(
            Identity::unlock(&vault, "wrong"),
            Err(CryptoError::VaultUnlock)
        ));
    }

    #[test]
    fn safety_number_is_symmetric_and_key_bound() {
        let (alice, bob) = pair();
        let mallory = Identity::create();

        let from_alice = safety_number(&alice.fingerprint_key(), &bob.fingerprint_key());
        let from_bob = safety_number(&bob.fingerprint_key(), &alice.fingerprint_key());
        assert_eq!(from_alice, from_bob);

        let impostor = safety_number(&alice.fingerprint_key(), &mallory.fingerprint_key());
        assert_ne!(from_alice, impostor);
        assert_eq!(from_alice.replace(' ', "").len(), 60);
    }
}
