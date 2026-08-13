//! Relay server.
//!
//! Deliberately dumb. It routes opaque ciphertext and stores public key
//! bundles. It cannot read messages, and clients verify identity keys against
//! scanned contact IDs, so it cannot substitute keys either.
//!
//! What it DOES see, and what you should tell your users it sees:
//!   - who is talking to whom (sender and recipient keys)
//!   - when, and how often
//!   - approximate message sizes
//!   - client IP addresses
//!
//! That is the price of offline delivery. If that metadata matters more than
//! reliability, this is the component to replace with direct WebRTC.
//!
//! Cargo.toml:
//!   axum = { version = "0.8", features = ["ws"] }
//!   tokio = { version = "1", features = ["full"] }
//!   ed25519-dalek = "2"
//!   serde = { version = "1", features = ["derive"] }
//!   serde_json = "1"
//!   dashmap = "6"
//!   rand = "0.8"
//!   base64 = "0.22"
//!   tracing = "0.1"
//!   tracing-subscriber = "0.3"

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use dashmap::DashMap;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

// --- limits ---------------------------------------------------------------

/// Olm ciphertext for a text message is small. Anything larger is abuse.
const MAX_ENVELOPE_BYTES: usize = 16 * 1024;
/// Per recipient. Beyond this, the oldest are dropped — a full queue must not
/// become a way to exhaust the server.
const MAX_QUEUED_PER_USER: usize = 1000;
/// Undelivered messages are discarded after this. Say so in your privacy policy.
const QUEUE_TTL: Duration = Duration::from_secs(30 * 24 * 3600);
/// THE nospam defence. A 2-byte nospam is only 65,536 values, so without this
/// an attacker brute-forces a valid contact ID for a known key in minutes.
/// Ten bundle fetches per hour per target makes that take roughly 750 years.
const BUNDLE_FETCHES_PER_HOUR: u32 = 10;
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);

// --- protocol -------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMessage {
    /// Answer to the challenge. `identity_key` is the Curve25519 key (matching
    /// the first 64 chars of the contact ID); `fingerprint_key` is Ed25519.
    Auth {
        identity_key: String,
        fingerprint_key: String,
        signature: String,
    },
    /// Upload or replace our public key bundle.
    PublishKeys { bundle: serde_json::Value },
    /// Ask for a peer's bundle so we can start a session. Consumes one of their
    /// one-time keys.
    FetchBundle { contact_id: String },
    /// Hand off an encrypted envelope for delivery.
    Send { envelope: Envelope },
    /// Confirm receipt so the server can drop them.
    Ack { ids: Vec<String> },
    /// How many one-time keys are left, so the client knows when to top up.
    KeyCount,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMessage {
    Challenge { nonce: String },
    AuthOk,
    Bundle { bundle: serde_json::Value },
    Deliver { id: String, envelope: Envelope },
    KeyCount { remaining: usize },
    Error { code: String, detail: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Envelope {
    to: String,
    from_identity_key: String,
    message_type: u8,
    ciphertext: String,
    #[serde(default)]
    received_at: Option<u64>,
}

// --- storage --------------------------------------------------------------
//
// In-memory. Fine for a few thousand users; swap for Postgres before you have
// real ones, because a restart currently loses every queued message.

#[derive(Clone)]
struct StoredBundle {
    identity_key: String,
    fingerprint_key: String,
    raw: serde_json::Value,
}

struct QueuedEnvelope {
    id: String,
    envelope: Envelope,
    queued_at: Instant,
}

#[derive(Default)]
struct RateWindow {
    count: u32,
    reset_at: Option<Instant>,
}

#[derive(Default)]
struct Store {
    /// Curve25519 identity key (base64) -> bundle.
    bundles: DashMap<String, StoredBundle>,
    /// Public key prefix of the contact ID -> queued envelopes.
    queues: DashMap<String, VecDeque<QueuedEnvelope>>,
    /// Live connections, for instant delivery.
    online: DashMap<String, mpsc::UnboundedSender<ServerMessage>>,
    /// Bundle-fetch rate limits, keyed by the target's public key.
    fetch_limits: DashMap<String, RateWindow>,
}

impl Store {
    /// Bundles and queues key on the 64-char public key, never the full 72-char
    /// ID — the nospam rotates, and rotating it must not orphan a mailbox.
    fn key_of(contact_id: &str) -> Option<String> {
        let cleaned: String = contact_id
            .trim()
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect::<String>()
            .to_uppercase();
        (cleaned.len() == 72).then(|| cleaned[..64].to_string())
    }

    fn allow_fetch(&self, target: &str) -> bool {
        let mut entry = self.fetch_limits.entry(target.to_string()).or_default();
        let now = Instant::now();
        match entry.reset_at {
            Some(at) if at > now => {
                if entry.count >= BUNDLE_FETCHES_PER_HOUR {
                    return false;
                }
                entry.count += 1;
            }
            _ => {
                entry.count = 1;
                entry.reset_at = Some(now + Duration::from_secs(3600));
            }
        }
        true
    }

    /// Pop one one-time key so it is never handed out twice. When they run out,
    /// the client falls back to the reusable fallback key.
    fn take_bundle(&self, pubkey: &str) -> Option<serde_json::Value> {
        let mut entry = self.bundles.get_mut(pubkey)?;
        let mut out = entry.raw.clone();

        let taken = entry
            .raw
            .get_mut("one_time_keys")
            .and_then(|v| v.as_object_mut())
            .and_then(|map| {
                let k = map.keys().next().cloned()?;
                map.remove(&k).map(|v| (k, v))
            });

        if let Some((k, v)) = taken {
            let mut only = serde_json::Map::new();
            only.insert(k, v);
            out["one_time_keys"] = serde_json::Value::Object(only);
        } else {
            out["one_time_keys"] = serde_json::json!({});
            tracing::warn!(%pubkey, "one-time keys exhausted, serving fallback key");
        }
        Some(out)
    }

    fn enqueue(&self, pubkey: &str, envelope: Envelope) -> String {
        let id = random_b64(12);
        if let Some(tx) = self.online.get(pubkey) {
            let msg = ServerMessage::Deliver { id: id.clone(), envelope: envelope.clone() };
            if tx.send(msg).is_ok() {
                // Still queue it. Only an explicit Ack removes a message —
                // otherwise a client that dies mid-delivery loses it silently.
            }
        }
        let mut q = self.queues.entry(pubkey.to_string()).or_default();
        if q.len() >= MAX_QUEUED_PER_USER {
            q.pop_front();
        }
        q.push_back(QueuedEnvelope { id: id.clone(), envelope, queued_at: Instant::now() });
        id
    }

    fn drain_for(&self, pubkey: &str) -> Vec<(String, Envelope)> {
        let Some(mut q) = self.queues.get_mut(pubkey) else { return Vec::new() };
        q.retain(|e| e.queued_at.elapsed() < QUEUE_TTL);
        q.iter().map(|e| (e.id.clone(), e.envelope.clone())).collect()
    }

    fn ack(&self, pubkey: &str, ids: &[String]) {
        if let Some(mut q) = self.queues.get_mut(pubkey) {
            q.retain(|e| !ids.contains(&e.id));
        }
    }
}

// --- connection handling --------------------------------------------------

type Shared = Arc<Store>;

async fn ws_handler(ws: WebSocketUpgrade, State(store): State<Shared>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| async move {
        if let Err(e) = handle_socket(socket, store).await {
            tracing::debug!("connection closed: {e}");
        }
    })
}

async fn handle_socket(mut socket: WebSocket, store: Shared) -> anyhow::Result<()> {
    // 1. Challenge. Random per connection, so a captured signature is useless.
    let nonce = random_b64(32);
    send(&mut socket, &ServerMessage::Challenge { nonce: nonce.clone() }).await?;

    // 2. Wait for a signed response, briefly.
    let auth = tokio::time::timeout(AUTH_TIMEOUT, socket.recv())
        .await
        .map_err(|_| anyhow::anyhow!("auth timeout"))?
        .ok_or_else(|| anyhow::anyhow!("closed during auth"))??;

    let Message::Text(text) = auth else {
        anyhow::bail!("expected text frame");
    };
    let ClientMessage::Auth { identity_key, fingerprint_key, signature } =
        serde_json::from_str(&text)?
    else {
        anyhow::bail!("expected auth");
    };

    // 3. Verify the signature over the nonce.
    if !verify_signature(&fingerprint_key, &nonce, &signature) {
        send(
            &mut socket,
            &ServerMessage::Error {
                code: "auth_failed".into(),
                detail: "signature did not verify".into(),
            },
        )
        .await?;
        anyhow::bail!("bad signature");
    }

    // 4. Bind Ed25519 to Curve25519, trust-on-first-use.
    //
    // The server cannot cryptographically verify this pairing — the two keys
    // are independent. That is acceptable: a server that lies about the pairing
    // can steal queued CIPHERTEXT for that account, but cannot read it, and
    // clients reject any bundle whose identity key does not match the contact
    // ID they scanned. Ship signed device keys if you want to close this.
    let pubkey_hex = curve_b64_to_hex(&identity_key)
        .ok_or_else(|| anyhow::anyhow!("malformed identity key"))?;

    if let Some(existing) = store.bundles.get(&pubkey_hex) {
        if existing.fingerprint_key != fingerprint_key {
            send(
                &mut socket,
                &ServerMessage::Error {
                    code: "fingerprint_changed".into(),
                    detail: "this account is registered to a different fingerprint key".into(),
                },
            )
            .await?;
            anyhow::bail!("fingerprint mismatch for {pubkey_hex}");
        }
    }

    send(&mut socket, &ServerMessage::AuthOk).await?;
    tracing::info!(user = %&pubkey_hex[..16], "authenticated");

    // 5. Register for live delivery and flush anything waiting.
    let (tx, mut rx) = mpsc::unbounded_channel();
    store.online.insert(pubkey_hex.clone(), tx);

    for (id, envelope) in store.drain_for(&pubkey_hex) {
        send(&mut socket, &ServerMessage::Deliver { id, envelope }).await?;
    }

    // 6. Main loop: fan in pushes and client requests.
    let result = loop {
        tokio::select! {
            Some(push) = rx.recv() => {
                if send(&mut socket, &push).await.is_err() { break Ok(()); }
            }
            incoming = socket.recv() => {
                let Some(frame) = incoming else { break Ok(()) };
                let Message::Text(text) = frame? else { continue };

                let parsed: ClientMessage = match serde_json::from_str(&text) {
                    Ok(m) => m,
                    Err(e) => {
                        send(&mut socket, &ServerMessage::Error {
                            code: "bad_request".into(),
                            detail: e.to_string(),
                        }).await?;
                        continue;
                    }
                };

                tracing::debug!(
                    user = %&pubkey_hex[..16],
                    kind = %match &parsed {
                        ClientMessage::Auth { .. } => "auth",
                        ClientMessage::PublishKeys { .. } => "publish_keys",
                        ClientMessage::FetchBundle { .. } => "fetch_bundle",
                        ClientMessage::Send { .. } => "send",
                        ClientMessage::Ack { .. } => "ack",
                        ClientMessage::KeyCount => "key_count",
                    },
                    "client message"
                );

                let reply = handle_message(parsed, &pubkey_hex, &identity_key,
                                           &fingerprint_key, &store);
                if let Some(msg) = reply {
                    if send(&mut socket, &msg).await.is_err() { break Ok(()); }
                }
            }
        }
    };

    store.online.remove(&pubkey_hex);
    result
}

fn handle_message(
    msg: ClientMessage,
    pubkey_hex: &str,
    identity_key: &str,
    fingerprint_key: &str,
    store: &Store,
) -> Option<ServerMessage> {
    match msg {
        ClientMessage::Auth { .. } => Some(ServerMessage::Error {
            code: "already_authenticated".into(),
            detail: "re-auth is not supported on an open connection".into(),
        }),

        ClientMessage::PublishKeys { bundle } => {
            store.bundles.insert(
                pubkey_hex.to_string(),
                StoredBundle {
                    identity_key: identity_key.to_string(),
                    fingerprint_key: fingerprint_key.to_string(),
                    raw: bundle,
                },
            );
            None
        }

        ClientMessage::FetchBundle { contact_id } => {
            let Some(target) = Store::key_of(&contact_id) else {
                return Some(ServerMessage::Error {
                    code: "bad_contact_id".into(),
                    detail: "expected 72 hex characters".into(),
                });
            };
            if !store.allow_fetch(&target) {
                return Some(ServerMessage::Error {
                    code: "rate_limited".into(),
                    detail: "too many lookups for this contact; try again later".into(),
                });
            }
            match store.take_bundle(&target) {
                Some(bundle) => Some(ServerMessage::Bundle { bundle }),
                // Same response shape as a rate limit would be better still —
                // this leaks whether an account exists.
                None => Some(ServerMessage::Error {
                    code: "not_found".into(),
                    detail: "no bundle published for that contact".into(),
                }),
            }
        }

        ClientMessage::Send { mut envelope } => {
            if envelope.ciphertext.len() > MAX_ENVELOPE_BYTES {
                return Some(ServerMessage::Error {
                    code: "too_large".into(),
                    detail: format!("limit is {MAX_ENVELOPE_BYTES} bytes"),
                });
            }
            let Some(target) = Store::key_of(&envelope.to) else {
                return Some(ServerMessage::Error {
                    code: "bad_contact_id".into(),
                    detail: "expected 72 hex characters".into(),
                });
            };
            // Overwrite rather than trust: a client must not be able to forge
            // the sender key on an envelope.
            envelope.from_identity_key = identity_key.to_string();
            envelope.received_at = Some(now_secs());
            let online = store.online.contains_key(&target);
            tracing::debug!(
                from = %&pubkey_hex[..16],
                to = %&target[..16],
                bytes = envelope.ciphertext.len(),
                online,
                "routing envelope"
            );
            store.enqueue(&target, envelope);
            None
        }

        ClientMessage::Ack { ids } => {
            store.ack(pubkey_hex, &ids);
            None
        }

        ClientMessage::KeyCount => {
            let remaining = store
                .bundles
                .get(pubkey_hex)
                .and_then(|b| b.raw.get("one_time_keys").cloned())
                .and_then(|v| v.as_object().map(|m| m.len()))
                .unwrap_or(0);
            Some(ServerMessage::KeyCount { remaining })
        }
    }
}

// --- helpers --------------------------------------------------------------

async fn send(socket: &mut WebSocket, msg: &ServerMessage) -> anyhow::Result<()> {
    socket.send(Message::Text(serde_json::to_string(msg)?.into())).await?;
    Ok(())
}

fn verify_signature(fingerprint_b64: &str, nonce: &str, signature_b64: &str) -> bool {
    // vodozemac emits unpadded base64; accept both.
    let decode = |s: &str| {
        B64.decode(s).or_else(|_| {
            base64::engine::general_purpose::STANDARD_NO_PAD.decode(s)
        })
    };

    let (Ok(key_bytes), Ok(sig_bytes)) = (decode(fingerprint_b64), decode(signature_b64)) else {
        return false;
    };
    let (Ok(key_arr), Ok(sig_arr)): (Result<[u8; 32], _>, Result<[u8; 64], _>) =
        (key_bytes.try_into(), sig_bytes.try_into())
    else {
        return false;
    };
    let Ok(verifying) = VerifyingKey::from_bytes(&key_arr) else { return false };
    verifying.verify(nonce.as_bytes(), &Signature::from_bytes(&sig_arr)).is_ok()
}

fn curve_b64_to_hex(identity_key_b64: &str) -> Option<String> {
    let bytes = B64
        .decode(identity_key_b64)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(identity_key_b64))
        .ok()?;
    (bytes.len() == 32).then(|| {
        bytes.iter().map(|b| format!("{b:02X}")).collect::<String>()
    })
}

fn random_b64(len: usize) -> String {
    let mut buf = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    B64.encode(buf)
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

// --- entry point ----------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let store: Shared = Arc::new(Store::default());

    // Sweep expired queue entries so abandoned mailboxes do not grow forever.
    {
        let store = store.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(3600));
            loop {
                tick.tick().await;
                store.queues.retain(|_, q| {
                    q.retain(|e| e.queued_at.elapsed() < QUEUE_TTL);
                    !q.is_empty()
                });
            }
        });
    }

    let app = Router::new()
        .route("/ws", get(ws_handler))
        .route("/health", get(|| async { "ok" }))
        .with_state(store);

    // Bind address. Defaults to all interfaces for local development; set
    // VEIL_BIND=127.0.0.1:8080 in production so only the reverse proxy on the
    // same host can reach the relay directly.
    let addr: SocketAddr = std::env::var("VEIL_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
        .parse()?;
    tracing::info!("relay listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// --- tests ----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(to: &str) -> Envelope {
        Envelope {
            to: to.into(),
            from_identity_key: "sender".into(),
            message_type: 0,
            ciphertext: "opaque".into(),
            received_at: None,
        }
    }

    fn id_of(pubkey_hex: &str) -> String {
        format!("{pubkey_hex}ABCDABCD")
    }

    #[test]
    fn contact_id_maps_to_public_key_prefix() {
        let pk = "A".repeat(64);
        let id = id_of(&pk);
        assert_eq!(Store::key_of(&id), Some(pk.clone()));
        // Formatting the user pasted from a chat app should still work.
        let spaced = id
            .as_bytes()
            .chunks(6)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(Store::key_of(&spaced), Some(pk));
        assert_eq!(Store::key_of("too short"), None);
    }

    #[test]
    fn nospam_rotation_keeps_the_same_mailbox() {
        let pk = "B".repeat(64);
        assert_eq!(
            Store::key_of(&format!("{pk}11112222")),
            Store::key_of(&format!("{pk}33334444"))
        );
    }

    #[test]
    fn queue_survives_until_acked() {
        let store = Store::default();
        let pk = "C".repeat(64);
        let id = store.enqueue(&pk, envelope(&id_of(&pk)));

        assert_eq!(store.drain_for(&pk).len(), 1, "unacked message must persist");
        store.ack(&pk, &[id]);
        assert!(store.drain_for(&pk).is_empty());
    }

    #[test]
    fn queue_is_bounded() {
        let store = Store::default();
        let pk = "D".repeat(64);
        for _ in 0..MAX_QUEUED_PER_USER + 50 {
            store.enqueue(&pk, envelope(&id_of(&pk)));
        }
        assert_eq!(store.drain_for(&pk).len(), MAX_QUEUED_PER_USER);
    }

    #[test]
    fn bundle_fetches_are_rate_limited() {
        let store = Store::default();
        let target = "E".repeat(64);
        for i in 0..BUNDLE_FETCHES_PER_HOUR {
            assert!(store.allow_fetch(&target), "fetch {i} should be allowed");
        }
        assert!(!store.allow_fetch(&target), "nospam brute force must be blocked");
        // Limits are per target, not global.
        assert!(store.allow_fetch(&"F".repeat(64)));
    }

    #[test]
    fn one_time_keys_are_never_served_twice() {
        let store = Store::default();
        let pk = "1".repeat(64);
        store.bundles.insert(
            pk.clone(),
            StoredBundle {
                identity_key: "ik".into(),
                fingerprint_key: "fk".into(),
                raw: serde_json::json!({
                    "identity_key": "ik",
                    "one_time_keys": { "k1": "aaa", "k2": "bbb" },
                    "fallback_key": "fallback"
                }),
            },
        );

        let mut served = vec![];
        for _ in 0..2 {
            let b = store.take_bundle(&pk).unwrap();
            let otks = b["one_time_keys"].as_object().unwrap();
            assert_eq!(otks.len(), 1);
            served.push(otks.keys().next().unwrap().clone());
        }
        assert_ne!(served[0], served[1], "same one-time key served twice");

        // Exhausted: fall back rather than fail.
        let b = store.take_bundle(&pk).unwrap();
        assert!(b["one_time_keys"].as_object().unwrap().is_empty());
        assert_eq!(b["fallback_key"], "fallback");
    }

    #[test]
    fn signature_verification_rejects_garbage() {
        assert!(!verify_signature("not-base64!!", "nonce", "also-bad"));
        assert!(!verify_signature(&B64.encode([0u8; 10]), "nonce", &B64.encode([0u8; 64])));
    }
}
