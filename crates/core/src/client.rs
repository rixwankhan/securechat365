//! Relay client: the runtime that keeps a connection alive and moves messages.
//!
//! Design rule: the network layer never sees plaintext and never makes trust
//! decisions. It hands ciphertext to `Identity` and reports events upward.
//!
//! Add this method to `crypto.rs` — the auth handshake needs it:
//!
//! ```ignore
//! impl Identity {
//!     pub fn sign(&self, message: &str) -> String {
//!         self.account.sign(message).to_base64()
//!     }
//! }
//! ```
//!
//! Cargo.toml additions:
//!   tokio-tungstenite = { version = "0.24", features = ["rustls-tls-webpki-roots"] }
//!   futures-util = "0.3"

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use vodozemac::Curve25519PublicKey;

use crate::crypto::{CryptoError, Envelope, Identity, KeyBundle, OTK_REFILL_THRESHOLD, OTK_TARGET};
use crate::identity::ContactId;

/// Reconnect backoff. Starts fast because the common case is a phone waking up
/// on a new network, not a server outage.
const BACKOFF_START: Duration = Duration::from_millis(500);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// Remember this many delivered message ids to suppress duplicates. The relay
/// re-sends anything unacked, so duplicates are expected, not exceptional.
const SEEN_CACHE: usize = 5000;

// --- events ---------------------------------------------------------------

/// What the UI subscribes to. Everything the user sees originates here.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ClientEvent {
    Connecting,
    Connected,
    /// `retry_in_secs` is for the UI; do not implement your own retry on top.
    Disconnected { reason: String, retry_in_secs: u64 },
    MessageReceived {
        /// Sender's public key in hex — always present.
        from: String,
        /// Sender's full 72-char ID, present only when cryptographically
        /// backed. `None` means we cannot offer to add them.
        from_id: Option<String>,
        text: String,
        /// True when this message created a new Olm session. Show it. A peer
        /// reinstalling looks identical to an attack, and only the user can
        /// tell the difference by re-checking the safety number.
        new_session: bool,
        received_at: u64,
    },
    MessageSent { local_id: String },
    /// Queued because we are offline. It will go out on reconnect.
    MessageQueued { local_id: String },
    SessionEstablished { contact_id: String },
    Error { detail: String },
}

// --- outbox ---------------------------------------------------------------

/// A message the user has sent that the relay has not yet accepted.
///
/// Persist this alongside the vault. Losing it means silently losing messages
/// the user believes they sent, which is worse than a visible failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboxItem {
    pub local_id: String,
    pub envelope: Envelope,
    pub attempts: u32,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Outbox {
    items: VecDeque<OutboxItem>,
}

impl Outbox {
    pub fn push(&mut self, local_id: String, envelope: Envelope) {
        self.items.push_back(OutboxItem { local_id, envelope, attempts: 0 });
    }
    pub fn peek(&self) -> Option<&OutboxItem> {
        self.items.front()
    }
    pub fn pop(&mut self) -> Option<OutboxItem> {
        self.items.pop_front()
    }
    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

// --- wire (mirrors relay.rs) ----------------------------------------------

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMessage {
    Auth { identity_key: String, fingerprint_key: String, signature: String },
    PublishKeys { bundle: KeyBundle },
    FetchBundle { contact_id: String },
    Send { envelope: Envelope },
    Ack { ids: Vec<String> },
    KeyCount,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMessage {
    Challenge { nonce: String },
    AuthOk,
    Bundle { bundle: KeyBundle },
    Deliver { id: String, envelope: Envelope },
    KeyCount { remaining: usize },
    Error { code: String, detail: String },
}

// --- commands from the UI -------------------------------------------------

#[derive(Debug)]
pub enum Command {
    /// Send text to a contact. Fails if no session exists yet.
    Send { local_id: String, to: ContactId, text: String },
    /// Fetch a contact's bundle and open a session. This is "add contact".
    AddContact { contact_id: ContactId },
    Shutdown,
}

// --- the client -----------------------------------------------------------

pub struct RelayClient {
    relay_url: String,
    identity: Arc<Mutex<Identity>>,
    outbox: Arc<Mutex<Outbox>>,
    events: mpsc::UnboundedSender<ClientEvent>,
}

impl RelayClient {
    pub fn new(
        relay_url: impl Into<String>,
        identity: Arc<Mutex<Identity>>,
        outbox: Arc<Mutex<Outbox>>,
    ) -> (Self, mpsc::UnboundedReceiver<ClientEvent>) {
        let (events, rx) = mpsc::unbounded_channel();
        (Self { relay_url: relay_url.into(), identity, outbox, events }, rx)
    }

    /// Runs until `Command::Shutdown`. Reconnects on its own; callers should
    /// never restart it in a loop or the backoff becomes meaningless.
    pub async fn run(&self, mut commands: mpsc::UnboundedReceiver<Command>) {
        let mut backoff = BACKOFF_START;

        loop {
            let _ = self.events.send(ClientEvent::Connecting);

            match self.session(&mut commands).await {
                Ok(SessionEnd::Shutdown) => return,
                Ok(SessionEnd::Closed) => {
                    let _ = self.events.send(ClientEvent::Disconnected {
                        reason: "connection closed".into(),
                        retry_in_secs: backoff.as_secs().max(1),
                    });
                }
                Err(e) => {
                    let _ = self.events.send(ClientEvent::Disconnected {
                        reason: e.to_string(),
                        retry_in_secs: backoff.as_secs().max(1),
                    });
                }
            }

            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(BACKOFF_MAX);
        }
    }

    async fn session(
        &self,
        commands: &mut mpsc::UnboundedReceiver<Command>,
    ) -> anyhow::Result<SessionEnd> {
        let (stream, _) = tokio_tungstenite::connect_async(&self.relay_url).await?;
        let (mut sink, mut source) = stream.split();

        // -- handshake ------------------------------------------------------
        let challenge = next_server_message(&mut source).await?;
        let ServerMessage::Challenge { nonce } = challenge else {
            anyhow::bail!("expected a challenge");
        };

        let auth = {
            let identity = self.identity.lock().await;
            ClientMessage::Auth {
                identity_key: identity.identity_key().to_base64(),
                fingerprint_key: identity.fingerprint_key().to_base64(),
                signature: identity.sign(&nonce),
            }
        };
        send(&mut sink, &auth).await?;

        match next_server_message(&mut source).await? {
            ServerMessage::AuthOk => {}
            ServerMessage::Error { code, detail } => {
                anyhow::bail!("auth rejected ({code}): {detail}")
            }
            _ => anyhow::bail!("unexpected reply during auth"),
        }

        let _ = self.events.send(ClientEvent::Connected);

        // Publish a fresh bundle on every connection, not only when one-time
        // keys run low. A "top up when low" rule means an upgraded client keeps
        // serving the bundle format it published before the upgrade — peers
        // then reject it, and no amount of reconnecting fixes it.
        {
            let bundle = {
                let mut identity = self.identity.lock().await;
                identity.generate_key_bundle(OTK_TARGET)
            };
            send(&mut sink, &ClientMessage::PublishKeys { bundle }).await?;
        }

        // Flush anything queued while offline, before handling new work.
        self.flush_outbox(&mut sink).await?;

        // -- main loop ------------------------------------------------------
        let mut seen: VecDeque<String> = VecDeque::with_capacity(SEEN_CACHE);
        let mut seen_set: HashSet<String> = HashSet::new();
        let mut pending_acks: Vec<String> = Vec::new();
        let mut ack_timer = tokio::time::interval(Duration::from_millis(500));

        // Contacts we have asked the relay about, keyed by the base64 identity
        // key we expect back. The ContactId here came from the user scanning a
        // QR code or pasting an ID — it is the only trusted reference point in
        // the whole exchange, so it must be captured before the relay speaks.
        let mut pending: HashMap<String, ContactId> = HashMap::new();

        loop {
            tokio::select! {
                incoming = source.next() => {
                    let Some(frame) = incoming else { return Ok(SessionEnd::Closed) };
                    let WsMessage::Text(text) = frame? else { continue };
                    let msg: ServerMessage = serde_json::from_str(&text)?;

                    match msg {
                        ServerMessage::Deliver { id, envelope } => {
                            // Ack regardless of whether we can decrypt it.
                            // A message we will never decrypt must not be
                            // redelivered forever.
                            pending_acks.push(id.clone());

                            if !seen_set.insert(id.clone()) { continue; }
                            seen.push_back(id);
                            if seen.len() > SEEN_CACHE {
                                if let Some(old) = seen.pop_front() { seen_set.remove(&old); }
                            }

                            let decrypted = {
                                let mut identity = self.identity.lock().await;
                                identity.decrypt(&envelope)
                            };

                            match decrypted {
                                Ok(incoming) => {
                                    // Emit hex, not base64. Contact IDs are hex,
                                    // and the UI matches on this to pick a
                                    // conversation — a base64 value here means
                                    // messages arrive, decrypt, and then land in
                                    // a thread nothing displays.
                                    let from = identity_key_to_hex(&envelope.from_identity_key)
                                        .unwrap_or_else(|| envelope.from_identity_key.clone());
                                    let _ = self.events.send(ClientEvent::MessageReceived {
                                        from,
                                        from_id: incoming.sender_id,
                                        text: incoming.text,
                                        new_session: incoming.new_session,
                                        received_at: envelope.received_at.unwrap_or(0),
                                    });
                                }
                                Err(e) => {
                                    // Common and usually benign: a peer
                                    // reinstalled, or we restored an older
                                    // vault. Surface it, do not crash.
                                    let _ = self.events.send(ClientEvent::Error {
                                        detail: format!("could not decrypt a message: {e}"),
                                    });
                                }
                            }
                        }

                        ServerMessage::KeyCount { remaining } => {
                            if remaining < OTK_REFILL_THRESHOLD {
                                let bundle = {
                                    let mut identity = self.identity.lock().await;
                                    identity.generate_key_bundle(OTK_TARGET - remaining)
                                };
                                send(&mut sink, &ClientMessage::PublishKeys { bundle }).await?;
                            }
                        }

                        ServerMessage::Bundle { bundle } => {
                            // Look up which contact this was for. A bundle whose
                            // identity key we never requested is either a relay
                            // bug or an attack — either way, drop it.
                            match pending.remove(&bundle.identity_key) {
                                Some(id) => {
                                    let result = {
                                        let mut identity = self.identity.lock().await;
                                        identity.begin_session(&id, &bundle)
                                    };
                                    match result {
                                        Ok(()) => {
                                            let _ = self.events.send(
                                                ClientEvent::SessionEstablished {
                                                    contact_id: id.to_string(),
                                                });
                                            self.flush_outbox(&mut sink).await?;
                                        }
                                        Err(CryptoError::BadBundle(detail)) => {
                                            // The check that matters. Do not
                                            // soften this copy.
                                            let _ = self.events.send(ClientEvent::Error {
                                                detail: format!(
                                                    "This contact's keys don't match their ID. \
                                                     Do not send anything. {detail}"),
                                            });
                                        }
                                        Err(e) => {
                                            let _ = self.events.send(ClientEvent::Error {
                                                detail: e.to_string() });
                                        }
                                    }
                                }
                                None => {
                                    let _ = self.events.send(ClientEvent::Error {
                                        detail: "The relay sent keys for a contact you didn't \
                                                 look up. Nothing was added.".into(),
                                    });
                                }
                            }
                        }

                        ServerMessage::Error { code, detail } => {
                            let _ = self.events.send(ClientEvent::Error {
                                detail: format!("{code}: {detail}") });
                        }

                        ServerMessage::Challenge { .. } | ServerMessage::AuthOk => {}
                    }
                }

                _ = ack_timer.tick(), if !pending_acks.is_empty() => {
                    let ids = std::mem::take(&mut pending_acks);
                    send(&mut sink, &ClientMessage::Ack { ids }).await?;
                }

                command = commands.recv() => {
                    match command {
                        None | Some(Command::Shutdown) => return Ok(SessionEnd::Shutdown),

                        Some(Command::AddContact { contact_id }) => {
                            // Record what the user actually scanned, keyed by
                            // the identity key we expect the relay to return.
                            let expected =
                                Curve25519PublicKey::from_bytes(*contact_id.public_key())
                                    .to_base64();
                            pending.insert(expected, contact_id);
                            send(&mut sink, &ClientMessage::FetchBundle {
                                contact_id: contact_id.to_string(),
                            }).await?;
                        }

                        Some(Command::Send { local_id, to, text }) => {
                            let encrypted = {
                                let mut identity = self.identity.lock().await;
                                identity.encrypt(&to, &text)
                            };
                            match encrypted {
                                Ok(envelope) => {
                                    // Queue first, then send. If the process
                                    // dies between the two, the message is
                                    // retried rather than lost.
                                    self.outbox.lock().await.push(local_id.clone(), envelope);
                                    let _ = self.events.send(
                                        ClientEvent::MessageQueued { local_id });
                                    self.flush_outbox(&mut sink).await?;
                                }
                                Err(CryptoError::NoSession) => {
                                    let _ = self.events.send(ClientEvent::Error {
                                        detail: "Add this contact before messaging them.".into(),
                                    });
                                }
                                Err(e) => {
                                    let _ = self.events.send(ClientEvent::Error {
                                        detail: e.to_string() });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    async fn flush_outbox<S>(&self, sink: &mut S) -> anyhow::Result<()>
    where
        S: SinkExt<WsMessage> + Unpin,
        S::Error: std::error::Error + Send + Sync + 'static,
    {
        loop {
            let next = {
                let outbox = self.outbox.lock().await;
                outbox.peek().cloned()
            };
            let Some(item) = next else { return Ok(()) };

            send(sink, &ClientMessage::Send { envelope: item.envelope.clone() }).await?;

            let mut outbox = self.outbox.lock().await;
            outbox.pop();
            let _ = self.events.send(ClientEvent::MessageSent { local_id: item.local_id });
        }
    }
}

enum SessionEnd {
    Closed,
    Shutdown,
}

/// Base64 Curve25519 -> the uppercase hex form used at the start of a contact
/// ID. Lets the UI map an incoming message to a conversation.
fn identity_key_to_hex(base64_key: &str) -> Option<String> {
    let key = Curve25519PublicKey::from_base64(base64_key).ok()?;
    Some(key.to_bytes().iter().map(|b| format!("{b:02X}")).collect())
}

async fn send<S>(sink: &mut S, msg: &ClientMessage) -> anyhow::Result<()>
where
    S: SinkExt<WsMessage> + Unpin,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    sink.send(WsMessage::Text(serde_json::to_string(msg)?.into())).await?;
    Ok(())
}

async fn next_server_message<S>(source: &mut S) -> anyhow::Result<ServerMessage>
where
    S: StreamExt<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    loop {
        let Some(frame) = source.next().await else {
            anyhow::bail!("connection closed");
        };
        if let WsMessage::Text(text) = frame? {
            return Ok(serde_json::from_str(&text)?);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Envelope;

    fn envelope() -> Envelope {
        Envelope {
            to: "0".repeat(72),
            from_identity_key: "ik".into(),
            message_type: 0,
            ciphertext: "opaque".into(),
            received_at: None,
        }
    }

    #[test]
    fn outbox_is_fifo() {
        let mut outbox = Outbox::default();
        outbox.push("a".into(), envelope());
        outbox.push("b".into(), envelope());
        assert_eq!(outbox.peek().unwrap().local_id, "a");
        assert_eq!(outbox.pop().unwrap().local_id, "a");
        assert_eq!(outbox.pop().unwrap().local_id, "b");
        assert!(outbox.is_empty());
    }

    #[test]
    fn outbox_survives_serialization() {
        let mut outbox = Outbox::default();
        outbox.push("a".into(), envelope());
        let json = serde_json::to_string(&outbox).unwrap();
        let restored: Outbox = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.len(), 1);
    }

    #[test]
    fn backoff_is_bounded() {
        let mut b = BACKOFF_START;
        for _ in 0..50 {
            b = (b * 2).min(BACKOFF_MAX);
        }
        assert_eq!(b, BACKOFF_MAX);
    }
}
