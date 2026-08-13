//! Tauri bridge. Owns the identity, runs the relay client, and exposes a small
//! command surface to the frontend.
//!
//! Nothing here makes trust decisions — those all live in veil-core. This file
//! moves data between the core and the window.

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::{mpsc, Mutex};

use securechat365_core::client::{ClientEvent, Command, Outbox, RelayClient};
use securechat365_core::crypto::{Identity, Vault};
use securechat365_core::identity::ContactId;

/// Set at build time: `RELAY_URL=wss://relay.example.com/ws npm run tauri build`
///
/// Baked in rather than read at runtime on purpose. A messenger that lets an
/// env var or config file redirect it to another relay is one social-engineering
/// step away from routing a user's traffic somewhere they didn't choose.
/// Note the empty check. An unset GitHub Actions variable expands to an empty
/// string, and `option_env!` reports that as `Some("")` — so without this, a CI
/// build with a missing variable compiles cleanly and ships a client that can
/// never connect to anything, with no error to explain why.
const RELAY_URL: &str = match option_env!("RELAY_URL") {
    Some(url) if !url.is_empty() => url,
    _ => "ws://localhost:8080/ws",
};

// --- persisted shapes -----------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    /// 72-char ID exactly as the user scanned it.
    pub id: String,
    pub name: String,
    /// Set once the user has compared safety numbers out of band.
    pub verified: bool,
}

/// TODO before release: this is written as plaintext JSON, which leaves the
/// user's contact list readable on disk. It must move inside the encrypted
/// vault. Messages are safe; the social graph currently is not.
#[derive(Debug, Default, Serialize, Deserialize)]
struct ContactBook {
    contacts: HashMap<String, Contact>,
}

// --- app state ------------------------------------------------------------

#[derive(Default)]
pub struct AppState {
    identity: Arc<Mutex<Option<Arc<Mutex<Identity>>>>>,
    commands: Mutex<Option<mpsc::UnboundedSender<Command>>>,
    contacts: Mutex<ContactBook>,
    /// Held in memory for the life of the session so the vault can be rewritten
    /// when the ratchet advances. Never written to disk.
    passphrase: Arc<Mutex<Option<String>>>,
}

type Result<T> = std::result::Result<T, String>;

fn data_dir(app: &AppHandle) -> Result<std::path::PathBuf> {
    // Dev-only: lets you run two instances side by side with separate
    // identities. Debug builds only — a release build that lets an env var
    // relocate the vault is an attack surface, not a feature.
    #[cfg(debug_assertions)]
    if let Ok(override_path) = std::env::var("SECURECHAT_DATA_DIR") {
        let dir = std::path::PathBuf::from(override_path);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        return Ok(dir);
    }

    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

fn vault_path(app: &AppHandle) -> Result<std::path::PathBuf> {
    Ok(data_dir(app)?.join("identity.vault"))
}

fn contacts_path(app: &AppHandle) -> Result<std::path::PathBuf> {
    Ok(data_dir(app)?.join("contacts.json"))
}

/// Write to a temp file then rename. A half-written vault is an unrecoverable
/// identity, and force-quit during save is common on mobile.
fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

// --- commands: vault lifecycle -------------------------------------------

/// Delete the identity and start over. Irreversible: the key is the account,
/// so this is not "log out", it is "become a different person".
#[tauri::command]
async fn reset_identity(app: AppHandle) -> Result<()> {
    let _ = std::fs::remove_file(vault_path(&app)?);
    let _ = std::fs::remove_file(contacts_path(&app)?);
    Ok(())
}

#[tauri::command]
fn has_identity(app: AppHandle) -> Result<bool> {
    Ok(vault_path(&app)?.exists())
}

#[derive(Serialize)]
pub struct IdentityInfo {
    id: String,
    display: String,
    qr_svg: String,
}

#[tauri::command]
async fn create_identity(
    app: AppHandle,
    state: State<'_, AppState>,
    passphrase: String,
) -> Result<IdentityInfo> {
    if passphrase.chars().count() < 8 {
        return Err("Use at least 8 characters. This is the only thing protecting your keys.".into());
    }
    if vault_path(&app)?.exists() {
        return Err("An identity already exists on this device.".into());
    }

    let identity = Identity::create();
    let vault = identity.lock(&passphrase).map_err(|e| e.to_string())?;
    write_atomic(&vault_path(&app)?, &serde_json::to_vec(&vault).map_err(|e| e.to_string())?)?;

    let info = describe(&identity)?;
    install(app, state, identity, passphrase).await?;
    Ok(info)
}

/// Vault layouts this build can read. Bump when the shape changes.
const VAULT_VERSION: u8 = 2;

#[tauri::command]
async fn unlock(
    app: AppHandle,
    state: State<'_, AppState>,
    passphrase: String,
) -> Result<IdentityInfo> {
    let bytes = std::fs::read(vault_path(&app)?).map_err(|e| e.to_string())?;

    // Check the version before deserialising into the real type, so a format
    // change produces an explanation rather than a parser error.
    let version = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| v.get("version").and_then(|n| n.as_u64()))
        .unwrap_or(0) as u8;

    if version != VAULT_VERSION {
        return Err(format!(
            "This identity was saved by an older version of the app (format {version}, \
             this build reads {VAULT_VERSION}). It can't be opened, and there's no upgrade \
             path yet. Delete the vault to start over — you'll get a new ID and your \
             contacts will need to add you again."
        ));
    }

    let vault: Vault = serde_json::from_slice(&bytes).map_err(|e| {
        format!("The vault file is damaged and can't be read: {e}")
    })?;
    let identity = Identity::unlock(&vault, &passphrase).map_err(|e| e.to_string())?;

    if let Ok(raw) = std::fs::read(contacts_path(&app)?) {
        if let Ok(book) = serde_json::from_slice::<ContactBook>(&raw) {
            *state.contacts.lock().await = book;
        }
    }

    let info = describe(&identity)?;
    install(app, state, identity, passphrase).await?;
    Ok(info)
}

fn describe(identity: &Identity) -> Result<IdentityInfo> {
    let id = identity.contact_id();
    Ok(IdentityInfo {
        display: id.to_display_string(),
        qr_svg: qr_svg(&id.to_uri())?,
        id: id.to_string(),
    })
}

/// Put the identity into shared state and start the relay client.
async fn install(
    app: AppHandle,
    state: State<'_, AppState>,
    identity: Identity,
    passphrase: String,
) -> Result<()> {
    let identity = Arc::new(Mutex::new(identity));
    *state.identity.lock().await = Some(identity.clone());
    *state.passphrase.lock().await = Some(passphrase);

    let (tx, rx) = mpsc::unbounded_channel();
    *state.commands.lock().await = Some(tx);

    let outbox = Arc::new(Mutex::new(Outbox::default()));
    eprintln!("relay: {RELAY_URL}");
    let (client, mut events) = RelayClient::new(RELAY_URL, identity.clone(), outbox);

    // Forward core events to the window, and save the vault whenever the
    // ratchet moves. Olm session state changes on every encrypt and decrypt —
    // if it is not persisted, every restart silently loses the ability to talk
    // to contacts that are still listed on screen.
    let sink = app.clone();
    let save_identity = identity.clone();
    let save_passphrase = state.passphrase.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(event) = events.recv().await {
            let ratchet_moved = matches!(
                &event,
                ClientEvent::SessionEstablished { .. }
                    | ClientEvent::MessageSent { .. }
                    | ClientEvent::MessageReceived { .. }
            );

            let _ = sink.emit("securechat365", &event);

            if ratchet_moved {
                let passphrase = save_passphrase.lock().await.clone();
                if let Some(passphrase) = passphrase {
                    let vault = { save_identity.lock().await.lock(&passphrase) };
                    match vault {
                        Ok(vault) => {
                            if let (Ok(path), Ok(bytes)) =
                                (vault_path(&sink), serde_json::to_vec(&vault))
                            {
                                if let Err(e) = write_atomic(&path, &bytes) {
                                    eprintln!("vault save failed: {e}");
                                }
                            }
                        }
                        Err(e) => eprintln!("vault serialisation failed: {e}"),
                    }
                }
            }
        }
    });

    tauri::async_runtime::spawn(async move {
        client.run(rx).await;
    });

    Ok(())
}

// --- commands: contacts and messaging ------------------------------------

#[tauri::command]
async fn add_contact(
    app: AppHandle,
    state: State<'_, AppState>,
    id: String,
    name: String,
) -> Result<Contact> {
    let parsed: ContactId = id.parse().map_err(|e: securechat365_core::identity::ParseError| {
        format!("That ID doesn't look right — {e}")
    })?;

    let me = {
        // Clone the Arc and release the outer lock before taking the inner
        // one. Holding both is what the borrow checker objected to, and it is
        // also how you deadlock yourself later.
        let identity = {
            let guard = state.identity.lock().await;
            guard.as_ref().ok_or("Unlock first.")?.clone()
        };
        let locked = identity.lock().await;
        locked.contact_id()
    };
    if parsed.public_key() == me.public_key() {
        return Err("That's your own ID.".into());
    }

    let contact = Contact {
        id: parsed.to_string(),
        name: if name.trim().is_empty() { "Unnamed".into() } else { name },
        verified: false,
    };

    {
        let mut book = state.contacts.lock().await;
        book.contacts.insert(contact.id.clone(), contact.clone());
        persist_contacts(&app, &book)?;
    }

    let tx = state.commands.lock().await;
    tx.as_ref()
        .ok_or("Not connected.")?
        .send(Command::AddContact { contact_id: parsed })
        .map_err(|e| e.to_string())?;

    Ok(contact)
}

#[tauri::command]
async fn list_contacts(state: State<'_, AppState>) -> Result<Vec<Contact>> {
    let book = state.contacts.lock().await;
    let mut all: Vec<_> = book.contacts.values().cloned().collect();
    all.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Ok(all)
}

#[tauri::command]
async fn send_message(
    state: State<'_, AppState>,
    to: String,
    text: String,
) -> Result<String> {
    if text.trim().is_empty() {
        return Err("Nothing to send.".into());
    }
    let parsed: ContactId = to.parse().map_err(|_| "Bad contact ID.".to_string())?;
    let local_id = format!("{:x}", rand::random::<u64>());

    let tx = state.commands.lock().await;
    tx.as_ref()
        .ok_or("Not connected.")?
        .send(Command::Send { local_id: local_id.clone(), to: parsed, text })
        .map_err(|e| e.to_string())?;

    Ok(local_id)
}

/// The 60 digits both people read aloud to each other. If they match, no one is
/// in the middle. If they don't, stop using the conversation.
#[tauri::command]
async fn get_safety_number(state: State<'_, AppState>, contact_id: String) -> Result<String> {
    let parsed: ContactId = contact_id.parse().map_err(|_| "Bad contact ID.".to_string())?;

    let identity = {
        let guard = state.identity.lock().await;
        guard.as_ref().ok_or("Unlock first.")?.clone()
    };
    let identity = identity.lock().await;

    identity.safety_number_with(&parsed).map_err(|e| match e {
        securechat365_core::crypto::CryptoError::NoFingerprint => {
            "Send or receive a message with this contact first, then verify.".to_string()
        }
        other => other.to_string(),
    })
}

#[tauri::command]
async fn mark_verified(
    app: AppHandle,
    state: State<'_, AppState>,
    contact_id: String,
    verified: bool,
) -> Result<()> {
    let mut book = state.contacts.lock().await;
    if let Some(c) = book.contacts.get_mut(&contact_id) {
        c.verified = verified;
    }
    persist_contacts(&app, &book)
}

fn persist_contacts(app: &AppHandle, book: &ContactBook) -> Result<()> {
    write_atomic(
        &contacts_path(app)?,
        &serde_json::to_vec_pretty(book).map_err(|e| e.to_string())?,
    )
}

// --- QR -------------------------------------------------------------------

/// Rendered in Rust so the app never fetches a QR library at runtime — an
/// offline app that reaches out to a CDN isn't offline.
fn qr_svg(payload: &str) -> Result<String> {
    use qrcode::render::svg;
    use qrcode::{EcLevel, QrCode};

    // High error correction: these get scanned off cracked phone screens.
    let code = QrCode::with_error_correction_level(payload, EcLevel::H)
        .map_err(|e| e.to_string())?;
    Ok(code
        .render::<svg::Color>()
        .min_dimensions(240, 240)
        .quiet_zone(true)
        .dark_color(svg::Color("#14161D"))
        .light_color(svg::Color("#FFFFFF"))
        .build())
}

// --- entry ----------------------------------------------------------------

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            has_identity,
            create_identity,
            reset_identity,
            unlock,
            add_contact,
            list_contacts,
            send_message,
            get_safety_number,
            mark_verified,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
