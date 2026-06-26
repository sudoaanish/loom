#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tauri::{AppHandle, Emitter, Manager};
use loom_core::{LoomEngine, LoomCallback};

// State stored in Tauri's managed state context
struct AppState {
    engine: Arc<LoomEngine>,
    network_started: AtomicBool,
}

// Serializable wrapper structs for UI serialization
#[derive(serde::Serialize)]
struct TauriContactInfo {
    public_key: Vec<u8>,
    display_name: String,
}

#[derive(serde::Serialize)]
struct TauriUIMessage {
    id: String,
    sender: Vec<u8>,
    recipient: Vec<u8>,
    content: String,
    timestamp: i64,
    is_read: bool,
}

// Serializable payloads for emitted frontend events
#[derive(Clone, serde::Serialize)]
struct PeerDiscoveredPayload {
    peer_identity: Vec<u8>,
    ip: String,
    port: u16,
}

#[derive(Clone, serde::Serialize)]
struct MessageReceivedPayload {
    sender_identity: Vec<u8>,
    message_id: String,
    content: String,
    timestamp: i64,
}

#[derive(Clone, serde::Serialize)]
struct SessionEstablishedPayload {
    peer_identity: Vec<u8>,
}

#[derive(Clone, serde::Serialize)]
struct LogPayload {
    level: String,
    message: String,
}

// Implement LoomCallback and bridge to Tauri frontend events
struct TauriCallback {
    app_handle: AppHandle,
}

impl LoomCallback for TauriCallback {
    fn on_peer_discovered(&self, peer_identity: Vec<u8>, ip: String, port: u16) {
        let _ = self.app_handle.emit("peer_discovered", PeerDiscoveredPayload {
            peer_identity,
            ip,
            port,
        });
    }

    fn on_message_received(&self, sender_identity: Vec<u8>, message_id: String, content: String, timestamp: i64) {
        let _ = self.app_handle.emit("message_received", MessageReceivedPayload {
            sender_identity,
            message_id,
            content,
            timestamp,
        });
    }

    fn on_session_established(&self, peer_identity: Vec<u8>) {
        let _ = self.app_handle.emit("session_established", SessionEstablishedPayload {
            peer_identity,
        });
    }

    fn on_log(&self, level: String, message: String) {
        let _ = self.app_handle.emit("log", LogPayload {
            level,
            message,
        });
    }
}

// IPC Commands Implementation

#[tauri::command]
async fn has_identity(state: tauri::State<'_, AppState>) -> Result<bool, String> {
    state.engine.has_identity().map_err(|e| e.to_string())
}

#[tauri::command]
async fn generate_new_identity(state: tauri::State<'_, AppState>) -> Result<String, String> {
    state.engine.generate_new_identity().map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_my_token(state: tauri::State<'_, AppState>) -> Result<String, String> {
    state.engine.get_my_token().map_err(|e| e.to_string())
}

#[tauri::command(rename_all = "snake_case")]
async fn add_contact_token(
    state: tauri::State<'_, AppState>,
    token_str: String,
    display_name: String,
) -> Result<(), String> {
    state.engine.add_contact_token(token_str, display_name).map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_contacts(state: tauri::State<'_, AppState>) -> Result<Vec<TauriContactInfo>, String> {
    let contacts = state.engine.get_contacts().map_err(|e| e.to_string())?;
    Ok(contacts
        .into_iter()
        .map(|c| TauriContactInfo {
            public_key: c.public_key,
            display_name: c.display_name,
        })
        .collect())
}

#[tauri::command]
async fn start_network(
    state: tauri::State<'_, AppState>,
    app_handle: AppHandle,
) -> Result<(), String> {
    if state.network_started.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return Err("Network is already running".to_string());
    }
    let engine = state.engine.clone();
    let callback = TauriCallback { app_handle };
    tokio::task::spawn_blocking(move || {
        engine.start_network(Box::new(callback))
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())
}

#[tauri::command(rename_all = "snake_case")]
async fn initiate_chat_handshake(
    state: tauri::State<'_, AppState>,
    contact_pub_key: Vec<u8>,
) -> Result<(), String> {
    let engine = state.engine.clone();
    tokio::task::spawn_blocking(move || {
        engine.initiate_chat_handshake(contact_pub_key)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())
}

#[tauri::command(rename_all = "snake_case")]
async fn send_message(
    state: tauri::State<'_, AppState>,
    contact_pub_key: Vec<u8>,
    content: String,
) -> Result<String, String> {
    let engine = state.engine.clone();
    tokio::task::spawn_blocking(move || {
        engine.send_message(contact_pub_key, content)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())
}

#[tauri::command(rename_all = "snake_case")]
async fn get_messages(
    state: tauri::State<'_, AppState>,
    contact_pub_key: Vec<u8>,
) -> Result<Vec<TauriUIMessage>, String> {
    let messages = state.engine.get_messages(contact_pub_key).map_err(|e| e.to_string())?;
    Ok(messages
        .into_iter()
        .map(|m| TauriUIMessage {
            id: m.id,
            sender: m.sender,
            recipient: m.recipient,
            content: m.content,
            timestamp: m.timestamp,
            is_read: m.is_read,
        })
        .collect())
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let args: Vec<String> = std::env::args().collect();
            let mut profile = None;
            for i in 0..args.len() {
                if (args[i] == "--profile" || args[i] == "-p") && i + 1 < args.len() {
                    profile = Some(args[i + 1].clone());
                }
            }

            let app_dir = app.path().app_data_dir().expect("Failed to get app data directory");
            std::fs::create_dir_all(&app_dir).expect("Failed to create app data directory");

            let db_filename = match profile {
                Some(ref p) => {
                    let sanitized: String = p.chars()
                        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                        .collect();
                    format!("loom_{}.db", sanitized)
                }
                None => "loom.db".to_string(),
            };
            let db_path = app_dir.join(db_filename).to_string_lossy().to_string();

            let engine = LoomEngine::new(db_path).expect("Failed to initialize LoomEngine");

            app.manage(AppState {
                engine,
                network_started: AtomicBool::new(false),
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            has_identity,
            generate_new_identity,
            get_my_token,
            add_contact_token,
            get_contacts,
            start_network,
            initiate_chat_handshake,
            send_message,
            get_messages
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
