# Project: Loom Secure Chat Client

## Architecture
Loom is a secure, offline, local-first chat client using Tauri, custom-styled with a liquid glass UI, integrating the `loom-core` Rust engine for cryptographic operations, double-ratchet encryption, SQLite storage, and mDNS peer discovery.

### Component Diagram
```
┌────────────────────────────────────────────────────────┐
│                    Tauri Frontend                      │
│     (Vanilla HTML, Liquid Glass CSS, ES6 JS)           │
└──────────────────────────┬─────────────────────────────┘
                           │ IPC Commands / Events (emit)
┌──────────────────────────▼─────────────────────────────┐
│                    Tauri Backend                       │
│                     (src-tauri)                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │ LoomCallback (UniFFI -> Tauri Event Forwarder)   │  │
│  └──────────────────────────────────────────────────┘  │
└──────────────────────────┬─────────────────────────────┘
                           │ Rust APIs
┌──────────────────────────▼─────────────────────────────┐
│                     loom-core crate                    │
│   ┌───────────────┐ ┌───────────────┐ ┌─────────────┐  │
│   │ DoubleRatchet │ │ mDNS SD Peer  │ │   SQLite    │  │
│   │   Sessions    │ │   Discovery   │ │   Storage   │  │
│   └───────────────┘ └───────────────┘ └─────────────┘  │
└────────────────────────────────────────────────────────┘
```

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|---|---|---|---|
| 1 | E2E Test Track | Design E2E test runner, write Tiers 1-4 tests | None | PLANNED |
| 2 | Tauri Backend | Setup src-tauri, implement IPC commands/callbacks | None | PLANNED |
| 3 | Frontend UI | Build Liquid Glass UI frontend views (onboarding, contacts, chat) | None | PLANNED |
| 4 | E2E Integration | Integrate UI and Backend, run tests, fix failures | M1, M2, M3 | PLANNED |
| 5 | Adversarial Hardening | Tier 5 white-box coverage analysis and adversarial testing | M4 | PLANNED |

## Interface Contracts
### Tauri IPC Commands
The Tauri backend must expose the following handlers:
- `has_identity() -> Result<bool, String>`
- `generate_new_identity() -> Result<String, String>`
- `get_my_token() -> Result<String, String>`
- `add_contact_token(token_str: String, display_name: String) -> Result<(), String>`
- `get_contacts() -> Result<Vec<ContactInfo>, String>`
- `start_network() -> Result<(), String>`
- `initiate_chat_handshake(contact_pub_key: Vec<u8>) -> Result<(), String>`
- `send_message(contact_pub_key: Vec<u8>, content: String) -> Result<String, String>`
- `get_messages(contact_pub_key: Vec<u8>) -> Result<Vec<UIMessage>, String>`

### Tauri Event Emissions
The backend forwards events to frontend using:
- `app.emit("peer_discovered", PeerDiscoveredPayload)`
- `app.emit("message_received", MessageReceivedPayload)`
- `app.emit("session_established", SessionEstablishedPayload)`
- `app.emit("log", LogPayload)`

Payload Structures:
- `PeerDiscoveredPayload`: `{ peer_identity: number[], ip: string, port: number }`
- `MessageReceivedPayload`: `{ sender_identity: number[], message_id: string, content: string, timestamp: number }`
- `SessionEstablishedPayload`: `{ peer_identity: number[] }`
- `LogPayload`: `{ level: string, message: string }`

## Code Layout
- `crates/loom-core/` — Core cryptography, SQLite storage, protocol implementation, and networking.
- `src-tauri/` — Tauri backend application.
  - `src-tauri/Cargo.toml` — Tauri cargo file.
  - `src-tauri/tauri.conf.json` — Tauri configuration.
  - `src-tauri/src/main.rs` — Entry point, state management, command handlers, event loops.
- `src/` — Webview frontend.
  - `src/index.html` — Single page HTML structure.
  - `src/style.css` — Liquid glass CSS styling.
  - `src/main.js` — Frontend JS logic and IPC invocation.
- `tests/` — E2E and unit integration testing suite.
