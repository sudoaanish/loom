# 📡 Loom

Loom is a local-first, serverless, peer-to-peer secure messaging client designed for desktop platforms. It enables devices on a local Wi-Fi subnet to discover each other and communicate directly—without central servers, cloud infrastructure, internet connectivity, user accounts, or telephone registration.

Identity is established through cryptographically signed base32 tokens shared out-of-band (e.g., via QR codes), and all communication is fully end-to-end encrypted using a custom Signal-protocol-style **Double Ratchet** implementation.

---

## Key Features

* **Serverless & Local-First:** Direct peer-to-peer architecture. Peers discover each other over local subnets using multicast DNS (mDNS) and establish direct TCP connections.
* **End-to-End Encryption:** Authenticated **3DH Handshake** (using X25519) to derive mutual Double Ratchet shared keys, securing all traffic with ChaCha20-Poly1305 AEAD and HKDF-SHA256.
* **Cryptographic Identity Tokens:** Typo-resistant, base32-encoded identity tokens with embedded BLAKE2b checksums.
* **Connection Resilience:** Supports automatic connection retries, out-of-order message caching, and peer roaming/reconnection recovery (e.g., preserving ratchet states when IP addresses or ports change).
* **Liquid Glass UI:** Frosted-glass design system built on Tauri with HTML, CSS, and ES6 JavaScript, featuring keyframe backdrop animations, soft outer drop-shadows, and tactile gloss controls.

---

## Architecture Overview

Loom is split into two primary layers:
1. **`loom-core` (Rust Engine):** Encapsulated in the [crates/loom-core](file:///D:/Projs/Loom/crates/loom-core) directory, this engine manages the cryptographic state machine, Double Ratchet sessions, database storage (SQLite via rusqlite), serialization, and peer socket connections (TCP + mDNS).
2. **Desktop UI (Tauri Shell):** Located in the [src](file:///D:/Projs/Loom/src) and [src-tauri](file:///D:/Projs/Loom/src-tauri) directories. The shell hosts the Rust engine, routes IPC command invocations, and maps engine callbacks (such as peer discovery and incoming messages) directly to the webview frontend via Tauri events.

```
┌────────────────────────────────────────────────────────┐
│                    Tauri Frontend                      │
│     (Vanilla HTML, Liquid Glass CSS, ES6 JS)           │
└──────────────────────────┬─────────────────────────────┘
                           │ IPC Commands / Events (emit)
┌──────────────────────────▼─────────────────────────────┐
│                    Tauri Backend                       │
│                     (src-tauri)                        │
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

---

## Installation & Setup

### Prerequisites
* **Rust Toolchain:** Stable channel, 2021 or 2024 edition.
* **Node.js & npm:** Required for running the Tauri CLI tool.

### Setup Instructions
1. Clone the repository:
   ```bash
   git clone https://github.com/sudoaanish/loom.git
   cd loom
   ```
2. Run the test suite to verify the cryptographic and networking modules:
   ```bash
   cargo test
   ```
3. Launch the desktop application in development mode:
   ```bash
   npx @tauri-apps/cli dev
   ```

---

## Local Multi-Peer Testing Guide

Because multicast DNS (mDNS) loopback routing is generally restricted on Windows by default, testing peer discovery and messaging on a single machine requires isolating profiles and using manual port injection. 

Loom supports profile isolation through database partitioning and manual port mapping.

### Step 1: Start Two Separate Instances
Since Windows locks running executables, you should compile the binary once, and then run it twice using separate profiles to prevent file-lock conflicts.

1. **Start Peer 1** (this will compile and run the application):
   ```powershell
   $env:LOOM_PROFILE="peer1"
   npx @tauri-apps/cli dev
   ```
   *Take note of the port displayed next to "My Device" in the sidebar (e.g., `Port: 52180`).*

2. **Start Peer 2** (runs the compiled binary directly, bypassing recompilation):
   ```powershell
   $env:LOOM_PROFILE="peer2"
   .\target\debug\loom-backend.exe
   ```
   *Take note of the port displayed next to "My Device" in the sidebar (e.g., `Port: 54930`).*

### Step 2: Establish the Connection
1. Click the **My Device** (QR icon) on **Peer 1** to open the modal. Click **Copy Token** to copy Peer 1's identity token to the clipboard.
2. In **Peer 2**, under **Add New Contact**:
   - Set **Display Name** to `One`.
   - Paste the token into **Paste LOOM-token...**.
   - Set **Port** to Peer 1's port (e.g., `52180`).
   - Click **Add**.
3. Now open the modal on **Peer 2**, click **Copy Token**.
4. In **Peer 1**, under **Add New Contact**:
   - Set **Display Name** to `Two`.
   - Paste the token.
   - Set **Port** to Peer 2's port (e.g., `54930`).
   - Click **Add**.

### Step 3: Initiate Handshake & Chat
Select the contact in either interface and click **Initiate Handshake**. The status indicators will turn to **Secured**, indicating the 3DH exchange succeeded and derived the shared double-ratchet keys. You can now chat securely!

---

## IPC Protocol API

Loom's UI interacts with the backend engine via Tauri IPC command handlers:

| Command | Arguments | Description |
|---|---|---|
| `has_identity` | None | Returns `bool` indicating if a local identity database seed exists. |
| `generate_new_identity` | None | Generates a new master seed and returns the base32 token. |
| `get_my_token` | None | Returns the current base32 identity token. |
| `add_contact_token` | `token_str: String`, `display_name: String` | Parses a token and adds the contact to the SQLite database. |
| `get_contacts` | None | Returns a list of all saved contacts. |
| `start_network` | None | Starts the TCP listener socket and begins mDNS advertising/browsing. |
| `initiate_chat_handshake` | `contact_pub_key: Vec<u8>` | Connects to a contact and executes the 3DH handshake. |
| `send_message` | `contact_pub_key: Vec<u8>`, `content: String` | Encrypts and transmits a secure chat message. |
| `get_messages` | `contact_pub_key: Vec<u8>` | Returns historical message logs for a contact. |
| `inject_peer_address` | `peer_pub_key: Vec<u8>`, `ip: String`, `port: u16` | Manually maps a peer's public key to a network location. |
| `get_network_port` | None | Returns the active local TCP socket listener port. |

---

## License

This project is authored by **Aanish Farrukh** and licensed under the [MIT License](LICENSE).
