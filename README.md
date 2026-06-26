# 📡 Loom

Loom is a local-first, serverless, peer-to-peer secure messaging client. It allows nearby devices to discover each other and communicate directly over local Wi-Fi networks—without requiring internet connectivity, central servers, user accounts, or phone numbers.

Identity is established via cryptographically signed base32 tokens shared out-of-band (e.g., via QR codes), and communication is fully end-to-end encrypted using a custom Signal-protocol-style **Double Ratchet** implementation.

---

## Features

* **Serverless & Local-First:** Complete peer-to-peer architecture. Peers discover each other over local subnets using multicast DNS (mDNS) and establish direct TCP connections.
* **End-to-End Encryption:** Uses an authenticated **3DH Handshake** to derive mutual Double Ratchet shared keys, securing all communication with ChaCha20-Poly1305 AEAD and HKDF-SHA256.
* **Cryptographic Identity Tokens:** Typo-resistant, base32-encoded identity tokens with embedded BLAKE2b checksums.
* **Resilient Networking:** Supports automatic connection retries, out-of-order message caching, and peer roaming/reconnection recovery (e.g., recovering sessions when ports or network configurations change).
* **Liquid Glass UI:** A responsive dark-mode desktop interface built on Tauri featuring dynamic frosted-glass panels (glassmorphic styling) and tactile controls.

---

## Architecture

Loom is split into two primary components:
1. **`loom-core` (Rust Engine):** The central state machine handling cryptography, Double Ratchet sessions, database storage (SQLite via rusqlite), protocol message serialization, and peer socket networking (mDNS discovery + TCP listener).
2. **Desktop UI (Tauri Shell):** A lightweight desktop interface utilizing Vanilla JS/CSS/HTML served statically and communicating with the Rust core via secure Tauri IPC commands and events.

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

## Get Started

### Prerequisites
* Rust toolchain (stable, 2021/2024 edition)
* Node.js and `npm` (for running the Tauri CLI)

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/sudoaanish/loom.git
   cd loom
   ```
2. Run the test suite to verify the cryptographic and networking modules:
   ```bash
   cargo test
   ```
3. Run the desktop application in development mode:
   ```bash
   npx @tauri-apps/cli dev
   ```

---

## License

This project is licensed under the [MIT License](LICENSE).
