pub mod crypto;
pub mod network;
pub mod protocol;
pub mod storage;
pub mod token;

use crypto::{derive_keys, generate_master_seed};
use network::NetworkManager;
use storage::Storage;
use token::LoomToken;

use std::sync::{Arc, Mutex};
use thiserror::Error;
use tokio::runtime::Runtime;

uniffi::setup_scaffolding!();

#[uniffi::export(callback_interface)]
pub trait LoomCallback: Send + Sync + 'static {
    fn on_peer_discovered(&self, peer_identity: Vec<u8>, ip: String, port: u16);
    fn on_message_received(&self, sender_identity: Vec<u8>, message_id: String, content: String, timestamp: i64);
    fn on_session_established(&self, peer_identity: Vec<u8>);
    fn on_log(&self, level: String, message: String);
}

struct SharedCallback {
    inner: Mutex<Box<dyn LoomCallback>>,
}

impl LoomCallback for SharedCallback {
    fn on_peer_discovered(&self, peer_identity: Vec<u8>, ip: String, port: u16) {
        self.inner.lock().unwrap().on_peer_discovered(peer_identity, ip, port);
    }
    fn on_message_received(&self, sender_identity: Vec<u8>, message_id: String, content: String, timestamp: i64) {
        self.inner.lock().unwrap().on_message_received(sender_identity, message_id, content, timestamp);
    }
    fn on_session_established(&self, peer_identity: Vec<u8>) {
        self.inner.lock().unwrap().on_session_established(peer_identity);
    }
    fn on_log(&self, level: String, message: String) {
        self.inner.lock().unwrap().on_log(level, message);
    }
}

#[derive(uniffi::Record)]
pub struct ContactInfo {
    pub public_key: Vec<u8>,
    pub display_name: String,
}

#[derive(uniffi::Record)]
pub struct UIMessage {
    pub id: String,
    pub sender: Vec<u8>,
    pub recipient: Vec<u8>,
    pub content: String,
    pub timestamp: i64,
    pub is_read: bool,
}

#[derive(Error, Debug, uniffi::Error)]
pub enum LoomError {
    #[error("Database error: {message}")]
    DatabaseError { message: String },
    #[error("Network error: {message}")]
    NetworkError { message: String },
    #[error("Crypto error: {message}")]
    CryptoError { message: String },
    #[error("Invalid token format")]
    InvalidToken,
    #[error("No identity found")]
    NoIdentity,
}

#[derive(uniffi::Object)]
pub struct LoomEngine {
    storage: Arc<Storage>,
    network_manager: Arc<Mutex<Option<Arc<NetworkManager>>>>,
    runtime: Runtime,
}

#[uniffi::export]
impl LoomEngine {
    #[uniffi::constructor]
    pub fn new(db_path: String) -> Result<Arc<Self>, LoomError> {
        if db_path.trim().is_empty() {
            return Err(LoomError::DatabaseError {
                message: "Database path cannot be empty".to_string(),
            });
        }
        let storage = Storage::open(&db_path)
            .map_err(|e| LoomError::DatabaseError { message: e.to_string() })?;
        
        let runtime = Runtime::new()
            .map_err(|e| LoomError::NetworkError { message: e.to_string() })?;

        Ok(Arc::new(Self {
            storage: Arc::new(storage),
            network_manager: Arc::new(Mutex::new(None)),
            runtime,
        }))
    }

    pub fn has_identity(&self) -> Result<bool, LoomError> {
        let seed = self.storage.get_self_seed()
            .map_err(|e| LoomError::DatabaseError { message: e.to_string() })?;
        Ok(seed.is_some())
    }

    pub fn generate_new_identity(&self) -> Result<String, LoomError> {
        let seed = generate_master_seed();
        self.storage.set_self_seed(&seed)
            .map_err(|e| LoomError::DatabaseError { message: e.to_string() })?;

        let keys = derive_keys(&seed);
        let id_pub = keys.identity_key.verifying_key().to_bytes();
        let dh_pub = keys.dh_public.to_bytes();

        let token = LoomToken::new(id_pub, dh_pub);
        Ok(token.to_string())
    }

    pub fn get_my_token(&self) -> Result<String, LoomError> {
        let seed = self.storage.get_self_seed()
            .map_err(|e| LoomError::DatabaseError { message: e.to_string() })?
            .ok_or(LoomError::NoIdentity)?;

        let keys = derive_keys(&seed);
        let id_pub = keys.identity_key.verifying_key().to_bytes();
        let dh_pub = keys.dh_public.to_bytes();

        let token = LoomToken::new(id_pub, dh_pub);
        Ok(token.to_string())
    }

    pub fn add_contact_token(&self, token_str: String, display_name: String) -> Result<(), LoomError> {
        let token = LoomToken::parse(&token_str)
            .map_err(|_| LoomError::InvalidToken)?;
        
        self.storage.add_contact(&token.identity_key, &token.dh_key, &display_name)
            .map_err(|e| LoomError::DatabaseError { message: e.to_string() })?;
        
        Ok(())
    }

    pub fn get_contacts(&self) -> Result<Vec<ContactInfo>, LoomError> {
        let db_contacts = self.storage.get_contacts()
            .map_err(|e| LoomError::DatabaseError { message: e.to_string() })?;
        
        let contacts = db_contacts
            .into_iter()
            .map(|(key, name)| ContactInfo {
                public_key: key,
                display_name: name,
            })
            .collect();
        
        Ok(contacts)
    }

    pub fn start_network(&self, callback: Box<dyn LoomCallback>) -> Result<(), LoomError> {
        let callback_arc = Arc::new(SharedCallback {
            inner: Mutex::new(callback),
        });
        let network = Arc::new(NetworkManager::new(self.storage.clone(), callback_arc));
        
        let network_clone = network.clone();
        self.runtime.block_on(async move {
            network_clone.start().await
                .map_err(|e| LoomError::NetworkError { message: e.to_string() })
        })?;

        *self.network_manager.lock().unwrap() = Some(network);
        Ok(())
    }

    pub fn initiate_chat_handshake(&self, contact_pub_key: Vec<u8>) -> Result<(), LoomError> {
        let network_lock = self.network_manager.lock().unwrap();
        let network = network_lock.as_ref().ok_or(LoomError::NetworkError {
            message: "Network not started".to_string(),
        })?;

        if contact_pub_key.len() != 32 {
            return Err(LoomError::CryptoError {
                message: "Invalid contact public key size".to_string(),
            });
        }

        let mut peer_identity = [0u8; 32];
        peer_identity.copy_from_slice(&contact_pub_key);

        let peer_dh = self.storage.get_contact_dh_key(&peer_identity)
            .map_err(|e| LoomError::DatabaseError { message: e.to_string() })?
            .ok_or(LoomError::CryptoError {
                message: "Contact DH key not found".to_string(),
            })?;

        self.runtime.block_on(async {
            network.initiate_handshake(&peer_identity, &peer_dh).await
        }).map_err(|e| LoomError::NetworkError { message: e.to_string() })?;

        Ok(())
    }

    pub fn send_message(&self, contact_pub_key: Vec<u8>, content: String) -> Result<String, LoomError> {
        let network_lock = self.network_manager.lock().unwrap();
        let network = network_lock.as_ref().ok_or(LoomError::NetworkError {
            message: "Network not started".to_string(),
        })?;

        if contact_pub_key.len() != 32 {
            return Err(LoomError::CryptoError {
                message: "Invalid public key length".to_string(),
            });
        }

        let mut peer_identity = [0u8; 32];
        peer_identity.copy_from_slice(&contact_pub_key);

        let msg_id = self.runtime.block_on(async {
            network.send_chat_message(&peer_identity, &content).await
        }).map_err(|e| LoomError::NetworkError { message: e.to_string() })?;

        Ok(msg_id)
    }

    pub fn get_messages(&self, contact_pub_key: Vec<u8>) -> Result<Vec<UIMessage>, LoomError> {
        if contact_pub_key.len() != 32 {
            return Err(LoomError::CryptoError {
                message: "Invalid public key length".to_string(),
            });
        }
        let mut peer_key = [0u8; 32];
        peer_key.copy_from_slice(&contact_pub_key);

        let records = self.storage.get_messages(&peer_key)
            .map_err(|e| LoomError::DatabaseError { message: e.to_string() })?;

        let messages = records
            .into_iter()
            .map(|r| UIMessage {
                id: r.id,
                sender: r.sender_key.to_vec(),
                recipient: r.recipient_key.to_vec(),
                content: r.content,
                timestamp: r.timestamp,
                is_read: r.is_read,
            })
            .collect();

        Ok(messages)
    }

    pub fn get_network_port(&self) -> Result<u16, LoomError> {
        let network_lock = self.network_manager.lock().unwrap();
        let network = network_lock.as_ref().ok_or(LoomError::NetworkError {
            message: "Network not started".to_string(),
        })?;
        let port = self.runtime.block_on(async {
            *network.local_port.lock().await
        });
        Ok(port)
    }

    pub fn inject_peer_address(&self, peer_pub_key: Vec<u8>, ip: String, port: u16) -> Result<(), LoomError> {
        let network_lock = self.network_manager.lock().unwrap();
        let network = network_lock.as_ref().ok_or(LoomError::NetworkError {
            message: "Network not started".to_string(),
        })?;
        if peer_pub_key.len() != 32 {
            return Err(LoomError::CryptoError {
                message: "Invalid public key length".to_string(),
            });
        }
        let addr = format!("{}:{}", ip, port)
            .parse::<std::net::SocketAddr>()
            .map_err(|e| LoomError::NetworkError { message: e.to_string() })?;
        self.runtime.block_on(async {
            network.peer_addresses.lock().await.insert(peer_pub_key.clone(), addr);
            network.active_connections.lock().await.remove(&peer_pub_key);
        });
        Ok(())
    }

    pub fn delete_contact(&self, contact_pub_key: Vec<u8>) -> Result<(), LoomError> {
        if contact_pub_key.len() != 32 {
            return Err(LoomError::CryptoError {
                message: "Invalid public key length".to_string(),
            });
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&contact_pub_key);
        self.storage.delete_contact(&key)
            .map_err(|e| LoomError::DatabaseError { message: e.to_string() })?;
        Ok(())
    }
}

impl LoomEngine {
    pub fn get_storage_rust(&self) -> Arc<Storage> {
        self.storage.clone()
    }

    pub fn send_raw_bytes(&self, peer_pub_key: Vec<u8>, payload: Vec<u8>) -> Result<(), LoomError> {
        let network_lock = self.network_manager.lock().unwrap();
        let network = network_lock.as_ref().ok_or(LoomError::NetworkError {
            message: "Network not started".to_string(),
        })?;
        self.runtime.block_on(async {
            let connections = network.active_connections.lock().await;
            let stream_shared = connections.get(&peer_pub_key).ok_or(LoomError::NetworkError {
                message: "No active connection".to_string(),
            })?;
            use tokio::io::AsyncWriteExt;
            let mut stream = stream_shared.lock().await;
            let len_bytes = (payload.len() as u32).to_be_bytes();
            stream.write_all(&len_bytes).await.map_err(|e| LoomError::NetworkError { message: e.to_string() })?;
            stream.write_all(&payload).await.map_err(|e| LoomError::NetworkError { message: e.to_string() })?;
            Ok::<(), LoomError>(())
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn test_token_serialization() {
        let id_key = [7u8; 32];
        let dh_key = [9u8; 32];
        let token = LoomToken::new(id_key, dh_key);
        let token_str = token.to_string();
        assert!(token_str.starts_with("LOOM-"));

        let parsed = LoomToken::parse(&token_str).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.identity_key, id_key);
        assert_eq!(parsed.dh_key, dh_key);
    }

    #[test]
    fn test_cryptography_and_ratchet() {
        let alice_seed = crypto::generate_master_seed();
        let bob_seed = crypto::generate_master_seed();

        let alice_keys = crypto::derive_keys(&alice_seed);
        let bob_keys = crypto::derive_keys(&bob_seed);

        // Simulate 3DH handshake
        let mut alice_ephemeral_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut alice_ephemeral_bytes);
        let alice_ephemeral_secret = x25519_dalek::StaticSecret::from(alice_ephemeral_bytes);
        let alice_ephemeral_pub = x25519_dalek::PublicKey::from(&alice_ephemeral_secret);

        let mut bob_ephemeral_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bob_ephemeral_bytes);
        let bob_ephemeral_secret = x25519_dalek::StaticSecret::from(bob_ephemeral_bytes);
        let bob_ephemeral_pub = x25519_dalek::PublicKey::from(&bob_ephemeral_secret);

        // Alice computes root key (responder)
        let alice_root = protocol::compute_3dh_responder(
            &alice_keys.dh_secret,
            &alice_ephemeral_secret,
            &bob_keys.dh_public,
            &bob_ephemeral_pub,
        );

        // Bob computes root key (initiator)
        let bob_root = protocol::compute_3dh_initiator(
            &bob_keys.dh_secret,
            &bob_ephemeral_secret,
            &alice_keys.dh_public,
            &alice_ephemeral_pub,
        );

        assert_eq!(alice_root, bob_root);

        // Initialize Double Ratchet sessions
        let mut alice_session = crypto::DoubleRatchetSession::initialize_passive(
            alice_ephemeral_secret,
            bob_ephemeral_pub,
            alice_root,
        );

        let mut bob_session = crypto::DoubleRatchetSession::initialize_active(
            bob_ephemeral_secret,
            alice_ephemeral_pub,
            bob_root,
        );

        // Bob sends message to Alice
        let msg = b"Hello Alice!";
        let ad = b"AD";
        let (ciphertext, nonce, dh_pub, n, pn) = bob_session.encrypt(msg, ad).unwrap();

        // Construct full AD incorporating the header values to match encrypt's logic
        let mut full_ad = Vec::new();
        full_ad.extend_from_slice(ad);
        full_ad.extend_from_slice(dh_pub.as_bytes());
        full_ad.extend_from_slice(&n.to_be_bytes());
        full_ad.extend_from_slice(&pn.to_be_bytes());

        // Alice decrypts
        let decrypted = alice_session.decrypt(&ciphertext, &nonce, dh_pub, n, pn, &full_ad).unwrap();
        assert_eq!(decrypted, msg);
    }
}
