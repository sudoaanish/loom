use crate::crypto::{derive_keys, DoubleRatchetSession};
use crate::protocol::{
    compute_3dh_initiator, compute_3dh_responder, EncryptedEnvelope, HandshakeInitiator,
    HandshakeResponder, WireMessage,
};
use crate::storage::Storage;
use ed25519_dalek::{VerifyingKey, Signer, Verifier};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use rand::RngCore;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

use crate::LoomCallback;

pub struct NetworkManager {
    pub(crate) storage: Arc<Storage>,
    pub(crate) callback: Arc<dyn LoomCallback>,
    pub(crate) local_port: Arc<Mutex<u16>>,
    pub(crate) peer_addresses: Arc<Mutex<HashMap<Vec<u8>, SocketAddr>>>,
    pub(crate) active_connections: Arc<Mutex<HashMap<Vec<u8>, Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>>>>,
}

impl NetworkManager {
    pub fn new(storage: Arc<Storage>, callback: Arc<dyn LoomCallback>) -> Self {
        Self {
            storage,
            callback,
            local_port: Arc::new(Mutex::new(0)),
            peer_addresses: Arc::new(Mutex::new(HashMap::new())),
            active_connections: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Bind TCP listener to random port
        let listener = TcpListener::bind("0.0.0.0:0").await?;
        let addr = listener.local_addr()?;
        let port = addr.port();
        *self.local_port.lock().await = port;

        self.callback.on_log("INFO".to_string(), format!("TCP listener bound to port {}", port));

        // Start mDNS advertising
        let storage_clone = self.storage.clone();
        let callback_clone = self.callback.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::advertise_mdns(storage_clone, port, callback_clone).await {
                log::error!("mDNS advertising error: {}", e);
            }
        });

        // Start mDNS browsing
        let peer_addresses_clone = self.peer_addresses.clone();
        let callback_clone2 = self.callback.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::browse_mdns(peer_addresses_clone, callback_clone2).await {
                log::error!("mDNS browsing error: {}", e);
            }
        });

        // Accept loop
        let storage_clone2 = self.storage.clone();
        let callback_clone3 = self.callback.clone();
        let peer_addresses_clone2 = self.peer_addresses.clone();
        let active_connections_clone = self.active_connections.clone();

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        let storage = storage_clone2.clone();
                        let callback = callback_clone3.clone();
                        let peer_addresses = peer_addresses_clone2.clone();
                        let active_connections = active_connections_clone.clone();
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_connection(
                                stream,
                                peer_addr,
                                storage,
                                callback,
                                peer_addresses,
                                active_connections,
                            )
                            .await
                            {
                                log::error!("Connection error with {}: {}", peer_addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        log::error!("Accept failed: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    async fn advertise_mdns(
        storage: Arc<Storage>,
        port: u16,
        callback: Arc<dyn LoomCallback>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let seed = match storage.get_self_seed()? {
            Some(s) => s,
            None => return Ok(()),
        };
        let keys = derive_keys(&seed);
        let id_pub = keys.identity_key.verifying_key().to_bytes();
        let peer_id_hex = hex::encode(id_pub);

        let daemon = ServiceDaemon::new()?;
        let service_type = "_loom._tcp.local.";
        let instance_name = format!("loom-{}", peer_id_hex);
        let host_name = format!("{}.local.", instance_name);

        let service_info = ServiceInfo::new(
            service_type,
            &instance_name,
            &host_name,
            "127.0.0.1", // mDNS crate resolves interface IPs automatically
            port,
            HashMap::new(),
        )?;

        daemon.register(service_info)?;
        callback.on_log("INFO".to_string(), format!("mDNS registered service: {}", instance_name));

        // Sleep to keep daemon alive
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
        }
    }

    async fn browse_mdns(
        peer_addresses: Arc<Mutex<HashMap<Vec<u8>, SocketAddr>>>,
        callback: Arc<dyn LoomCallback>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let daemon = ServiceDaemon::new()?;
        let service_type = "_loom._tcp.local.";
        let receiver = daemon.browse(service_type)?;

        callback.on_log("INFO".to_string(), "Starting mDNS browsing...".to_string());

        while let Ok(event) = receiver.recv_async().await {
            match event {
                ServiceEvent::ServiceResolved(info) => {
                    let instance_name = info.get_fullname();
                    // Instance name starts with "loom-<pubkey-hex>"
                    let parts: Vec<&str> = instance_name.split('.').next().unwrap_or("").split('-').collect();
                    if parts.len() >= 2 && parts[0] == "loom" {
                        let peer_key_hex = parts[1];
                        if let Ok(peer_key) = hex::decode(peer_key_hex) {
                            let addrs = info.get_addresses();
                            if let Some(ip) = addrs.iter().next() {
                                let port = info.get_port();
                                let addr = SocketAddr::new(*ip, port);
                                
                                peer_addresses.lock().await.insert(peer_key.clone(), addr);
                                callback.on_peer_discovered(
                                    peer_key,
                                    ip.to_string(),
                                    port,
                                );
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn handle_connection(
        mut stream: TcpStream,
        peer_addr: SocketAddr,
        storage: Arc<Storage>,
        callback: Arc<dyn LoomCallback>,
        peer_addresses: Arc<Mutex<HashMap<Vec<u8>, SocketAddr>>>,
        active_connections: Arc<Mutex<HashMap<Vec<u8>, Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>>>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        callback.on_log("INFO".to_string(), format!("Accepted connection from {}", peer_addr));

        // Read first message
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;

        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload).await?;

        let wire_msg: WireMessage = serde_json::from_slice(&payload)?;

        match wire_msg {
            WireMessage::Initiator(init) => {
                let seed = storage.get_self_seed()?.ok_or("No identity seed")?;
                let local_keys = derive_keys(&seed);

                // Verify initiator identity signature
                let initiator_id_verifying = VerifyingKey::from_bytes(&init.sender_identity)?;
                let mut sig_payload = Vec::new();
                sig_payload.extend_from_slice(&init.ephemeral_key);
                sig_payload.extend_from_slice(&local_keys.identity_key.verifying_key().to_bytes());

                let sig = ed25519_dalek::Signature::from_slice(&init.signature)?;
                initiator_id_verifying.verify(&sig_payload, &sig)?;

                // Generate responder ephemeral X25519 keypair
                let mut resp_ephemeral_bytes = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut resp_ephemeral_bytes);
                let resp_ephemeral_secret = XStaticSecret::from(resp_ephemeral_bytes);
                let resp_ephemeral_pub = XPublicKey::from(&resp_ephemeral_secret);

                // Compute 3DH shared root key
                let peer_dh_pk = XPublicKey::from(init.sender_dh);
                let peer_ephemeral_pk = XPublicKey::from(init.ephemeral_key);

                let shared_root = compute_3dh_responder(
                    &local_keys.dh_secret,
                    &resp_ephemeral_secret,
                    &peer_dh_pk,
                    &peer_ephemeral_pk,
                );

                // Create Double Ratchet session (passive)
                let ratchet = DoubleRatchetSession::initialize_passive(resp_ephemeral_secret, peer_ephemeral_pk, shared_root);
                let state_bytes = ratchet.to_bytes()?;
                storage.save_ratchet_state(&init.sender_identity, &state_bytes)?;
                storage.add_contact(
                    &init.sender_identity,
                    &init.sender_dh,
                    &format!("Loom Contact {}", &hex::encode(init.sender_identity)[..8])
                )?;
                peer_addresses.lock().await.insert(init.sender_identity.to_vec(), peer_addr);

                // Create responder handshake packet
                let mut resp_sig_payload = Vec::new();
                resp_sig_payload.extend_from_slice(resp_ephemeral_pub.as_bytes());
                resp_sig_payload.extend_from_slice(&init.ephemeral_key);
                let resp_signature = local_keys.identity_key.sign(&resp_sig_payload);

                let resp = HandshakeResponder {
                    ephemeral_key: *resp_ephemeral_pub.as_bytes(),
                    signature: resp_signature.to_bytes().to_vec(),
                };

                let resp_payload = serde_json::to_vec(&WireMessage::Responder(resp))?;
                let resp_len = (resp_payload.len() as u32).to_be_bytes();
                stream.write_all(&resp_len).await?;
                stream.write_all(&resp_payload).await?;

                callback.on_session_established(init.sender_identity.to_vec());

                // Save active stream
                let (read_half, write_half) = stream.into_split();
                let shared_writer = Arc::new(Mutex::new(write_half));
                active_connections.lock().await.insert(init.sender_identity.to_vec(), shared_writer.clone());

                // Start reader loop
                Self::start_chat_reader(
                    read_half,
                    init.sender_identity,
                    storage,
                    callback,
                    active_connections,
                ).await;
            }
            WireMessage::Chat(env) => {
                let mut unsigned_env = env.clone();
                unsigned_env.signature = Vec::new();
                let serialized_unsigned = serde_json::to_vec(&unsigned_env)?;

                let sig = ed25519_dalek::Signature::from_slice(&env.signature)?;

                // Find contact whose public key verifies the signature
                let contacts = storage.get_contacts()?;
                let mut found_peer = None;
                for (pub_key_vec, _) in contacts {
                    if let Ok(verifying_key) = VerifyingKey::from_bytes(&pub_key_vec.clone().try_into().unwrap_or([0u8; 32])) {
                        if verifying_key.verify(&serialized_unsigned, &sig).is_ok() {
                            found_peer = Some(pub_key_vec);
                            break;
                        }
                    }
                }

                let peer_pub_key = found_peer.ok_or("Unknown sender signature")?;
                let peer_pub_key_32: [u8; 32] = peer_pub_key.clone().try_into().map_err(|_| "Invalid peer pub key length")?;

                // Load ratchet state
                let state_bytes = storage.get_ratchet_state(&peer_pub_key_32)?.ok_or("No ratchet state")?;
                let mut ratchet = DoubleRatchetSession::from_bytes(&state_bytes)?;

                let peer_dh = XPublicKey::from(env.peer_dh_pub);

                // Associated data is message_id + peer_dh_pub + n + pn
                let mut associated_data = Vec::new();
                associated_data.extend_from_slice(env.message_id.as_bytes());
                associated_data.extend_from_slice(&env.peer_dh_pub);
                associated_data.extend_from_slice(&env.n.to_be_bytes());
                associated_data.extend_from_slice(&env.pn.to_be_bytes());

                let plaintext = ratchet.decrypt(
                    &env.ciphertext,
                    &env.nonce,
                    peer_dh,
                    env.n,
                    env.pn,
                    &associated_data,
                )?;

                let content = String::from_utf8_lossy(&plaintext).into_owned();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;

                let self_seed = storage.get_self_seed()?.ok_or("No identity seed")?;
                let self_keys = derive_keys(&self_seed);
                let self_identity = self_keys.identity_key.verifying_key().to_bytes();

                let _ = storage.save_message(
                    &env.message_id,
                    &peer_pub_key_32,
                    &peer_pub_key_32,
                    &self_identity,
                    &content,
                    now,
                    false,
                );

                // Save new ratchet state
                let new_state_bytes = ratchet.to_bytes()?;
                storage.save_ratchet_state(&peer_pub_key_32, &new_state_bytes)?;

                callback.on_message_received(
                    peer_pub_key_32.to_vec(),
                    env.message_id,
                    content,
                    now,
                );

                // Update peer address map to the actual peer_addr of this incoming connection
                peer_addresses.lock().await.insert(peer_pub_key_32.to_vec(), peer_addr);

                // Save connection
                let (read_half, write_half) = stream.into_split();
                let shared_writer = Arc::new(Mutex::new(write_half));
                active_connections.lock().await.insert(peer_pub_key_32.to_vec(), shared_writer.clone());

                // Start reader loop for subsequent messages
                Self::start_chat_reader(
                    read_half,
                    peer_pub_key_32,
                    storage,
                    callback,
                    active_connections,
                ).await;
            }
            _ => {}
        }

        Ok(())
    }

    async fn start_chat_reader(
        mut read_half: tokio::net::tcp::OwnedReadHalf,
        peer_identity: [u8; 32],
        storage: Arc<Storage>,
        callback: Arc<dyn LoomCallback>,
        active_connections: Arc<Mutex<HashMap<Vec<u8>, Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>>>>,
    ) {
        loop {
            let mut len_buf = [0u8; 4];
            if read_half.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let len = u32::from_be_bytes(len_buf) as usize;

            let mut payload = vec![0u8; len];
            if read_half.read_exact(&mut payload).await.is_err() {
                break;
            }

            // Load contact's ratchet state
            let ratchet_bytes = match storage.get_ratchet_state(&peer_identity) {
                Ok(Some(bytes)) => bytes,
                _ => break,
            };

            let mut ratchet = match DoubleRatchetSession::from_bytes(&ratchet_bytes) {
                Ok(r) => r,
                _ => break,
            };

            let verifying_key = match VerifyingKey::from_bytes(&peer_identity) {
                Ok(k) => k,
                _ => break,
            };

            match EncryptedEnvelope::verify_and_decrypt(&payload, &verifying_key, &mut ratchet) {
                Ok((msg_id, plaintext)) => {
                    let content = String::from_utf8_lossy(&plaintext).into_owned();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64;
                    
                    let _ = storage.save_message(
                        &msg_id,
                        &peer_identity,
                        &peer_identity,
                        &verifying_key.to_bytes(),
                        &content,
                        now,
                        false,
                    );

                    // Save new ratchet state
                    if let Ok(new_state_bytes) = ratchet.to_bytes() {
                        let _ = storage.save_ratchet_state(&peer_identity, &new_state_bytes);
                    }

                    callback.on_message_received(
                        peer_identity.to_vec(),
                        msg_id,
                        content,
                        now,
                    );
                }
                Err(e) => {
                    log::error!("Decrypt failed: {:?}", e);
                }
            }
        }

        active_connections.lock().await.remove(peer_identity.as_slice());
        callback.on_log("INFO".to_string(), format!("Connection closed for peer {}", hex::encode(peer_identity)));
    }

    pub async fn send_chat_message(
        &self,
        peer_identity: &[u8; 32],
        content: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let seed = self.storage.get_self_seed()?.ok_or("No seed")?;
        let local_keys = derive_keys(&seed);

        // Get ratchet state
        let state_bytes = self.storage.get_ratchet_state(peer_identity)?.ok_or("No ratchet session established")?;
        let mut ratchet = DoubleRatchetSession::from_bytes(&state_bytes)?;

        // Associated data
        let msg_id = uuid::Uuid::new_v4().to_string();

        // Encrypt with ratchet
        let (ciphertext, nonce, dh_pub, n, pn) = ratchet.encrypt(content.as_bytes(), msg_id.as_bytes())?;
        
        // Save ratchet state back
        let new_state_bytes = ratchet.to_bytes()?;
        self.storage.save_ratchet_state(peer_identity, &new_state_bytes)?;

        let wire_payload = EncryptedEnvelope::sign_and_serialize(
            msg_id.clone(),
            dh_pub,
            n,
            pn,
            ciphertext,
            nonce,
            &local_keys.identity_key,
        )?;

        // Send over TCP connection
        let mut connections = self.active_connections.lock().await;
        let mut stream_opt = connections.get(peer_identity.as_slice()).cloned();

        if stream_opt.is_none() {
            // Establish new connection
            let addr = self.peer_addresses.lock().await.get(peer_identity.as_slice()).cloned().ok_or("Peer offline or undiscovered")?;
            let stream = TcpStream::connect(addr).await?;
            let (read_half, write_half) = stream.into_split();
            let shared_writer = Arc::new(Mutex::new(write_half));
            connections.insert(peer_identity.to_vec(), shared_writer.clone());
            stream_opt = Some(shared_writer.clone());
            
            // Re-establish session read loop
            let storage = self.storage.clone();
            let callback = self.callback.clone();
            let connections_clone = self.active_connections.clone();
            let peer_id_clone = *peer_identity;
            tokio::spawn(async move {
                Self::start_chat_reader(read_half, peer_id_clone, storage, callback, connections_clone).await;
            });
        }

        let stream_shared = stream_opt.unwrap();
        let mut stream = stream_shared.lock().await;
        let len_bytes = (wire_payload.len() as u32).to_be_bytes();
        let mut write_res = stream.write_all(&len_bytes).await;
        if write_res.is_ok() {
            write_res = stream.write_all(&wire_payload).await;
        }
        
        if write_res.is_err() {
            // Write failed. Connection is dead or roamed. Let's reconnect once.
            drop(stream);
            connections.remove(peer_identity.as_slice());
            
            let addr = self.peer_addresses.lock().await.get(peer_identity.as_slice()).cloned().ok_or("Peer offline or undiscovered")?;
            let new_stream = TcpStream::connect(addr).await?;
            let (read_half, write_half) = new_stream.into_split();
            let shared_writer = Arc::new(Mutex::new(write_half));
            connections.insert(peer_identity.to_vec(), shared_writer.clone());
            
            let storage = self.storage.clone();
            let callback = self.callback.clone();
            let connections_clone = self.active_connections.clone();
            let peer_id_clone = *peer_identity;
            tokio::spawn(async move {
                Self::start_chat_reader(read_half, peer_id_clone, storage, callback, connections_clone).await;
            });
            
            let mut stream_lock = shared_writer.lock().await;
            stream_lock.write_all(&len_bytes).await?;
            stream_lock.write_all(&wire_payload).await?;
        }

        // Save sent message to local DB
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        self.storage.save_message(
            &msg_id,
            peer_identity,
            &local_keys.identity_key.verifying_key().to_bytes(),
            peer_identity,
            content,
            now,
            true,
        )?;

        Ok(msg_id)
    }

    pub async fn initiate_handshake(
        &self,
        peer_identity: &[u8; 32],
        peer_dh: &[u8; 32],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let seed = self.storage.get_self_seed()?.ok_or("No seed")?;
        let local_keys = derive_keys(&seed);

        // Generate initiator ephemeral key
        let mut init_ephemeral_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut init_ephemeral_bytes);
        let init_ephemeral_secret = XStaticSecret::from(init_ephemeral_bytes);
        let init_ephemeral_pub = XPublicKey::from(&init_ephemeral_secret);

        // Sign (ephemeral_key + recipient_identity)
        let mut sig_payload = Vec::new();
        sig_payload.extend_from_slice(init_ephemeral_pub.as_bytes());
        sig_payload.extend_from_slice(peer_identity);
        let signature = local_keys.identity_key.sign(&sig_payload);

        let init = HandshakeInitiator {
            sender_identity: local_keys.identity_key.verifying_key().to_bytes(),
            sender_dh: *local_keys.dh_public.as_bytes(),
            ephemeral_key: *init_ephemeral_pub.as_bytes(),
            signature: signature.to_bytes().to_vec(),
        };

        let payload = serde_json::to_vec(&WireMessage::Initiator(init))?;
        let len_bytes = (payload.len() as u32).to_be_bytes();

        let addr = self.peer_addresses.lock().await.get(peer_identity.as_slice()).cloned().ok_or("Peer offline or undiscovered")?;
        let mut stream = TcpStream::connect(addr).await?;
        stream.write_all(&len_bytes).await?;
        stream.write_all(&payload).await?;

        // Read response
        let mut resp_len_buf = [0u8; 4];
        stream.read_exact(&mut resp_len_buf).await?;
        let resp_len = u32::from_be_bytes(resp_len_buf) as usize;

        let mut resp_payload = vec![0u8; resp_len];
        stream.read_exact(&mut resp_payload).await?;

        let wire_msg: WireMessage = serde_json::from_slice(&resp_payload)?;
        match wire_msg {
            WireMessage::Responder(resp) => {
                // Verify responder signature
                let responder_id_verifying = VerifyingKey::from_bytes(peer_identity)?;
                let mut resp_sig_payload = Vec::new();
                resp_sig_payload.extend_from_slice(&resp.ephemeral_key);
                resp_sig_payload.extend_from_slice(init_ephemeral_pub.as_bytes());

                let sig = ed25519_dalek::Signature::from_slice(&resp.signature)?;
                responder_id_verifying.verify(&resp_sig_payload, &sig)?;

                // Compute 3DH shared root key
                let peer_dh_pk = XPublicKey::from(*peer_dh);
                let peer_ephemeral_pk = XPublicKey::from(resp.ephemeral_key);

                let shared_root = compute_3dh_initiator(
                    &local_keys.dh_secret,
                    &init_ephemeral_secret,
                    &peer_dh_pk,
                    &peer_ephemeral_pk,
                );

                // Create Double Ratchet session (active)
                let ratchet = DoubleRatchetSession::initialize_active(init_ephemeral_secret, peer_ephemeral_pk, shared_root);
                let state_bytes = ratchet.to_bytes()?;
                self.storage.save_ratchet_state(peer_identity, &state_bytes)?;

                self.callback.on_session_established(peer_identity.to_vec());

                // Save active stream
                let (read_half, write_half) = stream.into_split();
                let shared_writer = Arc::new(Mutex::new(write_half));
                self.active_connections.lock().await.insert(peer_identity.to_vec(), shared_writer.clone());

                // Start reader loop
                let storage = self.storage.clone();
                let callback = self.callback.clone();
                let connections_clone = self.active_connections.clone();
                let peer_id_clone = *peer_identity;
                tokio::spawn(async move {
                    Self::start_chat_reader(read_half, peer_id_clone, storage, callback, connections_clone).await;
                });
            }
            _ => return Err("Unexpected response".into()),
        }

        Ok(())
    }
}
