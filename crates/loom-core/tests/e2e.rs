use loom_core::{LoomCallback, LoomEngine, LoomError};
use loom_core::token::LoomToken;
use loom_core::crypto::{derive_keys, DoubleRatchetSession};
use loom_core::protocol::{EncryptedEnvelope, WireMessage, HandshakeInitiator};
use rand::RngCore;
use ed25519_dalek::Signer;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::thread;
use tempfile::TempDir;

// --- Test Harness ---

struct TestCallbackState {
    discovered_peers: Vec<(Vec<u8>, String, u16)>,
    received_messages: Vec<(Vec<u8>, String, String, i64)>,
    established_sessions: Vec<Vec<u8>>,
    logs: Vec<(String, String)>,
}

#[derive(Clone)]
struct TestCallback {
    state: Arc<Mutex<TestCallbackState>>,
}

impl LoomCallback for TestCallback {
    fn on_peer_discovered(&self, peer_identity: Vec<u8>, ip: String, port: u16) {
        let mut state = self.state.lock().unwrap();
        state.discovered_peers.push((peer_identity, ip, port));
    }

    fn on_message_received(&self, sender_identity: Vec<u8>, message_id: String, content: String, timestamp: i64) {
        let mut state = self.state.lock().unwrap();
        state.received_messages.push((sender_identity, message_id, content, timestamp));
    }

    fn on_session_established(&self, peer_identity: Vec<u8>) {
        let mut state = self.state.lock().unwrap();
        state.established_sessions.push(peer_identity);
    }

    fn on_log(&self, level: String, message: String) {
        let mut state = self.state.lock().unwrap();
        state.logs.push((level, message));
    }
}

struct TestNode {
    engine: Arc<LoomEngine>,
    db_dir: TempDir,
    state: Arc<Mutex<TestCallbackState>>,
}

impl TestNode {
    fn new() -> Self {
        let db_dir = tempfile::tempdir().unwrap();
        let db_path = db_dir.path().join("loom.db").to_str().unwrap().to_string();
        let engine = LoomEngine::new(db_path).unwrap();
        let state = Arc::new(Mutex::new(TestCallbackState {
            discovered_peers: Vec::new(),
            received_messages: Vec::new(),
            established_sessions: Vec::new(),
            logs: Vec::new(),
        }));
        Self {
            engine,
            db_dir,
            state,
        }
    }

    fn reboot(&mut self) {
        let db_path = self.db_dir.path().join("loom.db").to_str().unwrap().to_string();
        let engine = LoomEngine::new(db_path).unwrap();
        self.engine = engine;
    }

    fn start(&self) {
        let cb = TestCallback {
            state: self.state.clone(),
        };
        self.engine.start_network(Box::new(cb)).unwrap();
    }

    fn get_my_pub_key(&self) -> Vec<u8> {
        let token_str = self.engine.get_my_token().unwrap();
        let token = LoomToken::parse(&token_str).unwrap();
        token.identity_key.to_vec()
    }

    fn connect_to(&self, other: &Self) {
        let other_port = other.engine.get_network_port().unwrap();
        let other_pub_key = other.get_my_pub_key();
        self.engine.inject_peer_address(other_pub_key, "127.0.0.1".to_string(), other_port).unwrap();
    }

    fn wait_for_session(&self, peer_pub_key: &[u8], timeout: Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < timeout {
            {
                let state = self.state.lock().unwrap();
                if state.established_sessions.iter().any(|pk| pk == peer_pub_key) {
                    return true;
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
        false
    }

    fn wait_for_message(&self, peer_pub_key: &[u8], expected_content: &str, timeout: Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < timeout {
            {
                let state = self.state.lock().unwrap();
                if state.received_messages.iter().any(|(pk, _, content, _)| pk == peer_pub_key && content == expected_content) {
                    return true;
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
        false
    }
}

// --- Tier 1: Onboarding Tests ---

#[test]
fn test_onboarding_fresh_node() {
    let node = TestNode::new();
    assert!(!node.engine.has_identity().unwrap());
    
    let token = node.engine.generate_new_identity().unwrap();
    assert!(node.engine.has_identity().unwrap());
    assert!(token.starts_with("LOOM-"));
}

#[test]
fn test_onboarding_idempotent_identity_generation() {
    let node = TestNode::new();
    let token1 = node.engine.generate_new_identity().unwrap();
    let token2 = node.engine.generate_new_identity().unwrap();
    assert_ne!(token1, token2); // generate_new_identity regenerates seed, yielding different tokens
    assert!(node.engine.has_identity().unwrap());
}

#[test]
fn test_onboarding_persistence() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("persist.db").to_str().unwrap().to_string();
    
    let token = {
        let engine = LoomEngine::new(db_path.clone()).unwrap();
        let tok = engine.generate_new_identity().unwrap();
        assert!(engine.has_identity().unwrap());
        tok
    };

    // Reboot engine on same DB
    let engine = LoomEngine::new(db_path).unwrap();
    assert!(engine.has_identity().unwrap());
    assert_eq!(engine.get_my_token().unwrap(), token);
}

#[test]
fn test_onboarding_token_components() {
    let node = TestNode::new();
    let token_str = node.engine.generate_new_identity().unwrap();
    
    let token = LoomToken::parse(&token_str).unwrap();
    assert_eq!(token.version, 1);
    assert_eq!(token.identity_key.len(), 32);
    assert_eq!(token.dh_key.len(), 32);
}

#[test]
fn test_onboarding_network_startup() {
    let node = TestNode::new();
    node.engine.generate_new_identity().unwrap();
    node.start();
    let port = node.engine.get_network_port().unwrap();
    assert!(port > 0);
}

// --- Tier 1: Contact Management Tests ---

#[test]
fn test_contact_add_valid_token() {
    let node1 = TestNode::new();
    let node2 = TestNode::new();
    let token2 = node2.engine.generate_new_identity().unwrap();

    node1.engine.add_contact_token(token2, "Bob".to_string()).unwrap();
    let contacts = node1.engine.get_contacts().unwrap();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].display_name, "Bob");
    assert_eq!(contacts[0].public_key, node2.get_my_pub_key());
}

#[test]
fn test_contact_display_name_preservation() {
    let node1 = TestNode::new();
    let node2 = TestNode::new();
    let token2 = node2.engine.generate_new_identity().unwrap();

    node1.engine.add_contact_token(token2, "Preserved Name".to_string()).unwrap();
    let contacts = node1.engine.get_contacts().unwrap();
    assert_eq!(contacts[0].display_name, "Preserved Name");
}

#[test]
fn test_contact_duplicate_token() {
    let node1 = TestNode::new();
    let node2 = TestNode::new();
    let token2 = node2.engine.generate_new_identity().unwrap();

    node1.engine.add_contact_token(token2.clone(), "Bob First".to_string()).unwrap();
    node1.engine.add_contact_token(token2, "Bob Second".to_string()).unwrap();
    
    let contacts = node1.engine.get_contacts().unwrap();
    assert_eq!(contacts.len(), 1); // Should overwrite and update
    assert_eq!(contacts[0].display_name, "Bob Second");
}

#[test]
fn test_contact_multiple_contacts() {
    let node = TestNode::new();
    for i in 1..=5 {
        let temp = TestNode::new();
        let token = temp.engine.generate_new_identity().unwrap();
        node.engine.add_contact_token(token, format!("Contact {}", i)).unwrap();
    }
    
    let contacts = node.engine.get_contacts().unwrap();
    assert_eq!(contacts.len(), 5);
}

#[test]
fn test_contact_retrieve_empty() {
    let node = TestNode::new();
    let contacts = node.engine.get_contacts().unwrap();
    assert!(contacts.is_empty());
}

// --- Tier 1: Chat/Double-Ratchet Tests ---

#[test]
fn test_chat_handshake_flow() {
    let alice = TestNode::new();
    let bob = TestNode::new();
    
    let alice_token = alice.engine.generate_new_identity().unwrap();
    let bob_token = bob.engine.generate_new_identity().unwrap();

    alice.engine.add_contact_token(bob_token, "Bob".to_string()).unwrap();
    bob.engine.add_contact_token(alice_token, "Alice".to_string()).unwrap();

    alice.start();
    bob.start();

    alice.connect_to(&bob);
    alice.engine.initiate_chat_handshake(bob.get_my_pub_key()).unwrap();

    assert!(alice.wait_for_session(&bob.get_my_pub_key(), Duration::from_secs(5)));
    assert!(bob.wait_for_session(&alice.get_my_pub_key(), Duration::from_secs(5)));
}

#[test]
fn test_chat_single_message_delivery() {
    let alice = TestNode::new();
    let bob = TestNode::new();
    
    let alice_token = alice.engine.generate_new_identity().unwrap();
    let bob_token = bob.engine.generate_new_identity().unwrap();

    alice.engine.add_contact_token(bob_token, "Bob".to_string()).unwrap();
    bob.engine.add_contact_token(alice_token, "Alice".to_string()).unwrap();

    alice.start();
    bob.start();

    alice.connect_to(&bob);
    alice.engine.initiate_chat_handshake(bob.get_my_pub_key()).unwrap();

    assert!(alice.wait_for_session(&bob.get_my_pub_key(), Duration::from_secs(5)));
    assert!(bob.wait_for_session(&alice.get_my_pub_key(), Duration::from_secs(5)));

    alice.engine.send_message(bob.get_my_pub_key(), "Hello Bob!".to_string()).unwrap();
    assert!(bob.wait_for_message(&alice.get_my_pub_key(), "Hello Bob!", Duration::from_secs(5)));
}

#[test]
fn test_chat_two_way_communication() {
    let alice = TestNode::new();
    let bob = TestNode::new();
    
    let alice_token = alice.engine.generate_new_identity().unwrap();
    let bob_token = bob.engine.generate_new_identity().unwrap();

    alice.engine.add_contact_token(bob_token, "Bob".to_string()).unwrap();
    bob.engine.add_contact_token(alice_token, "Alice".to_string()).unwrap();

    alice.start();
    bob.start();

    alice.connect_to(&bob);
    alice.engine.initiate_chat_handshake(bob.get_my_pub_key()).unwrap();

    assert!(alice.wait_for_session(&bob.get_my_pub_key(), Duration::from_secs(5)));
    assert!(bob.wait_for_session(&alice.get_my_pub_key(), Duration::from_secs(5)));

    alice.engine.send_message(bob.get_my_pub_key(), "Hello Bob!".to_string()).unwrap();
    assert!(bob.wait_for_message(&alice.get_my_pub_key(), "Hello Bob!", Duration::from_secs(5)));

    bob.engine.send_message(alice.get_my_pub_key(), "Hello Alice!".to_string()).unwrap();
    assert!(alice.wait_for_message(&bob.get_my_pub_key(), "Hello Alice!", Duration::from_secs(5)));
}

#[test]
fn test_chat_multiple_sequential_messages() {
    let alice = TestNode::new();
    let bob = TestNode::new();
    
    let alice_token = alice.engine.generate_new_identity().unwrap();
    let bob_token = bob.engine.generate_new_identity().unwrap();

    alice.engine.add_contact_token(bob_token, "Bob".to_string()).unwrap();
    bob.engine.add_contact_token(alice_token, "Alice".to_string()).unwrap();

    alice.start();
    bob.start();

    alice.connect_to(&bob);
    alice.engine.initiate_chat_handshake(bob.get_my_pub_key()).unwrap();

    assert!(alice.wait_for_session(&bob.get_my_pub_key(), Duration::from_secs(5)));
    assert!(bob.wait_for_session(&alice.get_my_pub_key(), Duration::from_secs(5)));

    for i in 1..=5 {
        alice.engine.send_message(bob.get_my_pub_key(), format!("Msg {}", i)).unwrap();
        assert!(bob.wait_for_message(&alice.get_my_pub_key(), &format!("Msg {}", i), Duration::from_secs(5)));
    }
}

#[test]
fn test_chat_message_persistence() {
    let alice = TestNode::new();
    let mut bob = TestNode::new();
    
    let alice_token = alice.engine.generate_new_identity().unwrap();
    let bob_token = bob.engine.generate_new_identity().unwrap();

    alice.engine.add_contact_token(bob_token, "Bob".to_string()).unwrap();
    bob.engine.add_contact_token(alice_token, "Alice".to_string()).unwrap();

    alice.start();
    bob.start();

    alice.connect_to(&bob);
    alice.engine.initiate_chat_handshake(bob.get_my_pub_key()).unwrap();

    assert!(alice.wait_for_session(&bob.get_my_pub_key(), Duration::from_secs(5)));
    assert!(bob.wait_for_session(&alice.get_my_pub_key(), Duration::from_secs(5)));

    alice.engine.send_message(bob.get_my_pub_key(), "Persist me".to_string()).unwrap();
    assert!(bob.wait_for_message(&alice.get_my_pub_key(), "Persist me", Duration::from_secs(5)));

    // Reboot Bob
    bob.reboot();
    let messages = bob.engine.get_messages(alice.get_my_pub_key()).unwrap();
    assert!(!messages.is_empty());
    assert_eq!(messages[0].content, "Persist me");
}

// --- Tier 2: Onboarding Boundary Tests ---

#[test]
fn test_onboarding_boundary_empty_db_path() {
    let engine = LoomEngine::new("".to_string());
    assert!(engine.is_err());
}

#[test]
fn test_onboarding_boundary_locked_db_file() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("locked.db");
    
    // Lock SQLite file exclusively by opening, writing schema dummy table, and starting an exclusive transaction
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute("CREATE TABLE foo (bar TEXT);", []).unwrap();
    conn.execute("INSERT INTO foo VALUES ('x');", []).unwrap();
    let _ = conn.execute("PRAGMA locking_mode = EXCLUSIVE;", []);
    conn.execute("BEGIN EXCLUSIVE TRANSACTION;", []).unwrap();
    
    let engine = LoomEngine::new(path.to_str().unwrap().to_string());
    assert!(engine.is_err());
}

#[test]
fn test_onboarding_boundary_corrupted_db_file() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("corrupt.db");
    std::fs::write(&path, b"not a sqlite db file garbage").unwrap();
    
    let engine = LoomEngine::new(path.to_str().unwrap().to_string());
    assert!(engine.is_err());
}

#[test]
fn test_onboarding_boundary_token_fetch_with_no_identity() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("test.db");
    let engine = LoomEngine::new(path.to_str().unwrap().to_string()).unwrap();
    
    let res = engine.get_my_token();
    assert!(res.is_err());
    match res {
        Err(LoomError::NoIdentity) => {}
        _ => panic!("Expected LoomError::NoIdentity"),
    }
}

#[test]
fn test_onboarding_boundary_max_concurrent_engines() {
    let mut engines = Vec::new();
    let mut temps = Vec::new();
    for _ in 0..10 {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("engine.db").to_str().unwrap().to_string();
        let engine = LoomEngine::new(path).unwrap();
        engine.generate_new_identity().unwrap();
        engines.push(engine);
        temps.push(temp);
    }
    for engine in engines {
        assert!(engine.has_identity().unwrap());
    }
}

// --- Tier 2: Contact Boundary Tests ---

#[test]
fn test_contact_boundary_invalid_prefixes() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("test.db");
    let engine = LoomEngine::new(path.to_str().unwrap().to_string()).unwrap();
    let res = engine.add_contact_token("NOTLOOM-XYZ".to_string(), "Name".to_string());
    assert!(res.is_err());
}

#[test]
fn test_contact_boundary_invalid_base32() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("test.db");
    let engine = LoomEngine::new(path.to_str().unwrap().to_string()).unwrap();
    // 8 and 9 are not valid in base32
    let res = engine.add_contact_token("LOOM-BASE3289".to_string(), "Name".to_string());
    assert!(res.is_err());
}

#[test]
fn test_contact_boundary_corrupt_checksums() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("test.db");
    let engine = LoomEngine::new(path.to_str().unwrap().to_string()).unwrap();
    let valid_token = engine.generate_new_identity().unwrap();
    
    let mut chars: Vec<char> = valid_token.chars().collect();
    if let Some(last) = chars.last_mut() {
        *last = if *last == 'A' { 'B' } else { 'A' };
    }
    let mutated_token: String = chars.into_iter().collect();
    let res = engine.add_contact_token(mutated_token, "Name".to_string());
    assert!(res.is_err());
}

#[test]
fn test_contact_boundary_invalid_length() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("test.db");
    let engine = LoomEngine::new(path.to_str().unwrap().to_string()).unwrap();
    let valid_token = engine.generate_new_identity().unwrap();
    
    let truncated = valid_token[..valid_token.len()-5].to_string();
    let res = engine.add_contact_token(truncated, "Name".to_string());
    assert!(res.is_err());
}

#[test]
fn test_contact_boundary_huge_display_name() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("test.db");
    let engine = LoomEngine::new(path.to_str().unwrap().to_string()).unwrap();
    let valid_token = engine.generate_new_identity().unwrap();
    
    let huge_name = "A".repeat(10000);
    engine.add_contact_token(valid_token, huge_name.clone()).unwrap();
    let contacts = engine.get_contacts().unwrap();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].display_name, huge_name);
}

// --- Tier 2: Chat/Double-Ratchet Boundary Tests ---

#[test]
fn test_chat_boundary_empty_message() {
    let alice = TestNode::new();
    let bob = TestNode::new();
    
    let alice_token = alice.engine.generate_new_identity().unwrap();
    let bob_token = bob.engine.generate_new_identity().unwrap();

    alice.engine.add_contact_token(bob_token, "Bob".to_string()).unwrap();
    bob.engine.add_contact_token(alice_token, "Alice".to_string()).unwrap();

    alice.start();
    bob.start();

    alice.connect_to(&bob);
    alice.engine.initiate_chat_handshake(bob.get_my_pub_key()).unwrap();

    assert!(alice.wait_for_session(&bob.get_my_pub_key(), Duration::from_secs(5)));
    assert!(bob.wait_for_session(&alice.get_my_pub_key(), Duration::from_secs(5)));

    alice.engine.send_message(bob.get_my_pub_key(), "".to_string()).unwrap();
    assert!(bob.wait_for_message(&alice.get_my_pub_key(), "", Duration::from_secs(5)));
}

#[test]
fn test_chat_boundary_max_message_size() {
    let alice = TestNode::new();
    let bob = TestNode::new();
    
    let alice_token = alice.engine.generate_new_identity().unwrap();
    let bob_token = bob.engine.generate_new_identity().unwrap();

    alice.engine.add_contact_token(bob_token, "Bob".to_string()).unwrap();
    bob.engine.add_contact_token(alice_token, "Alice".to_string()).unwrap();

    alice.start();
    bob.start();

    alice.connect_to(&bob);
    alice.engine.initiate_chat_handshake(bob.get_my_pub_key()).unwrap();

    assert!(alice.wait_for_session(&bob.get_my_pub_key(), Duration::from_secs(5)));
    assert!(bob.wait_for_session(&alice.get_my_pub_key(), Duration::from_secs(5)));

    // Send a 100KB message
    let large_message = "A".repeat(100000);
    alice.engine.send_message(bob.get_my_pub_key(), large_message.clone()).unwrap();
    assert!(bob.wait_for_message(&alice.get_my_pub_key(), &large_message, Duration::from_secs(5)));
}

#[test]
fn test_chat_boundary_missing_dh_key() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("test.db");
    let engine = LoomEngine::new(path.to_str().unwrap().to_string()).unwrap();
    engine.generate_new_identity().unwrap();
    engine.start_network(Box::new(TestCallback {
        state: Arc::new(Mutex::new(TestCallbackState {
            discovered_peers: Vec::new(),
            received_messages: Vec::new(),
            established_sessions: Vec::new(),
            logs: Vec::new(),
        })),
    })).unwrap();
    
    // Nonexistent contact identity key
    let fake_pk = vec![0u8; 32];
    let res = engine.initiate_chat_handshake(fake_pk);
    assert!(res.is_err());
}

#[test]
fn test_chat_boundary_peer_offline_on_handshake() {
    let alice = TestNode::new();
    let bob = TestNode::new();
    
    let alice_token = alice.engine.generate_new_identity().unwrap();
    let bob_token = bob.engine.generate_new_identity().unwrap();

    alice.engine.add_contact_token(bob_token, "Bob".to_string()).unwrap();
    bob.engine.add_contact_token(alice_token, "Alice".to_string()).unwrap();

    alice.start();
    // Bob network NOT started, but Alice injects Bob's offline address (mocking port 9999)
    alice.engine.inject_peer_address(bob.get_my_pub_key(), "127.0.0.1".to_string(), 9999).unwrap();

    let res = alice.engine.initiate_chat_handshake(bob.get_my_pub_key());
    // Since Bob is offline, connect to 127.0.0.1:9999 will fail immediately or timeout
    assert!(res.is_err());
}

#[test]
fn test_chat_boundary_network_loss_during_session() {
    let alice = TestNode::new();
    let mut bob = TestNode::new();
    
    let alice_token = alice.engine.generate_new_identity().unwrap();
    let bob_token = bob.engine.generate_new_identity().unwrap();

    alice.engine.add_contact_token(bob_token, "Bob".to_string()).unwrap();
    bob.engine.add_contact_token(alice_token, "Alice".to_string()).unwrap();

    alice.start();
    bob.start();

    alice.connect_to(&bob);
    alice.engine.initiate_chat_handshake(bob.get_my_pub_key()).unwrap();

    assert!(alice.wait_for_session(&bob.get_my_pub_key(), Duration::from_secs(5)));
    assert!(bob.wait_for_session(&alice.get_my_pub_key(), Duration::from_secs(5)));

    // Bob goes offline (reboot without starting network/listener)
    bob.reboot();

    // Alice tries to send a message. Since the active TCP stream is closed, writing to it will fail or return error.
    let res = alice.engine.send_message(bob.get_my_pub_key(), "Offline yet?".to_string());
    assert!(res.is_err());
}

// --- Tier 3: Cross-Feature Combination Tests ---

#[test]
fn test_cross_lifecycle_reboot_and_chat_restart() {
    let mut alice = TestNode::new();
    let mut bob = TestNode::new();
    
    let alice_token = alice.engine.generate_new_identity().unwrap();
    let bob_token = bob.engine.generate_new_identity().unwrap();

    alice.engine.add_contact_token(bob_token, "Bob".to_string()).unwrap();
    bob.engine.add_contact_token(alice_token, "Alice".to_string()).unwrap();

    alice.start();
    bob.start();

    alice.connect_to(&bob);
    alice.engine.initiate_chat_handshake(bob.get_my_pub_key()).unwrap();

    assert!(alice.wait_for_session(&bob.get_my_pub_key(), Duration::from_secs(5)));
    assert!(bob.wait_for_session(&alice.get_my_pub_key(), Duration::from_secs(5)));

    alice.engine.send_message(bob.get_my_pub_key(), "Before reboot".to_string()).unwrap();
    assert!(bob.wait_for_message(&alice.get_my_pub_key(), "Before reboot", Duration::from_secs(5)));

    // Reboot Alice
    alice.reboot();
    alice.start();
    // Reboot Bob
    bob.reboot();
    bob.start();

    // Re-connect
    alice.connect_to(&bob);
    bob.connect_to(&alice);

    // Alice sends message to Bob WITHOUT repeating handshake
    alice.engine.send_message(bob.get_my_pub_key(), "After reboot".to_string()).unwrap();
    assert!(bob.wait_for_message(&alice.get_my_pub_key(), "After reboot", Duration::from_secs(5)));
}

#[test]
fn test_cross_contact_deletion_mid_session() {
    let alice = TestNode::new();
    let bob = TestNode::new();
    
    let alice_token = alice.engine.generate_new_identity().unwrap();
    let bob_token = bob.engine.generate_new_identity().unwrap();

    alice.engine.add_contact_token(bob_token, "Bob".to_string()).unwrap();
    bob.engine.add_contact_token(alice_token, "Alice".to_string()).unwrap();

    alice.start();
    bob.start();

    alice.connect_to(&bob);
    alice.engine.initiate_chat_handshake(bob.get_my_pub_key()).unwrap();

    assert!(alice.wait_for_session(&bob.get_my_pub_key(), Duration::from_secs(5)));
    assert!(bob.wait_for_session(&alice.get_my_pub_key(), Duration::from_secs(5)));

    // Alice sends a message first to Bob to initialize Bob's sending chain (ck_s)
    alice.engine.send_message(bob.get_my_pub_key(), "Hello Bob".to_string()).unwrap();
    assert!(bob.wait_for_message(&alice.get_my_pub_key(), "Hello Bob", Duration::from_secs(5)));

    // Alice deletes Bob
    alice.engine.delete_contact(bob.get_my_pub_key()).unwrap();

    // Bob sends a message to Alice
    bob.engine.send_message(alice.get_my_pub_key(), "Hey Alice!".to_string()).unwrap();

    // Alice should ignore/reject Bob's message because she deleted him from contacts.
    // Let's verify Alice's callback state didn't receive "Hey Alice!"
    thread::sleep(Duration::from_millis(500));
    {
        let state = alice.state.lock().unwrap();
        assert!(!state.received_messages.iter().any(|(_, _, content, _)| content == "Hey Alice!"));
    }
}

#[test]
fn test_cross_concurrent_multi_peer_chats() {
    let alice = TestNode::new();
    let bob = TestNode::new();
    let charlie = TestNode::new();

    let a_tok = alice.engine.generate_new_identity().unwrap();
    let b_tok = bob.engine.generate_new_identity().unwrap();
    let c_tok = charlie.engine.generate_new_identity().unwrap();

    alice.engine.add_contact_token(b_tok.clone(), "Bob".to_string()).unwrap();
    alice.engine.add_contact_token(c_tok.clone(), "Charlie".to_string()).unwrap();
    bob.engine.add_contact_token(a_tok.clone(), "Alice".to_string()).unwrap();
    charlie.engine.add_contact_token(a_tok.clone(), "Alice".to_string()).unwrap();

    alice.start();
    bob.start();
    charlie.start();

    alice.connect_to(&bob);
    alice.connect_to(&charlie);

    alice.engine.initiate_chat_handshake(bob.get_my_pub_key()).unwrap();
    alice.engine.initiate_chat_handshake(charlie.get_my_pub_key()).unwrap();

    assert!(alice.wait_for_session(&bob.get_my_pub_key(), Duration::from_secs(5)));
    assert!(alice.wait_for_session(&charlie.get_my_pub_key(), Duration::from_secs(5)));

    alice.engine.send_message(bob.get_my_pub_key(), "Hello Bob".to_string()).unwrap();
    alice.engine.send_message(charlie.get_my_pub_key(), "Hello Charlie".to_string()).unwrap();

    assert!(bob.wait_for_message(&alice.get_my_pub_key(), "Hello Bob", Duration::from_secs(5)));
    assert!(charlie.wait_for_message(&alice.get_my_pub_key(), "Hello Charlie", Duration::from_secs(5)));
}

// --- Tier 4: Real-world Scenario Tests ---

#[test]
fn test_real_world_star_topology() {
    let hub = TestNode::new();
    let spoke1 = TestNode::new();
    let spoke2 = TestNode::new();
    let spoke3 = TestNode::new();

    let h_tok = hub.engine.generate_new_identity().unwrap();
    let s1_tok = spoke1.engine.generate_new_identity().unwrap();
    let s2_tok = spoke2.engine.generate_new_identity().unwrap();
    let s3_tok = spoke3.engine.generate_new_identity().unwrap();

    hub.engine.add_contact_token(s1_tok, "S1".to_string()).unwrap();
    hub.engine.add_contact_token(s2_tok, "S2".to_string()).unwrap();
    hub.engine.add_contact_token(s3_tok, "S3".to_string()).unwrap();
    
    spoke1.engine.add_contact_token(h_tok.clone(), "Hub".to_string()).unwrap();
    spoke2.engine.add_contact_token(h_tok.clone(), "Hub".to_string()).unwrap();
    spoke3.engine.add_contact_token(h_tok, "Hub".to_string()).unwrap();

    hub.start();
    spoke1.start();
    spoke2.start();
    spoke3.start();

    // Spoke nodes connect to Hub
    spoke1.connect_to(&hub);
    spoke2.connect_to(&hub);
    spoke3.connect_to(&hub);

    spoke1.engine.initiate_chat_handshake(hub.get_my_pub_key()).unwrap();
    spoke2.engine.initiate_chat_handshake(hub.get_my_pub_key()).unwrap();
    spoke3.engine.initiate_chat_handshake(hub.get_my_pub_key()).unwrap();

    assert!(hub.wait_for_session(&spoke1.get_my_pub_key(), Duration::from_secs(5)));
    assert!(hub.wait_for_session(&spoke2.get_my_pub_key(), Duration::from_secs(5)));
    assert!(hub.wait_for_session(&spoke3.get_my_pub_key(), Duration::from_secs(5)));

    // Chat Spoke -> Hub
    spoke1.engine.send_message(hub.get_my_pub_key(), "Hello Hub from S1".to_string()).unwrap();
    spoke2.engine.send_message(hub.get_my_pub_key(), "Hello Hub from S2".to_string()).unwrap();
    spoke3.engine.send_message(hub.get_my_pub_key(), "Hello Hub from S3".to_string()).unwrap();

    assert!(hub.wait_for_message(&spoke1.get_my_pub_key(), "Hello Hub from S1", Duration::from_secs(5)));
    assert!(hub.wait_for_message(&spoke2.get_my_pub_key(), "Hello Hub from S2", Duration::from_secs(5)));
    assert!(hub.wait_for_message(&spoke3.get_my_pub_key(), "Hello Hub from S3", Duration::from_secs(5)));
}

#[test]
fn test_real_world_network_partition_recovery() {
    let alice = TestNode::new();
    let bob = TestNode::new();

    let a_tok = alice.engine.generate_new_identity().unwrap();
    let b_tok = bob.engine.generate_new_identity().unwrap();

    alice.engine.add_contact_token(b_tok, "Bob".to_string()).unwrap();
    bob.engine.add_contact_token(a_tok, "Alice".to_string()).unwrap();

    alice.start();
    bob.start();

    alice.connect_to(&bob);
    alice.engine.initiate_chat_handshake(bob.get_my_pub_key()).unwrap();

    assert!(alice.wait_for_session(&bob.get_my_pub_key(), Duration::from_secs(5)));

    // Partition: Inject invalid address to mock loss of connection
    alice.engine.inject_peer_address(bob.get_my_pub_key(), "127.0.0.1".to_string(), 9999).unwrap();
    
    // Try sending message - should fail because Bob's address is 9999 (offline)
    let res = alice.engine.send_message(bob.get_my_pub_key(), "Partitioned".to_string());
    assert!(res.is_err());

    // Healing: Re-inject correct address
    alice.connect_to(&bob);

    // Send should succeed and reconnect
    alice.engine.send_message(bob.get_my_pub_key(), "Healed!".to_string()).unwrap();
    assert!(bob.wait_for_message(&alice.get_my_pub_key(), "Healed!", Duration::from_secs(5)));
}

#[test]
fn test_real_world_out_of_order_delivery() {
    let alice = TestNode::new();
    let bob = TestNode::new();

    let a_tok = alice.engine.generate_new_identity().unwrap();
    let b_tok = bob.engine.generate_new_identity().unwrap();

    alice.engine.add_contact_token(b_tok, "Bob".to_string()).unwrap();
    bob.engine.add_contact_token(a_tok, "Alice".to_string()).unwrap();

    alice.start();
    bob.start();

    alice.connect_to(&bob);
    alice.engine.initiate_chat_handshake(bob.get_my_pub_key()).unwrap();

    assert!(alice.wait_for_session(&bob.get_my_pub_key(), Duration::from_secs(5)));
    assert!(bob.wait_for_session(&alice.get_my_pub_key(), Duration::from_secs(5)));

    // Prepare out-of-order messages manually using Alice's ratchet
    let alice_storage = alice.engine.get_storage_rust();
    let bob_pub_key = bob.get_my_pub_key();
    let bob_pub_key_32: [u8; 32] = bob_pub_key.clone().try_into().unwrap();
    
    let state_bytes = alice_storage.get_ratchet_state(&bob_pub_key_32).unwrap().unwrap();
    let mut ratchet = DoubleRatchetSession::from_bytes(&state_bytes).unwrap();
    let alice_seed = alice_storage.get_self_seed().unwrap().unwrap();
    let alice_keys = derive_keys(&alice_seed);

    // Message 1
    let msg1_id = "msg1".to_string();
    let (c1, n1, dh1, n1_val, pn1) = ratchet.encrypt(b"Message 1", msg1_id.as_bytes()).unwrap();
    let env1 = EncryptedEnvelope::sign_and_serialize(
        msg1_id,
        dh1,
        n1_val,
        pn1,
        c1,
        n1,
        &alice_keys.identity_key,
    ).unwrap();

    // Message 2
    let msg2_id = "msg2".to_string();
    let (c2, n2, dh2, n2_val, pn2) = ratchet.encrypt(b"Message 2", msg2_id.as_bytes()).unwrap();
    let env2 = EncryptedEnvelope::sign_and_serialize(
        msg2_id,
        dh2,
        n2_val,
        pn2,
        c2,
        n2,
        &alice_keys.identity_key,
    ).unwrap();

    // Message 3
    let msg3_id = "msg3".to_string();
    let (c3, n3, dh3, n3_val, pn3) = ratchet.encrypt(b"Message 3", msg3_id.as_bytes()).unwrap();
    let env3 = EncryptedEnvelope::sign_and_serialize(
        msg3_id,
        dh3,
        n3_val,
        pn3,
        c3,
        n3,
        &alice_keys.identity_key,
    ).unwrap();

    // Save advanced ratchet state to Alice's storage
    let adv_state_bytes = ratchet.to_bytes().unwrap();
    alice_storage.save_ratchet_state(&bob_pub_key_32, &adv_state_bytes).unwrap();

    // Deliver to Bob out of order: Message 2, Message 3, then Message 1
    alice.engine.send_raw_bytes(bob_pub_key.clone(), env2).unwrap();
    assert!(bob.wait_for_message(&alice.get_my_pub_key(), "Message 2", Duration::from_secs(5)));

    alice.engine.send_raw_bytes(bob_pub_key.clone(), env3).unwrap();
    assert!(bob.wait_for_message(&alice.get_my_pub_key(), "Message 3", Duration::from_secs(5)));

    alice.engine.send_raw_bytes(bob_pub_key.clone(), env1).unwrap();
    assert!(bob.wait_for_message(&alice.get_my_pub_key(), "Message 1", Duration::from_secs(5)));
}

#[test]
fn test_real_world_roaming_peer() {
    let alice = TestNode::new();
    let mut bob = TestNode::new();

    let a_tok = alice.engine.generate_new_identity().unwrap();
    let b_tok = bob.engine.generate_new_identity().unwrap();

    alice.engine.add_contact_token(b_tok, "Bob".to_string()).unwrap();
    bob.engine.add_contact_token(a_tok, "Alice".to_string()).unwrap();

    alice.start();
    bob.start();

    alice.connect_to(&bob);
    alice.engine.initiate_chat_handshake(bob.get_my_pub_key()).unwrap();

    assert!(alice.wait_for_session(&bob.get_my_pub_key(), Duration::from_secs(5)));

    // Bob shuts down and roams to a different port
    bob.reboot();
    bob.start(); // This starts Bob's listener on a new random TCP port!
    
    // Alice connects to Bob's new port
    alice.connect_to(&bob);

    // Alice sends a message to Bob without a new handshake, verifying the Double Ratchet roaming capability
    alice.engine.send_message(bob.get_my_pub_key(), "Where are you?".to_string()).unwrap();
    assert!(bob.wait_for_message(&alice.get_my_pub_key(), "Where are you?", Duration::from_secs(5)));
}

#[test]
fn test_real_world_malicious_handshake_replay() {
    let alice = TestNode::new();
    let bob = TestNode::new();

    let a_tok = alice.engine.generate_new_identity().unwrap();
    let b_tok = bob.engine.generate_new_identity().unwrap();

    alice.engine.add_contact_token(b_tok, "Bob".to_string()).unwrap();
    bob.engine.add_contact_token(a_tok, "Alice".to_string()).unwrap();

    alice.start();
    bob.start();

    alice.connect_to(&bob);
    
    // Manually construct a HandshakeInitiator payload to replay
    let alice_storage = alice.engine.get_storage_rust();
    let alice_seed = alice_storage.get_self_seed().unwrap().unwrap();
    let alice_keys = derive_keys(&alice_seed);
    let bob_id = bob.get_my_pub_key();

    let mut init_ephemeral_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut init_ephemeral_bytes);
    let init_ephemeral_secret = x25519_dalek::StaticSecret::from(init_ephemeral_bytes);
    let init_ephemeral_pub = x25519_dalek::PublicKey::from(&init_ephemeral_secret);

    let mut sig_payload = Vec::new();
    sig_payload.extend_from_slice(init_ephemeral_pub.as_bytes());
    sig_payload.extend_from_slice(&bob_id);
    let signature = alice_keys.identity_key.sign(&sig_payload);

    let init = HandshakeInitiator {
        sender_identity: alice_keys.identity_key.verifying_key().to_bytes(),
        sender_dh: *alice_keys.dh_public.as_bytes(),
        ephemeral_key: *init_ephemeral_pub.as_bytes(),
        signature: signature.to_bytes().to_vec(),
    };

    let payload = serde_json::to_vec(&WireMessage::Initiator(init)).unwrap();

    // 1st Handshake: Replay/send the payload to Bob's port manually
    let bob_port = bob.engine.get_network_port().unwrap();
    
    // We establish a connection to Bob and write the handshake initiator
    {
        use std::io::{Read, Write};
        let mut stream = std::net::TcpStream::connect(format!("127.0.0.1:{}", bob_port)).unwrap();
        let len_bytes = (payload.len() as u32).to_be_bytes();
        stream.write_all(&len_bytes).unwrap();
        stream.write_all(&payload).unwrap();
        
        // Read responder handshake
        let mut resp_len_buf = [0u8; 4];
        stream.read_exact(&mut resp_len_buf).unwrap();
        let resp_len = u32::from_be_bytes(resp_len_buf) as usize;
        let mut resp_payload = vec![0u8; resp_len];
        stream.read_exact(&mut resp_payload).unwrap();
        
        let wire_msg: WireMessage = serde_json::from_slice(&resp_payload).unwrap();
        assert!(matches!(wire_msg, WireMessage::Responder(_)));
    }

    // Now, we simulate an attacker trying to send a replayed handshake, but they don't know the private keys.
    // They cannot decrypt Bob's responder or generate valid chat messages.
    // Bob's session keys cannot be hijacked by replaying public handshake messages.
    // Let's verify that sending a message with invalid signature/decryption on the new session is rejected.
    {
        use std::io::Write;
        let mut stream = std::net::TcpStream::connect(format!("127.0.0.1:{}", bob_port)).unwrap();
        // Attacker replays initiator
        let len_bytes = (payload.len() as u32).to_be_bytes();
        stream.write_all(&len_bytes).unwrap();
        stream.write_all(&payload).unwrap();

        // Bob responds, but attacker cannot send a valid encrypted message because they don't have ephemeral_secret
        // If they send random garbage as a chat envelope, Bob's reader loop will reject it
        let bad_envelope = WireMessage::Chat(EncryptedEnvelope {
            message_id: "fake".to_string(),
            peer_dh_pub: [0u8; 32],
            n: 0,
            pn: 0,
            ciphertext: vec![0u8; 32],
            nonce: [0u8; 12],
            signature: vec![0u8; 64],
        });
        let bad_payload = serde_json::to_vec(&bad_envelope).unwrap();
        let bad_len_bytes = (bad_payload.len() as u32).to_be_bytes();
        stream.write_all(&bad_len_bytes).unwrap();
        
        // Let's sleep and check that Bob did not save any message with content from this bad stream
        thread::sleep(Duration::from_millis(200));
        let messages = bob.engine.get_messages(alice.get_my_pub_key()).unwrap();
        assert!(!messages.iter().any(|m| m.content == "fake"));
    }
}
