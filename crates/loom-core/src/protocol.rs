use crate::crypto::{CryptoError, DoubleRatchetSession};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey, Signer, Verifier};
use hkdf::Hkdf;
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HandshakeInitiator {
    pub sender_identity: [u8; 32],  // Ed25519 Public Key
    pub sender_dh: [u8; 32],        // X25519 Public Key
    pub ephemeral_key: [u8; 32],    // X25519 Ephemeral Public Key
    pub signature: Vec<u8>,         // Ed25519 signature of (ephemeral_key + recipient_identity)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HandshakeResponder {
    pub ephemeral_key: [u8; 32],    // X25519 Ephemeral Public Key
    pub signature: Vec<u8>,         // Ed25519 signature of (ephemeral_key + initiator_ephemeral_key)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedEnvelope {
    pub message_id: String,
    pub peer_dh_pub: [u8; 32],      // X25519 Public Key
    pub n: u32,
    pub pn: u32,
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub signature: Vec<u8>,         // Ed25519 signature of the serialized fields
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum WireMessage {
    Initiator(HandshakeInitiator),
    Responder(HandshakeResponder),
    Chat(EncryptedEnvelope),
}

// Computes the 3DH shared root key
pub fn compute_3dh_initiator(
    static_secret: &XStaticSecret,
    ephemeral_secret: &XStaticSecret,
    peer_static_pub: &XPublicKey,
    peer_ephemeral_pub: &XPublicKey,
) -> [u8; 32] {
    let dh1 = static_secret.diffie_hellman(peer_ephemeral_pub);
    let dh2 = ephemeral_secret.diffie_hellman(peer_static_pub);
    let dh3 = ephemeral_secret.diffie_hellman(peer_ephemeral_pub);

    let mut ikm = Vec::with_capacity(96);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(b"LOOM-HANDSHAKE-SALT"), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(b"LOOM-SHARED-ROOT-KEY", &mut okm).unwrap();
    okm
}

pub fn compute_3dh_responder(
    static_secret: &XStaticSecret,
    ephemeral_secret: &XStaticSecret,
    peer_static_pub: &XPublicKey,
    peer_ephemeral_pub: &XPublicKey,
) -> [u8; 32] {
    let dh1 = ephemeral_secret.diffie_hellman(peer_static_pub);
    let dh2 = static_secret.diffie_hellman(peer_ephemeral_pub);
    let dh3 = ephemeral_secret.diffie_hellman(peer_ephemeral_pub);

    let mut ikm = Vec::with_capacity(96);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(b"LOOM-HANDSHAKE-SALT"), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(b"LOOM-SHARED-ROOT-KEY", &mut okm).unwrap();
    okm
}

impl EncryptedEnvelope {
    pub fn sign_and_serialize(
        message_id: String,
        peer_dh_pub: XPublicKey,
        n: u32,
        pn: u32,
        ciphertext: Vec<u8>,
        nonce: [u8; 12],
        signing_key: &SigningKey,
    ) -> Result<Vec<u8>, CryptoError> {
        let mut envelope = EncryptedEnvelope {
            message_id,
            peer_dh_pub: *peer_dh_pub.as_bytes(),
            n,
            pn,
            ciphertext,
            nonce,
            signature: Vec::new(),
        };

        // Serialize envelope without signature to create sign payload
        let serialized_unsigned = serde_json::to_vec(&envelope).map_err(|_| CryptoError::EncryptionError)?;
        let signature = signing_key.sign(&serialized_unsigned);
        envelope.signature = signature.to_bytes().to_vec();

        let wire_msg = WireMessage::Chat(envelope);
        serde_json::to_vec(&wire_msg).map_err(|_| CryptoError::EncryptionError)
    }

    pub fn verify_and_decrypt(
        wire_bytes: &[u8],
        verifying_key: &VerifyingKey,
        ratchet: &mut DoubleRatchetSession,
    ) -> Result<(String, Vec<u8>), CryptoError> {
        let wire_msg: WireMessage = serde_json::from_slice(wire_bytes).map_err(|_| CryptoError::DecryptionError)?;
        
        let envelope = match wire_msg {
            WireMessage::Chat(env) => env,
            _ => return Err(CryptoError::DecryptionError),
        };

        // Create a copy to verify signature on
        let mut unsigned_env = envelope.clone();
        unsigned_env.signature = Vec::new();
        let serialized_unsigned = serde_json::to_vec(&unsigned_env).map_err(|_| CryptoError::DecryptionError)?;

        let sig = Signature::from_slice(&envelope.signature)
            .map_err(|_| CryptoError::InvalidSignature)?;
        
        verifying_key
            .verify(&serialized_unsigned, &sig)
            .map_err(|_| CryptoError::InvalidSignature)?;

        let peer_dh = XPublicKey::from(envelope.peer_dh_pub);
        
        // Associated data is the header info: message_id + peer_dh_pub + n + pn
        let mut associated_data = Vec::new();
        associated_data.extend_from_slice(envelope.message_id.as_bytes());
        associated_data.extend_from_slice(&envelope.peer_dh_pub);
        associated_data.extend_from_slice(&envelope.n.to_be_bytes());
        associated_data.extend_from_slice(&envelope.pn.to_be_bytes());

        // Decrypt using the Double Ratchet session
        let plaintext = ratchet.decrypt(
            &envelope.ciphertext,
            &envelope.nonce,
            peer_dh,
            envelope.n,
            envelope.pn,
            &associated_data,
        )?;

        Ok((envelope.message_id, plaintext))
    }
}
