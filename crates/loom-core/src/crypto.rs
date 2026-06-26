use blake2::{Blake2b512, Digest};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use std::collections::HashMap;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Error, Debug, Clone)]
pub enum CryptoError {
    #[error("Encryption failed")]
    EncryptionError,
    #[error("Decryption failed")]
    DecryptionError,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid key format")]
    InvalidKeyFormat,
    #[error("Ratchet out of sync")]
    RatchetOutOfSync,
}

// Generates a 32-byte master seed using CSPRNG
pub fn generate_master_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    seed
}

// Derives the Ed25519 identity keypair and X25519 static keypair from the master seed
pub struct KeyDerivation {
    pub identity_key: SigningKey,
    pub dh_secret: StaticSecret,
    pub dh_public: PublicKey,
}

pub fn derive_keys(master_seed: &[u8; 32]) -> KeyDerivation {
    // Derive Ed25519 seed
    let mut hasher = Blake2b512::new();
    hasher.update(b"LOOM-ED25519-DERIVATION");
    hasher.update(master_seed);
    let hash_ed = hasher.finalize();
    let mut ed_seed = [0u8; 32];
    ed_seed.copy_from_slice(&hash_ed[..32]);
    let identity_key = SigningKey::from_bytes(&ed_seed);

    // Derive X25519 seed
    let mut hasher = Blake2b512::new();
    hasher.update(b"LOOM-X25519-DERIVATION");
    hasher.update(master_seed);
    let hash_x = hasher.finalize();
    let mut x_seed = [0u8; 32];
    x_seed.copy_from_slice(&hash_x[..32]);
    let dh_secret = StaticSecret::from(x_seed);
    let dh_public = PublicKey::from(&dh_secret);

    KeyDerivation {
        identity_key,
        dh_secret,
        dh_public,
    }
}

// Simple symmetric encryption helper using ChaCha20-Poly1305
pub fn encrypt_symmetric(key: &[u8; 32], plaintext: &[u8], associated_data: &[u8]) -> Result<(Vec<u8>, [u8; 12]), CryptoError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher
        .encrypt(nonce, chacha20poly1305::aead::Payload {
            msg: plaintext,
            aad: associated_data,
        })
        .map_err(|_| CryptoError::EncryptionError)?;

    Ok((ciphertext, nonce_bytes))
}

pub fn decrypt_symmetric(
    key: &[u8; 32],
    ciphertext: &[u8],
    nonce_bytes: &[u8; 12],
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, chacha20poly1305::aead::Payload {
            msg: ciphertext,
            aad: associated_data,
        })
        .map_err(|_| CryptoError::DecryptionError)
}

// Double Ratchet implementation structures
#[derive(serde::Serialize, serde::Deserialize)]
struct DoubleRatchetStateShadow {
    dhs_bytes: [u8; 32],
    dhp_bytes: [u8; 32],
    rk: [u8; 32],
    ck_s: Option<[u8; 32]>,
    ck_r: Option<[u8; 32]>,
    ns: u32,
    nr: u32,
    pn: u32,
    skipped_message_keys: Vec<((Vec<u8>, u32), [u8; 32])>,
}

pub struct DoubleRatchetSession {
    dhs: StaticSecret,
    dhp: PublicKey,
    rk: [u8; 32],
    ck_s: Option<[u8; 32]>,
    ck_r: Option<[u8; 32]>,
    ns: u32,
    nr: u32,
    pn: u32,
    skipped_message_keys: HashMap<(Vec<u8>, u32), [u8; 32]>,
}

impl DoubleRatchetSession {
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        let shadow = DoubleRatchetStateShadow {
            dhs_bytes: self.dhs.to_bytes(),
            dhp_bytes: *self.dhp.as_bytes(),
            rk: self.rk,
            ck_s: self.ck_s,
            ck_r: self.ck_r,
            ns: self.ns,
            nr: self.nr,
            pn: self.pn,
            skipped_message_keys: self
                .skipped_message_keys
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect(),
        };
        serde_json::to_vec(&shadow).map_err(|_| CryptoError::EncryptionError)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let shadow: DoubleRatchetStateShadow =
            serde_json::from_slice(bytes).map_err(|_| CryptoError::DecryptionError)?;
        Ok(Self {
            dhs: StaticSecret::from(shadow.dhs_bytes),
            dhp: PublicKey::from(shadow.dhp_bytes),
            rk: shadow.rk,
            ck_s: shadow.ck_s,
            ck_r: shadow.ck_r,
            ns: shadow.ns,
            nr: shadow.nr,
            pn: shadow.pn,
            skipped_message_keys: shadow.skipped_message_keys.into_iter().collect(),
        })
    }

    pub fn initialize_active(
        _ephemeral_secret: StaticSecret,
        peer_dh_pub: PublicKey,
        shared_root: [u8; 32],
    ) -> Self {
        // Generate Bob's new ephemeral key for sending
        let mut next_dhs_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut next_dhs_bytes);
        let next_dhs = StaticSecret::from(next_dhs_bytes);

        // DH step between Bob's new ephemeral and Alice's handshake ephemeral public key
        let dh_out = next_dhs.diffie_hellman(&peer_dh_pub);
        let (rk, ck_s) = Self::kdf_rk(&shared_root, dh_out.as_bytes());

        Self {
            dhs: next_dhs,
            dhp: peer_dh_pub,
            rk,
            ck_s: Some(ck_s),
            ck_r: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped_message_keys: HashMap::new(),
        }
    }

    pub fn initialize_passive(
        ephemeral_secret: StaticSecret,
        peer_dh_pub: PublicKey,
        shared_root: [u8; 32],
    ) -> Self {
        Self {
            dhs: ephemeral_secret,
            dhp: peer_dh_pub,
            rk: shared_root,
            ck_s: None,
            ck_r: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped_message_keys: HashMap::new(),
        }
    }

    fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let hk = Hkdf::<Sha256>::new(Some(rk), dh_out);
        let mut okm = [0u8; 64];
        hk.expand(b"LOOM-DOUBLE-RATCHET-KDF-RK", &mut okm).unwrap();
        let mut next_rk = [0u8; 32];
        let mut ck = [0u8; 32];
        next_rk.copy_from_slice(&okm[0..32]);
        ck.copy_from_slice(&okm[32..64]);
        (next_rk, ck)
    }

    fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        // Simple HMAC-based symmetric KDF step
        let hk = Hkdf::<Sha256>::new(Some(ck), &[]);
        let mut okm = [0u8; 64];
        hk.expand(b"LOOM-DOUBLE-RATCHET-KDF-CK", &mut okm).unwrap();
        let mut next_ck = [0u8; 32];
        let mut mk = [0u8; 32];
        next_ck.copy_from_slice(&okm[0..32]);
        mk.copy_from_slice(&okm[32..64]);
        (next_ck, mk)
    }

    fn dh_ratchet(&mut self, peer_dh_pub: PublicKey) {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhp = peer_dh_pub;
        
        let dh_out = self.dhs.diffie_hellman(&self.dhp);
        let (next_rk, ck_r) = Self::kdf_rk(&self.rk, dh_out.as_bytes());
        self.rk = next_rk;
        self.ck_r = Some(ck_r);

        // Generate new DH ephemeral key
        let mut next_dhs_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut next_dhs_bytes);
        self.dhs = StaticSecret::from(next_dhs_bytes);
        let dh_out_new = self.dhs.diffie_hellman(&self.dhp);
        let (next_rk_s, ck_s) = Self::kdf_rk(&self.rk, dh_out_new.as_bytes());
        self.rk = next_rk_s;
        self.ck_s = Some(ck_s);
    }

    pub fn encrypt(&mut self, plaintext: &[u8], associated_data: &[u8]) -> Result<(Vec<u8>, [u8; 12], PublicKey, u32, u32), CryptoError> {
        let ck = self.ck_s.ok_or(CryptoError::RatchetOutOfSync)?;
        let (next_ck, mk) = Self::kdf_ck(&ck);
        self.ck_s = Some(next_ck);
        
        let dh_pub = PublicKey::from(&self.dhs);
        let n = self.ns;
        self.ns += 1;

        // Construct full AD incorporating the header values
        let mut full_ad = Vec::new();
        full_ad.extend_from_slice(associated_data);
        full_ad.extend_from_slice(dh_pub.as_bytes());
        full_ad.extend_from_slice(&n.to_be_bytes());
        full_ad.extend_from_slice(&self.pn.to_be_bytes());
        
        let (ciphertext, nonce) = encrypt_symmetric(&mk, plaintext, &full_ad)?;
        
        Ok((ciphertext, nonce, dh_pub, n, self.pn))
    }

    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        nonce_bytes: &[u8; 12],
        peer_dh_pub: PublicKey,
        n: u32,
        pn: u32,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        // If the key is in skipped_message_keys, decrypt using it
        if self.skipped_message_keys.contains_key(&(peer_dh_pub.as_bytes().to_vec(), n)) {
            return self.decrypt_skipped(ciphertext, nonce_bytes, peer_dh_pub, n, associated_data);
        }

        if peer_dh_pub != self.dhp {
            self.skip_message_keys(pn)?;
            self.dh_ratchet(peer_dh_pub);
        }
        self.skip_message_keys(n)?;

        let ck = self.ck_r.ok_or(CryptoError::RatchetOutOfSync)?;
        let (next_ck, mk) = Self::kdf_ck(&ck);
        self.ck_r = Some(next_ck);
        self.nr += 1;

        decrypt_symmetric(&mk, ciphertext, nonce_bytes, associated_data)
    }

    fn skip_message_keys(&mut self, until_n: u32) -> Result<(), CryptoError> {
        if self.nr + 100 < until_n {
            // Prevent denial-of-service / resource exhaustion by limiting skipped keys
            return Err(CryptoError::RatchetOutOfSync);
        }
        if let Some(ck) = self.ck_r {
            let mut current_ck = ck;
            while self.nr < until_n {
                let (next_ck, mk) = Self::kdf_ck(&current_ck);
                self.skipped_message_keys.insert((self.dhp.as_bytes().to_vec(), self.nr), mk);
                current_ck = next_ck;
                self.nr += 1;
            }
            self.ck_r = Some(current_ck);
        }
        Ok(())
    }

    pub fn decrypt_skipped(
        &mut self,
        ciphertext: &[u8],
        nonce_bytes: &[u8; 12],
        peer_dh_pub: PublicKey,
        n: u32,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let key = self
            .skipped_message_keys
            .remove(&(peer_dh_pub.as_bytes().to_vec(), n))
            .ok_or(CryptoError::DecryptionError)?;
        
        decrypt_symmetric(&key, ciphertext, nonce_bytes, associated_data)
    }
}
