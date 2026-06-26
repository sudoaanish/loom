use blake2::{Blake2b512, Digest};
use data_encoding::BASE32_NOPAD;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TokenError {
    #[error("Invalid token prefix")]
    InvalidPrefix,
    #[error("Invalid token encoding")]
    InvalidEncoding,
    #[error("Invalid token length")]
    InvalidLength,
    #[error("Checksum mismatch")]
    ChecksumMismatch,
    #[error("Unsupported token version")]
    UnsupportedVersion,
}

pub struct LoomToken {
    pub version: u8,
    pub identity_key: [u8; 32],
    pub dh_key: [u8; 32],
}

impl LoomToken {
    pub fn new(identity_key: [u8; 32], dh_key: [u8; 32]) -> Self {
        Self {
            version: 1,
            identity_key,
            dh_key,
        }
    }

    pub fn to_string(&self) -> String {
        let mut payload = Vec::with_capacity(66);
        payload.push(self.version);
        payload.extend_from_slice(&self.identity_key);
        payload.extend_from_slice(&self.dh_key);

        // Compute 1-byte BLAKE2b checksum
        let mut hasher = Blake2b512::new();
        hasher.update(&payload);
        let hash = hasher.finalize();
        let checksum = hash[0];
        payload.push(checksum);

        // Encode to Base32
        let base32_payload = BASE32_NOPAD.encode(&payload);
        format!("LOOM-{}", base32_payload)
    }

    pub fn parse(token_str: &str) -> Result<Self, TokenError> {
        let cleaned = token_str.trim();
        if !cleaned.starts_with("LOOM-") {
            return Err(TokenError::InvalidPrefix);
        }

        let base32_part = &cleaned[5..];
        let base32_upper = base32_part.to_uppercase();

        let payload = BASE32_NOPAD
            .decode(base32_upper.as_bytes())
            .map_err(|_| TokenError::InvalidEncoding)?;

        if payload.len() != 66 {
            return Err(TokenError::InvalidLength);
        }

        let version = payload[0];
        if version != 1 {
            return Err(TokenError::UnsupportedVersion);
        }

        let mut identity_key = [0u8; 32];
        identity_key.copy_from_slice(&payload[1..33]);

        let mut dh_key = [0u8; 32];
        dh_key.copy_from_slice(&payload[33..65]);

        let expected_checksum = payload[65];

        // Verify checksum
        let mut hasher = Blake2b512::new();
        hasher.update(&payload[0..65]);
        let hash = hasher.finalize();
        let actual_checksum = hash[0];

        if expected_checksum != actual_checksum {
            return Err(TokenError::ChecksumMismatch);
        }

        Ok(Self {
            version,
            identity_key,
            dh_key,
        })
    }
}
