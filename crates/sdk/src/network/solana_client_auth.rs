//! # Solana Client Authentication
//!
//! This module provides helpers for signing client authentication messages
//! using Ed25519 signatures compatible with Solana addresses.

use anyhow::{Context, Result};
use ed25519_dalek::{SigningKey, Signer};
use sha2::{Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};

/// Derive Solana address from private key
pub fn derive_solana_address(private_key: &[u8]) -> Result<String> {
    // Parse private key (32 bytes)
    let signing_key = SigningKey::from_bytes(
        private_key
            .try_into()
            .context("private key must be 32 bytes")?
    );
    let verifying_key = signing_key.verifying_key();
    
    // Solana address is base58 of public key
    let address = bs58::encode(verifying_key.as_bytes()).into_string();
    Ok(address)
}

/// Sign client authentication message
/// 
/// The message format is: sha256(job_id || nonce || timestamp_le_bytes)
/// where timestamp is a 64-bit little-endian integer.
pub fn sign_client_auth(
    private_key: &[u8],
    job_id: &str,
    nonce: &str,
    timestamp: i64,
) -> Result<Vec<u8>> {
    let signing_key = SigningKey::from_bytes(
        private_key
            .try_into()
            .context("private key must be 32 bytes")?
    );
    
    // Create message: sha256(job_id || nonce || timestamp_le_bytes)
    let mut hasher = Sha256::new();
    hasher.update(job_id.as_bytes());
    hasher.update(nonce.as_bytes());
    hasher.update(timestamp.to_le_bytes());
    let digest = hasher.finalize();
    
    // Sign the digest
    let signature = signing_key.sign(&digest);
    Ok(signature.to_bytes().to_vec())
}

/// Create client authentication data
pub fn create_client_auth(
    private_key: &[u8],
) -> Result<(String, String, i64, Vec<u8>, String)> {
    let job_id = uuid::Uuid::new_v4().to_string();
    let nonce = uuid::Uuid::new_v4().to_string();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("failed to get timestamp")?
        .as_secs() as i64;
    
    let signature = sign_client_auth(
        private_key,
        &job_id,
        &nonce,
        timestamp,
    )?;
    
    let client_address = derive_solana_address(private_key)?;
    
    Ok((job_id, nonce, timestamp, signature, client_address))
}

