use anyhow::{anyhow, ensure, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use rld_core::{generate_identity, sign_bytes, verify_bytes, Identity};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const FORMAT: &str = "RLD-EARTH-WALLET-ARGON2ID-XCHACHA20POLY1305-V1";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vault {
    format: String,
    pub public_key: String,
    salt: String,
    nonce: String,
    ciphertext: String,
}
pub(crate) fn key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    ensure!(
        password.chars().count() >= 12 && password.len() <= 1024,
        "Password must contain at least 12 characters and at most 1024 UTF-8 bytes"
    );
    let mut key = Zeroizing::new([0u8; 32]);
    let params = Params::new(65536, 3, 1, Some(32)).map_err(|e| anyhow!(e.to_string()))?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut *key)
        .map_err(|e| anyhow!(e.to_string()))?;
    Ok(key)
}
impl Vault {
    pub fn create(password: &str) -> Result<Self> {
        let Identity {
            public_key,
            secret_key,
        } = generate_identity();
        let secret = Zeroizing::new(secret_key);
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        let key = key(password, &salt)?;
        let aad = format!("{FORMAT}:{}:{public_key}", crate::CHAIN);
        let cipher =
            XChaCha20Poly1305::new_from_slice(&*key).map_err(|_| anyhow!("Encryption initialization failed"))?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: secret.as_bytes(),
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| anyhow!("Encryption failed"))?;
        Ok(Self {
            format: FORMAT.into(),
            public_key,
            salt: hex::encode(salt),
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
        })
    }
    pub fn unlock(&self, password: &str) -> Result<Zeroizing<String>> {
        ensure!(self.format == FORMAT, "Unsupported backup format");
        rld_core::validate_ed25519_public_key(&self.public_key).map_err(|e| anyhow!(e))?;
        let salt = hex::decode(&self.salt)?;
        let nonce = hex::decode(&self.nonce)?;
        let ciphertext = hex::decode(&self.ciphertext)?;
        ensure!(
            salt.len() == 16 && nonce.len() == 24 && ciphertext.len() == 80,
            "Invalid backup length"
        );
        let key = key(password, &salt)?;
        let aad = format!("{FORMAT}:{}:{}", crate::CHAIN, self.public_key);
        let cipher =
            XChaCha20Poly1305::new_from_slice(&*key).map_err(|_| anyhow!("Decryption initialization failed"))?;
        let bytes = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: &ciphertext,
                        aad: aad.as_bytes(),
                    },
                )
                .map_err(|_| anyhow!("Incorrect password or corrupted backup"))?,
        );
        let secret = Zeroizing::new(String::from_utf8(bytes.to_vec())?);
        let proof = b"RLD-EARTH-WALLET-KEY-CHECK";
        verify_bytes(
            &self.public_key,
            proof,
            &sign_bytes(&secret, proof).map_err(|e| anyhow!(e))?,
        )
        .map_err(|_| anyhow!("Backup public and private keys do not match"))?;
        Ok(secret)
    }
    #[cfg(test)]
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 4096 {
            anyhow::bail!("Backup exceeds size limit");
        }
        Ok(serde_json::from_slice(bytes)?)
    }
}
