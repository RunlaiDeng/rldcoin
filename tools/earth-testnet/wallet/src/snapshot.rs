use anyhow::{anyhow, ensure, Result};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const MAX: usize = 16 * 1024 * 1024;
const FORMAT: &str = "RLD-EARTH-FULL-BACKUP-V1";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    format: String,
    pub chain_id: String,
    pub public_key: String,
    salt: String,
    nonce: String,
    ciphertext: String,
}
impl Snapshot {
    pub fn seal(saved: &crate::Saved, password: &str) -> Result<Self> {
        crate::validate_saved(saved)?;
        let public_key = saved
            .owner()
            .ok_or_else(|| anyhow!("Create a wallet first"))?
            .to_owned();
        let mut salt = [0; 16];
        let mut nonce = [0; 24];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        let key = crate::vault::key(password, &salt)?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(&*key).map_err(|_| anyhow!("Encryption initialization failed"))?;
        let plaintext = Zeroizing::new(serde_json::to_vec(saved)?);
        ensure!(plaintext.len() <= MAX, "Complete backup exceeds capacity");
        let aad = format!("{FORMAT}:{}:{public_key}", saved.chain_id);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| anyhow!("Encryption failed"))?;
        Ok(Self {
            format: FORMAT.into(),
            chain_id: saved.chain_id.clone(),
            public_key,
            salt: hex::encode(salt),
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
        })
    }
    pub fn open(&self, password: &str, expected_chain: &str) -> Result<crate::Saved> {
        ensure!(
            self.format == FORMAT && self.chain_id == expected_chain,
            "Unsupported backup format or chain identity"
        );
        rld_core::validate_ed25519_public_key(&self.public_key).map_err(|e| anyhow!(e))?;
        ensure!(self.ciphertext.len() <= (MAX + 16) * 2, "Backup exceeds capacity");
        let salt = hex::decode(&self.salt)?;
        let nonce = hex::decode(&self.nonce)?;
        ensure!(salt.len() == 16 && nonce.len() == 24, "Invalid backup parameter length");
        let key = crate::vault::key(password, &salt)?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(&*key).map_err(|_| anyhow!("Decryption initialization failed"))?;
        let aad = format!("{FORMAT}:{}:{}", self.chain_id, self.public_key);
        let bytes = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: &hex::decode(&self.ciphertext)?,
                        aad: aad.as_bytes(),
                    },
                )
                .map_err(|_| anyhow!("Incorrect password or corrupted backup"))?,
        );
        let saved: crate::Saved = serde_json::from_slice(&bytes)?;
        crate::validate_saved(&saved)?;
        ensure!(
            saved.owner() == Some(self.public_key.as_str()) && saved.chain_id == self.chain_id,
            "Backup identity differs from its records"
        );
        Ok(saved)
    }
}
