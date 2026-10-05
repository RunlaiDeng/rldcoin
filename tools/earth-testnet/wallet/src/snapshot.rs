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
            .ok_or_else(|| anyhow!("请先创建钱包"))?
            .to_owned();
        let mut salt = [0; 16];
        let mut nonce = [0; 24];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        let key = crate::vault::key(password, &salt)?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(&*key).map_err(|_| anyhow!("加密初始化失败"))?;
        let plaintext = Zeroizing::new(serde_json::to_vec(saved)?);
        ensure!(plaintext.len() <= MAX, "完整备份超过容量限制");
        let aad = format!("{FORMAT}:{}:{public_key}", saved.chain_id);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| anyhow!("加密失败"))?;
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
            "不支持的备份格式或链身份"
        );
        rld_core::validate_ed25519_public_key(&self.public_key).map_err(|e| anyhow!(e))?;
        ensure!(self.ciphertext.len() <= (MAX + 16) * 2, "备份超过容量限制");
        let salt = hex::decode(&self.salt)?;
        let nonce = hex::decode(&self.nonce)?;
        ensure!(salt.len() == 16 && nonce.len() == 24, "备份参数长度不正确");
        let key = crate::vault::key(password, &salt)?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(&*key).map_err(|_| anyhow!("解密初始化失败"))?;
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
                .map_err(|_| anyhow!("密码错误或备份已损坏"))?,
        );
        let saved: crate::Saved = serde_json::from_slice(&bytes)?;
        crate::validate_saved(&saved)?;
        ensure!(
            saved.owner() == Some(self.public_key.as_str()) && saved.chain_id == self.chain_id,
            "备份身份与记录不一致"
        );
        Ok(saved)
    }
}
