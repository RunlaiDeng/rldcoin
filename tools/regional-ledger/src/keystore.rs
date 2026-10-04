//! Ground wallet custody. Domain-bound AEAD; no plaintext fallback or issuance.
//! A backup is a complete owner journal, not a rollback authorization.
use super::*;
use crate::{
    storage::{safe_dir, Store},
    wallet_agent::{Agent, Binding, Journal, Observation},
};
use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce, Tag,
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};
use zeroize::{Zeroize, Zeroizing};

const VERSION: &str = "RLD-REGIONAL-ENCRYPTED-WALLET-V1";
const KEY: &str = "OWNER_KEY";
const BACKUP: &str = "OWNER_KEY_AND_JOURNAL";
const MAX_ENVELOPE: usize = 12 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    format: String,
    kind: String,
    binding: Binding,
    cipher: String,
    kdf: String,
    kdf_version: u32,
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
    salt: String,
    nonce: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    header: Header,
    ciphertext: String,
    tag: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Secret {
    seed: Vec<u8>,
    journal: Option<Journal>,
    observation: Option<Observation>,
    head: Option<Hash>,
}
impl Drop for Secret {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

fn io(_: std::io::Error) -> String {
    "private wallet file operation failed".into()
}
pub fn validate_passphrase(pass: &[u8]) -> Result<()> {
    require(
        (12..=1024).contains(&pass.len())
            && std::str::from_utf8(pass).is_ok()
            && !pass.iter().any(|b| *b < 32 || *b == 127),
        "passphrase must be 12..1024 UTF-8 bytes without controls",
    )
}
/// Exact bytes from a bounded pipe, or an echo-free local terminal. Never argv/env.
pub fn passphrase(stdin: bool, confirm: bool) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = if stdin {
        let mut b = Zeroizing::new(Vec::new());
        std::io::stdin()
            .take(1025)
            .read_to_end(&mut b)
            .map_err(io)?;
        b
    } else {
        let first = Zeroizing::new(rpassword::prompt_password("Wallet passphrase: ").map_err(io)?);
        if confirm {
            let again =
                Zeroizing::new(rpassword::prompt_password("Confirm passphrase: ").map_err(io)?);
            require(*first == *again, "passphrases differ")?;
        }
        Zeroizing::new(first.as_bytes().to_vec())
    };
    validate_passphrase(&bytes)?;
    Ok(bytes)
}
fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::getrandom(&mut bytes).map_err(|_| "OS entropy unavailable")?;
    Ok(bytes)
}
fn derive(pass: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    validate_passphrase(pass)?;
    let params = Params::new(65536, 3, 4, Some(32)).map_err(|_| "KDF parameters")?;
    let mut key = Zeroizing::new([0; 32]);
    // The convenience API allocates ordinary Vec<Block>; scrub KDF memory too.
    let mut memory = Zeroizing::new(vec![argon2::Block::default(); params.block_count()]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(pass, salt, &mut *key, memory.as_mut_slice())
        .map_err(|_| "KDF failed")?;
    Ok(key)
}
fn private_dir(path: &Path) -> Result<()> {
    safe_dir(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = fs::metadata(path).map_err(io)?;
        require(
            m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
            "wallet parent directory must be owned and private",
        )?;
    }
    Ok(())
}
pub(crate) fn private_read(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    private_dir(path.parent().ok_or("private parent missing")?)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(io)?;
    let meta = file.metadata().map_err(io)?;
    require(
        meta.is_file() && meta.len() <= limit as u64,
        "private file type or byte bound",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        require(
            meta.uid() == unsafe { libc::geteuid() }
                && meta.mode() & 0o077 == 0
                && meta.nlink() == 1,
            "private file ownership, permissions or link count",
        )?;
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    require(bytes.len() <= limit, "private file grew beyond bound")?;
    Ok(bytes)
}
pub(crate) fn private_create(path: &Path, bytes: &[u8]) -> Result<()> {
    private_dir(path.parent().ok_or("private parent missing")?)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(io)?;
    file.write_all(bytes).map_err(io)?;
    file.sync_all().map_err(io)?;
    File::open(path.parent().unwrap())
        .map_err(io)?
        .sync_all()
        .map_err(io)
}
fn seal(binding: Binding, kind: &str, secret: &Secret, pass: &[u8]) -> Result<Vec<u8>> {
    let salt = random::<16>()?;
    let nonce = random::<12>()?;
    let header = Header {
        format: VERSION.into(),
        kind: kind.into(),
        binding,
        cipher: "AES-256-GCM".into(),
        kdf: "Argon2id".into(),
        kdf_version: 19,
        memory_kib: 65536,
        iterations: 3,
        lanes: 4,
        salt: hex::encode(salt),
        nonce: hex::encode(nonce),
    };
    let aad = serde_json::to_vec(&header).map_err(|_| "header encoding")?;
    let key = derive(pass, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|_| "cipher key")?;
    let mut bytes = Zeroizing::new(serde_json::to_vec(secret).map_err(|_| "backup encoding")?);
    require(bytes.len() <= MAX_BYTES + 65536, "backup plaintext bound")?;
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, &mut bytes)
        .map_err(|_| "wallet encryption failed")?;
    let encoded = serde_json::to_vec(&Envelope {
        header,
        ciphertext: STANDARD.encode(&*bytes),
        tag: hex::encode(tag),
    })
    .map_err(|_| "envelope encoding")?;
    require(encoded.len() <= MAX_ENVELOPE, "backup envelope bound")?;
    Ok(encoded)
}
fn open(
    path: &Path,
    binding: Option<&Binding>,
    kind: &str,
    pass: &[u8],
) -> Result<(Binding, Secret)> {
    let raw = private_read(path, if kind == KEY { 16384 } else { MAX_ENVELOPE })?;
    let env: Envelope =
        serde_json::from_slice(&raw).map_err(|_| "invalid encrypted wallet envelope")?;
    let h = &env.header;
    require(
        h.format == VERSION
            && h.kind == kind
            && h.cipher == "AES-256-GCM"
            && h.kdf == "Argon2id"
            && h.kdf_version == 19
            && h.memory_kib == 65536
            && h.iterations == 3
            && h.lanes == 4
            && binding.is_none_or(|b| b == &h.binding),
        "encrypted wallet domain, format or KDF differs",
    )?;
    validate_ed25519_public_key(&h.binding.owner)?;
    let salt = hex::decode(&h.salt).map_err(|_| "salt encoding")?;
    let nonce = hex::decode(&h.nonce).map_err(|_| "nonce encoding")?;
    let tag = hex::decode(&env.tag).map_err(|_| "tag encoding")?;
    require(
        salt.len() == 16
            && nonce.len() == 12
            && tag.len() == 16
            && hex::encode(&salt) == h.salt
            && hex::encode(&nonce) == h.nonce
            && hex::encode(&tag) == env.tag,
        "encryption header encoding/length",
    )?;
    let key = derive(pass, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|_| "cipher key")?;
    let mut bytes = Zeroizing::new(
        STANDARD
            .decode(env.ciphertext)
            .map_err(|_| "ciphertext encoding")?,
    );
    require(bytes.len() <= MAX_BYTES + 65536, "ciphertext bound")?;
    let aad = serde_json::to_vec(h).map_err(|_| "header encoding")?;
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&nonce),
            &aad,
            &mut bytes,
            Tag::from_slice(&tag),
        )
        .map_err(|_| "wallet authentication failed")?;
    let secret: Secret =
        serde_json::from_slice(&bytes).map_err(|_| "invalid wallet secret payload")?;
    require(secret.seed.len() == 32, "wallet secret seed length")?;
    let seed =
        Zeroizing::new(<[u8; 32]>::try_from(secret.seed.as_slice()).map_err(|_| "wallet seed")?);
    require(
        hex::encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes()) == h.binding.owner,
        "wallet seed does not match owner",
    )?;
    require(
        if kind == KEY {
            secret.journal.is_none() && secret.head.is_none() && secret.observation.is_none()
        } else {
            secret.journal.is_some() && secret.head.is_some() && secret.observation.is_some()
        },
        "wallet secret kind differs",
    )?;
    Ok((h.binding.clone(), secret))
}
pub fn create(node: &Store, output: &Path, pass: &[u8]) -> Result<Binding> {
    let seed = Zeroizing::new(random::<32>()?);
    let binding = Binding {
        currency: node.trust.currency()?,
        region: node.chain.region,
        owner: hex::encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes()),
    };
    let secret = Secret {
        seed: seed.to_vec(),
        journal: None,
        observation: None,
        head: None,
    };
    private_create(output, &seal(binding.clone(), KEY, &secret, pass)?)?;
    Ok(binding)
}
pub fn check(node: &Store, owner: &str, key: &Path, pass: &[u8]) -> Result<Binding> {
    let binding = Binding {
        currency: node.trust.currency()?,
        region: node.chain.region,
        owner: owner.into(),
    };
    open(key, Some(&binding), KEY, pass)?;
    Ok(binding)
}
pub(crate) fn sign(binding: &Binding, key: &Path, pass: &[u8], message: &[u8]) -> Result<Approval> {
    let (_, secret) = open(key, Some(binding), KEY, pass)?;
    let seed =
        Zeroizing::new(<[u8; 32]>::try_from(secret.seed.as_slice()).map_err(|_| "wallet seed")?);
    Ok(Approval {
        key: binding.owner.clone(),
        signature: hex::encode(SigningKey::from_bytes(&seed).sign(message).to_bytes()),
    })
}
pub fn backup(
    node: &Store,
    agent: &Agent,
    expected: Hash,
    key: &Path,
    output: &Path,
    pass: &[u8],
) -> Result<Hash> {
    agent.view(node, expected)?;
    let (binding, mut secret) = open(key, Some(&agent.journal.binding), KEY, pass)?;
    secret.journal = Some(agent.journal.clone());
    secret.observation = Some(Observation::current(node)?);
    secret.head = Some(expected);
    private_create(output, &seal(binding, BACKUP, &secret, pass)?)?;
    Ok(expected)
}
pub fn restore(
    node: &Store,
    backup: &Path,
    dir: &Path,
    expected: Hash,
    pass: &[u8],
) -> Result<Binding> {
    let (binding, mut secret) = open(backup, None, BACKUP, pass)?;
    let journal = secret.journal.take().ok_or("backup journal missing")?;
    require(
        journal.binding == binding
            && binding.currency == node.trust.currency()?
            && binding.region == node.chain.region,
        "backup belongs to another native domain",
    )?;
    require(
        secret.head == Some(expected) && journal.head()? == expected,
        "latest caller-retained head rejects old backup",
    )?;
    secret
        .observation
        .take()
        .ok_or("backup observation missing")?
        .check(node, &binding)?;
    secret.head = None;
    let key_bytes = seal(binding.clone(), KEY, &secret, pass)?;
    Agent::restore(dir, node, journal, &key_bytes)?;
    Ok(binding)
}
