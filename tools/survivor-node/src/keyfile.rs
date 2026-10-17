//! O13 native encrypted key files. Passwords are bytes from secure local input,
//! never command-line, environment, HTTP or log values.
use crate::kernel::{Hash, Result};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use ed25519_dalek::SigningKey;
use scrypt::{scrypt, Params};
use zeroize::Zeroizing;
const HEADER: usize = 74;
fn ensure(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err("INVALID encrypted key".into())
    }
}
fn password(p: &[u8]) -> Result<()> {
    ensure((1..=1024).contains(&p.len()) && std::str::from_utf8(p).is_ok())
}
fn prefix() -> Vec<u8> {
    [
        b"RLDSKEY1".to_vec(),
        1u16.to_be_bytes().to_vec(),
        1u16.to_be_bytes().to_vec(),
        1u16.to_be_bytes().to_vec(),
        32768u32.to_be_bytes().to_vec(),
        8u32.to_be_bytes().to_vec(),
        1u32.to_be_bytes().to_vec(),
    ]
    .concat()
}
pub(crate) fn derived(p: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    password(p)?;
    let mut out = Zeroizing::new([0; 32]);
    scrypt(
        p,
        salt,
        &Params::new(15, 8, 1, 32).map_err(|_| "INVALID KDF")?,
        out.as_mut(),
    )
    .map_err(|_| "INVALID KDF")?;
    Ok(out)
}
pub fn generate() -> Result<SigningKey> {
    let mut seed = Zeroizing::new([0; 32]);
    getrandom::getrandom(seed.as_mut()).map_err(|_| "RESOURCE_WAIT entropy unavailable")?;
    Ok(SigningKey::from_bytes(&seed))
}
pub fn encrypt(key: &SigningKey, chain: Hash, p: &[u8]) -> Result<Vec<u8>> {
    password(p)?;
    let mut random = [0u8; 44];
    getrandom::getrandom(&mut random).map_err(|_| "RESOURCE_WAIT entropy unavailable")?;
    let mut header = prefix();
    header.extend(random);
    header.extend(113u32.to_be_bytes());
    ensure(header.len() == HEADER)?;
    let mut plain = Zeroizing::new(Vec::with_capacity(97));
    plain.push(1);
    plain.extend(chain);
    plain.extend(key.verifying_key().to_bytes());
    plain.extend(key.to_bytes());
    let derived = derived(p, &random[..32])?;
    let cipher = Aes256Gcm::new_from_slice(derived.as_ref()).map_err(|_| "INVALID AEAD")?;
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(&random[32..]),
            Payload {
                msg: plain.as_slice(),
                aad: &header,
            },
        )
        .map_err(|_| "INVALID AEAD")?;
    header.extend(sealed);
    Ok(header)
}
pub fn decrypt(raw: &[u8], chain: Hash, p: &[u8]) -> Result<SigningKey> {
    password(p)?;
    ensure(raw.len() == HEADER + 113)?;
    ensure(raw[..26] == prefix() && raw[70..74] == 113u32.to_be_bytes())?;
    let derived = derived(p, &raw[26..58])?;
    let cipher =
        Aes256Gcm::new_from_slice(derived.as_ref()).map_err(|_| "INVALID encrypted key")?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&raw[58..70]),
                Payload {
                    msg: &raw[HEADER..],
                    aad: &raw[..HEADER],
                },
            )
            .map_err(|_| "INVALID encrypted key authentication")?,
    );
    ensure(plain.len() == 97 && plain[0] == 1 && plain[1..33] == chain)?;
    let seed =
        Zeroizing::new(<[u8; 32]>::try_from(&plain[65..]).map_err(|_| "INVALID encrypted key")?);
    let key = SigningKey::from_bytes(&seed);
    ensure(key.verifying_key().as_bytes() == &plain[33..65])?;
    Ok(key)
}
