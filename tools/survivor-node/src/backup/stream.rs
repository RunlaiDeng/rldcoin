//! Bounded local backup records, not network or consensus objects.
//! One fresh salt/key and nonce prefix per file; the chunk index never repeats.
use crate::kernel::{Hash, Result};
use aes_gcm::{aead::KeyInit, AeadInPlace, Aes256Gcm, Nonce, Tag};
use std::io::{Read, Write};
use zeroize::Zeroizing;

pub(super) const HEADER: usize = 126;
pub(super) const CHUNK: usize = 1024 * 1024;
const MAGIC: &[u8; 8] = b"RLDSBKP2";
fn io(e: impl std::fmt::Display) -> String {
    format!("RESOURCE_WAIT backup stream {e}")
}
fn ensure(ok: bool, error: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(error.into())
    }
}
fn buffer() -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.try_reserve_exact(CHUNK + 16).map_err(io)?;
    bytes.resize(CHUNK + 16, 0);
    Ok(bytes)
}
fn count(length: u64) -> Result<u64> {
    let chunks = length.div_ceil(CHUNK as u64).max(1);
    ensure(chunks <= 1u64 << 32, "RESOURCE_WAIT backup nonce space")?;
    Ok(chunks)
}
fn chunk_len(length: u64, index: u64) -> usize {
    length
        .saturating_sub(index * CHUNK as u64)
        .min(CHUNK as u64) as usize
}
fn nonce(header: &[u8; HEADER], index: u32) -> [u8; 12] {
    let mut n = [0; 12];
    n[..8].copy_from_slice(&header[118..126]);
    n[8..].copy_from_slice(&index.to_be_bytes());
    n
}
fn aad(header: &[u8; HEADER], index: u32, length: usize) -> [u8; HEADER + 8] {
    let mut aad = [0; HEADER + 8];
    aad[..HEADER].copy_from_slice(header);
    aad[HEADER..HEADER + 4].copy_from_slice(&index.to_be_bytes());
    aad[HEADER + 4..].copy_from_slice(&(length as u32).to_be_bytes());
    aad
}
pub(super) fn seal(
    mut input: impl Read,
    mut output: impl Write,
    length: u64,
    chain: Hash,
    bundle: Hash,
    kind: u16,
    password: &[u8],
) -> Result<()> {
    let chunks = count(length)?;
    let mut header = [0; HEADER];
    header[..8].copy_from_slice(MAGIC);
    header[8..40].copy_from_slice(&chain);
    header[40..72].copy_from_slice(&bundle);
    header[72..74].copy_from_slice(&kind.to_be_bytes());
    header[74..82].copy_from_slice(&length.to_be_bytes());
    header[82..86].copy_from_slice(&(CHUNK as u32).to_be_bytes());
    getrandom::getrandom(&mut header[86..]).map_err(io)?;
    let key = crate::keyfile::derived(password, &header[86..118])?;
    let cipher =
        Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| "INVALID_CRYPTO backup cipher")?;
    output.write_all(&header).map_err(io)?;
    // Keep the allocation at full length through the last partial chunk, so all
    // possible plaintext tail bytes are zeroized on every exit path.
    let mut buffer = buffer()?;
    for index in 0..chunks {
        let encoded_index = u32::try_from(index).map_err(|_| "RESOURCE_WAIT backup nonce space")?;
        let n = chunk_len(length, index);
        input.read_exact(&mut buffer[..n]).map_err(io)?;
        let tag = cipher
            .encrypt_in_place_detached(
                Nonce::from_slice(&nonce(&header, encoded_index)),
                &aad(&header, encoded_index, n),
                &mut buffer[..n],
            )
            .map_err(|_| "INVALID_CRYPTO backup encryption")?;
        buffer[n..n + 16].copy_from_slice(&tag);
        output.write_all(&buffer[..n + 16]).map_err(io)?;
    }
    let mut extra = [0];
    ensure(
        input.read(&mut extra).map_err(io)? == 0,
        "INVALID_ENCODING changed backup image length",
    )
}
pub(super) fn open(
    mut input: impl Read,
    mut output: impl Write,
    cap: u64,
    chain: Hash,
    bundle: Hash,
    kind: u16,
    password: &[u8],
) -> Result<u64> {
    let mut header = [0; HEADER];
    input.read_exact(&mut header).map_err(io)?;
    ensure(
        &header[..8] == MAGIC
            && header[8..40] == chain
            && header[40..72] == bundle
            && header[72..74] == kind.to_be_bytes(),
        "INVALID_CRYPTO backup binding",
    )?;
    ensure(
        header[82..86] == (CHUNK as u32).to_be_bytes(),
        "UNSUPPORTED_VERSION backup chunk size",
    )?;
    let length = u64::from_be_bytes(header[74..82].try_into().unwrap());
    ensure(length <= cap, "RESOURCE_WAIT backup provisioned file bound")?;
    let chunks = count(length)?;
    let key = crate::keyfile::derived(password, &header[86..118])?;
    let cipher =
        Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| "INVALID_CRYPTO backup cipher")?;
    let mut buffer = buffer()?;
    for index in 0..chunks {
        let encoded_index = u32::try_from(index).map_err(|_| "RESOURCE_WAIT backup nonce space")?;
        let n = chunk_len(length, index);
        input.read_exact(&mut buffer[..n + 16]).map_err(io)?;
        let (body, tag) = buffer[..n + 16].split_at_mut(n);
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&nonce(&header, encoded_index)),
                &aad(&header, encoded_index, n),
                body,
                Tag::from_slice(tag),
            )
            .map_err(|_| "INVALID_CRYPTO backup authentication")?;
        // Nothing from an unauthenticated chunk is released. The caller keeps
        // its RESTORING marker until all chunks and native state are verified.
        output.write_all(body).map_err(io)?;
    }
    let mut extra = [0];
    ensure(
        input.read(&mut extra).map_err(io)? == 0,
        "INVALID_ENCODING trailing backup bytes",
    )?;
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    const PASSWORD: &[u8] = b"PUBLIC NO-VALUE STREAM RECORD FIXTURE";
    fn encrypted(raw: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        seal(
            raw,
            &mut out,
            raw.len() as u64,
            [1; 32],
            [2; 32],
            1,
            PASSWORD,
        )
        .unwrap();
        out
    }
    fn decrypted(raw: &[u8], length: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        open(raw, &mut out, length as u64, [1; 32], [2; 32], 1, PASSWORD)?;
        Ok(out)
    }
    #[test]
    fn empty_partial_and_multiple_chunks_roundtrip_exactly() {
        for size in [0, CHUNK + 31, 2 * CHUNK + 7] {
            let raw = (0..size).map(|n| (n % 251) as u8).collect::<Vec<_>>();
            let sealed = encrypted(&raw);
            assert_eq!(
                sealed.len() as u64,
                HEADER as u64 + size as u64 + count(size as u64).unwrap() * 16
            );
            assert_eq!(decrypted(&sealed, size).unwrap(), raw);
        }
    }
    #[test]
    fn changed_binding_header_body_order_duplicates_or_tail_refuse() {
        let raw = (0..2 * CHUNK + 7)
            .map(|n| (n % 251) as u8)
            .collect::<Vec<_>>();
        let sealed = encrypted(&raw);
        for offset in [
            0,
            8,
            40,
            73,
            81,
            85,
            86,
            118,
            HEADER,
            HEADER + CHUNK,
            sealed.len() - 1,
        ] {
            let mut bad = sealed.clone();
            bad[offset] ^= 1;
            assert!(decrypted(&bad, raw.len()).is_err(), "offset {offset}");
        }
        let width = CHUNK + 16;
        let mut swapped = sealed.clone();
        swapped[HEADER..HEADER + width]
            .copy_from_slice(&sealed[HEADER + width..HEADER + 2 * width]);
        swapped[HEADER + width..HEADER + 2 * width]
            .copy_from_slice(&sealed[HEADER..HEADER + width]);
        assert!(decrypted(&swapped, raw.len()).is_err());
        let mut duplicate = sealed.clone();
        duplicate[HEADER + width..HEADER + 2 * width]
            .copy_from_slice(&sealed[HEADER..HEADER + width]);
        assert!(decrypted(&duplicate, raw.len()).is_err());
        assert!(decrypted(&sealed[..HEADER + 2 * width], raw.len()).is_err());
        let mut extra = sealed.clone();
        extra.push(0);
        assert!(decrypted(&extra, raw.len()).is_err());
        assert!(open(
            sealed.as_slice(),
            Vec::new(),
            raw.len() as u64,
            [1; 32],
            [2; 32],
            1,
            b"PUBLIC WRONG PASSWORD"
        )
        .is_err());
        // Editing a binding and requesting that new binding still cannot forge
        // its AEAD authentication, even when the early equality check agrees.
        let mut edited = sealed;
        edited[8..40].copy_from_slice(&[3; 32]);
        assert!(open(
            edited.as_slice(),
            Vec::new(),
            raw.len() as u64,
            [3; 32],
            [2; 32],
            1,
            PASSWORD
        )
        .is_err());
    }
    #[test]
    fn declared_caps_nonce_space_and_source_length_remain_bounded() {
        let raw = vec![7; CHUNK + 3];
        let sealed = encrypted(&raw);
        let mut cursor = Cursor::new(&sealed);
        assert!(open(
            &mut cursor,
            Vec::new(),
            CHUNK as u64,
            [1; 32],
            [2; 32],
            1,
            PASSWORD
        )
        .is_err());
        assert_eq!(cursor.position(), HEADER as u64);
        assert_eq!(count(1u64 << 52).unwrap(), 1u64 << 32);
        assert!(count((1u64 << 52) + 1).is_err());
        assert!(seal(
            raw.as_slice(),
            Vec::new(),
            raw.len() as u64 + 1,
            [1; 32],
            [2; 32],
            1,
            PASSWORD
        )
        .is_err());
        assert!(seal(
            raw.as_slice(),
            Vec::new(),
            raw.len() as u64 - 1,
            [1; 32],
            [2; 32],
            1,
            PASSWORD
        )
        .is_err());
    }
}
