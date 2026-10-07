//! Verification-only permanent import-ID commitment candidate.
//!
//! The caller must independently authenticate the CURRENT scope/root. Neither a
//! root read from an archive nor success here authorizes an import, value, nonce,
//! custody, finality, rollback recovery or an adopted profile. Native limits stay
//! unchanged. There is no storage, signing, root installation or deletion API.
use sha2::{Digest, Sha512};

const DOMAIN: &[u8] = b"RLD-PERMANENT-IMPORT-INDEX-CANDIDATE-V1\0";
const PROOF_DOMAIN: &[u8] = b"RLD-PERMANENT-IMPORT-PROOF-CANDIDATE-V1\0";
pub const MAX_IMPORT_KEYS_CANDIDATE: u32 = 200001;
pub const MAX_IMPORT_DEPTH_CANDIDATE: usize = 256;
pub const MAX_IMPORT_PROOF_BYTES_CANDIDATE: usize = 32768;
const FRAME_BYTES: usize = 102;
type Root = [u8; 64];
type Key = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PermanentImportCandidateError {
    #[error("noncanonical or unbounded permanent import proof")]
    Encoding,
    #[error("permanent import proof route differs")]
    Route,
    #[error("proof differs from independently authenticated current root")]
    Root,
    #[error("permanent import ID already present")]
    Duplicate,
    #[error("candidate permanent import-key capacity exhausted")]
    Capacity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PermanentImportMembershipCandidate {
    pub present: bool,
    pub committed_key_count: u32,
}

#[derive(Clone)]
struct Frame {
    common: Key,
    bit: u16,
    sibling_count: u32,
    sibling_hash: Root,
}

struct Proof {
    terminal: Option<Key>,
    frames: Vec<Frame>,
}

fn decode(raw: &[u8]) -> Result<Proof, PermanentImportCandidateError> {
    use PermanentImportCandidateError::Encoding;
    let mut offset = PROOF_DOMAIN.len();
    if raw.len() > MAX_IMPORT_PROOF_BYTES_CANDIDATE
        || raw.len() < offset + 3
        || !raw.starts_with(PROOF_DOMAIN)
    {
        return Err(Encoding);
    }
    let kind = raw[offset];
    offset += 1;
    let terminal = match kind {
        0 => None,
        1 if raw.len() >= offset + 34 => {
            let key = raw[offset..offset + 32].try_into().map_err(|_| Encoding)?;
            offset += 32;
            Some(key)
        }
        _ => return Err(Encoding),
    };
    let count =
        u16::from_be_bytes(raw[offset..offset + 2].try_into().map_err(|_| Encoding)?) as usize;
    offset += 2;
    if count > MAX_IMPORT_DEPTH_CANDIDATE
        || raw.len() != offset + count * FRAME_BYTES
        || (terminal.is_none() && count != 0)
    {
        return Err(Encoding);
    }
    let mut frames = Vec::with_capacity(count);
    for record in raw[offset..].as_chunks::<FRAME_BYTES>().0 {
        let bit = u16::from_be_bytes(record[32..34].try_into().map_err(|_| Encoding)?);
        let sibling_count = u32::from_be_bytes(record[34..38].try_into().map_err(|_| Encoding)?);
        if bit > 255 || sibling_count == 0 || sibling_count >= MAX_IMPORT_KEYS_CANDIDATE {
            return Err(Encoding);
        }
        frames.push(Frame {
            common: record[..32].try_into().map_err(|_| Encoding)?,
            bit,
            sibling_count,
            sibling_hash: record[38..].try_into().map_err(|_| Encoding)?,
        });
    }
    Ok(Proof { terminal, frames })
}

fn direction(key: &Key, bit: u16) -> bool {
    key[usize::from(bit / 8)] & (1 << (7 - bit % 8)) != 0
}

fn common_prefix(key: &Key, bit: u16) -> Key {
    let mut out = [0; 32];
    let bytes = usize::from(bit / 8);
    out[..bytes].copy_from_slice(&key[..bytes]);
    if !bit.is_multiple_of(8) {
        out[bytes] = key[bytes] & (u8::MAX << (8 - bit % 8));
    }
    out
}

fn empty(scope: &Root) -> Root {
    let mut hash = Sha512::new();
    hash.update(DOMAIN);
    hash.update(scope);
    hash.update(b"E");
    hash.finalize().into()
}

fn leaf(scope: &Root, key: &Key) -> Root {
    let mut hash = Sha512::new();
    hash.update(DOMAIN);
    hash.update(scope);
    hash.update(b"L");
    hash.update(key);
    hash.finalize().into()
}

fn branch(
    scope: &Root,
    bit: u16,
    common: &Key,
    left: (Root, u32),
    right: (Root, u32),
) -> Result<(Root, u32), PermanentImportCandidateError> {
    let count = left
        .1
        .checked_add(right.1)
        .ok_or(PermanentImportCandidateError::Capacity)?;
    if left.1 == 0 || right.1 == 0 || count > MAX_IMPORT_KEYS_CANDIDATE {
        return Err(PermanentImportCandidateError::Capacity);
    }
    if bit > 255 || common_prefix(common, bit) != *common {
        return Err(PermanentImportCandidateError::Encoding);
    }
    let mut hash = Sha512::new();
    hash.update(DOMAIN);
    hash.update(scope);
    hash.update(b"B");
    hash.update(common);
    hash.update(bit.to_be_bytes());
    hash.update(left.1.to_be_bytes());
    hash.update(left.0);
    hash.update(right.1.to_be_bytes());
    hash.update(right.0);
    Ok((hash.finalize().into(), count))
}

fn fold(
    scope: &Root,
    query: &Key,
    frames: &[Frame],
    mut child: (Root, u32),
) -> Result<(Root, u32), PermanentImportCandidateError> {
    for frame in frames.iter().rev() {
        let sibling = (frame.sibling_hash, frame.sibling_count);
        child = if direction(query, frame.bit) {
            branch(scope, frame.bit, &frame.common, sibling, child)?
        } else {
            branch(scope, frame.bit, &frame.common, child, sibling)?
        };
    }
    Ok(child)
}

fn evaluate(
    scope: &Root,
    query: &Key,
    proof: &Proof,
) -> Result<((Root, u32), bool), PermanentImportCandidateError> {
    let Some(terminal) = proof.terminal else {
        return Ok(((empty(scope), 0), false));
    };
    let mut previous = None;
    for frame in &proof.frames {
        if previous.is_some_and(|bit| frame.bit <= bit)
            || frame.common != common_prefix(&terminal, frame.bit)
            || direction(&terminal, frame.bit) != direction(query, frame.bit)
        {
            return Err(PermanentImportCandidateError::Route);
        }
        previous = Some(frame.bit);
    }
    Ok((
        fold(scope, query, &proof.frames, (leaf(scope, &terminal), 1))?,
        terminal == *query,
    ))
}

/// Proves membership OR absence only under a separately supplied current root.
/// A formerly valid root is not independently assured freshness.
pub fn verify_permanent_import_proof_candidate(
    scope: &Root,
    independently_current_root: &Root,
    query: &Key,
    raw: &[u8],
) -> Result<PermanentImportMembershipCandidate, PermanentImportCandidateError> {
    let proof = decode(raw)?;
    let ((root, count), present) = evaluate(scope, query, &proof)?;
    if root != *independently_current_root {
        return Err(PermanentImportCandidateError::Root);
    }
    Ok(PermanentImportMembershipCandidate {
        present,
        committed_key_count: count,
    })
}

/// Derives the sole one-key append while preserving committed siblings. Pure
/// output only: the caller must authenticate, authorize and atomically install
/// any future transition under a separately adopted rule. Old roots grant none.
pub fn derive_permanent_import_append_candidate(
    scope: &Root,
    independently_current_root: &Root,
    query: &Key,
    raw: &[u8],
) -> Result<Root, PermanentImportCandidateError> {
    let proof = decode(raw)?;
    let ((root, count), present) = evaluate(scope, query, &proof)?;
    if root != *independently_current_root {
        return Err(PermanentImportCandidateError::Root);
    }
    if present {
        return Err(PermanentImportCandidateError::Duplicate);
    }
    if count >= MAX_IMPORT_KEYS_CANDIDATE {
        return Err(PermanentImportCandidateError::Capacity);
    }
    let Some(terminal) = proof.terminal else {
        return Ok(leaf(scope, query));
    };
    let split = terminal
        .iter()
        .zip(query)
        .enumerate()
        .find_map(|(byte, (a, b))| {
            let xor = a ^ b;
            (xor != 0).then(|| (byte as u16) * 8 + xor.leading_zeros() as u16)
        })
        .ok_or(PermanentImportCandidateError::Duplicate)?;
    // Rebuild the complete subtree below the new fork, then only its ancestors.
    // This is independent of the Python verifier's wrapped-digest state machine.
    let position = proof.frames.partition_point(|frame| frame.bit < split);
    let retained = fold(
        scope,
        query,
        &proof.frames[position..],
        (leaf(scope, &terminal), 1),
    )?;
    let incoming = (leaf(scope, query), 1);
    let common = common_prefix(query, split);
    let forked = if direction(query, split) {
        branch(scope, split, &common, retained, incoming)?
    } else {
        branch(scope, split, &common, incoming, retained)?
    };
    Ok(fold(scope, query, &proof.frames[..position], forked)?.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn vectors() -> Value {
        serde_json::from_str(include_str!(
            "../../../vectors/permanent-import-index-candidate-v1/vectors.json"
        ))
        .unwrap()
    }
    fn bytes<const N: usize>(v: &Value) -> [u8; N] {
        hex::decode(v.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }
    fn raw(v: &Value) -> Vec<u8> {
        hex::decode(v.as_str().unwrap()).unwrap()
    }

    #[test]
    fn python_public_vectors_membership_absence_and_exact_append_agree() {
        let v = vectors();
        let scope = bytes(&v["scope"]);
        let root = bytes(&v["root"]);
        for case in v["cases"].as_array().unwrap() {
            let query = bytes(&case["query"]);
            let proof = raw(&case["proof"]);
            let answer =
                verify_permanent_import_proof_candidate(&scope, &root, &query, &proof).unwrap();
            assert_eq!(answer.present, case["expected_present"].as_bool().unwrap());
            assert_eq!(
                u64::from(answer.committed_key_count),
                case["expected_count"].as_u64().unwrap()
            );
            if answer.present {
                assert_eq!(
                    derive_permanent_import_append_candidate(&scope, &root, &query, &proof),
                    Err(PermanentImportCandidateError::Duplicate)
                );
            } else {
                let appended =
                    derive_permanent_import_append_candidate(&scope, &root, &query, &proof)
                        .unwrap();
                assert_eq!(appended, bytes(&case["expected_insert_root"]));
                assert_eq!(
                    verify_permanent_import_proof_candidate(&scope, &appended, &query, &proof),
                    Err(PermanentImportCandidateError::Root)
                );
            }
        }
    }

    #[test]
    fn changed_scope_root_sibling_count_prefix_and_order_refuse() {
        let v = vectors();
        let scope = bytes(&v["scope"]);
        let root = bytes(&v["root"]);
        let case = &v["cases"][0];
        let query = bytes(&case["query"]);
        let original = raw(&case["proof"]);
        let offset = PROOF_DOMAIN.len() + 1 + 32 + 2;
        for position in [offset, offset + 33, offset + 37, offset + 38] {
            let mut forged = original.clone();
            forged[position] ^= 1;
            assert!(
                verify_permanent_import_proof_candidate(&scope, &root, &query, &forged).is_err()
            );
        }
        assert!(
            verify_permanent_import_proof_candidate(&[0; 64], &root, &query, &original).is_err()
        );
        assert!(
            verify_permanent_import_proof_candidate(&scope, &[0; 64], &query, &original).is_err()
        );
        let mut reordered = original.clone();
        reordered[offset..offset + FRAME_BYTES]
            .copy_from_slice(&original[offset + FRAME_BYTES..offset + 2 * FRAME_BYTES]);
        reordered[offset + FRAME_BYTES..offset + 2 * FRAME_BYTES]
            .copy_from_slice(&original[offset..offset + FRAME_BYTES]);
        assert!(
            verify_permanent_import_proof_candidate(&scope, &root, &query, &reordered).is_err()
        );
    }

    #[test]
    fn canonical_wire_refuses_truncation_trailing_bytes_unknown_kind_and_bound() {
        let v = vectors();
        let scope = bytes(&v["scope"]);
        let root = bytes(&v["root"]);
        let query = bytes(&v["cases"][0]["query"]);
        let original = raw(&v["cases"][0]["proof"]);
        for size in 0..original.len() {
            assert!(verify_permanent_import_proof_candidate(
                &scope,
                &root,
                &query,
                &original[..size]
            )
            .is_err());
        }
        let mut trailing = original.clone();
        trailing.push(0);
        let mut kind = original.clone();
        kind[PROOF_DOMAIN.len()] = 2;
        let mut empty = original;
        empty[PROOF_DOMAIN.len()] = 0;
        for invalid in [
            trailing,
            kind,
            empty,
            vec![0; MAX_IMPORT_PROOF_BYTES_CANDIDATE + 1],
        ] {
            assert!(
                verify_permanent_import_proof_candidate(&scope, &root, &query, &invalid).is_err()
            );
        }
    }

    #[test]
    fn actual256_depth_and_empty_append_preserve_fixed_bounds() {
        let v = vectors();
        let scope = bytes(&v["scope"]);
        let deepest = &v["full_depth"];
        let proof = raw(&deepest["proof"]);
        assert_eq!(decode(&proof).unwrap().frames.len(), 256);
        assert!(proof.len() <= MAX_IMPORT_PROOF_BYTES_CANDIDATE);
        let answer = verify_permanent_import_proof_candidate(
            &scope,
            &bytes(&deepest["root"]),
            &bytes(&deepest["query"]),
            &proof,
        )
        .unwrap();
        assert!(answer.present);
        assert_eq!(answer.committed_key_count, 257);
        let empty_proof = [PROOF_DOMAIN, &[0, 0, 0]].concat();
        let key = [0; 32];
        let root = empty(&scope);
        assert_eq!(
            verify_permanent_import_proof_candidate(&scope, &root, &key, &empty_proof)
                .unwrap()
                .committed_key_count,
            0
        );
        assert_eq!(
            derive_permanent_import_append_candidate(&scope, &root, &key, &empty_proof).unwrap(),
            leaf(&scope, &key)
        );
    }

    #[test]
    fn authenticated_count_boundary_cannot_append_or_overflow() {
        let scope = [9; 64];
        let query = [0; 32];
        let terminal = [1; 32];
        let bit = 255;
        let common = common_prefix(&terminal, bit);
        let frame = Frame {
            common,
            bit,
            sibling_count: MAX_IMPORT_KEYS_CANDIDATE - 1,
            sibling_hash: [3; 64],
        };
        // Synthetic counted commitment tests scalar admission, not a large native tree.
        let proof = Proof {
            terminal: Some(terminal),
            frames: vec![frame.clone()],
        };
        let mut raw = PROOF_DOMAIN.to_vec();
        raw.push(1);
        raw.extend_from_slice(&terminal);
        raw.extend_from_slice(&1u16.to_be_bytes());
        raw.extend_from_slice(&common);
        raw.extend_from_slice(&bit.to_be_bytes());
        raw.extend_from_slice(&frame.sibling_count.to_be_bytes());
        raw.extend_from_slice(&frame.sibling_hash);
        // The chosen query must follow terminal's branch; differ at an earlier bit.
        let query = {
            let mut q = query;
            q[0] = 2;
            q[31] = 1;
            q
        };
        let ((root, count), present) = evaluate(&scope, &query, &proof).unwrap();
        assert_eq!(count, MAX_IMPORT_KEYS_CANDIDATE);
        assert!(!present);
        assert_eq!(
            derive_permanent_import_append_candidate(&scope, &root, &query, &raw),
            Err(PermanentImportCandidateError::Capacity)
        );
        let count_offset = PROOF_DOMAIN.len() + 1 + 32 + 2 + 34;
        raw[count_offset..count_offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(verify_permanent_import_proof_candidate(&scope, &root, &query, &raw).is_err());
    }
}
