//! Offline dual-authorized finite archive manifest candidate. No adopted suite,
//! nonce consumption, ledger installation, trust discovery or receipt authority.
//! The independently authenticated caller supplies policy and current observation.
use crate::hybrid_authorization::{
    decode_hybrid_public_envelope_candidate, verify_hybrid_authorization_candidate,
    HybridCandidateError, HybridIntentCandidateV1, HybridObservationCandidateV1,
    HybridPolicyCandidateV1, HybridPurposeV1,
};
use sha2::{Digest, Sha512};
use std::collections::BTreeSet;

pub const HYBRID_ARCHIVE_MANIFEST_CANDIDATE_DOMAIN: &[u8] = b"RLD-PQ-PUBLIC-ARCHIVE-CANDIDATE-V1\0";
pub const HYBRID_ARCHIVE_MANIFEST_CANDIDATE_MAX_ENTRIES: usize = 64;
pub const HYBRID_ARCHIVE_MANIFEST_CANDIDATE_MAX_ENTRY_BYTES: u32 = 32768;
pub const HYBRID_ARCHIVE_MANIFEST_CANDIDATE_MAX_TOTAL_BYTES: u32 = 2097152;
pub const HYBRID_ARCHIVE_MANIFEST_CANDIDATE_MAX_WIRE_BYTES: usize =
    HYBRID_ARCHIVE_MANIFEST_CANDIDATE_DOMAIN.len() + 2 + 64 * 68;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HybridArchiveEntryCandidateV1 {
    pub size_bytes: u32,
    pub sha512: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridVerifiedArchiveManifestCandidateV1 {
    pub manifest_root: [u8; 64],
    pub entries: Vec<HybridArchiveEntryCandidateV1>,
    pub total_bytes: u32,
    pub verified_intent: HybridIntentCandidateV1,
}

fn entries_valid(entries: &[HybridArchiveEntryCandidateV1]) -> Result<u32, HybridCandidateError> {
    if entries.is_empty() || entries.len() > HYBRID_ARCHIVE_MANIFEST_CANDIDATE_MAX_ENTRIES {
        return Err(HybridCandidateError::Encoding);
    }
    let mut total = 0u32;
    let mut roots = BTreeSet::new();
    for entry in entries {
        if entry.size_bytes == 0
            || entry.size_bytes > HYBRID_ARCHIVE_MANIFEST_CANDIDATE_MAX_ENTRY_BYTES
            || !roots.insert(entry.sha512)
        {
            return Err(HybridCandidateError::Encoding);
        }
        total = total
            .checked_add(entry.size_bytes)
            .ok_or(HybridCandidateError::Encoding)?;
        if total > HYBRID_ARCHIVE_MANIFEST_CANDIDATE_MAX_TOTAL_BYTES {
            return Err(HybridCandidateError::Encoding);
        }
    }
    Ok(total)
}

pub fn encode_hybrid_archive_manifest_candidate(
    entries: &[HybridArchiveEntryCandidateV1],
) -> Result<Vec<u8>, HybridCandidateError> {
    entries_valid(entries)?;
    let mut raw = HYBRID_ARCHIVE_MANIFEST_CANDIDATE_DOMAIN.to_vec();
    raw.extend_from_slice(&(entries.len() as u16).to_be_bytes());
    for entry in entries {
        raw.extend_from_slice(&entry.size_bytes.to_be_bytes());
        raw.extend_from_slice(&entry.sha512);
    }
    Ok(raw)
}

pub fn decode_hybrid_archive_manifest_candidate(
    raw: &[u8],
) -> Result<Vec<HybridArchiveEntryCandidateV1>, HybridCandidateError> {
    let offset = HYBRID_ARCHIVE_MANIFEST_CANDIDATE_DOMAIN.len();
    if raw.len() > HYBRID_ARCHIVE_MANIFEST_CANDIDATE_MAX_WIRE_BYTES
        || raw.len() < offset + 2
        || !raw.starts_with(HYBRID_ARCHIVE_MANIFEST_CANDIDATE_DOMAIN)
    {
        return Err(HybridCandidateError::Encoding);
    }
    let count = u16::from_be_bytes(raw[offset..offset + 2].try_into().unwrap()) as usize;
    if count == 0
        || count > HYBRID_ARCHIVE_MANIFEST_CANDIDATE_MAX_ENTRIES
        || raw.len() != offset + 2 + count * 68
    {
        return Err(HybridCandidateError::Encoding);
    }
    let entries = raw[offset + 2..]
        .as_chunks::<68>()
        .0
        .iter()
        .map(|record| HybridArchiveEntryCandidateV1 {
            size_bytes: u32::from_be_bytes(record[..4].try_into().unwrap()),
            sha512: record[4..].try_into().unwrap(),
        })
        .collect::<Vec<_>>();
    entries_valid(&entries)?;
    Ok(entries)
}

/// A dedicated ARCHIVE_MANIFEST purpose prevents payment/finality/governance
/// signatures from becoming archive authorization. Both halves authenticate the
/// exact canonical manifest root, roots/epoch/nonce and explicit finite policy.
/// No immediate handshake is needed; expiry or unknown authority still refuses.
/// Success permits only this verification result. The caller must authenticate
/// its policy, retain freshness and atomically handle any eventual nonce/state use.
pub fn verify_hybrid_archive_manifest_candidate(
    policy: &HybridPolicyCandidateV1,
    observation: HybridObservationCandidateV1,
    manifest: &[u8],
    public_envelope: &[u8],
) -> Result<HybridVerifiedArchiveManifestCandidateV1, HybridCandidateError> {
    if policy.purpose != HybridPurposeV1::ArchiveManifest {
        return Err(HybridCandidateError::Scope);
    }
    let entries = decode_hybrid_archive_manifest_candidate(manifest)?;
    let root: [u8; 64] = Sha512::digest(manifest).into();
    let (intent, proof) = decode_hybrid_public_envelope_candidate(public_envelope)?;
    if intent.purpose != HybridPurposeV1::ArchiveManifest || intent.payload_root != root {
        return Err(HybridCandidateError::Scope);
    }
    verify_hybrid_authorization_candidate(policy, &intent, &proof, observation)?;
    Ok(HybridVerifiedArchiveManifestCandidateV1 {
        manifest_root: root,
        total_bytes: entries_valid(&entries)?,
        entries,
        verified_intent: intent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid_authorization::{
        encode_hybrid_public_envelope_candidate, HybridPolicyTrustV1, HybridProofCandidateV1,
        HYBRID_CANDIDATE_CONTEXT, HYBRID_CANDIDATE_PROFILE,
    };
    use ed25519_dalek::Signer as _;
    use fips204::{
        ml_dsa_87,
        traits::{SerDes, Signer as _},
    };

    fn fixture(
        purpose: HybridPurposeV1,
    ) -> (
        HybridPolicyCandidateV1,
        Vec<u8>,
        HybridIntentCandidateV1,
        HybridProofCandidateV1,
    ) {
        let mut rng = rand::rngs::OsRng;
        let ed = ed25519_dalek::SigningKey::generate(&mut rng);
        let (public, private) = ml_dsa_87::try_keygen_with_rng(&mut rng).unwrap();
        let entries = [
            HybridArchiveEntryCandidateV1 {
                size_bytes: 12,
                sha512: Sha512::digest(b"first public").into(),
            },
            HybridArchiveEntryCandidateV1 {
                size_bytes: 13,
                sha512: Sha512::digest(b"second public").into(),
            },
        ];
        let manifest = encode_hybrid_archive_manifest_candidate(&entries).unwrap();
        let policy = HybridPolicyCandidateV1 {
            profile: HYBRID_CANDIDATE_PROFILE.into(),
            currency_root: [1; 32],
            region_root: [2; 32],
            purpose,
            valid_from_epoch: 1,
            valid_until_epoch: 8,
            ed_public_key: ed.verifying_key().to_bytes(),
            pq_public_key: Box::new(public.into_bytes()),
        };
        let intent = HybridIntentCandidateV1 {
            currency_root: policy.currency_root,
            region_root: policy.region_root,
            purpose,
            epoch: 2,
            nonce: 1,
            payload_root: Sha512::digest(&manifest).into(),
        };
        let message = intent.signing_bytes();
        let proof = HybridProofCandidateV1 {
            ed_signature: ed.sign(&message).to_bytes(),
            pq_signature: Box::new(
                private
                    .try_sign_with_rng(&mut rng, &message, HYBRID_CANDIDATE_CONTEXT)
                    .unwrap(),
            ),
        };
        (policy, manifest, intent, proof)
    }

    fn observed(epoch: u64) -> HybridObservationCandidateV1 {
        HybridObservationCandidateV1 {
            current_epoch: epoch,
            next_nonce: 1,
            policy_trust: HybridPolicyTrustV1::CurrentAndTrusted,
        }
    }

    #[test]
    fn archive_manifest_candidate_canonical_bounds_and_order_root() {
        let entries: Vec<_> = (0..64)
            .map(|index| HybridArchiveEntryCandidateV1 {
                size_bytes: 32768,
                sha512: Sha512::digest([index as u8]).into(),
            })
            .collect();
        let raw = encode_hybrid_archive_manifest_candidate(&entries).unwrap();
        assert_eq!(raw.len(), 4389);
        assert_eq!(
            decode_hybrid_archive_manifest_candidate(&raw).unwrap(),
            entries
        );
        assert_eq!(entries_valid(&entries), Ok(2097152));
        let mut reversed = entries.clone();
        reversed.reverse();
        assert_ne!(
            Sha512::digest(&raw),
            Sha512::digest(encode_hybrid_archive_manifest_candidate(&reversed).unwrap())
        );
        for invalid in [
            vec![],
            vec![entries[0]; 65],
            vec![entries[0]; 2],
            vec![HybridArchiveEntryCandidateV1 {
                size_bytes: 32769,
                ..entries[0]
            }],
            vec![HybridArchiveEntryCandidateV1 {
                size_bytes: 0,
                ..entries[0]
            }],
        ] {
            assert_eq!(
                encode_hybrid_archive_manifest_candidate(&invalid),
                Err(HybridCandidateError::Encoding)
            );
        }
        for bad in [
            raw[..raw.len() - 1].to_vec(),
            [raw.as_slice(), b"x"].concat(),
            vec![0; 4390],
        ] {
            assert_eq!(
                decode_hybrid_archive_manifest_candidate(&bad),
                Err(HybridCandidateError::Encoding)
            );
        }
        let mut unknown = raw;
        unknown[0] ^= 1;
        assert_eq!(
            decode_hybrid_archive_manifest_candidate(&unknown),
            Err(HybridCandidateError::Encoding)
        );
    }

    #[test]
    fn archive_manifest_candidate_real_dual_auth_accepts_delayed_bounded_observation() {
        let (policy, manifest, intent, proof) = fixture(HybridPurposeV1::ArchiveManifest);
        let before = policy.clone();
        let envelope = encode_hybrid_public_envelope_candidate(&intent, &proof);
        for arrival_epoch in [2, 7, 8] {
            let verified = verify_hybrid_archive_manifest_candidate(
                &policy,
                observed(arrival_epoch),
                &manifest,
                &envelope,
            )
            .unwrap();
            assert_eq!(verified.manifest_root, intent.payload_root);
            assert_eq!(verified.verified_intent, intent);
            assert_eq!(verified.entries.len(), 2);
            assert_eq!(verified.total_bytes, 25);
            assert_eq!(policy, before); // Verify-only; no trust/nonce installation.
        }
        assert_eq!(
            verify_hybrid_archive_manifest_candidate(&policy, observed(9), &manifest, &envelope),
            Err(HybridCandidateError::Horizon)
        );
    }

    #[test]
    fn archive_manifest_candidate_rejects_half_signatures_scope_stale_and_altered_manifest() {
        let (policy, manifest, intent, proof) = fixture(HybridPurposeV1::ArchiveManifest);
        let envelope = encode_hybrid_public_envelope_candidate(&intent, &proof);
        for trust in [
            HybridPolicyTrustV1::Unavailable,
            HybridPolicyTrustV1::Revoked,
            HybridPolicyTrustV1::Broken,
        ] {
            assert_eq!(
                verify_hybrid_archive_manifest_candidate(
                    &policy,
                    HybridObservationCandidateV1 {
                        policy_trust: trust,
                        ..observed(7)
                    },
                    &manifest,
                    &envelope
                ),
                Err(HybridCandidateError::Untrusted)
            );
        }
        assert_eq!(
            verify_hybrid_archive_manifest_candidate(
                &policy,
                HybridObservationCandidateV1 {
                    next_nonce: 2,
                    ..observed(7)
                },
                &manifest,
                &envelope
            ),
            Err(HybridCandidateError::Scope)
        );
        let mut wrong_policy = policy.clone();
        wrong_policy.region_root[0] ^= 1;
        assert_eq!(
            verify_hybrid_archive_manifest_candidate(
                &wrong_policy,
                observed(7),
                &manifest,
                &envelope
            ),
            Err(HybridCandidateError::Scope)
        );
        let mut bad = proof.clone();
        bad.ed_signature[0] ^= 1;
        assert_eq!(
            verify_hybrid_archive_manifest_candidate(
                &policy,
                observed(7),
                &manifest,
                &encode_hybrid_public_envelope_candidate(&intent, &bad)
            ),
            Err(HybridCandidateError::Classical)
        );
        let mut bad = proof;
        bad.pq_signature[0] ^= 1;
        assert_eq!(
            verify_hybrid_archive_manifest_candidate(
                &policy,
                observed(7),
                &manifest,
                &encode_hybrid_public_envelope_candidate(&intent, &bad)
            ),
            Err(HybridCandidateError::PostQuantum)
        );
        let mut entries = decode_hybrid_archive_manifest_candidate(&manifest).unwrap();
        entries.reverse();
        let altered = encode_hybrid_archive_manifest_candidate(&entries).unwrap();
        assert_eq!(
            verify_hybrid_archive_manifest_candidate(&policy, observed(7), &altered, &envelope),
            Err(HybridCandidateError::Scope)
        );
        let (governance, manifest, intent, proof) = fixture(HybridPurposeV1::Governance);
        assert_eq!(
            verify_hybrid_authorization_candidate(&governance, &intent, &proof, observed(7)),
            Ok(())
        );
        assert_eq!(
            verify_hybrid_archive_manifest_candidate(
                &governance,
                observed(7),
                &manifest,
                &encode_hybrid_public_envelope_candidate(&intent, &proof)
            ),
            Err(HybridCandidateError::Scope)
        );
    }
}
