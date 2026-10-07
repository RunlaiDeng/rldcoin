//! Complete finite append-chain verification from independently trusted anchors.
//! No ledger/root installation, nonce consumption, value, custody or recovery.
use crate::{
    hybrid_authorization::{
        HybridObservationCandidateV1, HybridPolicyCandidateV1, HybridPurposeV1,
        HYBRID_CANDIDATE_MAX_PUBLIC_WIRE_BYTES,
    },
    hybrid_permanent_import::{
        verify_hybrid_permanent_import_append_candidate, HybridPermanentImportCandidateError,
        PermanentImportAppendCandidateV1,
    },
    permanent_import_candidate::{MAX_IMPORT_KEYS_CANDIDATE, MAX_IMPORT_PROOF_BYTES_CANDIDATE},
};
use sha2::{Digest, Sha512};

pub const MAX_APPEND_ARCHIVE_ENTRIES_CANDIDATE: usize = 64;
pub const MAX_APPEND_ARCHIVE_BYTES_CANDIDATE: usize = 2 * 1024 * 1024;
const HEAD_DOMAIN: &[u8] = b"RLD-PERMANENT-IMPORT-APPEND-ARCHIVE-HEAD-CANDIDATE-V1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermanentImportArchiveAnchorCandidateV1 {
    pub current_root: [u8; 64],
    pub key_count: u32,
    pub next_nonce: u64,
    pub archive_head: [u8; 64],
    pub caller_locks_root: [u8; 64],
}

/// These are complete untrusted bytes, never trust/freshness observations.
#[derive(Clone, Copy, Debug)]
pub struct PermanentImportArchiveEntryCandidateV1<'a> {
    pub query: [u8; 32],
    pub complete_proof: &'a [u8],
    pub detached_envelope: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PermanentImportArchiveCandidateError {
    #[error("append archive encoding/capacity or observation count differs")]
    Bounds,
    #[error("independently authenticated initial/latest anchor differs")]
    Anchor,
    #[error(transparent)]
    Append(#[from] HybridPermanentImportCandidateError),
}

fn successor_head(
    policy: &HybridPolicyCandidateV1,
    anchor: &PermanentImportArchiveAnchorCandidateV1,
    append: &PermanentImportAppendCandidateV1,
    epoch: u64,
    complete_envelope: &[u8],
) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(HEAD_DOMAIN);
    h.update(policy.currency_root);
    h.update(policy.region_root);
    h.update(anchor.archive_head);
    h.update(anchor.caller_locks_root);
    h.update(anchor.next_nonce.to_be_bytes());
    h.update(epoch.to_be_bytes());
    h.update(append.payload_root);
    h.update(Sha512::digest(complete_envelope));
    h.finalize().into()
}

/// Every entry is fully proof- and dual-signature-verified before deriving the
/// next cursor. The complete final cursor must equal the separately retained
/// latest anchor. A valid prefix, peer head or partial result grants no success.
/// Observation positions/trust are supplied separately, never decoded from wire.
pub fn verify_hybrid_permanent_import_archive_candidate(
    policy: &HybridPolicyCandidateV1,
    initial: &PermanentImportArchiveAnchorCandidateV1,
    entries: &[PermanentImportArchiveEntryCandidateV1<'_>],
    independently_observed: &[HybridObservationCandidateV1],
    independently_latest: &PermanentImportArchiveAnchorCandidateV1,
) -> Result<PermanentImportArchiveAnchorCandidateV1, PermanentImportArchiveCandidateError> {
    if entries.is_empty()
        || entries.len() > MAX_APPEND_ARCHIVE_ENTRIES_CANDIDATE
        || entries.len() != independently_observed.len()
    {
        return Err(PermanentImportArchiveCandidateError::Bounds);
    }
    if policy.purpose != HybridPurposeV1::PermanentImportAppend
        || initial.key_count > MAX_IMPORT_KEYS_CANDIDATE
        || initial.next_nonce == 0
        || initial
            .next_nonce
            .checked_add(entries.len() as u64)
            .is_none()
        || independently_latest.caller_locks_root != initial.caller_locks_root
    {
        return Err(PermanentImportArchiveCandidateError::Anchor);
    }
    let mut total = 0usize;
    for entry in entries {
        if entry.complete_proof.len() > MAX_IMPORT_PROOF_BYTES_CANDIDATE
            || entry.detached_envelope.len() > HYBRID_CANDIDATE_MAX_PUBLIC_WIRE_BYTES
        {
            return Err(PermanentImportArchiveCandidateError::Bounds);
        }
        total = total
            .checked_add(entry.complete_proof.len())
            .and_then(|n| n.checked_add(entry.detached_envelope.len()))
            .and_then(|n| n.checked_add(32))
            .ok_or(PermanentImportArchiveCandidateError::Bounds)?;
        if total > MAX_APPEND_ARCHIVE_BYTES_CANDIDATE {
            return Err(PermanentImportArchiveCandidateError::Bounds);
        }
    }
    let mut cursor = initial.clone();
    let mut previous_observed_epoch = 0;
    for (entry, observation) in entries.iter().zip(independently_observed) {
        if observation.next_nonce != cursor.next_nonce
            || observation.current_epoch < previous_observed_epoch
        {
            return Err(PermanentImportArchiveCandidateError::Anchor);
        }
        let verified = verify_hybrid_permanent_import_append_candidate(
            policy,
            *observation,
            &cursor.current_root,
            &entry.query,
            entry.complete_proof,
            entry.detached_envelope,
        )?;
        if verified.append.previous_key_count != cursor.key_count {
            return Err(PermanentImportArchiveCandidateError::Anchor);
        }
        let head = successor_head(
            policy,
            &cursor,
            &verified.append,
            verified.verified_intent.epoch,
            entry.detached_envelope,
        );
        cursor.current_root = verified.append.new_root;
        cursor.key_count = verified.append.new_key_count;
        cursor.next_nonce = cursor
            .next_nonce
            .checked_add(1)
            .ok_or(PermanentImportArchiveCandidateError::Anchor)?;
        cursor.archive_head = head;
        previous_observed_epoch = observation.current_epoch;
    }
    if &cursor != independently_latest {
        return Err(PermanentImportArchiveCandidateError::Anchor);
    }
    Ok(cursor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid_authorization::{
        encode_hybrid_public_envelope_candidate, HybridCandidateError, HybridIntentCandidateV1,
        HybridPolicyTrustV1, HybridProofCandidateV1, HYBRID_CANDIDATE_CONTEXT,
        HYBRID_CANDIDATE_PROFILE,
    };
    use crate::hybrid_permanent_import::prepare_permanent_import_append_candidate;
    use ed25519_dalek::Signer as _;
    use fips204::{
        ml_dsa_87,
        traits::{SerDes, Signer as _},
    };

    struct Fixture {
        policy: HybridPolicyCandidateV1,
        initial: PermanentImportArchiveAnchorCandidateV1,
        latest: PermanentImportArchiveAnchorCandidateV1,
        queries: Vec<[u8; 32]>,
        proofs: Vec<Vec<u8>>,
        envelopes: Vec<Vec<u8>>,
        observations: Vec<HybridObservationCandidateV1>,
    }
    impl Fixture {
        fn entries(&self) -> Vec<PermanentImportArchiveEntryCandidateV1<'_>> {
            (0..self.queries.len())
                .map(|i| PermanentImportArchiveEntryCandidateV1 {
                    query: self.queries[i],
                    complete_proof: &self.proofs[i],
                    detached_envelope: &self.envelopes[i],
                })
                .collect()
        }
        fn verify(
            &self,
        ) -> Result<PermanentImportArchiveAnchorCandidateV1, PermanentImportArchiveCandidateError>
        {
            verify_hybrid_permanent_import_archive_candidate(
                &self.policy,
                &self.initial,
                &self.entries(),
                &self.observations,
                &self.latest,
            )
        }
    }
    fn fixture() -> Fixture {
        let mut rng = rand::rngs::OsRng;
        let ed = ed25519_dalek::SigningKey::generate(&mut rng);
        let (pq, secret) = ml_dsa_87::try_keygen_with_rng(&mut rng).unwrap();
        let policy = HybridPolicyCandidateV1 {
            profile: HYBRID_CANDIDATE_PROFILE.into(),
            currency_root: [1; 32],
            region_root: [2; 32],
            purpose: HybridPurposeV1::PermanentImportAppend,
            valid_from_epoch: 1,
            valid_until_epoch: 8,
            ed_public_key: ed.verifying_key().to_bytes(),
            pq_public_key: Box::new(pq.into_bytes()),
        };
        let mut scope = [1; 64];
        scope[32..].fill(2);
        let initial = PermanentImportArchiveAnchorCandidateV1 {
            current_root: Sha512::digest(
                [
                    b"RLD-PERMANENT-IMPORT-INDEX-CANDIDATE-V1\0".as_slice(),
                    &scope,
                    b"E",
                ]
                .concat(),
            )
            .into(),
            key_count: 0,
            next_nonce: 1,
            archive_head: [4; 64],
            caller_locks_root: [5; 64],
        };
        let mut f = Fixture {
            policy,
            initial: initial.clone(),
            latest: initial,
            queries: vec![],
            proofs: vec![],
            envelopes: vec![],
            observations: vec![],
        };
        for nonce in 1..=2 {
            let mut query = [0; 32];
            query[31] = nonce as u8;
            let mut proof = b"RLD-PERMANENT-IMPORT-PROOF-CANDIDATE-V1\0".to_vec();
            proof.push(u8::from(nonce != 1));
            if nonce != 1 {
                proof.extend_from_slice(&f.queries[0]);
            }
            proof.extend_from_slice(&0u16.to_be_bytes());
            let append = prepare_permanent_import_append_candidate(
                &scope,
                &f.latest.current_root,
                &query,
                &proof,
            )
            .unwrap();
            let intent = HybridIntentCandidateV1 {
                currency_root: [1; 32],
                region_root: [2; 32],
                purpose: HybridPurposeV1::PermanentImportAppend,
                epoch: 2,
                nonce,
                payload_root: append.payload_root,
            };
            let msg = intent.signing_bytes();
            let signatures = HybridProofCandidateV1 {
                ed_signature: ed.sign(&msg).to_bytes(),
                pq_signature: Box::new(
                    secret
                        .try_sign_with_rng(&mut rng, &msg, HYBRID_CANDIDATE_CONTEXT)
                        .unwrap(),
                ),
            };
            let envelope = encode_hybrid_public_envelope_candidate(&intent, &signatures);
            f.latest.archive_head =
                successor_head(&f.policy, &f.latest, &append, intent.epoch, &envelope);
            f.latest.current_root = append.new_root;
            f.latest.key_count = append.new_key_count;
            f.latest.next_nonce += 1;
            f.queries.push(query);
            f.proofs.push(proof);
            f.envelopes.push(envelope);
            f.observations.push(HybridObservationCandidateV1 {
                current_epoch: 7,
                next_nonce: nonce,
                policy_trust: HybridPolicyTrustV1::CurrentAndTrusted,
            });
        }
        f
    }
    #[test]
    fn actual_two_append_chain_requires_complete_latest_without_mutation() {
        let f = fixture();
        let initial = f.initial.clone();
        let latest = f.latest.clone();
        assert_eq!(f.verify().unwrap(), latest);
        assert_eq!(f.initial, initial);
        assert_eq!(
            verify_hybrid_permanent_import_archive_candidate(
                &f.policy,
                &f.initial,
                &f.entries()[..1],
                &f.observations[..1],
                &f.latest
            ),
            Err(PermanentImportArchiveCandidateError::Anchor)
        );
        let mut entries = f.entries();
        entries.swap(0, 1);
        assert!(verify_hybrid_permanent_import_archive_candidate(
            &f.policy,
            &f.initial,
            &entries,
            &f.observations,
            &f.latest
        )
        .is_err());
        entries[1] = entries[0];
        assert!(verify_hybrid_permanent_import_archive_candidate(
            &f.policy,
            &f.initial,
            &entries,
            &f.observations,
            &f.latest
        )
        .is_err());
        assert_eq!(f.initial, initial);
    }
    #[test]
    fn invalid_tail_and_separate_root_count_nonce_head_lock_trust_refuse() {
        let mut f = fixture();
        let initial = f.initial.clone();
        for field in 0..5 {
            let mut latest = f.latest.clone();
            match field {
                0 => latest.current_root[0] ^= 1,
                1 => latest.key_count += 1,
                2 => latest.next_nonce += 1,
                3 => latest.archive_head[0] ^= 1,
                _ => latest.caller_locks_root[0] ^= 1,
            }
            assert_eq!(
                verify_hybrid_permanent_import_archive_candidate(
                    &f.policy,
                    &f.initial,
                    &f.entries(),
                    &f.observations,
                    &latest
                ),
                Err(PermanentImportArchiveCandidateError::Anchor)
            );
        }
        let mut wire: serde_json::Value = serde_json::from_slice(&f.envelopes[1]).unwrap();
        let mut sig = hex::decode(wire["pq_signature"].as_str().unwrap()).unwrap();
        sig[0] ^= 1;
        wire["pq_signature"] = hex::encode(sig).into();
        f.envelopes[1] = serde_json::to_vec(&wire).unwrap();
        assert_eq!(
            f.verify(),
            Err(PermanentImportArchiveCandidateError::Append(
                HybridCandidateError::PostQuantum.into()
            ))
        );
        f.observations[0].policy_trust = HybridPolicyTrustV1::Revoked;
        assert!(f.verify().is_err());
        assert_eq!(f.initial, initial);
    }
    #[test]
    fn outer_capacity_observations_and_counter_overflow_refuse_before_auth() {
        let f = fixture();
        let entries = f.entries();
        let oversized = vec![entries[0]; 65];
        assert_eq!(
            verify_hybrid_permanent_import_archive_candidate(
                &f.policy,
                &f.initial,
                &oversized,
                &vec![f.observations[0]; 65],
                &f.latest
            ),
            Err(PermanentImportArchiveCandidateError::Bounds)
        );
        assert_eq!(
            verify_hybrid_permanent_import_archive_candidate(
                &f.policy,
                &f.initial,
                &entries,
                &f.observations[..1],
                &f.latest
            ),
            Err(PermanentImportArchiveCandidateError::Bounds)
        );
        let mut initial = f.initial.clone();
        initial.next_nonce = u64::MAX;
        assert_eq!(
            verify_hybrid_permanent_import_archive_candidate(
                &f.policy,
                &initial,
                &entries,
                &f.observations,
                &f.latest
            ),
            Err(PermanentImportArchiveCandidateError::Anchor)
        );
        initial = f.initial.clone();
        initial.key_count = 1;
        assert_eq!(
            verify_hybrid_permanent_import_archive_candidate(
                &f.policy,
                &initial,
                &entries,
                &f.observations,
                &f.latest
            ),
            Err(PermanentImportArchiveCandidateError::Anchor)
        );
        let mut observations = f.observations.clone();
        observations[1].current_epoch = 6;
        assert_eq!(
            verify_hybrid_permanent_import_archive_candidate(
                &f.policy,
                &f.initial,
                &entries,
                &observations,
                &f.latest
            ),
            Err(PermanentImportArchiveCandidateError::Anchor)
        );
    }
}
