//! Dedicated dual authorization of a permanent-ID append candidate.
//! No import, ledger/head installation, nonce consumption or custody recovery.
//! The caller authenticates its policy, current root, epoch and next nonce
//! separately. Retained signatures do not supply any of those current anchors.
use crate::hybrid_authorization::{
    decode_hybrid_public_envelope_candidate, verify_hybrid_authorization_candidate,
    HybridCandidateError, HybridIntentCandidateV1, HybridObservationCandidateV1,
    HybridPolicyCandidateV1, HybridPurposeV1,
};
use crate::permanent_import_candidate::{
    derive_permanent_import_append_candidate, verify_permanent_import_proof_candidate,
    PermanentImportCandidateError,
};
use sha2::{Digest, Sha512};

const DOMAIN: &[u8] = b"RLD-PERMANENT-IMPORT-APPEND-CANDIDATE-V1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HybridPermanentImportCandidateError {
    #[error(transparent)]
    Commitment(#[from] PermanentImportCandidateError),
    #[error(transparent)]
    Authorization(#[from] HybridCandidateError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermanentImportAppendCandidateV1 {
    pub previous_root: [u8; 64],
    pub new_root: [u8; 64],
    pub query: [u8; 32],
    pub previous_key_count: u32,
    pub new_key_count: u32,
    pub proof_sha512: [u8; 64],
    pub payload_root: [u8; 64],
}

/// Canonical fixed-width append intent preparation, NOT authorization. Scope is
/// currency32 || destination32. Complete proof bytes remain separately required.
pub fn prepare_permanent_import_append_candidate(
    scope: &[u8; 64],
    independently_current_root: &[u8; 64],
    query: &[u8; 32],
    complete_proof: &[u8],
) -> Result<PermanentImportAppendCandidateV1, PermanentImportCandidateError> {
    let membership = verify_permanent_import_proof_candidate(
        scope,
        independently_current_root,
        query,
        complete_proof,
    )?;
    let new_root = derive_permanent_import_append_candidate(
        scope,
        independently_current_root,
        query,
        complete_proof,
    )?;
    let new_count = membership
        .committed_key_count
        .checked_add(1)
        .ok_or(PermanentImportCandidateError::Capacity)?;
    let proof_sha512: [u8; 64] = Sha512::digest(complete_proof).into();
    let mut hash = Sha512::new();
    hash.update(DOMAIN);
    hash.update(scope);
    hash.update(independently_current_root);
    hash.update(query);
    hash.update(new_root);
    hash.update(membership.committed_key_count.to_be_bytes());
    hash.update(new_count.to_be_bytes());
    hash.update(proof_sha512);
    Ok(PermanentImportAppendCandidateV1 {
        previous_root: *independently_current_root,
        new_root,
        query: *query,
        previous_key_count: membership.committed_key_count,
        new_key_count: new_count,
        proof_sha512,
        payload_root: hash.finalize().into(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPermanentImportAppendCandidateV1 {
    pub append: PermanentImportAppendCandidateV1,
    pub verified_intent: HybridIntentCandidateV1,
}

/// Requires both actual signature halves over the exact append payload and a
/// dedicated purpose. Payment/finality/archive authorization cannot become ID
/// maintenance authority. The result cannot credit value or install any root.
pub fn verify_hybrid_permanent_import_append_candidate(
    policy: &HybridPolicyCandidateV1,
    observation: HybridObservationCandidateV1,
    independently_current_root: &[u8; 64],
    query: &[u8; 32],
    complete_proof: &[u8],
    detached_envelope: &[u8],
) -> Result<VerifiedPermanentImportAppendCandidateV1, HybridPermanentImportCandidateError> {
    if policy.purpose != HybridPurposeV1::PermanentImportAppend {
        return Err(HybridCandidateError::Scope.into());
    }
    let mut scope = [0; 64];
    scope[..32].copy_from_slice(&policy.currency_root);
    scope[32..].copy_from_slice(&policy.region_root);
    let append = prepare_permanent_import_append_candidate(
        &scope,
        independently_current_root,
        query,
        complete_proof,
    )?;
    let (intent, signatures) = decode_hybrid_public_envelope_candidate(detached_envelope)?;
    if intent.purpose != HybridPurposeV1::PermanentImportAppend
        || intent.payload_root != append.payload_root
    {
        return Err(HybridCandidateError::Scope.into());
    }
    verify_hybrid_authorization_candidate(policy, &intent, &signatures, observation)?;
    Ok(VerifiedPermanentImportAppendCandidateV1 {
        append,
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
    use serde_json::Value;

    struct Fixture {
        policy: HybridPolicyCandidateV1,
        root: [u8; 64],
        query: [u8; 32],
        proof: Vec<u8>,
        intent: HybridIntentCandidateV1,
        signatures: HybridProofCandidateV1,
    }
    fn bytes<const N: usize>(value: &Value) -> [u8; N] {
        hex::decode(value.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }
    fn fixture(purpose: HybridPurposeV1) -> Fixture {
        let value: Value = serde_json::from_str(include_str!(
            "../../../vectors/permanent-import-index-candidate-v1/vectors.json"
        ))
        .unwrap();
        let root = bytes(&value["root"]);
        let query = bytes(&value["cases"][3]["query"]);
        let proof = hex::decode(value["cases"][3]["proof"].as_str().unwrap()).unwrap();
        let scope = bytes(&value["scope"]);
        let append =
            prepare_permanent_import_append_candidate(&scope, &root, &query, &proof).unwrap();
        let mut rng = rand::rngs::OsRng;
        let ed = ed25519_dalek::SigningKey::generate(&mut rng);
        let (pq_public, pq_private) = ml_dsa_87::try_keygen_with_rng(&mut rng).unwrap();
        let policy = HybridPolicyCandidateV1 {
            profile: HYBRID_CANDIDATE_PROFILE.into(),
            currency_root: [1; 32],
            region_root: [2; 32],
            purpose,
            valid_from_epoch: 1,
            valid_until_epoch: 8,
            ed_public_key: ed.verifying_key().to_bytes(),
            pq_public_key: Box::new(pq_public.into_bytes()),
        };
        let intent = HybridIntentCandidateV1 {
            currency_root: policy.currency_root,
            region_root: policy.region_root,
            purpose,
            epoch: 2,
            nonce: 1,
            payload_root: append.payload_root,
        };
        let message = intent.signing_bytes();
        let signatures = HybridProofCandidateV1 {
            ed_signature: ed.sign(&message).to_bytes(),
            pq_signature: Box::new(
                pq_private
                    .try_sign_with_rng(&mut rng, &message, HYBRID_CANDIDATE_CONTEXT)
                    .unwrap(),
            ),
        };
        Fixture {
            policy,
            root,
            query,
            proof,
            intent,
            signatures,
        }
    }
    fn observed(epoch: u64) -> HybridObservationCandidateV1 {
        HybridObservationCandidateV1 {
            current_epoch: epoch,
            next_nonce: 1,
            policy_trust: HybridPolicyTrustV1::CurrentAndTrusted,
        }
    }
    fn check(
        f: &Fixture,
        observation: HybridObservationCandidateV1,
    ) -> Result<VerifiedPermanentImportAppendCandidateV1, HybridPermanentImportCandidateError> {
        verify_hybrid_permanent_import_append_candidate(
            &f.policy,
            observation,
            &f.root,
            &f.query,
            &f.proof,
            &encode_hybrid_public_envelope_candidate(&f.intent, &f.signatures),
        )
    }

    #[test]
    fn real_dual_append_accepts_finite_delay_without_installing_state() {
        let f = fixture(HybridPurposeV1::PermanentImportAppend);
        let expected = check(&f, observed(2)).unwrap();
        assert_eq!(expected.append.previous_root, f.root);
        assert_eq!(expected.append.previous_key_count, 5);
        assert_eq!(expected.append.new_key_count, 6);
        for epoch in [7, 8] {
            assert_eq!(check(&f, observed(epoch)).unwrap(), expected);
        }
        assert_eq!(
            check(&f, observed(9)),
            Err(HybridCandidateError::Horizon.into())
        );
        // A retained old signature cannot learn, replace or reset a current root.
        assert!(verify_hybrid_permanent_import_append_candidate(
            &f.policy,
            observed(2),
            &expected.append.new_root,
            &f.query,
            &f.proof,
            &encode_hybrid_public_envelope_candidate(&f.intent, &f.signatures)
        )
        .is_err());
    }

    #[test]
    fn both_bad_halves_and_valid_wrong_purpose_refuse() {
        let mut f = fixture(HybridPurposeV1::PermanentImportAppend);
        let original = f.signatures.clone();
        f.signatures.ed_signature[0] ^= 1;
        assert_eq!(
            check(&f, observed(2)),
            Err(HybridCandidateError::Classical.into())
        );
        f.signatures = original;
        f.signatures.pq_signature[0] ^= 1;
        assert_eq!(
            check(&f, observed(2)),
            Err(HybridCandidateError::PostQuantum.into())
        );
        for purpose in [
            HybridPurposeV1::Payment,
            HybridPurposeV1::Finality,
            HybridPurposeV1::ArchiveManifest,
        ] {
            let f = fixture(purpose);
            // Both signatures are genuine over the append payload under another purpose.
            assert_eq!(
                check(&f, observed(2)),
                Err(HybridCandidateError::Scope.into())
            );
        }
    }

    #[test]
    fn query_proof_scope_nonce_trust_and_duplicate_remain_bound() {
        let mut f = fixture(HybridPurposeV1::PermanentImportAppend);
        let mut stale = observed(2);
        stale.next_nonce = 2;
        assert_eq!(check(&f, stale), Err(HybridCandidateError::Scope.into()));
        for trust in [
            HybridPolicyTrustV1::Revoked,
            HybridPolicyTrustV1::Broken,
            HybridPolicyTrustV1::Unavailable,
        ] {
            let mut observation = observed(2);
            observation.policy_trust = trust;
            assert_eq!(
                check(&f, observation),
                Err(HybridCandidateError::Untrusted.into())
            );
        }
        let original_query = f.query;
        f.query[0] ^= 1;
        assert!(check(&f, observed(2)).is_err());
        f.query = original_query;
        let original_proof = f.proof.clone();
        f.proof.push(0);
        assert!(check(&f, observed(2)).is_err());
        f.proof = original_proof;
        f.policy.region_root[0] ^= 1;
        assert!(check(&f, observed(2)).is_err());
        f.policy.region_root[0] ^= 1;
        let value: Value = serde_json::from_str(include_str!(
            "../../../vectors/permanent-import-index-candidate-v1/vectors.json"
        ))
        .unwrap();
        f.query = bytes(&value["cases"][0]["query"]);
        f.proof = hex::decode(value["cases"][0]["proof"].as_str().unwrap()).unwrap();
        assert_eq!(
            check(&f, observed(2)),
            Err(PermanentImportCandidateError::Duplicate.into())
        );
    }
}
