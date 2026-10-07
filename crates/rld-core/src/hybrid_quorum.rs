//! Fixed 3-of-4 dual-signature finality candidate, not an adopted ledger format.
//! The complete roster and observations are independently trusted caller inputs.
//! No aggregation, policy discovery, signer locks or state installation occurs.

use crate::hybrid_authorization::{
    decode_hybrid_public_envelope_candidate, encode_hybrid_public_envelope_candidate,
    verify_hybrid_authorization_candidate, HybridCandidateError, HybridIntentCandidateV1,
    HybridObservationCandidateV1, HybridPolicyCandidateV1, HybridProofCandidateV1, HybridPurposeV1,
};
use serde::{Deserialize, Serialize};

pub const HYBRID_QUORUM_CANDIDATE_PROFILE: &str = "RLDCOIN-HYBRID-QUORUM-CANDIDATE-V1";
pub const HYBRID_QUORUM_CANDIDATE_MEMBERS: usize = 4;
pub const HYBRID_QUORUM_CANDIDATE_THRESHOLD: usize = 3;
/// Separate candidate parser bound, not an increase of any transport/ledger limit.
pub const HYBRID_QUORUM_CANDIDATE_MAX_PUBLIC_WIRE_BYTES: usize = 32 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridMemberProofCandidateV1 {
    pub member: u8,
    pub proof: HybridProofCandidateV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridQuorumCandidateV1 {
    pub intent: HybridIntentCandidateV1,
    pub members: Vec<HybridMemberProofCandidateV1>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HybridQuorumError {
    #[error("candidate quorum is oversized, malformed or noncanonical")]
    Encoding,
    #[error("candidate requires exactly three sorted distinct configured members")]
    Members,
    #[error("candidate roster shares classical or post-quantum signing identities")]
    SharedIdentity,
    #[error("candidate quorum must bind one finality intent")]
    Scope,
    #[error("candidate member authorization refused: {0}")]
    Authorization(HybridCandidateError),
}

fn members(quorum: &HybridQuorumCandidateV1) -> Result<(), HybridQuorumError> {
    if quorum.members.len() != HYBRID_QUORUM_CANDIDATE_THRESHOLD
        || quorum
            .members
            .iter()
            .any(|m| usize::from(m.member) >= HYBRID_QUORUM_CANDIDATE_MEMBERS)
        || quorum
            .members
            .windows(2)
            .any(|pair| pair[0].member >= pair[1].member)
    {
        return Err(HybridQuorumError::Members);
    }
    if quorum.intent.purpose != HybridPurposeV1::Finality {
        return Err(HybridQuorumError::Scope);
    }
    Ok(())
}

/// All three proofs must independently verify against their configured identities
/// and local horizons/nonces. An unavailable fourth voter does not lower the
/// threshold; a shared key anywhere in the configured roster refuses the profile.
pub fn verify_hybrid_quorum_candidate(
    policies: &[HybridPolicyCandidateV1; HYBRID_QUORUM_CANDIDATE_MEMBERS],
    quorum: &HybridQuorumCandidateV1,
    observations: &[HybridObservationCandidateV1; HYBRID_QUORUM_CANDIDATE_MEMBERS],
) -> Result<(), HybridQuorumError> {
    members(quorum)?;
    for (index, policy) in policies.iter().enumerate() {
        for other in &policies[..index] {
            if policy.ed_public_key == other.ed_public_key
                || policy.pq_public_key == other.pq_public_key
            {
                return Err(HybridQuorumError::SharedIdentity);
            }
        }
    }
    for member in &quorum.members {
        let index = usize::from(member.member);
        verify_hybrid_authorization_candidate(
            &policies[index],
            &quorum.intent,
            &member.proof,
            observations[index],
        )
        .map_err(HybridQuorumError::Authorization)?;
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicMemberV1 {
    envelope: serde_json::Value,
    member: u8,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicQuorumV1 {
    members: Vec<PublicMemberV1>,
    profile: String,
}

/// Exact public envelopes retain all individual signature/domain fields. No
/// public keys are learned from the wire; no compression or aggregation is implied.
pub fn encode_hybrid_quorum_candidate(
    quorum: &HybridQuorumCandidateV1,
) -> Result<Vec<u8>, HybridQuorumError> {
    members(quorum)?;
    let public = PublicQuorumV1 {
        members: quorum
            .members
            .iter()
            .map(|member| PublicMemberV1 {
                envelope: serde_json::from_slice(&encode_hybrid_public_envelope_candidate(
                    &quorum.intent,
                    &member.proof,
                ))
                .expect("fixed public envelope is valid JSON"),
                member: member.member,
            })
            .collect(),
        profile: HYBRID_QUORUM_CANDIDATE_PROFILE.into(),
    };
    let bytes = serde_json::to_vec(&public).expect("fixed public quorum serializes");
    if bytes.len() > HYBRID_QUORUM_CANDIDATE_MAX_PUBLIC_WIRE_BYTES {
        return Err(HybridQuorumError::Encoding);
    }
    Ok(bytes)
}

/// Bound the whole input before allocation/parsing. Canonical re-encoding also
/// rejects duplicate fields erased by a nested JSON Value, alternate whitespace,
/// key ordering and numeric representations. Decode grants no finality authority.
pub fn decode_hybrid_quorum_candidate(
    bytes: &[u8],
) -> Result<HybridQuorumCandidateV1, HybridQuorumError> {
    if bytes.len() > HYBRID_QUORUM_CANDIDATE_MAX_PUBLIC_WIRE_BYTES {
        return Err(HybridQuorumError::Encoding);
    }
    let public: PublicQuorumV1 =
        serde_json::from_slice(bytes).map_err(|_| HybridQuorumError::Encoding)?;
    if public.profile != HYBRID_QUORUM_CANDIDATE_PROFILE
        || public.members.len() != HYBRID_QUORUM_CANDIDATE_THRESHOLD
    {
        return Err(HybridQuorumError::Encoding);
    }
    let mut intent = None;
    let mut proofs = Vec::with_capacity(HYBRID_QUORUM_CANDIDATE_THRESHOLD);
    for member in public.members {
        let raw = serde_json::to_vec(&member.envelope).map_err(|_| HybridQuorumError::Encoding)?;
        let (member_intent, proof) = decode_hybrid_public_envelope_candidate(&raw)
            .map_err(|_| HybridQuorumError::Encoding)?;
        if intent.as_ref().is_some_and(|known| known != &member_intent) {
            return Err(HybridQuorumError::Scope);
        }
        intent = Some(member_intent);
        proofs.push(HybridMemberProofCandidateV1 {
            member: member.member,
            proof,
        });
    }
    let quorum = HybridQuorumCandidateV1 {
        intent: intent.ok_or(HybridQuorumError::Encoding)?,
        members: proofs,
    };
    if encode_hybrid_quorum_candidate(&quorum)? != bytes {
        return Err(HybridQuorumError::Encoding);
    }
    Ok(quorum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid_authorization::{
        HybridPolicyTrustV1, HYBRID_CANDIDATE_CONTEXT, HYBRID_CANDIDATE_MAX_PUBLIC_WIRE_BYTES,
        HYBRID_CANDIDATE_PROFILE,
    };
    use ed25519_dalek::Signer as _;
    use fips204::{
        ml_dsa_87,
        traits::{SerDes, Signer as _},
    };

    struct Fixture {
        policies: [HybridPolicyCandidateV1; 4],
        observations: [HybridObservationCandidateV1; 4],
        quorum: HybridQuorumCandidateV1,
    }

    fn fresh() -> Fixture {
        fresh_selected([0, 1, 2])
    }

    fn fresh_selected(selected: [usize; 3]) -> Fixture {
        // All secret keys are fresh RAM-only fixture objects; never written or printed.
        let intent = HybridIntentCandidateV1 {
            currency_root: [1; 32],
            region_root: [2; 32],
            purpose: HybridPurposeV1::Finality,
            epoch: 2,
            nonce: 1,
            payload_root: [3; 64],
        };
        let mut proofs = Vec::new();
        let policies = std::array::from_fn(|member| {
            let ed = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
            let (public, pq) = ml_dsa_87::try_keygen_with_rng(&mut rand::rngs::OsRng).unwrap();
            if selected.contains(&member) {
                proofs.push(HybridMemberProofCandidateV1 {
                    member: member as u8,
                    proof: HybridProofCandidateV1 {
                        ed_signature: ed.sign(&intent.signing_bytes()).to_bytes(),
                        pq_signature: Box::new(
                            pq.try_sign_with_rng(
                                &mut rand::rngs::OsRng,
                                &intent.signing_bytes(),
                                HYBRID_CANDIDATE_CONTEXT,
                            )
                            .unwrap(),
                        ),
                    },
                });
            }
            HybridPolicyCandidateV1 {
                profile: HYBRID_CANDIDATE_PROFILE.into(),
                currency_root: intent.currency_root,
                region_root: intent.region_root,
                purpose: intent.purpose,
                valid_from_epoch: 1,
                valid_until_epoch: 9,
                ed_public_key: ed.verifying_key().to_bytes(),
                pq_public_key: Box::new(public.into_bytes()),
            }
        });
        Fixture {
            policies,
            observations: [HybridObservationCandidateV1 {
                current_epoch: 2,
                next_nonce: 1,
                policy_trust: HybridPolicyTrustV1::CurrentAndTrusted,
            }; 4],
            quorum: HybridQuorumCandidateV1 {
                intent,
                members: proofs,
            },
        }
    }

    #[test]
    fn quorum_accepts_every_three_member_subset_with_the_fourth_unavailable() {
        for selected in [[0, 1, 2], [0, 1, 3], [0, 2, 3], [1, 2, 3]] {
            let mut f = fresh_selected(selected);
            for member in 0..4 {
                if !selected.contains(&member) {
                    f.observations[member].policy_trust = HybridPolicyTrustV1::Unavailable;
                }
            }
            assert!(
                verify_hybrid_quorum_candidate(&f.policies, &f.quorum, &f.observations).is_ok()
            );
            let raw = encode_hybrid_quorum_candidate(&f.quorum).unwrap();
            let decoded = decode_hybrid_quorum_candidate(&raw).unwrap();
            assert_eq!(decoded, f.quorum);
            assert!(verify_hybrid_quorum_candidate(&f.policies, &decoded, &f.observations).is_ok());
        }
    }

    #[test]
    fn quorum_requires_distinct_actual_dual_signatures_not_three_successful_calls() {
        let mut f = fresh();
        assert!(verify_hybrid_quorum_candidate(&f.policies, &f.quorum, &f.observations).is_ok());
        // Single-proof verification repeated three times is not a quorum check.
        for _ in 0..3 {
            assert!(verify_hybrid_authorization_candidate(
                &f.policies[0],
                &f.quorum.intent,
                &f.quorum.members[0].proof,
                f.observations[0]
            )
            .is_ok());
        }
        f.quorum.members = vec![f.quorum.members[0].clone(); 3];
        assert_eq!(
            verify_hybrid_quorum_candidate(&f.policies, &f.quorum, &f.observations),
            Err(HybridQuorumError::Members)
        );
    }

    #[test]
    fn quorum_refuses_wrong_member_missing_vote_order_and_shared_roster_halves() {
        let f = fresh();
        for member in [1, 4, u8::MAX] {
            let mut q = f.quorum.clone();
            q.members[0].member = member;
            assert!(verify_hybrid_quorum_candidate(&f.policies, &q, &f.observations).is_err());
        }
        let mut q = f.quorum.clone();
        q.members[1].proof = q.members[0].proof.clone();
        assert!(verify_hybrid_quorum_candidate(&f.policies, &q, &f.observations).is_err());
        q = f.quorum.clone();
        q.members.swap(0, 1);
        assert_eq!(
            verify_hybrid_quorum_candidate(&f.policies, &q, &f.observations),
            Err(HybridQuorumError::Members)
        );
        for size in [0, 1, 2, 4] {
            let mut q = f.quorum.clone();
            q.members.resize(size, q.members[0].clone());
            assert_eq!(
                verify_hybrid_quorum_candidate(&f.policies, &q, &f.observations),
                Err(HybridQuorumError::Members)
            );
        }
        let mut policies = f.policies.clone();
        policies[3].ed_public_key = policies[0].ed_public_key;
        assert_eq!(
            verify_hybrid_quorum_candidate(&policies, &f.quorum, &f.observations),
            Err(HybridQuorumError::SharedIdentity)
        );
        policies = f.policies.clone();
        *policies[3].pq_public_key = *policies[0].pq_public_key;
        assert_eq!(
            verify_hybrid_quorum_candidate(&policies, &f.quorum, &f.observations),
            Err(HybridQuorumError::SharedIdentity)
        );
    }

    #[test]
    fn quorum_preserves_each_member_scope_nonce_horizon_and_current_trust() {
        let f = fresh();
        for trust in [
            HybridPolicyTrustV1::Revoked,
            HybridPolicyTrustV1::Broken,
            HybridPolicyTrustV1::Unavailable,
        ] {
            let mut observations = f.observations;
            observations[0].policy_trust = trust;
            assert!(verify_hybrid_quorum_candidate(&f.policies, &f.quorum, &observations).is_err());
            observations = f.observations;
            observations[3].policy_trust = trust;
            assert!(verify_hybrid_quorum_candidate(&f.policies, &f.quorum, &observations).is_ok());
        }
        let mut observations = f.observations;
        observations[1].next_nonce = 2;
        assert!(verify_hybrid_quorum_candidate(&f.policies, &f.quorum, &observations).is_err());
        observations = f.observations;
        observations[1].current_epoch = 10;
        assert!(verify_hybrid_quorum_candidate(&f.policies, &f.quorum, &observations).is_err());
        for field in 0..4 {
            let mut policies = f.policies.clone();
            match field {
                0 => policies[1].currency_root[0] ^= 1,
                1 => policies[1].region_root[0] ^= 1,
                2 => policies[1].purpose = HybridPurposeV1::Payment,
                _ => policies[1].profile.push_str("-unknown"),
            }
            assert!(verify_hybrid_quorum_candidate(&policies, &f.quorum, &f.observations).is_err());
        }
    }

    #[test]
    fn quorum_decoding_never_substitutes_for_both_signature_verifications() {
        let f = fresh();
        for pq in [false, true] {
            let mut q = f.quorum.clone();
            if pq {
                q.members[1].proof.pq_signature[0] ^= 1;
            } else {
                q.members[1].proof.ed_signature[0] ^= 1;
            }
            let bytes = encode_hybrid_quorum_candidate(&q).unwrap();
            let decoded = decode_hybrid_quorum_candidate(&bytes).unwrap();
            assert_eq!(q, decoded);
            assert!(
                verify_hybrid_quorum_candidate(&f.policies, &decoded, &f.observations).is_err()
            );
        }
        let mut q = f.quorum;
        q.intent.purpose = HybridPurposeV1::Payment;
        assert_eq!(
            encode_hybrid_quorum_candidate(&q),
            Err(HybridQuorumError::Scope)
        );
    }

    #[test]
    fn quorum_wire_refuses_mixed_intents_duplicates_unknown_fields_and_alternate_json() {
        let f = fresh();
        let raw = encode_hybrid_quorum_candidate(&f.quorum).unwrap();
        let canonical = String::from_utf8(raw.clone()).unwrap();
        let mut cases = vec![
            vec![b' '; HYBRID_QUORUM_CANDIDATE_MAX_PUBLIC_WIRE_BYTES + 1],
            [raw.as_slice(), b"\n"].concat(),
            raw[..raw.len() - 1].to_vec(),
        ];
        for (from, to) in [
            ("\"member\":0", "\"member\":false"),
            ("\"member\":0", "\"member\":0,\"member\":0"),
            ("\"member\":0", "\"member\":0,\"extra\":0"),
            ("\"nonce\":1", "\"nonce\":1,\"nonce\":1"),
            ("\"nonce\":1", "\"nonce\":2"),
            ("QUORUM-CANDIDATE-V1", "QUORUM-CANDIDATE-unknown"),
            ("\"epoch\":2", "\"epoch\":2.0"),
            ("\"candidate_only\":true", "\"candidate_only\":false"),
        ] {
            assert!(canonical.contains(from));
            cases.push(canonical.replacen(from, to, 1).into_bytes());
        }
        for case in cases {
            assert!(decode_hybrid_quorum_candidate(&case).is_err());
        }
        let mut q = f.quorum;
        q.members[1].member = 0;
        assert!(encode_hybrid_quorum_candidate(&q).is_err());
    }

    #[test]
    fn quorum_measures_complete_public_wire_and_refuses_single_envelope_transport_assumption() {
        let f = fresh();
        let wire = encode_hybrid_quorum_candidate(&f.quorum).unwrap();
        let decoded = decode_hybrid_quorum_candidate(&wire).unwrap();
        assert_eq!(decoded, f.quorum);
        let at = std::time::Instant::now();
        assert!(verify_hybrid_quorum_candidate(&f.policies, &decoded, &f.observations).is_ok());
        let seconds = at.elapsed().as_secs_f64();
        let public_keys = f
            .policies
            .iter()
            .map(|p| p.ed_public_key.len() + p.pq_public_key.len())
            .sum::<usize>();
        let signatures = f
            .quorum
            .members
            .iter()
            .map(|p| p.proof.ed_signature.len() + p.proof.pq_signature.len())
            .sum::<usize>();
        assert_eq!(public_keys, 4 * (32 + 2592));
        assert_eq!(signatures, 3 * (64 + 4627));
        assert!(wire.len() > HYBRID_CANDIDATE_MAX_PUBLIC_WIRE_BYTES);
        assert!(wire.len() <= HYBRID_QUORUM_CANDIDATE_MAX_PUBLIC_WIRE_BYTES);
        println!("HYBRID_QUORUM_RESOURCE_V1 {{\"candidate_only\":true,\"members\":4,\"threshold\":3,\"signatures_bytes\":{signatures},\"configured_public_keys_bytes\":{public_keys},\"complete_public_wire_bytes\":{},\"single_envelope_transport_limit\":{},\"single_envelope_transport_fits\":false,\"one_actual_verification_seconds\":{seconds},\"adopted\":false}}", wire.len(), HYBRID_CANDIDATE_MAX_PUBLIC_WIRE_BYTES);
    }
}
