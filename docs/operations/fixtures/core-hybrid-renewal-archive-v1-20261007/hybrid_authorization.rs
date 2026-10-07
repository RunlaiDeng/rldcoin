//! Deterministic, verification-only hybrid candidate. No adopted ledger uses it.
//!
//! The caller must authenticate the policy and observation independently, and
//! persist nonce consumption atomically with its eventual state change. This
//! module neither discovers trust nor changes balances, epochs or signer locks.
//! A retired, revoked, broken or unavailable policy cannot be rehabilitated by
//! a fresh signature. Transport receipts are never authorization observations.

use crate::crypto::validate_ed25519_public_key;
use ed25519_dalek::{Signature, VerifyingKey};
use fips204::{
    ml_dsa_87,
    traits::{SerDes, Verifier},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

pub const HYBRID_CANDIDATE_PROFILE: &str = "RLDCOIN-HYBRID-AUTH-CANDIDATE-V1";
pub const HYBRID_CANDIDATE_CONTEXT: &[u8] = b"RLDCOIN-PQ-AUTH-CANDIDATE-V1";
const MESSAGE_DOMAIN: &[u8] = b"RLDCOIN-HYBRID-AUTH-CANDIDATE-V1\0";
/// A separately versioned candidate envelope bound; existing network, ledger
/// and archival limits are unchanged. This format grants no admission rights.
pub const HYBRID_CANDIDATE_MAX_PUBLIC_WIRE_BYTES: usize = 12 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HybridPurposeV1 {
    Payment,
    Finality,
    Admission,
    Governance,
    Renewal,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridPolicyCandidateV1 {
    pub profile: String,
    pub currency_root: [u8; 32],
    pub region_root: [u8; 32],
    pub purpose: HybridPurposeV1,
    pub valid_from_epoch: u64,
    pub valid_until_epoch: u64,
    pub ed_public_key: [u8; 32],
    pub pq_public_key: Box<[u8; 2592]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridIntentCandidateV1 {
    pub currency_root: [u8; 32],
    pub region_root: [u8; 32],
    pub purpose: HybridPurposeV1,
    pub epoch: u64,
    pub nonce: u64,
    pub payload_root: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridProofCandidateV1 {
    pub ed_signature: [u8; 64],
    pub pq_signature: Box<[u8; 4627]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HybridPolicyTrustV1 {
    CurrentAndTrusted,
    Revoked,
    Broken,
    Unavailable,
}

/// An independently authenticated local observation, never inferred from the
/// intent's timestamp or a peer's claim. Unknown revocation remains unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HybridObservationCandidateV1 {
    pub current_epoch: u64,
    pub next_nonce: u64,
    pub policy_trust: HybridPolicyTrustV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HybridCandidateError {
    #[error("candidate public envelope is malformed, oversized or noncanonical")]
    Encoding,
    #[error("candidate profile or policy invalid")]
    Policy,
    #[error("candidate authority is revoked, broken or unavailable")]
    Untrusted,
    #[error("candidate outside the authenticated finite epoch horizon")]
    Horizon,
    #[error("candidate purpose, roots or nonce differ from local authority")]
    Scope,
    #[error("candidate classical key or signature invalid")]
    Classical,
    #[error("candidate post-quantum key or signature invalid")]
    PostQuantum,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicWireIntentV1 {
    candidate_only: bool,
    currency_root: String,
    epoch: u64,
    nonce: u64,
    payload_root: String,
    purpose: HybridPurposeV1,
    region_root: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicWireEnvelopeV1 {
    ed_signature: String,
    intent: PublicWireIntentV1,
    pq_signature: String,
    profile: String,
}

fn decode_canonical_hex<const N: usize>(value: &str) -> Result<[u8; N], HybridCandidateError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(HybridCandidateError::Encoding);
    }
    hex::decode(value)
        .map_err(|_| HybridCandidateError::Encoding)?
        .try_into()
        .map_err(|_| HybridCandidateError::Encoding)
}

/// Canonical public bytes only: no key lookup, signing or state change.
pub fn encode_hybrid_public_envelope_candidate(
    intent: &HybridIntentCandidateV1,
    proof: &HybridProofCandidateV1,
) -> Vec<u8> {
    let wire = PublicWireEnvelopeV1 {
        ed_signature: hex::encode(proof.ed_signature),
        intent: PublicWireIntentV1 {
            candidate_only: true,
            currency_root: hex::encode(intent.currency_root),
            epoch: intent.epoch,
            nonce: intent.nonce,
            payload_root: hex::encode(intent.payload_root),
            purpose: intent.purpose,
            region_root: hex::encode(intent.region_root),
        },
        pq_signature: hex::encode(proof.pq_signature.as_ref()),
        profile: HYBRID_CANDIDATE_PROFILE.into(),
    };
    serde_json::to_vec(&wire).expect("fixed public candidate primitives serialize")
}

/// Reject the entire public input before parsing if it exceeds the fixed bound.
/// Duplicate/unknown fields, extra data, noninteger positions, unknown roles,
/// missing components and any alternate JSON/hex encoding refuse. Successful
/// decoding is deliberately not signature verification or ledger authority.
pub fn decode_hybrid_public_envelope_candidate(
    raw: &[u8],
) -> Result<(HybridIntentCandidateV1, HybridProofCandidateV1), HybridCandidateError> {
    if raw.len() > HYBRID_CANDIDATE_MAX_PUBLIC_WIRE_BYTES {
        return Err(HybridCandidateError::Encoding);
    }
    let wire: PublicWireEnvelopeV1 =
        serde_json::from_slice(raw).map_err(|_| HybridCandidateError::Encoding)?;
    if wire.profile != HYBRID_CANDIDATE_PROFILE
        || !wire.intent.candidate_only
        || wire.intent.epoch == 0
        || wire.intent.nonce == 0
    {
        return Err(HybridCandidateError::Encoding);
    }
    let intent = HybridIntentCandidateV1 {
        currency_root: decode_canonical_hex(&wire.intent.currency_root)?,
        region_root: decode_canonical_hex(&wire.intent.region_root)?,
        purpose: wire.intent.purpose,
        epoch: wire.intent.epoch,
        nonce: wire.intent.nonce,
        payload_root: decode_canonical_hex(&wire.intent.payload_root)?,
    };
    let proof = HybridProofCandidateV1 {
        ed_signature: decode_canonical_hex(&wire.ed_signature)?,
        pq_signature: Box::new(decode_canonical_hex(&wire.pq_signature)?),
    };
    if encode_hybrid_public_envelope_candidate(&intent, &proof) != raw {
        return Err(HybridCandidateError::Encoding);
    }
    Ok((intent, proof))
}

impl HybridIntentCandidateV1 {
    /// Exact bounded canonical JSON of this candidate, shared with the public
    /// OpenSSL verifier. Sorted ASCII field names and integer encoding only.
    pub fn signing_bytes(&self) -> Vec<u8> {
        #[derive(Serialize)]
        struct Canonical<'a> {
            candidate_only: bool,
            currency_root: String,
            epoch: u64,
            nonce: u64,
            payload_root: String,
            purpose: &'a HybridPurposeV1,
            region_root: String,
        }
        let value = Canonical {
            candidate_only: true,
            currency_root: hex::encode(self.currency_root),
            epoch: self.epoch,
            nonce: self.nonce,
            payload_root: hex::encode(self.payload_root),
            purpose: &self.purpose,
            region_root: hex::encode(self.region_root),
        };
        let mut bytes = MESSAGE_DOMAIN.to_vec();
        // Fixed fields and primitive serializer inputs cannot produce an error.
        bytes.extend(serde_json::to_vec(&value).expect("fixed candidate primitives serialize"));
        bytes
    }
}

fn verify_pq(
    key: &[u8; 2592],
    signature: &[u8; 4627],
    message: &[u8],
    context: &[u8],
) -> Result<(), HybridCandidateError> {
    let key = ml_dsa_87::PublicKey::try_from_bytes(*key)
        .map_err(|_| HybridCandidateError::PostQuantum)?;
    if key.verify(message, signature, context) {
        Ok(())
    } else {
        Err(HybridCandidateError::PostQuantum)
    }
}

/// Verify BOTH components over identical canonical bytes. There is no OR,
/// classical fallback, alternate suite lookup, private key or wall-clock input.
/// Success is a signature result, not a spend/consensus/import permission.
pub fn verify_hybrid_authorization_candidate(
    policy: &HybridPolicyCandidateV1,
    intent: &HybridIntentCandidateV1,
    proof: &HybridProofCandidateV1,
    observation: HybridObservationCandidateV1,
) -> Result<(), HybridCandidateError> {
    if policy.profile != HYBRID_CANDIDATE_PROFILE
        || policy.valid_from_epoch == 0
        || policy.valid_until_epoch < policy.valid_from_epoch
    {
        return Err(HybridCandidateError::Policy);
    }
    if observation.policy_trust != HybridPolicyTrustV1::CurrentAndTrusted {
        return Err(HybridCandidateError::Untrusted);
    }
    if observation.current_epoch < policy.valid_from_epoch
        || observation.current_epoch > policy.valid_until_epoch
        || intent.epoch < policy.valid_from_epoch
        || intent.epoch > observation.current_epoch
    {
        return Err(HybridCandidateError::Horizon);
    }
    if intent.currency_root != policy.currency_root
        || intent.region_root != policy.region_root
        || intent.purpose != policy.purpose
        || observation.next_nonce == 0
        || intent.nonce != observation.next_nonce
    {
        return Err(HybridCandidateError::Scope);
    }
    validate_ed25519_public_key(&hex::encode(policy.ed_public_key))
        .map_err(|_| HybridCandidateError::Classical)?;
    let key = VerifyingKey::from_bytes(&policy.ed_public_key)
        .map_err(|_| HybridCandidateError::Classical)?;
    let message = intent.signing_bytes();
    key.verify_strict(&message, &Signature::from_bytes(&proof.ed_signature))
        .map_err(|_| HybridCandidateError::Classical)?;
    verify_pq(
        &policy.pq_public_key,
        &proof.pq_signature,
        &message,
        HYBRID_CANDIDATE_CONTEXT,
    )
}

/// A caller-authenticated candidate renewal anchor. Commitments stand for the
/// actual caller locks and permanent consumed-export records; this model never
/// replaces, reconstructs or releases those records. Durable atomic adoption
/// and independent trust-anchor custody remain requirements of its caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridRenewalAnchorCandidateV1 {
    pub policy: HybridPolicyCandidateV1,
    pub crypto_era: u64,
    pub key_epoch: u64,
    pub next_nonce: u64,
    pub last_transition: [u8; 64],
    pub caller_locks_root: [u8; 64],
    pub consumed_exports_root: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridRenewalCandidateV1 {
    pub previous_transition: [u8; 64],
    pub new_crypto_era: u64,
    pub new_key_epoch: u64,
    pub activation_epoch: u64,
    pub next_policy: HybridPolicyCandidateV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridJointRenewalProofCandidateV1 {
    pub old: HybridProofCandidateV1,
    pub new: HybridProofCandidateV1,
}

fn policy_commitment_bytes(policy: &HybridPolicyCandidateV1) -> Vec<u8> {
    let mut bytes = b"RLD-PQ-RENEWAL-POLICY-CANDIDATE-V1\0".to_vec();
    bytes.extend_from_slice(&(policy.profile.len() as u64).to_be_bytes());
    bytes.extend_from_slice(policy.profile.as_bytes());
    bytes.extend_from_slice(&policy.currency_root);
    bytes.extend_from_slice(&policy.region_root);
    bytes.push(match policy.purpose {
        HybridPurposeV1::Payment => 1,
        HybridPurposeV1::Finality => 2,
        HybridPurposeV1::Admission => 3,
        HybridPurposeV1::Governance => 4,
        HybridPurposeV1::Renewal => 5,
    });
    bytes.extend_from_slice(&policy.valid_from_epoch.to_be_bytes());
    bytes.extend_from_slice(&policy.valid_until_epoch.to_be_bytes());
    bytes.extend_from_slice(&policy.ed_public_key);
    bytes.extend_from_slice(policy.pq_public_key.as_ref());
    bytes
}

impl HybridRenewalCandidateV1 {
    /// Public signing preview only. It does not validate or authorize a renewal.
    /// All key, era, predecessor, lock and consumed-record fields are signed.
    pub fn signing_intent(
        &self,
        anchor: &HybridRenewalAnchorCandidateV1,
    ) -> Result<HybridIntentCandidateV1, HybridCandidateError> {
        if anchor.policy.profile != HYBRID_CANDIDATE_PROFILE
            || self.next_policy.profile != HYBRID_CANDIDATE_PROFILE
        {
            return Err(HybridCandidateError::Policy);
        }
        let mut hash = Sha512::new();
        hash.update(b"RLD-PQ-JOINT-RENEWAL-CANDIDATE-V1\0");
        hash.update(policy_commitment_bytes(&anchor.policy));
        hash.update(policy_commitment_bytes(&self.next_policy));
        for number in [
            anchor.crypto_era,
            anchor.key_epoch,
            anchor.next_nonce,
            self.new_crypto_era,
            self.new_key_epoch,
            self.activation_epoch,
        ] {
            hash.update(number.to_be_bytes());
        }
        hash.update(anchor.last_transition);
        hash.update(self.previous_transition);
        hash.update(anchor.caller_locks_root);
        hash.update(anchor.consumed_exports_root);
        Ok(HybridIntentCandidateV1 {
            currency_root: anchor.policy.currency_root,
            region_root: anchor.policy.region_root,
            purpose: HybridPurposeV1::Renewal,
            epoch: self.activation_epoch,
            nonce: anchor.next_nonce,
            payload_root: hash.finalize().into(),
        })
    }
}

/// Return a new anchor only after the complete old AND new dual signatures.
/// The input remains untouched on every failure. The caller must install this
/// result atomically with its actual locks/consumed records and latest head.
/// These are logical-time candidate rules, not a cryptographic lifetime claim.
pub fn verify_joint_hybrid_renewal_candidate(
    anchor: &HybridRenewalAnchorCandidateV1,
    renewal: &HybridRenewalCandidateV1,
    proof: &HybridJointRenewalProofCandidateV1,
    observation: HybridObservationCandidateV1,
) -> Result<HybridRenewalAnchorCandidateV1, HybridCandidateError> {
    let next_nonce = anchor
        .next_nonce
        .checked_add(1)
        .ok_or(HybridCandidateError::Scope)?;
    if anchor.crypto_era == 0
        || anchor.key_epoch == 0
        || anchor.next_nonce == 0
        || anchor.policy.purpose != HybridPurposeV1::Renewal
        || renewal.next_policy.purpose != HybridPurposeV1::Renewal
        || renewal.previous_transition != anchor.last_transition
        || Some(renewal.new_crypto_era) != anchor.crypto_era.checked_add(1)
        || Some(renewal.new_key_epoch) != anchor.key_epoch.checked_add(1)
        || observation.next_nonce != anchor.next_nonce
        || renewal.activation_epoch > observation.current_epoch
        || renewal.next_policy.ed_public_key == anchor.policy.ed_public_key
        || renewal.next_policy.pq_public_key == anchor.policy.pq_public_key
    {
        return Err(HybridCandidateError::Scope);
    }
    let intent = renewal.signing_intent(anchor)?;
    // Reject expired/broken/revoked originals before considering new possession.
    verify_hybrid_authorization_candidate(&anchor.policy, &intent, &proof.old, observation)?;
    // The old signature authenticates all new policy bytes. The new signature
    // demonstrates possession under exactly that authorized policy, not a
    // self-signed replacement trust anchor.
    verify_hybrid_authorization_candidate(
        &renewal.next_policy,
        &intent,
        &proof.new,
        HybridObservationCandidateV1 {
            policy_trust: HybridPolicyTrustV1::CurrentAndTrusted,
            ..observation
        },
    )?;
    let mut hash = Sha512::new();
    hash.update(b"RLD-PQ-JOINT-RENEWAL-HEAD-CANDIDATE-V1\0");
    hash.update(intent.signing_bytes());
    hash.update(proof.old.ed_signature);
    hash.update(proof.old.pq_signature.as_ref());
    hash.update(proof.new.ed_signature);
    hash.update(proof.new.pq_signature.as_ref());
    Ok(HybridRenewalAnchorCandidateV1 {
        policy: renewal.next_policy.clone(),
        crypto_era: renewal.new_crypto_era,
        key_epoch: renewal.new_key_epoch,
        next_nonce,
        last_transition: hash.finalize().into(),
        caller_locks_root: anchor.caller_locks_root,
        consumed_exports_root: anchor.consumed_exports_root,
    })
}

/// Separate complete-renewal parser bound. Existing transport/ledger limits
/// remain unchanged; the old trusted anchor is never obtained from this wire.
pub const HYBRID_RENEWAL_CANDIDATE_MAX_PUBLIC_WIRE_BYTES: usize = 32 * 1024;
pub const HYBRID_RENEWAL_WIRE_CANDIDATE_PROFILE: &str =
    "RLDCOIN-HYBRID-JOINT-RENEWAL-WIRE-CANDIDATE-V1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicRenewalPolicyV1 {
    currency_root: String,
    ed_public_key: String,
    pq_public_key: String,
    profile: String,
    purpose: HybridPurposeV1,
    region_root: String,
    valid_from_epoch: u64,
    valid_until_epoch: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicRenewalProofV1 {
    ed_signature: String,
    pq_signature: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicJointRenewalProofV1 {
    new: PublicRenewalProofV1,
    old: PublicRenewalProofV1,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicJointRenewalV1 {
    activation_epoch: u64,
    new_crypto_era: u64,
    new_key_epoch: u64,
    next_policy: PublicRenewalPolicyV1,
    previous_transition: String,
    profile: String,
    proof: PublicJointRenewalProofV1,
}

fn renewal_wire_shape(renewal: &HybridRenewalCandidateV1) -> Result<(), HybridCandidateError> {
    if renewal.activation_epoch == 0
        || renewal.new_crypto_era == 0
        || renewal.new_key_epoch == 0
        || renewal.next_policy.profile != HYBRID_CANDIDATE_PROFILE
        || renewal.next_policy.purpose != HybridPurposeV1::Renewal
        || renewal.next_policy.valid_from_epoch == 0
        || renewal.next_policy.valid_until_epoch < renewal.next_policy.valid_from_epoch
    {
        return Err(HybridCandidateError::Encoding);
    }
    Ok(())
}

/// All four signatures and the complete new policy are retained. No old policy,
/// trust observation, lock or consumed record is replaced by a peer's bytes.
/// This is encoding, not authentication, renewal activation or durable adoption.
pub fn encode_joint_hybrid_renewal_candidate(
    renewal: &HybridRenewalCandidateV1,
    proof: &HybridJointRenewalProofCandidateV1,
) -> Result<Vec<u8>, HybridCandidateError> {
    renewal_wire_shape(renewal)?;
    let policy = &renewal.next_policy;
    let public_proof = |proof: &HybridProofCandidateV1| PublicRenewalProofV1 {
        ed_signature: hex::encode(proof.ed_signature),
        pq_signature: hex::encode(proof.pq_signature.as_ref()),
    };
    let public = PublicJointRenewalV1 {
        activation_epoch: renewal.activation_epoch,
        new_crypto_era: renewal.new_crypto_era,
        new_key_epoch: renewal.new_key_epoch,
        next_policy: PublicRenewalPolicyV1 {
            currency_root: hex::encode(policy.currency_root),
            ed_public_key: hex::encode(policy.ed_public_key),
            pq_public_key: hex::encode(policy.pq_public_key.as_ref()),
            profile: policy.profile.clone(),
            purpose: policy.purpose,
            region_root: hex::encode(policy.region_root),
            valid_from_epoch: policy.valid_from_epoch,
            valid_until_epoch: policy.valid_until_epoch,
        },
        previous_transition: hex::encode(renewal.previous_transition),
        profile: HYBRID_RENEWAL_WIRE_CANDIDATE_PROFILE.into(),
        proof: PublicJointRenewalProofV1 {
            new: public_proof(&proof.new),
            old: public_proof(&proof.old),
        },
    };
    let raw = serde_json::to_vec(&public).expect("fixed candidate primitives serialize");
    if raw.len() > HYBRID_RENEWAL_CANDIDATE_MAX_PUBLIC_WIRE_BYTES {
        return Err(HybridCandidateError::Encoding);
    }
    Ok(raw)
}

/// Check the entire input bound before parsing. Exact re-encoding rejects
/// alternate JSON, numeric/hex encodings, duplicate, missing and unknown fields.
/// Call verify_joint_hybrid_renewal_candidate with a separately trusted anchor
/// and observation afterward; even a decoded valid signature changes no state.
pub fn decode_joint_hybrid_renewal_candidate(
    raw: &[u8],
) -> Result<(HybridRenewalCandidateV1, HybridJointRenewalProofCandidateV1), HybridCandidateError> {
    if raw.len() > HYBRID_RENEWAL_CANDIDATE_MAX_PUBLIC_WIRE_BYTES {
        return Err(HybridCandidateError::Encoding);
    }
    let public: PublicJointRenewalV1 =
        serde_json::from_slice(raw).map_err(|_| HybridCandidateError::Encoding)?;
    if public.profile != HYBRID_RENEWAL_WIRE_CANDIDATE_PROFILE {
        return Err(HybridCandidateError::Encoding);
    }
    let policy = public.next_policy;
    let renewal = HybridRenewalCandidateV1 {
        previous_transition: decode_canonical_hex(&public.previous_transition)?,
        new_crypto_era: public.new_crypto_era,
        new_key_epoch: public.new_key_epoch,
        activation_epoch: public.activation_epoch,
        next_policy: HybridPolicyCandidateV1 {
            profile: policy.profile,
            currency_root: decode_canonical_hex(&policy.currency_root)?,
            region_root: decode_canonical_hex(&policy.region_root)?,
            purpose: policy.purpose,
            valid_from_epoch: policy.valid_from_epoch,
            valid_until_epoch: policy.valid_until_epoch,
            ed_public_key: decode_canonical_hex(&policy.ed_public_key)?,
            pq_public_key: Box::new(decode_canonical_hex(&policy.pq_public_key)?),
        },
    };
    let decode_proof =
        |p: PublicRenewalProofV1| -> Result<HybridProofCandidateV1, HybridCandidateError> {
            Ok(HybridProofCandidateV1 {
                ed_signature: decode_canonical_hex(&p.ed_signature)?,
                pq_signature: Box::new(decode_canonical_hex(&p.pq_signature)?),
            })
        };
    let proof = HybridJointRenewalProofCandidateV1 {
        old: decode_proof(public.proof.old)?,
        new: decode_proof(public.proof.new)?,
    };
    if encode_joint_hybrid_renewal_candidate(&renewal, &proof)? != raw {
        return Err(HybridCandidateError::Encoding);
    }
    Ok((renewal, proof))
}

/// Finite verification-only archive limits, separate from native ledger/history
/// and transport limits. Every complete entry keeps the existing renewal bound.
pub const HYBRID_RENEWAL_ARCHIVE_CANDIDATE_MAX_ENTRIES: usize = 64;
pub const HYBRID_RENEWAL_ARCHIVE_CANDIDATE_MAX_TOTAL_BYTES: usize =
    HYBRID_RENEWAL_ARCHIVE_CANDIDATE_MAX_ENTRIES * HYBRID_RENEWAL_CANDIDATE_MAX_PUBLIC_WIRE_BYTES;

/// Verify the complete ordered chain from an independently authenticated old
/// anchor to a separately retained exact latest transition. A valid signed
/// prefix is not freshness. Neither observations nor the expected latest head
/// may be taken from the archive sender. Unknown/broken historical authority
/// remains a refusal; this does not infer past trust from a new signature.
///
/// Returns a candidate anchor only after every complete entry and final head
/// check; the input is immutable on all failures. No durable installation,
/// signer lock, consumed record or adopted ledger is changed/reconstructed.
/// This finite logical-time model is not independent anti-rollback custody.
pub fn verify_hybrid_renewal_archive_candidate(
    initial: &HybridRenewalAnchorCandidateV1,
    entries: &[Vec<u8>],
    observations: &[HybridObservationCandidateV1],
    expected_latest_transition: &[u8; 64],
) -> Result<HybridRenewalAnchorCandidateV1, HybridCandidateError> {
    if entries.is_empty()
        || entries.len() > HYBRID_RENEWAL_ARCHIVE_CANDIDATE_MAX_ENTRIES
        || entries.len() != observations.len()
    {
        return Err(HybridCandidateError::Encoding);
    }
    let mut total = 0usize;
    // Check all resource bounds before starting signature verification.
    for raw in entries {
        if raw.is_empty() || raw.len() > HYBRID_RENEWAL_CANDIDATE_MAX_PUBLIC_WIRE_BYTES {
            return Err(HybridCandidateError::Encoding);
        }
        total = total
            .checked_add(raw.len())
            .ok_or(HybridCandidateError::Encoding)?;
    }
    if total > HYBRID_RENEWAL_ARCHIVE_CANDIDATE_MAX_TOTAL_BYTES {
        return Err(HybridCandidateError::Encoding);
    }
    let mut current = initial.clone();
    for (raw, observation) in entries.iter().zip(observations) {
        let (renewal, proof) = decode_joint_hybrid_renewal_candidate(raw)?;
        current = verify_joint_hybrid_renewal_candidate(&current, &renewal, &proof, *observation)?;
    }
    if &current.last_transition != expected_latest_transition {
        return Err(HybridCandidateError::Scope);
    }
    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn bytes<const N: usize>(
        values: &BTreeMap<String, String>,
        name: &str,
        offset: usize,
    ) -> [u8; N] {
        let raw = hex::decode(&values[name]).unwrap();
        raw[offset..].try_into().unwrap()
    }

    fn fixture() -> (
        HybridPolicyCandidateV1,
        HybridIntentCandidateV1,
        HybridProofCandidateV1,
        HybridObservationCandidateV1,
        BTreeMap<String, String>,
    ) {
        let values: BTreeMap<String, String> = serde_json::from_str(include_str!(
            "../../../vectors/pq-hybrid-authorization-v1/openssl-hybrid-public.json"
        ))
        .unwrap();
        let policy = HybridPolicyCandidateV1 {
            profile: HYBRID_CANDIDATE_PROFILE.into(),
            currency_root: [1; 32],
            region_root: [2; 32],
            purpose: HybridPurposeV1::Payment,
            valid_from_epoch: 1,
            valid_until_epoch: 3,
            ed_public_key: bytes(&values, "ed-public.der", 12),
            pq_public_key: Box::new(bytes(&values, "pq-public.der", 22)),
        };
        let intent = HybridIntentCandidateV1 {
            currency_root: [1; 32],
            region_root: [2; 32],
            purpose: HybridPurposeV1::Payment,
            epoch: 1,
            nonce: 1,
            payload_root: [3; 64],
        };
        let proof = HybridProofCandidateV1 {
            ed_signature: bytes(&values, "ed-signature.bin", 0),
            pq_signature: Box::new(bytes(&values, "pq-signature.bin", 0)),
        };
        let observation = HybridObservationCandidateV1 {
            current_epoch: 1,
            next_nonce: 1,
            policy_trust: HybridPolicyTrustV1::CurrentAndTrusted,
        };
        (policy, intent, proof, observation, values)
    }

    #[test]
    fn provider_bytes_and_both_signatures_match_exactly() {
        let (policy, intent, proof, observation, values) = fixture();
        assert_eq!(
            intent.signing_bytes(),
            hex::decode(&values["intent.bin"]).unwrap()
        );
        assert_eq!(
            verify_hybrid_authorization_candidate(&policy, &intent, &proof, observation),
            Ok(())
        );
        assert!(intent.signing_bytes().len() <= 2048);
    }

    #[test]
    fn public_wire_roundtrip_requires_both_real_components_and_grants_no_authority() {
        let (policy, intent, proof, observation, _) = fixture();
        let raw = encode_hybrid_public_envelope_candidate(&intent, &proof);
        assert!(raw.len() <= HYBRID_CANDIDATE_MAX_PUBLIC_WIRE_BYTES);
        let (decoded, signatures) = decode_hybrid_public_envelope_candidate(&raw).unwrap();
        assert_eq!(decoded, intent);
        assert_eq!(signatures, proof);
        assert_eq!(
            verify_hybrid_authorization_candidate(&policy, &decoded, &signatures, observation),
            Ok(())
        );
        let mut forged = proof.clone();
        *forged.pq_signature = [0; 4627];
        let raw = encode_hybrid_public_envelope_candidate(&intent, &forged);
        let (decoded, signatures) = decode_hybrid_public_envelope_candidate(&raw).unwrap();
        assert_eq!(
            verify_hybrid_authorization_candidate(&policy, &decoded, &signatures, observation),
            Err(HybridCandidateError::PostQuantum)
        );
    }

    #[test]
    fn public_wire_refuses_oversize_duplicate_stripped_and_noncanonical_encodings() {
        let (_, intent, proof, _, _) = fixture();
        let raw = encode_hybrid_public_envelope_candidate(&intent, &proof);
        let wire: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        for case in 0..18 {
            let mut bad = wire.clone();
            match case {
                0 => {
                    bad.as_object_mut().unwrap().remove("ed_signature");
                }
                1 => {
                    bad.as_object_mut().unwrap().remove("pq_signature");
                }
                2 => bad["ed_signature"] = "00".into(),
                3 => bad["pq_signature"] = "00".into(),
                4 => bad["profile"] = "ED25519-ONLY".into(),
                5 => bad["fallback"] = true.into(),
                6 => bad["intent"]["candidate_only"] = false.into(),
                7 => bad["intent"]["epoch"] = true.into(),
                8 => bad["intent"]["nonce"] = 0.into(),
                9 => bad["intent"]["nonce"] = 1.0.into(),
                10 => bad["intent"]["purpose"] = "UNKNOWN".into(),
                11 => bad["intent"]["currency_root"] = "ABCDEF".repeat(11).into(),
                12 => bad["intent"]["region_root"] = "xx".repeat(32).into(),
                13 => bad["intent"]["payload_root"] = "00".repeat(63).into(),
                14 => bad["intent"]["unknown"] = true.into(),
                15 => {
                    bad["pq_signature"] = hex::encode(proof.pq_signature.as_ref())
                        .to_uppercase()
                        .into()
                }
                16 => bad["intent"]["nonce"] = "1".into(),
                _ => bad["intent"]["epoch"] = 0.into(),
            }
            assert_eq!(
                decode_hybrid_public_envelope_candidate(&serde_json::to_vec(&bad).unwrap()),
                Err(HybridCandidateError::Encoding)
            );
        }
        let whitespace = [b"\n".as_slice(), raw.as_slice()].concat();
        let duplicate = [
            b"{\"profile\":\"RLDCOIN-HYBRID-AUTH-CANDIDATE-V1\",",
            &raw[1..],
        ]
        .concat();
        let trailing = [raw.as_slice(), b"null".as_slice()].concat();
        let deep = format!("{}0{}", "[".repeat(129), "]".repeat(129)).into_bytes();
        for bad in [
            whitespace,
            duplicate,
            trailing,
            deep,
            vec![b' '; HYBRID_CANDIDATE_MAX_PUBLIC_WIRE_BYTES + 1],
            b"[]".to_vec(),
            b"{}".to_vec(),
            b"null".to_vec(),
            b"{\"epoch\":NaN}".to_vec(),
        ] {
            assert_eq!(
                decode_hybrid_public_envelope_candidate(&bad),
                Err(HybridCandidateError::Encoding)
            );
        }
    }

    #[test]
    fn either_bad_or_missing_half_and_wrong_key_refuse() {
        let (policy, intent, proof, observation, values) = fixture();
        let mut bad = proof.clone();
        bad.ed_signature = bytes(&values, "ed-altered-signature.bin", 0);
        assert_eq!(
            verify_hybrid_authorization_candidate(&policy, &intent, &bad, observation),
            Err(HybridCandidateError::Classical)
        );
        bad = proof.clone();
        *bad.pq_signature = bytes(&values, "pq-altered-signature.bin", 0);
        assert_eq!(
            verify_hybrid_authorization_candidate(&policy, &intent, &bad, observation),
            Err(HybridCandidateError::PostQuantum)
        );
        bad = proof.clone();
        bad.ed_signature = [0; 64];
        assert!(
            verify_hybrid_authorization_candidate(&policy, &intent, &bad, observation).is_err()
        );
        bad = proof.clone();
        *bad.pq_signature = [0; 4627];
        assert!(
            verify_hybrid_authorization_candidate(&policy, &intent, &bad, observation).is_err()
        );
        let mut wrong = policy.clone();
        *wrong.pq_public_key = bytes(&values, "wrong-pq-public.der", 22);
        assert!(
            verify_hybrid_authorization_candidate(&wrong, &intent, &proof, observation).is_err()
        );
        wrong = policy.clone();
        wrong.ed_public_key = [0; 32];
        assert!(
            verify_hybrid_authorization_candidate(&wrong, &intent, &proof, observation).is_err()
        );
    }

    #[test]
    fn roots_roles_message_and_replayed_nonce_refuse() {
        let (policy, intent, proof, observation, _) = fixture();
        for change in 0..6 {
            let mut wrong = intent.clone();
            match change {
                0 => wrong.currency_root[0] ^= 1,
                1 => wrong.region_root[0] ^= 1,
                2 => wrong.purpose = HybridPurposeV1::Finality,
                3 => wrong.nonce = 2,
                4 => wrong.payload_root[0] ^= 1,
                _ => wrong.epoch = 0,
            }
            assert!(
                verify_hybrid_authorization_candidate(&policy, &wrong, &proof, observation)
                    .is_err()
            );
        }
        for next_nonce in [0, 2, u64::MAX] {
            assert_eq!(
                verify_hybrid_authorization_candidate(
                    &policy,
                    &intent,
                    &proof,
                    HybridObservationCandidateV1 {
                        next_nonce,
                        ..observation
                    }
                ),
                Err(HybridCandidateError::Scope)
            );
        }
        assert!(verify_pq(
            &policy.pq_public_key,
            &proof.pq_signature,
            &intent.signing_bytes(),
            b"wrong-purpose"
        )
        .is_err());
    }

    #[test]
    fn finite_horizon_revocation_break_and_unknown_policy_stop_acceptance() {
        let (policy, intent, proof, observation, _) = fixture();
        for current_epoch in [0, 4, u64::MAX] {
            assert_eq!(
                verify_hybrid_authorization_candidate(
                    &policy,
                    &intent,
                    &proof,
                    HybridObservationCandidateV1 {
                        current_epoch,
                        ..observation
                    }
                ),
                Err(HybridCandidateError::Horizon)
            );
        }
        for policy_trust in [
            HybridPolicyTrustV1::Revoked,
            HybridPolicyTrustV1::Broken,
            HybridPolicyTrustV1::Unavailable,
        ] {
            assert_eq!(
                verify_hybrid_authorization_candidate(
                    &policy,
                    &intent,
                    &proof,
                    HybridObservationCandidateV1 {
                        policy_trust,
                        ..observation
                    }
                ),
                Err(HybridCandidateError::Untrusted)
            );
        }
        let mut wrong = policy.clone();
        wrong.profile = "ED25519-ONLY-FALLBACK".into();
        assert_eq!(
            verify_hybrid_authorization_candidate(&wrong, &intent, &proof, observation),
            Err(HybridCandidateError::Policy)
        );
        wrong = policy.clone();
        wrong.valid_from_epoch = 4;
        assert_eq!(
            verify_hybrid_authorization_candidate(&wrong, &intent, &proof, observation),
            Err(HybridCandidateError::Policy)
        );
        // No fresh signature can restore a policy rejected before crypto checks.
        assert_eq!(
            verify_hybrid_authorization_candidate(
                &policy,
                &intent,
                &proof,
                HybridObservationCandidateV1 {
                    current_epoch: 3,
                    ..observation
                }
            ),
            Ok(())
        );
    }

    #[test]
    fn official_external_pure_sigver_subset_matches_all_expected_results() {
        #[derive(serde::Deserialize)]
        struct Vector {
            pk: String,
            signature: String,
            message: String,
            context: String,
            expected: bool,
        }
        let vectors: Vec<Vector> = serde_json::from_str(include_str!(
            "../../../vectors/pq-hybrid-authorization-v1/nist-external-pure-sigver.json"
        ))
        .unwrap();
        assert_eq!(vectors.len(), 15);
        assert_eq!(vectors.iter().filter(|v| v.expected).count(), 3);
        for vector in vectors {
            let key: [u8; 2592] = hex::decode(vector.pk).unwrap().try_into().unwrap();
            let signature: [u8; 4627] = hex::decode(vector.signature).unwrap().try_into().unwrap();
            let message = hex::decode(vector.message).unwrap();
            let context = hex::decode(vector.context).unwrap();
            assert_eq!(
                verify_pq(&key, &signature, &message, &context).is_ok(),
                vector.expected
            );
        }
    }

    #[test]
    fn primitive_does_not_enable_unintegrated_ledger_suite() {
        let suite = crate::types::CryptoSuiteDescriptor {
            suite_id: HYBRID_CANDIDATE_PROFILE.into(),
            signature_algorithm: "ED25519+ML-DSA-87-AND".into(),
            hash_algorithm: "SHA-256".into(),
            encoding: "RLD-CANONICAL-V1".into(),
        };
        assert!(suite.validate_reference_implementation(true).is_err());
        assert!(suite.validate_reference_implementation(false).is_err());
    }

    struct RenewalKeys {
        ed: ed25519_dalek::SigningKey,
        pq: ml_dsa_87::PrivateKey,
    }

    fn renewal_keys(from: u64, until: u64) -> (HybridPolicyCandidateV1, RenewalKeys) {
        let ed = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let (pq_public, pq) = ml_dsa_87::try_keygen_with_rng(&mut rand::rngs::OsRng).unwrap();
        (
            HybridPolicyCandidateV1 {
                profile: HYBRID_CANDIDATE_PROFILE.into(),
                currency_root: [1; 32],
                region_root: [2; 32],
                purpose: HybridPurposeV1::Renewal,
                valid_from_epoch: from,
                valid_until_epoch: until,
                ed_public_key: ed.verifying_key().to_bytes(),
                pq_public_key: Box::new(pq_public.into_bytes()),
            },
            RenewalKeys { ed, pq },
        )
    }

    fn renewal_sign(
        keys: &RenewalKeys,
        intent: &HybridIntentCandidateV1,
    ) -> HybridProofCandidateV1 {
        use ed25519_dalek::Signer as _;
        use fips204::traits::Signer as _;
        let bytes = intent.signing_bytes();
        HybridProofCandidateV1 {
            ed_signature: keys.ed.sign(&bytes).to_bytes(),
            pq_signature: Box::new(
                keys.pq
                    .try_sign_with_rng(&mut rand::rngs::OsRng, &bytes, HYBRID_CANDIDATE_CONTEXT)
                    .unwrap(),
            ),
        }
    }

    #[test]
    fn joint_renewal_keeps_locks_consumption_and_rejects_replay_conflict_and_stripping() {
        // Fresh in-memory no-value keys only; no file, prior fixture or ledger.
        let (old_policy, old_keys) = renewal_keys(1, 3);
        let (new_policy, new_keys) = renewal_keys(2, 5);
        let anchor = HybridRenewalAnchorCandidateV1 {
            policy: old_policy,
            crypto_era: 1,
            key_epoch: 1,
            next_nonce: 1,
            last_transition: [7; 64],
            caller_locks_root: [8; 64],
            consumed_exports_root: [9; 64],
        };
        let renewal = HybridRenewalCandidateV1 {
            previous_transition: anchor.last_transition,
            new_crypto_era: 2,
            new_key_epoch: 2,
            activation_epoch: 2,
            next_policy: new_policy,
        };
        let intent = renewal.signing_intent(&anchor).unwrap();
        let proof = HybridJointRenewalProofCandidateV1 {
            old: renewal_sign(&old_keys, &intent),
            new: renewal_sign(&new_keys, &intent),
        };
        let observation = HybridObservationCandidateV1 {
            current_epoch: 2,
            next_nonce: 1,
            policy_trust: HybridPolicyTrustV1::CurrentAndTrusted,
        };
        let original = anchor.clone();
        let advanced =
            verify_joint_hybrid_renewal_candidate(&anchor, &renewal, &proof, observation).unwrap();
        assert_eq!(advanced.policy, renewal.next_policy);
        assert_eq!(advanced.crypto_era, 2);
        assert_eq!(advanced.key_epoch, 2);
        assert_eq!(advanced.next_nonce, 2);
        assert_ne!(advanced.last_transition, anchor.last_transition);
        assert_eq!(advanced.caller_locks_root, anchor.caller_locks_root);
        assert_eq!(advanced.consumed_exports_root, anchor.consumed_exports_root);
        assert_eq!(anchor, original);
        // A delayed original is eligible only while both policies remain trusted.
        assert_eq!(
            verify_joint_hybrid_renewal_candidate(
                &anchor,
                &renewal,
                &proof,
                HybridObservationCandidateV1 {
                    current_epoch: 3,
                    ..observation
                }
            )
            .unwrap(),
            advanced
        );
        assert!(verify_joint_hybrid_renewal_candidate(
            &advanced,
            &renewal,
            &proof,
            HybridObservationCandidateV1 {
                next_nonce: 2,
                ..observation
            }
        )
        .is_err());
        for half in 0..4 {
            let mut bad = proof.clone();
            match half {
                0 => bad.old.ed_signature = [0; 64],
                1 => *bad.old.pq_signature = [0; 4627],
                2 => bad.new.ed_signature = [0; 64],
                _ => *bad.new.pq_signature = [0; 4627],
            }
            assert!(
                verify_joint_hybrid_renewal_candidate(&anchor, &renewal, &bad, observation)
                    .is_err()
            );
            assert_eq!(anchor, original);
        }
        let (conflicting_policy, conflicting_keys) = renewal_keys(2, 5);
        let mut conflict = renewal.clone();
        conflict.next_policy = conflicting_policy;
        let conflict_intent = conflict.signing_intent(&anchor).unwrap();
        let conflict_proof = HybridJointRenewalProofCandidateV1 {
            old: renewal_sign(&old_keys, &conflict_intent),
            new: renewal_sign(&conflicting_keys, &conflict_intent),
        };
        assert!(verify_joint_hybrid_renewal_candidate(
            &anchor,
            &conflict,
            &conflict_proof,
            observation
        )
        .is_ok());
        assert!(verify_joint_hybrid_renewal_candidate(
            &advanced,
            &conflict,
            &conflict_proof,
            HybridObservationCandidateV1 {
                next_nonce: 2,
                ..observation
            }
        )
        .is_err());
    }

    #[test]
    fn joint_renewal_binds_every_field_and_cannot_rehabilitate_untrusted_original() {
        let (old_policy, old_keys) = renewal_keys(1, 3);
        let (new_policy, new_keys) = renewal_keys(2, 5);
        let anchor = HybridRenewalAnchorCandidateV1 {
            policy: old_policy,
            crypto_era: 1,
            key_epoch: 1,
            next_nonce: 1,
            last_transition: [7; 64],
            caller_locks_root: [8; 64],
            consumed_exports_root: [9; 64],
        };
        let renewal = HybridRenewalCandidateV1 {
            previous_transition: anchor.last_transition,
            new_crypto_era: 2,
            new_key_epoch: 2,
            activation_epoch: 2,
            next_policy: new_policy,
        };
        let intent = renewal.signing_intent(&anchor).unwrap();
        let proof = HybridJointRenewalProofCandidateV1 {
            old: renewal_sign(&old_keys, &intent),
            new: renewal_sign(&new_keys, &intent),
        };
        let observation = HybridObservationCandidateV1 {
            current_epoch: 2,
            next_nonce: 1,
            policy_trust: HybridPolicyTrustV1::CurrentAndTrusted,
        };
        for field in 0..13 {
            let mut bad = renewal.clone();
            match field {
                0 => bad.previous_transition[0] ^= 1,
                1 => bad.new_crypto_era = 3,
                2 => bad.new_key_epoch = 3,
                3 => bad.activation_epoch = 1,
                4 => bad.next_policy.currency_root[0] ^= 1,
                5 => bad.next_policy.region_root[0] ^= 1,
                6 => bad.next_policy.purpose = HybridPurposeV1::Payment,
                7 => bad.next_policy.valid_from_epoch = 1,
                8 => bad.next_policy.valid_until_epoch = 6,
                9 => bad.next_policy.ed_public_key = anchor.policy.ed_public_key,
                10 => *bad.next_policy.pq_public_key = *anchor.policy.pq_public_key,
                11 => bad.next_policy.profile = "CLASSICAL-ONLY".into(),
                _ => bad.activation_epoch = 4,
            }
            assert!(
                verify_joint_hybrid_renewal_candidate(&anchor, &bad, &proof, observation).is_err()
            );
        }
        for field in 0..6 {
            let mut bad = anchor.clone();
            match field {
                0 => bad.caller_locks_root[0] ^= 1,
                1 => bad.consumed_exports_root[0] ^= 1,
                2 => bad.last_transition[0] ^= 1,
                3 => bad.next_nonce = u64::MAX,
                4 => bad.crypto_era = u64::MAX,
                _ => bad.key_epoch = u64::MAX,
            }
            let before = bad.clone();
            assert!(
                verify_joint_hybrid_renewal_candidate(&bad, &renewal, &proof, observation).is_err()
            );
            assert_eq!(bad, before);
        }
        for policy_trust in [
            HybridPolicyTrustV1::Broken,
            HybridPolicyTrustV1::Revoked,
            HybridPolicyTrustV1::Unavailable,
        ] {
            assert_eq!(
                verify_joint_hybrid_renewal_candidate(
                    &anchor,
                    &renewal,
                    &proof,
                    HybridObservationCandidateV1 {
                        policy_trust,
                        ..observation
                    }
                ),
                Err(HybridCandidateError::Untrusted)
            );
        }
        assert_eq!(
            verify_joint_hybrid_renewal_candidate(
                &anchor,
                &renewal,
                &proof,
                HybridObservationCandidateV1 {
                    current_epoch: 4,
                    ..observation
                }
            ),
            Err(HybridCandidateError::Horizon)
        );
    }
    fn renewal_wire_fixture() -> (
        HybridRenewalAnchorCandidateV1,
        HybridRenewalCandidateV1,
        HybridJointRenewalProofCandidateV1,
        HybridObservationCandidateV1,
    ) {
        let (old, old_keys) = renewal_keys(1, 3);
        let (new, new_keys) = renewal_keys(2, 5);
        let anchor = HybridRenewalAnchorCandidateV1 {
            policy: old,
            crypto_era: 1,
            key_epoch: 1,
            next_nonce: 1,
            last_transition: [7; 64],
            caller_locks_root: [8; 64],
            consumed_exports_root: [9; 64],
        };
        let renewal = HybridRenewalCandidateV1 {
            previous_transition: anchor.last_transition,
            new_crypto_era: 2,
            new_key_epoch: 2,
            activation_epoch: 2,
            next_policy: new,
        };
        let intent = renewal.signing_intent(&anchor).unwrap();
        let proof = HybridJointRenewalProofCandidateV1 {
            old: renewal_sign(&old_keys, &intent),
            new: renewal_sign(&new_keys, &intent),
        };
        let observation = HybridObservationCandidateV1 {
            current_epoch: 2,
            next_nonce: 1,
            policy_trust: HybridPolicyTrustV1::CurrentAndTrusted,
        };
        (anchor, renewal, proof, observation)
    }

    #[test]
    fn joint_renewal_wire_roundtrip_verifies_complete_four_signatures_and_retained_roots() {
        let (anchor, renewal, proof, observation) = renewal_wire_fixture();
        let before = anchor.clone();
        let expected =
            verify_joint_hybrid_renewal_candidate(&anchor, &renewal, &proof, observation).unwrap();
        let raw = encode_joint_hybrid_renewal_candidate(&renewal, &proof).unwrap();
        assert!(raw.len() > HYBRID_CANDIDATE_MAX_PUBLIC_WIRE_BYTES);
        assert!(raw.len() <= HYBRID_RENEWAL_CANDIDATE_MAX_PUBLIC_WIRE_BYTES);
        let (decoded, decoded_proof) = decode_joint_hybrid_renewal_candidate(&raw).unwrap();
        assert_eq!((decoded.clone(), decoded_proof.clone()), (renewal, proof));
        let actual =
            verify_joint_hybrid_renewal_candidate(&anchor, &decoded, &decoded_proof, observation)
                .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(actual.caller_locks_root, before.caller_locks_root);
        assert_eq!(actual.consumed_exports_root, before.consumed_exports_root);
        assert_eq!(anchor, before);
        assert!(verify_joint_hybrid_renewal_candidate(
            &actual,
            &decoded,
            &decoded_proof,
            HybridObservationCandidateV1 {
                next_nonce: 2,
                ..observation
            }
        )
        .is_err());
        println!("joint-renewal-complete-public-wire-bytes={}", raw.len());
    }

    #[test]
    fn joint_renewal_wire_refuses_malformed_missing_duplicate_alternate_and_oversized_input() {
        let (anchor, renewal, proof, _) = renewal_wire_fixture();
        let original = anchor.clone();
        let raw = encode_joint_hybrid_renewal_candidate(&renewal, &proof).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        let mut bad = vec![
            vec![b' '; HYBRID_RENEWAL_CANDIDATE_MAX_PUBLIC_WIRE_BYTES + 1],
            raw[..raw.len() - 1].to_vec(),
        ];
        bad.push([b" ".as_slice(), raw.as_slice()].concat());
        let text = String::from_utf8(raw.clone()).unwrap();
        bad.push(
            text.replacen(
                "\"activation_epoch\":2",
                "\"activation_epoch\":2,\"activation_epoch\":2",
                1,
            )
            .into_bytes(),
        );
        bad.push(
            text.replacen("\"activation_epoch\":2", "\"activation_epoch\":2.0", 1)
                .into_bytes(),
        );
        bad.push(
            text.replacen("\"activation_epoch\":2", "\"activation_epoch\":true", 1)
                .into_bytes(),
        );
        bad.push(
            text.replacen("\"activation_epoch\":2", "\"activation_epoch\":0", 1)
                .into_bytes(),
        );
        bad.push(
            text.replacen(
                "\"activation_epoch\":2",
                "\"activation_epoch\":2,\"authority\":true",
                1,
            )
            .into_bytes(),
        );
        for path in [
            vec!["proof", "old", "ed_signature"],
            vec!["proof", "old", "pq_signature"],
            vec!["proof", "new", "ed_signature"],
            vec!["proof", "new", "pq_signature"],
            vec!["next_policy", "pq_public_key"],
        ] {
            let mut changed = value.clone();
            let mut cursor = &mut changed;
            for key in &path[..path.len() - 1] {
                cursor = &mut cursor[*key];
            }
            cursor.as_object_mut().unwrap().remove(path[path.len() - 1]);
            bad.push(serde_json::to_vec(&changed).unwrap());
        }
        for (path, replacement) in [
            (vec!["profile"], serde_json::json!("UNKNOWN")),
            (
                vec!["next_policy", "profile"],
                serde_json::json!("CLASSICAL-ONLY"),
            ),
            (vec!["next_policy", "purpose"], serde_json::json!("PAYMENT")),
            (
                vec!["next_policy", "pq_public_key"],
                serde_json::json!("00"),
            ),
            (
                vec!["proof", "old", "pq_signature"],
                serde_json::json!("00"),
            ),
            (
                vec!["next_policy", "valid_from_epoch"],
                serde_json::json!(0),
            ),
            (
                vec!["next_policy", "valid_until_epoch"],
                serde_json::json!(1),
            ),
        ] {
            let mut changed = value.clone();
            let mut cursor = &mut changed;
            for key in &path[..path.len() - 1] {
                cursor = &mut cursor[*key];
            }
            cursor[path[path.len() - 1]] = replacement;
            bad.push(serde_json::to_vec(&changed).unwrap());
        }
        for (i, bytes) in bad.iter().enumerate() {
            assert_eq!(
                decode_joint_hybrid_renewal_candidate(bytes),
                Err(HybridCandidateError::Encoding),
                "malformed case {i}"
            );
            assert_eq!(anchor, original);
        }
    }

    #[test]
    fn joint_renewal_wire_decoding_never_grants_trust_or_rehabilitates_bad_signatures() {
        let (anchor, renewal, proof, observation) = renewal_wire_fixture();
        let before = anchor.clone();
        for half in 0..4 {
            let mut forged = proof.clone();
            match half {
                0 => forged.old.ed_signature[0] ^= 1,
                1 => forged.old.pq_signature[0] ^= 1,
                2 => forged.new.ed_signature[0] ^= 1,
                _ => forged.new.pq_signature[0] ^= 1,
            };
            let raw = encode_joint_hybrid_renewal_candidate(&renewal, &forged).unwrap();
            let (decoded, decoded_proof) = decode_joint_hybrid_renewal_candidate(&raw).unwrap();
            assert!(verify_joint_hybrid_renewal_candidate(
                &anchor,
                &decoded,
                &decoded_proof,
                observation
            )
            .is_err());
            assert_eq!(anchor, before);
        }
        let raw = encode_joint_hybrid_renewal_candidate(&renewal, &proof).unwrap();
        let (decoded, decoded_proof) = decode_joint_hybrid_renewal_candidate(&raw).unwrap();
        for trust in [
            HybridPolicyTrustV1::Unavailable,
            HybridPolicyTrustV1::Broken,
            HybridPolicyTrustV1::Revoked,
        ] {
            assert_eq!(
                verify_joint_hybrid_renewal_candidate(
                    &anchor,
                    &decoded,
                    &decoded_proof,
                    HybridObservationCandidateV1 {
                        policy_trust: trust,
                        ..observation
                    }
                ),
                Err(HybridCandidateError::Untrusted)
            );
        }
        let mut substituted = anchor.clone();
        substituted.caller_locks_root[0] ^= 1;
        let unchanged = substituted.clone();
        assert!(verify_joint_hybrid_renewal_candidate(
            &substituted,
            &decoded,
            &decoded_proof,
            observation
        )
        .is_err());
        assert_eq!(substituted, unchanged);
        assert_eq!(anchor, before);
    }
    fn renewal_archive_fixture() -> (
        HybridRenewalAnchorCandidateV1,
        Vec<Vec<u8>>,
        Vec<HybridObservationCandidateV1>,
        Vec<HybridRenewalAnchorCandidateV1>,
    ) {
        let (policy, mut current_keys) = renewal_keys(1, 3);
        let initial = HybridRenewalAnchorCandidateV1 {
            policy,
            crypto_era: 1,
            key_epoch: 1,
            next_nonce: 1,
            last_transition: [7; 64],
            caller_locks_root: [8; 64],
            consumed_exports_root: [9; 64],
        };
        let mut current = initial.clone();
        let mut entries = Vec::new();
        let mut observations = Vec::new();
        let mut heads = Vec::new();
        for epoch in 2..=3 {
            let (next_policy, next_keys) = renewal_keys(epoch, epoch + 3);
            let renewal = HybridRenewalCandidateV1 {
                previous_transition: current.last_transition,
                new_crypto_era: current.crypto_era + 1,
                new_key_epoch: current.key_epoch + 1,
                activation_epoch: epoch,
                next_policy,
            };
            let intent = renewal.signing_intent(&current).unwrap();
            let proof = HybridJointRenewalProofCandidateV1 {
                old: renewal_sign(&current_keys, &intent),
                new: renewal_sign(&next_keys, &intent),
            };
            let observation = HybridObservationCandidateV1 {
                current_epoch: epoch,
                next_nonce: current.next_nonce,
                policy_trust: HybridPolicyTrustV1::CurrentAndTrusted,
            };
            let raw = encode_joint_hybrid_renewal_candidate(&renewal, &proof).unwrap();
            current =
                verify_joint_hybrid_renewal_candidate(&current, &renewal, &proof, observation)
                    .unwrap();
            entries.push(raw);
            observations.push(observation);
            heads.push(current.clone());
            current_keys = next_keys;
        }
        (initial, entries, observations, heads)
    }

    #[test]
    fn joint_renewal_archive_verifies_ordered_complete_chain_and_separate_latest_head() {
        let (initial, entries, observations, heads) = renewal_archive_fixture();
        let before = initial.clone();
        let latest = &heads.last().unwrap().last_transition;
        let reconstructed =
            verify_hybrid_renewal_archive_candidate(&initial, &entries, &observations, latest)
                .unwrap();
        assert_eq!(reconstructed, *heads.last().unwrap());
        assert_eq!(
            (
                reconstructed.crypto_era,
                reconstructed.key_epoch,
                reconstructed.next_nonce
            ),
            (3, 3, 3)
        );
        assert_eq!(reconstructed.caller_locks_root, initial.caller_locks_root);
        assert_eq!(
            reconstructed.consumed_exports_root,
            initial.consumed_exports_root
        );
        assert_eq!(initial, before);
        println!(
            "joint-renewal-archive-complete-entries={} bytes={}",
            entries.len(),
            entries.iter().map(Vec::len).sum::<usize>()
        );
    }

    #[test]
    fn joint_renewal_archive_refuses_valid_stale_prefix_and_missing_repeated_reordered_chain() {
        let (initial, entries, observations, heads) = renewal_archive_fixture();
        let before = initial.clone();
        // The old single-step verifier correctly accepts this valid transition;
        // only the independently retained latest head discriminates a stale tail.
        let (renewal, proof) = decode_joint_hybrid_renewal_candidate(&entries[0]).unwrap();
        let valid_prefix =
            verify_joint_hybrid_renewal_candidate(&initial, &renewal, &proof, observations[0])
                .unwrap();
        assert_eq!(valid_prefix, heads[0]);
        assert_ne!(valid_prefix.last_transition, heads[1].last_transition);
        assert_eq!(
            verify_hybrid_renewal_archive_candidate(
                &initial,
                &entries[..1],
                &observations[..1],
                &heads[1].last_transition
            ),
            Err(HybridCandidateError::Scope)
        );
        for altered in [
            vec![entries[1].clone()],
            vec![entries[1].clone(), entries[0].clone()],
            vec![entries[0].clone(), entries[0].clone()],
        ] {
            assert!(verify_hybrid_renewal_archive_candidate(
                &initial,
                &altered,
                &observations[..altered.len()],
                &heads[1].last_transition
            )
            .is_err());
        }
        assert_eq!(
            verify_hybrid_renewal_archive_candidate(
                &initial,
                &entries,
                &observations,
                &heads[0].last_transition
            ),
            Err(HybridCandidateError::Scope)
        );
        assert_eq!(initial, before);
    }

    #[test]
    fn joint_renewal_archive_refuses_bad_tail_unknown_authority_and_resource_overflow_atomically() {
        let (initial, entries, observations, heads) = renewal_archive_fixture();
        let before = initial.clone();
        let latest = &heads[1].last_transition;
        let mut bad = entries.clone();
        let (renewal, mut proof) = decode_joint_hybrid_renewal_candidate(&bad[1]).unwrap();
        proof.new.pq_signature[0] ^= 1;
        bad[1] = encode_joint_hybrid_renewal_candidate(&renewal, &proof).unwrap();
        assert_eq!(
            verify_hybrid_renewal_archive_candidate(&initial, &bad, &observations, latest),
            Err(HybridCandidateError::PostQuantum)
        );
        for trust in [
            HybridPolicyTrustV1::Unavailable,
            HybridPolicyTrustV1::Broken,
            HybridPolicyTrustV1::Revoked,
        ] {
            let mut unknown = observations.clone();
            unknown[1].policy_trust = trust;
            assert_eq!(
                verify_hybrid_renewal_archive_candidate(&initial, &entries, &unknown, latest),
                Err(HybridCandidateError::Untrusted)
            );
        }
        assert_eq!(
            verify_hybrid_renewal_archive_candidate(&initial, &entries, &observations[..1], latest),
            Err(HybridCandidateError::Encoding)
        );
        assert_eq!(
            verify_hybrid_renewal_archive_candidate(&initial, &[], &[], latest),
            Err(HybridCandidateError::Encoding)
        );
        let too_many = vec![entries[0].clone(); HYBRID_RENEWAL_ARCHIVE_CANDIDATE_MAX_ENTRIES + 1];
        let many_observations = vec![observations[0]; too_many.len()];
        assert_eq!(
            verify_hybrid_renewal_archive_candidate(
                &initial,
                &too_many,
                &many_observations,
                latest
            ),
            Err(HybridCandidateError::Encoding)
        );
        let mut oversized = entries.clone();
        oversized[1] = vec![b' '; HYBRID_RENEWAL_CANDIDATE_MAX_PUBLIC_WIRE_BYTES + 1];
        assert_eq!(
            verify_hybrid_renewal_archive_candidate(&initial, &oversized, &observations, latest),
            Err(HybridCandidateError::Encoding)
        );
        assert_eq!(initial, before);
    }
}
