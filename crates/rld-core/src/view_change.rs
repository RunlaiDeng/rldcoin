//! Authenticated view-change protocol kernel.
//!
//! This module deliberately does not activate nonzero rounds in the node. It
//! defines and verifies the signed timeout evidence that a later pacemaker must
//! persist before changing leaders. The current one-phase consensus keeps a
//! permanent value lock across rounds; if timeout voters report conflicting
//! locks, the certificate fails closed instead of guessing a safe value.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    crypto::hash_parts, deterministic_round_leader, required_quorum, verify_bytes,
    ConsensusProposal,
};

pub const TIMEOUT_VOTE_VERSION: &str = "RLD-CONSENSUS-TIMEOUT-VOTE-V1";
pub const TIMEOUT_CERTIFICATE_VERSION: &str = "RLD-CONSENSUS-TIMEOUT-CERTIFICATE-V1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsensusViewContext {
    pub network_domain: String,
    pub zone_id: String,
    pub currency_genesis_root: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub validator_set_epoch: u64,
    pub validator_set_commitment: String,
    pub parent_height: u64,
    pub parent_state_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsensusLockedValue {
    pub locked_round: u64,
    pub proposal_value_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsensusTimeoutVote {
    pub protocol_version: String,
    pub context: ConsensusViewContext,
    pub timed_out_round: u64,
    pub highest_lock: Option<ConsensusLockedValue>,
    pub voter_public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsensusTimeoutCertificate {
    pub protocol_version: String,
    pub context: ConsensusViewContext,
    pub timed_out_round: u64,
    pub votes: Vec<ConsensusTimeoutVote>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedTimeoutCertificate {
    pub next_round: u64,
    pub required_proposal_value_hash: Option<String>,
    pub signer_count: usize,
}

impl ConsensusViewContext {
    pub fn bind_validator_set(mut self, validator_keys: &[String]) -> Result<Self, String> {
        if !self.validator_set_commitment.is_empty() {
            return Err("view-change context is already bound to a validator set".into());
        }
        self.validator_set_commitment = validator_set_commitment(validator_keys)?;
        self.validate(validator_keys)?;
        Ok(self)
    }

    pub fn validate(&self, validator_keys: &[String]) -> Result<(), String> {
        if self.network_domain.trim().is_empty() || self.zone_id.trim().is_empty() {
            return Err("view-change network domain and Zone are required".into());
        }
        validate_hex_32("currency genesis root", &self.currency_genesis_root)?;
        validate_hex_32("parent state root", &self.parent_state_root)?;
        validate_hex_32("validator-set commitment", &self.validator_set_commitment)?;
        let expected = validator_set_commitment(validator_keys)?;
        if self.validator_set_commitment != expected {
            return Err("view-change validator-set commitment mismatch".into());
        }
        Ok(())
    }

    fn append_signing_bytes(&self, bytes: &mut Vec<u8>) -> Result<(), String> {
        append_string(bytes, &self.network_domain)?;
        append_string(bytes, &self.zone_id)?;
        append_string(bytes, &self.currency_genesis_root)?;
        bytes.extend_from_slice(&self.protocol_era.to_be_bytes());
        bytes.extend_from_slice(&self.crypto_era.to_be_bytes());
        bytes.extend_from_slice(&self.validator_set_epoch.to_be_bytes());
        append_string(bytes, &self.validator_set_commitment)?;
        bytes.extend_from_slice(&self.parent_height.to_be_bytes());
        append_string(bytes, &self.parent_state_root)?;
        Ok(())
    }
}

impl ConsensusTimeoutVote {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        if self.protocol_version != TIMEOUT_VOTE_VERSION {
            return Err(format!(
                "unsupported timeout-vote version {}",
                self.protocol_version
            ));
        }
        let mut bytes = b"RLD-CONSENSUS-TIMEOUT-VOTE-V1\0".to_vec();
        self.context.append_signing_bytes(&mut bytes)?;
        bytes.extend_from_slice(&self.timed_out_round.to_be_bytes());
        match &self.highest_lock {
            Some(lock) => {
                bytes.push(1);
                bytes.extend_from_slice(&lock.locked_round.to_be_bytes());
                append_string(&mut bytes, &lock.proposal_value_hash)?;
            }
            None => bytes.push(0),
        }
        append_string(&mut bytes, &self.voter_public_key)?;
        Ok(bytes)
    }

    pub fn verify(
        &self,
        expected_context: &ConsensusViewContext,
        validator_keys: &[String],
    ) -> Result<(), String> {
        expected_context.validate(validator_keys)?;
        if &self.context != expected_context {
            return Err("timeout vote context mismatch".into());
        }
        if self.timed_out_round == u64::MAX {
            return Err("timeout vote cannot advance beyond u64::MAX".into());
        }
        if !validator_keys.contains(&self.voter_public_key) {
            return Err("timeout voter is not in the committed validator set".into());
        }
        if let Some(lock) = &self.highest_lock {
            if lock.locked_round > self.timed_out_round {
                return Err("timeout vote reports a lock from a future round".into());
            }
            validate_hex_32("locked proposal value hash", &lock.proposal_value_hash)?;
        }
        verify_bytes(
            &self.voter_public_key,
            &self.signing_bytes()?,
            &self.signature,
        )
    }
}

impl ConsensusTimeoutCertificate {
    pub fn verify(
        &self,
        expected_context: &ConsensusViewContext,
        validator_keys: &[String],
    ) -> Result<VerifiedTimeoutCertificate, String> {
        if self.protocol_version != TIMEOUT_CERTIFICATE_VERSION {
            return Err(format!(
                "unsupported timeout-certificate version {}",
                self.protocol_version
            ));
        }
        expected_context.validate(validator_keys)?;
        if &self.context != expected_context {
            return Err("timeout certificate context mismatch".into());
        }
        let next_round = self
            .timed_out_round
            .checked_add(1)
            .ok_or_else(|| "timeout certificate round overflows".to_string())?;
        if self.votes.len() > validator_keys.len() {
            return Err("timeout certificate has more votes than validators".into());
        }
        let required = required_quorum(validator_keys.len())?;
        let mut signers = BTreeSet::new();
        let mut locked_values = BTreeSet::new();
        for vote in &self.votes {
            if vote.timed_out_round != self.timed_out_round {
                return Err("timeout certificate mixes rounds".into());
            }
            vote.verify(expected_context, validator_keys)?;
            if !signers.insert(vote.voter_public_key.clone()) {
                return Err("timeout certificate contains a duplicate signer".into());
            }
            if let Some(lock) = &vote.highest_lock {
                locked_values.insert(lock.proposal_value_hash.clone());
            }
        }
        if signers.len() < required {
            return Err(format!(
                "timeout quorum not met: {} valid votes, {required} required",
                signers.len()
            ));
        }
        if locked_values.len() > 1 {
            return Err(
                "timeout certificate contains conflicting durable value locks; fail closed".into(),
            );
        }
        Ok(VerifiedTimeoutCertificate {
            next_round,
            required_proposal_value_hash: locked_values.into_iter().next(),
            signer_count: signers.len(),
        })
    }

    pub fn authorize_proposal(
        &self,
        expected_context: &ConsensusViewContext,
        validator_keys: &[String],
        proposal_round: u64,
        proposer_public_key: &str,
        proposal_value_hash: &str,
    ) -> Result<(), String> {
        validate_hex_32("proposal value hash", proposal_value_hash)?;
        let verified = self.verify(expected_context, validator_keys)?;
        if proposal_round != verified.next_round {
            return Err("proposal round is not the certificate's immediate successor".into());
        }
        let expected_leader = deterministic_round_leader(
            validator_keys,
            expected_context.parent_height,
            proposal_round,
        )?;
        if proposer_public_key != expected_leader {
            return Err("proposal is not from the deterministic view leader".into());
        }
        if let Some(required_value) = verified.required_proposal_value_hash {
            if proposal_value_hash != required_value {
                return Err("proposal conflicts with a durable cross-view value lock".into());
            }
        }
        Ok(())
    }
}

pub fn validator_set_commitment(validator_keys: &[String]) -> Result<String, String> {
    if validator_keys.is_empty() {
        return Err("consensus validator set is empty".into());
    }
    let mut canonical = validator_keys.to_vec();
    canonical.sort_unstable();
    if canonical.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("consensus validator set contains duplicate public keys".into());
    }
    let mut encoded = b"RLD-CONSENSUS-VALIDATOR-SET-V1\0".to_vec();
    encoded.extend_from_slice(
        &u64::try_from(canonical.len())
            .map_err(|_| "validator count does not fit u64".to_string())?
            .to_be_bytes(),
    );
    for key in canonical {
        validate_hex_32("validator public key", &key)?;
        append_string(&mut encoded, &key)?;
    }
    Ok(hash_parts(&[&encoded]))
}

pub fn consensus_proposal_value_hash(
    context: &ConsensusViewContext,
    proposal: &ConsensusProposal,
) -> Result<String, String> {
    if proposal.zone_id != context.zone_id
        || proposal.currency_genesis_root != context.currency_genesis_root
        || proposal.protocol_era != context.protocol_era
        || proposal.crypto_era != context.crypto_era
        || proposal.parent_height != context.parent_height
        || proposal.parent_state_root != context.parent_state_root
        || proposal.expected_height
            != proposal
                .parent_height
                .checked_add(1)
                .ok_or_else(|| "proposal parent height overflows".to_string())?
    {
        return Err("proposal does not match the view-change context".into());
    }
    validate_hex_32("proposal command hash", &proposal.command_hash)?;
    validate_hex_32(
        "proposal expected state root",
        &proposal.expected_state_root,
    )?;
    let mut bytes = b"RLD-CONSENSUS-PROPOSAL-VALUE-V1\0".to_vec();
    context.append_signing_bytes(&mut bytes)?;
    append_string(&mut bytes, &proposal.command_hash)?;
    bytes.extend_from_slice(&proposal.expected_height.to_be_bytes());
    append_string(&mut bytes, &proposal.expected_state_root)?;
    Ok(hash_parts(&[&bytes]))
}

fn append_string(bytes: &mut Vec<u8>, value: &str) -> Result<(), String> {
    let length = u64::try_from(value.len()).map_err(|_| "field length does not fit u64")?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn validate_hex_32(name: &str, value: &str) -> Result<(), String> {
    let decoded = hex::decode(value).map_err(|_| format!("{name} is not lowercase hex"))?;
    if decoded.len() != 32 || hex::encode(decoded) != value {
        return Err(format!("{name} must be canonical lowercase 32-byte hex"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{generate_identity, sign_bytes, ConsensusCommand};

    fn fixture() -> (
        Vec<crate::Identity>,
        Vec<String>,
        ConsensusViewContext,
        String,
    ) {
        let identities = (0..4).map(|_| generate_identity()).collect::<Vec<_>>();
        let keys = identities
            .iter()
            .map(|identity| identity.public_key.clone())
            .collect::<Vec<_>>();
        let context = ConsensusViewContext {
            network_domain: "rldcoin:mainnet-candidate:v1".into(),
            zone_id: "zone-a".into(),
            currency_genesis_root: "11".repeat(32),
            protocol_era: 7,
            crypto_era: 3,
            validator_set_epoch: 9,
            validator_set_commitment: String::new(),
            parent_height: 42,
            parent_state_root: "22".repeat(32),
        }
        .bind_validator_set(&keys)
        .unwrap();
        (identities, keys, context, "33".repeat(32))
    }

    fn signed_vote(
        identity: &crate::Identity,
        context: &ConsensusViewContext,
        round: u64,
        lock: Option<ConsensusLockedValue>,
    ) -> ConsensusTimeoutVote {
        let mut vote = ConsensusTimeoutVote {
            protocol_version: TIMEOUT_VOTE_VERSION.into(),
            context: context.clone(),
            timed_out_round: round,
            highest_lock: lock,
            voter_public_key: identity.public_key.clone(),
            signature: String::new(),
        };
        vote.signature = sign_bytes(&identity.secret_key, &vote.signing_bytes().unwrap()).unwrap();
        vote
    }

    fn certificate(
        identities: &[crate::Identity],
        context: &ConsensusViewContext,
        round: u64,
        locks: &[Option<ConsensusLockedValue>],
    ) -> ConsensusTimeoutCertificate {
        ConsensusTimeoutCertificate {
            protocol_version: TIMEOUT_CERTIFICATE_VERSION.into(),
            context: context.clone(),
            timed_out_round: round,
            votes: identities
                .iter()
                .zip(locks.iter().cloned())
                .map(|(identity, lock)| signed_vote(identity, context, round, lock))
                .collect(),
        }
    }

    #[test]
    fn three_of_four_timeout_votes_authorize_only_the_next_round_leader() {
        let (identities, keys, context, value_hash) = fixture();
        let certificate = certificate(&identities[..3], &context, 0, &[None, None, None]);
        let leader = deterministic_round_leader(&keys, context.parent_height, 1).unwrap();
        certificate
            .authorize_proposal(&context, &keys, 1, &leader, &value_hash)
            .unwrap();
        assert!(certificate
            .authorize_proposal(&context, &keys, 2, &leader, &value_hash)
            .is_err());
        let nonleader = keys.iter().find(|key| **key != leader).unwrap();
        assert!(certificate
            .authorize_proposal(&context, &keys, 1, nonleader, &value_hash)
            .is_err());
    }

    #[test]
    fn insufficient_duplicate_and_mixed_round_certificates_fail() {
        let (identities, keys, context, _) = fixture();
        let two = certificate(&identities[..2], &context, 0, &[None, None]);
        assert!(two.verify(&context, &keys).is_err());

        let mut duplicate = certificate(&identities[..3], &context, 0, &[None, None, None]);
        duplicate.votes[2] = duplicate.votes[0].clone();
        assert!(duplicate.verify(&context, &keys).is_err());

        let mut mixed = certificate(&identities[..3], &context, 0, &[None, None, None]);
        mixed.votes[2] = signed_vote(&identities[2], &context, 1, None);
        assert!(mixed.verify(&context, &keys).is_err());
    }

    #[test]
    fn domain_era_parent_and_validator_set_replay_fail() {
        let (identities, keys, context, _) = fixture();
        let certificate = certificate(&identities[..3], &context, 0, &[None, None, None]);
        let mut wrong = context.clone();
        wrong.crypto_era += 1;
        assert!(certificate.verify(&wrong, &keys).is_err());
        let mut wrong = context.clone();
        wrong.parent_state_root = "44".repeat(32);
        assert!(certificate.verify(&wrong, &keys).is_err());
        let mut foreign_keys = keys.clone();
        foreign_keys[3] = generate_identity().public_key;
        assert!(certificate.verify(&context, &foreign_keys).is_err());
    }

    #[test]
    fn one_durable_value_lock_is_mandatory_across_views() {
        let (identities, keys, context, value_hash) = fixture();
        let lock = Some(ConsensusLockedValue {
            locked_round: 0,
            proposal_value_hash: value_hash.clone(),
        });
        let certificate = certificate(&identities[..3], &context, 0, &[lock.clone(), lock, None]);
        let verified = certificate.verify(&context, &keys).unwrap();
        assert_eq!(
            verified.required_proposal_value_hash,
            Some(value_hash.clone())
        );
        let leader = deterministic_round_leader(&keys, context.parent_height, 1).unwrap();
        assert!(certificate
            .authorize_proposal(&context, &keys, 1, &leader, &"55".repeat(32))
            .is_err());
        certificate
            .authorize_proposal(&context, &keys, 1, &leader, &value_hash)
            .unwrap();
    }

    #[test]
    fn conflicting_reported_locks_fail_closed() {
        let (identities, keys, context, _) = fixture();
        let first = Some(ConsensusLockedValue {
            locked_round: 0,
            proposal_value_hash: "33".repeat(32),
        });
        let second = Some(ConsensusLockedValue {
            locked_round: 0,
            proposal_value_hash: "44".repeat(32),
        });
        let certificate = certificate(&identities[..3], &context, 0, &[first, second, None]);
        assert!(certificate.verify(&context, &keys).is_err());
    }

    #[test]
    fn future_lock_and_round_overflow_fail() {
        let (identities, keys, context, _) = fixture();
        let future_lock = Some(ConsensusLockedValue {
            locked_round: 1,
            proposal_value_hash: "33".repeat(32),
        });
        let future_certificate =
            certificate(&identities[..3], &context, 0, &[future_lock, None, None]);
        assert!(future_certificate.verify(&context, &keys).is_err());
        let overflow = certificate(&identities[..3], &context, u64::MAX, &[None, None, None]);
        assert!(overflow.verify(&context, &keys).is_err());
    }

    #[test]
    fn proposal_value_excludes_proposer_and_round_but_binds_execution() {
        let (identities, keys, context, _) = fixture();
        let mut proposal = ConsensusProposal {
            proposal_id: "proposal-round-zero".into(),
            zone_id: context.zone_id.clone(),
            currency_genesis_root: context.currency_genesis_root.clone(),
            protocol_era: context.protocol_era,
            crypto_era: context.crypto_era,
            parent_height: context.parent_height,
            parent_state_root: context.parent_state_root.clone(),
            round: 0,
            proposer_public_key: identities[0].public_key.clone(),
            command: ConsensusCommand::ActivatePendingValueRiskPolicy,
            command_hash: "33".repeat(32),
            expected_height: context.parent_height + 1,
            expected_state_root: "44".repeat(32),
            signature: String::new(),
        };
        let first = consensus_proposal_value_hash(&context, &proposal).unwrap();
        proposal.proposal_id = "proposal-round-one".into();
        proposal.proposer_public_key = identities[1].public_key.clone();
        proposal.round = 1;
        assert_eq!(
            first,
            consensus_proposal_value_hash(&context, &proposal).unwrap()
        );
        proposal.expected_state_root = "55".repeat(32);
        assert_ne!(
            first,
            consensus_proposal_value_hash(&context, &proposal).unwrap()
        );
        assert_eq!(
            context.validator_set_commitment,
            validator_set_commitment(&keys).unwrap()
        );
    }
}
