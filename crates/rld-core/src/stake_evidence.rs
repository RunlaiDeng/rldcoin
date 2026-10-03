//! Objective, cryptographically verifiable evidence for consensus-stake slashing.
//!
//! The verifier in this module is deliberately independent of current runtime
//! membership.  It resolves the historical public key and liability window
//! from a validated, ledger-derived Epoch record.  It does not mutate Coins;
//! the ledger slash transition is a separate atomic operation.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{
    crypto::{hash_parts, verify_bytes},
    stake_epoch::{
        validate_ledger_derived_stake_epoch_v1, ConsensusStakeEpochLiabilityV2,
        ConsensusStakeSlashPolicyV2, LedgerDerivedStakeEpochV1,
    },
    wire::{digest_hex, encode_source, preimage, WireSchema},
};

const CHECKPOINT_SIGNATURE_DOMAIN: &[u8] = b"RLD-CONSENSUS-STAKE-CHECKPOINT-V1";
const EVIDENCE_HASH_DOMAIN: &[u8] = b"RLD-CONSENSUS-STAKE-SLASH-EVIDENCE-V1";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConsensusStakeSlashEvidenceKindV1 {
    DoubleSign,
    ConflictingCheckpoint,
    InvalidStateCommitment,
}

impl ConsensusStakeSlashEvidenceKindV1 {
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::DoubleSign => "DOUBLE_SIGN",
            Self::ConflictingCheckpoint => "CONFLICTING_CHECKPOINT",
            Self::InvalidStateCommitment => "INVALID_STATE_COMMITMENT",
        }
    }
}

/// Exact RLD-WIRE-V1 vote statement.  The bytes are identical to the bytes a
/// `ConsensusVote` signs, but the command evidence does not deserialize or
/// execute the referenced proposal.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedConsensusVoteStatementV1 {
    pub proposal_id: String,
    pub proposal_hash: String,
    pub zone_id: String,
    pub currency_genesis_root: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub parent_height: u64,
    pub parent_state_root: String,
    pub round: u64,
    pub expected_state_root: String,
    pub voter_public_key: String,
    pub signature: String,
}

impl SignedConsensusVoteStatementV1 {
    pub fn wire_v1_canonical_bytes(&self, network_domain: &str) -> Result<Vec<u8>, String> {
        let mut source = Map::new();
        source.insert(
            "network_domain".into(),
            Value::String(network_domain.into()),
        );
        source.insert(
            "proposal_id".into(),
            Value::String(self.proposal_id.clone()),
        );
        source.insert(
            "proposal_hash".into(),
            Value::String(self.proposal_hash.clone()),
        );
        source.insert("zone_id".into(), Value::String(self.zone_id.clone()));
        source.insert(
            "currency_genesis_root".into(),
            Value::String(self.currency_genesis_root.clone()),
        );
        source.insert(
            "protocol_era".into(),
            Value::String(self.protocol_era.to_string()),
        );
        source.insert(
            "crypto_era".into(),
            Value::String(self.crypto_era.to_string()),
        );
        source.insert(
            "parent_height".into(),
            Value::String(u128::from(self.parent_height).to_string()),
        );
        source.insert(
            "parent_state_root".into(),
            Value::String(self.parent_state_root.clone()),
        );
        source.insert("round".into(), Value::String(self.round.to_string()));
        source.insert(
            "expected_state_root".into(),
            Value::String(self.expected_state_root.clone()),
        );
        source.insert(
            "voter_public_key".into(),
            Value::String(self.voter_public_key.clone()),
        );
        encode_source(WireSchema::ConsensusVote, &source).map_err(|error| error.to_string())
    }

    pub fn signing_bytes(&self, network_domain: &str) -> Result<Vec<u8>, String> {
        Ok(preimage(
            WireSchema::ConsensusVote,
            &self.wire_v1_canonical_bytes(network_domain)?,
        ))
    }

    pub fn content_hash(&self, network_domain: &str) -> Result<String, String> {
        Ok(digest_hex(
            WireSchema::ConsensusVote,
            &self.wire_v1_canonical_bytes(network_domain)?,
        ))
    }

    pub fn signed_commitment(&self, network_domain: &str) -> Result<String, String> {
        Ok(hash_parts(&[
            b"RLD-CONSENSUS-STAKE-SIGNED-VOTE-V1",
            &self.signing_bytes(network_domain)?,
            self.signature.as_bytes(),
        ]))
    }
}

/// Exact proposal signing statement without embedding or executing the command.
/// `command_hash` is the already content-addressed command commitment.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedConsensusProposalStatementV1 {
    pub proposal_id: String,
    pub zone_id: String,
    pub currency_genesis_root: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub parent_height: u64,
    pub parent_state_root: String,
    pub round: u64,
    pub proposer_public_key: String,
    pub command_hash: String,
    pub expected_height: u64,
    pub expected_state_root: String,
    pub signature: String,
}

impl SignedConsensusProposalStatementV1 {
    pub fn wire_v1_canonical_bytes(&self, network_domain: &str) -> Result<Vec<u8>, String> {
        let mut source = Map::new();
        source.insert(
            "network_domain".into(),
            Value::String(network_domain.into()),
        );
        source.insert(
            "proposal_id".into(),
            Value::String(self.proposal_id.clone()),
        );
        source.insert("zone_id".into(), Value::String(self.zone_id.clone()));
        source.insert(
            "currency_genesis_root".into(),
            Value::String(self.currency_genesis_root.clone()),
        );
        source.insert(
            "protocol_era".into(),
            Value::String(self.protocol_era.to_string()),
        );
        source.insert(
            "crypto_era".into(),
            Value::String(self.crypto_era.to_string()),
        );
        source.insert(
            "parent_height".into(),
            Value::String(u128::from(self.parent_height).to_string()),
        );
        source.insert(
            "parent_state_root".into(),
            Value::String(self.parent_state_root.clone()),
        );
        source.insert("round".into(), Value::String(self.round.to_string()));
        source.insert(
            "proposer_public_key".into(),
            Value::String(self.proposer_public_key.clone()),
        );
        source.insert(
            "command_hash".into(),
            Value::String(self.command_hash.clone()),
        );
        source.insert(
            "expected_height".into(),
            Value::String(u128::from(self.expected_height).to_string()),
        );
        source.insert(
            "expected_state_root".into(),
            Value::String(self.expected_state_root.clone()),
        );
        encode_source(WireSchema::ConsensusProposal, &source).map_err(|error| error.to_string())
    }

    pub fn signing_bytes(&self, network_domain: &str) -> Result<Vec<u8>, String> {
        Ok(preimage(
            WireSchema::ConsensusProposal,
            &self.wire_v1_canonical_bytes(network_domain)?,
        ))
    }

    pub fn content_hash(&self, network_domain: &str) -> Result<String, String> {
        Ok(digest_hex(
            WireSchema::ConsensusProposal,
            &self.wire_v1_canonical_bytes(network_domain)?,
        ))
    }

    pub fn signed_commitment(&self, network_domain: &str) -> Result<String, String> {
        Ok(hash_parts(&[
            b"RLD-CONSENSUS-STAKE-SIGNED-PROPOSAL-V1",
            &self.signing_bytes(network_domain)?,
            self.signature.as_bytes(),
        ]))
    }
}

/// Validator-signed checkpoint statement.  Every contextual field is inside
/// the signature; two statements conflict only when all fields other than the
/// state root are byte-identical.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedConsensusCheckpointStatementV1 {
    pub network_domain: String,
    pub zone_id: String,
    pub currency_genesis_root: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub consensus_protocol_version: u64,
    pub consensus_epoch: u64,
    pub checkpoint_height: u128,
    pub previous_checkpoint_hash: String,
    pub state_root: String,
    pub validator_id: String,
    pub validator_public_key: String,
    pub validator_key_era: u64,
    pub signature: String,
}

impl SignedConsensusCheckpointStatementV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = CHECKPOINT_SIGNATURE_DOMAIN.to_vec();
        for value in [
            self.network_domain.as_str(),
            self.zone_id.as_str(),
            self.currency_genesis_root.as_str(),
        ] {
            push_framed_text(&mut bytes, value)?;
        }
        bytes.extend_from_slice(&self.protocol_era.to_be_bytes());
        bytes.extend_from_slice(&self.crypto_era.to_be_bytes());
        bytes.extend_from_slice(&self.consensus_protocol_version.to_be_bytes());
        bytes.extend_from_slice(&self.consensus_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.checkpoint_height.to_be_bytes());
        push_framed_text(&mut bytes, &self.previous_checkpoint_hash)?;
        push_framed_text(&mut bytes, &self.state_root)?;
        push_framed_text(&mut bytes, &self.validator_id)?;
        push_framed_text(&mut bytes, &self.validator_public_key)?;
        bytes.extend_from_slice(&self.validator_key_era.to_be_bytes());
        Ok(bytes)
    }

    pub fn signed_commitment(&self) -> Result<String, String> {
        Ok(hash_parts(&[
            b"RLD-CONSENSUS-STAKE-SIGNED-CHECKPOINT-V1",
            &self.signing_bytes()?,
            self.signature.as_bytes(),
        ]))
    }
}

/// A fixed-shape union avoids ambiguous enum serialization.  Exactly one field
/// set is permitted for the declared kind; all inactive fields must be absent.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsensusStakeSlashEvidenceV1 {
    pub kind: ConsensusStakeSlashEvidenceKindV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_vote: Option<SignedConsensusVoteStatementV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub second_vote: Option<SignedConsensusVoteStatementV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_checkpoint: Option<SignedConsensusCheckpointStatementV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub second_checkpoint: Option<SignedConsensusCheckpointStatementV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal: Option<SignedConsensusProposalStatementV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invalid_vote: Option<SignedConsensusVoteStatementV1>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedConsensusStakeSlashEvidenceV1 {
    pub evidence_hash: String,
    pub kind: ConsensusStakeSlashEvidenceKindV1,
    pub slash_bps: u16,
    pub fault_height: u128,
    pub liability: ConsensusStakeEpochLiabilityV2,
}

/// Error ordering is consensus-significant and deliberately matches the order
/// in `verify_consensus_stake_slash_evidence_v1`.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ConsensusStakeEvidenceError {
    #[error("derived Epoch record is invalid: {0}")]
    InvalidEpochRecord(String),
    #[error("slash liability was not found or does not match")]
    LiabilityMismatch,
    #[error("evidence shape is invalid for its declared kind")]
    InvalidEvidenceShape,
    #[error("evidence context does not match the historical liability")]
    ContextMismatch,
    #[error("evidence height is outside the historical liability window")]
    OutsideLiabilityWindow,
    #[error("evidence does not use the historical validator key")]
    HistoricalKeyMismatch,
    #[error("paired evidence statements are not in canonical commitment order")]
    NonCanonicalPair,
    #[error("evidence statement encoding or signature is invalid: {0}")]
    InvalidSignature(String),
    #[error("evidence statements do not prove the declared objective fault")]
    NoObjectiveFault,
}

impl ConsensusStakeSlashEvidenceV1 {
    pub fn evidence_hash(
        &self,
        network_domain: &str,
    ) -> Result<String, ConsensusStakeEvidenceError> {
        let mut parts = vec![EVIDENCE_HASH_DOMAIN, self.kind.wire_name().as_bytes()];
        let commitments = self.active_commitments(network_domain)?;
        for commitment in &commitments {
            parts.push(commitment.as_bytes());
        }
        Ok(hash_parts(&parts))
    }

    fn active_commitments(
        &self,
        network_domain: &str,
    ) -> Result<Vec<String>, ConsensusStakeEvidenceError> {
        let invalid_shape = || ConsensusStakeEvidenceError::InvalidEvidenceShape;
        match self.kind {
            ConsensusStakeSlashEvidenceKindV1::DoubleSign => {
                if self.first_checkpoint.is_some()
                    || self.second_checkpoint.is_some()
                    || self.proposal.is_some()
                    || self.invalid_vote.is_some()
                {
                    return Err(invalid_shape());
                }
                Ok(vec![
                    self.first_vote
                        .as_ref()
                        .ok_or_else(invalid_shape)?
                        .signed_commitment(network_domain)
                        .map_err(ConsensusStakeEvidenceError::InvalidSignature)?,
                    self.second_vote
                        .as_ref()
                        .ok_or_else(invalid_shape)?
                        .signed_commitment(network_domain)
                        .map_err(ConsensusStakeEvidenceError::InvalidSignature)?,
                ])
            }
            ConsensusStakeSlashEvidenceKindV1::ConflictingCheckpoint => {
                if self.first_vote.is_some()
                    || self.second_vote.is_some()
                    || self.proposal.is_some()
                    || self.invalid_vote.is_some()
                {
                    return Err(invalid_shape());
                }
                Ok(vec![
                    self.first_checkpoint
                        .as_ref()
                        .ok_or_else(invalid_shape)?
                        .signed_commitment()
                        .map_err(ConsensusStakeEvidenceError::InvalidSignature)?,
                    self.second_checkpoint
                        .as_ref()
                        .ok_or_else(invalid_shape)?
                        .signed_commitment()
                        .map_err(ConsensusStakeEvidenceError::InvalidSignature)?,
                ])
            }
            ConsensusStakeSlashEvidenceKindV1::InvalidStateCommitment => {
                if self.first_vote.is_some()
                    || self.second_vote.is_some()
                    || self.first_checkpoint.is_some()
                    || self.second_checkpoint.is_some()
                {
                    return Err(invalid_shape());
                }
                Ok(vec![
                    self.proposal
                        .as_ref()
                        .ok_or_else(invalid_shape)?
                        .signed_commitment(network_domain)
                        .map_err(ConsensusStakeEvidenceError::InvalidSignature)?,
                    self.invalid_vote
                        .as_ref()
                        .ok_or_else(invalid_shape)?
                        .signed_commitment(network_domain)
                        .map_err(ConsensusStakeEvidenceError::InvalidSignature)?,
                ])
            }
        }
    }
}

pub fn verify_consensus_stake_slash_evidence_v1(
    record: &LedgerDerivedStakeEpochV1,
    position_id: &str,
    liability_commitment: &str,
    evidence: &ConsensusStakeSlashEvidenceV1,
) -> Result<VerifiedConsensusStakeSlashEvidenceV1, ConsensusStakeEvidenceError> {
    validate_ledger_derived_stake_epoch_v1(record)
        .map_err(|error| ConsensusStakeEvidenceError::InvalidEpochRecord(error.to_string()))?;
    let liability = record
        .stake_liabilities
        .iter()
        .find(|liability| {
            liability.position.position_id == position_id
                && liability.liability_commitment == liability_commitment
        })
        .cloned()
        .ok_or(ConsensusStakeEvidenceError::LiabilityMismatch)?;
    let terms = liability
        .position
        .slash_terms
        .as_ref()
        .filter(|terms| terms.slash_policy == ConsensusStakeSlashPolicyV2::protocol_v2())
        .ok_or(ConsensusStakeEvidenceError::LiabilityMismatch)?;
    let network_domain = record.descriptor.network_domain.as_str();

    let (slash_bps, fault_height) = match evidence.kind {
        ConsensusStakeSlashEvidenceKindV1::DoubleSign => {
            verify_double_sign(record, &liability, evidence, network_domain)?;
            (
                terms.slash_policy.double_sign_slash_bps,
                u128::from(
                    evidence
                        .first_vote
                        .as_ref()
                        .expect("shape was checked")
                        .parent_height
                        .checked_add(1)
                        .ok_or(ConsensusStakeEvidenceError::OutsideLiabilityWindow)?,
                ),
            )
        }
        ConsensusStakeSlashEvidenceKindV1::ConflictingCheckpoint => {
            verify_conflicting_checkpoint(record, &liability, evidence)?;
            (
                terms.slash_policy.conflicting_checkpoint_slash_bps,
                evidence
                    .first_checkpoint
                    .as_ref()
                    .expect("shape was checked")
                    .checkpoint_height,
            )
        }
        ConsensusStakeSlashEvidenceKindV1::InvalidStateCommitment => {
            verify_invalid_state_commitment(record, &liability, evidence, network_domain)?;
            (
                terms.slash_policy.invalid_state_commitment_slash_bps,
                u128::from(
                    evidence
                        .proposal
                        .as_ref()
                        .expect("shape was checked")
                        .expected_height,
                ),
            )
        }
    };
    if slash_bps == 0 || slash_bps > terms.slash_policy.maximum_cumulative_slash_bps {
        return Err(ConsensusStakeEvidenceError::LiabilityMismatch);
    }
    Ok(VerifiedConsensusStakeSlashEvidenceV1 {
        evidence_hash: evidence.evidence_hash(network_domain)?,
        kind: evidence.kind,
        slash_bps,
        fault_height,
        liability,
    })
}

fn verify_double_sign(
    record: &LedgerDerivedStakeEpochV1,
    liability: &ConsensusStakeEpochLiabilityV2,
    evidence: &ConsensusStakeSlashEvidenceV1,
    network_domain: &str,
) -> Result<(), ConsensusStakeEvidenceError> {
    let commitments = evidence.active_commitments(network_domain)?;
    if commitments[0] >= commitments[1] {
        return Err(ConsensusStakeEvidenceError::NonCanonicalPair);
    }
    let first = evidence.first_vote.as_ref().expect("shape was checked");
    let second = evidence.second_vote.as_ref().expect("shape was checked");
    validate_vote_context(record, liability, first)?;
    validate_vote_context(record, liability, second)?;
    if first.zone_id != second.zone_id
        || first.currency_genesis_root != second.currency_genesis_root
        || first.protocol_era != second.protocol_era
        || first.crypto_era != second.crypto_era
        || first.parent_height != second.parent_height
        || first.parent_state_root != second.parent_state_root
        || first.round != second.round
        || first.voter_public_key != second.voter_public_key
    {
        return Err(ConsensusStakeEvidenceError::ContextMismatch);
    }
    verify_vote_signature(first, network_domain)?;
    verify_vote_signature(second, network_domain)?;
    if first.proposal_hash == second.proposal_hash
        && first.expected_state_root == second.expected_state_root
    {
        return Err(ConsensusStakeEvidenceError::NoObjectiveFault);
    }
    Ok(())
}

fn verify_conflicting_checkpoint(
    record: &LedgerDerivedStakeEpochV1,
    liability: &ConsensusStakeEpochLiabilityV2,
    evidence: &ConsensusStakeSlashEvidenceV1,
) -> Result<(), ConsensusStakeEvidenceError> {
    let commitments = evidence.active_commitments(&record.descriptor.network_domain)?;
    if commitments[0] >= commitments[1] {
        return Err(ConsensusStakeEvidenceError::NonCanonicalPair);
    }
    let first = evidence
        .first_checkpoint
        .as_ref()
        .expect("shape was checked");
    let second = evidence
        .second_checkpoint
        .as_ref()
        .expect("shape was checked");
    validate_checkpoint_context(record, liability, first)?;
    validate_checkpoint_context(record, liability, second)?;
    if checkpoint_instance(first) != checkpoint_instance(second) {
        return Err(ConsensusStakeEvidenceError::ContextMismatch);
    }
    verify_bytes(
        &first.validator_public_key,
        &first
            .signing_bytes()
            .map_err(ConsensusStakeEvidenceError::InvalidSignature)?,
        &first.signature,
    )
    .map_err(ConsensusStakeEvidenceError::InvalidSignature)?;
    verify_bytes(
        &second.validator_public_key,
        &second
            .signing_bytes()
            .map_err(ConsensusStakeEvidenceError::InvalidSignature)?,
        &second.signature,
    )
    .map_err(ConsensusStakeEvidenceError::InvalidSignature)?;
    if first.state_root == second.state_root {
        return Err(ConsensusStakeEvidenceError::NoObjectiveFault);
    }
    Ok(())
}

fn verify_invalid_state_commitment(
    record: &LedgerDerivedStakeEpochV1,
    liability: &ConsensusStakeEpochLiabilityV2,
    evidence: &ConsensusStakeSlashEvidenceV1,
    network_domain: &str,
) -> Result<(), ConsensusStakeEvidenceError> {
    evidence.active_commitments(network_domain)?;
    let proposal = evidence.proposal.as_ref().expect("shape was checked");
    let vote = evidence.invalid_vote.as_ref().expect("shape was checked");
    validate_vote_context(record, liability, vote)?;
    if proposal.zone_id != record.descriptor.zone_id
        || proposal.currency_genesis_root != record.descriptor.currency_genesis_root
        || proposal.protocol_era != record.descriptor.protocol_era
        || proposal.crypto_era != record.descriptor.crypto_era
        || proposal.parent_height != vote.parent_height
        || proposal.parent_state_root != vote.parent_state_root
        || proposal.round != vote.round
        || proposal.proposal_id != vote.proposal_id
        || proposal.expected_height
            != proposal
                .parent_height
                .checked_add(1)
                .ok_or(ConsensusStakeEvidenceError::OutsideLiabilityWindow)?
        || u128::from(proposal.expected_height) < liability.activation_height
        || u128::from(proposal.expected_height) >= liability.exit_height
        || !record
            .descriptor
            .validators
            .iter()
            .any(|validator| validator.public_key == proposal.proposer_public_key)
    {
        return Err(ConsensusStakeEvidenceError::ContextMismatch);
    }
    let proposal_hash = proposal
        .content_hash(network_domain)
        .map_err(ConsensusStakeEvidenceError::InvalidSignature)?;
    if vote.proposal_hash != proposal_hash {
        return Err(ConsensusStakeEvidenceError::ContextMismatch);
    }
    verify_bytes(
        &proposal.proposer_public_key,
        &proposal
            .signing_bytes(network_domain)
            .map_err(ConsensusStakeEvidenceError::InvalidSignature)?,
        &proposal.signature,
    )
    .map_err(ConsensusStakeEvidenceError::InvalidSignature)?;
    verify_vote_signature(vote, network_domain)?;
    if vote.expected_state_root == proposal.expected_state_root {
        return Err(ConsensusStakeEvidenceError::NoObjectiveFault);
    }
    Ok(())
}

fn validate_vote_context(
    record: &LedgerDerivedStakeEpochV1,
    liability: &ConsensusStakeEpochLiabilityV2,
    vote: &SignedConsensusVoteStatementV1,
) -> Result<(), ConsensusStakeEvidenceError> {
    if vote.zone_id != record.descriptor.zone_id
        || vote.currency_genesis_root != record.descriptor.currency_genesis_root
        || vote.protocol_era != record.descriptor.protocol_era
        || vote.crypto_era != record.descriptor.crypto_era
    {
        return Err(ConsensusStakeEvidenceError::ContextMismatch);
    }
    let height = vote
        .parent_height
        .checked_add(1)
        .map(u128::from)
        .ok_or(ConsensusStakeEvidenceError::OutsideLiabilityWindow)?;
    if height < liability.activation_height || height >= liability.exit_height {
        return Err(ConsensusStakeEvidenceError::OutsideLiabilityWindow);
    }
    if vote.voter_public_key != liability.validator_public_key {
        return Err(ConsensusStakeEvidenceError::HistoricalKeyMismatch);
    }
    Ok(())
}

fn validate_checkpoint_context(
    record: &LedgerDerivedStakeEpochV1,
    liability: &ConsensusStakeEpochLiabilityV2,
    checkpoint: &SignedConsensusCheckpointStatementV1,
) -> Result<(), ConsensusStakeEvidenceError> {
    if checkpoint.network_domain != record.descriptor.network_domain
        || checkpoint.zone_id != record.descriptor.zone_id
        || checkpoint.currency_genesis_root != record.descriptor.currency_genesis_root
        || checkpoint.protocol_era != record.descriptor.protocol_era
        || checkpoint.crypto_era != record.descriptor.crypto_era
        || checkpoint.consensus_protocol_version != record.descriptor.consensus_protocol_version
        || checkpoint.consensus_epoch != liability.consensus_epoch
    {
        return Err(ConsensusStakeEvidenceError::ContextMismatch);
    }
    if checkpoint.checkpoint_height < liability.activation_height
        || checkpoint.checkpoint_height >= liability.exit_height
    {
        return Err(ConsensusStakeEvidenceError::OutsideLiabilityWindow);
    }
    if checkpoint.validator_id != liability.position.validator_id()
        || checkpoint.validator_public_key != liability.validator_public_key
        || checkpoint.validator_key_era != liability.validator_key_era
    {
        return Err(ConsensusStakeEvidenceError::HistoricalKeyMismatch);
    }
    Ok(())
}

type CheckpointInstance<'a> = (
    &'a str,
    &'a str,
    &'a str,
    u64,
    u64,
    u64,
    u64,
    u128,
    &'a str,
    &'a str,
    &'a str,
    u64,
);

fn checkpoint_instance(
    checkpoint: &SignedConsensusCheckpointStatementV1,
) -> CheckpointInstance<'_> {
    (
        &checkpoint.network_domain,
        &checkpoint.zone_id,
        &checkpoint.currency_genesis_root,
        checkpoint.protocol_era,
        checkpoint.crypto_era,
        checkpoint.consensus_protocol_version,
        checkpoint.consensus_epoch,
        checkpoint.checkpoint_height,
        &checkpoint.previous_checkpoint_hash,
        &checkpoint.validator_id,
        &checkpoint.validator_public_key,
        checkpoint.validator_key_era,
    )
}

fn verify_vote_signature(
    vote: &SignedConsensusVoteStatementV1,
    network_domain: &str,
) -> Result<(), ConsensusStakeEvidenceError> {
    verify_bytes(
        &vote.voter_public_key,
        &vote
            .signing_bytes(network_domain)
            .map_err(ConsensusStakeEvidenceError::InvalidSignature)?,
        &vote.signature,
    )
    .map_err(ConsensusStakeEvidenceError::InvalidSignature)
}

fn push_framed_text(bytes: &mut Vec<u8>, value: &str) -> Result<(), String> {
    let length = u32::try_from(value.len()).map_err(|_| "checkpoint field is too long")?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}
