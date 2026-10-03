//! Frozen stake-state resource schemas plus adopted policy-governance commands.
//!
//! Tags 18/19 are delayed policy proposal and activation. R6.18 separately
//! adopts candidate-registration tag 20. R6.19 appends resource-bound position
//! lock and exact legacy-position migration as tags 21/22. Epoch, unbond,
//! slash-evidence, settlement and runtime membership remain closed. R6.22B
//! additionally freezes codec-only unbond-v2 tags 26/27 and schemas
//! `0x1060..=0x1063`; those tags are not runtime `ConsensusCommand` variants.

use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

use crate::{
    action_payload_hash,
    command_wire::encode_codec_only_candidate_payload,
    wire::{digest_hex, WireError, WireSchema},
    Amount, QuorumCertificate, SignedActionAuthorization, StakePositionLiabilityHorizonV1,
    RLDCOIN_MAINNET_DOMAIN, RLDCOIN_TESTNET_DOMAIN,
};

pub const PROPOSE_STAKE_STATE_RESOURCE_POLICY_CANDIDATE_TAG_V1: u16 = 18;
pub const ACTIVATE_STAKE_STATE_RESOURCE_POLICY_CANDIDATE_TAG_V1: u16 = 19;
pub const PROPOSE_STAKE_STATE_RESOURCE_POLICY_ACTION_V1: &str =
    "PROPOSE_STAKE_STATE_RESOURCE_POLICY_V1";
pub const ACTIVATE_STAKE_STATE_RESOURCE_POLICY_ACTION_V1: &str =
    "ACTIVATE_STAKE_STATE_RESOURCE_POLICY_V1";
pub const REQUEST_CONSENSUS_STAKE_UNBOND_CANDIDATE_TAG_V2: u16 = 26;
pub const COMPLETE_CONSENSUS_STAKE_UNBOND_CANDIDATE_TAG_V2: u16 = 27;
pub const REQUEST_CONSENSUS_STAKE_UNBOND_ACTION_V2: &str = "REQUEST_CONSENSUS_STAKE_UNBOND_V2";
pub const COMPLETE_CONSENSUS_STAKE_UNBOND_ACTION_V2: &str = "COMPLETE_CONSENSUS_STAKE_UNBOND_V2";

pub const STAKE_STATE_RESOURCE_POLICY_SCHEMA_V1: u16 = 0x1038;
pub const STAKE_STATE_RESOURCE_ENVELOPE_SCHEMA_V1: u16 = 0x1039;
pub const STAKE_STATE_BOND_RECORD_SCHEMA_V1: u16 = 0x103a;
pub const STAKE_STATE_MAINTENANCE_POOL_SCHEMA_V1: u16 = 0x103b;
pub const PROPOSE_STAKE_STATE_RESOURCE_POLICY_SCHEMA_V1: u16 = 0x103c;
pub const ACTIVATE_STAKE_STATE_RESOURCE_POLICY_SCHEMA_V1: u16 = 0x103d;
pub const STAKE_STATE_BOND_RECORD_SCHEMA_V2: u16 = 0x103e;
pub const STAKE_STATE_MAINTENANCE_POOL_POLICY_BUCKET_SCHEMA_V2: u16 = 0x103f;
pub const STAKE_STATE_MAINTENANCE_POOL_SCHEMA_V2: u16 = 0x1040;
pub const STAKE_STATE_BOND_RENEWAL_RECORD_SCHEMA_V1: u16 = 0x1047;
pub const REQUEST_CONSENSUS_STAKE_UNBOND_SCHEMA_V2: u16 = 0x1060;
pub const COMPLETE_CONSENSUS_STAKE_UNBOND_SCHEMA_V2: u16 = 0x1061;
pub const STAKE_STATE_RESOURCE_MUTATION_ENVELOPE_SCHEMA_V1: u16 = 0x1062;
pub const STAKE_POSITION_LIABILITY_HORIZON_SCHEMA_V1: u16 = 0x1063;
pub const STAKE_STATE_RESOURCE_KIND_ENUM_V1: u16 = 0x300a;
pub const STAKE_STATE_BOND_STATUS_ENUM_V1: u16 = 0x300b;

const PAYLOAD_LIMIT: usize = 1024 * 1024;
const COMMAND_MAGIC: &[u8; 4] = b"RLDW";
const COMMAND_VERSION: u16 = 1;
const COMMAND_COMMITMENT_SCHEMA: u16 = 0x0500;
const OUTER_TEXT: u8 = 0x01;
const OUTER_U16: u8 = 0x03;
const OUTER_BYTES: u8 = 0x09;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StakeStateResourcePolicyV1 {
    pub policy_version: u16,
    pub sequence: u64,
    pub previous_policy_commitment: String,
    pub activation_delay_blocks: u64,
    pub base_candidate_fee: Amount,
    pub base_position_fee: Amount,
    pub base_epoch_fee: Amount,
    pub base_unbond_fee: Amount,
    pub base_slash_evidence_fee: Amount,
    pub fee_per_wire_byte: Amount,
    pub fee_per_signature_verification: Amount,
    pub fee_per_state_read: Amount,
    pub fee_per_state_write: Amount,
    pub bond_per_persistent_byte: Amount,
    pub minimum_candidate_bond: Amount,
    pub minimum_position_bond: Amount,
    pub minimum_lease_blocks: u64,
    pub maximum_lease_blocks: u64,
    pub expiry_grace_blocks: u64,
    pub terminal_retention_blocks: u64,
    pub maximum_active_candidates: u32,
    pub maximum_candidates_per_owner: u32,
    pub maximum_active_positions: u32,
    pub maximum_positions_per_owner: u32,
    pub maximum_pending_unbonds: u32,
    pub maximum_pending_unbonds_per_owner: u32,
    pub maximum_slash_record_bytes: u32,
    pub maximum_total_stake_state_bytes: u64,
    pub maximum_stake_state_bytes_per_block: u32,
    pub maximum_stake_signature_checks_per_block: u32,
    pub maximum_stake_state_reads_per_block: u32,
    pub maximum_stake_state_writes_per_block: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StakeStateResourceEnvelopeV1 {
    pub resource_policy_sequence: u64,
    pub resource_policy_commitment: String,
    pub sponsor: String,
    pub funding_coin_id: String,
    pub max_resource_fee: Amount,
    pub max_state_bond: Amount,
    pub lease_end_height: u64,
    pub resource_subject_hash: String,
    pub authorization: SignedActionAuthorization,
}

/// Separately funded execution-only mutation of an already bonded resource.
///
/// There is deliberately no caller-supplied usage, state-bond amount, lease,
/// resource key, kind or owner. A future runtime must derive usage internally
/// and bind this envelope to one exact operation and bond-record predecessor.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StakeStateResourceMutationEnvelopeV1 {
    pub resource_policy_sequence: u64,
    pub resource_policy_commitment: String,
    pub sponsor: String,
    pub funding_coin_id: String,
    pub max_resource_fee: Amount,
    pub outer_operation_hash: String,
    pub expected_mutated_bond_record_hash: String,
    pub resource_subject_hash: String,
    pub authorization: SignedActionAuthorization,
}

/// Codec-only resource-bound unbond request. This type is intentionally not a
/// `ConsensusCommand` variant and has no ledger transition.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RequestConsensusStakeUnbondV2 {
    pub request_id: String,
    pub zone_id: String,
    pub currency_genesis_root: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub proposed_height: u64,
    pub expires_at_height: u64,
    pub expected_authority_sequence: u64,
    pub expected_authority_commitment: String,
    pub position_id: String,
    pub escrow_coin_id: String,
    pub owner: String,
    pub beneficiary: String,
    pub requested_withdraw_after_height: u64,
    pub expected_position_commitment: String,
    pub expected_liability_horizon_commitment: String,
    pub expected_position_resource_bond_record_hash: String,
    pub resource_envelope: StakeStateResourceEnvelopeV1,
    pub authorization: SignedActionAuthorization,
}

/// Codec-only resource-bound unbond completion. It cannot unlock stake until a
/// separately reviewed runtime transition is implemented and enabled.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompleteConsensusStakeUnbondV2 {
    pub completion_id: String,
    pub request_id: String,
    pub zone_id: String,
    pub currency_genesis_root: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub proposed_height: u64,
    pub expires_at_height: u64,
    pub expected_unbond_request_commitment: String,
    pub beneficiary: String,
    pub expected_unbond_resource_bond_record_hash: String,
    pub expected_position_resource_bond_record_hash: String,
    pub expected_liability_horizon_commitment: String,
    pub resource_mutation_envelope: StakeStateResourceMutationEnvelopeV1,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StakeStateResourceKindV1 {
    Candidate,
    Position,
    Epoch,
    Unbond,
    SlashEvidence,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StakeStateBondStatusV1 {
    Locked,
    Releaseable,
    Refunded,
    Forfeited,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StakeStateBondRecordV1 {
    pub bond_id: String,
    pub resource_key: String,
    pub resource_kind: StakeStateResourceKindV1,
    pub sponsor: String,
    pub funding_source_coin_id: String,
    pub bond_coin_id: String,
    pub locked_amount: Amount,
    pub charged_creation_fee: Amount,
    pub charged_wire_bytes: u32,
    pub charged_signature_checks: u32,
    pub charged_state_reads: u32,
    pub charged_state_writes: u32,
    pub created_height: u64,
    pub lease_end_height: u64,
    pub forfeit_after_height: u64,
    pub status: StakeStateBondStatusV1,
    pub terminal_record_commitment: String,
    pub record_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StakeStateMaintenancePoolV1 {
    pub pool_version: u16,
    pub resource_policy_sequence: u64,
    pub resource_policy_commitment: String,
    pub charged_fees: Amount,
    pub forfeited_bonds: Amount,
    pub live_bonds: Amount,
    pub refunded_bonds: Amount,
    pub active_bond_records: u64,
    pub terminal_bond_records: u64,
    pub previous_pool_commitment: String,
    pub runtime_payout_enabled: bool,
    pub pool_commitment: String,
}

/// Audit-complete successor to the codec-only V1 bond record.
///
/// V1 is retained byte-for-byte for candidate-history stability, but it did
/// not retain the policy, signed resource subject or persistent-byte charge
/// needed to re-derive an admission. Any future accounting implementation
/// must therefore use V2 and must not manufacture those facts from V1.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StakeStateBondRecordV2 {
    pub bond_id: String,
    pub resource_key: String,
    pub resource_kind: StakeStateResourceKindV1,
    pub resource_owner: String,
    pub resource_policy_sequence: u64,
    pub resource_policy_commitment: String,
    pub resource_subject_hash: String,
    pub sponsor: String,
    pub sponsor_authorization_id: String,
    pub funding_source_coin_id: String,
    pub bond_coin_id: String,
    pub locked_amount: Amount,
    pub charged_creation_fee: Amount,
    pub charged_wire_bytes: u32,
    pub charged_persistent_bytes: u64,
    pub charged_signature_checks: u32,
    pub charged_state_reads: u32,
    pub charged_state_writes: u32,
    pub created_height: u64,
    pub lease_end_height: u64,
    pub forfeit_after_height: u64,
    pub status: StakeStateBondStatusV1,
    pub terminal_record_commitment: String,
    pub previous_record_hash: String,
    pub record_hash: String,
}

/// Immutable, separately funded lease-extension tranche. The original bond
/// record is never rewritten: each tranche commits to the previous effective
/// history tip and adds only a fee, a reserved Coin and a later lease end.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StakeStateBondRenewalRecordV1 {
    pub renewal_id: String,
    pub resource_key: String,
    pub resource_kind: StakeStateResourceKindV1,
    pub resource_owner: String,
    pub original_bond_id: String,
    pub initial_bond_record_hash: String,
    pub previous_renewal_hash: String,
    pub previous_lease_end_height: u64,
    pub new_lease_end_height: u64,
    pub resource_policy_sequence: u64,
    pub resource_policy_commitment: String,
    pub sponsor: String,
    pub sponsor_authorization_id: String,
    pub funding_source_coin_id: String,
    pub bond_coin_id: String,
    pub additional_locked_amount: Amount,
    pub charged_renewal_fee: Amount,
    pub charged_wire_bytes: u32,
    pub charged_persistent_bytes: u64,
    pub charged_signature_checks: u32,
    pub charged_state_reads: u32,
    pub charged_state_writes: u32,
    pub renewed_height: u64,
    pub forfeit_after_height: u64,
    pub record_hash: String,
}

/// Per-policy conservation bucket. Several policy generations can have live
/// bonds simultaneously, so a single current-policy label is insufficient.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StakeStateMaintenancePoolPolicyBucketV2 {
    pub resource_policy_sequence: u64,
    pub resource_policy_commitment: String,
    pub charged_fees: Amount,
    pub forfeited_bonds: Amount,
    pub live_bonds: Amount,
    pub refunded_bonds: Amount,
    pub active_bond_records: u64,
    pub terminal_bond_records: u64,
    pub bucket_commitment: String,
}

/// Multi-policy maintenance pool. The policy buckets are ordered strictly by
/// sequence by the accounting validator; the wire codec preserves that order.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StakeStateMaintenancePoolV2 {
    pub pool_version: u16,
    pub policy_buckets: Vec<StakeStateMaintenancePoolPolicyBucketV2>,
    pub total_charged_fees: Amount,
    pub total_forfeited_bonds: Amount,
    pub total_live_bonds: Amount,
    pub total_refunded_bonds: Amount,
    pub active_bond_records: u64,
    pub terminal_bond_records: u64,
    pub previous_pool_commitment: String,
    pub runtime_payout_enabled: bool,
    pub pool_commitment: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProposeStakeStateResourcePolicyV1 {
    pub proposal_id: String,
    pub network_domain: String,
    pub zone_id: String,
    pub currency_genesis_root: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub proposed_height: u64,
    pub activate_after_height: u64,
    pub expires_at_height: u64,
    pub expected_current_policy_sequence: u64,
    pub expected_current_policy_commitment: String,
    pub proposed_policy: StakeStateResourcePolicyV1,
    pub proposed_policy_commitment: String,
    pub subject_hash: String,
    pub validator_qc: QuorumCertificate,
    pub notary_qc: QuorumCertificate,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActivateStakeStateResourcePolicyV1 {
    pub activation_id: String,
    pub network_domain: String,
    pub zone_id: String,
    pub currency_genesis_root: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub proposed_height: u64,
    pub expires_at_height: u64,
    pub proposal_id: String,
    pub expected_pending_policy_commitment: String,
    pub expected_current_policy_sequence: u64,
    pub expected_current_policy_commitment: String,
    pub subject_hash: String,
    pub validator_qc: QuorumCertificate,
    pub notary_qc: QuorumCertificate,
}

pub trait StakeResourceCandidatePayload: Serialize {
    fn wire_v1_candidate_payload_bytes(&self) -> Result<Vec<u8>, WireError> {
        encode_codec_only_candidate_payload(self)
    }
}

impl StakeResourceCandidatePayload for StakeStateResourcePolicyV1 {}
impl StakeResourceCandidatePayload for StakeStateResourceEnvelopeV1 {}
impl StakeResourceCandidatePayload for StakeStateResourceMutationEnvelopeV1 {}
impl StakeResourceCandidatePayload for StakeStateBondRecordV1 {}
impl StakeResourceCandidatePayload for StakeStateMaintenancePoolV1 {}
impl StakeResourceCandidatePayload for StakeStateBondRecordV2 {}
impl StakeResourceCandidatePayload for StakeStateBondRenewalRecordV1 {}
impl StakeResourceCandidatePayload for StakeStateMaintenancePoolPolicyBucketV2 {}
impl StakeResourceCandidatePayload for StakeStateMaintenancePoolV2 {}
impl StakeResourceCandidatePayload for ProposeStakeStateResourcePolicyV1 {}
impl StakeResourceCandidatePayload for ActivateStakeStateResourcePolicyV1 {}
impl StakeResourceCandidatePayload for RequestConsensusStakeUnbondV2 {}
impl StakeResourceCandidatePayload for CompleteConsensusStakeUnbondV2 {}
impl StakeResourceCandidatePayload for StakePositionLiabilityHorizonV1 {}

impl ProposeStakeStateResourcePolicyV1 {
    pub fn compute_subject_hash(&self) -> String {
        action_payload_hash(
            PROPOSE_STAKE_STATE_RESOURCE_POLICY_ACTION_V1,
            &[
                self.proposal_id.as_bytes(),
                self.network_domain.as_bytes(),
                self.zone_id.as_bytes(),
                self.currency_genesis_root.as_bytes(),
                &self.protocol_era.to_be_bytes(),
                &self.crypto_era.to_be_bytes(),
                &self.proposed_height.to_be_bytes(),
                &self.activate_after_height.to_be_bytes(),
                &self.expires_at_height.to_be_bytes(),
                &self.expected_current_policy_sequence.to_be_bytes(),
                self.expected_current_policy_commitment.as_bytes(),
                self.proposed_policy_commitment.as_bytes(),
            ],
        )
    }

    pub fn wire_v1_candidate_command_bytes(&self) -> Result<Vec<u8>, WireError> {
        encode_candidate_command(
            &self.network_domain,
            PROPOSE_STAKE_STATE_RESOURCE_POLICY_CANDIDATE_TAG_V1,
            &self.wire_v1_candidate_payload_bytes()?,
        )
    }

    pub fn wire_v1_candidate_command_hash(&self) -> Result<String, WireError> {
        let bytes = self.wire_v1_candidate_command_bytes()?;
        Ok(digest_hex(WireSchema::CommandCommitment, &bytes))
    }
}

impl ActivateStakeStateResourcePolicyV1 {
    pub fn compute_subject_hash(&self) -> String {
        action_payload_hash(
            ACTIVATE_STAKE_STATE_RESOURCE_POLICY_ACTION_V1,
            &[
                self.activation_id.as_bytes(),
                self.network_domain.as_bytes(),
                self.zone_id.as_bytes(),
                self.currency_genesis_root.as_bytes(),
                &self.protocol_era.to_be_bytes(),
                &self.crypto_era.to_be_bytes(),
                &self.proposed_height.to_be_bytes(),
                &self.expires_at_height.to_be_bytes(),
                self.proposal_id.as_bytes(),
                self.expected_pending_policy_commitment.as_bytes(),
                &self.expected_current_policy_sequence.to_be_bytes(),
                self.expected_current_policy_commitment.as_bytes(),
            ],
        )
    }

    pub fn wire_v1_candidate_command_bytes(&self) -> Result<Vec<u8>, WireError> {
        encode_candidate_command(
            &self.network_domain,
            ACTIVATE_STAKE_STATE_RESOURCE_POLICY_CANDIDATE_TAG_V1,
            &self.wire_v1_candidate_payload_bytes()?,
        )
    }

    pub fn wire_v1_candidate_command_hash(&self) -> Result<String, WireError> {
        let bytes = self.wire_v1_candidate_command_bytes()?;
        Ok(digest_hex(WireSchema::CommandCommitment, &bytes))
    }
}

impl RequestConsensusStakeUnbondV2 {
    pub fn wire_v1_candidate_command_bytes(
        &self,
        network_domain: &str,
    ) -> Result<Vec<u8>, WireError> {
        encode_candidate_command(
            network_domain,
            REQUEST_CONSENSUS_STAKE_UNBOND_CANDIDATE_TAG_V2,
            &self.wire_v1_candidate_payload_bytes()?,
        )
    }

    pub fn wire_v1_candidate_command_hash(
        &self,
        network_domain: &str,
    ) -> Result<String, WireError> {
        let bytes = self.wire_v1_candidate_command_bytes(network_domain)?;
        Ok(digest_hex(WireSchema::CommandCommitment, &bytes))
    }
}

impl CompleteConsensusStakeUnbondV2 {
    pub fn wire_v1_candidate_command_bytes(
        &self,
        network_domain: &str,
    ) -> Result<Vec<u8>, WireError> {
        encode_candidate_command(
            network_domain,
            COMPLETE_CONSENSUS_STAKE_UNBOND_CANDIDATE_TAG_V2,
            &self.wire_v1_candidate_payload_bytes()?,
        )
    }

    pub fn wire_v1_candidate_command_hash(
        &self,
        network_domain: &str,
    ) -> Result<String, WireError> {
        let bytes = self.wire_v1_candidate_command_bytes(network_domain)?;
        Ok(digest_hex(WireSchema::CommandCommitment, &bytes))
    }
}

fn encode_candidate_command(
    network_domain: &str,
    consensus_tag: u16,
    payload: &[u8],
) -> Result<Vec<u8>, WireError> {
    if !matches!(
        consensus_tag,
        PROPOSE_STAKE_STATE_RESOURCE_POLICY_CANDIDATE_TAG_V1
            | ACTIVATE_STAKE_STATE_RESOURCE_POLICY_CANDIDATE_TAG_V1
            | REQUEST_CONSENSUS_STAKE_UNBOND_CANDIDATE_TAG_V2
            | COMPLETE_CONSENSUS_STAKE_UNBOND_CANDIDATE_TAG_V2
    ) {
        return Err(WireError::new(
            "unknown_candidate_command_tag",
            "stake-resource candidate reserves only tags 18, 19, 26 and 27",
        ));
    }
    if !matches!(
        network_domain,
        RLDCOIN_MAINNET_DOMAIN | RLDCOIN_TESTNET_DOMAIN
    ) || network_domain.len() > 64
        || !network_domain.nfc().eq(network_domain.chars())
        || network_domain
            .chars()
            .any(|character| matches!(character as u32, 0x00..=0x1f | 0x7f..=0x9f))
    {
        return Err(WireError::new(
            "invalid_network_domain",
            "candidate command network domain is not canonical",
        ));
    }
    if payload.is_empty() || payload.len() > PAYLOAD_LIMIT {
        return Err(WireError::new(
            "invalid_command_payload",
            "candidate command payload must be nonempty and at most 1 MiB",
        ));
    }

    let mut wire = Vec::new();
    wire.extend_from_slice(COMMAND_MAGIC);
    wire.extend_from_slice(&COMMAND_VERSION.to_be_bytes());
    wire.extend_from_slice(&COMMAND_COMMITMENT_SCHEMA.to_be_bytes());
    wire.extend_from_slice(&3u16.to_be_bytes());
    push_outer_field(&mut wire, 1, OUTER_TEXT, network_domain.as_bytes())?;
    push_outer_field(&mut wire, 2, OUTER_U16, &consensus_tag.to_be_bytes())?;
    push_outer_field(&mut wire, 4, OUTER_BYTES, payload)?;
    Ok(wire)
}

fn push_outer_field(
    output: &mut Vec<u8>,
    field_id: u16,
    kind: u8,
    value: &[u8],
) -> Result<(), WireError> {
    let length = u32::try_from(value.len())
        .map_err(|_| WireError::new("field_too_long", "candidate field exceeds u32"))?;
    output.extend_from_slice(&field_id.to_be_bytes());
    output.push(kind);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        wire::{decode_wire, encode_command_commitment},
        ConsensusCommand,
    };
    use serde_json::Value;

    const VECTORS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/wire-v1/stake-state-resource-v1.json"
    ));

    #[test]
    fn rust_matches_every_frozen_r615_candidate_accept_vector() {
        let bundle: Value = serde_json::from_str(VECTORS).unwrap();
        let metadata = &bundle["payload"];
        for claim in [
            "runtime_adoption_claim",
            "ledger_execution_claim",
            "node_route_claim",
            "dynamic_membership_claim",
            "mainnet_value_claim",
            "resource_economics_claim",
            "legacy_tags_8_17_modified",
        ] {
            assert_eq!(metadata[claim], false, "{claim} must remain false");
        }

        let mut accepted = 0usize;
        for case in metadata["cases"].as_array().unwrap() {
            if case["expected"] != "accept" {
                continue;
            }
            accepted += 1;
            let source = case["source"].clone();
            let payload = match case["schema"].as_str().unwrap() {
                "StakeStateResourcePolicyV1" => {
                    serde_json::from_value::<StakeStateResourcePolicyV1>(source)
                        .unwrap()
                        .wire_v1_candidate_payload_bytes()
                        .unwrap()
                }
                "StakeStateResourceEnvelopeV1" => {
                    serde_json::from_value::<StakeStateResourceEnvelopeV1>(source)
                        .unwrap()
                        .wire_v1_candidate_payload_bytes()
                        .unwrap()
                }
                "StakeStateBondRecordV1" => {
                    serde_json::from_value::<StakeStateBondRecordV1>(source)
                        .unwrap()
                        .wire_v1_candidate_payload_bytes()
                        .unwrap()
                }
                "StakeStateMaintenancePoolV1" => {
                    serde_json::from_value::<StakeStateMaintenancePoolV1>(source)
                        .unwrap()
                        .wire_v1_candidate_payload_bytes()
                        .unwrap()
                }
                "StakeStateBondRecordV2" => {
                    serde_json::from_value::<StakeStateBondRecordV2>(source)
                        .unwrap()
                        .wire_v1_candidate_payload_bytes()
                        .unwrap()
                }
                "StakeStateMaintenancePoolPolicyBucketV2" => {
                    serde_json::from_value::<StakeStateMaintenancePoolPolicyBucketV2>(source)
                        .unwrap()
                        .wire_v1_candidate_payload_bytes()
                        .unwrap()
                }
                "StakeStateMaintenancePoolV2" => {
                    serde_json::from_value::<StakeStateMaintenancePoolV2>(source)
                        .unwrap()
                        .wire_v1_candidate_payload_bytes()
                        .unwrap()
                }
                "ProposeStakeStateResourcePolicyV1" => {
                    let value = serde_json::from_value::<ProposeStakeStateResourcePolicyV1>(source)
                        .unwrap();
                    let payload = value.wire_v1_candidate_payload_bytes().unwrap();
                    assert_eq!(
                        hex::encode(value.wire_v1_candidate_command_bytes().unwrap()),
                        case["canonical_command_wire_hex"].as_str().unwrap()
                    );
                    assert_eq!(
                        value.wire_v1_candidate_command_hash().unwrap(),
                        case["command_hash"].as_str().unwrap()
                    );
                    payload
                }
                "ActivateStakeStateResourcePolicyV1" => {
                    let value =
                        serde_json::from_value::<ActivateStakeStateResourcePolicyV1>(source)
                            .unwrap();
                    let payload = value.wire_v1_candidate_payload_bytes().unwrap();
                    assert_eq!(
                        hex::encode(value.wire_v1_candidate_command_bytes().unwrap()),
                        case["canonical_command_wire_hex"].as_str().unwrap()
                    );
                    assert_eq!(
                        value.wire_v1_candidate_command_hash().unwrap(),
                        case["command_hash"].as_str().unwrap()
                    );
                    payload
                }
                "StakeStateResourceMutationEnvelopeV1" => {
                    serde_json::from_value::<StakeStateResourceMutationEnvelopeV1>(source)
                        .unwrap()
                        .wire_v1_candidate_payload_bytes()
                        .unwrap()
                }
                "StakePositionLiabilityHorizonV1" => {
                    serde_json::from_value::<StakePositionLiabilityHorizonV1>(source)
                        .unwrap()
                        .wire_v1_candidate_payload_bytes()
                        .unwrap()
                }
                "RequestConsensusStakeUnbondV2" => {
                    let value =
                        serde_json::from_value::<RequestConsensusStakeUnbondV2>(source).unwrap();
                    let payload = value.wire_v1_candidate_payload_bytes().unwrap();
                    let network = case["command_network_domain"].as_str().unwrap();
                    assert_eq!(
                        hex::encode(value.wire_v1_candidate_command_bytes(network).unwrap()),
                        case["canonical_command_wire_hex"].as_str().unwrap()
                    );
                    assert_eq!(
                        value.wire_v1_candidate_command_hash(network).unwrap(),
                        case["command_hash"].as_str().unwrap()
                    );
                    payload
                }
                "CompleteConsensusStakeUnbondV2" => {
                    let value =
                        serde_json::from_value::<CompleteConsensusStakeUnbondV2>(source).unwrap();
                    let payload = value.wire_v1_candidate_payload_bytes().unwrap();
                    let network = case["command_network_domain"].as_str().unwrap();
                    assert_eq!(
                        hex::encode(value.wire_v1_candidate_command_bytes(network).unwrap()),
                        case["canonical_command_wire_hex"].as_str().unwrap()
                    );
                    assert_eq!(
                        value.wire_v1_candidate_command_hash(network).unwrap(),
                        case["command_hash"].as_str().unwrap()
                    );
                    payload
                }
                schema => panic!("unhandled candidate schema {schema}"),
            };
            assert_eq!(
                hex::encode(payload),
                case["canonical_payload_hex"].as_str().unwrap(),
                "{}",
                case["name"]
            );
        }
        assert_eq!(accepted, 13);
    }

    #[test]
    fn resource_policy_candidate_position_and_epoch_tags_are_the_append_only_runtime_tail() {
        let commands: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/wire-v1/commands.json"
        )))
        .unwrap();
        let maximum_runtime_tag = commands["payload"]["cases"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|case| case["expected"] == "accept")
            .filter_map(|case| case["source"]["consensus_tag"].as_str())
            .map(|tag| tag.parse::<u16>().unwrap())
            .max()
            .unwrap();
        assert_eq!(maximum_runtime_tag, 25);
        assert_eq!(PROPOSE_STAKE_STATE_RESOURCE_POLICY_CANDIDATE_TAG_V1, 18);
        assert_eq!(ACTIVATE_STAKE_STATE_RESOURCE_POLICY_CANDIDATE_TAG_V1, 19);
        assert_eq!(REQUEST_CONSENSUS_STAKE_UNBOND_CANDIDATE_TAG_V2, 26);
        assert_eq!(COMPLETE_CONSENSUS_STAKE_UNBOND_CANDIDATE_TAG_V2, 27);
    }

    #[test]
    fn adopted_runtime_policy_commands_match_the_frozen_candidate_bytes() {
        let bundle: Value = serde_json::from_str(VECTORS).unwrap();
        for case in bundle["payload"]["cases"].as_array().unwrap() {
            let Some(tag) = case["reserved_consensus_tag"].as_u64() else {
                continue;
            };
            if tag > 25 {
                continue;
            }
            let wire = hex::decode(case["canonical_command_wire_hex"].as_str().unwrap()).unwrap();
            decode_wire(WireSchema::CommandCommitment, &wire).unwrap();
            let encoded = encode_command_commitment(
                case["source"]["network_domain"].as_str().unwrap(),
                u16::try_from(tag).unwrap(),
                None,
                &hex::decode(case["canonical_payload_hex"].as_str().unwrap()).unwrap(),
            )
            .unwrap();
            assert_eq!(encoded, wire);
            let source = case["source"].clone();
            let command = match tag {
                18 => ConsensusCommand::ProposeStakeStateResourcePolicy(Box::new(
                    serde_json::from_value(source).unwrap(),
                )),
                19 => ConsensusCommand::ActivateStakeStateResourcePolicy(Box::new(
                    serde_json::from_value(source).unwrap(),
                )),
                _ => unreachable!(),
            };
            assert_eq!(
                command
                    .wire_v1_command_bytes(RLDCOIN_MAINNET_DOMAIN)
                    .unwrap(),
                wire
            );
        }
    }

    #[test]
    fn codec_only_unbond_tags_remain_rejected_by_runtime_command_envelope() {
        let bundle: Value = serde_json::from_str(VECTORS).unwrap();
        for case in bundle["payload"]["cases"].as_array().unwrap() {
            let Some(tag) = case["reserved_consensus_tag"].as_u64() else {
                continue;
            };
            if !matches!(tag, 26 | 27) {
                continue;
            }
            let wire = hex::decode(case["canonical_command_wire_hex"].as_str().unwrap()).unwrap();
            let error = decode_wire(WireSchema::CommandCommitment, &wire).unwrap_err();
            assert_eq!(error.code, "unknown_command_tag");
        }
    }

    #[test]
    fn codec_only_unbond_types_reject_caller_usage_and_mutation_rewrites() {
        let bundle: Value = serde_json::from_str(VECTORS).unwrap();
        let mut checked = 0usize;
        for case in bundle["payload"]["cases"].as_array().unwrap() {
            if case["expected"] != "reject" || case["mode"] != "source" {
                continue;
            }
            let source = case["source"].clone();
            let rejected = match case["schema"].as_str().unwrap() {
                "RequestConsensusStakeUnbondV2" => {
                    serde_json::from_value::<RequestConsensusStakeUnbondV2>(source).is_err()
                }
                "CompleteConsensusStakeUnbondV2" => {
                    serde_json::from_value::<CompleteConsensusStakeUnbondV2>(source).is_err()
                }
                "StakeStateResourceMutationEnvelopeV1" => {
                    serde_json::from_value::<StakeStateResourceMutationEnvelopeV1>(source).is_err()
                }
                _ => continue,
            };
            checked += 1;
            assert!(rejected, "{} must fail closed", case["name"]);
        }
        assert_eq!(checked, 9);
    }

    #[test]
    fn codec_only_candidate_rejects_oversized_payload() {
        let error = encode_candidate_command(
            RLDCOIN_MAINNET_DOMAIN,
            REQUEST_CONSENSUS_STAKE_UNBOND_CANDIDATE_TAG_V2,
            &vec![0; PAYLOAD_LIMIT + 1],
        )
        .unwrap_err();
        assert_eq!(error.code, "invalid_command_payload");
    }
}
