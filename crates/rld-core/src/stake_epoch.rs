//! Pure, runtime-disabled derivation of a candidate weighted consensus epoch.
//!
//! This module deliberately has no `Ledger`, runtime, adoption, or value-cap
//! mutation entry point. Its only operation validates an already-finalized,
//! coin-backed stake view and returns a `DERIVED_ONLY` record.

use std::collections::{BTreeMap, BTreeSet};

use serde::{de, Deserialize, Deserializer, Serialize};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

use crate::{
    consensus_epoch::{
        consensus_epoch_descriptor_commitment_v1, quorum_power_v1, ConsensusEpochDescriptor,
        ConsensusQuorumRule, ValidatorRecord, MAX_VALIDATORS_PER_EPOCH,
    },
    crypto::{hash_parts, validate_ed25519_public_key, verify_bytes},
    types::{
        CoinObject, CoinState, SignedActionAuthorization, RLDCOIN_MAINNET_DOMAIN,
        RLDCOIN_TESTNET_DOMAIN,
    },
    Amount,
};

pub const STAKE_EPOCH_DERIVATION_VERSION_V1: u16 = 1;
pub const STAKE_EPOCH_DERIVATION_VERSION_V2: u16 = 2;
pub const STAKE_POSITION_LIABILITY_HORIZON_VERSION_V1: u16 = 1;
pub const STAKE_AUTHORITY_STATE_VERSION_V1: u16 = 1;
pub const CONSENSUS_STAKE_SLASH_TERMS_VERSION_V2: u16 = 2;
pub const ACCEPT_CONSENSUS_STAKE_SLASH_TERMS_ACTION_V2: &str =
    "ACCEPT_CONSENSUS_STAKE_SLASH_TERMS_V2";
pub const CONSENSUS_SLASH_SAFETY_POOL_V2: &str = "RLD_CONSENSUS_SLASH_SAFETY_POOL_V2";
pub const CONSENSUS_PROTOCOL_VERSION_V1: u64 = 1;
pub const MIN_TESTNET_STAKE_VALIDATORS: usize = 4;
pub const MIN_MAINNET_STAKE_VALIDATORS: usize = 21;
pub const MAX_STAKE_CANDIDATE_RECORDS: usize = 16_384;
pub const MAX_STAKE_POSITION_RECORDS: usize = 262_144;
pub const MAX_UBO_CONTROL_RECORDS: usize = 16_384;
pub const MAX_STAKE_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_STAKE_ESCROW_PARENTS: usize = 16;

const SNAPSHOT_MAGIC: &[u8; 4] = b"RLDS";
const SNAPSHOT_SCHEMA_VERSION_V1: u16 = 1;
const SNAPSHOT_SCHEMA: u16 = 0x0001;
const SNAPSHOT_CONTEXT_SCHEMA: u16 = 0x0002;
const SNAPSHOT_POLICY_SCHEMA: u16 = 0x0003;
const SNAPSHOT_ANCHOR_SCHEMA: u16 = 0x0004;
const SNAPSHOT_CANDIDATE_SCHEMA: u16 = 0x0005;
const SNAPSHOT_POSITION_SCHEMA: u16 = 0x0006;
const SNAPSHOT_UBO_MAP_SCHEMA: u16 = 0x0007;
const SNAPSHOT_UBO_RECORD_SCHEMA: u16 = 0x0008;
const SNAPSHOT_COIN_SCHEMA: u16 = 0x0009;
const SNAPSHOT_AUTHORITY_STATE_SCHEMA: u16 = 0x000a;
const SNAPSHOT_POSITION_V2_SCHEMA: u16 = 0x000b;
const SNAPSHOT_SLASH_POLICY_V2_SCHEMA: u16 = 0x000c;
const SNAPSHOT_SLASH_TERMS_V2_SCHEMA: u16 = 0x000d;

const SNAPSHOT_KIND_TEXT: u8 = 0x01;
const SNAPSHOT_KIND_U16: u8 = 0x03;
const SNAPSHOT_KIND_U64: u8 = 0x04;
const SNAPSHOT_KIND_U128: u8 = 0x05;
const SNAPSHOT_KIND_HASH32: u8 = 0x06;
const SNAPSHOT_KIND_KEY32: u8 = 0x07;
const SNAPSHOT_KIND_SIGNATURE64: u8 = 0x08;
const SNAPSHOT_KIND_AMOUNT: u8 = 0x09;
const SNAPSHOT_KIND_OPTION_U128: u8 = 0x0a;
const SNAPSHOT_KIND_OPTION_TEXT: u8 = 0x0b;
const SNAPSHOT_KIND_STRUCT: u8 = 0x0c;
const SNAPSHOT_KIND_STRUCT_LIST: u8 = 0x0d;
const SNAPSHOT_KIND_TEXT_LIST: u8 = 0x0e;
const SNAPSHOT_KIND_ENUM_U8: u8 = 0x0f;

const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_OWNER_BYTES: usize = 256;
const MAX_CONTROL_GROUP_BYTES: usize = 128;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StakeLedgerContextV1 {
    pub network_domain: String,
    pub zone_id: String,
    pub currency_genesis_root: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub consensus_protocol_version: u64,
    pub finalized_height: u128,
    pub finalized_state_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsensusStakePolicyV1 {
    pub policy_version: u16,
    pub minimum_self_bond: Amount,
    pub minimum_delegation: Amount,
    pub candidate_maturity_blocks: u128,
    pub stake_maturity_blocks: u128,
    pub evidence_window_blocks: u128,
    pub activation_delay_blocks: u128,
    pub epoch_length_blocks: u128,
    pub maximum_validators: u16,
}

/// Protocol-fixed objective-fault penalties for policy/derivation version 2.
/// Version 2 deliberately has no downtime or subjective-performance slash:
/// only cryptographically contradictory safety statements are in scope.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsensusStakeSlashPolicyV2 {
    pub policy_version: u16,
    pub double_sign_slash_bps: u16,
    pub conflicting_checkpoint_slash_bps: u16,
    pub invalid_state_commitment_slash_bps: u16,
    pub maximum_cumulative_slash_bps: u16,
    pub reporter_reward_bps: u16,
    pub safety_pool: String,
}

impl ConsensusStakeSlashPolicyV2 {
    pub fn protocol_v2() -> Self {
        Self {
            policy_version: CONSENSUS_STAKE_SLASH_TERMS_VERSION_V2,
            double_sign_slash_bps: 10_000,
            conflicting_checkpoint_slash_bps: 10_000,
            invalid_state_commitment_slash_bps: 10_000,
            maximum_cumulative_slash_bps: 10_000,
            reporter_reward_bps: 0,
            safety_pool: CONSENSUS_SLASH_SAFETY_POOL_V2.into(),
        }
    }

    pub fn commitment(&self) -> String {
        hash_parts(&[
            b"RLD-CONSENSUS-STAKE-SLASH-POLICY-V2",
            &self.policy_version.to_be_bytes(),
            &self.double_sign_slash_bps.to_be_bytes(),
            &self.conflicting_checkpoint_slash_bps.to_be_bytes(),
            &self.invalid_state_commitment_slash_bps.to_be_bytes(),
            &self.maximum_cumulative_slash_bps.to_be_bytes(),
            &self.reporter_reward_bps.to_be_bytes(),
            self.safety_pool.as_bytes(),
        ])
    }

    fn validate(&self) -> Result<(), &'static str> {
        if self != &Self::protocol_v2() {
            return Err("slash policy does not equal the protocol-fixed v2 policy");
        }
        Ok(())
    }
}

/// Durable proof that the Coin owner explicitly accepted the protocol-fixed
/// objective-fault slash policy for one exact position. The authorization is
/// retained so a historical liability can reverify consent without consulting
/// current policy or a mutable authorization table.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsensusStakeSlashTermsV2 {
    pub terms_version: u16,
    pub slash_policy: ConsensusStakeSlashPolicyV2,
    pub owner_authorization: SignedActionAuthorization,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsensusEpochAnchor {
    pub consensus_epoch: u64,
    pub activation_height: u128,
    pub stake_snapshot_height: u128,
    pub stake_snapshot_state_root: String,
    /// Non-zero external/genesis anchor for the first derived epoch, and the
    /// exact previous derived-record hash for every later epoch.
    pub record_chain_anchor: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ValidatorCandidateRecord {
    pub validator_id: String,
    pub owner: String,
    pub public_key: String,
    pub key_era: u64,
    pub registered_height: u128,
    /// Exclusive candidate exit. `None` means no exit is scheduled.
    pub exit_height: Option<u128>,
    pub proof_of_possession: String,
}

impl ValidatorCandidateRecord {
    /// Commits every immutable candidate field so a bounded pre-policy
    /// inventory can enter resource accounting without substituting an owner,
    /// consensus key, key era, lifetime or proof of possession.
    pub fn resource_commitment_v1(&self) -> String {
        hash_parts(&[
            b"RLD-CONSENSUS-CANDIDATE-RESOURCE-COMMITMENT-V1",
            self.validator_id.as_bytes(),
            self.owner.as_bytes(),
            self.public_key.as_bytes(),
            &self.key_era.to_be_bytes(),
            &self.registered_height.to_be_bytes(),
            &self.exit_height.unwrap_or_default().to_be_bytes(),
            &[u8::from(self.exit_height.is_some())],
            self.proof_of_possession.as_bytes(),
        ])
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ConsensusStakePositionKind {
    SelfBond { validator_id: String },
    Delegation { validator_id: String },
}

impl ConsensusStakePositionKind {
    fn validator_id(&self) -> &str {
        match self {
            Self::SelfBond { validator_id } | Self::Delegation { validator_id } => validator_id,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsensusStakePosition {
    pub position_id: String,
    pub kind: ConsensusStakePositionKind,
    pub owner: String,
    pub source_coin_id: String,
    pub escrow_coin_id: String,
    pub amount: Amount,
    pub locked_height: u128,
    pub committed_through_height: u128,
    /// `None` is a legacy V1 position. Legacy positions remain withdrawable
    /// but cannot contribute weight to a derivation-version-2 Epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slash_terms: Option<ConsensusStakeSlashTermsV2>,
}

impl ConsensusStakePosition {
    pub fn validator_id(&self) -> &str {
        self.kind.validator_id()
    }

    pub fn slash_terms_payload_hash_v2(&self) -> String {
        consensus_stake_slash_terms_payload_hash_v2(
            &self.position_id,
            &self.kind,
            &self.owner,
            &self.source_coin_id,
            self.amount,
            self.committed_through_height,
            &ConsensusStakeSlashPolicyV2::protocol_v2(),
        )
    }

    pub fn slash_terms_commitment_v2(&self) -> Option<String> {
        self.slash_terms.as_ref().map(|terms| {
            hash_parts(&[
                b"RLD-CONSENSUS-STAKE-SLASH-TERMS-COMMITMENT-V2",
                self.position_id.as_bytes(),
                self.kind.validator_id().as_bytes(),
                self.owner.as_bytes(),
                self.source_coin_id.as_bytes(),
                self.escrow_coin_id.as_bytes(),
                &self.amount.0.to_be_bytes(),
                &self.locked_height.to_be_bytes(),
                &self.committed_through_height.to_be_bytes(),
                terms.slash_policy.commitment().as_bytes(),
                &terms.owner_authorization.signing_bytes(),
                terms.owner_authorization.signature.as_bytes(),
            ])
        })
    }

    /// Commits every immutable position and slash-liability field needed to
    /// migrate a pre-policy position into resource accounting without allowing
    /// the migration command to substitute principal, owner, target or term.
    pub fn resource_commitment_v1(&self) -> String {
        let kind = match &self.kind {
            ConsensusStakePositionKind::SelfBond { .. } => "SELF_BOND",
            ConsensusStakePositionKind::Delegation { .. } => "DELEGATION",
        };
        hash_parts(&[
            b"RLD-CONSENSUS-STAKE-RESOURCE-POSITION-COMMITMENT-V1",
            self.position_id.as_bytes(),
            kind.as_bytes(),
            self.validator_id().as_bytes(),
            self.owner.as_bytes(),
            self.source_coin_id.as_bytes(),
            self.escrow_coin_id.as_bytes(),
            &self.amount.0.to_be_bytes(),
            &self.locked_height.to_be_bytes(),
            &self.committed_through_height.to_be_bytes(),
            self.slash_terms_commitment_v2()
                .unwrap_or_else(|| "00".repeat(32))
                .as_bytes(),
        ])
    }
}

pub fn consensus_stake_slash_terms_payload_hash_v2(
    position_id: &str,
    kind: &ConsensusStakePositionKind,
    owner: &str,
    source_coin_id: &str,
    amount: Amount,
    committed_through_height: u128,
    policy: &ConsensusStakeSlashPolicyV2,
) -> String {
    hash_parts(&[
        b"RLD-CONSENSUS-STAKE-SLASH-TERMS-PAYLOAD-V2",
        position_id.as_bytes(),
        match kind {
            ConsensusStakePositionKind::SelfBond { .. } => b"SELF_BOND".as_slice(),
            ConsensusStakePositionKind::Delegation { .. } => b"DELEGATION".as_slice(),
        },
        kind.validator_id().as_bytes(),
        owner.as_bytes(),
        source_coin_id.as_bytes(),
        &amount.0.to_be_bytes(),
        &committed_through_height.to_be_bytes(),
        policy.commitment().as_bytes(),
    ])
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UboControlRecord {
    pub control_group: String,
    pub valid_from_height: u128,
    /// Exclusive end of the public challenge period. A record is ineligible
    /// until a later finalized height observes this boundary.
    pub challenge_ends_height: u128,
    pub valid_through_height: u128,
    pub evidence_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UboControlMap {
    pub map_version: u16,
    pub sequence: u64,
    pub predecessor_commitment: String,
    pub verifier_set_commitment: String,
    pub evidence_root: String,
    /// Keyed by validator id.
    pub validators: BTreeMap<String, UboControlRecord>,
}

/// A complete, bounded replacement view proposed for ledger ownership. This
/// type is deliberately not a runtime command: authorization and durable
/// command wiring must be added before external callers can mutate it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LedgerStakeAuthorityUpdateV1 {
    pub authority_version: u16,
    pub sequence: u64,
    pub expected_previous_commitment: String,
    pub policy: ConsensusStakePolicyV1,
    pub candidates: Vec<ValidatorCandidateRecord>,
    pub positions: Vec<ConsensusStakePosition>,
    pub ubo_control: UboControlMap,
}

/// Canonical stake-authority data owned by a ledger snapshot. `STAGED_ONLY`
/// means the state can be audited and used to derive a candidate Epoch record,
/// but can never replace the runtime validator set.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct LedgerStakeAuthorityStateV1 {
    pub authority_version: u16,
    pub status: StakeAuthorityStateStatus,
    pub network_domain: String,
    pub zone_id: String,
    pub currency_genesis_root: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub consensus_protocol_version: u64,
    pub sequence: u64,
    pub previous_commitment: String,
    pub source_height: u128,
    pub source_state_root: String,
    pub effective_height: u128,
    pub policy: ConsensusStakePolicyV1,
    pub candidates: Vec<ValidatorCandidateRecord>,
    pub positions: Vec<ConsensusStakePosition>,
    pub ubo_control: UboControlMap,
    pub commitment: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLedgerStakeAuthorityStateV1 {
    authority_version: u16,
    status: StakeAuthorityStateStatus,
    network_domain: String,
    zone_id: String,
    currency_genesis_root: String,
    protocol_era: u64,
    crypto_era: u64,
    consensus_protocol_version: u64,
    sequence: u64,
    previous_commitment: String,
    source_height: u128,
    source_state_root: String,
    effective_height: u128,
    policy: ConsensusStakePolicyV1,
    candidates: Vec<ValidatorCandidateRecord>,
    positions: Vec<ConsensusStakePosition>,
    ubo_control: UboControlMap,
    commitment: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StakeAuthorityStateStatus {
    StagedOnly,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StakeEpochRecordStatus {
    DerivedOnly,
}

impl StakeEpochRecordStatus {
    fn wire_name(self) -> &'static str {
        match self {
            Self::DerivedOnly => "DERIVED_ONLY",
        }
    }
}

/// Output of the pure derivation kernel. The status intentionally has no
/// activated/adopted alternative.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsensusStakeEpochLiabilityV2 {
    pub consensus_epoch: u64,
    pub position: ConsensusStakePosition,
    pub validator_public_key: String,
    pub validator_key_era: u64,
    pub activation_height: u128,
    pub exit_height: u128,
    pub evidence_window_blocks: u128,
    pub evidence_deadline_height: u128,
    pub slash_terms_commitment: String,
    pub liability_commitment: String,
}

impl ConsensusStakeEpochLiabilityV2 {
    fn compute_commitment(&self) -> String {
        hash_parts(&[
            b"RLD-CONSENSUS-STAKE-EPOCH-LIABILITY-V2",
            &self.consensus_epoch.to_be_bytes(),
            self.position.position_id.as_bytes(),
            self.position.kind.validator_id().as_bytes(),
            self.position.owner.as_bytes(),
            self.position.source_coin_id.as_bytes(),
            self.position.escrow_coin_id.as_bytes(),
            &self.position.amount.0.to_be_bytes(),
            &self.position.locked_height.to_be_bytes(),
            &self.position.committed_through_height.to_be_bytes(),
            self.validator_public_key.as_bytes(),
            &self.validator_key_era.to_be_bytes(),
            &self.activation_height.to_be_bytes(),
            &self.exit_height.to_be_bytes(),
            &self.evidence_window_blocks.to_be_bytes(),
            &self.evidence_deadline_height.to_be_bytes(),
            self.slash_terms_commitment.as_bytes(),
        ])
    }
}

/// Authenticated, monotonic summary of every retained Epoch liability for one
/// stake position. Runtime unbond paths may read the current record in O(1),
/// while recovery and audit rebuild the same chain from immutable Epochs.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StakePositionLiabilityHorizonV1 {
    pub horizon_version: u16,
    pub position_id: String,
    pub owner: String,
    pub escrow_coin_id: String,
    pub retained_liability_count: u64,
    pub max_evidence_deadline_height: u128,
    pub last_consensus_epoch: u64,
    pub liability_accumulator_root: String,
    pub previous_horizon_commitment: String,
    pub horizon_commitment: String,
}

pub type StakePositionLiabilityHorizonIndexV1 = BTreeMap<String, StakePositionLiabilityHorizonV1>;
pub type StakePositionLiabilityHorizonHistoryV1 =
    BTreeMap<String, Vec<StakePositionLiabilityHorizonV1>>;
pub type StakePositionLiabilityHorizonStateV1 = (
    StakePositionLiabilityHorizonIndexV1,
    StakePositionLiabilityHorizonHistoryV1,
);

impl StakePositionLiabilityHorizonV1 {
    pub fn compute_commitment(&self) -> String {
        hash_parts(&[
            b"RLD-STAKE-POSITION-LIABILITY-HORIZON-V1",
            &self.horizon_version.to_be_bytes(),
            self.position_id.as_bytes(),
            self.owner.as_bytes(),
            self.escrow_coin_id.as_bytes(),
            &self.retained_liability_count.to_be_bytes(),
            &self.max_evidence_deadline_height.to_be_bytes(),
            &self.last_consensus_epoch.to_be_bytes(),
            self.liability_accumulator_root.as_bytes(),
            self.previous_horizon_commitment.as_bytes(),
        ])
    }

    pub fn validate(&self) -> Result<(), StakeEpochDerivationError> {
        let previous_is_genesis = self.previous_horizon_commitment == ZERO_HASH;
        if self.horizon_version != STAKE_POSITION_LIABILITY_HORIZON_VERSION_V1
            || self.position_id.trim().is_empty()
            || self.owner.trim().is_empty()
            || self.escrow_coin_id.trim().is_empty()
            || self.retained_liability_count == 0
            || self.last_consensus_epoch == 0
            || self.max_evidence_deadline_height == 0
            || validate_nonzero_hash(&self.liability_accumulator_root).is_err()
            || (!previous_is_genesis
                && validate_nonzero_hash(&self.previous_horizon_commitment).is_err())
            || (self.retained_liability_count == 1) != previous_is_genesis
            || validate_nonzero_hash(&self.horizon_commitment).is_err()
            || self.horizon_commitment != self.compute_commitment()
        {
            return Err(StakeEpochDerivationError::InvalidLiabilityHorizon {
                position_id: self.position_id.clone(),
                reason: "identity, counter, hash or commitment mismatch".into(),
            });
        }
        Ok(())
    }
}

/// Appends exactly one validated Epoch to an already-authenticated horizon
/// index. Normal runtime uses this bounded path; full history traversal is
/// reserved for bootstrap, recovery and audit.
pub fn extend_stake_position_liability_horizons_v1(
    current: &mut BTreeMap<String, StakePositionLiabilityHorizonV1>,
    history: &mut BTreeMap<String, Vec<StakePositionLiabilityHorizonV1>>,
    record: &LedgerDerivedStakeEpochV1,
) -> Result<(), StakeEpochDerivationError> {
    validate_ledger_derived_stake_epoch_v1(record)?;
    let epoch = record.descriptor.consensus_epoch;
    for liability in &record.stake_liabilities {
        if liability.consensus_epoch != epoch
            || liability.liability_commitment != liability.compute_commitment()
        {
            return Err(StakeEpochDerivationError::InvalidLiabilityHorizon {
                position_id: liability.position.position_id.clone(),
                reason: "liability Epoch or commitment mismatch".into(),
            });
        }
        let position_id = liability.position.position_id.clone();
        let prior = current.get(&position_id);
        let retained_history = history.get(&position_id);
        if prior.is_some_and(|value| {
            value.owner != liability.position.owner
                || value.escrow_coin_id != liability.position.escrow_coin_id
                || value.last_consensus_epoch >= epoch
        }) || prior.is_some() != retained_history.is_some()
            || prior.is_some_and(|value| {
                retained_history
                    .and_then(|records| records.last())
                    .is_none_or(|tip| tip != value)
            })
        {
            return Err(StakeEpochDerivationError::InvalidLiabilityHorizon {
                position_id,
                reason: "position identity, history tip or Epoch continuity mismatch".into(),
            });
        }
        let previous_accumulator =
            prior.map_or(ZERO_HASH, |value| value.liability_accumulator_root.as_str());
        let previous_commitment =
            prior.map_or(ZERO_HASH, |value| value.horizon_commitment.as_str());
        let leaf = hash_parts(&[
            b"RLD-STAKE-POSITION-LIABILITY-HORIZON-LEAF-V1",
            liability.position.position_id.as_bytes(),
            liability.position.owner.as_bytes(),
            liability.position.escrow_coin_id.as_bytes(),
            &liability.consensus_epoch.to_be_bytes(),
            liability.liability_commitment.as_bytes(),
            &liability.evidence_deadline_height.to_be_bytes(),
        ]);
        let accumulator = hash_parts(&[
            b"RLD-STAKE-POSITION-LIABILITY-HORIZON-ACCUMULATOR-V1",
            previous_accumulator.as_bytes(),
            leaf.as_bytes(),
        ]);
        let retained_liability_count = prior.map_or(Ok(1), |value| {
            value
                .retained_liability_count
                .checked_add(1)
                .ok_or(StakeEpochDerivationError::ArithmeticOverflow)
        })?;
        let mut next = StakePositionLiabilityHorizonV1 {
            horizon_version: STAKE_POSITION_LIABILITY_HORIZON_VERSION_V1,
            position_id: liability.position.position_id.clone(),
            owner: liability.position.owner.clone(),
            escrow_coin_id: liability.position.escrow_coin_id.clone(),
            retained_liability_count,
            max_evidence_deadline_height: prior.map_or(
                liability.evidence_deadline_height,
                |value| {
                    value
                        .max_evidence_deadline_height
                        .max(liability.evidence_deadline_height)
                },
            ),
            last_consensus_epoch: epoch,
            liability_accumulator_root: accumulator,
            previous_horizon_commitment: previous_commitment.into(),
            horizon_commitment: String::new(),
        };
        next.horizon_commitment = next.compute_commitment();
        next.validate()?;
        history
            .entry(next.position_id.clone())
            .or_default()
            .push(next.clone());
        current.insert(next.position_id.clone(), next);
    }
    Ok(())
}

/// Rebuilds both the O(1) current index and the append-only per-position
/// horizon history. Epoch order and every liability commitment are rechecked;
/// no caller-provided count, root or deadline is trusted.
pub fn rebuild_stake_position_liability_horizons_v1<'a, I>(
    epochs: I,
) -> Result<StakePositionLiabilityHorizonStateV1, StakeEpochDerivationError>
where
    I: IntoIterator<Item = &'a LedgerDerivedStakeEpochV1>,
{
    let mut current = BTreeMap::<String, StakePositionLiabilityHorizonV1>::new();
    let mut history = BTreeMap::<String, Vec<StakePositionLiabilityHorizonV1>>::new();
    let mut previous_epoch = None;
    for record in epochs {
        validate_ledger_derived_stake_epoch_v1(record)?;
        let epoch = record.descriptor.consensus_epoch;
        if previous_epoch
            .replace(epoch)
            .is_some_and(|prior| prior >= epoch)
        {
            return Err(StakeEpochDerivationError::InvalidPreviousEpoch(
                "liability horizon Epoch input is not strictly ordered".into(),
            ));
        }
        extend_stake_position_liability_horizons_v1(&mut current, &mut history, record)?;
    }
    Ok((current, history))
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct LedgerDerivedStakeEpochV1 {
    pub derivation_version: u16,
    pub status: StakeEpochRecordStatus,
    pub stake_snapshot_height: u128,
    pub stake_snapshot_state_root: String,
    pub previous_record_hash: String,
    pub descriptor: ConsensusEpochDescriptor,
    pub descriptor_commitment: String,
    #[serde(default = "zero_hash_string", skip_serializing_if = "is_zero_hash")]
    pub stake_liability_root: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stake_liabilities: Vec<ConsensusStakeEpochLiabilityV2>,
    pub record_hash: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLedgerDerivedStakeEpochV1 {
    derivation_version: u16,
    status: StakeEpochRecordStatus,
    stake_snapshot_height: u128,
    stake_snapshot_state_root: String,
    previous_record_hash: String,
    descriptor: ConsensusEpochDescriptor,
    descriptor_commitment: String,
    #[serde(default = "zero_hash_string")]
    stake_liability_root: String,
    #[serde(default)]
    stake_liabilities: Vec<ConsensusStakeEpochLiabilityV2>,
    record_hash: String,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum StakeEpochDerivationError {
    #[error("invalid ledger context: {0}")]
    InvalidContext(&'static str),
    #[error("invalid consensus stake policy: {0}")]
    InvalidPolicy(&'static str),
    #[error("invalid consensus epoch anchor: {0}")]
    InvalidAnchor(&'static str),
    #[error("previous derived epoch is invalid: {0}")]
    InvalidPreviousEpoch(String),
    #[error("invalid stake-position liability horizon for {position_id}: {reason}")]
    InvalidLiabilityHorizon { position_id: String, reason: String },
    #[error("consensus epoch sequence is not contiguous")]
    NonContiguousEpoch,
    #[error("epoch activation is not contiguous with the previous exit")]
    NonContiguousActivation,
    #[error("validator count is below the network minimum of {minimum}")]
    InsufficientValidators { minimum: usize },
    #[error("mainnet control-group count is below the minimum of {minimum}")]
    InsufficientControlGroups { minimum: usize },
    #[error("{collection} contains {actual} records, above the limit of {maximum}")]
    InputLimitExceeded {
        collection: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("duplicate validator id: {0}")]
    DuplicateValidatorId(String),
    #[error("duplicate validator public key: {0}")]
    DuplicateValidatorKey(String),
    #[error("invalid validator candidate {validator_id}: {reason}")]
    InvalidCandidate {
        validator_id: String,
        reason: String,
    },
    #[error("invalid proof of possession for validator {validator_id}: {reason}")]
    InvalidProofOfPossession {
        validator_id: String,
        reason: String,
    },
    #[error("duplicate stake position id: {0}")]
    DuplicateStakePosition(String),
    #[error("escrow coin is referenced by more than one stake position: {0}")]
    DuplicateEscrowCoin(String),
    #[error("invalid stake position {position_id}: {reason}")]
    InvalidStakePosition { position_id: String, reason: String },
    #[error("stake escrow coin was not found: {0}")]
    EscrowCoinNotFound(String),
    #[error("stake escrow coin does not match position {0}")]
    EscrowCoinMismatch(String),
    #[error("invalid UBO control for validator {validator_id}: {reason}")]
    InvalidUboControl {
        validator_id: String,
        reason: String,
    },
    #[error("checked u128 arithmetic overflow")]
    ArithmeticOverflow,
    #[error("stake snapshot serialization failed: {0}")]
    SnapshotSerialization(String),
    #[error("canonical stake snapshot encoding failed: {0}")]
    CanonicalSnapshotEncoding(String),
    #[error("canonical stake snapshot exceeds the {maximum_bytes}-byte limit")]
    StakeSnapshotTooLarge { maximum_bytes: usize },
    #[error("derived consensus epoch descriptor rejected: {0}")]
    DescriptorRejected(String),
    #[error("invalid ledger stake-authority transition: {0}")]
    InvalidAuthorityTransition(String),
    #[error("ledger stake-authority commitment mismatch")]
    AuthorityCommitmentMismatch,
}

#[derive(Clone)]
struct CandidatePower<'a> {
    candidate: &'a ValidatorCandidateRecord,
    self_bond: u128,
    delegated_weight: u128,
    weight: u128,
    unbonding_height: u128,
    control_group: String,
}

/// Stable PoP message for one candidate. It binds the validator identity and
/// key to the ledger's network/Zone/genesis and protocol eras, but not to one
/// particular snapshot height so an unchanged key does not require renewal on
/// every derivation.
pub fn validator_candidate_pop_message_v1(
    context: &StakeLedgerContextV1,
    candidate: &ValidatorCandidateRecord,
) -> Vec<u8> {
    let exit_height = candidate.exit_height.unwrap_or_default().to_be_bytes();
    let exit_present = [u8::from(candidate.exit_height.is_some())];
    hash_parts(&[
        b"RLD-VALIDATOR-CANDIDATE-POP-V1",
        context.network_domain.as_bytes(),
        context.zone_id.as_bytes(),
        context.currency_genesis_root.as_bytes(),
        &context.protocol_era.to_be_bytes(),
        &context.crypto_era.to_be_bytes(),
        &context.consensus_protocol_version.to_be_bytes(),
        candidate.validator_id.as_bytes(),
        candidate.owner.as_bytes(),
        candidate.public_key.as_bytes(),
        &candidate.key_era.to_be_bytes(),
        &candidate.registered_height.to_be_bytes(),
        &exit_present,
        &exit_height,
    ])
    .into_bytes()
}

/// The nonzero first-link anchor is derived from immutable ledger identity. It
/// is not supplied by a caller and cannot be reused across a Zone or era.
pub fn ledger_stake_authority_genesis_anchor_v1(context: &StakeLedgerContextV1) -> String {
    hash_parts(&[
        b"RLD-LEDGER-STAKE-AUTHORITY-GENESIS-V1",
        context.network_domain.as_bytes(),
        context.zone_id.as_bytes(),
        context.currency_genesis_root.as_bytes(),
        &context.protocol_era.to_be_bytes(),
        &context.crypto_era.to_be_bytes(),
        &context.consensus_protocol_version.to_be_bytes(),
    ])
}

/// Builds one canonical, predecessor-linked authority state without mutating a
/// ledger. All candidates and positions are structurally validated against the
/// supplied finalized context and Coin set before a commitment is returned.
pub fn build_ledger_stake_authority_state_v1(
    context: &StakeLedgerContextV1,
    effective_height: u128,
    previous: Option<&LedgerStakeAuthorityStateV1>,
    update: LedgerStakeAuthorityUpdateV1,
    coins: &BTreeMap<String, CoinObject>,
) -> Result<LedgerStakeAuthorityStateV1, StakeEpochDerivationError> {
    validate_context(context)?;
    validate_policy(context, &update.policy)?;
    validate_input_bounds(&update.candidates, &update.positions, &update.ubo_control)?;
    if update.authority_version != STAKE_AUTHORITY_STATE_VERSION_V1
        || update.sequence == 0
        || effective_height <= context.finalized_height
    {
        return Err(StakeEpochDerivationError::InvalidAuthorityTransition(
            "unsupported version, zero sequence, or non-advancing effective height".into(),
        ));
    }

    let expected_previous = if let Some(previous) = previous {
        validate_ledger_stake_authority_state_v1(previous)?;
        if previous.network_domain != context.network_domain
            || previous.zone_id != context.zone_id
            || previous.currency_genesis_root != context.currency_genesis_root
            || previous.protocol_era != context.protocol_era
            || previous.crypto_era != context.crypto_era
            || previous.consensus_protocol_version != context.consensus_protocol_version
        {
            return Err(StakeEpochDerivationError::InvalidAuthorityTransition(
                "authority identity changed across the predecessor chain".into(),
            ));
        }
        let expected_sequence = previous
            .sequence
            .checked_add(1)
            .ok_or(StakeEpochDerivationError::ArithmeticOverflow)?;
        if update.sequence != expected_sequence {
            return Err(StakeEpochDerivationError::InvalidAuthorityTransition(
                "authority sequence is not contiguous".into(),
            ));
        }
        previous.commitment.clone()
    } else {
        if update.sequence != 1 {
            return Err(StakeEpochDerivationError::InvalidAuthorityTransition(
                "first authority sequence must be one".into(),
            ));
        }
        ledger_stake_authority_genesis_anchor_v1(context)
    };
    if update.expected_previous_commitment != expected_previous {
        return Err(StakeEpochDerivationError::InvalidAuthorityTransition(
            "authority predecessor commitment mismatch".into(),
        ));
    }

    validate_authority_view(
        context,
        &update.policy,
        &update.candidates,
        &update.positions,
        &update.ubo_control,
        coins,
    )?;
    validate_ubo_transition(
        previous.map(|state| &state.ubo_control),
        &update.ubo_control,
    )?;

    let mut candidates = update.candidates;
    candidates.sort_by(|left, right| {
        left.validator_id
            .as_bytes()
            .cmp(right.validator_id.as_bytes())
            .then_with(|| left.public_key.as_bytes().cmp(right.public_key.as_bytes()))
    });
    let mut positions = update.positions;
    positions.sort_by(|left, right| {
        left.position_id
            .as_bytes()
            .cmp(right.position_id.as_bytes())
            .then_with(|| {
                left.escrow_coin_id
                    .as_bytes()
                    .cmp(right.escrow_coin_id.as_bytes())
            })
    });
    let mut state = LedgerStakeAuthorityStateV1 {
        authority_version: update.authority_version,
        status: StakeAuthorityStateStatus::StagedOnly,
        network_domain: context.network_domain.clone(),
        zone_id: context.zone_id.clone(),
        currency_genesis_root: context.currency_genesis_root.clone(),
        protocol_era: context.protocol_era,
        crypto_era: context.crypto_era,
        consensus_protocol_version: context.consensus_protocol_version,
        sequence: update.sequence,
        previous_commitment: expected_previous,
        source_height: context.finalized_height,
        source_state_root: context.finalized_state_root.clone(),
        effective_height,
        policy: update.policy,
        candidates,
        positions,
        ubo_control: update.ubo_control,
        commitment: String::new(),
    };
    state.commitment = ledger_stake_authority_state_commitment_v1(&state)?;
    Ok(state)
}

pub fn validate_ledger_stake_authority_state_v1(
    state: &LedgerStakeAuthorityStateV1,
) -> Result<(), StakeEpochDerivationError> {
    if state.authority_version != STAKE_AUTHORITY_STATE_VERSION_V1
        || state.status != StakeAuthorityStateStatus::StagedOnly
        || !matches!(
            state.network_domain.as_str(),
            RLDCOIN_MAINNET_DOMAIN | RLDCOIN_TESTNET_DOMAIN
        )
        || !is_valid_zone_id(&state.zone_id)
        || validate_nonzero_hash(&state.currency_genesis_root).is_err()
        || state.protocol_era == 0
        || state.crypto_era == 0
        || state.consensus_protocol_version == 0
        || state.sequence == 0
        || state.effective_height <= state.source_height
        || validate_nonzero_hash(&state.previous_commitment).is_err()
        || validate_nonzero_hash(&state.source_state_root).is_err()
    {
        return Err(StakeEpochDerivationError::InvalidAuthorityTransition(
            "malformed authority header".into(),
        ));
    }
    if !state
        .candidates
        .windows(2)
        .all(|pair| pair[0].validator_id.as_bytes() < pair[1].validator_id.as_bytes())
        || !state
            .positions
            .windows(2)
            .all(|pair| pair[0].position_id.as_bytes() < pair[1].position_id.as_bytes())
    {
        return Err(StakeEpochDerivationError::InvalidAuthorityTransition(
            "authority candidates or positions are not in canonical order".into(),
        ));
    }
    let expected = ledger_stake_authority_state_commitment_v1(state)?;
    if state.commitment != expected {
        return Err(StakeEpochDerivationError::AuthorityCommitmentMismatch);
    }
    Ok(())
}

impl<'de> Deserialize<'de> for LedgerStakeAuthorityStateV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawLedgerStakeAuthorityStateV1::deserialize(deserializer)?;
        let state = Self {
            authority_version: raw.authority_version,
            status: raw.status,
            network_domain: raw.network_domain,
            zone_id: raw.zone_id,
            currency_genesis_root: raw.currency_genesis_root,
            protocol_era: raw.protocol_era,
            crypto_era: raw.crypto_era,
            consensus_protocol_version: raw.consensus_protocol_version,
            sequence: raw.sequence,
            previous_commitment: raw.previous_commitment,
            source_height: raw.source_height,
            source_state_root: raw.source_state_root,
            effective_height: raw.effective_height,
            policy: raw.policy,
            candidates: raw.candidates,
            positions: raw.positions,
            ubo_control: raw.ubo_control,
            commitment: raw.commitment,
        };
        validate_ledger_stake_authority_state_v1(&state).map_err(de::Error::custom)?;
        Ok(state)
    }
}

pub fn ledger_stake_authority_state_commitment_v1(
    state: &LedgerStakeAuthorityStateV1,
) -> Result<String, StakeEpochDerivationError> {
    let candidate_items = state
        .candidates
        .iter()
        .map(encode_snapshot_candidate)
        .collect::<Result<Vec<_>, _>>()?;
    let position_items = state
        .positions
        .iter()
        .map(encode_snapshot_position)
        .collect::<Result<Vec<_>, _>>()?;
    let status = match state.status {
        StakeAuthorityStateStatus::StagedOnly => 1,
    };
    let mut encoded = SnapshotStructEncoder::new(SNAPSHOT_AUTHORITY_STATE_SCHEMA)?;
    encoded.push_u16(1, state.authority_version)?;
    encoded.push(2, SNAPSHOT_KIND_ENUM_U8, &[status])?;
    encoded.push_text(3, &state.network_domain)?;
    encoded.push_text(4, &state.zone_id)?;
    encoded.push_hex(
        5,
        SNAPSHOT_KIND_HASH32,
        &state.currency_genesis_root,
        32,
        "authority currency genesis root",
    )?;
    encoded.push_u64(6, state.protocol_era)?;
    encoded.push_u64(7, state.crypto_era)?;
    encoded.push_u64(8, state.consensus_protocol_version)?;
    encoded.push_u64(9, state.sequence)?;
    encoded.push_hex(
        10,
        SNAPSHOT_KIND_HASH32,
        &state.previous_commitment,
        32,
        "authority previous commitment",
    )?;
    encoded.push_u128(11, state.source_height)?;
    encoded.push_hex(
        12,
        SNAPSHOT_KIND_HASH32,
        &state.source_state_root,
        32,
        "authority source state root",
    )?;
    encoded.push_u128(13, state.effective_height)?;
    encoded.push_struct(14, &encode_snapshot_policy(&state.policy)?)?;
    encoded.push_struct_list(15, &candidate_items)?;
    encoded.push_struct_list(16, &position_items)?;
    encoded.push_struct(17, &encode_snapshot_ubo_map(&state.ubo_control)?)?;
    let bytes = encoded.finish()?;
    Ok(hash_parts(&[
        b"RLD-LEDGER-STAKE-AUTHORITY-STATE-V1",
        &bytes,
    ]))
}

fn validate_authority_view(
    context: &StakeLedgerContextV1,
    policy: &ConsensusStakePolicyV1,
    candidates: &[ValidatorCandidateRecord],
    positions: &[ConsensusStakePosition],
    ubo_control: &UboControlMap,
    coins: &BTreeMap<String, CoinObject>,
) -> Result<(), StakeEpochDerivationError> {
    let candidate_index = validate_candidates(context, candidates)?;
    validate_ubo_map(ubo_control)?;
    validate_and_sum_positions(context, policy, 0, &candidate_index, positions, coins)?;
    Ok(())
}

fn validate_ubo_transition(
    previous: Option<&UboControlMap>,
    next: &UboControlMap,
) -> Result<(), StakeEpochDerivationError> {
    let Some(previous) = previous else {
        return Ok(());
    };
    let expected_sequence = previous
        .sequence
        .checked_add(1)
        .ok_or(StakeEpochDerivationError::ArithmeticOverflow)?;
    let previous_commitment = ubo_control_commitment_v1(previous)?;
    if next.sequence != expected_sequence || next.predecessor_commitment != previous_commitment {
        return Err(StakeEpochDerivationError::InvalidAuthorityTransition(
            "UBO sequence or predecessor commitment is not contiguous".into(),
        ));
    }
    Ok(())
}

pub fn ubo_control_commitment_v1(
    control: &UboControlMap,
) -> Result<String, StakeEpochDerivationError> {
    validate_ubo_map(control)?;
    let bytes = encode_snapshot_ubo_map(control)?;
    Ok(hash_parts(&[b"RLD-UBO-CONTROL-MAP-V1", &bytes]))
}

/// Derives an epoch only from finalized, validated input. No caller-owned
/// descriptor fields are accepted and no input is mutated on failure.
#[allow(clippy::too_many_arguments)]
pub fn derive_ledger_stake_epoch_v1(
    context: &StakeLedgerContextV1,
    policy: &ConsensusStakePolicyV1,
    anchor: &ConsensusEpochAnchor,
    previous_epoch: Option<&LedgerDerivedStakeEpochV1>,
    candidates: &[ValidatorCandidateRecord],
    positions: &[ConsensusStakePosition],
    ubo_control: &UboControlMap,
    coins: &BTreeMap<String, CoinObject>,
) -> Result<LedgerDerivedStakeEpochV1, StakeEpochDerivationError> {
    validate_context(context)?;
    let minimum_validators = validate_policy(context, policy)?;
    validate_input_bounds(candidates, positions, ubo_control)?;
    validate_anchor(context, policy, anchor, previous_epoch)?;

    let exit_height = anchor
        .activation_height
        .checked_add(policy.epoch_length_blocks)
        .ok_or(StakeEpochDerivationError::ArithmeticOverflow)?;
    let required_commitment_height = exit_height
        .checked_add(policy.evidence_window_blocks)
        .ok_or(StakeEpochDerivationError::ArithmeticOverflow)?;

    let candidate_index = validate_candidates(context, candidates)?;
    validate_ubo_map(ubo_control)?;
    let powers = validate_and_sum_positions(
        context,
        policy,
        required_commitment_height,
        &candidate_index,
        positions,
        coins,
    )?;
    let mut powers = eligible_candidate_powers(
        context,
        policy,
        exit_height,
        required_commitment_height,
        powers,
        ubo_control,
    )?;

    powers = select_control_group_representatives(powers, usize::from(policy.maximum_validators));
    if context.network_domain == RLDCOIN_MAINNET_DOMAIN {
        let independent_groups = powers
            .iter()
            .map(|power| power.control_group.as_str())
            .collect::<BTreeSet<_>>()
            .len();
        if independent_groups < MIN_MAINNET_STAKE_VALIDATORS {
            return Err(StakeEpochDerivationError::InsufficientControlGroups {
                minimum: MIN_MAINNET_STAKE_VALIDATORS,
            });
        }
    }
    if powers.len() < minimum_validators {
        return Err(StakeEpochDerivationError::InsufficientValidators {
            minimum: minimum_validators,
        });
    }

    powers.sort_by(|left, right| {
        left.candidate
            .validator_id
            .as_bytes()
            .cmp(right.candidate.validator_id.as_bytes())
            .then_with(|| {
                left.candidate
                    .public_key
                    .as_bytes()
                    .cmp(right.candidate.public_key.as_bytes())
            })
    });

    let mut total_weight = 0u128;
    let validators = powers
        .iter()
        .map(|power| {
            total_weight = total_weight
                .checked_add(power.weight)
                .ok_or(StakeEpochDerivationError::ArithmeticOverflow)?;
            Ok(ValidatorRecord {
                validator_id: power.candidate.validator_id.clone(),
                public_key: power.candidate.public_key.clone(),
                key_era: power.candidate.key_era,
                weight: power.weight,
                control_group: power.control_group.clone(),
                self_bond: power.self_bond,
                delegated_weight: power.delegated_weight,
                unbonding_height: power.unbonding_height,
            })
        })
        .collect::<Result<Vec<_>, StakeEpochDerivationError>>()?;

    let (stake_liability_root, stake_liabilities) =
        if policy.policy_version == STAKE_EPOCH_DERIVATION_VERSION_V2 {
            build_stake_epoch_liabilities_v2(
                context,
                policy,
                anchor,
                exit_height,
                required_commitment_height,
                &powers,
                positions,
            )?
        } else {
            (ZERO_HASH.into(), Vec::new())
        };

    let previous_record_hash = anchor.record_chain_anchor.clone();
    let stake_snapshot_root = stake_snapshot_root_v1(
        context,
        policy,
        anchor,
        candidates,
        positions,
        ubo_control,
        coins,
    )?;
    let quorum_power = quorum_power_v1(total_weight)
        .map_err(|error| StakeEpochDerivationError::DescriptorRejected(error.to_string()))?;
    let descriptor = ConsensusEpochDescriptor {
        network_domain: context.network_domain.clone(),
        zone_id: context.zone_id.clone(),
        currency_genesis_root: context.currency_genesis_root.clone(),
        protocol_era: context.protocol_era,
        crypto_era: context.crypto_era,
        consensus_protocol_version: context.consensus_protocol_version,
        consensus_epoch: anchor.consensus_epoch,
        activation_height: anchor.activation_height,
        exit_height,
        stake_snapshot_root,
        validators,
        total_weight,
        quorum_power,
        quorum_rule: ConsensusQuorumRule::v1(),
    };
    descriptor
        .validate()
        .map_err(|error| StakeEpochDerivationError::DescriptorRejected(error.to_string()))?;
    let descriptor_commitment = consensus_epoch_descriptor_commitment_v1(&descriptor)
        .map_err(|error| StakeEpochDerivationError::DescriptorRejected(error.to_string()))?
        .as_str()
        .to_owned();
    let record_hash = derived_record_hash(
        policy.policy_version,
        StakeEpochRecordStatus::DerivedOnly,
        anchor.stake_snapshot_height,
        &anchor.stake_snapshot_state_root,
        &previous_record_hash,
        &descriptor_commitment,
        &stake_liability_root,
    );

    Ok(LedgerDerivedStakeEpochV1 {
        derivation_version: policy.policy_version,
        status: StakeEpochRecordStatus::DerivedOnly,
        stake_snapshot_height: anchor.stake_snapshot_height,
        stake_snapshot_state_root: anchor.stake_snapshot_state_root.clone(),
        previous_record_hash,
        descriptor,
        descriptor_commitment,
        stake_liability_root,
        stake_liabilities,
        record_hash,
    })
}

pub fn validate_ledger_derived_stake_epoch_v1(
    record: &LedgerDerivedStakeEpochV1,
) -> Result<(), StakeEpochDerivationError> {
    if !matches!(
        record.derivation_version,
        STAKE_EPOCH_DERIVATION_VERSION_V1 | STAKE_EPOCH_DERIVATION_VERSION_V2
    ) || record.status != StakeEpochRecordStatus::DerivedOnly
    {
        return Err(StakeEpochDerivationError::InvalidPreviousEpoch(
            "unsupported derivation version or status".into(),
        ));
    }
    validate_nonzero_hash(&record.stake_snapshot_state_root).map_err(|_| {
        StakeEpochDerivationError::InvalidPreviousEpoch(
            "stake snapshot state root is invalid".into(),
        )
    })?;
    validate_nonzero_hash(&record.previous_record_hash).map_err(|_| {
        StakeEpochDerivationError::InvalidPreviousEpoch("previous record hash is invalid".into())
    })?;
    if record.stake_snapshot_height >= record.descriptor.activation_height {
        return Err(StakeEpochDerivationError::InvalidPreviousEpoch(
            "stake snapshot must precede descriptor activation".into(),
        ));
    }
    record
        .descriptor
        .validate()
        .map_err(|error| StakeEpochDerivationError::InvalidPreviousEpoch(error.to_string()))?;
    let commitment = consensus_epoch_descriptor_commitment_v1(&record.descriptor)
        .map_err(|error| StakeEpochDerivationError::InvalidPreviousEpoch(error.to_string()))?;
    if record.descriptor_commitment != commitment.as_str() {
        return Err(StakeEpochDerivationError::InvalidPreviousEpoch(
            "descriptor commitment mismatch".into(),
        ));
    }
    validate_record_stake_liabilities(record)?;
    let expected = derived_record_hash(
        record.derivation_version,
        record.status,
        record.stake_snapshot_height,
        &record.stake_snapshot_state_root,
        &record.previous_record_hash,
        &record.descriptor_commitment,
        &record.stake_liability_root,
    );
    if record.record_hash != expected {
        return Err(StakeEpochDerivationError::InvalidPreviousEpoch(
            "record hash mismatch".into(),
        ));
    }
    Ok(())
}

fn validate_record_stake_liabilities(
    record: &LedgerDerivedStakeEpochV1,
) -> Result<(), StakeEpochDerivationError> {
    if record.derivation_version == STAKE_EPOCH_DERIVATION_VERSION_V1 {
        if record.stake_liability_root != ZERO_HASH || !record.stake_liabilities.is_empty() {
            return Err(StakeEpochDerivationError::InvalidPreviousEpoch(
                "derivation v1 must not claim slash liabilities".into(),
            ));
        }
        return Ok(());
    }
    if record.stake_liabilities.is_empty()
        || validate_nonzero_hash(&record.stake_liability_root).is_err()
    {
        return Err(StakeEpochDerivationError::InvalidPreviousEpoch(
            "derivation v2 has no nonzero per-position liability root".into(),
        ));
    }
    let context = StakeLedgerContextV1 {
        network_domain: record.descriptor.network_domain.clone(),
        zone_id: record.descriptor.zone_id.clone(),
        currency_genesis_root: record.descriptor.currency_genesis_root.clone(),
        protocol_era: record.descriptor.protocol_era,
        crypto_era: record.descriptor.crypto_era,
        consensus_protocol_version: record.descriptor.consensus_protocol_version,
        finalized_height: record.stake_snapshot_height,
        finalized_state_root: record.stake_snapshot_state_root.clone(),
    };
    let validators = record
        .descriptor
        .validators
        .iter()
        .map(|validator| (validator.validator_id.as_str(), validator))
        .collect::<BTreeMap<_, _>>();
    let mut position_ids = BTreeSet::new();
    let mut escrow_ids = BTreeSet::new();
    let mut authorization_ids = BTreeSet::new();
    let mut totals = BTreeMap::<&str, (u128, u128, u128)>::new();
    let mut previous_position_id: Option<&str> = None;
    for liability in &record.stake_liabilities {
        let position_id = liability.position.position_id.as_str();
        if previous_position_id
            .is_some_and(|previous| previous.as_bytes() >= position_id.as_bytes())
            || !position_ids.insert(position_id)
            || !escrow_ids.insert(liability.position.escrow_coin_id.as_str())
        {
            return Err(StakeEpochDerivationError::InvalidPreviousEpoch(
                "liability positions are duplicated or not canonically ordered".into(),
            ));
        }
        previous_position_id = Some(position_id);
        let terms = liability.position.slash_terms.as_ref().ok_or_else(|| {
            StakeEpochDerivationError::InvalidPreviousEpoch(
                "liability position has no signed v2 slash terms".into(),
            )
        })?;
        if !authorization_ids.insert(terms.owner_authorization.authorization_id.as_str()) {
            return Err(StakeEpochDerivationError::InvalidPreviousEpoch(
                "liability reuses a slash-terms authorization".into(),
            ));
        }
        validate_position_slash_terms_v2(&context, &liability.position)?;
        let validator = validators
            .get(liability.position.kind.validator_id())
            .ok_or_else(|| {
                StakeEpochDerivationError::InvalidPreviousEpoch(
                    "liability targets a validator outside the descriptor".into(),
                )
            })?;
        let expected_deadline = liability
            .exit_height
            .checked_add(liability.evidence_window_blocks)
            .ok_or(StakeEpochDerivationError::ArithmeticOverflow)?;
        if liability.consensus_epoch != record.descriptor.consensus_epoch
            || liability.activation_height != record.descriptor.activation_height
            || liability.exit_height != record.descriptor.exit_height
            || liability.evidence_window_blocks == 0
            || liability.evidence_deadline_height != expected_deadline
            || liability.position.committed_through_height < expected_deadline
            || liability.validator_public_key != validator.public_key
            || liability.validator_key_era != validator.key_era
            || liability.slash_terms_commitment
                != liability
                    .position
                    .slash_terms_commitment_v2()
                    .unwrap_or_default()
            || liability.liability_commitment != liability.compute_commitment()
        {
            return Err(StakeEpochDerivationError::InvalidPreviousEpoch(
                "liability context, key, deadline, terms or commitment mismatch".into(),
            ));
        }
        let total = totals
            .entry(liability.position.kind.validator_id())
            .or_insert((0, 0, u128::MAX));
        match liability.position.kind {
            ConsensusStakePositionKind::SelfBond { .. } => {
                total.0 = total
                    .0
                    .checked_add(liability.position.amount.0)
                    .ok_or(StakeEpochDerivationError::ArithmeticOverflow)?;
            }
            ConsensusStakePositionKind::Delegation { .. } => {
                total.1 = total
                    .1
                    .checked_add(liability.position.amount.0)
                    .ok_or(StakeEpochDerivationError::ArithmeticOverflow)?;
            }
        }
        total.2 = total.2.min(liability.position.committed_through_height);
    }
    for validator in &record.descriptor.validators {
        let totals = totals.get(validator.validator_id.as_str()).ok_or_else(|| {
            StakeEpochDerivationError::InvalidPreviousEpoch(
                "descriptor validator has no position liability".into(),
            )
        })?;
        if totals.0 != validator.self_bond
            || totals.1 != validator.delegated_weight
            || totals.0.checked_add(totals.1) != Some(validator.weight)
            || totals.2 != validator.unbonding_height
        {
            return Err(StakeEpochDerivationError::InvalidPreviousEpoch(
                "liability totals do not reconstruct descriptor weight".into(),
            ));
        }
    }
    let mut parts = Vec::<&[u8]>::with_capacity(record.stake_liabilities.len() + 1);
    parts.push(b"RLD-CONSENSUS-STAKE-EPOCH-LIABILITY-ROOT-V2");
    for liability in &record.stake_liabilities {
        parts.push(liability.liability_commitment.as_bytes());
    }
    if record.stake_liability_root != hash_parts(&parts) {
        return Err(StakeEpochDerivationError::InvalidPreviousEpoch(
            "stake liability root mismatch".into(),
        ));
    }
    Ok(())
}

impl<'de> Deserialize<'de> for LedgerDerivedStakeEpochV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawLedgerDerivedStakeEpochV1::deserialize(deserializer)?;
        let record = Self {
            derivation_version: raw.derivation_version,
            status: raw.status,
            stake_snapshot_height: raw.stake_snapshot_height,
            stake_snapshot_state_root: raw.stake_snapshot_state_root,
            previous_record_hash: raw.previous_record_hash,
            descriptor: raw.descriptor,
            descriptor_commitment: raw.descriptor_commitment,
            stake_liability_root: raw.stake_liability_root,
            stake_liabilities: raw.stake_liabilities,
            record_hash: raw.record_hash,
        };
        validate_ledger_derived_stake_epoch_v1(&record).map_err(de::Error::custom)?;
        Ok(record)
    }
}

fn validate_context(context: &StakeLedgerContextV1) -> Result<(), StakeEpochDerivationError> {
    if !matches!(
        context.network_domain.as_str(),
        RLDCOIN_MAINNET_DOMAIN | RLDCOIN_TESTNET_DOMAIN
    ) {
        return Err(StakeEpochDerivationError::InvalidContext(
            "unsupported network domain",
        ));
    }
    if context.protocol_era == 0
        || context.crypto_era == 0
        || context.consensus_protocol_version == 0
    {
        return Err(StakeEpochDerivationError::InvalidContext(
            "protocol and crypto eras and consensus version must be nonzero",
        ));
    }
    if !is_valid_zone_id(&context.zone_id) {
        return Err(StakeEpochDerivationError::InvalidContext(
            "invalid Zone identifier",
        ));
    }
    validate_nonzero_hash(&context.currency_genesis_root)
        .map_err(|_| StakeEpochDerivationError::InvalidContext("invalid currency genesis root"))?;
    validate_nonzero_hash(&context.finalized_state_root)
        .map_err(|_| StakeEpochDerivationError::InvalidContext("invalid finalized state root"))?;
    Ok(())
}

fn validate_policy(
    context: &StakeLedgerContextV1,
    policy: &ConsensusStakePolicyV1,
) -> Result<usize, StakeEpochDerivationError> {
    let minimum = if context.network_domain == RLDCOIN_MAINNET_DOMAIN {
        MIN_MAINNET_STAKE_VALIDATORS
    } else {
        MIN_TESTNET_STAKE_VALIDATORS
    };
    if !matches!(
        policy.policy_version,
        STAKE_EPOCH_DERIVATION_VERSION_V1 | STAKE_EPOCH_DERIVATION_VERSION_V2
    ) {
        return Err(StakeEpochDerivationError::InvalidPolicy(
            "unsupported policy version",
        ));
    }
    if policy.minimum_self_bond.is_zero()
        || policy.minimum_delegation.is_zero()
        || policy.candidate_maturity_blocks == 0
        || policy.stake_maturity_blocks == 0
        || policy.evidence_window_blocks == 0
        || policy.activation_delay_blocks == 0
        || policy.epoch_length_blocks == 0
    {
        return Err(StakeEpochDerivationError::InvalidPolicy(
            "bond, delegation floor, maturity, activation delay, evidence window and epoch length must be nonzero",
        ));
    }
    let maximum = usize::from(policy.maximum_validators);
    if !(minimum..=MAX_VALIDATORS_PER_EPOCH).contains(&maximum) {
        return Err(StakeEpochDerivationError::InvalidPolicy(
            "maximum validator count is outside network bounds",
        ));
    }
    Ok(minimum)
}

fn validate_input_bounds(
    candidates: &[ValidatorCandidateRecord],
    positions: &[ConsensusStakePosition],
    ubo_control: &UboControlMap,
) -> Result<(), StakeEpochDerivationError> {
    for (collection, actual, maximum) in [
        (
            "validator candidates",
            candidates.len(),
            MAX_STAKE_CANDIDATE_RECORDS,
        ),
        (
            "stake positions",
            positions.len(),
            MAX_STAKE_POSITION_RECORDS,
        ),
        (
            "UBO control records",
            ubo_control.validators.len(),
            MAX_UBO_CONTROL_RECORDS,
        ),
    ] {
        if actual > maximum {
            return Err(StakeEpochDerivationError::InputLimitExceeded {
                collection,
                actual,
                maximum,
            });
        }
    }
    Ok(())
}

fn validate_anchor(
    context: &StakeLedgerContextV1,
    policy: &ConsensusStakePolicyV1,
    anchor: &ConsensusEpochAnchor,
    previous_epoch: Option<&LedgerDerivedStakeEpochV1>,
) -> Result<(), StakeEpochDerivationError> {
    if anchor.consensus_epoch == 0 {
        return Err(StakeEpochDerivationError::InvalidAnchor(
            "consensus epoch must be nonzero",
        ));
    }
    if anchor.stake_snapshot_height != context.finalized_height
        || anchor.stake_snapshot_state_root != context.finalized_state_root
    {
        return Err(StakeEpochDerivationError::InvalidAnchor(
            "snapshot anchor does not equal finalized ledger context",
        ));
    }
    if anchor.activation_height <= context.finalized_height {
        return Err(StakeEpochDerivationError::InvalidAnchor(
            "activation height must follow the finalized snapshot",
        ));
    }
    let scheduled_snapshot_height = anchor
        .activation_height
        .checked_sub(policy.activation_delay_blocks)
        .ok_or(StakeEpochDerivationError::ArithmeticOverflow)?;
    if context.finalized_height != scheduled_snapshot_height {
        return Err(StakeEpochDerivationError::InvalidAnchor(
            "snapshot height does not equal activation minus policy delay",
        ));
    }
    validate_nonzero_hash(&anchor.stake_snapshot_state_root).map_err(|_| {
        StakeEpochDerivationError::InvalidAnchor("invalid stake snapshot state root")
    })?;
    validate_nonzero_hash(&anchor.record_chain_anchor)
        .map_err(|_| StakeEpochDerivationError::InvalidAnchor("record chain anchor is zero"))?;

    if let Some(previous) = previous_epoch {
        validate_ledger_derived_stake_epoch_v1(previous)?;
        if context.network_domain != previous.descriptor.network_domain
            || context.zone_id != previous.descriptor.zone_id
            || context.currency_genesis_root != previous.descriptor.currency_genesis_root
            || context.protocol_era != previous.descriptor.protocol_era
            || context.crypto_era != previous.descriptor.crypto_era
            || context.consensus_protocol_version != previous.descriptor.consensus_protocol_version
        {
            return Err(StakeEpochDerivationError::InvalidAnchor(
                "ledger context changed across one Epoch chain",
            ));
        }
        if context.finalized_height <= previous.stake_snapshot_height {
            return Err(StakeEpochDerivationError::InvalidAnchor(
                "stake snapshot height did not advance",
            ));
        }
        let expected_epoch = previous
            .descriptor
            .consensus_epoch
            .checked_add(1)
            .ok_or(StakeEpochDerivationError::ArithmeticOverflow)?;
        if anchor.consensus_epoch != expected_epoch {
            return Err(StakeEpochDerivationError::NonContiguousEpoch);
        }
        if anchor.activation_height != previous.descriptor.exit_height {
            return Err(StakeEpochDerivationError::NonContiguousActivation);
        }
        if anchor.record_chain_anchor != previous.record_hash {
            return Err(StakeEpochDerivationError::InvalidAnchor(
                "record chain anchor does not match previous record",
            ));
        }
    }
    Ok(())
}

fn validate_candidates<'a>(
    context: &StakeLedgerContextV1,
    candidates: &'a [ValidatorCandidateRecord],
) -> Result<BTreeMap<&'a str, &'a ValidatorCandidateRecord>, StakeEpochDerivationError> {
    let mut index = BTreeMap::new();
    let mut keys = BTreeSet::new();
    for candidate in candidates {
        if !is_valid_identifier(&candidate.validator_id)
            || !is_valid_text(&candidate.owner, MAX_OWNER_BYTES)
        {
            return Err(StakeEpochDerivationError::InvalidCandidate {
                validator_id: candidate.validator_id.clone(),
                reason: "invalid validator id or owner".into(),
            });
        }
        if index
            .insert(candidate.validator_id.as_str(), candidate)
            .is_some()
        {
            return Err(StakeEpochDerivationError::DuplicateValidatorId(
                candidate.validator_id.clone(),
            ));
        }
        if !is_canonical_lower_hex(&candidate.public_key, 32)
            || !is_canonical_lower_hex(&candidate.proof_of_possession, 64)
        {
            return Err(StakeEpochDerivationError::InvalidCandidate {
                validator_id: candidate.validator_id.clone(),
                reason: "key or proof of possession has a non-canonical encoding".into(),
            });
        }
        validate_ed25519_public_key(&candidate.public_key).map_err(|reason| {
            StakeEpochDerivationError::InvalidCandidate {
                validator_id: candidate.validator_id.clone(),
                reason,
            }
        })?;
        if !keys.insert(candidate.public_key.as_str()) {
            return Err(StakeEpochDerivationError::DuplicateValidatorKey(
                candidate.public_key.clone(),
            ));
        }
        if candidate.key_era != context.crypto_era {
            return Err(StakeEpochDerivationError::InvalidCandidate {
                validator_id: candidate.validator_id.clone(),
                reason: "key era does not match ledger crypto era".into(),
            });
        }
        if candidate
            .exit_height
            .is_some_and(|candidate_exit| candidate_exit <= candidate.registered_height)
        {
            return Err(StakeEpochDerivationError::InvalidCandidate {
                validator_id: candidate.validator_id.clone(),
                reason: "candidate exit does not follow registration".into(),
            });
        }
        verify_bytes(
            &candidate.public_key,
            &validator_candidate_pop_message_v1(context, candidate),
            &candidate.proof_of_possession,
        )
        .map_err(
            |reason| StakeEpochDerivationError::InvalidProofOfPossession {
                validator_id: candidate.validator_id.clone(),
                reason,
            },
        )?;
    }
    Ok(index)
}

fn validate_ubo_map(ubo_control: &UboControlMap) -> Result<(), StakeEpochDerivationError> {
    if ubo_control.map_version != STAKE_EPOCH_DERIVATION_VERSION_V1 || ubo_control.sequence == 0 {
        return Err(StakeEpochDerivationError::InvalidUboControl {
            validator_id: "*".into(),
            reason: "unsupported UBO map version or zero sequence".into(),
        });
    }
    if validate_nonzero_hash(&ubo_control.predecessor_commitment).is_err()
        || validate_nonzero_hash(&ubo_control.verifier_set_commitment).is_err()
        || validate_nonzero_hash(&ubo_control.evidence_root).is_err()
    {
        return Err(StakeEpochDerivationError::InvalidUboControl {
            validator_id: "*".into(),
            reason: "invalid predecessor, verifier-set or evidence commitment".into(),
        });
    }
    for (validator_id, control) in &ubo_control.validators {
        if !is_valid_identifier(validator_id)
            || !is_valid_text(&control.control_group, MAX_CONTROL_GROUP_BYTES)
            || control.valid_from_height > control.challenge_ends_height
            || control.challenge_ends_height > control.valid_through_height
            || validate_nonzero_hash(&control.evidence_hash).is_err()
        {
            return Err(StakeEpochDerivationError::InvalidUboControl {
                validator_id: validator_id.clone(),
                reason: "malformed validator id, control group, challenge window or evidence hash"
                    .into(),
            });
        }
    }
    if ubo_control.validators.is_empty() {
        Err(StakeEpochDerivationError::InvalidUboControl {
            validator_id: "*".into(),
            reason: "UBO map is empty".into(),
        })
    } else {
        Ok(())
    }
}

fn validate_position_slash_terms_v2(
    context: &StakeLedgerContextV1,
    position: &ConsensusStakePosition,
) -> Result<(), StakeEpochDerivationError> {
    let Some(terms) = &position.slash_terms else {
        return Ok(());
    };
    if terms.terms_version != CONSENSUS_STAKE_SLASH_TERMS_VERSION_V2 {
        return Err(StakeEpochDerivationError::InvalidStakePosition {
            position_id: position.position_id.clone(),
            reason: "unsupported slash-terms version".into(),
        });
    }
    terms.slash_policy.validate().map_err(|reason| {
        StakeEpochDerivationError::InvalidStakePosition {
            position_id: position.position_id.clone(),
            reason: reason.into(),
        }
    })?;
    let payload_hash = position.slash_terms_payload_hash_v2();
    terms
        .owner_authorization
        .verify_scope(
            &context.zone_id,
            &context.currency_genesis_root,
            context.protocol_era,
            context.crypto_era,
            ACCEPT_CONSENSUS_STAKE_SLASH_TERMS_ACTION_V2,
            &payload_hash,
        )
        .map_err(|reason| StakeEpochDerivationError::InvalidStakePosition {
            position_id: position.position_id.clone(),
            reason: format!("slash-terms owner authorization is invalid: {reason}"),
        })?;
    if terms.owner_authorization.signer_address() != position.owner {
        return Err(StakeEpochDerivationError::InvalidStakePosition {
            position_id: position.position_id.clone(),
            reason: "slash-terms signer is not the position owner".into(),
        });
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_and_sum_positions<'a>(
    context: &StakeLedgerContextV1,
    policy: &ConsensusStakePolicyV1,
    required_commitment_height: u128,
    candidate_index: &BTreeMap<&'a str, &'a ValidatorCandidateRecord>,
    positions: &[ConsensusStakePosition],
    coins: &BTreeMap<String, CoinObject>,
) -> Result<Vec<CandidatePower<'a>>, StakeEpochDerivationError> {
    let mut position_ids = BTreeSet::new();
    let mut source_ids = BTreeSet::new();
    let mut escrow_ids = BTreeSet::new();
    let mut slash_authorization_ids = BTreeSet::new();
    let mut powers = candidate_index
        .values()
        .map(|candidate| {
            (
                candidate.validator_id.as_str(),
                CandidatePower {
                    candidate,
                    self_bond: 0,
                    delegated_weight: 0,
                    weight: 0,
                    unbonding_height: u128::MAX,
                    control_group: String::new(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();

    for position in positions {
        if !is_valid_identifier(&position.position_id)
            || !is_valid_text(&position.owner, MAX_OWNER_BYTES)
            || !is_valid_identifier(&position.source_coin_id)
            || !is_valid_identifier(&position.escrow_coin_id)
            || position.amount.is_zero()
        {
            return Err(StakeEpochDerivationError::InvalidStakePosition {
                position_id: position.position_id.clone(),
                reason: "position id, owner, escrow and amount must be valid".into(),
            });
        }
        if !position_ids.insert(position.position_id.as_str()) {
            return Err(StakeEpochDerivationError::DuplicateStakePosition(
                position.position_id.clone(),
            ));
        }
        if !source_ids.insert(position.source_coin_id.as_str()) {
            return Err(StakeEpochDerivationError::InvalidStakePosition {
                position_id: position.position_id.clone(),
                reason: "source Coin is referenced by more than one stake position".into(),
            });
        }
        if !escrow_ids.insert(position.escrow_coin_id.as_str()) {
            return Err(StakeEpochDerivationError::DuplicateEscrowCoin(
                position.escrow_coin_id.clone(),
            ));
        }
        validate_position_slash_terms_v2(context, position)?;
        if let Some(terms) = &position.slash_terms {
            if !slash_authorization_ids.insert(terms.owner_authorization.authorization_id.as_str())
            {
                return Err(StakeEpochDerivationError::InvalidStakePosition {
                    position_id: position.position_id.clone(),
                    reason: "slash-terms authorization is reused by another position".into(),
                });
            }
        }
        let validator_id = position.kind.validator_id();
        let candidate = candidate_index.get(validator_id).ok_or_else(|| {
            StakeEpochDerivationError::InvalidStakePosition {
                position_id: position.position_id.clone(),
                reason: "stake target is not a direct validator candidate".into(),
            }
        })?;
        let coin = coins.get(&position.escrow_coin_id).ok_or_else(|| {
            StakeEpochDerivationError::EscrowCoinNotFound(position.escrow_coin_id.clone())
        })?;
        let unique_parents = coin.parent_ids.iter().collect::<BTreeSet<_>>();
        let parents_are_canonical = coin
            .parent_ids
            .windows(2)
            .all(|pair| pair[0].as_bytes() < pair[1].as_bytes());
        if coin.object_id != position.escrow_coin_id
            || position.source_coin_id == position.escrow_coin_id
            || coin.parent_ids.len() > MAX_STAKE_ESCROW_PARENTS
            || unique_parents.len() != coin.parent_ids.len()
            || !parents_are_canonical
            || !coin
                .parent_ids
                .windows(2)
                .all(|pair| pair[0].as_bytes() < pair[1].as_bytes())
            || coin.parent_ids.iter().any(|id| !is_valid_identifier(id))
            || coin
                .parent_ids
                .iter()
                .filter(|id| *id == &position.source_coin_id)
                .count()
                != 1
            || !is_valid_text(&coin.lineage_root, MAX_OWNER_BYTES)
            || coin.zone_id != context.zone_id
            || coin.state != CoinState::Reserved
            || coin.owner != position.owner
            || coin.amount != position.amount
            || coin.created_height as u128 > position.locked_height
            || coin.transit_id.is_some()
            || !is_valid_zone_id(&coin.origin_zone)
            || coin.origin_genesis_root != context.currency_genesis_root
        {
            return Err(StakeEpochDerivationError::EscrowCoinMismatch(
                position.position_id.clone(),
            ));
        }
        if matches!(position.kind, ConsensusStakePositionKind::SelfBond { .. })
            && position.owner != candidate.owner
        {
            return Err(StakeEpochDerivationError::InvalidStakePosition {
                position_id: position.position_id.clone(),
                reason: "SELF_BOND owner does not equal candidate owner".into(),
            });
        }
        let mature_at = position
            .locked_height
            .checked_add(policy.stake_maturity_blocks)
            .ok_or(StakeEpochDerivationError::ArithmeticOverflow)?;
        if mature_at > context.finalized_height
            || position.committed_through_height < required_commitment_height
            || (policy.policy_version == STAKE_EPOCH_DERIVATION_VERSION_V2
                && position.slash_terms.is_none())
        {
            continue;
        }

        let Some(power) = powers.get_mut(validator_id) else {
            return Err(StakeEpochDerivationError::InvalidStakePosition {
                position_id: position.position_id.clone(),
                reason: "stake target disappeared during bounded validation".into(),
            });
        };
        match &position.kind {
            ConsensusStakePositionKind::SelfBond { .. } => {
                power.self_bond = power
                    .self_bond
                    .checked_add(position.amount.0)
                    .ok_or(StakeEpochDerivationError::ArithmeticOverflow)?;
            }
            ConsensusStakePositionKind::Delegation { .. } => {
                if position.amount < policy.minimum_delegation {
                    continue;
                }
                power.delegated_weight = power
                    .delegated_weight
                    .checked_add(position.amount.0)
                    .ok_or(StakeEpochDerivationError::ArithmeticOverflow)?;
            }
        }
        power.unbonding_height = power
            .unbonding_height
            .min(position.committed_through_height);
    }

    for power in powers.values_mut() {
        let weight = power
            .self_bond
            .checked_add(power.delegated_weight)
            .ok_or(StakeEpochDerivationError::ArithmeticOverflow)?;
        power.weight = weight;
    }
    Ok(powers.into_values().collect())
}

fn eligible_candidate_powers<'a>(
    context: &StakeLedgerContextV1,
    policy: &ConsensusStakePolicyV1,
    exit_height: u128,
    required_commitment_height: u128,
    powers: Vec<CandidatePower<'a>>,
    ubo_control: &UboControlMap,
) -> Result<Vec<CandidatePower<'a>>, StakeEpochDerivationError> {
    let mut eligible = Vec::new();
    for mut power in powers {
        let mature_at = power
            .candidate
            .registered_height
            .checked_add(policy.candidate_maturity_blocks)
            .ok_or(StakeEpochDerivationError::ArithmeticOverflow)?;
        if mature_at > context.finalized_height
            || power
                .candidate
                .exit_height
                .is_some_and(|candidate_exit| candidate_exit < exit_height)
            || power.self_bond < policy.minimum_self_bond.0
        {
            continue;
        }
        let Some(control) = ubo_control.validators.get(&power.candidate.validator_id) else {
            continue;
        };
        if control.valid_from_height > context.finalized_height
            || control.challenge_ends_height >= context.finalized_height
            || control.valid_through_height < required_commitment_height
        {
            continue;
        }
        power.control_group.clone_from(&control.control_group);
        eligible.push(power);
    }
    Ok(eligible)
}

#[allow(clippy::too_many_arguments)]
fn build_stake_epoch_liabilities_v2(
    context: &StakeLedgerContextV1,
    policy: &ConsensusStakePolicyV1,
    anchor: &ConsensusEpochAnchor,
    exit_height: u128,
    evidence_deadline_height: u128,
    selected_powers: &[CandidatePower<'_>],
    positions: &[ConsensusStakePosition],
) -> Result<(String, Vec<ConsensusStakeEpochLiabilityV2>), StakeEpochDerivationError> {
    let selected = selected_powers
        .iter()
        .map(|power| (power.candidate.validator_id.as_str(), power.candidate))
        .collect::<BTreeMap<_, _>>();
    let mut liabilities = Vec::new();
    for position in positions {
        let Some(candidate) = selected.get(position.kind.validator_id()) else {
            continue;
        };
        if position.slash_terms.is_none() {
            continue;
        }
        let mature_at = position
            .locked_height
            .checked_add(policy.stake_maturity_blocks)
            .ok_or(StakeEpochDerivationError::ArithmeticOverflow)?;
        if mature_at > context.finalized_height
            || position.committed_through_height < evidence_deadline_height
            || (matches!(position.kind, ConsensusStakePositionKind::Delegation { .. })
                && position.amount < policy.minimum_delegation)
        {
            continue;
        }
        validate_position_slash_terms_v2(context, position)?;
        let slash_terms_commitment = position.slash_terms_commitment_v2().ok_or_else(|| {
            StakeEpochDerivationError::InvalidStakePosition {
                position_id: position.position_id.clone(),
                reason: "v2 liability has no slash-terms commitment".into(),
            }
        })?;
        let mut liability = ConsensusStakeEpochLiabilityV2 {
            consensus_epoch: anchor.consensus_epoch,
            position: position.clone(),
            validator_public_key: candidate.public_key.clone(),
            validator_key_era: candidate.key_era,
            activation_height: anchor.activation_height,
            exit_height,
            evidence_window_blocks: policy.evidence_window_blocks,
            evidence_deadline_height,
            slash_terms_commitment,
            liability_commitment: String::new(),
        };
        liability.liability_commitment = liability.compute_commitment();
        liabilities.push(liability);
    }
    liabilities.sort_by(|left, right| {
        left.position
            .position_id
            .as_bytes()
            .cmp(right.position.position_id.as_bytes())
    });
    let mut parts = Vec::<&[u8]>::with_capacity(liabilities.len() + 1);
    parts.push(b"RLD-CONSENSUS-STAKE-EPOCH-LIABILITY-ROOT-V2");
    for liability in &liabilities {
        parts.push(liability.liability_commitment.as_bytes());
    }
    Ok((hash_parts(&parts), liabilities))
}

/// Selects at most one validator per declared control group before applying
/// the global validator limit. Without this group-first step, one controller
/// could split a minority stake over many slightly larger candidates, occupy
/// every top-N slot, and force the later concentration check to halt an Epoch
/// even though enough independent candidates existed.
fn select_control_group_representatives<'a>(
    powers: Vec<CandidatePower<'a>>,
    maximum_validators: usize,
) -> Vec<CandidatePower<'a>> {
    let mut group_representatives = BTreeMap::<String, CandidatePower<'a>>::new();
    for power in powers {
        match group_representatives.entry(power.control_group.clone()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(power);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let current = entry.get();
                let replace = power.weight > current.weight
                    || (power.weight == current.weight
                        && power.candidate.validator_id.as_bytes()
                            < current.candidate.validator_id.as_bytes());
                if replace {
                    entry.insert(power);
                }
            }
        }
    }

    let mut representatives = group_representatives.into_values().collect::<Vec<_>>();
    representatives.sort_by(|left, right| {
        right.weight.cmp(&left.weight).then_with(|| {
            left.candidate
                .validator_id
                .as_bytes()
                .cmp(right.candidate.validator_id.as_bytes())
        })
    });
    representatives.truncate(maximum_validators);
    representatives
}

fn stake_snapshot_root_v1(
    context: &StakeLedgerContextV1,
    policy: &ConsensusStakePolicyV1,
    anchor: &ConsensusEpochAnchor,
    candidates: &[ValidatorCandidateRecord],
    positions: &[ConsensusStakePosition],
    ubo_control: &UboControlMap,
    coins: &BTreeMap<String, CoinObject>,
) -> Result<String, StakeEpochDerivationError> {
    let bytes = canonical_stake_snapshot_bytes_v1(
        context,
        policy,
        anchor,
        candidates,
        positions,
        ubo_control,
        coins,
    )?;
    Ok(hash_parts(&[b"RLD-LEDGER-STAKE-SNAPSHOT-V1", &bytes]))
}

/// Frozen binary preimage for `stake_snapshot_root`.
///
/// Every nested object uses the `RLDS` envelope, a permanent schema number,
/// strictly increasing field numbers, one-byte type codes, and u32 length
/// framing. Collections carry a u32 count and individually framed members.
/// This function deliberately avoids Serde/JSON so another implementation can
/// reproduce the exact bytes without inheriting Rust data-model choices.
#[allow(clippy::too_many_arguments)]
pub fn canonical_stake_snapshot_bytes_v1(
    context: &StakeLedgerContextV1,
    policy: &ConsensusStakePolicyV1,
    anchor: &ConsensusEpochAnchor,
    candidates: &[ValidatorCandidateRecord],
    positions: &[ConsensusStakePosition],
    ubo_control: &UboControlMap,
    coins: &BTreeMap<String, CoinObject>,
) -> Result<Vec<u8>, StakeEpochDerivationError> {
    let mut canonical_candidates = candidates.iter().collect::<Vec<_>>();
    canonical_candidates.sort_by(|left, right| {
        left.validator_id
            .as_bytes()
            .cmp(right.validator_id.as_bytes())
            .then_with(|| left.public_key.as_bytes().cmp(right.public_key.as_bytes()))
    });
    let mut canonical_positions = positions.iter().collect::<Vec<_>>();
    canonical_positions.sort_by(|left, right| {
        left.position_id
            .as_bytes()
            .cmp(right.position_id.as_bytes())
            .then_with(|| {
                left.escrow_coin_id
                    .as_bytes()
                    .cmp(right.escrow_coin_id.as_bytes())
            })
    });
    let referenced_coins = canonical_positions
        .iter()
        .map(|position| {
            coins.get(&position.escrow_coin_id).ok_or_else(|| {
                StakeEpochDerivationError::EscrowCoinNotFound(position.escrow_coin_id.clone())
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let candidate_items = canonical_candidates
        .into_iter()
        .map(encode_snapshot_candidate)
        .collect::<Result<Vec<_>, _>>()?;
    let position_items = canonical_positions
        .iter()
        .map(|position| encode_snapshot_position(position))
        .collect::<Result<Vec<_>, _>>()?;
    let coin_items = referenced_coins
        .into_iter()
        .map(encode_snapshot_coin)
        .collect::<Result<Vec<_>, _>>()?;

    let mut encoded = SnapshotStructEncoder::new(SNAPSHOT_SCHEMA)?;
    encoded.push_u16(1, STAKE_EPOCH_DERIVATION_VERSION_V1)?;
    encoded.push_struct(2, &encode_snapshot_context(context)?)?;
    encoded.push_struct(3, &encode_snapshot_policy(policy)?)?;
    encoded.push_struct(4, &encode_snapshot_anchor(anchor)?)?;
    encoded.push_struct_list(5, &candidate_items)?;
    encoded.push_struct_list(6, &position_items)?;
    encoded.push_struct(7, &encode_snapshot_ubo_map(ubo_control)?)?;
    encoded.push_struct_list(8, &coin_items)?;
    encoded.finish()
}

struct SnapshotStructEncoder {
    bytes: Vec<u8>,
    fields: u16,
    previous_field: u16,
}

impl SnapshotStructEncoder {
    fn new(schema: u16) -> Result<Self, StakeEpochDerivationError> {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(SNAPSHOT_MAGIC);
        bytes.extend_from_slice(&SNAPSHOT_SCHEMA_VERSION_V1.to_be_bytes());
        bytes.extend_from_slice(&schema.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        ensure_snapshot_size(bytes.len())?;
        Ok(Self {
            bytes,
            fields: 0,
            previous_field: 0,
        })
    }

    fn push(
        &mut self,
        field: u16,
        kind: u8,
        value: &[u8],
    ) -> Result<(), StakeEpochDerivationError> {
        if field == 0 || field <= self.previous_field {
            return Err(StakeEpochDerivationError::CanonicalSnapshotEncoding(
                "snapshot fields are not in strict numeric order".into(),
            ));
        }
        let value_length = u32::try_from(value.len()).map_err(|_| {
            StakeEpochDerivationError::StakeSnapshotTooLarge {
                maximum_bytes: MAX_STAKE_SNAPSHOT_BYTES,
            }
        })?;
        let next_length = self
            .bytes
            .len()
            .checked_add(2 + 1 + 4)
            .and_then(|length| length.checked_add(value.len()))
            .ok_or(StakeEpochDerivationError::ArithmeticOverflow)?;
        ensure_snapshot_size(next_length)?;
        self.bytes.extend_from_slice(&field.to_be_bytes());
        self.bytes.push(kind);
        self.bytes.extend_from_slice(&value_length.to_be_bytes());
        self.bytes.extend_from_slice(value);
        self.fields = self
            .fields
            .checked_add(1)
            .ok_or(StakeEpochDerivationError::ArithmeticOverflow)?;
        self.previous_field = field;
        Ok(())
    }

    fn push_text(&mut self, field: u16, value: &str) -> Result<(), StakeEpochDerivationError> {
        self.push(field, SNAPSHOT_KIND_TEXT, value.as_bytes())
    }

    fn push_u16(&mut self, field: u16, value: u16) -> Result<(), StakeEpochDerivationError> {
        self.push(field, SNAPSHOT_KIND_U16, &value.to_be_bytes())
    }

    fn push_u64(&mut self, field: u16, value: u64) -> Result<(), StakeEpochDerivationError> {
        self.push(field, SNAPSHOT_KIND_U64, &value.to_be_bytes())
    }

    fn push_u128(&mut self, field: u16, value: u128) -> Result<(), StakeEpochDerivationError> {
        self.push(field, SNAPSHOT_KIND_U128, &value.to_be_bytes())
    }

    fn push_amount(&mut self, field: u16, value: Amount) -> Result<(), StakeEpochDerivationError> {
        self.push(field, SNAPSHOT_KIND_AMOUNT, &value.0.to_be_bytes())
    }

    fn push_hex(
        &mut self,
        field: u16,
        kind: u8,
        value: &str,
        expected_bytes: usize,
        label: &'static str,
    ) -> Result<(), StakeEpochDerivationError> {
        let decoded = decode_snapshot_hex(value, expected_bytes, label)?;
        self.push(field, kind, &decoded)
    }

    fn push_optional_u128(
        &mut self,
        field: u16,
        value: Option<u128>,
    ) -> Result<(), StakeEpochDerivationError> {
        let mut encoded = Vec::with_capacity(17);
        encoded.push(u8::from(value.is_some()));
        if let Some(value) = value {
            encoded.extend_from_slice(&value.to_be_bytes());
        }
        self.push(field, SNAPSHOT_KIND_OPTION_U128, &encoded)
    }

    fn push_optional_text(
        &mut self,
        field: u16,
        value: Option<&str>,
    ) -> Result<(), StakeEpochDerivationError> {
        let mut encoded = Vec::new();
        encoded.push(u8::from(value.is_some()));
        if let Some(value) = value {
            let length = u32::try_from(value.len()).map_err(|_| {
                StakeEpochDerivationError::StakeSnapshotTooLarge {
                    maximum_bytes: MAX_STAKE_SNAPSHOT_BYTES,
                }
            })?;
            encoded.extend_from_slice(&length.to_be_bytes());
            encoded.extend_from_slice(value.as_bytes());
        }
        self.push(field, SNAPSHOT_KIND_OPTION_TEXT, &encoded)
    }

    fn push_struct(&mut self, field: u16, value: &[u8]) -> Result<(), StakeEpochDerivationError> {
        self.push(field, SNAPSHOT_KIND_STRUCT, value)
    }

    fn push_struct_list(
        &mut self,
        field: u16,
        values: &[Vec<u8>],
    ) -> Result<(), StakeEpochDerivationError> {
        let encoded = encode_snapshot_list(values.iter().map(Vec::as_slice))?;
        self.push(field, SNAPSHOT_KIND_STRUCT_LIST, &encoded)
    }

    fn push_text_list(
        &mut self,
        field: u16,
        values: &[String],
    ) -> Result<(), StakeEpochDerivationError> {
        let encoded = encode_snapshot_list(values.iter().map(|value| value.as_bytes()))?;
        self.push(field, SNAPSHOT_KIND_TEXT_LIST, &encoded)
    }

    fn finish(mut self) -> Result<Vec<u8>, StakeEpochDerivationError> {
        self.bytes[8..10].copy_from_slice(&self.fields.to_be_bytes());
        ensure_snapshot_size(self.bytes.len())?;
        Ok(self.bytes)
    }
}

fn ensure_snapshot_size(length: usize) -> Result<(), StakeEpochDerivationError> {
    if length > MAX_STAKE_SNAPSHOT_BYTES {
        Err(StakeEpochDerivationError::StakeSnapshotTooLarge {
            maximum_bytes: MAX_STAKE_SNAPSHOT_BYTES,
        })
    } else {
        Ok(())
    }
}

fn encode_snapshot_list<'a>(
    values: impl ExactSizeIterator<Item = &'a [u8]>,
) -> Result<Vec<u8>, StakeEpochDerivationError> {
    let count = u32::try_from(values.len()).map_err(|_| {
        StakeEpochDerivationError::StakeSnapshotTooLarge {
            maximum_bytes: MAX_STAKE_SNAPSHOT_BYTES,
        }
    })?;
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&count.to_be_bytes());
    for value in values {
        let value_length = u32::try_from(value.len()).map_err(|_| {
            StakeEpochDerivationError::StakeSnapshotTooLarge {
                maximum_bytes: MAX_STAKE_SNAPSHOT_BYTES,
            }
        })?;
        let next_length = encoded
            .len()
            .checked_add(4)
            .and_then(|length| length.checked_add(value.len()))
            .ok_or(StakeEpochDerivationError::ArithmeticOverflow)?;
        ensure_snapshot_size(next_length)?;
        encoded.extend_from_slice(&value_length.to_be_bytes());
        encoded.extend_from_slice(value);
    }
    Ok(encoded)
}

fn decode_snapshot_hex(
    value: &str,
    expected_bytes: usize,
    label: &'static str,
) -> Result<Vec<u8>, StakeEpochDerivationError> {
    if !is_canonical_lower_hex(value, expected_bytes) {
        return Err(StakeEpochDerivationError::CanonicalSnapshotEncoding(
            format!("{label} is not canonical lowercase hex"),
        ));
    }
    hex::decode(value).map_err(|error| {
        StakeEpochDerivationError::CanonicalSnapshotEncoding(format!(
            "{label} hex decoding failed: {error}"
        ))
    })
}

fn encode_snapshot_context(
    context: &StakeLedgerContextV1,
) -> Result<Vec<u8>, StakeEpochDerivationError> {
    let mut encoded = SnapshotStructEncoder::new(SNAPSHOT_CONTEXT_SCHEMA)?;
    encoded.push_text(1, &context.network_domain)?;
    encoded.push_text(2, &context.zone_id)?;
    encoded.push_hex(
        3,
        SNAPSHOT_KIND_HASH32,
        &context.currency_genesis_root,
        32,
        "currency genesis root",
    )?;
    encoded.push_u64(4, context.protocol_era)?;
    encoded.push_u64(5, context.crypto_era)?;
    encoded.push_u64(6, context.consensus_protocol_version)?;
    encoded.push_u128(7, context.finalized_height)?;
    encoded.push_hex(
        8,
        SNAPSHOT_KIND_HASH32,
        &context.finalized_state_root,
        32,
        "finalized state root",
    )?;
    encoded.finish()
}

fn encode_snapshot_policy(
    policy: &ConsensusStakePolicyV1,
) -> Result<Vec<u8>, StakeEpochDerivationError> {
    let mut encoded = SnapshotStructEncoder::new(SNAPSHOT_POLICY_SCHEMA)?;
    encoded.push_u16(1, policy.policy_version)?;
    encoded.push_amount(2, policy.minimum_self_bond)?;
    encoded.push_amount(3, policy.minimum_delegation)?;
    encoded.push_u128(4, policy.candidate_maturity_blocks)?;
    encoded.push_u128(5, policy.stake_maturity_blocks)?;
    encoded.push_u128(6, policy.evidence_window_blocks)?;
    encoded.push_u128(7, policy.activation_delay_blocks)?;
    encoded.push_u128(8, policy.epoch_length_blocks)?;
    encoded.push_u16(9, policy.maximum_validators)?;
    encoded.finish()
}

fn encode_snapshot_anchor(
    anchor: &ConsensusEpochAnchor,
) -> Result<Vec<u8>, StakeEpochDerivationError> {
    let mut encoded = SnapshotStructEncoder::new(SNAPSHOT_ANCHOR_SCHEMA)?;
    encoded.push_u64(1, anchor.consensus_epoch)?;
    encoded.push_u128(2, anchor.activation_height)?;
    encoded.push_u128(3, anchor.stake_snapshot_height)?;
    encoded.push_hex(
        4,
        SNAPSHOT_KIND_HASH32,
        &anchor.stake_snapshot_state_root,
        32,
        "anchor state root",
    )?;
    encoded.push_hex(
        5,
        SNAPSHOT_KIND_HASH32,
        &anchor.record_chain_anchor,
        32,
        "record chain anchor",
    )?;
    encoded.finish()
}

fn encode_snapshot_candidate(
    candidate: &ValidatorCandidateRecord,
) -> Result<Vec<u8>, StakeEpochDerivationError> {
    let mut encoded = SnapshotStructEncoder::new(SNAPSHOT_CANDIDATE_SCHEMA)?;
    encoded.push_text(1, &candidate.validator_id)?;
    encoded.push_text(2, &candidate.owner)?;
    encoded.push_hex(
        3,
        SNAPSHOT_KIND_KEY32,
        &candidate.public_key,
        32,
        "candidate public key",
    )?;
    encoded.push_u64(4, candidate.key_era)?;
    encoded.push_u128(5, candidate.registered_height)?;
    encoded.push_optional_u128(6, candidate.exit_height)?;
    encoded.push_hex(
        7,
        SNAPSHOT_KIND_SIGNATURE64,
        &candidate.proof_of_possession,
        64,
        "candidate proof of possession",
    )?;
    encoded.finish()
}

fn encode_snapshot_position(
    position: &ConsensusStakePosition,
) -> Result<Vec<u8>, StakeEpochDerivationError> {
    let schema = if position.slash_terms.is_some() {
        SNAPSHOT_POSITION_V2_SCHEMA
    } else {
        SNAPSHOT_POSITION_SCHEMA
    };
    let mut encoded = SnapshotStructEncoder::new(schema)?;
    encoded.push_text(1, &position.position_id)?;
    let kind = match &position.kind {
        ConsensusStakePositionKind::SelfBond { .. } => 1,
        ConsensusStakePositionKind::Delegation { .. } => 2,
    };
    encoded.push(2, SNAPSHOT_KIND_ENUM_U8, &[kind])?;
    encoded.push_text(3, position.kind.validator_id())?;
    encoded.push_text(4, &position.owner)?;
    encoded.push_text(5, &position.source_coin_id)?;
    encoded.push_text(6, &position.escrow_coin_id)?;
    encoded.push_amount(7, position.amount)?;
    encoded.push_u128(8, position.locked_height)?;
    encoded.push_u128(9, position.committed_through_height)?;
    if let Some(terms) = &position.slash_terms {
        encoded.push_struct(10, &encode_snapshot_slash_terms_v2(terms)?)?;
    }
    encoded.finish()
}

fn encode_snapshot_slash_policy_v2(
    policy: &ConsensusStakeSlashPolicyV2,
) -> Result<Vec<u8>, StakeEpochDerivationError> {
    policy
        .validate()
        .map_err(|reason| StakeEpochDerivationError::CanonicalSnapshotEncoding(reason.into()))?;
    let mut encoded = SnapshotStructEncoder::new(SNAPSHOT_SLASH_POLICY_V2_SCHEMA)?;
    encoded.push_u16(1, policy.policy_version)?;
    encoded.push_u16(2, policy.double_sign_slash_bps)?;
    encoded.push_u16(3, policy.conflicting_checkpoint_slash_bps)?;
    encoded.push_u16(4, policy.invalid_state_commitment_slash_bps)?;
    encoded.push_u16(5, policy.maximum_cumulative_slash_bps)?;
    encoded.push_u16(6, policy.reporter_reward_bps)?;
    encoded.push_text(7, &policy.safety_pool)?;
    encoded.finish()
}

fn encode_snapshot_slash_terms_v2(
    terms: &ConsensusStakeSlashTermsV2,
) -> Result<Vec<u8>, StakeEpochDerivationError> {
    let authorization = &terms.owner_authorization;
    let mut encoded = SnapshotStructEncoder::new(SNAPSHOT_SLASH_TERMS_V2_SCHEMA)?;
    encoded.push_u16(1, terms.terms_version)?;
    encoded.push_struct(2, &encode_snapshot_slash_policy_v2(&terms.slash_policy)?)?;
    encoded.push_text(3, &authorization.authorization_id)?;
    encoded.push_text(4, &authorization.zone_id)?;
    encoded.push_hex(
        5,
        SNAPSHOT_KIND_HASH32,
        &authorization.currency_genesis_root,
        32,
        "slash-terms currency genesis root",
    )?;
    encoded.push_u64(6, authorization.protocol_era)?;
    encoded.push_u64(7, authorization.crypto_era)?;
    encoded.push_hex(
        8,
        SNAPSHOT_KIND_KEY32,
        &authorization.signer_public_key,
        32,
        "slash-terms owner public key",
    )?;
    encoded.push_text(9, &authorization.action)?;
    encoded.push_hex(
        10,
        SNAPSHOT_KIND_HASH32,
        &authorization.payload_hash,
        32,
        "slash-terms payload hash",
    )?;
    encoded.push_u64(11, authorization.nonce)?;
    encoded.push_hex(
        12,
        SNAPSHOT_KIND_SIGNATURE64,
        &authorization.signature,
        64,
        "slash-terms owner signature",
    )?;
    encoded.finish()
}

fn encode_snapshot_ubo_map(
    ubo_control: &UboControlMap,
) -> Result<Vec<u8>, StakeEpochDerivationError> {
    let records = ubo_control
        .validators
        .iter()
        .map(|(validator_id, record)| encode_snapshot_ubo_record(validator_id, record))
        .collect::<Result<Vec<_>, _>>()?;
    let mut encoded = SnapshotStructEncoder::new(SNAPSHOT_UBO_MAP_SCHEMA)?;
    encoded.push_u16(1, ubo_control.map_version)?;
    encoded.push_u64(2, ubo_control.sequence)?;
    encoded.push_hex(
        3,
        SNAPSHOT_KIND_HASH32,
        &ubo_control.predecessor_commitment,
        32,
        "UBO predecessor commitment",
    )?;
    encoded.push_hex(
        4,
        SNAPSHOT_KIND_HASH32,
        &ubo_control.verifier_set_commitment,
        32,
        "UBO verifier-set commitment",
    )?;
    encoded.push_hex(
        5,
        SNAPSHOT_KIND_HASH32,
        &ubo_control.evidence_root,
        32,
        "UBO evidence root",
    )?;
    encoded.push_struct_list(6, &records)?;
    encoded.finish()
}

fn encode_snapshot_ubo_record(
    validator_id: &str,
    record: &UboControlRecord,
) -> Result<Vec<u8>, StakeEpochDerivationError> {
    let mut encoded = SnapshotStructEncoder::new(SNAPSHOT_UBO_RECORD_SCHEMA)?;
    encoded.push_text(1, validator_id)?;
    encoded.push_text(2, &record.control_group)?;
    encoded.push_u128(3, record.valid_from_height)?;
    encoded.push_u128(4, record.challenge_ends_height)?;
    encoded.push_u128(5, record.valid_through_height)?;
    encoded.push_hex(
        6,
        SNAPSHOT_KIND_HASH32,
        &record.evidence_hash,
        32,
        "UBO record evidence hash",
    )?;
    encoded.finish()
}

fn encode_snapshot_coin(coin: &CoinObject) -> Result<Vec<u8>, StakeEpochDerivationError> {
    let state = match coin.state {
        CoinState::Spendable => 1,
        CoinState::Reserved => 2,
        CoinState::InTransit => 3,
        CoinState::Returning => 4,
        CoinState::Quarantined => 5,
        CoinState::Consumed => 6,
    };
    let mut encoded = SnapshotStructEncoder::new(SNAPSHOT_COIN_SCHEMA)?;
    encoded.push_text(1, &coin.object_id)?;
    encoded.push_text(2, &coin.lineage_root)?;
    encoded.push_text_list(3, &coin.parent_ids)?;
    encoded.push_text(4, &coin.owner)?;
    encoded.push_text(5, &coin.zone_id)?;
    encoded.push_amount(6, coin.amount)?;
    encoded.push(7, SNAPSHOT_KIND_ENUM_U8, &[state])?;
    encoded.push_u64(8, coin.version)?;
    encoded.push_u64(9, coin.created_height)?;
    encoded.push_optional_text(10, coin.transit_id.as_deref())?;
    encoded.push_optional_text(11, coin.imported_from.as_deref())?;
    encoded.push_text(12, &coin.origin_zone)?;
    encoded.push_hex(
        13,
        SNAPSHOT_KIND_HASH32,
        &coin.origin_genesis_root,
        32,
        "Coin origin genesis root",
    )?;
    encoded.finish()
}

fn derived_record_hash(
    version: u16,
    status: StakeEpochRecordStatus,
    snapshot_height: u128,
    snapshot_state_root: &str,
    previous_record_hash: &str,
    descriptor_commitment: &str,
    stake_liability_root: &str,
) -> String {
    if version == STAKE_EPOCH_DERIVATION_VERSION_V1 {
        hash_parts(&[
            b"RLD-LEDGER-DERIVED-STAKE-EPOCH-RECORD-V1",
            &version.to_be_bytes(),
            status.wire_name().as_bytes(),
            &snapshot_height.to_be_bytes(),
            snapshot_state_root.as_bytes(),
            previous_record_hash.as_bytes(),
            descriptor_commitment.as_bytes(),
        ])
    } else {
        hash_parts(&[
            b"RLD-LEDGER-DERIVED-STAKE-EPOCH-RECORD-V2",
            &version.to_be_bytes(),
            status.wire_name().as_bytes(),
            &snapshot_height.to_be_bytes(),
            snapshot_state_root.as_bytes(),
            previous_record_hash.as_bytes(),
            descriptor_commitment.as_bytes(),
            stake_liability_root.as_bytes(),
        ])
    }
}

fn zero_hash_string() -> String {
    ZERO_HASH.into()
}

fn is_zero_hash(value: &String) -> bool {
    value == ZERO_HASH
}

fn validate_nonzero_hash(value: &str) -> Result<(), ()> {
    if value != ZERO_HASH
        && value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(())
    }
}

fn is_canonical_lower_hex(value: &str, bytes: usize) -> bool {
    bytes
        .checked_mul(2)
        .is_some_and(|expected_len| value.len() == expected_len)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_valid_zone_id(value: &str) -> bool {
    value.strip_prefix("zone-").is_some_and(|suffix| {
        suffix.len() == 20
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn is_valid_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes.all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
        && value.len() <= MAX_IDENTIFIER_BYTES
}

fn is_valid_text(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.trim() == value
        && value.len() <= maximum_bytes
        && !value.chars().any(char::is_control)
        && value.nfc().collect::<String>() == value
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use crate::{crypto::sign_bytes, CoinState, Ledger, ProtocolReservePools};

    use super::*;

    struct Fixture {
        context: StakeLedgerContextV1,
        policy: ConsensusStakePolicyV1,
        anchor: ConsensusEpochAnchor,
        candidates: Vec<ValidatorCandidateRecord>,
        positions: Vec<ConsensusStakePosition>,
        ubo: UboControlMap,
        coins: BTreeMap<String, CoinObject>,
        secrets: BTreeMap<String, String>,
    }

    impl Fixture {
        fn derive(&self) -> Result<LedgerDerivedStakeEpochV1, StakeEpochDerivationError> {
            derive_ledger_stake_epoch_v1(
                &self.context,
                &self.policy,
                &self.anchor,
                None,
                &self.candidates,
                &self.positions,
                &self.ubo,
                &self.coins,
            )
        }

        fn resign(&mut self, index: usize) {
            let id = self.candidates[index].validator_id.clone();
            let secret = self.secrets[&id].clone();
            self.candidates[index].proof_of_possession = sign_bytes(
                &secret,
                &validator_candidate_pop_message_v1(&self.context, &self.candidates[index]),
            )
            .unwrap();
        }

        fn enable_v2_slash_terms(&mut self) {
            self.policy.policy_version = STAKE_EPOCH_DERIVATION_VERSION_V2;
            for index in 0..self.positions.len() {
                let validator_id = self.positions[index].validator_id().to_owned();
                let candidate_index = self
                    .candidates
                    .iter()
                    .position(|candidate| candidate.validator_id == validator_id)
                    .unwrap();
                let public_key = self.candidates[candidate_index].public_key.clone();
                let owner = format!("rld:{}:{public_key}", self.context.zone_id);
                self.candidates[candidate_index].owner.clone_from(&owner);
                self.positions[index].owner.clone_from(&owner);
                self.coins
                    .get_mut(&self.positions[index].escrow_coin_id)
                    .unwrap()
                    .owner
                    .clone_from(&owner);
                self.resign(candidate_index);

                let payload_hash = self.positions[index].slash_terms_payload_hash_v2();
                let mut authorization = SignedActionAuthorization {
                    authorization_id: format!("slash-terms-{}", self.positions[index].position_id),
                    zone_id: self.context.zone_id.clone(),
                    currency_genesis_root: self.context.currency_genesis_root.clone(),
                    protocol_era: self.context.protocol_era,
                    crypto_era: self.context.crypto_era,
                    signer_public_key: public_key,
                    action: ACCEPT_CONSENSUS_STAKE_SLASH_TERMS_ACTION_V2.into(),
                    payload_hash,
                    nonce: u64::try_from(index + 1).unwrap(),
                    signature: String::new(),
                };
                authorization.signature =
                    sign_bytes(&self.secrets[&validator_id], &authorization.signing_bytes())
                        .unwrap();
                self.positions[index].slash_terms = Some(ConsensusStakeSlashTermsV2 {
                    terms_version: CONSENSUS_STAKE_SLASH_TERMS_VERSION_V2,
                    slash_policy: ConsensusStakeSlashPolicyV2::protocol_v2(),
                    owner_authorization: authorization,
                });
            }
        }
    }

    #[test]
    fn frozen_snapshot_vector_matches_independent_binary_preimage() {
        let bundle: serde_json::Value = serde_json::from_str(include_str!(
            "../../../vectors/stake-epoch-v1/snapshot-encoding.json"
        ))
        .unwrap();
        assert_eq!(bundle["snapshot_encoding_claim"], true);
        for claim in [
            "selection_claim",
            "ledger_authority_claim",
            "runtime_adoption_claim",
            "state_machine_claim",
        ] {
            assert_eq!(bundle[claim], false, "{claim} must remain false");
        }

        for case in bundle["cases"].as_array().unwrap() {
            let context: StakeLedgerContextV1 =
                serde_json::from_value(case["context"].clone()).unwrap();
            let policy: ConsensusStakePolicyV1 =
                serde_json::from_value(case["policy"].clone()).unwrap();
            let anchor: ConsensusEpochAnchor =
                serde_json::from_value(case["anchor"].clone()).unwrap();
            let candidates: Vec<ValidatorCandidateRecord> =
                serde_json::from_value(case["candidates"].clone()).unwrap();
            let positions: Vec<ConsensusStakePosition> =
                serde_json::from_value(case["positions"].clone()).unwrap();
            let ubo_control: UboControlMap =
                serde_json::from_value(case["ubo_control"].clone()).unwrap();
            let coins: BTreeMap<String, CoinObject> =
                serde_json::from_value(case["coins"].clone()).unwrap();
            let encoded = canonical_stake_snapshot_bytes_v1(
                &context,
                &policy,
                &anchor,
                &candidates,
                &positions,
                &ubo_control,
                &coins,
            )
            .unwrap();
            assert_eq!(
                hex::encode(&encoded),
                case["expected_preimage_hex"].as_str().unwrap(),
                "{} preimage",
                case["name"].as_str().unwrap()
            );
            assert_eq!(
                hash_parts(&[b"RLD-LEDGER-STAKE-SNAPSHOT-V1", &encoded]),
                case["expected_stake_snapshot_root"].as_str().unwrap(),
                "{} root",
                case["name"].as_str().unwrap()
            );
        }
    }

    fn fixture(count: usize, network_domain: &str) -> Fixture {
        let context = StakeLedgerContextV1 {
            network_domain: network_domain.into(),
            zone_id: "zone-0123456789abcdefabcd".into(),
            currency_genesis_root: "11".repeat(32),
            protocol_era: 3,
            crypto_era: 4,
            consensus_protocol_version: 1,
            finalized_height: 1_000,
            finalized_state_root: "22".repeat(32),
        };
        let policy = ConsensusStakePolicyV1 {
            policy_version: 1,
            minimum_self_bond: Amount::from_runlai(10),
            minimum_delegation: Amount::from_runlai(1),
            candidate_maturity_blocks: 10,
            stake_maturity_blocks: 10,
            evidence_window_blocks: 20,
            activation_delay_blocks: 100,
            epoch_length_blocks: 100,
            maximum_validators: u16::try_from(count).unwrap(),
        };
        let anchor = ConsensusEpochAnchor {
            consensus_epoch: 7,
            activation_height: 1_100,
            stake_snapshot_height: context.finalized_height,
            stake_snapshot_state_root: context.finalized_state_root.clone(),
            record_chain_anchor: "33".repeat(32),
        };
        let mut candidates = Vec::new();
        let mut positions = Vec::new();
        let mut controls = BTreeMap::new();
        let mut coins = BTreeMap::new();
        let mut secrets = BTreeMap::new();
        for index in 0..count {
            let seed = u8::try_from(index + 1).unwrap();
            let signing_key = SigningKey::from_bytes(&[seed; 32]);
            let validator_id = format!("validator-{index:04}");
            let public_key = hex::encode(signing_key.verifying_key().to_bytes());
            let secret_key = hex::encode(signing_key.to_bytes());
            let owner = format!("owner-{index:04}");
            let mut candidate = ValidatorCandidateRecord {
                validator_id: validator_id.clone(),
                owner: owner.clone(),
                public_key,
                key_era: context.crypto_era,
                registered_height: 900,
                exit_height: None,
                proof_of_possession: String::new(),
            };
            candidate.proof_of_possession = sign_bytes(
                &secret_key,
                &validator_candidate_pop_message_v1(&context, &candidate),
            )
            .unwrap();
            let position_id = format!("stake-{index:04}");
            let source_coin_id = format!("source-{index:04}");
            let escrow_coin_id = format!("coin-{index:04}");
            positions.push(ConsensusStakePosition {
                position_id,
                kind: ConsensusStakePositionKind::SelfBond {
                    validator_id: validator_id.clone(),
                },
                owner: owner.clone(),
                source_coin_id: source_coin_id.clone(),
                escrow_coin_id: escrow_coin_id.clone(),
                amount: Amount::from_runlai(10),
                locked_height: 900,
                committed_through_height: 1_400,
                slash_terms: None,
            });
            coins.insert(
                escrow_coin_id.clone(),
                CoinObject {
                    object_id: escrow_coin_id,
                    lineage_root: format!("lineage-{index:04}"),
                    parent_ids: vec![source_coin_id],
                    owner,
                    zone_id: context.zone_id.clone(),
                    amount: Amount::from_runlai(10),
                    state: CoinState::Reserved,
                    version: 1,
                    created_height: 900,
                    transit_id: None,
                    imported_from: None,
                    origin_zone: context.zone_id.clone(),
                    origin_genesis_root: context.currency_genesis_root.clone(),
                },
            );
            controls.insert(
                validator_id.clone(),
                UboControlRecord {
                    control_group: format!("group-{index:04}"),
                    valid_from_height: 800,
                    challenge_ends_height: 900,
                    valid_through_height: 1_500,
                    evidence_hash: format!("{:064x}", index + 100),
                },
            );
            secrets.insert(validator_id, secret_key);
            candidates.push(candidate);
        }
        Fixture {
            context,
            policy,
            anchor,
            candidates,
            positions,
            ubo: UboControlMap {
                map_version: 1,
                sequence: 1,
                predecessor_commitment: "45".repeat(32),
                verifier_set_commitment: "46".repeat(32),
                evidence_root: "44".repeat(32),
                validators: controls,
            },
            coins,
            secrets,
        }
    }

    #[test]
    fn valid_derivation_is_coin_backed_canonical_and_derived_only() {
        let mut fixture = fixture(5, RLDCOIN_TESTNET_DOMAIN);
        fixture.policy.maximum_validators = 4;
        fixture.positions[4].amount = Amount::from_runlai(11);
        fixture.coins.get_mut("coin-0004").unwrap().amount = Amount::from_runlai(11);

        let record = fixture.derive().unwrap();
        assert_eq!(record.status, StakeEpochRecordStatus::DerivedOnly);
        assert_eq!(record.descriptor.validators.len(), 4);
        assert!(record
            .descriptor
            .validators
            .windows(2)
            .all(|pair| pair[0].validator_id < pair[1].validator_id));
        assert!(record
            .descriptor
            .validators
            .iter()
            .any(|validator| validator.validator_id == "validator-0004"));
        assert!(!record
            .descriptor
            .validators
            .iter()
            .any(|validator| validator.validator_id == "validator-0003"));
        validate_ledger_derived_stake_epoch_v1(&record).unwrap();
    }

    #[test]
    fn v2_derivation_freezes_exact_owner_signed_position_liabilities() {
        let mut fixture = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        fixture.enable_v2_slash_terms();

        let record = fixture.derive().unwrap();
        assert_eq!(record.derivation_version, STAKE_EPOCH_DERIVATION_VERSION_V2);
        assert_ne!(record.stake_liability_root, ZERO_HASH);
        assert_eq!(record.stake_liabilities.len(), fixture.positions.len());
        for liability in &record.stake_liabilities {
            let validator = record
                .descriptor
                .validators
                .iter()
                .find(|validator| validator.validator_id == liability.position.validator_id())
                .unwrap();
            assert_eq!(liability.validator_public_key, validator.public_key);
            assert_eq!(liability.validator_key_era, validator.key_era);
            assert_eq!(
                liability.evidence_deadline_height,
                record.descriptor.exit_height + fixture.policy.evidence_window_blocks
            );
            assert_eq!(
                liability.position.slash_terms_commitment_v2().as_deref(),
                Some(liability.slash_terms_commitment.as_str())
            );
        }
        validate_ledger_derived_stake_epoch_v1(&record).unwrap();
        let round_trip: LedgerDerivedStakeEpochV1 =
            serde_json::from_value(serde_json::to_value(&record).unwrap()).unwrap();
        assert_eq!(round_trip, record);

        let mut legacy_position = fixture;
        legacy_position.positions[0].slash_terms = None;
        assert!(matches!(
            legacy_position.derive(),
            Err(StakeEpochDerivationError::InsufficientValidators { .. })
        ));
    }

    #[test]
    fn v2_liability_tampering_fails_strict_deserialization() {
        let mut fixture = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        fixture.enable_v2_slash_terms();
        let record = fixture.derive().unwrap();

        let mut amount = record.clone();
        amount.stake_liabilities[0].position.amount = Amount::from_runlai(11);
        assert!(serde_json::from_value::<LedgerDerivedStakeEpochV1>(
            serde_json::to_value(amount).unwrap()
        )
        .is_err());

        let mut owner = record.clone();
        owner.stake_liabilities[0].position.owner = "rld:forged-owner".into();
        assert!(serde_json::from_value::<LedgerDerivedStakeEpochV1>(
            serde_json::to_value(owner).unwrap()
        )
        .is_err());

        let mut key = record.clone();
        key.stake_liabilities[0].validator_public_key = "aa".repeat(32);
        assert!(serde_json::from_value::<LedgerDerivedStakeEpochV1>(
            serde_json::to_value(key).unwrap()
        )
        .is_err());

        let mut deadline = record.clone();
        deadline.stake_liabilities[0].evidence_deadline_height += 1;
        assert!(serde_json::from_value::<LedgerDerivedStakeEpochV1>(
            serde_json::to_value(deadline).unwrap()
        )
        .is_err());

        let mut root = record;
        root.stake_liability_root = "99".repeat(32);
        assert!(serde_json::from_value::<LedgerDerivedStakeEpochV1>(
            serde_json::to_value(root).unwrap()
        )
        .is_err());
    }

    #[test]
    fn legacy_v1_records_make_no_slash_liability_claim() {
        let record = fixture(4, RLDCOIN_TESTNET_DOMAIN).derive().unwrap();
        assert_eq!(record.derivation_version, STAKE_EPOCH_DERIVATION_VERSION_V1);
        assert_eq!(record.stake_liability_root, ZERO_HASH);
        assert!(record.stake_liabilities.is_empty());
        let json = serde_json::to_value(&record).unwrap();
        assert!(json.get("stake_liability_root").is_none());
        assert!(json.get("stake_liabilities").is_none());
        validate_ledger_derived_stake_epoch_v1(&record).unwrap();
    }

    #[test]
    fn minority_control_group_aliases_cannot_fill_the_global_validator_limit() {
        let mut fixture = fixture(7, RLDCOIN_TESTNET_DOMAIN);
        fixture.policy.maximum_validators = 4;
        for index in 0..3 {
            fixture.positions[index].amount = Amount::from_runlai(11);
            fixture
                .coins
                .get_mut(&format!("coin-{index:04}"))
                .unwrap()
                .amount = Amount::from_runlai(11);
            fixture
                .ubo
                .validators
                .get_mut(&format!("validator-{index:04}"))
                .unwrap()
                .control_group = "minority-split-group".into();
        }

        let record = fixture.derive().unwrap();
        assert_eq!(record.descriptor.validators.len(), 4);
        assert_eq!(
            record
                .descriptor
                .validators
                .iter()
                .filter(|validator| validator.control_group == "minority-split-group")
                .count(),
            1
        );
        assert!(record
            .descriptor
            .validators
            .iter()
            .any(|validator| validator.validator_id == "validator-0000"));
        assert!(!record
            .descriptor
            .validators
            .iter()
            .any(|validator| validator.validator_id == "validator-0001"));
        assert!(!record
            .descriptor
            .validators
            .iter()
            .any(|validator| validator.validator_id == "validator-0002"));
    }

    #[test]
    fn coin_mismatch_and_duplicate_escrow_are_rejected() {
        let mut mismatched = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        mismatched.coins.get_mut("coin-0000").unwrap().owner = "wrong-owner".into();
        assert!(matches!(
            mismatched.derive(),
            Err(StakeEpochDerivationError::EscrowCoinMismatch(_))
        ));

        let mut duplicate = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        duplicate.positions[1].escrow_coin_id = duplicate.positions[0].escrow_coin_id.clone();
        duplicate.positions[1].owner = duplicate.positions[0].owner.clone();
        assert!(matches!(
            duplicate.derive(),
            Err(StakeEpochDerivationError::DuplicateEscrowCoin(_))
        ));
    }

    #[test]
    fn maturity_exit_and_unbonding_window_are_enforced() {
        let mut immature = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        immature.positions[0].locked_height = 995;
        assert!(matches!(
            immature.derive(),
            Err(StakeEpochDerivationError::InsufficientValidators { .. })
        ));

        let mut candidate_exit = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        candidate_exit.candidates[0].exit_height = Some(1_199);
        candidate_exit.resign(0);
        assert!(matches!(
            candidate_exit.derive(),
            Err(StakeEpochDerivationError::InsufficientValidators { .. })
        ));

        let mut early_unlock = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        early_unlock.positions[0].committed_through_height = 1_219;
        assert!(matches!(
            early_unlock.derive(),
            Err(StakeEpochDerivationError::InsufficientValidators { .. })
        ));
    }

    #[test]
    fn ubo_coverage_validity_and_concentration_are_enforced() {
        let mut missing = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        missing.ubo.validators.remove("validator-0000");
        assert!(matches!(
            missing.derive(),
            Err(StakeEpochDerivationError::InsufficientValidators { .. })
        ));

        let mut expired = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        expired
            .ubo
            .validators
            .get_mut("validator-0000")
            .unwrap()
            .valid_through_height = 1_219;
        assert!(matches!(
            expired.derive(),
            Err(StakeEpochDerivationError::InsufficientValidators { .. })
        ));

        let mut unchallenged = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        unchallenged
            .ubo
            .validators
            .get_mut("validator-0000")
            .unwrap()
            .challenge_ends_height = unchallenged.context.finalized_height;
        assert!(matches!(
            unchallenged.derive(),
            Err(StakeEpochDerivationError::InsufficientValidators { .. })
        ));

        let mut concentrated = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        for control in concentrated.ubo.validators.values_mut() {
            control.control_group = "one-controller".into();
        }
        assert!(matches!(
            concentrated.derive(),
            Err(StakeEpochDerivationError::InsufficientValidators { .. })
        ));
    }

    #[test]
    fn later_epoch_requires_exact_sequence_activation_and_record_chain() {
        let first_fixture = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        let first = first_fixture.derive().unwrap();

        let mut next = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        next.context.finalized_height = 1_100;
        next.context.finalized_state_root = "55".repeat(32);
        next.anchor.consensus_epoch = first.descriptor.consensus_epoch + 1;
        next.anchor.activation_height = first.descriptor.exit_height;
        next.anchor.stake_snapshot_height = next.context.finalized_height;
        next.anchor.stake_snapshot_state_root = next.context.finalized_state_root.clone();
        next.anchor.record_chain_anchor = first.record_hash.clone();
        let second = derive_ledger_stake_epoch_v1(
            &next.context,
            &next.policy,
            &next.anchor,
            Some(&first),
            &next.candidates,
            &next.positions,
            &next.ubo,
            &next.coins,
        )
        .unwrap();
        assert_eq!(second.previous_record_hash, first.record_hash);

        next.anchor.consensus_epoch += 1;
        assert_eq!(
            derive_ledger_stake_epoch_v1(
                &next.context,
                &next.policy,
                &next.anchor,
                Some(&first),
                &next.candidates,
                &next.positions,
                &next.ubo,
                &next.coins,
            ),
            Err(StakeEpochDerivationError::NonContiguousEpoch)
        );
    }

    #[test]
    fn changes_in_each_authoritative_input_class_change_the_record_hash() {
        let baseline_fixture = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        let baseline = baseline_fixture.derive().unwrap().record_hash;

        let mut changed = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        changed.context.finalized_state_root = "66".repeat(32);
        changed.anchor.stake_snapshot_state_root = changed.context.finalized_state_root.clone();
        assert_ne!(changed.derive().unwrap().record_hash, baseline);

        let mut changed = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        changed.policy.candidate_maturity_blocks += 1;
        assert_ne!(changed.derive().unwrap().record_hash, baseline);

        let mut changed = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        changed.anchor.record_chain_anchor = "77".repeat(32);
        assert_ne!(changed.derive().unwrap().record_hash, baseline);

        let mut changed = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        changed.candidates[0].owner = "replacement-owner".into();
        changed.positions[0].owner = "replacement-owner".into();
        changed.coins.get_mut("coin-0000").unwrap().owner = "replacement-owner".into();
        changed.resign(0);
        assert_ne!(changed.derive().unwrap().record_hash, baseline);

        let mut changed = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        changed.positions[0].position_id = "stake-replaced".into();
        assert_ne!(changed.derive().unwrap().record_hash, baseline);

        let mut changed = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        changed
            .ubo
            .validators
            .get_mut("validator-0000")
            .unwrap()
            .evidence_hash = "88".repeat(32);
        assert_ne!(changed.derive().unwrap().record_hash, baseline);

        let mut changed = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        changed.coins.get_mut("coin-0000").unwrap().lineage_root = "changed-lineage".into();
        assert_ne!(changed.derive().unwrap().record_hash, baseline);
    }

    #[test]
    fn checked_overflow_and_member_bounds_fail_closed() {
        let mut overflow = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        overflow.context.finalized_height = u128::MAX - 150;
        overflow.anchor.stake_snapshot_height = overflow.context.finalized_height;
        overflow.anchor.activation_height = u128::MAX - 50;
        assert_eq!(
            overflow.derive(),
            Err(StakeEpochDerivationError::ArithmeticOverflow)
        );

        let too_few = fixture(3, RLDCOIN_TESTNET_DOMAIN);
        assert_eq!(
            too_few.derive(),
            Err(StakeEpochDerivationError::InvalidPolicy(
                "maximum validator count is outside network bounds"
            ))
        );

        let mainnet_too_few = fixture(4, RLDCOIN_MAINNET_DOMAIN);
        assert_eq!(
            mainnet_too_few.derive(),
            Err(StakeEpochDerivationError::InvalidPolicy(
                "maximum validator count is outside network bounds"
            ))
        );

        let mainnet_minimum = fixture(21, RLDCOIN_MAINNET_DOMAIN);
        assert_eq!(
            mainnet_minimum
                .derive()
                .unwrap()
                .descriptor
                .validators
                .len(),
            21
        );

        let mut too_many = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        too_many.policy.maximum_validators = 4_097;
        assert!(matches!(
            too_many.derive(),
            Err(StakeEpochDerivationError::InvalidPolicy(_))
        ));
    }

    #[test]
    fn bad_pop_and_non_direct_delegation_fail_closed() {
        let mut bad_pop = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        bad_pop.candidates[0].proof_of_possession =
            bad_pop.candidates[1].proof_of_possession.clone();
        assert!(matches!(
            bad_pop.derive(),
            Err(StakeEpochDerivationError::InvalidProofOfPossession { .. })
        ));

        let mut indirect = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        indirect.positions[0].kind = ConsensusStakePositionKind::Delegation {
            validator_id: "stake-0001".into(),
        };
        assert!(matches!(
            indirect.derive(),
            Err(StakeEpochDerivationError::InvalidStakePosition { .. })
        ));
    }

    #[test]
    fn direct_delegation_is_coin_backed_and_counted_once() {
        let mut fixture = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        fixture.positions.push(ConsensusStakePosition {
            position_id: "delegation-0000".into(),
            kind: ConsensusStakePositionKind::Delegation {
                validator_id: "validator-0000".into(),
            },
            owner: "delegator-0000".into(),
            source_coin_id: "delegation-source-0000".into(),
            escrow_coin_id: "delegation-coin-0000".into(),
            amount: Amount::from_runlai(1),
            locked_height: 900,
            committed_through_height: 1_400,
            slash_terms: None,
        });
        fixture.coins.insert(
            "delegation-coin-0000".into(),
            CoinObject {
                object_id: "delegation-coin-0000".into(),
                lineage_root: "delegation-lineage-0000".into(),
                parent_ids: vec!["delegation-source-0000".into()],
                owner: "delegator-0000".into(),
                zone_id: fixture.context.zone_id.clone(),
                amount: Amount::from_runlai(1),
                state: CoinState::Reserved,
                version: 1,
                created_height: 900,
                transit_id: None,
                imported_from: None,
                origin_zone: fixture.context.zone_id.clone(),
                origin_genesis_root: fixture.context.currency_genesis_root.clone(),
            },
        );

        let record = fixture.derive().unwrap();
        let validator = record
            .descriptor
            .validators
            .iter()
            .find(|validator| validator.validator_id == "validator-0000")
            .unwrap();
        assert_eq!(validator.self_bond, 10);
        assert_eq!(validator.delegated_weight, 1);
        assert_eq!(validator.weight, 11);

        fixture.policy.minimum_delegation = Amount::from_runlai(2);
        let dust_filtered = fixture.derive().unwrap();
        let validator = dust_filtered
            .descriptor
            .validators
            .iter()
            .find(|validator| validator.validator_id == "validator-0000")
            .unwrap();
        assert_eq!(validator.delegated_weight, 0);
        assert_eq!(validator.weight, 10);
    }

    #[test]
    fn insertion_order_does_not_change_snapshot_or_record() {
        let baseline = fixture(4, RLDCOIN_TESTNET_DOMAIN).derive().unwrap();
        let mut reordered = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        reordered.candidates.reverse();
        reordered.positions.reverse();
        let reordered = reordered.derive().unwrap();
        assert_eq!(
            reordered.descriptor.stake_snapshot_root,
            baseline.descriptor.stake_snapshot_root
        );
        assert_eq!(
            reordered.descriptor_commitment,
            baseline.descriptor_commitment
        );
        assert_eq!(reordered.record_hash, baseline.record_hash);
    }

    #[test]
    fn pending_or_expiring_candidates_are_filtered_without_stalling_epoch() {
        let mut pending = fixture(5, RLDCOIN_TESTNET_DOMAIN);
        pending.policy.maximum_validators = 4;
        pending.candidates[0].registered_height = 995;
        pending.resign(0);
        pending.ubo.validators.remove("validator-0000");

        let record = pending.derive().unwrap();
        assert_eq!(record.descriptor.validators.len(), 4);
        assert!(!record
            .descriptor
            .validators
            .iter()
            .any(|validator| validator.validator_id == "validator-0000"));
    }

    #[test]
    fn source_coin_and_currency_lineage_are_unique_and_bound() {
        let mut duplicate_source = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        duplicate_source.positions[1].source_coin_id =
            duplicate_source.positions[0].source_coin_id.clone();
        duplicate_source
            .coins
            .get_mut("coin-0001")
            .unwrap()
            .parent_ids = vec![duplicate_source.positions[0].source_coin_id.clone()];
        assert!(matches!(
            duplicate_source.derive(),
            Err(StakeEpochDerivationError::InvalidStakePosition { .. })
        ));

        let mut foreign_currency = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        foreign_currency
            .coins
            .get_mut("coin-0000")
            .unwrap()
            .origin_genesis_root = "99".repeat(32);
        assert!(matches!(
            foreign_currency.derive(),
            Err(StakeEpochDerivationError::EscrowCoinMismatch(_))
        ));

        let mut noncanonical_parents = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        noncanonical_parents
            .coins
            .get_mut("coin-0000")
            .unwrap()
            .parent_ids = vec!["source-0000".into(), "earlier-parent".into()];
        assert!(matches!(
            noncanonical_parents.derive(),
            Err(StakeEpochDerivationError::EscrowCoinMismatch(_))
        ));
    }

    #[test]
    fn first_activation_and_successor_context_are_not_caller_selectable() {
        let mut early = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        early.anchor.activation_height -= 1;
        assert_eq!(
            early.derive(),
            Err(StakeEpochDerivationError::InvalidAnchor(
                "snapshot height does not equal activation minus policy delay"
            ))
        );

        let first = fixture(4, RLDCOIN_TESTNET_DOMAIN).derive().unwrap();
        let mut malformed_previous = first.clone();
        malformed_previous.stake_snapshot_height = malformed_previous.descriptor.activation_height;
        malformed_previous.record_hash = derived_record_hash(
            malformed_previous.derivation_version,
            malformed_previous.status,
            malformed_previous.stake_snapshot_height,
            &malformed_previous.stake_snapshot_state_root,
            &malformed_previous.previous_record_hash,
            &malformed_previous.descriptor_commitment,
            &malformed_previous.stake_liability_root,
        );
        assert!(matches!(
            validate_ledger_derived_stake_epoch_v1(&malformed_previous),
            Err(StakeEpochDerivationError::InvalidPreviousEpoch(_))
        ));

        let mut successor = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        successor.context.finalized_height = 1_100;
        successor.context.finalized_state_root = "55".repeat(32);
        successor.context.zone_id = "zone-ffffffffffffffffffff".into();
        successor.anchor.consensus_epoch = first.descriptor.consensus_epoch + 1;
        successor.anchor.activation_height = first.descriptor.exit_height;
        successor.anchor.stake_snapshot_height = successor.context.finalized_height;
        successor.anchor.stake_snapshot_state_root = successor.context.finalized_state_root.clone();
        successor.anchor.record_chain_anchor = first.record_hash.clone();
        assert!(matches!(
            derive_ledger_stake_epoch_v1(
                &successor.context,
                &successor.policy,
                &successor.anchor,
                Some(&first),
                &successor.candidates,
                &successor.positions,
                &successor.ubo,
                &successor.coins,
            ),
            Err(StakeEpochDerivationError::InvalidAnchor(_))
        ));
    }

    #[test]
    fn mainnet_requires_21_distinct_asserted_control_groups() {
        let mut mainnet = fixture(21, RLDCOIN_MAINNET_DOMAIN);
        let duplicate_group = mainnet.ubo.validators["validator-0000"]
            .control_group
            .clone();
        mainnet
            .ubo
            .validators
            .get_mut("validator-0001")
            .unwrap()
            .control_group = duplicate_group;
        assert_eq!(
            mainnet.derive(),
            Err(StakeEpochDerivationError::InsufficientControlGroups {
                minimum: MIN_MAINNET_STAKE_VALIDATORS
            })
        );
    }

    #[test]
    fn ubo_chain_metadata_and_input_limits_fail_closed() {
        let mut zero_sequence = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        zero_sequence.ubo.sequence = 0;
        assert!(matches!(
            zero_sequence.derive(),
            Err(StakeEpochDerivationError::InvalidUboControl { .. })
        ));

        let fixture = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        let excessive_candidates =
            vec![fixture.candidates[0].clone(); MAX_STAKE_CANDIDATE_RECORDS + 1];
        assert_eq!(
            derive_ledger_stake_epoch_v1(
                &fixture.context,
                &fixture.policy,
                &fixture.anchor,
                None,
                &excessive_candidates,
                &fixture.positions,
                &fixture.ubo,
                &fixture.coins,
            ),
            Err(StakeEpochDerivationError::InputLimitExceeded {
                collection: "validator candidates",
                actual: MAX_STAKE_CANDIDATE_RECORDS + 1,
                maximum: MAX_STAKE_CANDIDATE_RECORDS,
            })
        );

        assert_eq!(
            ensure_snapshot_size(MAX_STAKE_SNAPSHOT_BYTES + 1),
            Err(StakeEpochDerivationError::StakeSnapshotTooLarge {
                maximum_bytes: MAX_STAKE_SNAPSHOT_BYTES
            })
        );
    }

    fn ledger_authority_fixture() -> (Ledger, LedgerStakeAuthorityUpdateV1) {
        let mut fixture = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        let validator_keys = fixture
            .candidates
            .iter()
            .map(|candidate| candidate.public_key.clone())
            .collect::<Vec<_>>();
        let mut ledger = Ledger::new(
            "stake-authority-test",
            Amount::from_runlai(40),
            validator_keys,
            Vec::new(),
            true,
        )
        .unwrap();
        ledger.height = 1_000;
        ledger.reserve = Amount::ZERO;
        ledger.reserve_pools = ProtocolReservePools::default();

        fixture.context = StakeLedgerContextV1 {
            network_domain: ledger.descriptor.network_domain.clone(),
            zone_id: ledger.descriptor.zone_id.clone(),
            currency_genesis_root: ledger.descriptor.currency_genesis_root.clone(),
            protocol_era: ledger.descriptor.protocol_era,
            crypto_era: ledger.descriptor.crypto_era,
            consensus_protocol_version: CONSENSUS_PROTOCOL_VERSION_V1,
            finalized_height: u128::from(ledger.height),
            finalized_state_root: String::new(),
        };
        for index in 0..fixture.candidates.len() {
            fixture.candidates[index].key_era = fixture.context.crypto_era;
            fixture.resign(index);
        }
        for coin in fixture.coins.values_mut() {
            coin.zone_id.clone_from(&fixture.context.zone_id);
            coin.origin_zone.clone_from(&fixture.context.zone_id);
            coin.origin_genesis_root
                .clone_from(&fixture.context.currency_genesis_root);
        }
        ledger.coins = fixture.coins;
        for position in &fixture.positions {
            let escrow = ledger.coins[&position.escrow_coin_id].clone();
            ledger.coins.insert(
                position.source_coin_id.clone(),
                CoinObject {
                    object_id: position.source_coin_id.clone(),
                    lineage_root: escrow.lineage_root,
                    parent_ids: Vec::new(),
                    owner: position.owner.clone(),
                    zone_id: ledger.descriptor.zone_id.clone(),
                    amount: position.amount,
                    state: CoinState::Consumed,
                    version: 0,
                    created_height: 899,
                    transit_id: None,
                    imported_from: None,
                    origin_zone: ledger.descriptor.zone_id.clone(),
                    origin_genesis_root: ledger.descriptor.currency_genesis_root.clone(),
                },
            );
            ledger
                .consensus_stake_escrows
                .insert(position.escrow_coin_id.clone(), position.clone());
        }
        ledger.assert_conservation().unwrap();
        fixture.context.finalized_state_root = ledger.state_root().unwrap();

        let update = LedgerStakeAuthorityUpdateV1 {
            authority_version: STAKE_AUTHORITY_STATE_VERSION_V1,
            sequence: 1,
            expected_previous_commitment: ledger_stake_authority_genesis_anchor_v1(
                &fixture.context,
            ),
            policy: fixture.policy,
            candidates: fixture.candidates,
            positions: fixture.positions,
            ubo_control: fixture.ubo,
        };
        (ledger, update)
    }

    #[test]
    fn ledger_owns_canonical_stake_authority_and_round_trips_it() {
        let (mut ledger, mut update) = ledger_authority_fixture();
        update.candidates.reverse();
        update.positions.reverse();
        let before = ledger.state_root().unwrap();

        let state = ledger.stage_ledger_stake_authority(update).unwrap();
        assert_eq!(state.status, StakeAuthorityStateStatus::StagedOnly);
        assert_eq!(state.source_height, 1_000);
        assert_eq!(state.effective_height, 1_001);
        assert_eq!(ledger.height, 1_001);
        assert_ne!(ledger.state_root().unwrap(), before);
        assert!(state
            .candidates
            .windows(2)
            .all(|pair| pair[0].validator_id < pair[1].validator_id));
        assert!(state
            .positions
            .windows(2)
            .all(|pair| pair[0].position_id < pair[1].position_id));
        validate_ledger_stake_authority_state_v1(&state).unwrap();
        ledger.assert_conservation().unwrap();

        let encoded = serde_json::to_vec(&ledger).unwrap();
        let recovered: Ledger = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(
            recovered.state_root().unwrap(),
            ledger.state_root().unwrap()
        );
        assert_eq!(recovered.consensus_stake_authority, Some(state));

        let mut tampered = serde_json::to_value(&ledger).unwrap();
        tampered["consensus_stake_authority"]["commitment"] =
            serde_json::Value::String("99".repeat(32));
        assert!(serde_json::from_value::<Ledger>(tampered).is_err());
    }

    #[test]
    fn authority_predecessor_and_ubo_chains_fail_atomically() {
        let (mut ledger, update) = ledger_authority_fixture();
        let before_root = ledger.state_root().unwrap();
        let before_height = ledger.height;
        let mut bad = update.clone();
        bad.expected_previous_commitment = "88".repeat(32);
        assert!(ledger.stage_ledger_stake_authority(bad).is_err());
        assert_eq!(ledger.height, before_height);
        assert_eq!(ledger.state_root().unwrap(), before_root);

        let first = ledger.stage_ledger_stake_authority(update.clone()).unwrap();
        let mut second = update;
        second.sequence = 2;
        second.expected_previous_commitment = first.commitment.clone();
        second.ubo_control.sequence = first.ubo_control.sequence + 1;
        second.ubo_control.predecessor_commitment =
            ubo_control_commitment_v1(&first.ubo_control).unwrap();
        let foreign_context = StakeLedgerContextV1 {
            network_domain: ledger.descriptor.network_domain.clone(),
            zone_id: "zone-ffffffffffffffffffff".into(),
            currency_genesis_root: ledger.descriptor.currency_genesis_root.clone(),
            protocol_era: ledger.descriptor.protocol_era,
            crypto_era: ledger.descriptor.crypto_era,
            consensus_protocol_version: CONSENSUS_PROTOCOL_VERSION_V1,
            finalized_height: u128::from(ledger.height),
            finalized_state_root: ledger.state_root().unwrap(),
        };
        assert!(matches!(
            build_ledger_stake_authority_state_v1(
                &foreign_context,
                foreign_context.finalized_height + 1,
                Some(&first),
                second.clone(),
                &ledger.coins,
            ),
            Err(StakeEpochDerivationError::InvalidAuthorityTransition(_))
        ));
        let second_state = ledger.stage_ledger_stake_authority(second.clone()).unwrap();
        assert_eq!(second_state.previous_commitment, first.commitment);

        let before_root = ledger.state_root().unwrap();
        let before_height = ledger.height;
        second.sequence = 4;
        second.expected_previous_commitment = second_state.commitment;
        second.ubo_control.sequence += 1;
        second.ubo_control.predecessor_commitment =
            ubo_control_commitment_v1(&second_state.ubo_control).unwrap();
        assert!(ledger.stage_ledger_stake_authority(second).is_err());
        assert_eq!(ledger.height, before_height);
        assert_eq!(ledger.state_root().unwrap(), before_root);
    }

    #[test]
    fn liability_horizon_is_monotonic_rebuildable_and_tamper_evident() {
        let mut first_fixture = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        first_fixture.enable_v2_slash_terms();
        let first = first_fixture.derive().unwrap();

        let mut next = fixture(4, RLDCOIN_TESTNET_DOMAIN);
        next.enable_v2_slash_terms();
        next.context.finalized_height = 1_100;
        next.context.finalized_state_root = "55".repeat(32);
        next.anchor.consensus_epoch = first.descriptor.consensus_epoch + 1;
        next.anchor.activation_height = first.descriptor.exit_height;
        next.anchor.stake_snapshot_height = next.context.finalized_height;
        next.anchor.stake_snapshot_state_root = next.context.finalized_state_root.clone();
        next.anchor.record_chain_anchor = first.record_hash.clone();
        let second = derive_ledger_stake_epoch_v1(
            &next.context,
            &next.policy,
            &next.anchor,
            Some(&first),
            &next.candidates,
            &next.positions,
            &next.ubo,
            &next.coins,
        )
        .unwrap();

        let (current, history) =
            rebuild_stake_position_liability_horizons_v1([&first, &second]).unwrap();
        assert_eq!(current.len(), first.stake_liabilities.len());
        for (position_id, records) in &history {
            assert_eq!(records.len(), 2);
            assert_eq!(records[0].retained_liability_count, 1);
            assert_eq!(records[0].previous_horizon_commitment, ZERO_HASH);
            assert_eq!(records[1].retained_liability_count, 2);
            assert_eq!(
                records[1].previous_horizon_commitment,
                records[0].horizon_commitment
            );
            assert_eq!(current.get(position_id), records.last());
            assert!(
                records[1].max_evidence_deadline_height >= records[0].max_evidence_deadline_height
            );
        }

        let mut tampered = current.values().next().unwrap().clone();
        tampered.retained_liability_count += 1;
        assert!(matches!(
            tampered.validate(),
            Err(StakeEpochDerivationError::InvalidLiabilityHorizon { .. })
        ));
        let mut rewound = current.values().next().unwrap().clone();
        rewound.previous_horizon_commitment = ZERO_HASH.into();
        rewound.horizon_commitment = rewound.compute_commitment();
        assert!(matches!(
            rewound.validate(),
            Err(StakeEpochDerivationError::InvalidLiabilityHorizon { .. })
        ));
    }

    #[test]
    fn liability_horizon_matches_independent_unbond_redteam_fixture() {
        let horizon = StakePositionLiabilityHorizonV1 {
            horizon_version: STAKE_POSITION_LIABILITY_HORIZON_VERSION_V1,
            position_id: "position-1".into(),
            owner: "alice".into(),
            escrow_coin_id: "principal-1".into(),
            retained_liability_count: 2,
            max_evidence_deadline_height: 315,
            last_consensus_epoch: 11,
            liability_accumulator_root: "11".repeat(32),
            previous_horizon_commitment: "22".repeat(32),
            horizon_commitment: "e0834293aa9e5696ab8788666db5b44ee87442687c3c2f67a1aebef0f5d963c2"
                .into(),
        };
        horizon.validate().unwrap();
        assert_eq!(horizon.horizon_commitment, horizon.compute_commitment());
    }

    #[test]
    fn ledger_derives_one_state_rooted_epoch_without_runtime_activation() {
        let (mut ledger, update) = ledger_authority_fixture();
        ledger.stage_ledger_stake_authority(update).unwrap();
        let runtime_keys = ledger.descriptor.validator_keys.clone();
        let snapshot_root = ledger.state_root().unwrap();

        let record = ledger.derive_and_store_next_stake_epoch().unwrap();
        assert_eq!(record.status, StakeEpochRecordStatus::DerivedOnly);
        assert_eq!(record.descriptor.consensus_epoch, 1);
        assert_eq!(record.stake_snapshot_height, 1_001);
        assert_eq!(record.stake_snapshot_state_root, snapshot_root);
        assert_eq!(ledger.derived_stake_epochs.get(&1), Some(&record));
        assert_eq!(ledger.descriptor.validator_keys, runtime_keys);

        let before_root = ledger.state_root().unwrap();
        let before_height = ledger.height;
        assert!(ledger.derive_and_store_next_stake_epoch().is_err());
        assert_eq!(ledger.height, before_height);
        assert_eq!(ledger.state_root().unwrap(), before_root);

        let encoded = serde_json::to_value(&ledger).unwrap();
        let recovered: Ledger = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(
            recovered.state_root().unwrap(),
            ledger.state_root().unwrap()
        );
        let mut tampered = encoded;
        tampered["derived_stake_epochs"]["1"]["record_hash"] =
            serde_json::Value::String("aa".repeat(32));
        assert!(serde_json::from_value::<Ledger>(tampered).is_err());
    }
}
