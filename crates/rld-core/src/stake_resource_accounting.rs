//! Fail-closed accounting engine for stake-state resource responsibility.
//!
//! R6.20 roots policy governance and admits candidate/position creation,
//! bounded legacy migration and resource-bound Epoch retention. Each adopted
//! command derives usage internally before this engine consumes a Coin, charges
//! a fee or creates a bond. Every later lifecycle path remains closed.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    action_payload_hash,
    crypto::{hash_bytes, hash_parts},
    Amount, CoinObject, CoinState, ConsensusStakePosition, DeriveNextStakeEpochRequestV2,
    LedgerDerivedStakeEpochV1, LockConsensusStakeRequestV3,
    MigrateConsensusCandidateResourceRequestV1, MigrateConsensusStakeResourceRequestV1,
    RegisterConsensusValidatorRequestV2, RenewStakeStateResourceBondRequestV1,
    StakePositionLiabilityHorizonV1, StakeResourceCandidatePayload, StakeStateBondRecordV2,
    StakeStateBondRenewalRecordV1, StakeStateBondStatusV1, StakeStateMaintenancePoolPolicyBucketV2,
    StakeStateMaintenancePoolV2, StakeStateResourceEnvelopeV1, StakeStateResourceKindV1,
    StakeStateResourcePolicyV1, ValidatorCandidateRecord,
    RENEW_STAKE_STATE_RESOURCE_BOND_ACTION_V1, RLDCOIN_MAINNET_DOMAIN, RLDCOIN_TESTNET_DOMAIN,
};

pub const FUND_STAKE_STATE_RESOURCE_ACTION_V1: &str = "FUND_STAKE_STATE_RESOURCE_V1";
pub const STAKE_RESOURCE_ACCOUNTING_VERSION_V1: u16 = 1;
pub const STAKE_RESOURCE_POOL_VERSION_V2: u16 = 2;
/// Fail-closed bound until an authenticated policy-history compaction format
/// exists. Hitting this bound stops policy rotation; it never drops a policy
/// that is needed to re-derive a live or terminal bond record.
pub const MAX_STAKE_RESOURCE_POLICY_GENERATIONS_V1: usize = 4_096;
pub const ZERO_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";
pub const REGISTER_CONSENSUS_VALIDATOR_SIGNATURE_CHECKS_V2: u32 = 3;
pub const REGISTER_CONSENSUS_VALIDATOR_STATE_READS_V2: u32 = 8;
pub const REGISTER_CONSENSUS_VALIDATOR_STATE_WRITES_V2: u32 = 10;
pub const LOCK_CONSENSUS_STAKE_SIGNATURE_CHECKS_V3: u32 = 3;
pub const LOCK_CONSENSUS_STAKE_STATE_READS_V3: u32 = 12;
pub const LOCK_CONSENSUS_STAKE_STATE_WRITES_V3: u32 = 14;
pub const MIGRATE_CONSENSUS_STAKE_RESOURCE_SIGNATURE_CHECKS_V1: u32 = 2;
pub const MIGRATE_CONSENSUS_STAKE_RESOURCE_STATE_READS_V1: u32 = 10;
pub const MIGRATE_CONSENSUS_STAKE_RESOURCE_STATE_WRITES_V1: u32 = 9;
pub const MIGRATE_CONSENSUS_CANDIDATE_RESOURCE_SIGNATURE_CHECKS_V1: u32 = 2;
pub const MIGRATE_CONSENSUS_CANDIDATE_RESOURCE_STATE_READS_V1: u32 = 8;
pub const MIGRATE_CONSENSUS_CANDIDATE_RESOURCE_STATE_WRITES_V1: u32 = 9;
pub const DERIVE_NEXT_STAKE_EPOCH_SIGNATURE_CHECKS_V2: u32 = 2;
pub const DERIVE_NEXT_STAKE_EPOCH_BASE_STATE_READS_V2: u32 = 6;
pub const DERIVE_NEXT_STAKE_EPOCH_BASE_STATE_WRITES_V2: u32 = 11;
pub const RENEW_STAKE_STATE_RESOURCE_BOND_SIGNATURE_CHECKS_V1: u32 = 1;
pub const RENEW_STAKE_STATE_RESOURCE_BOND_STATE_READS_V1: u32 = 7;
pub const RENEW_STAKE_STATE_RESOURCE_BOND_STATE_WRITES_V1: u32 = 9;

/// R6.22B deliberately has no authenticated policy prices or block limits for
/// general CPU/proof work. A fee-only unbond mutation may therefore use only
/// the already priced wire/signature/read/write dimensions. Any non-zero work
/// in either reserved dimension fails closed instead of being hidden inside a
/// fixed multiplier.
pub const FEE_ONLY_MUTATION_MAX_UNPRICED_CPU_UNITS_V1: u64 = 0;
pub const FEE_ONLY_MUTATION_MAX_UNPRICED_PROOF_UNITS_V1: u64 = 0;
/// Request-time reservation cannot know a future completion/slash identifier.
/// Runtime adoption must reject a longer identifier before mutation so this
/// protocol bound is a real upper limit, not an average fixture length.
pub const MAX_STAKE_UNBOND_TERMINAL_ID_UTF8_BYTES_V1: u64 = 256;
/// Payout/nullifier identifiers are protocol-derived rather than caller
/// selected. This bound covers their domain prefix plus a hexadecimal digest.
pub const MAX_STAKE_UNBOND_DERIVED_ID_UTF8_BYTES_V1: u64 = 128;

/// Exact retained-state components needed to plan one resource-bound unbond.
///
/// Candidate, position, Epoch-liability and horizon bytes are dependencies
/// already covered by their own bonds; they are included in the total peak so
/// they cannot disappear from capacity analysis, but are not charged again by
/// the new UNBOND bond. The UNBOND bond covers the pending record plus the
/// larger terminal branch and its immutable indices/audit entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StakeUnbondWorstCaseFootprintInputV1 {
    pub retained_position_bytes: u64,
    pub retained_candidate_bytes: u64,
    pub retained_epoch_liability_bytes: u64,
    pub retained_horizon_history_bytes: u64,
    pub pending_unbond_bytes: u64,
    pub completed_terminal_bytes: u64,
    pub fully_slashed_terminal_bytes: u64,
    pub terminal_index_and_audit_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StakeUnbondWorstCaseFootprintV1 {
    pub dependency_retained_bytes: u64,
    pub terminal_branch_upper_bound_bytes: u64,
    pub prepaid_terminal_capacity_bytes: u64,
    pub unbond_bond_persistent_bytes: u64,
    pub total_worst_case_retained_bytes: u64,
}

/// Checked worst-case bound. Zero Candidate bytes are permitted for a
/// delegation whose validator-candidate responsibility is accounted outside
/// this local lifecycle. Every other component is mandatory.
pub fn stake_unbond_worst_case_footprint_v1(
    input: StakeUnbondWorstCaseFootprintInputV1,
) -> Result<StakeUnbondWorstCaseFootprintV1, StakeResourceAccountingError> {
    if input.retained_position_bytes == 0
        || input.retained_epoch_liability_bytes == 0
        || input.retained_horizon_history_bytes == 0
        || input.pending_unbond_bytes == 0
        || input.completed_terminal_bytes == 0
        || input.fully_slashed_terminal_bytes == 0
        || input.terminal_index_and_audit_bytes == 0
    {
        return Err(StakeResourceAccountingError::InvalidRequest(
            "unbond worst-case footprint has a missing mandatory component".into(),
        ));
    }
    let dependency_retained_bytes = input
        .retained_position_bytes
        .checked_add(input.retained_candidate_bytes)
        .and_then(|value| value.checked_add(input.retained_epoch_liability_bytes))
        .and_then(|value| value.checked_add(input.retained_horizon_history_bytes))
        .ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic("unbond retained dependencies".into())
        })?;
    let terminal_branch_upper_bound_bytes = input
        .completed_terminal_bytes
        .max(input.fully_slashed_terminal_bytes);
    let prepaid_terminal_capacity_bytes = terminal_branch_upper_bound_bytes
        .checked_add(input.terminal_index_and_audit_bytes)
        .ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic("unbond terminal capacity".into())
        })?;
    let unbond_bond_persistent_bytes = input
        .pending_unbond_bytes
        .checked_add(prepaid_terminal_capacity_bytes)
        .ok_or_else(|| StakeResourceAccountingError::Arithmetic("unbond bond footprint".into()))?;
    let total_worst_case_retained_bytes = dependency_retained_bytes
        .checked_add(unbond_bond_persistent_bytes)
        .ok_or_else(|| StakeResourceAccountingError::Arithmetic("unbond total footprint".into()))?;
    Ok(StakeUnbondWorstCaseFootprintV1 {
        dependency_retained_bytes,
        terminal_branch_upper_bound_bytes,
        prepaid_terminal_capacity_bytes,
        unbond_bond_persistent_bytes,
        total_worst_case_retained_bytes,
    })
}

/// Fee-only mutation meter. `live` is the replaceable current index; history
/// is immutable and must satisfy `next = previous + appended`. Deletion and
/// shrink are represented by removing live bytes and writing a smaller (or
/// empty) replacement while still appending an immutable terminal audit fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StakeStateResourceMutationUsageV1 {
    pub wire_bytes: u32,
    pub predecessor_total_stake_state_bytes: u64,
    pub predecessor_live_bytes: u64,
    pub removed_live_bytes: u64,
    pub replacement_live_bytes: u64,
    pub predecessor_history_bytes: u64,
    pub predecessor_history_commitment: [u8; 32],
    pub successor_history_bytes: u64,
    pub successor_history_prefix_commitment: [u8; 32],
    pub appended_history_bytes: u64,
    pub prepaid_terminal_capacity_bytes: u64,
    pub signature_checks: u32,
    pub state_reads: u32,
    pub state_writes: u32,
    pub cpu_units: u64,
    pub proof_verification_units: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StakeStateResourceMutationQuoteV1 {
    pub charged_fee: Amount,
    pub refundable_bond_delta: Amount,
    pub predecessor_total_bytes: u64,
    pub successor_total_bytes: u64,
    pub successor_total_stake_state_bytes: u64,
    pub newly_materialized_bytes: u64,
    pub net_released_bytes: u64,
}

pub const UNBOND_TERMINAL_RESERVATION_VERSION_V1: u16 = 1;
const UNBOND_RESERVATION_REQUEST_ROOT_DOMAIN_V1: &[u8] = b"RLD-UNBOND-RESERVATION-REQUEST-ROOT-V1";
const UNBOND_RESERVATION_TERMINAL_ROOT_DOMAIN_V1: &[u8] =
    b"RLD-UNBOND-RESERVATION-TERMINAL-ROOT-V1";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StakeUnbondTerminalBranchV1 {
    Complete,
    Slash,
}

impl StakeUnbondTerminalBranchV1 {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::Complete => "COMPLETE",
            Self::Slash => "SLASH",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StakeUnbondTerminalReservationStatusV1 {
    Reserved,
    SpentComplete,
    SpentSlash,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StakeUnbondTerminalReservationRecordV1 {
    pub reservation_version: u16,
    pub request_id: String,
    pub resource_key: String,
    pub unbond_bond_record_hash: String,
    pub owner: String,
    pub prepaid_terminal_capacity_bytes: u64,
    pub predecessor_history_root: String,
    pub predecessor_history_bytes: u64,
    pub request_history_root: String,
    pub status: StakeUnbondTerminalReservationStatusV1,
    pub terminal_branch: Option<StakeUnbondTerminalBranchV1>,
    pub terminal_record_digest: Option<String>,
    pub successor_history_root: Option<String>,
    pub record_hash: String,
}

impl StakeUnbondTerminalReservationRecordV1 {
    fn compute_hash(&self) -> String {
        hash_parts(&[
            b"RLD-UNBOND-TERMINAL-RESERVATION-RECORD-V1",
            &self.reservation_version.to_be_bytes(),
            self.request_id.as_bytes(),
            self.resource_key.as_bytes(),
            self.unbond_bond_record_hash.as_bytes(),
            self.owner.as_bytes(),
            &self.prepaid_terminal_capacity_bytes.to_be_bytes(),
            self.predecessor_history_root.as_bytes(),
            &self.predecessor_history_bytes.to_be_bytes(),
            self.request_history_root.as_bytes(),
            match self.status {
                StakeUnbondTerminalReservationStatusV1::Reserved => b"RESERVED",
                StakeUnbondTerminalReservationStatusV1::SpentComplete => b"SPENT_COMPLETE",
                StakeUnbondTerminalReservationStatusV1::SpentSlash => b"SPENT_SLASH",
            },
            self.terminal_branch
                .map_or(b"", |value| value.wire_name().as_bytes()),
            self.terminal_record_digest
                .as_deref()
                .unwrap_or("")
                .as_bytes(),
            self.successor_history_root
                .as_deref()
                .unwrap_or("")
                .as_bytes(),
        ])
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StakeUnbondReservationBlockMeterV1 {
    pub height: u64,
    pub materialized_bytes: u64,
    pub signature_checks: u64,
    pub state_reads: u64,
    pub state_writes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StakeUnbondTerminalReservationAccountingV1 {
    pub accounting_version: u16,
    pub materialized_persistent_bytes: u64,
    pub reserved_terminal_capacity_bytes: u64,
    pub reservations: BTreeMap<String, StakeUnbondTerminalReservationRecordV1>,
    pub block_meter: StakeUnbondReservationBlockMeterV1,
    pub state_commitment: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StakeUnbondTerminalReserveInputV1 {
    pub request_id: String,
    pub resource_key: String,
    pub unbond_bond_record_hash: String,
    pub owner: String,
    pub prepaid_terminal_capacity_bytes: u64,
    pub predecessor_history_root: String,
    pub predecessor_history_bytes: u64,
    pub request_materialized_bytes: u64,
    pub height: u64,
    pub signature_checks: u32,
    pub state_reads: u32,
    pub state_writes: u32,
    pub cpu_units: u64,
    pub proof_verification_units: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StakeUnbondTerminalConsumeInputV1 {
    pub request_id: String,
    pub expected_unbond_bond_record_hash: String,
    pub expected_predecessor_history_root: String,
    pub expected_predecessor_history_bytes: u64,
    pub branch: StakeUnbondTerminalBranchV1,
    pub terminal_record_bytes: Vec<u8>,
    pub removed_live_bytes: u64,
    pub replacement_live_bytes: u64,
    pub wire_bytes: u32,
    pub height: u64,
    pub signature_checks: u32,
    pub state_reads: u32,
    pub state_writes: u32,
    pub cpu_units: u64,
    pub proof_verification_units: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StakeUnbondTerminalConsumeOutcomeV1 {
    pub charged_fee: Amount,
    pub refundable_bond_delta: Amount,
    pub terminal_record_digest: String,
    pub successor_history_root: String,
    pub newly_materialized_bytes: u64,
}

/// Text-bearing logical record inputs for the bounded pending-unbond terminal
/// path. These are accounting fields only; R6.22B does not define a command or
/// wire codec. Every string is charged as a four-byte frame plus exact UTF-8.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StakeUnbondLifecycleRecordInputV1<'a> {
    pub request_id: &'a str,
    pub owner: &'a str,
    pub beneficiary: &'a str,
    pub completion_id: &'a str,
    pub payout_coin_id: &'a str,
    pub slash_id: &'a str,
    pub completion_nullifier_id: &'a str,
    pub slash_nullifier_id: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StakeUnbondLifecycleRecordFootprintsV1 {
    pub pending_unbond_bytes: u64,
    pub completed_terminal_bytes: u64,
    pub fully_slashed_terminal_bytes: u64,
    pub terminal_index_and_audit_bytes: u64,
}

/// Frozen logical footprints for the pending record and both mutually
/// exclusive terminal branches. A terminal event is appended to history; the
/// current index may be deleted or replaced, but historical bytes are never
/// reclaimed or rewritten.
pub fn stake_unbond_lifecycle_record_footprints_v1(
    input: StakeUnbondLifecycleRecordInputV1<'_>,
) -> Result<StakeUnbondLifecycleRecordFootprintsV1, StakeResourceAccountingError> {
    if input.owner != input.beneficiary
        || [
            input.request_id,
            input.owner,
            input.beneficiary,
            input.completion_id,
            input.payout_coin_id,
            input.slash_id,
            input.completion_nullifier_id,
            input.slash_nullifier_id,
        ]
        .into_iter()
        .any(str::is_empty)
    {
        return Err(StakeResourceAccountingError::InvalidRequest(
            "unbond lifecycle footprint fields are incomplete or beneficiary is not the owner"
                .into(),
        ));
    }
    if u64::try_from(input.completion_id.len()).map_or(true, |length| {
        length > MAX_STAKE_UNBOND_TERMINAL_ID_UTF8_BYTES_V1
    }) || u64::try_from(input.slash_id.len()).map_or(true, |length| {
        length > MAX_STAKE_UNBOND_TERMINAL_ID_UTF8_BYTES_V1
    }) || [
        input.payout_coin_id,
        input.completion_nullifier_id,
        input.slash_nullifier_id,
    ]
    .into_iter()
    .any(|value| {
        u64::try_from(value.len()).map_or(true, |length| {
            length > MAX_STAKE_UNBOND_DERIVED_ID_UTF8_BYTES_V1
        })
    }) {
        return Err(StakeResourceAccountingError::HardLimit(
            "unbond terminal or derived identifier exceeds its reserved UTF-8 bound".into(),
        ));
    }

    // version + status + requested/withdraw heights + amount + four roots +
    // three optional-terminal discriminants. The retained Position is bound
    // by commitment and covered by its own bond; copying its full record here
    // would double-charge the same persistent bytes.
    let pending_fixed = 2u64 + 1 + 8 * 2 + 16 + 32 * 4 + 3;
    let pending_unbond_bytes = [input.request_id, input.owner, input.beneficiary]
        .into_iter()
        .try_fold(pending_fixed, |total, value| {
            total
                .checked_add(framed_len(value, "pending unbond text")?)
                .ok_or_else(|| {
                    StakeResourceAccountingError::Arithmetic("pending unbond footprint".into())
                })
        })?;

    // version + status + four roots + completed height + amount.
    let completed_fixed = 2u64 + 1 + 32 * 4 + 8 + 16;
    let completed_terminal_bytes = [input.completion_id, input.payout_coin_id, input.beneficiary]
        .into_iter()
        .try_fold(completed_fixed, |total, value| {
            total
                .checked_add(framed_len(value, "completed terminal text")?)
                .ok_or_else(|| {
                    StakeResourceAccountingError::Arithmetic("completed terminal footprint".into())
                })
        })?;

    // version + status + five roots (including slash evidence) + terminal
    // height + amount.
    let fully_slashed_fixed = 2u64 + 1 + 32 * 5 + 8 + 16;
    let fully_slashed_terminal_bytes = [input.slash_id, input.owner].into_iter().try_fold(
        fully_slashed_fixed,
        |total, value| {
            total
                .checked_add(framed_len(value, "fully slashed terminal text")?)
                .ok_or_else(|| {
                    StakeResourceAccountingError::Arithmetic(
                        "fully slashed terminal footprint".into(),
                    )
                })
        },
    )?;

    // Pending/current map key, immutable history map key and vector frame,
    // both mutually-exclusive nullifiers, one terminal audit commitment and a
    // status byte.
    let terminal_index_and_audit_bytes = [
        input.request_id,
        input.request_id,
        input.completion_nullifier_id,
        input.slash_nullifier_id,
    ]
    .into_iter()
    .try_fold(4u64 + 32 + 1, |total, value| {
        total
            .checked_add(framed_len(value, "unbond index and audit text")?)
            .ok_or_else(|| {
                StakeResourceAccountingError::Arithmetic("unbond index and audit footprint".into())
            })
    })?;

    Ok(StakeUnbondLifecycleRecordFootprintsV1 {
        pending_unbond_bytes,
        completed_terminal_bytes,
        fully_slashed_terminal_bytes,
        terminal_index_and_audit_bytes,
    })
}

/// Request-time upper bound for a not-yet-known completion or slash branch.
/// Request id and owner are already known and charged at their exact UTF-8
/// lengths; future caller-selected and protocol-derived ids use the frozen
/// maxima above.
pub fn stake_unbond_lifecycle_worst_case_record_footprints_v1(
    request_id: &str,
    owner: &str,
) -> Result<StakeUnbondLifecycleRecordFootprintsV1, StakeResourceAccountingError> {
    if request_id.is_empty() || owner.is_empty() {
        return Err(StakeResourceAccountingError::InvalidRequest(
            "unbond worst-case footprint requires request id and owner".into(),
        ));
    }
    let framed_bytes = |length: u64, label: &str| {
        length
            .checked_add(4)
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic(label.into()))
    };
    let request_frame = framed_len(request_id, "unbond worst-case request id")?;
    let owner_frame = framed_len(owner, "unbond worst-case owner")?;
    let terminal_id_frame = framed_bytes(
        MAX_STAKE_UNBOND_TERMINAL_ID_UTF8_BYTES_V1,
        "unbond terminal id frame",
    )?;
    let derived_id_frame = framed_bytes(
        MAX_STAKE_UNBOND_DERIVED_ID_UTF8_BYTES_V1,
        "unbond derived id frame",
    )?;
    let pending_unbond_bytes = (2u64 + 1 + 8 * 2 + 16 + 32 * 4 + 3)
        .checked_add(request_frame)
        .and_then(|value| value.checked_add(owner_frame.checked_mul(2)?))
        .ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic("worst pending unbond footprint".into())
        })?;
    let completed_terminal_bytes = (2u64 + 1 + 32 * 4 + 8 + 16)
        .checked_add(terminal_id_frame)
        .and_then(|value| value.checked_add(derived_id_frame))
        .and_then(|value| value.checked_add(owner_frame))
        .ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic("worst completed terminal footprint".into())
        })?;
    let fully_slashed_terminal_bytes = (2u64 + 1 + 32 * 5 + 8 + 16)
        .checked_add(terminal_id_frame)
        .and_then(|value| value.checked_add(owner_frame))
        .ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic("worst slashed terminal footprint".into())
        })?;
    let terminal_index_and_audit_bytes = (4u64 + 32 + 1)
        .checked_add(request_frame.checked_mul(2).ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic("worst unbond request indices".into())
        })?)
        .and_then(|value| value.checked_add(derived_id_frame.checked_mul(2)?))
        .ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic("worst unbond index footprint".into())
        })?;
    Ok(StakeUnbondLifecycleRecordFootprintsV1 {
        pending_unbond_bytes,
        completed_terminal_bytes,
        fully_slashed_terminal_bytes,
        terminal_index_and_audit_bytes,
    })
}

impl StakeUnbondTerminalReservationAccountingV1 {
    pub fn new(initial_height: u64, materialized_persistent_bytes: u64) -> Self {
        let mut state = Self {
            accounting_version: UNBOND_TERMINAL_RESERVATION_VERSION_V1,
            materialized_persistent_bytes,
            reserved_terminal_capacity_bytes: 0,
            reservations: BTreeMap::new(),
            block_meter: StakeUnbondReservationBlockMeterV1 {
                height: initial_height,
                materialized_bytes: 0,
                signature_checks: 0,
                state_reads: 0,
                state_writes: 0,
            },
            state_commitment: String::new(),
        };
        state.state_commitment = state.compute_commitment();
        state
    }

    fn compute_commitment(&self) -> String {
        let mut projection = self.clone();
        projection.state_commitment.clear();
        hash_bytes(
            &serde_json::to_vec(&projection)
                .expect("terminal reservation accounting serialization is infallible"),
        )
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, StakeResourceAccountingError> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|error| StakeResourceAccountingError::Recovery(error.to_string()))
    }

    pub fn restore_canonical_json(bytes: &[u8]) -> Result<Self, StakeResourceAccountingError> {
        let state: Self = serde_json::from_slice(bytes)
            .map_err(|error| StakeResourceAccountingError::Recovery(error.to_string()))?;
        if serde_json::to_vec(&state)
            .map_err(|error| StakeResourceAccountingError::Recovery(error.to_string()))?
            != bytes
        {
            return Err(StakeResourceAccountingError::Recovery(
                "terminal reservation state is not canonical JSON".into(),
            ));
        }
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> Result<(), StakeResourceAccountingError> {
        if self.accounting_version != UNBOND_TERMINAL_RESERVATION_VERSION_V1 {
            return Err(StakeResourceAccountingError::InvalidState(
                "terminal reservation accounting version mismatch".into(),
            ));
        }
        let mut reserved = 0u64;
        for (request_id, record) in &self.reservations {
            if request_id != &record.request_id
                || record.reservation_version != UNBOND_TERMINAL_RESERVATION_VERSION_V1
                || record.resource_key != format!("UNBOND/{request_id}")
                || record.owner.is_empty()
                || !is_hash(&record.unbond_bond_record_hash)
                || !is_hash(&record.predecessor_history_root)
                || !is_hash(&record.request_history_root)
                || record.prepaid_terminal_capacity_bytes == 0
                || record.record_hash != record.compute_hash()
            {
                return Err(StakeResourceAccountingError::InvalidState(
                    "terminal reservation record identity or commitment mismatch".into(),
                ));
            }
            match record.status {
                StakeUnbondTerminalReservationStatusV1::Reserved => {
                    if record.terminal_branch.is_some()
                        || record.terminal_record_digest.is_some()
                        || record.successor_history_root.is_some()
                    {
                        return Err(StakeResourceAccountingError::InvalidState(
                            "reserved terminal capacity already has a terminal fact".into(),
                        ));
                    }
                    reserved = reserved
                        .checked_add(record.prepaid_terminal_capacity_bytes)
                        .ok_or_else(|| {
                            StakeResourceAccountingError::Arithmetic(
                                "reserved terminal capacity total".into(),
                            )
                        })?;
                }
                StakeUnbondTerminalReservationStatusV1::SpentComplete
                | StakeUnbondTerminalReservationStatusV1::SpentSlash => {
                    let branch = record.terminal_branch.ok_or_else(|| {
                        StakeResourceAccountingError::InvalidState(
                            "spent reservation has no terminal branch".into(),
                        )
                    })?;
                    let status_matches = matches!(
                        (record.status, branch),
                        (
                            StakeUnbondTerminalReservationStatusV1::SpentComplete,
                            StakeUnbondTerminalBranchV1::Complete
                        ) | (
                            StakeUnbondTerminalReservationStatusV1::SpentSlash,
                            StakeUnbondTerminalBranchV1::Slash
                        )
                    );
                    if !status_matches
                        || record
                            .terminal_record_digest
                            .as_deref()
                            .is_none_or(|value| !is_hash(value))
                        || record
                            .successor_history_root
                            .as_deref()
                            .is_none_or(|value| !is_hash(value))
                    {
                        return Err(StakeResourceAccountingError::InvalidState(
                            "spent reservation terminal binding mismatch".into(),
                        ));
                    }
                }
            }
        }
        if reserved != self.reserved_terminal_capacity_bytes
            || self.state_commitment != self.compute_commitment()
        {
            return Err(StakeResourceAccountingError::InvalidState(
                "terminal reservation totals or state commitment mismatch".into(),
            ));
        }
        Ok(())
    }

    fn stage_meter(
        &mut self,
        policy: &StakeStateResourcePolicyV1,
        height: u64,
        bytes: u64,
        signatures: u32,
        reads: u32,
        writes: u32,
    ) -> Result<(), StakeResourceAccountingError> {
        if height < self.block_meter.height {
            return Err(StakeResourceAccountingError::InvalidRequest(
                "terminal reservation meter height moved backwards".into(),
            ));
        }
        if height > self.block_meter.height {
            let expected = self.block_meter.height.checked_add(1).ok_or_else(|| {
                StakeResourceAccountingError::Arithmetic("reservation meter height".into())
            })?;
            if height != expected {
                return Err(StakeResourceAccountingError::InvalidRequest(
                    "terminal reservation meter height skipped without authenticated context"
                        .into(),
                ));
            }
            self.block_meter = StakeUnbondReservationBlockMeterV1 {
                height,
                materialized_bytes: 0,
                signature_checks: 0,
                state_reads: 0,
                state_writes: 0,
            };
        }
        let next_bytes = self
            .block_meter
            .materialized_bytes
            .checked_add(bytes)
            .ok_or_else(|| {
                StakeResourceAccountingError::Arithmetic("block mutation bytes".into())
            })?;
        let next_signatures = self
            .block_meter
            .signature_checks
            .checked_add(u64::from(signatures))
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("block signatures".into()))?;
        let next_reads = self
            .block_meter
            .state_reads
            .checked_add(u64::from(reads))
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("block reads".into()))?;
        let next_writes = self
            .block_meter
            .state_writes
            .checked_add(u64::from(writes))
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("block writes".into()))?;
        if next_bytes > u64::from(policy.maximum_stake_state_bytes_per_block)
            || next_signatures > u64::from(policy.maximum_stake_signature_checks_per_block)
            || next_reads > u64::from(policy.maximum_stake_state_reads_per_block)
            || next_writes > u64::from(policy.maximum_stake_state_writes_per_block)
        {
            return Err(StakeResourceAccountingError::HardLimit(
                "terminal reservation cumulative block meter".into(),
            ));
        }
        self.block_meter.materialized_bytes = next_bytes;
        self.block_meter.signature_checks = next_signatures;
        self.block_meter.state_reads = next_reads;
        self.block_meter.state_writes = next_writes;
        Ok(())
    }

    pub fn reserve(
        &mut self,
        policy: &StakeStateResourcePolicyV1,
        input: StakeUnbondTerminalReserveInputV1,
    ) -> Result<StakeUnbondTerminalReservationRecordV1, StakeResourceAccountingError> {
        self.validate()?;
        if input.cpu_units != 0 || input.proof_verification_units != 0 {
            return Err(StakeResourceAccountingError::HardLimit(
                "terminal reservation uses unpriced CPU or proof work".into(),
            ));
        }
        if input.request_id.is_empty()
            || input.resource_key != format!("UNBOND/{}", input.request_id)
            || input.owner.is_empty()
            || !is_hash(&input.unbond_bond_record_hash)
            || !is_hash(&input.predecessor_history_root)
            || input.prepaid_terminal_capacity_bytes == 0
            || input.request_materialized_bytes == 0
            || self.reservations.contains_key(&input.request_id)
        {
            return Err(StakeResourceAccountingError::InvalidRequest(
                "terminal reservation request is malformed or duplicate".into(),
            ));
        }
        let reserved = self
            .reserved_terminal_capacity_bytes
            .checked_add(input.prepaid_terminal_capacity_bytes)
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("reserved capacity".into()))?;
        let materialized = self
            .materialized_persistent_bytes
            .checked_add(input.request_materialized_bytes)
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("materialized bytes".into()))?;
        if materialized.checked_add(reserved).ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic("reserved global total".into())
        })? > policy.maximum_total_stake_state_bytes
        {
            return Err(StakeResourceAccountingError::HardLimit(
                "materialized plus reserved terminal capacity".into(),
            ));
        }
        let metered_bytes = input
            .request_materialized_bytes
            .checked_add(input.prepaid_terminal_capacity_bytes)
            .ok_or_else(|| {
                StakeResourceAccountingError::Arithmetic("request meter bytes".into())
            })?;
        let mut staged = self.clone();
        staged.stage_meter(
            policy,
            input.height,
            metered_bytes,
            input.signature_checks,
            input.state_reads,
            input.state_writes,
        )?;
        let request_history_root = hash_parts(&[
            UNBOND_RESERVATION_REQUEST_ROOT_DOMAIN_V1,
            input.predecessor_history_root.as_bytes(),
            &input.predecessor_history_bytes.to_be_bytes(),
            input.request_id.as_bytes(),
            input.resource_key.as_bytes(),
            input.unbond_bond_record_hash.as_bytes(),
            input.owner.as_bytes(),
            &input.prepaid_terminal_capacity_bytes.to_be_bytes(),
        ]);
        let mut record = StakeUnbondTerminalReservationRecordV1 {
            reservation_version: UNBOND_TERMINAL_RESERVATION_VERSION_V1,
            request_id: input.request_id.clone(),
            resource_key: input.resource_key,
            unbond_bond_record_hash: input.unbond_bond_record_hash,
            owner: input.owner,
            prepaid_terminal_capacity_bytes: input.prepaid_terminal_capacity_bytes,
            predecessor_history_root: input.predecessor_history_root,
            predecessor_history_bytes: input.predecessor_history_bytes,
            request_history_root,
            status: StakeUnbondTerminalReservationStatusV1::Reserved,
            terminal_branch: None,
            terminal_record_digest: None,
            successor_history_root: None,
            record_hash: String::new(),
        };
        record.record_hash = record.compute_hash();
        staged.materialized_persistent_bytes = materialized;
        staged.reserved_terminal_capacity_bytes = reserved;
        staged.reservations.insert(input.request_id, record.clone());
        staged.state_commitment = staged.compute_commitment();
        staged.validate()?;
        *self = staged;
        Ok(record)
    }

    pub fn consume(
        &mut self,
        policy: &StakeStateResourcePolicyV1,
        input: StakeUnbondTerminalConsumeInputV1,
    ) -> Result<StakeUnbondTerminalConsumeOutcomeV1, StakeResourceAccountingError> {
        self.validate()?;
        if input.cpu_units != 0 || input.proof_verification_units != 0 {
            return Err(StakeResourceAccountingError::HardLimit(
                "terminal consume uses unpriced CPU or proof work".into(),
            ));
        }
        let record = self.reservations.get(&input.request_id).ok_or_else(|| {
            StakeResourceAccountingError::InvalidRequest("missing terminal reservation".into())
        })?;
        if record.status != StakeUnbondTerminalReservationStatusV1::Reserved
            || input.expected_unbond_bond_record_hash != record.unbond_bond_record_hash
            || input.expected_predecessor_history_root != record.request_history_root
            || input.expected_predecessor_history_bytes != record.predecessor_history_bytes
            || input.terminal_record_bytes.is_empty()
            || input.removed_live_bytes > self.materialized_persistent_bytes
        {
            return Err(StakeResourceAccountingError::InvalidRequest(
                "terminal consume parent, branch token or predecessor mismatch".into(),
            ));
        }
        let terminal_bytes = u64::try_from(input.terminal_record_bytes.len()).map_err(|_| {
            StakeResourceAccountingError::Arithmetic("terminal record length".into())
        })?;
        let newly_materialized_bytes = input
            .replacement_live_bytes
            .checked_add(terminal_bytes)
            .ok_or_else(|| {
                StakeResourceAccountingError::Arithmetic("terminal materialized".into())
            })?;
        if newly_materialized_bytes > record.prepaid_terminal_capacity_bytes {
            return Err(StakeResourceAccountingError::HardLimit(
                "terminal branch exceeds its one-time reservation".into(),
            ));
        }
        let materialized = self
            .materialized_persistent_bytes
            .checked_sub(input.removed_live_bytes)
            .and_then(|value| value.checked_add(newly_materialized_bytes))
            .ok_or_else(|| {
                StakeResourceAccountingError::Arithmetic("terminal global bytes".into())
            })?;
        let reserved = self
            .reserved_terminal_capacity_bytes
            .checked_sub(record.prepaid_terminal_capacity_bytes)
            .ok_or_else(|| {
                StakeResourceAccountingError::Arithmetic("terminal reservation spend".into())
            })?;
        if materialized.checked_add(reserved).ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic("terminal global total".into())
        })? > policy.maximum_total_stake_state_bytes
        {
            return Err(StakeResourceAccountingError::HardLimit(
                "terminal consume exceeds global materialized plus reserved limit".into(),
            ));
        }
        let terminal_record_digest = hash_bytes(&input.terminal_record_bytes);
        let successor_history_root = hash_parts(&[
            UNBOND_RESERVATION_TERMINAL_ROOT_DOMAIN_V1,
            record.request_history_root.as_bytes(),
            input.branch.wire_name().as_bytes(),
            input.request_id.as_bytes(),
            input.expected_unbond_bond_record_hash.as_bytes(),
            terminal_record_digest.as_bytes(),
            &terminal_bytes.to_be_bytes(),
        ]);
        let charged_fee = quote_execution_fee(
            policy,
            StakeStateResourceKindV1::Unbond,
            input.wire_bytes,
            input.signature_checks,
            input.state_reads,
            input.state_writes,
        )?;
        let mut staged = self.clone();
        staged.stage_meter(
            policy,
            input.height,
            newly_materialized_bytes,
            input.signature_checks,
            input.state_reads,
            input.state_writes,
        )?;
        let staged_record = staged
            .reservations
            .get_mut(&input.request_id)
            .ok_or_else(|| {
                StakeResourceAccountingError::InvalidState("staged reservation disappeared".into())
            })?;
        staged_record.status = match input.branch {
            StakeUnbondTerminalBranchV1::Complete => {
                StakeUnbondTerminalReservationStatusV1::SpentComplete
            }
            StakeUnbondTerminalBranchV1::Slash => {
                StakeUnbondTerminalReservationStatusV1::SpentSlash
            }
        };
        staged_record.terminal_branch = Some(input.branch);
        staged_record.terminal_record_digest = Some(terminal_record_digest.clone());
        staged_record.successor_history_root = Some(successor_history_root.clone());
        staged_record.record_hash = staged_record.compute_hash();
        staged.materialized_persistent_bytes = materialized;
        staged.reserved_terminal_capacity_bytes = reserved;
        staged.state_commitment = staged.compute_commitment();
        staged.validate()?;
        *self = staged;
        Ok(StakeUnbondTerminalConsumeOutcomeV1 {
            charged_fee,
            refundable_bond_delta: Amount::ZERO,
            terminal_record_digest,
            successor_history_root,
            newly_materialized_bytes,
        })
    }
}

/// Logical bytes introduced by one renewal tranche. The covered object and
/// original bond are deliberately absent: they remain byte-for-byte intact.
pub fn renew_stake_state_resource_bond_persistent_bytes_v1(
    request: &RenewStakeStateResourceBondRequestV1,
) -> Result<u64, StakeResourceAccountingError> {
    const RENEWAL_FIXED: u64 = 32 * 4 + 8 * 8 + 16 * 2 + 4 * 5;
    const COIN_FIXED: u64 = 104;
    const BOND_COIN_ID_BYTES: u64 = 23 + 64;
    const CHANGE_COIN_ID_BYTES: u64 = 25 + 64;
    let mut total = RENEWAL_FIXED
        .checked_add(
            COIN_FIXED
                .checked_mul(2)
                .ok_or_else(|| StakeResourceAccountingError::Arithmetic("renewal Coins".into()))?,
        )
        .ok_or_else(|| StakeResourceAccountingError::Arithmetic("renewal fixed fields".into()))?;
    for value in [
        request.renewal_id.as_str(),
        request.resource_key.as_str(),
        request.resource_owner.as_str(),
        request.expected_bond_id.as_str(),
        request.sponsor.as_str(),
        request.authorization.authorization_id.as_str(),
        request.funding_coin_id.as_str(),
        request.funding_coin_id.as_str(),
        request.sponsor.as_str(),
        request.zone_id.as_str(),
        request.zone_id.as_str(),
        request.funding_coin_id.as_str(),
        request.sponsor.as_str(),
        request.zone_id.as_str(),
        request.zone_id.as_str(),
        request.authorization.authorization_id.as_str(),
        request.funding_coin_id.as_str(),
    ] {
        total = total
            .checked_add(framed_len(value, "renewal persistent text")?)
            .ok_or_else(|| {
                StakeResourceAccountingError::Arithmetic("renewal persistent footprint".into())
            })?;
    }
    total
        .checked_add(4 + BOND_COIN_ID_BYTES)
        .and_then(|value| value.checked_add(4 + BOND_COIN_ID_BYTES))
        .and_then(|value| value.checked_add(4 + CHANGE_COIN_ID_BYTES))
        .ok_or_else(|| StakeResourceAccountingError::Arithmetic("renewal Coin ids".into()))
}

/// Frozen logical persistent footprint for one V2 candidate admission.
///
/// This is a protocol accounting unit, not a Rust allocator or JSON size. It
/// covers the candidate, V2 bond record and key, bond Coin, the maximum one
/// change Coin, and the owner/sponsor/funding nullifier entries. Hashes, keys,
/// signatures and numeric fields use their decoded widths; variable text uses
/// a four-byte length prefix plus exact UTF-8 bytes. Charging the possible
/// change Coin unconditionally removes a fee/change circular dependency.
pub fn register_consensus_validator_persistent_bytes_v2(
    request: &RegisterConsensusValidatorRequestV2,
) -> Result<u64, StakeResourceAccountingError> {
    const CANDIDATE_FIXED: u64 = 32 + 8 + 16 + 1 + 16 + 64;
    const BOND_RECORD_FIXED: u64 = 284;
    const COIN_FIXED: u64 = 104;
    const BOND_COIN_ID_BYTES: u64 = 17 + 64;
    const CHANGE_COIN_ID_BYTES: u64 = 19 + 64;

    fn framed_len(value: &str) -> Result<u64, StakeResourceAccountingError> {
        u64::try_from(value.len())
            .ok()
            .and_then(|length| length.checked_add(4))
            .ok_or_else(|| {
                StakeResourceAccountingError::Arithmetic("candidate persistent text length".into())
            })
    }

    let resource_key = format!("CANDIDATE/{}", request.validator_id);
    let sponsor_authorization_id = &request.resource_envelope.authorization.authorization_id;
    let owner_authorization_id = &request.authorization.authorization_id;
    let funding_coin_id = &request.resource_envelope.funding_coin_id;
    let sponsor = &request.resource_envelope.sponsor;
    let zone_id = &request.zone_id;

    let mut total = CANDIDATE_FIXED
        .checked_add(BOND_RECORD_FIXED)
        .and_then(|value| value.checked_add(COIN_FIXED.checked_mul(2)?))
        .ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic("candidate persistent fixed fields".into())
        })?;
    for value in [
        // Candidate record.
        request.validator_id.as_str(),
        request.owner.as_str(),
        // Bond record plus its ordered map key.
        resource_key.as_str(),
        request.owner.as_str(),
        sponsor.as_str(),
        sponsor_authorization_id.as_str(),
        funding_coin_id.as_str(),
        resource_key.as_str(),
        // Bond Coin and worst-case change Coin share lineage/context fields.
        funding_coin_id.as_str(),
        sponsor.as_str(),
        zone_id.as_str(),
        zone_id.as_str(),
        funding_coin_id.as_str(),
        sponsor.as_str(),
        zone_id.as_str(),
        zone_id.as_str(),
        // Ledger and accounting nullifier/index entries.
        owner_authorization_id.as_str(),
        sponsor_authorization_id.as_str(),
        sponsor_authorization_id.as_str(),
        funding_coin_id.as_str(),
    ] {
        total = total.checked_add(framed_len(value)?).ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic("candidate persistent footprint".into())
        })?;
    }
    total = total
        .checked_add(4 + BOND_COIN_ID_BYTES)
        .and_then(|value| value.checked_add(4 + BOND_COIN_ID_BYTES))
        .and_then(|value| value.checked_add(4 + CHANGE_COIN_ID_BYTES))
        .ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic("candidate persistent Coin ids".into())
        })?;
    Ok(total)
}

/// Retroactively accounts one exact retained candidate plus the resource
/// record, bond Coin, worst-case change Coin and authorization/funding indices.
pub fn migrate_consensus_candidate_resource_persistent_bytes_v1(
    request: &MigrateConsensusCandidateResourceRequestV1,
    candidate: &ValidatorCandidateRecord,
) -> Result<u64, StakeResourceAccountingError> {
    const CANDIDATE_FIXED: u64 = 32 + 8 + 16 + 1 + 16 + 64;
    const BOND_RECORD_FIXED: u64 = 284;
    const COIN_FIXED: u64 = 104;
    const BOND_COIN_ID_BYTES: u64 = 17 + 64;
    const CHANGE_COIN_ID_BYTES: u64 = 19 + 64;

    let resource_key = format!("CANDIDATE/{}", candidate.validator_id);
    let sponsor_authorization_id = &request.resource_envelope.authorization.authorization_id;
    let owner_authorization_id = &request.authorization.authorization_id;
    let funding_coin_id = &request.resource_envelope.funding_coin_id;
    let sponsor = &request.resource_envelope.sponsor;
    let mut total = CANDIDATE_FIXED
        .checked_add(BOND_RECORD_FIXED)
        .and_then(|value| value.checked_add(COIN_FIXED.checked_mul(2)?))
        .ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic(
                "candidate migration persistent fixed fields".into(),
            )
        })?;
    for value in [
        candidate.validator_id.as_str(),
        candidate.owner.as_str(),
        resource_key.as_str(),
        candidate.owner.as_str(),
        sponsor.as_str(),
        sponsor_authorization_id.as_str(),
        funding_coin_id.as_str(),
        resource_key.as_str(),
        funding_coin_id.as_str(),
        sponsor.as_str(),
        request.zone_id.as_str(),
        request.zone_id.as_str(),
        funding_coin_id.as_str(),
        sponsor.as_str(),
        request.zone_id.as_str(),
        request.zone_id.as_str(),
        owner_authorization_id.as_str(),
        sponsor_authorization_id.as_str(),
        sponsor_authorization_id.as_str(),
        funding_coin_id.as_str(),
    ] {
        total = total
            .checked_add(framed_len(value, "candidate migration persistent text")?)
            .ok_or_else(|| {
                StakeResourceAccountingError::Arithmetic(
                    "candidate migration persistent footprint".into(),
                )
            })?;
    }
    total = total
        .checked_add(4 + BOND_COIN_ID_BYTES)
        .and_then(|value| value.checked_add(4 + BOND_COIN_ID_BYTES))
        .and_then(|value| value.checked_add(4 + CHANGE_COIN_ID_BYTES))
        .ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic(
                "candidate migration persistent Coin ids".into(),
            )
        })?;
    Ok(total)
}

fn framed_len(value: &str, label: &str) -> Result<u64, StakeResourceAccountingError> {
    u64::try_from(value.len())
        .ok()
        .and_then(|length| length.checked_add(4))
        .ok_or_else(|| StakeResourceAccountingError::Arithmetic(label.into()))
}

fn position_record_bytes_v3(
    position_id: &str,
    validator_id: &str,
    owner: &str,
    source_coin_id: &str,
    escrow_coin_id_bytes: u64,
    slash_authorization: &crate::SignedActionAuthorization,
) -> Result<u64, StakeResourceAccountingError> {
    // Enum, Amount, two u128 heights, terms/policy u16 fields, fixed decoded
    // hash/key/signature widths and authorization numeric fields.
    const POSITION_FIXED: u64 = 1 + 16 + 16 + 16 + 2 + 12 + 32 + 32 + 16 + 32 + 32 + 8 + 64;
    let mut total = POSITION_FIXED
        .checked_add(4 + escrow_coin_id_bytes)
        .ok_or_else(|| StakeResourceAccountingError::Arithmetic("position fixed fields".into()))?;
    for value in [
        position_id,
        validator_id,
        owner,
        source_coin_id,
        crate::CONSENSUS_SLASH_SAFETY_POOL_V2,
        slash_authorization.authorization_id.as_str(),
        slash_authorization.zone_id.as_str(),
        slash_authorization.action.as_str(),
    ] {
        total = total
            .checked_add(framed_len(value, "position persistent text length")?)
            .ok_or_else(|| {
                StakeResourceAccountingError::Arithmetic("position persistent footprint".into())
            })?;
    }
    Ok(total)
}

fn resource_position_admission_bytes_v1(
    resource_key: &str,
    owner: &str,
    sponsor: &str,
    sponsor_authorization_id: &str,
    funding_coin_id: &str,
    owner_authorization_id: &str,
    zone_id: &str,
) -> Result<u64, StakeResourceAccountingError> {
    const BOND_RECORD_FIXED: u64 = 284;
    const COIN_FIXED: u64 = 104;
    const BOND_COIN_ID_BYTES: u64 = 17 + 64;
    const CHANGE_COIN_ID_BYTES: u64 = 19 + 64;
    let mut total = BOND_RECORD_FIXED
        .checked_add(COIN_FIXED.checked_mul(2).ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic("position resource Coins".into())
        })?)
        .ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic("position resource fixed fields".into())
        })?;
    for value in [
        resource_key,
        owner,
        sponsor,
        sponsor_authorization_id,
        funding_coin_id,
        resource_key,
        funding_coin_id,
        sponsor,
        zone_id,
        zone_id,
        funding_coin_id,
        sponsor,
        zone_id,
        zone_id,
        owner_authorization_id,
        sponsor_authorization_id,
        sponsor_authorization_id,
        funding_coin_id,
    ] {
        total = total
            .checked_add(framed_len(value, "position resource text length")?)
            .ok_or_else(|| {
                StakeResourceAccountingError::Arithmetic(
                    "position resource admission footprint".into(),
                )
            })?;
    }
    total
        .checked_add(4 + BOND_COIN_ID_BYTES)
        .and_then(|value| value.checked_add(4 + BOND_COIN_ID_BYTES))
        .and_then(|value| value.checked_add(4 + CHANGE_COIN_ID_BYTES))
        .ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic("position resource Coin ids".into())
        })
}

/// Frozen logical footprint for a new V3 position.
///
/// The meter charges both retained position copies, the escrow map key, the
/// stake escrow and worst-case stake change, plus the resource record, bond,
/// worst-case resource change and all three authorization/funding indices.
pub fn lock_consensus_stake_persistent_bytes_v3(
    request: &LockConsensusStakeRequestV3,
) -> Result<u64, StakeResourceAccountingError> {
    const LEDGER_COIN_ID_BYTES: u64 = 5 + 32;
    const COIN_FIXED: u64 = 104;
    let resource_key = format!("POSITION/{}", request.position_id);
    let position = position_record_bytes_v3(
        &request.position_id,
        &request.validator_id,
        &request.owner,
        &request.source_coin_id,
        LEDGER_COIN_ID_BYTES,
        &request.slash_terms_authorization,
    )?;
    let mut total = position
        .checked_mul(2)
        .and_then(|value| value.checked_add(4 + LEDGER_COIN_ID_BYTES))
        .and_then(|value| value.checked_add(COIN_FIXED.checked_mul(2)?))
        .ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic("new position fixed footprint".into())
        })?;
    for value in [
        request.source_coin_id.as_str(),
        request.owner.as_str(),
        request.zone_id.as_str(),
        request.zone_id.as_str(),
        request.source_coin_id.as_str(),
        request.owner.as_str(),
        request.zone_id.as_str(),
        request.zone_id.as_str(),
    ] {
        total = total
            .checked_add(framed_len(value, "stake Coin persistent text length")?)
            .ok_or_else(|| {
                StakeResourceAccountingError::Arithmetic("stake Coin footprint".into())
            })?;
    }
    total = total
        .checked_add((4 + LEDGER_COIN_ID_BYTES) * 2)
        .ok_or_else(|| StakeResourceAccountingError::Arithmetic("stake Coin ids".into()))?;
    total
        .checked_add(resource_position_admission_bytes_v1(
            &resource_key,
            &request.owner,
            &request.resource_envelope.sponsor,
            &request.resource_envelope.authorization.authorization_id,
            &request.resource_envelope.funding_coin_id,
            &request.authorization.authorization_id,
            &request.zone_id,
        )?)
        .ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic("new position total footprint".into())
        })
}

/// Retroactively accounts the exact retained position inventory plus the new
/// resource record. It creates no new stake escrow or stake-principal change.
pub fn migrate_consensus_stake_resource_persistent_bytes_v1(
    request: &MigrateConsensusStakeResourceRequestV1,
    position: &ConsensusStakePosition,
) -> Result<u64, StakeResourceAccountingError> {
    let slash_authorization = position
        .slash_terms
        .as_ref()
        .ok_or_else(|| {
            StakeResourceAccountingError::InvalidRequest(
                "legacy position must accept objective slash terms before resource migration"
                    .into(),
            )
        })?
        .owner_authorization
        .clone();
    let escrow_coin_id_bytes = u64::try_from(position.escrow_coin_id.len()).map_err(|_| {
        StakeResourceAccountingError::Arithmetic("legacy escrow Coin id length".into())
    })?;
    let resource_key = format!("POSITION/{}", position.position_id);
    let position_bytes = position_record_bytes_v3(
        &position.position_id,
        position.validator_id(),
        &position.owner,
        &position.source_coin_id,
        escrow_coin_id_bytes,
        &slash_authorization,
    )?;
    let admission_bytes = resource_position_admission_bytes_v1(
        &resource_key,
        &request.owner,
        &request.resource_envelope.sponsor,
        &request.resource_envelope.authorization.authorization_id,
        &request.resource_envelope.funding_coin_id,
        &request.authorization.authorization_id,
        &request.zone_id,
    )?;
    position_bytes
        .checked_mul(2)
        .and_then(|value| value.checked_add(4 + escrow_coin_id_bytes))
        .and_then(|value| value.checked_add(admission_bytes))
        .ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic("migrated position total footprint".into())
        })
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StakeLiabilityHorizonUsageDeltaV1 {
    pub persistent_bytes: u64,
    pub state_reads: u32,
    pub state_writes: u32,
    pub appended_records: u32,
    pub touched_positions: u32,
}

fn stake_liability_horizon_record_bytes_v1(
    record: &StakePositionLiabilityHorizonV1,
) -> Result<u64, StakeResourceAccountingError> {
    record.validate().map_err(|error| {
        StakeResourceAccountingError::InvalidRequest(format!(
            "invalid liability horizon retention record: {error}"
        ))
    })?;
    let mut total = 2u64 + 8 + 16 + 8 + 32 * 3;
    for value in [
        record.position_id.as_str(),
        record.owner.as_str(),
        record.escrow_coin_id.as_str(),
    ] {
        total = total
            .checked_add(framed_len(value, "liability horizon text")?)
            .ok_or_else(|| {
                StakeResourceAccountingError::Arithmetic(
                    "liability horizon record footprint".into(),
                )
            })?;
    }
    Ok(total)
}

/// Exact persistent and state-operation delta between two authenticated
/// liability-horizon states. Existing history must be a strict prefix; no
/// rewrite, deletion or caller-supplied counter is accepted.
pub fn stake_liability_horizon_usage_delta_v1(
    previous_current: &BTreeMap<String, StakePositionLiabilityHorizonV1>,
    previous_history: &BTreeMap<String, Vec<StakePositionLiabilityHorizonV1>>,
    next_current: &BTreeMap<String, StakePositionLiabilityHorizonV1>,
    next_history: &BTreeMap<String, Vec<StakePositionLiabilityHorizonV1>>,
) -> Result<StakeLiabilityHorizonUsageDeltaV1, StakeResourceAccountingError> {
    if previous_current.len() != previous_history.len()
        || next_current.len() != next_history.len()
        || previous_current.keys().ne(previous_history.keys())
        || next_current.keys().ne(next_history.keys())
    {
        return Err(StakeResourceAccountingError::InvalidRequest(
            "liability horizon current/history key sets diverge".into(),
        ));
    }
    let mut result = StakeLiabilityHorizonUsageDeltaV1::default();
    for (position_id, records) in next_history {
        let next_tip = records.last().ok_or_else(|| {
            StakeResourceAccountingError::InvalidRequest(
                "liability horizon history cannot be empty".into(),
            )
        })?;
        if next_current.get(position_id) != Some(next_tip) {
            return Err(StakeResourceAccountingError::InvalidRequest(
                "liability horizon current record is not the history tip".into(),
            ));
        }
        let prior_records = previous_history.get(position_id);
        let prior_len = prior_records.map_or(0, Vec::len);
        if prior_len > records.len()
            || prior_records.is_some_and(|prior| records.get(..prior_len) != Some(prior.as_slice()))
            || previous_current.get(position_id) != prior_records.and_then(|prior| prior.last())
        {
            return Err(StakeResourceAccountingError::InvalidRequest(
                "liability horizon history is not append-only".into(),
            ));
        }
        let appended = &records[prior_len..];
        if appended.is_empty() {
            continue;
        }
        result.touched_positions = result.touched_positions.checked_add(1).ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic("liability horizon touched positions".into())
        })?;
        for record in appended {
            if record.position_id != *position_id {
                return Err(StakeResourceAccountingError::InvalidRequest(
                    "liability horizon map key does not match its record".into(),
                ));
            }
            result.persistent_bytes = result
                .persistent_bytes
                .checked_add(stake_liability_horizon_record_bytes_v1(record)?)
                .ok_or_else(|| {
                    StakeResourceAccountingError::Arithmetic(
                        "liability horizon history footprint".into(),
                    )
                })?;
            result.appended_records = result.appended_records.checked_add(1).ok_or_else(|| {
                StakeResourceAccountingError::Arithmetic(
                    "liability horizon appended records".into(),
                )
            })?;
        }
        if prior_records.is_none() {
            let map_key = framed_len(position_id, "liability horizon map key")?;
            let current_record = stake_liability_horizon_record_bytes_v1(next_tip)?;
            result.persistent_bytes = result
                .persistent_bytes
                .checked_add(map_key.checked_mul(2).ok_or_else(|| {
                    StakeResourceAccountingError::Arithmetic(
                        "liability horizon map key footprint".into(),
                    )
                })?)
                .and_then(|value| value.checked_add(4))
                .and_then(|value| value.checked_add(current_record))
                .ok_or_else(|| {
                    StakeResourceAccountingError::Arithmetic(
                        "liability horizon new-position footprint".into(),
                    )
                })?;
        }
    }
    if previous_history
        .keys()
        .any(|position_id| !next_history.contains_key(position_id))
    {
        return Err(StakeResourceAccountingError::InvalidRequest(
            "liability horizon history deletion is forbidden".into(),
        ));
    }
    if previous_history.is_empty() && !next_history.is_empty() {
        // Option discriminant plus the u64 activation Epoch retained by the
        // ledger to make bootstrap accounting exactly replayable.
        result.persistent_bytes = result.persistent_bytes.checked_add(1 + 8).ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic(
                "liability horizon activation Epoch footprint".into(),
            )
        })?;
    }
    result.state_reads = result
        .appended_records
        .checked_add(result.touched_positions)
        .ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic("liability horizon read meter".into())
        })?;
    result.state_writes = result.state_reads;
    Ok(result)
}

/// Deterministic state-read meter for V2 Epoch derivation. Every selected
/// candidate and every retained stake liability requires one resource-bond
/// lookup; the horizon delta additionally charges each retained source record
/// and each current-index lookup.
pub fn derive_next_stake_epoch_state_reads_v2(
    record: &LedgerDerivedStakeEpochV1,
    horizon_usage: StakeLiabilityHorizonUsageDeltaV1,
) -> Result<u32, StakeResourceAccountingError> {
    let dependency_reads = record
        .descriptor
        .validators
        .len()
        .checked_add(record.stake_liabilities.len())
        .ok_or_else(|| StakeResourceAccountingError::Arithmetic("Epoch read meter".into()))?;
    u32::try_from(dependency_reads)
        .ok()
        .and_then(|reads| reads.checked_add(DERIVE_NEXT_STAKE_EPOCH_BASE_STATE_READS_V2))
        .and_then(|reads| reads.checked_add(horizon_usage.state_reads))
        .ok_or_else(|| StakeResourceAccountingError::Arithmetic("Epoch read meter".into()))
}

pub fn derive_next_stake_epoch_state_writes_v2(
    horizon_usage: StakeLiabilityHorizonUsageDeltaV1,
) -> Result<u32, StakeResourceAccountingError> {
    DERIVE_NEXT_STAKE_EPOCH_BASE_STATE_WRITES_V2
        .checked_add(horizon_usage.state_writes)
        .ok_or_else(|| StakeResourceAccountingError::Arithmetic("Epoch write meter".into()))
}

/// Frozen logical footprint of the newly retained Epoch record and its
/// resource admission. Existing authority candidate/position objects are not
/// charged again; the descriptor and liability copies actually retained by
/// the Epoch record are charged exactly once.
pub fn derive_next_stake_epoch_persistent_bytes_v2(
    request: &DeriveNextStakeEpochRequestV2,
    record: &LedgerDerivedStakeEpochV1,
    horizon_usage: StakeLiabilityHorizonUsageDeltaV1,
) -> Result<u64, StakeResourceAccountingError> {
    fn add(total: &mut u64, value: u64, label: &str) -> Result<(), StakeResourceAccountingError> {
        *total = total
            .checked_add(value)
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic(label.into()))?;
        Ok(())
    }

    // Derivation version/status, heights, decoded hashes, vector framing and
    // descriptor quorum/numeric fields.
    let mut epoch_bytes = 2u64 + 1 + 16 + 32 + 32 + 32 + 32 + 4 + 32;
    let descriptor = &record.descriptor;
    let mut descriptor_bytes = 4u64 + 8 * 4 + 16 * 2 + 32 + 16 * 2 + (2 + 8 + 8 + 1);
    for value in [
        descriptor.network_domain.as_str(),
        descriptor.zone_id.as_str(),
    ] {
        add(
            &mut descriptor_bytes,
            framed_len(value, "Epoch descriptor text")?,
            "Epoch descriptor footprint",
        )?;
    }
    // currency_genesis_root and stake_snapshot_root are decoded 32-byte hashes.
    add(&mut descriptor_bytes, 32, "Epoch descriptor currency hash")?;
    for validator in &descriptor.validators {
        let mut validator_bytes = 32u64 + 8 + 16 * 4;
        for value in [
            validator.validator_id.as_str(),
            validator.control_group.as_str(),
        ] {
            add(
                &mut validator_bytes,
                framed_len(value, "Epoch validator text")?,
                "Epoch validator footprint",
            )?;
        }
        add(
            &mut descriptor_bytes,
            validator_bytes,
            "Epoch descriptor validators",
        )?;
    }
    add(&mut epoch_bytes, descriptor_bytes, "Epoch descriptor")?;

    for liability in &record.stake_liabilities {
        let slash_authorization = liability
            .position
            .slash_terms
            .as_ref()
            .ok_or_else(|| {
                StakeResourceAccountingError::InvalidRequest(
                    "Epoch liability lacks retained slash authorization".into(),
                )
            })?
            .owner_authorization
            .clone();
        let escrow_coin_id_bytes = u64::try_from(liability.position.escrow_coin_id.len())
            .map_err(|_| StakeResourceAccountingError::Arithmetic("Epoch escrow id".into()))?;
        let position_bytes = position_record_bytes_v3(
            &liability.position.position_id,
            liability.position.validator_id(),
            &liability.position.owner,
            &liability.position.source_coin_id,
            escrow_coin_id_bytes,
            &slash_authorization,
        )?;
        // Epoch, key, key era, four u128 boundaries and two decoded hashes.
        add(
            &mut epoch_bytes,
            8 + position_bytes + 32 + 8 + 16 * 4 + 32 + 32,
            "Epoch liability footprint",
        )?;
    }

    // Ordered epoch-map key plus the generic resource admission.
    add(&mut epoch_bytes, 8, "Epoch map key")?;
    let resource_key = format!("EPOCH/{}", record.descriptor.consensus_epoch);
    let admission_bytes = resource_position_admission_bytes_v1(
        &resource_key,
        &request.payer,
        &request.resource_envelope.sponsor,
        &request.resource_envelope.authorization.authorization_id,
        &request.resource_envelope.funding_coin_id,
        &request.authorization.authorization_id,
        &request.zone_id,
    )?;
    add(
        &mut epoch_bytes,
        admission_bytes,
        "Epoch resource admission",
    )?;
    add(
        &mut epoch_bytes,
        horizon_usage.persistent_bytes,
        "Epoch liability horizon retention",
    )?;
    Ok(epoch_bytes)
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StakeResourceAccountingError {
    #[error("invalid stake-resource policy: {0}")]
    InvalidPolicy(String),
    #[error("invalid stake-resource request: {0}")]
    InvalidRequest(String),
    #[error("stake-resource authorization failed: {0}")]
    Authorization(String),
    #[error("stake-resource funding Coin is invalid: {0}")]
    FundingCoin(String),
    #[error("stake-resource duplicate: {0}")]
    Duplicate(String),
    #[error("stake-resource hard limit exceeded: {0}")]
    HardLimit(String),
    #[error("stake-resource arithmetic overflow or underflow: {0}")]
    Arithmetic(String),
    #[error("stake-resource state failed validation: {0}")]
    InvalidState(String),
    #[error("stake-resource canonical recovery failed: {0}")]
    Recovery(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StakeStateResourceContextV1 {
    pub network_domain: String,
    pub zone_id: String,
    pub currency_genesis_root: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StakeStateResourceUsageV1 {
    pub wire_bytes: u32,
    pub persistent_bytes: u64,
    pub signature_checks: u32,
    pub state_reads: u32,
    pub state_writes: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StakeStateResourceAdmissionRequestV1 {
    pub resource_key: String,
    pub resource_kind: StakeStateResourceKindV1,
    pub resource_owner: String,
    pub outer_operation_hash: String,
    pub expected_parent_commitment: String,
    pub usage: StakeStateResourceUsageV1,
    pub envelope: StakeStateResourceEnvelopeV1,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StakeStateResourceBlockMeterV1 {
    pub height: u64,
    pub admitted_persistent_bytes: u64,
    pub signature_checks: u64,
    pub state_reads: u64,
    pub state_writes: u64,
}

impl StakeStateResourceBlockMeterV1 {
    fn empty(height: u64) -> Self {
        Self {
            height,
            admitted_persistent_bytes: 0,
            signature_checks: 0,
            state_reads: 0,
            state_writes: 0,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StakeStateResourceAdmissionOutcomeV1 {
    pub charged_fee: Amount,
    pub locked_bond: Amount,
    pub consumed_funding_coin: CoinObject,
    pub bond_coin: CoinObject,
    pub change_coin: Option<CoinObject>,
    pub bond_record: StakeStateBondRecordV2,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StakeStateResourceRenewalOutcomeV1 {
    pub charged_fee: Amount,
    pub additional_bond: Amount,
    pub consumed_funding_coin: CoinObject,
    pub bond_coin: CoinObject,
    pub change_coin: Option<CoinObject>,
    pub renewal_record: StakeStateBondRenewalRecordV1,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StakeStateResourceRefundOutcomeV1 {
    pub consumed_bond_coin: CoinObject,
    pub refund_coin: CoinObject,
    pub bond_record: StakeStateBondRecordV2,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StakeStateResourceForfeitOutcomeV1 {
    pub consumed_bond_coin: CoinObject,
    pub bond_record: StakeStateBondRecordV2,
}

/// Serializable, self-validating accounting state. R6.20 permits candidate,
/// position and Epoch admissions; later lifecycle kinds remain fail-closed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StakeStateResourceAccountingV1 {
    accounting_version: u16,
    context: StakeStateResourceContextV1,
    active_policy_sequence: u64,
    policies: BTreeMap<u64, StakeStateResourcePolicyV1>,
    policy_commitments: BTreeMap<u64, String>,
    bonds: BTreeMap<String, StakeStateBondRecordV2>,
    #[serde(default)]
    renewals: BTreeMap<String, StakeStateBondRenewalRecordV1>,
    consumed_funding_coin_ids: BTreeSet<String>,
    consumed_authorization_ids: BTreeSet<String>,
    total_persistent_bytes: u64,
    block_meter: StakeStateResourceBlockMeterV1,
    maintenance_pool: StakeStateMaintenancePoolV2,
}

impl StakeStateResourceKindV1 {
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Candidate => "CANDIDATE",
            Self::Position => "POSITION",
            Self::Epoch => "EPOCH",
            Self::Unbond => "UNBOND",
            Self::SlashEvidence => "SLASH_EVIDENCE",
        }
    }

    fn resource_key_prefix(self) -> &'static str {
        match self {
            Self::Candidate => "CANDIDATE/",
            Self::Position => "POSITION/",
            Self::Epoch => "EPOCH/",
            Self::Unbond => "UNBOND/",
            Self::SlashEvidence => "SLASH/",
        }
    }
}

impl StakeStateBondStatusV1 {
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Locked => "LOCKED",
            Self::Releaseable => "RELEASEABLE",
            Self::Refunded => "REFUNDED",
            Self::Forfeited => "FORFEITED",
        }
    }
}

pub fn stake_state_resource_policy_commitment_v1(
    policy: &StakeStateResourcePolicyV1,
) -> Result<String, StakeResourceAccountingError> {
    let bytes = policy
        .wire_v1_candidate_payload_bytes()
        .map_err(|error| StakeResourceAccountingError::InvalidPolicy(error.to_string()))?;
    Ok(hash_parts(&[
        b"RLD-STAKE-STATE-RESOURCE-POLICY-COMMITMENT-V1",
        &bytes,
    ]))
}

pub fn stake_state_resource_subject_hash_v1(
    context: &StakeStateResourceContextV1,
    request: &StakeStateResourceAdmissionRequestV1,
) -> String {
    action_payload_hash(
        FUND_STAKE_STATE_RESOURCE_ACTION_V1,
        &[
            context.network_domain.as_bytes(),
            context.zone_id.as_bytes(),
            context.currency_genesis_root.as_bytes(),
            &context.protocol_era.to_be_bytes(),
            &context.crypto_era.to_be_bytes(),
            request.resource_key.as_bytes(),
            request.resource_kind.wire_name().as_bytes(),
            request.resource_owner.as_bytes(),
            request.outer_operation_hash.as_bytes(),
            request.expected_parent_commitment.as_bytes(),
            &request.envelope.resource_policy_sequence.to_be_bytes(),
            request.envelope.resource_policy_commitment.as_bytes(),
            request.envelope.sponsor.as_bytes(),
            request.envelope.funding_coin_id.as_bytes(),
            &request.envelope.max_resource_fee.0.to_be_bytes(),
            &request.envelope.max_state_bond.0.to_be_bytes(),
            &request.envelope.lease_end_height.to_be_bytes(),
            &request.usage.wire_bytes.to_be_bytes(),
            &request.usage.persistent_bytes.to_be_bytes(),
            &request.usage.signature_checks.to_be_bytes(),
            &request.usage.state_reads.to_be_bytes(),
            &request.usage.state_writes.to_be_bytes(),
        ],
    )
}

impl StakeStateBondRecordV2 {
    /// Reconstructs the immutable admission-time record hash even after a
    /// later release/refund/forfeit transition extended the record chain.
    pub fn initial_record_hash(&self) -> String {
        let mut initial = self.clone();
        initial.status = StakeStateBondStatusV1::Locked;
        initial.terminal_record_commitment = ZERO_SHA256.into();
        initial.previous_record_hash = ZERO_SHA256.into();
        initial.compute_record_hash()
    }

    pub fn compute_record_hash(&self) -> String {
        hash_parts(&[
            b"RLD-STAKE-STATE-BOND-RECORD-V2",
            self.bond_id.as_bytes(),
            self.resource_key.as_bytes(),
            self.resource_kind.wire_name().as_bytes(),
            self.resource_owner.as_bytes(),
            &self.resource_policy_sequence.to_be_bytes(),
            self.resource_policy_commitment.as_bytes(),
            self.resource_subject_hash.as_bytes(),
            self.sponsor.as_bytes(),
            self.sponsor_authorization_id.as_bytes(),
            self.funding_source_coin_id.as_bytes(),
            self.bond_coin_id.as_bytes(),
            &self.locked_amount.0.to_be_bytes(),
            &self.charged_creation_fee.0.to_be_bytes(),
            &self.charged_wire_bytes.to_be_bytes(),
            &self.charged_persistent_bytes.to_be_bytes(),
            &self.charged_signature_checks.to_be_bytes(),
            &self.charged_state_reads.to_be_bytes(),
            &self.charged_state_writes.to_be_bytes(),
            &self.created_height.to_be_bytes(),
            &self.lease_end_height.to_be_bytes(),
            &self.forfeit_after_height.to_be_bytes(),
            self.status.wire_name().as_bytes(),
            self.terminal_record_commitment.as_bytes(),
            self.previous_record_hash.as_bytes(),
        ])
    }
}

impl StakeStateBondRenewalRecordV1 {
    pub fn compute_record_hash(&self) -> String {
        hash_parts(&[
            b"RLD-STAKE-STATE-BOND-RENEWAL-RECORD-V1",
            self.renewal_id.as_bytes(),
            self.resource_key.as_bytes(),
            self.resource_kind.wire_name().as_bytes(),
            self.resource_owner.as_bytes(),
            self.original_bond_id.as_bytes(),
            self.initial_bond_record_hash.as_bytes(),
            self.previous_renewal_hash.as_bytes(),
            &self.previous_lease_end_height.to_be_bytes(),
            &self.new_lease_end_height.to_be_bytes(),
            &self.resource_policy_sequence.to_be_bytes(),
            self.resource_policy_commitment.as_bytes(),
            self.sponsor.as_bytes(),
            self.sponsor_authorization_id.as_bytes(),
            self.funding_source_coin_id.as_bytes(),
            self.bond_coin_id.as_bytes(),
            &self.additional_locked_amount.0.to_be_bytes(),
            &self.charged_renewal_fee.0.to_be_bytes(),
            &self.charged_wire_bytes.to_be_bytes(),
            &self.charged_persistent_bytes.to_be_bytes(),
            &self.charged_signature_checks.to_be_bytes(),
            &self.charged_state_reads.to_be_bytes(),
            &self.charged_state_writes.to_be_bytes(),
            &self.renewed_height.to_be_bytes(),
            &self.forfeit_after_height.to_be_bytes(),
        ])
    }
}

impl StakeStateMaintenancePoolPolicyBucketV2 {
    pub fn compute_bucket_commitment(&self) -> String {
        hash_parts(&[
            b"RLD-STAKE-STATE-MAINTENANCE-POOL-POLICY-BUCKET-V2",
            &self.resource_policy_sequence.to_be_bytes(),
            self.resource_policy_commitment.as_bytes(),
            &self.charged_fees.0.to_be_bytes(),
            &self.forfeited_bonds.0.to_be_bytes(),
            &self.live_bonds.0.to_be_bytes(),
            &self.refunded_bonds.0.to_be_bytes(),
            &self.active_bond_records.to_be_bytes(),
            &self.terminal_bond_records.to_be_bytes(),
        ])
    }
}

impl StakeStateMaintenancePoolV2 {
    pub fn compute_pool_commitment(&self) -> String {
        let bucket_commitments = self
            .policy_buckets
            .iter()
            .flat_map(|bucket| {
                let mut bytes = Vec::with_capacity(40);
                bytes.extend_from_slice(&bucket.resource_policy_sequence.to_be_bytes());
                bytes.extend_from_slice(bucket.bucket_commitment.as_bytes());
                bytes
            })
            .collect::<Vec<_>>();
        hash_parts(&[
            b"RLD-STAKE-STATE-MAINTENANCE-POOL-V2",
            &self.pool_version.to_be_bytes(),
            &bucket_commitments,
            &self.total_charged_fees.0.to_be_bytes(),
            &self.total_forfeited_bonds.0.to_be_bytes(),
            &self.total_live_bonds.0.to_be_bytes(),
            &self.total_refunded_bonds.0.to_be_bytes(),
            &self.active_bond_records.to_be_bytes(),
            &self.terminal_bond_records.to_be_bytes(),
            self.previous_pool_commitment.as_bytes(),
            &[u8::from(self.runtime_payout_enabled)],
        ])
    }
}

impl StakeStateResourceAccountingV1 {
    pub fn new(
        context: StakeStateResourceContextV1,
        policy: StakeStateResourcePolicyV1,
        initial_height: u64,
    ) -> Result<Self, StakeResourceAccountingError> {
        validate_context(&context)?;
        validate_policy(&policy)?;
        let policy_commitment = stake_state_resource_policy_commitment_v1(&policy)?;
        let mut policy_bucket = StakeStateMaintenancePoolPolicyBucketV2 {
            resource_policy_sequence: policy.sequence,
            resource_policy_commitment: policy_commitment.clone(),
            charged_fees: Amount::ZERO,
            forfeited_bonds: Amount::ZERO,
            live_bonds: Amount::ZERO,
            refunded_bonds: Amount::ZERO,
            active_bond_records: 0,
            terminal_bond_records: 0,
            bucket_commitment: String::new(),
        };
        policy_bucket.bucket_commitment = policy_bucket.compute_bucket_commitment();
        let mut maintenance_pool = StakeStateMaintenancePoolV2 {
            pool_version: STAKE_RESOURCE_POOL_VERSION_V2,
            policy_buckets: vec![policy_bucket],
            total_charged_fees: Amount::ZERO,
            total_forfeited_bonds: Amount::ZERO,
            total_live_bonds: Amount::ZERO,
            total_refunded_bonds: Amount::ZERO,
            active_bond_records: 0,
            terminal_bond_records: 0,
            previous_pool_commitment: ZERO_SHA256.into(),
            runtime_payout_enabled: false,
            pool_commitment: String::new(),
        };
        maintenance_pool.pool_commitment = maintenance_pool.compute_pool_commitment();
        let sequence = policy.sequence;
        let mut policies = BTreeMap::new();
        policies.insert(sequence, policy);
        let mut policy_commitments = BTreeMap::new();
        policy_commitments.insert(sequence, policy_commitment);
        let state = Self {
            accounting_version: STAKE_RESOURCE_ACCOUNTING_VERSION_V1,
            context,
            active_policy_sequence: sequence,
            policies,
            policy_commitments,
            bonds: BTreeMap::new(),
            renewals: BTreeMap::new(),
            consumed_funding_coin_ids: BTreeSet::new(),
            consumed_authorization_ids: BTreeSet::new(),
            total_persistent_bytes: 0,
            block_meter: StakeStateResourceBlockMeterV1::empty(initial_height),
            maintenance_pool,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn active_policy(&self) -> &StakeStateResourcePolicyV1 {
        &self.policies[&self.active_policy_sequence]
    }

    pub const fn context(&self) -> &StakeStateResourceContextV1 {
        &self.context
    }

    pub fn active_policy_commitment(&self) -> &str {
        &self.policy_commitments[&self.active_policy_sequence]
    }

    pub fn policy_commitment(&self, sequence: u64) -> Option<&str> {
        self.policy_commitments.get(&sequence).map(String::as_str)
    }

    pub fn policy(&self, sequence: u64) -> Option<&StakeStateResourcePolicyV1> {
        self.policies.get(&sequence)
    }

    pub fn policy_generations(&self) -> usize {
        self.policies.len()
    }

    pub fn bonds(&self) -> &BTreeMap<String, StakeStateBondRecordV2> {
        &self.bonds
    }

    pub fn renewals(&self) -> &BTreeMap<String, StakeStateBondRenewalRecordV1> {
        &self.renewals
    }

    pub fn effective_lease_end_height(&self, resource_key: &str) -> Option<u64> {
        let original = self.bonds.get(resource_key)?;
        Some(
            self.renewals
                .values()
                .filter(|record| record.resource_key == resource_key)
                .map(|record| record.new_lease_end_height)
                .max()
                .unwrap_or(original.lease_end_height),
        )
    }

    pub const fn consumed_funding_coin_ids(&self) -> &BTreeSet<String> {
        &self.consumed_funding_coin_ids
    }

    pub const fn consumed_authorization_ids(&self) -> &BTreeSet<String> {
        &self.consumed_authorization_ids
    }

    pub fn has_accounted_value(&self) -> bool {
        let pool = &self.maintenance_pool;
        !self.bonds.is_empty()
            || !pool.total_charged_fees.is_zero()
            || !pool.total_forfeited_bonds.is_zero()
            || !pool.total_live_bonds.is_zero()
            || !pool.total_refunded_bonds.is_zero()
    }

    pub const fn total_persistent_bytes(&self) -> u64 {
        self.total_persistent_bytes
    }

    pub const fn block_meter(&self) -> &StakeStateResourceBlockMeterV1 {
        &self.block_meter
    }

    pub const fn maintenance_pool(&self) -> &StakeStateMaintenancePoolV2 {
        &self.maintenance_pool
    }

    pub fn state_hash(&self) -> Result<String, StakeResourceAccountingError> {
        Ok(hash_bytes(&self.canonical_json_bytes()?))
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, StakeResourceAccountingError> {
        serde_json::to_vec(self)
            .map_err(|error| StakeResourceAccountingError::Recovery(error.to_string()))
    }

    pub fn restore_canonical_json(bytes: &[u8]) -> Result<Self, StakeResourceAccountingError> {
        let state: Self = serde_json::from_slice(bytes)
            .map_err(|error| StakeResourceAccountingError::Recovery(error.to_string()))?;
        let canonical = state.canonical_json_bytes()?;
        if canonical != bytes {
            return Err(StakeResourceAccountingError::Recovery(
                "state JSON is not the exact canonical serialization".into(),
            ));
        }
        state.validate()?;
        Ok(state)
    }

    pub fn quote(
        &self,
        kind: StakeStateResourceKindV1,
        usage: StakeStateResourceUsageV1,
    ) -> Result<(Amount, Amount), StakeResourceAccountingError> {
        quote(self.active_policy(), kind, usage)
    }

    /// Activates the exact next policy while retaining every predecessor that
    /// is needed to re-derive historical bond charges. Governance delay and
    /// quorum authorization are intentionally enforced by the enclosing
    /// ledger command; this method enforces accounting continuity and limits.
    pub fn activate_policy(
        &mut self,
        policy: StakeStateResourcePolicyV1,
        activation_height: u64,
    ) -> Result<String, StakeResourceAccountingError> {
        self.validate()?;
        validate_policy(&policy)?;
        if self.policies.len() >= MAX_STAKE_RESOURCE_POLICY_GENERATIONS_V1 {
            return Err(StakeResourceAccountingError::HardLimit(
                "maximum retained resource-policy generations".into(),
            ));
        }
        let expected_sequence = self
            .active_policy_sequence
            .checked_add(1)
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("policy sequence".into()))?;
        let previous_commitment = self.active_policy_commitment().to_owned();
        if policy.sequence != expected_sequence
            || policy.previous_policy_commitment != previous_commitment
            || self.policies.contains_key(&policy.sequence)
        {
            return Err(StakeResourceAccountingError::InvalidPolicy(
                "policy is not the exact successor of the active policy".into(),
            ));
        }
        self.check_policy_can_cover_current_state(&policy)?;
        let commitment = stake_state_resource_policy_commitment_v1(&policy)?;
        let mut staged = self.clone();
        staged.policies.insert(policy.sequence, policy.clone());
        staged
            .policy_commitments
            .insert(policy.sequence, commitment.clone());
        staged.active_policy_sequence = policy.sequence;
        let mut bucket = StakeStateMaintenancePoolPolicyBucketV2 {
            resource_policy_sequence: policy.sequence,
            resource_policy_commitment: commitment.clone(),
            charged_fees: Amount::ZERO,
            forfeited_bonds: Amount::ZERO,
            live_bonds: Amount::ZERO,
            refunded_bonds: Amount::ZERO,
            active_bond_records: 0,
            terminal_bond_records: 0,
            bucket_commitment: String::new(),
        };
        bucket.bucket_commitment = bucket.compute_bucket_commitment();
        let previous_pool_commitment = staged.maintenance_pool.pool_commitment.clone();
        staged.maintenance_pool.policy_buckets.push(bucket);
        staged.recompute_pool(previous_pool_commitment)?;
        staged.block_meter = StakeStateResourceBlockMeterV1::empty(activation_height);
        staged.validate()?;
        *self = staged;
        Ok(commitment)
    }

    fn check_policy_can_cover_current_state(
        &self,
        policy: &StakeStateResourcePolicyV1,
    ) -> Result<(), StakeResourceAccountingError> {
        if self.total_persistent_bytes > policy.maximum_total_stake_state_bytes {
            return Err(StakeResourceAccountingError::HardLimit(
                "successor policy cannot cover existing persistent state".into(),
            ));
        }
        let active = self.bonds.values().filter(|record| {
            matches!(
                record.status,
                StakeStateBondStatusV1::Locked | StakeStateBondStatusV1::Releaseable
            )
        });
        for (kind, global_limit, owner_limit) in [
            (
                StakeStateResourceKindV1::Candidate,
                policy.maximum_active_candidates,
                policy.maximum_candidates_per_owner,
            ),
            (
                StakeStateResourceKindV1::Position,
                policy.maximum_active_positions,
                policy.maximum_positions_per_owner,
            ),
            (
                StakeStateResourceKindV1::Unbond,
                policy.maximum_pending_unbonds,
                policy.maximum_pending_unbonds_per_owner,
            ),
        ] {
            let matching = active
                .clone()
                .filter(|record| record.resource_kind == kind)
                .collect::<Vec<_>>();
            if matching.len() > global_limit as usize {
                return Err(StakeResourceAccountingError::HardLimit(
                    "successor policy global record limit is below live state".into(),
                ));
            }
            let mut by_owner = BTreeMap::<&str, usize>::new();
            for record in matching {
                *by_owner.entry(record.resource_owner.as_str()).or_default() += 1;
            }
            if by_owner.values().any(|count| *count > owner_limit as usize) {
                return Err(StakeResourceAccountingError::HardLimit(
                    "successor policy owner limit is below live state".into(),
                ));
            }
        }
        Ok(())
    }

    /// Atomically admits one separately funded resource responsibility.
    pub fn admit(
        &mut self,
        request: StakeStateResourceAdmissionRequestV1,
        funding_coin: &CoinObject,
        protected_coin_ids: &BTreeSet<String>,
        current_height: u64,
    ) -> Result<StakeStateResourceAdmissionOutcomeV1, StakeResourceAccountingError> {
        self.validate()?;
        let mut staged = self.clone();
        let outcome =
            staged.admit_inner(request, funding_coin, protected_coin_ids, current_height)?;
        staged.validate()?;
        *self = staged;
        Ok(outcome)
    }

    fn admit_inner(
        &mut self,
        request: StakeStateResourceAdmissionRequestV1,
        funding_coin: &CoinObject,
        protected_coin_ids: &BTreeSet<String>,
        current_height: u64,
    ) -> Result<StakeStateResourceAdmissionOutcomeV1, StakeResourceAccountingError> {
        validate_request_shape(&request)?;
        if !request
            .resource_key
            .starts_with(request.resource_kind.resource_key_prefix())
        {
            return Err(StakeResourceAccountingError::InvalidRequest(
                "resource key prefix does not match resource kind".into(),
            ));
        }
        if self.bonds.contains_key(&request.resource_key) {
            return Err(StakeResourceAccountingError::Duplicate(
                request.resource_key,
            ));
        }
        let envelope = &request.envelope;
        if envelope.resource_policy_sequence != self.active_policy_sequence
            || envelope.resource_policy_commitment != self.active_policy_commitment()
        {
            return Err(StakeResourceAccountingError::InvalidRequest(
                "resource envelope does not bind the active policy".into(),
            ));
        }
        let expected_subject = stake_state_resource_subject_hash_v1(&self.context, &request);
        if envelope.resource_subject_hash != expected_subject
            || envelope.authorization.payload_hash != expected_subject
        {
            return Err(StakeResourceAccountingError::Authorization(
                "resource subject hash mismatch".into(),
            ));
        }
        if self
            .consumed_authorization_ids
            .contains(&envelope.authorization.authorization_id)
        {
            return Err(StakeResourceAccountingError::Duplicate(
                envelope.authorization.authorization_id.clone(),
            ));
        }
        envelope
            .authorization
            .verify_scope(
                &self.context.zone_id,
                &self.context.currency_genesis_root,
                self.context.protocol_era,
                self.context.crypto_era,
                FUND_STAKE_STATE_RESOURCE_ACTION_V1,
                &expected_subject,
            )
            .map_err(StakeResourceAccountingError::Authorization)?;
        if envelope.authorization.signer_address() != envelope.sponsor {
            return Err(StakeResourceAccountingError::Authorization(
                "resource sponsor is not the authorization signer".into(),
            ));
        }
        self.validate_funding_coin(envelope, funding_coin, protected_coin_ids)?;

        let policy = self.active_policy().clone();
        let minimum_lease_end = current_height
            .checked_add(policy.minimum_lease_blocks)
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("lease minimum".into()))?;
        let maximum_lease_end = current_height
            .checked_add(policy.maximum_lease_blocks)
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("lease maximum".into()))?;
        if envelope.lease_end_height < minimum_lease_end
            || envelope.lease_end_height > maximum_lease_end
        {
            return Err(StakeResourceAccountingError::InvalidRequest(
                "lease is outside the active policy bounds".into(),
            ));
        }
        let forfeit_after_height = envelope
            .lease_end_height
            .checked_add(policy.expiry_grace_blocks)
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("forfeit height".into()))?;
        self.check_count_limits(&request)?;
        self.check_and_stage_block_meter(current_height, request.usage, &policy)?;
        let next_total_bytes = self
            .total_persistent_bytes
            .checked_add(request.usage.persistent_bytes)
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("state bytes".into()))?;
        if next_total_bytes > policy.maximum_total_stake_state_bytes {
            return Err(StakeResourceAccountingError::HardLimit(
                "maximum total stake-state bytes".into(),
            ));
        }

        let (charged_fee, locked_bond) = quote(&policy, request.resource_kind, request.usage)?;
        if charged_fee > envelope.max_resource_fee || locked_bond > envelope.max_state_bond {
            return Err(StakeResourceAccountingError::InvalidRequest(
                "deterministic fee or bond exceeds sponsor maximum".into(),
            ));
        }
        let required = charged_fee
            .checked_add(locked_bond)
            .map_err(|_| StakeResourceAccountingError::Arithmetic("fee plus bond".into()))?;
        if funding_coin.amount < required {
            return Err(StakeResourceAccountingError::FundingCoin(
                "funding amount is below fee plus bond".into(),
            ));
        }
        let next_version = funding_coin
            .version
            .checked_add(1)
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("Coin version".into()))?;
        let bond_id = hash_parts(&[
            b"RLD-STAKE-STATE-BOND-ID-V2",
            request.resource_key.as_bytes(),
            envelope.funding_coin_id.as_bytes(),
            envelope.resource_policy_commitment.as_bytes(),
            &current_height.to_be_bytes(),
        ]);
        let bond_coin_id = format!("stake-state-bond:{bond_id}");
        if self
            .bonds
            .values()
            .any(|record| record.bond_id == bond_id || record.bond_coin_id == bond_coin_id)
        {
            return Err(StakeResourceAccountingError::Duplicate(bond_id));
        }
        let mut record = StakeStateBondRecordV2 {
            bond_id,
            resource_key: request.resource_key.clone(),
            resource_kind: request.resource_kind,
            resource_owner: request.resource_owner,
            resource_policy_sequence: envelope.resource_policy_sequence,
            resource_policy_commitment: envelope.resource_policy_commitment.clone(),
            resource_subject_hash: expected_subject,
            sponsor: envelope.sponsor.clone(),
            sponsor_authorization_id: envelope.authorization.authorization_id.clone(),
            funding_source_coin_id: funding_coin.object_id.clone(),
            bond_coin_id: bond_coin_id.clone(),
            locked_amount: locked_bond,
            charged_creation_fee: charged_fee,
            charged_wire_bytes: request.usage.wire_bytes,
            charged_persistent_bytes: request.usage.persistent_bytes,
            charged_signature_checks: request.usage.signature_checks,
            charged_state_reads: request.usage.state_reads,
            charged_state_writes: request.usage.state_writes,
            created_height: current_height,
            lease_end_height: envelope.lease_end_height,
            forfeit_after_height,
            status: StakeStateBondStatusV1::Locked,
            terminal_record_commitment: ZERO_SHA256.into(),
            previous_record_hash: ZERO_SHA256.into(),
            record_hash: String::new(),
        };
        record.record_hash = record.compute_record_hash();

        let mut consumed_funding_coin = funding_coin.clone();
        consumed_funding_coin.state = CoinState::Consumed;
        let bond_coin = child_coin(
            funding_coin,
            bond_coin_id,
            envelope.sponsor.clone(),
            locked_bond,
            CoinState::Reserved,
            next_version,
            current_height,
        );
        let change = funding_coin
            .amount
            .checked_sub(required)
            .map_err(|_| StakeResourceAccountingError::Arithmetic("funding change".into()))?;
        let change_coin = if change.is_zero() {
            None
        } else {
            let change_id = hash_parts(&[
                b"RLD-STAKE-STATE-RESOURCE-CHANGE-COIN-V1",
                funding_coin.object_id.as_bytes(),
                record.bond_id.as_bytes(),
                &change.0.to_be_bytes(),
            ]);
            Some(child_coin(
                funding_coin,
                format!("stake-state-change:{change_id}"),
                envelope.sponsor.clone(),
                change,
                CoinState::Spendable,
                next_version,
                current_height,
            ))
        };

        let output_total = charged_fee
            .checked_add(bond_coin.amount)
            .and_then(|total| {
                total.checked_add(
                    change_coin
                        .as_ref()
                        .map_or(Amount::ZERO, |coin| coin.amount),
                )
            })
            .map_err(|_| StakeResourceAccountingError::Arithmetic("admission outputs".into()))?;
        if output_total != funding_coin.amount {
            return Err(StakeResourceAccountingError::InvalidState(
                "admission does not conserve funding value".into(),
            ));
        }

        self.consumed_funding_coin_ids
            .insert(funding_coin.object_id.clone());
        self.consumed_authorization_ids
            .insert(envelope.authorization.authorization_id.clone());
        self.total_persistent_bytes = next_total_bytes;
        self.credit_admission_pool(&record)?;
        self.bonds
            .insert(record.resource_key.clone(), record.clone());
        Ok(StakeStateResourceAdmissionOutcomeV1 {
            charged_fee,
            locked_bond,
            consumed_funding_coin,
            bond_coin,
            change_coin,
            bond_record: record,
        })
    }

    /// Extends exactly one live resource history using a fresh Coin and one
    /// fresh sponsor authorization. The original record is never mutated.
    pub fn renew(
        &mut self,
        request: &RenewStakeStateResourceBondRequestV1,
        usage: StakeStateResourceUsageV1,
        funding_coin: &CoinObject,
        protected_coin_ids: &BTreeSet<String>,
        current_height: u64,
    ) -> Result<StakeStateResourceRenewalOutcomeV1, StakeResourceAccountingError> {
        self.validate()?;
        let mut staged = self.clone();
        let outcome = staged.renew_inner(
            request,
            usage,
            funding_coin,
            protected_coin_ids,
            current_height,
        )?;
        staged.validate()?;
        *self = staged;
        Ok(outcome)
    }

    fn renew_inner(
        &mut self,
        request: &RenewStakeStateResourceBondRequestV1,
        usage: StakeStateResourceUsageV1,
        funding_coin: &CoinObject,
        protected_coin_ids: &BTreeSet<String>,
        current_height: u64,
    ) -> Result<StakeStateResourceRenewalOutcomeV1, StakeResourceAccountingError> {
        if request.renewal_id.trim().is_empty()
            || request.resource_key.is_empty()
            || request.resource_key.len() > 256
            || !request.resource_key.is_ascii()
            || request.resource_owner.trim().is_empty()
            || request.sponsor.trim().is_empty()
            || request.funding_coin_id.trim().is_empty()
            || !is_hash(&request.expected_initial_bond_record_hash)
            || !is_hash(&request.expected_previous_renewal_hash)
            || !is_hash(&request.resource_policy_commitment)
            || usage.wire_bytes == 0
            || usage.persistent_bytes == 0
            || usage.signature_checks == 0
            || usage.state_reads == 0
            || usage.state_writes == 0
        {
            return Err(StakeResourceAccountingError::InvalidRequest(
                "renewal identity, hashes or internally derived usage are invalid".into(),
            ));
        }
        if self.renewals.contains_key(&request.renewal_id) {
            return Err(StakeResourceAccountingError::Duplicate(
                request.renewal_id.clone(),
            ));
        }
        if request.resource_policy_sequence != self.active_policy_sequence
            || request.resource_policy_commitment != self.active_policy_commitment()
        {
            return Err(StakeResourceAccountingError::InvalidRequest(
                "renewal does not bind the active resource policy".into(),
            ));
        }
        let original = self
            .bonds
            .get(&request.resource_key)
            .cloned()
            .ok_or_else(|| {
                StakeResourceAccountingError::InvalidRequest("unknown resource bond".into())
            })?;
        if original.status != StakeStateBondStatusV1::Locked
            || original.resource_kind != request.resource_kind
            || original.resource_owner != request.resource_owner
            || original.bond_id != request.expected_bond_id
            || original.initial_record_hash() != request.expected_initial_bond_record_hash
        {
            return Err(StakeResourceAccountingError::InvalidRequest(
                "renewal does not bind the exact locked resource history".into(),
            ));
        }
        let latest = self
            .renewals
            .values()
            .filter(|record| record.resource_key == request.resource_key)
            .max_by_key(|record| record.new_lease_end_height);
        let expected_tip = latest.map_or(ZERO_SHA256, |record| record.record_hash.as_str());
        let current_lease = latest.map_or(original.lease_end_height, |record| {
            record.new_lease_end_height
        });
        if request.expected_previous_renewal_hash != expected_tip
            || request.expected_current_lease_end_height != current_lease
            || request.new_lease_end_height <= current_lease
            || current_height > current_lease
        {
            return Err(StakeResourceAccountingError::InvalidRequest(
                "renewal predecessor, current lease or monotonic extension mismatch".into(),
            ));
        }
        let policy = self.active_policy().clone();
        let minimum_end = current_height
            .checked_add(policy.minimum_lease_blocks)
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("renewal minimum".into()))?;
        let maximum_end = current_height
            .checked_add(policy.maximum_lease_blocks)
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("renewal maximum".into()))?;
        if request.new_lease_end_height < minimum_end || request.new_lease_end_height > maximum_end
        {
            return Err(StakeResourceAccountingError::InvalidRequest(
                "renewed lease is outside active policy bounds".into(),
            ));
        }
        if request.authorization.payload_hash != request.payload_hash() {
            return Err(StakeResourceAccountingError::Authorization(
                "renewal authorization payload mismatch".into(),
            ));
        }
        if self
            .consumed_authorization_ids
            .contains(&request.authorization.authorization_id)
        {
            return Err(StakeResourceAccountingError::Duplicate(
                request.authorization.authorization_id.clone(),
            ));
        }
        request
            .authorization
            .verify_scope(
                &self.context.zone_id,
                &self.context.currency_genesis_root,
                self.context.protocol_era,
                self.context.crypto_era,
                RENEW_STAKE_STATE_RESOURCE_BOND_ACTION_V1,
                &request.payload_hash(),
            )
            .map_err(StakeResourceAccountingError::Authorization)?;
        if request.authorization.signer_address() != request.sponsor {
            return Err(StakeResourceAccountingError::Authorization(
                "renewal sponsor is not the authorization signer".into(),
            ));
        }
        if request.funding_coin_id != funding_coin.object_id
            || funding_coin.state != CoinState::Spendable
            || funding_coin.owner != request.sponsor
            || funding_coin.zone_id != self.context.zone_id
            || funding_coin.origin_genesis_root != self.context.currency_genesis_root
            || funding_coin.transit_id.is_some()
            || protected_coin_ids.contains(&funding_coin.object_id)
            || self
                .consumed_funding_coin_ids
                .contains(&funding_coin.object_id)
            || self
                .bonds
                .values()
                .any(|record| record.bond_coin_id == funding_coin.object_id)
            || self
                .renewals
                .values()
                .any(|record| record.bond_coin_id == funding_coin.object_id)
        {
            return Err(StakeResourceAccountingError::FundingCoin(
                "renewal funding Coin is not fresh, independent and spendable".into(),
            ));
        }

        self.check_and_stage_block_meter(current_height, usage, &policy)?;
        let next_total_bytes = self
            .total_persistent_bytes
            .checked_add(usage.persistent_bytes)
            .ok_or_else(|| {
                StakeResourceAccountingError::Arithmetic("renewal state bytes".into())
            })?;
        if next_total_bytes > policy.maximum_total_stake_state_bytes {
            return Err(StakeResourceAccountingError::HardLimit(
                "maximum total stake-state bytes".into(),
            ));
        }
        let delta = request
            .new_lease_end_height
            .checked_sub(current_lease)
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("renewal delta".into()))?;
        let (charged_fee, additional_bond) = quote_renewal(
            &policy,
            request.resource_kind,
            original.charged_persistent_bytes,
            delta,
            usage,
        )?;
        if charged_fee > request.max_resource_fee
            || additional_bond > request.max_additional_bond
            || additional_bond.is_zero()
        {
            return Err(StakeResourceAccountingError::InvalidRequest(
                "renewal fee or additional bond exceeds signed maximum".into(),
            ));
        }
        let required = charged_fee
            .checked_add(additional_bond)
            .map_err(|_| StakeResourceAccountingError::Arithmetic("renewal funding".into()))?;
        if funding_coin.amount < required {
            return Err(StakeResourceAccountingError::FundingCoin(
                "renewal funding is below fee plus additional bond".into(),
            ));
        }
        let next_version = funding_coin.version.checked_add(1).ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic("renewal Coin version".into())
        })?;
        let bond_id = hash_parts(&[
            b"RLD-STAKE-STATE-RENEWAL-BOND-ID-V1",
            request.renewal_id.as_bytes(),
            request.resource_key.as_bytes(),
            request.expected_previous_renewal_hash.as_bytes(),
            funding_coin.object_id.as_bytes(),
        ]);
        let bond_coin_id = format!("stake-state-renewal-bond:{bond_id}");
        if self
            .renewals
            .values()
            .any(|record| record.bond_coin_id == bond_coin_id)
        {
            return Err(StakeResourceAccountingError::Duplicate(bond_coin_id));
        }
        let forfeit_after_height = request
            .new_lease_end_height
            .checked_add(policy.expiry_grace_blocks)
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("renewal forfeit".into()))?;
        let mut record = StakeStateBondRenewalRecordV1 {
            renewal_id: request.renewal_id.clone(),
            resource_key: request.resource_key.clone(),
            resource_kind: request.resource_kind,
            resource_owner: request.resource_owner.clone(),
            original_bond_id: original.bond_id,
            initial_bond_record_hash: request.expected_initial_bond_record_hash.clone(),
            previous_renewal_hash: request.expected_previous_renewal_hash.clone(),
            previous_lease_end_height: current_lease,
            new_lease_end_height: request.new_lease_end_height,
            resource_policy_sequence: request.resource_policy_sequence,
            resource_policy_commitment: request.resource_policy_commitment.clone(),
            sponsor: request.sponsor.clone(),
            sponsor_authorization_id: request.authorization.authorization_id.clone(),
            funding_source_coin_id: funding_coin.object_id.clone(),
            bond_coin_id: bond_coin_id.clone(),
            additional_locked_amount: additional_bond,
            charged_renewal_fee: charged_fee,
            charged_wire_bytes: usage.wire_bytes,
            charged_persistent_bytes: usage.persistent_bytes,
            charged_signature_checks: usage.signature_checks,
            charged_state_reads: usage.state_reads,
            charged_state_writes: usage.state_writes,
            renewed_height: current_height,
            forfeit_after_height,
            record_hash: String::new(),
        };
        record.record_hash = record.compute_record_hash();
        let mut consumed_funding_coin = funding_coin.clone();
        consumed_funding_coin.state = CoinState::Consumed;
        let bond_coin = child_coin(
            funding_coin,
            bond_coin_id,
            request.sponsor.clone(),
            additional_bond,
            CoinState::Reserved,
            next_version,
            current_height,
        );
        let change = funding_coin
            .amount
            .checked_sub(required)
            .map_err(|_| StakeResourceAccountingError::Arithmetic("renewal change".into()))?;
        let change_coin = if change.is_zero() {
            None
        } else {
            let change_id = hash_parts(&[
                b"RLD-STAKE-STATE-RENEWAL-CHANGE-COIN-V1",
                funding_coin.object_id.as_bytes(),
                record.record_hash.as_bytes(),
                &change.0.to_be_bytes(),
            ]);
            Some(child_coin(
                funding_coin,
                format!("stake-state-renewal-change:{change_id}"),
                request.sponsor.clone(),
                change,
                CoinState::Spendable,
                next_version,
                current_height,
            ))
        };
        let output_total = charged_fee
            .checked_add(bond_coin.amount)
            .and_then(|total| {
                total.checked_add(
                    change_coin
                        .as_ref()
                        .map_or(Amount::ZERO, |coin| coin.amount),
                )
            })
            .map_err(|_| StakeResourceAccountingError::Arithmetic("renewal outputs".into()))?;
        if output_total != funding_coin.amount {
            return Err(StakeResourceAccountingError::InvalidState(
                "renewal does not conserve funding value".into(),
            ));
        }
        self.consumed_funding_coin_ids
            .insert(funding_coin.object_id.clone());
        self.consumed_authorization_ids
            .insert(request.authorization.authorization_id.clone());
        self.total_persistent_bytes = next_total_bytes;
        self.credit_renewal_pool(&record)?;
        self.renewals
            .insert(request.renewal_id.clone(), record.clone());
        Ok(StakeStateResourceRenewalOutcomeV1 {
            charged_fee,
            additional_bond,
            consumed_funding_coin,
            bond_coin,
            change_coin,
            renewal_record: record,
        })
    }

    /// Marks a bond refundable only after an externally authoritative terminal
    /// record, all liability deadlines and the policy retention interval have
    /// ended. The terminal commitment is retained in the hash chain.
    pub fn mark_releaseable(
        &mut self,
        resource_key: &str,
        terminal_record_commitment: &str,
        last_liability_height: u64,
        terminal_state_height: u64,
        current_height: u64,
    ) -> Result<StakeStateBondRecordV2, StakeResourceAccountingError> {
        self.validate()?;
        if !is_hash(terminal_record_commitment) || terminal_record_commitment == ZERO_SHA256 {
            return Err(StakeResourceAccountingError::InvalidRequest(
                "terminal record commitment must be a nonzero canonical hash".into(),
            ));
        }
        let mut staged = self.clone();
        let current = staged.bonds.get(resource_key).cloned().ok_or_else(|| {
            StakeResourceAccountingError::InvalidRequest("unknown resource".into())
        })?;
        if current.status != StakeStateBondStatusV1::Locked {
            return Err(StakeResourceAccountingError::InvalidRequest(
                "only a locked bond can become releaseable".into(),
            ));
        }
        let policy = staged
            .policies
            .get(&current.resource_policy_sequence)
            .ok_or_else(|| StakeResourceAccountingError::InvalidState("missing policy".into()))?;
        let retention_end = terminal_state_height
            .checked_add(policy.terminal_retention_blocks)
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("retention height".into()))?;
        if current_height < last_liability_height.max(retention_end) {
            return Err(StakeResourceAccountingError::InvalidRequest(
                "liability or terminal retention boundary has not ended".into(),
            ));
        }
        let record = staged
            .bonds
            .get_mut(resource_key)
            .expect("record checked above");
        record.previous_record_hash = current.record_hash;
        record.status = StakeStateBondStatusV1::Releaseable;
        record.terminal_record_commitment = terminal_record_commitment.into();
        record.record_hash = record.compute_record_hash();
        let result = record.clone();
        staged.validate()?;
        *self = staged;
        Ok(result)
    }

    pub fn refund(
        &mut self,
        resource_key: &str,
        funding_source_coin: &CoinObject,
        bond_coin: &CoinObject,
        current_height: u64,
    ) -> Result<StakeStateResourceRefundOutcomeV1, StakeResourceAccountingError> {
        self.validate()?;
        let mut staged = self.clone();
        let current = staged.bonds.get(resource_key).cloned().ok_or_else(|| {
            StakeResourceAccountingError::InvalidRequest("unknown resource".into())
        })?;
        if current.status != StakeStateBondStatusV1::Releaseable {
            return Err(StakeResourceAccountingError::InvalidRequest(
                "bond is not releaseable".into(),
            ));
        }
        validate_bond_coin(&current, funding_source_coin, bond_coin)?;
        let next_version = bond_coin.version.checked_add(1).ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic("refund Coin version".into())
        })?;
        let refund_id = hash_parts(&[
            b"RLD-STAKE-STATE-BOND-REFUND-COIN-V1",
            bond_coin.object_id.as_bytes(),
            current.record_hash.as_bytes(),
            &current_height.to_be_bytes(),
        ]);
        let refund_coin = child_coin(
            bond_coin,
            format!("stake-state-refund:{refund_id}"),
            current.sponsor.clone(),
            current.locked_amount,
            CoinState::Spendable,
            next_version,
            current_height,
        );
        let mut consumed_bond_coin = bond_coin.clone();
        consumed_bond_coin.state = CoinState::Consumed;
        let record = staged
            .bonds
            .get_mut(resource_key)
            .expect("record checked above");
        record.previous_record_hash = current.record_hash;
        record.status = StakeStateBondStatusV1::Refunded;
        record.record_hash = record.compute_record_hash();
        let result_record = record.clone();
        staged.settle_pool(&result_record, false)?;
        staged.validate()?;
        *self = staged;
        Ok(StakeStateResourceRefundOutcomeV1 {
            consumed_bond_coin,
            refund_coin,
            bond_record: result_record,
        })
    }

    pub fn forfeit(
        &mut self,
        resource_key: &str,
        terminal_record_commitment: &str,
        funding_source_coin: &CoinObject,
        bond_coin: &CoinObject,
        current_height: u64,
    ) -> Result<StakeStateResourceForfeitOutcomeV1, StakeResourceAccountingError> {
        self.validate()?;
        if !is_hash(terminal_record_commitment) || terminal_record_commitment == ZERO_SHA256 {
            return Err(StakeResourceAccountingError::InvalidRequest(
                "forfeit requires a nonzero expiry-terminal commitment".into(),
            ));
        }
        let mut staged = self.clone();
        let current = staged.bonds.get(resource_key).cloned().ok_or_else(|| {
            StakeResourceAccountingError::InvalidRequest("unknown resource".into())
        })?;
        if current.status != StakeStateBondStatusV1::Locked
            || current_height < current.forfeit_after_height
        {
            return Err(StakeResourceAccountingError::InvalidRequest(
                "bond is not eligible for deterministic forfeiture".into(),
            ));
        }
        validate_bond_coin(&current, funding_source_coin, bond_coin)?;
        let mut consumed_bond_coin = bond_coin.clone();
        consumed_bond_coin.state = CoinState::Consumed;
        let record = staged
            .bonds
            .get_mut(resource_key)
            .expect("record checked above");
        record.previous_record_hash = current.record_hash;
        record.status = StakeStateBondStatusV1::Forfeited;
        record.terminal_record_commitment = terminal_record_commitment.into();
        record.record_hash = record.compute_record_hash();
        let result_record = record.clone();
        staged.settle_pool(&result_record, true)?;
        staged.validate()?;
        *self = staged;
        Ok(StakeStateResourceForfeitOutcomeV1 {
            consumed_bond_coin,
            bond_record: result_record,
        })
    }

    pub fn validate(&self) -> Result<(), StakeResourceAccountingError> {
        if self.accounting_version != STAKE_RESOURCE_ACCOUNTING_VERSION_V1 {
            return Err(StakeResourceAccountingError::InvalidState(
                "unsupported accounting version".into(),
            ));
        }
        validate_context(&self.context)?;
        if self.policies.is_empty()
            || self.policies.len() > MAX_STAKE_RESOURCE_POLICY_GENERATIONS_V1
            || !self.policies.contains_key(&self.active_policy_sequence)
            || self.policies.len() != self.policy_commitments.len()
        {
            return Err(StakeResourceAccountingError::InvalidState(
                "active policy registry is inconsistent".into(),
            ));
        }
        let mut previous: Option<(u64, String)> = None;
        for (sequence, policy) in &self.policies {
            validate_policy(policy)?;
            let commitment = stake_state_resource_policy_commitment_v1(policy)?;
            let chain_is_valid = match &previous {
                None => policy.previous_policy_commitment == ZERO_SHA256,
                Some((previous_sequence, previous_commitment)) => {
                    previous_sequence.checked_add(1) == Some(*sequence)
                        && policy.previous_policy_commitment == *previous_commitment
                }
            };
            if *sequence != policy.sequence
                || self.policy_commitments.get(sequence) != Some(&commitment)
                || !chain_is_valid
            {
                return Err(StakeResourceAccountingError::InvalidState(
                    "policy sequence, predecessor or commitment mismatch".into(),
                ));
            }
            previous = Some((*sequence, commitment));
        }

        let mut expected_sources = self
            .bonds
            .values()
            .map(|record| record.funding_source_coin_id.clone())
            .collect::<BTreeSet<_>>();
        expected_sources.extend(
            self.renewals
                .values()
                .map(|record| record.funding_source_coin_id.clone()),
        );
        let mut expected_authorizations = self
            .bonds
            .values()
            .map(|record| record.sponsor_authorization_id.clone())
            .collect::<BTreeSet<_>>();
        expected_authorizations.extend(
            self.renewals
                .values()
                .map(|record| record.sponsor_authorization_id.clone()),
        );
        let expected_nullifiers = self
            .bonds
            .len()
            .checked_add(self.renewals.len())
            .ok_or_else(|| {
                StakeResourceAccountingError::Arithmetic("resource nullifiers".into())
            })?;
        if expected_sources.len() != expected_nullifiers
            || expected_authorizations.len() != expected_nullifiers
            || expected_sources != self.consumed_funding_coin_ids
            || expected_authorizations != self.consumed_authorization_ids
        {
            return Err(StakeResourceAccountingError::InvalidState(
                "funding or authorization nullifier set diverges from bonds".into(),
            ));
        }
        let mut bond_ids = BTreeSet::new();
        let mut bond_coin_ids = BTreeSet::new();
        let mut total_bytes = 0u64;
        for (resource_key, record) in &self.bonds {
            if resource_key != &record.resource_key
                || !bond_ids.insert(record.bond_id.as_str())
                || !bond_coin_ids.insert(record.bond_coin_id.as_str())
                || !record
                    .resource_key
                    .starts_with(record.resource_kind.resource_key_prefix())
                || self
                    .policy_commitments
                    .get(&record.resource_policy_sequence)
                    != Some(&record.resource_policy_commitment)
                || record.record_hash != record.compute_record_hash()
                || !is_hash(&record.resource_subject_hash)
                || !is_hash(&record.terminal_record_commitment)
                || !is_hash(&record.previous_record_hash)
                || record.created_height >= record.lease_end_height
                || record.lease_end_height >= record.forfeit_after_height
                || record.charged_persistent_bytes == 0
                || record.locked_amount.is_zero()
            {
                return Err(StakeResourceAccountingError::InvalidState(
                    "bond identity, policy, hash, usage or lifecycle is invalid".into(),
                ));
            }
            let terminal = record.status != StakeStateBondStatusV1::Locked;
            if (terminal && record.terminal_record_commitment == ZERO_SHA256)
                || (!terminal && record.terminal_record_commitment != ZERO_SHA256)
                || (record.status == StakeStateBondStatusV1::Locked
                    && record.previous_record_hash != ZERO_SHA256)
                || (record.status != StakeStateBondStatusV1::Locked
                    && record.previous_record_hash == ZERO_SHA256)
            {
                return Err(StakeResourceAccountingError::InvalidState(
                    "bond status is inconsistent with its hash-chain fields".into(),
                ));
            }
            let policy = &self.policies[&record.resource_policy_sequence];
            let quoted = quote(
                policy,
                record.resource_kind,
                StakeStateResourceUsageV1 {
                    wire_bytes: record.charged_wire_bytes,
                    persistent_bytes: record.charged_persistent_bytes,
                    signature_checks: record.charged_signature_checks,
                    state_reads: record.charged_state_reads,
                    state_writes: record.charged_state_writes,
                },
            )?;
            if quoted != (record.charged_creation_fee, record.locked_amount) {
                return Err(StakeResourceAccountingError::InvalidState(
                    "bond fee or amount cannot be re-derived".into(),
                ));
            }
            total_bytes = total_bytes
                .checked_add(record.charged_persistent_bytes)
                .ok_or_else(|| StakeResourceAccountingError::Arithmetic("state bytes".into()))?;
        }
        let mut renewal_coin_ids = BTreeSet::new();
        let mut renewal_predecessors = BTreeSet::new();
        for record in self.renewals.values() {
            let original = self.bonds.get(&record.resource_key).ok_or_else(|| {
                StakeResourceAccountingError::InvalidState("renewal has no original bond".into())
            })?;
            let predecessor = if record.previous_renewal_hash == ZERO_SHA256 {
                None
            } else {
                self.renewals
                    .values()
                    .find(|candidate| candidate.record_hash == record.previous_renewal_hash)
            };
            let expected_previous_lease = predecessor
                .map_or(original.lease_end_height, |candidate| {
                    candidate.new_lease_end_height
                });
            if original.status != StakeStateBondStatusV1::Locked
                || record.resource_kind != original.resource_kind
                || record.resource_owner != original.resource_owner
                || record.original_bond_id != original.bond_id
                || record.initial_bond_record_hash != original.initial_record_hash()
                || self
                    .policy_commitments
                    .get(&record.resource_policy_sequence)
                    != Some(&record.resource_policy_commitment)
                || record.record_hash != record.compute_record_hash()
                || predecessor
                    .is_some_and(|candidate| candidate.resource_key != record.resource_key)
                || record.previous_lease_end_height != expected_previous_lease
                || record.new_lease_end_height <= record.previous_lease_end_height
                || record.renewed_height > record.previous_lease_end_height
                || record.new_lease_end_height >= record.forfeit_after_height
                || record.additional_locked_amount.is_zero()
                || record.charged_persistent_bytes == 0
                || !renewal_coin_ids.insert(record.bond_coin_id.as_str())
                || !renewal_predecessors.insert((
                    record.resource_key.as_str(),
                    record.previous_renewal_hash.as_str(),
                ))
            {
                return Err(StakeResourceAccountingError::InvalidState(
                    "renewal identity, chain, lease, policy or amount is invalid".into(),
                ));
            }
            let policy = &self.policies[&record.resource_policy_sequence];
            let usage = StakeStateResourceUsageV1 {
                wire_bytes: record.charged_wire_bytes,
                persistent_bytes: record.charged_persistent_bytes,
                signature_checks: record.charged_signature_checks,
                state_reads: record.charged_state_reads,
                state_writes: record.charged_state_writes,
            };
            if quote(policy, record.resource_kind, usage)?.0 != record.charged_renewal_fee {
                return Err(StakeResourceAccountingError::InvalidState(
                    "renewal fee cannot be re-derived".into(),
                ));
            }
            let delta = record.new_lease_end_height - record.previous_lease_end_height;
            if quote_renewal(
                policy,
                record.resource_kind,
                original.charged_persistent_bytes,
                delta,
                usage,
            )? != (record.charged_renewal_fee, record.additional_locked_amount)
            {
                return Err(StakeResourceAccountingError::InvalidState(
                    "renewal fee or additional bond cannot be re-derived".into(),
                ));
            }
            total_bytes = total_bytes
                .checked_add(record.charged_persistent_bytes)
                .ok_or_else(|| StakeResourceAccountingError::Arithmetic("renewal bytes".into()))?;
        }
        if total_bytes != self.total_persistent_bytes
            || total_bytes > self.active_policy().maximum_total_stake_state_bytes
        {
            return Err(StakeResourceAccountingError::InvalidState(
                "total persistent-byte accounting mismatch".into(),
            ));
        }
        self.validate_pool()?;
        Ok(())
    }

    fn validate_funding_coin(
        &self,
        envelope: &StakeStateResourceEnvelopeV1,
        coin: &CoinObject,
        protected_coin_ids: &BTreeSet<String>,
    ) -> Result<(), StakeResourceAccountingError> {
        if envelope.funding_coin_id != coin.object_id
            || coin.state != CoinState::Spendable
            || coin.owner != envelope.sponsor
            || coin.zone_id != self.context.zone_id
            || coin.origin_genesis_root != self.context.currency_genesis_root
            || coin.transit_id.is_some()
            || coin.object_id.trim().is_empty()
            || coin.lineage_root.trim().is_empty()
        {
            return Err(StakeResourceAccountingError::FundingCoin(
                "Coin identity, state, owner, Zone or currency mismatch".into(),
            ));
        }
        if protected_coin_ids.contains(&coin.object_id)
            || self.consumed_funding_coin_ids.contains(&coin.object_id)
            || self
                .bonds
                .values()
                .any(|record| record.bond_coin_id == coin.object_id)
        {
            return Err(StakeResourceAccountingError::FundingCoin(
                "Coin aliases protected stake, payout, pool or prior resource funding".into(),
            ));
        }
        Ok(())
    }

    fn check_count_limits(
        &self,
        request: &StakeStateResourceAdmissionRequestV1,
    ) -> Result<(), StakeResourceAccountingError> {
        let policy = self.active_policy();
        let active = |record: &&StakeStateBondRecordV2| {
            matches!(
                record.status,
                StakeStateBondStatusV1::Locked | StakeStateBondStatusV1::Releaseable
            )
        };
        let records = self.bonds.values().filter(active);
        let global = records
            .clone()
            .filter(|record| record.resource_kind == request.resource_kind)
            .count();
        let owner = records
            .filter(|record| {
                record.resource_kind == request.resource_kind
                    && record.resource_owner == request.resource_owner
            })
            .count();
        let (maximum_global, maximum_owner) = match request.resource_kind {
            StakeStateResourceKindV1::Candidate => (
                policy.maximum_active_candidates,
                policy.maximum_candidates_per_owner,
            ),
            StakeStateResourceKindV1::Position => (
                policy.maximum_active_positions,
                policy.maximum_positions_per_owner,
            ),
            StakeStateResourceKindV1::Unbond => (
                policy.maximum_pending_unbonds,
                policy.maximum_pending_unbonds_per_owner,
            ),
            StakeStateResourceKindV1::Epoch | StakeStateResourceKindV1::SlashEvidence => {
                return Ok(())
            }
        };
        if global >= maximum_global as usize || owner >= maximum_owner as usize {
            return Err(StakeResourceAccountingError::HardLimit(
                "global or per-owner record count".into(),
            ));
        }
        Ok(())
    }

    fn check_and_stage_block_meter(
        &mut self,
        height: u64,
        usage: StakeStateResourceUsageV1,
        policy: &StakeStateResourcePolicyV1,
    ) -> Result<(), StakeResourceAccountingError> {
        if height < self.block_meter.height {
            return Err(StakeResourceAccountingError::InvalidRequest(
                "resource accounting height moved backwards".into(),
            ));
        }
        if height > self.block_meter.height {
            self.block_meter = StakeStateResourceBlockMeterV1::empty(height);
        }
        let bytes = self
            .block_meter
            .admitted_persistent_bytes
            .checked_add(usage.persistent_bytes)
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("block bytes".into()))?;
        let signatures = self
            .block_meter
            .signature_checks
            .checked_add(u64::from(usage.signature_checks))
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("signature meter".into()))?;
        let reads = self
            .block_meter
            .state_reads
            .checked_add(u64::from(usage.state_reads))
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("read meter".into()))?;
        let writes = self
            .block_meter
            .state_writes
            .checked_add(u64::from(usage.state_writes))
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("write meter".into()))?;
        if bytes > u64::from(policy.maximum_stake_state_bytes_per_block)
            || signatures > u64::from(policy.maximum_stake_signature_checks_per_block)
            || reads > u64::from(policy.maximum_stake_state_reads_per_block)
            || writes > u64::from(policy.maximum_stake_state_writes_per_block)
        {
            return Err(StakeResourceAccountingError::HardLimit(
                "per-block work or state meter".into(),
            ));
        }
        self.block_meter.admitted_persistent_bytes = bytes;
        self.block_meter.signature_checks = signatures;
        self.block_meter.state_reads = reads;
        self.block_meter.state_writes = writes;
        Ok(())
    }

    fn credit_admission_pool(
        &mut self,
        record: &StakeStateBondRecordV2,
    ) -> Result<(), StakeResourceAccountingError> {
        let previous = self.maintenance_pool.pool_commitment.clone();
        let bucket = self
            .maintenance_pool
            .policy_buckets
            .iter_mut()
            .find(|bucket| bucket.resource_policy_sequence == record.resource_policy_sequence)
            .ok_or_else(|| {
                StakeResourceAccountingError::InvalidState("missing pool bucket".into())
            })?;
        bucket.charged_fees = checked_add(bucket.charged_fees, record.charged_creation_fee)?;
        bucket.live_bonds = checked_add(bucket.live_bonds, record.locked_amount)?;
        bucket.active_bond_records = bucket
            .active_bond_records
            .checked_add(1)
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("active bonds".into()))?;
        bucket.bucket_commitment = bucket.compute_bucket_commitment();
        self.recompute_pool(previous)
    }

    fn credit_renewal_pool(
        &mut self,
        record: &StakeStateBondRenewalRecordV1,
    ) -> Result<(), StakeResourceAccountingError> {
        let previous = self.maintenance_pool.pool_commitment.clone();
        let bucket = self
            .maintenance_pool
            .policy_buckets
            .iter_mut()
            .find(|bucket| bucket.resource_policy_sequence == record.resource_policy_sequence)
            .ok_or_else(|| {
                StakeResourceAccountingError::InvalidState("missing pool bucket".into())
            })?;
        bucket.charged_fees = checked_add(bucket.charged_fees, record.charged_renewal_fee)?;
        bucket.live_bonds = checked_add(bucket.live_bonds, record.additional_locked_amount)?;
        bucket.bucket_commitment = bucket.compute_bucket_commitment();
        self.recompute_pool(previous)
    }

    fn settle_pool(
        &mut self,
        record: &StakeStateBondRecordV2,
        forfeited: bool,
    ) -> Result<(), StakeResourceAccountingError> {
        let previous = self.maintenance_pool.pool_commitment.clone();
        let bucket = self
            .maintenance_pool
            .policy_buckets
            .iter_mut()
            .find(|bucket| bucket.resource_policy_sequence == record.resource_policy_sequence)
            .ok_or_else(|| {
                StakeResourceAccountingError::InvalidState("missing pool bucket".into())
            })?;
        bucket.live_bonds = checked_sub(bucket.live_bonds, record.locked_amount)?;
        if forfeited {
            bucket.forfeited_bonds = checked_add(bucket.forfeited_bonds, record.locked_amount)?;
        } else {
            bucket.refunded_bonds = checked_add(bucket.refunded_bonds, record.locked_amount)?;
        }
        bucket.active_bond_records = bucket
            .active_bond_records
            .checked_sub(1)
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("active bonds".into()))?;
        bucket.terminal_bond_records = bucket
            .terminal_bond_records
            .checked_add(1)
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("terminal bonds".into()))?;
        bucket.bucket_commitment = bucket.compute_bucket_commitment();
        self.recompute_pool(previous)
    }

    fn recompute_pool(&mut self, previous: String) -> Result<(), StakeResourceAccountingError> {
        let (fees, forfeited, live, refunded, active, terminal) =
            pool_totals(&self.maintenance_pool.policy_buckets)?;
        self.maintenance_pool.total_charged_fees = fees;
        self.maintenance_pool.total_forfeited_bonds = forfeited;
        self.maintenance_pool.total_live_bonds = live;
        self.maintenance_pool.total_refunded_bonds = refunded;
        self.maintenance_pool.active_bond_records = active;
        self.maintenance_pool.terminal_bond_records = terminal;
        self.maintenance_pool.previous_pool_commitment = previous;
        self.maintenance_pool.pool_commitment = self.maintenance_pool.compute_pool_commitment();
        Ok(())
    }

    fn validate_pool(&self) -> Result<(), StakeResourceAccountingError> {
        if self.maintenance_pool.pool_version != STAKE_RESOURCE_POOL_VERSION_V2
            || self.maintenance_pool.runtime_payout_enabled
            || !is_hash(&self.maintenance_pool.previous_pool_commitment)
            || self.maintenance_pool.pool_commitment
                != self.maintenance_pool.compute_pool_commitment()
        {
            return Err(StakeResourceAccountingError::InvalidState(
                "maintenance-pool version, payout flag or commitment is invalid".into(),
            ));
        }
        let sequences = self
            .maintenance_pool
            .policy_buckets
            .iter()
            .map(|bucket| bucket.resource_policy_sequence)
            .collect::<Vec<_>>();
        if sequences.windows(2).any(|pair| pair[0] >= pair[1])
            || sequences.len() != self.policies.len()
        {
            return Err(StakeResourceAccountingError::InvalidState(
                "pool policy buckets are missing, duplicated or unordered".into(),
            ));
        }
        let mut expected = self
            .policies
            .keys()
            .map(|sequence| {
                (
                    *sequence,
                    StakeStateMaintenancePoolPolicyBucketV2 {
                        resource_policy_sequence: *sequence,
                        resource_policy_commitment: self.policy_commitments[sequence].clone(),
                        charged_fees: Amount::ZERO,
                        forfeited_bonds: Amount::ZERO,
                        live_bonds: Amount::ZERO,
                        refunded_bonds: Amount::ZERO,
                        active_bond_records: 0,
                        terminal_bond_records: 0,
                        bucket_commitment: String::new(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        for record in self.bonds.values() {
            let bucket = expected
                .get_mut(&record.resource_policy_sequence)
                .ok_or_else(|| {
                    StakeResourceAccountingError::InvalidState("bond policy has no bucket".into())
                })?;
            bucket.charged_fees = checked_add(bucket.charged_fees, record.charged_creation_fee)?;
            match record.status {
                StakeStateBondStatusV1::Locked | StakeStateBondStatusV1::Releaseable => {
                    bucket.live_bonds = checked_add(bucket.live_bonds, record.locked_amount)?;
                    bucket.active_bond_records =
                        bucket.active_bond_records.checked_add(1).ok_or_else(|| {
                            StakeResourceAccountingError::Arithmetic("active bonds".into())
                        })?;
                }
                StakeStateBondStatusV1::Refunded => {
                    bucket.refunded_bonds =
                        checked_add(bucket.refunded_bonds, record.locked_amount)?;
                    bucket.terminal_bond_records =
                        bucket.terminal_bond_records.checked_add(1).ok_or_else(|| {
                            StakeResourceAccountingError::Arithmetic("terminal bonds".into())
                        })?;
                }
                StakeStateBondStatusV1::Forfeited => {
                    bucket.forfeited_bonds =
                        checked_add(bucket.forfeited_bonds, record.locked_amount)?;
                    bucket.terminal_bond_records =
                        bucket.terminal_bond_records.checked_add(1).ok_or_else(|| {
                            StakeResourceAccountingError::Arithmetic("terminal bonds".into())
                        })?;
                }
            }
        }
        for record in self.renewals.values() {
            let bucket = expected
                .get_mut(&record.resource_policy_sequence)
                .ok_or_else(|| {
                    StakeResourceAccountingError::InvalidState(
                        "renewal policy has no bucket".into(),
                    )
                })?;
            bucket.charged_fees = checked_add(bucket.charged_fees, record.charged_renewal_fee)?;
            bucket.live_bonds = checked_add(bucket.live_bonds, record.additional_locked_amount)?;
        }
        for bucket in expected.values_mut() {
            bucket.bucket_commitment = bucket.compute_bucket_commitment();
        }
        if self.maintenance_pool.policy_buckets != expected.into_values().collect::<Vec<_>>() {
            return Err(StakeResourceAccountingError::InvalidState(
                "maintenance-pool buckets do not match bond records".into(),
            ));
        }
        let totals = pool_totals(&self.maintenance_pool.policy_buckets)?;
        if totals
            != (
                self.maintenance_pool.total_charged_fees,
                self.maintenance_pool.total_forfeited_bonds,
                self.maintenance_pool.total_live_bonds,
                self.maintenance_pool.total_refunded_bonds,
                self.maintenance_pool.active_bond_records,
                self.maintenance_pool.terminal_bond_records,
            )
        {
            return Err(StakeResourceAccountingError::InvalidState(
                "maintenance-pool totals do not match policy buckets".into(),
            ));
        }
        Ok(())
    }
}

fn validate_context(
    context: &StakeStateResourceContextV1,
) -> Result<(), StakeResourceAccountingError> {
    if !matches!(
        context.network_domain.as_str(),
        RLDCOIN_MAINNET_DOMAIN | RLDCOIN_TESTNET_DOMAIN
    ) || context.zone_id.trim().is_empty()
        || !is_hash(&context.currency_genesis_root)
        || context.protocol_era == 0
        || context.crypto_era == 0
    {
        return Err(StakeResourceAccountingError::InvalidState(
            "network, Zone, currency or era context is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_policy(
    policy: &StakeStateResourcePolicyV1,
) -> Result<(), StakeResourceAccountingError> {
    if policy.policy_version != 1
        || policy.sequence == 0
        || !is_hash(&policy.previous_policy_commitment)
        || policy.activation_delay_blocks == 0
        || policy.minimum_lease_blocks == 0
        || policy.minimum_lease_blocks > policy.maximum_lease_blocks
        || policy.expiry_grace_blocks == 0
        || policy.terminal_retention_blocks == 0
        || policy.maximum_active_candidates == 0
        || policy.maximum_candidates_per_owner == 0
        || policy.maximum_candidates_per_owner > policy.maximum_active_candidates
        || policy.maximum_active_positions == 0
        || policy.maximum_positions_per_owner == 0
        || policy.maximum_positions_per_owner > policy.maximum_active_positions
        || policy.maximum_pending_unbonds == 0
        || policy.maximum_pending_unbonds_per_owner == 0
        || policy.maximum_pending_unbonds_per_owner > policy.maximum_pending_unbonds
        || policy.maximum_slash_record_bytes == 0
        || policy.maximum_total_stake_state_bytes == 0
        || policy.maximum_stake_state_bytes_per_block == 0
        || u64::from(policy.maximum_stake_state_bytes_per_block)
            > policy.maximum_total_stake_state_bytes
        || policy.maximum_stake_signature_checks_per_block == 0
        || policy.maximum_stake_state_reads_per_block == 0
        || policy.maximum_stake_state_writes_per_block == 0
        || policy.fee_per_wire_byte.is_zero()
        || policy.fee_per_signature_verification.is_zero()
        || policy.fee_per_state_read.is_zero()
        || policy.fee_per_state_write.is_zero()
        || policy.bond_per_persistent_byte.is_zero()
        || policy.minimum_candidate_bond.is_zero()
        || policy.minimum_position_bond.is_zero()
    {
        return Err(StakeResourceAccountingError::InvalidPolicy(
            "version, bounds, prices, bonds or limits are invalid".into(),
        ));
    }
    for kind in [
        StakeStateResourceKindV1::Candidate,
        StakeStateResourceKindV1::Position,
        StakeStateResourceKindV1::Epoch,
        StakeStateResourceKindV1::Unbond,
        StakeStateResourceKindV1::SlashEvidence,
    ] {
        let persistent_bytes = if kind == StakeStateResourceKindV1::SlashEvidence {
            u64::from(policy.maximum_slash_record_bytes)
        } else {
            policy.maximum_total_stake_state_bytes
        };
        quote(
            policy,
            kind,
            StakeStateResourceUsageV1 {
                wire_bytes: u32::MAX,
                persistent_bytes,
                signature_checks: u32::MAX,
                state_reads: u32::MAX,
                state_writes: u32::MAX,
            },
        )?;
    }
    Ok(())
}

pub fn validate_stake_state_resource_policy_v1(
    policy: &StakeStateResourcePolicyV1,
) -> Result<(), StakeResourceAccountingError> {
    validate_policy(policy)
}

fn validate_request_shape(
    request: &StakeStateResourceAdmissionRequestV1,
) -> Result<(), StakeResourceAccountingError> {
    if request.resource_key.is_empty()
        || request.resource_key.len() > 256
        || !request.resource_key.is_ascii()
        || request.resource_owner.trim().is_empty()
        || !is_hash(&request.outer_operation_hash)
        || !is_hash(&request.expected_parent_commitment)
        || !is_hash(&request.envelope.resource_policy_commitment)
        || !is_hash(&request.envelope.resource_subject_hash)
        || request.envelope.sponsor.trim().is_empty()
        || request.envelope.funding_coin_id.trim().is_empty()
        || request.usage.wire_bytes == 0
        || request.usage.persistent_bytes == 0
        || request.usage.signature_checks == 0
        || request.usage.state_reads == 0
        || request.usage.state_writes == 0
    {
        return Err(StakeResourceAccountingError::InvalidRequest(
            "identity, hash, owner, sponsor or resource usage is invalid".into(),
        ));
    }
    Ok(())
}

fn quote_execution_fee(
    policy: &StakeStateResourcePolicyV1,
    kind: StakeStateResourceKindV1,
    wire_bytes: u32,
    signature_checks: u32,
    state_reads: u32,
    state_writes: u32,
) -> Result<Amount, StakeResourceAccountingError> {
    let base = match kind {
        StakeStateResourceKindV1::Candidate => policy.base_candidate_fee,
        StakeStateResourceKindV1::Position => policy.base_position_fee,
        StakeStateResourceKindV1::Epoch => policy.base_epoch_fee,
        StakeStateResourceKindV1::Unbond => policy.base_unbond_fee,
        StakeStateResourceKindV1::SlashEvidence => policy.base_slash_evidence_fee,
    };
    [
        (u128::from(wire_bytes), policy.fee_per_wire_byte),
        (
            u128::from(signature_checks),
            policy.fee_per_signature_verification,
        ),
        (u128::from(state_reads), policy.fee_per_state_read),
        (u128::from(state_writes), policy.fee_per_state_write),
    ]
    .into_iter()
    .try_fold(base, |total, (units, price)| {
        let component = units
            .checked_mul(price.0)
            .map(Amount)
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("fee multiplication".into()))?;
        checked_add(total, component)
    })
}

/// Quotes an unbond completion/destruction mutation without creating a new
/// resource bond. The fee pays only for authenticated policy dimensions. The
/// returned refundable delta is always zero: released capacity may only make
/// an already-locked bond eligible for the separate refund lifecycle.
pub fn quote_fee_only_unbond_mutation_v1(
    policy: &StakeStateResourcePolicyV1,
    usage: StakeStateResourceMutationUsageV1,
) -> Result<StakeStateResourceMutationQuoteV1, StakeResourceAccountingError> {
    if usage.wire_bytes == 0
        || usage.predecessor_live_bytes == 0
        || usage.appended_history_bytes == 0
        || usage.signature_checks == 0
        || usage.state_reads == 0
        || usage.state_writes == 0
    {
        return Err(StakeResourceAccountingError::InvalidRequest(
            "fee-only unbond mutation has a zero mandatory work or history dimension".into(),
        ));
    }
    if usage.cpu_units > FEE_ONLY_MUTATION_MAX_UNPRICED_CPU_UNITS_V1
        || usage.proof_verification_units > FEE_ONLY_MUTATION_MAX_UNPRICED_PROOF_UNITS_V1
    {
        return Err(StakeResourceAccountingError::HardLimit(
            "fee-only unbond mutation uses an unpriced CPU or proof dimension".into(),
        ));
    }
    if usage.removed_live_bytes > usage.predecessor_live_bytes {
        return Err(StakeResourceAccountingError::InvalidRequest(
            "fee-only unbond mutation removes more live bytes than exist".into(),
        ));
    }
    if usage.predecessor_history_commitment == [0; 32]
        || usage.successor_history_prefix_commitment != usage.predecessor_history_commitment
    {
        return Err(StakeResourceAccountingError::InvalidRequest(
            "unbond successor history does not preserve the exact predecessor prefix".into(),
        ));
    }
    let predecessor_total_bytes = usage
        .predecessor_live_bytes
        .checked_add(usage.predecessor_history_bytes)
        .ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic("mutation predecessor footprint".into())
        })?;
    if usage.predecessor_total_stake_state_bytes < predecessor_total_bytes {
        return Err(StakeResourceAccountingError::InvalidRequest(
            "global predecessor footprint is smaller than the unbond lifecycle".into(),
        ));
    }
    let expected_successor_history = usage
        .predecessor_history_bytes
        .checked_add(usage.appended_history_bytes)
        .ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic("mutation appended history".into())
        })?;
    if usage.successor_history_bytes != expected_successor_history {
        return Err(StakeResourceAccountingError::InvalidRequest(
            "unbond history must be an exact append; rewrite or truncation is forbidden".into(),
        ));
    }
    let successor_live_bytes = usage
        .predecessor_live_bytes
        .checked_sub(usage.removed_live_bytes)
        .and_then(|value| value.checked_add(usage.replacement_live_bytes))
        .ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic("mutation successor live footprint".into())
        })?;
    let successor_total_bytes = successor_live_bytes
        .checked_add(usage.successor_history_bytes)
        .ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic("mutation successor footprint".into())
        })?;
    let newly_materialized_bytes = usage
        .replacement_live_bytes
        .checked_add(usage.appended_history_bytes)
        .ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic("mutation materialized footprint".into())
        })?;
    if newly_materialized_bytes > usage.prepaid_terminal_capacity_bytes {
        return Err(StakeResourceAccountingError::HardLimit(
            "fee-only unbond mutation exceeds prepaid terminal capacity".into(),
        ));
    }
    let successor_total_stake_state_bytes = usage
        .predecessor_total_stake_state_bytes
        .checked_sub(usage.removed_live_bytes)
        .and_then(|value| value.checked_add(newly_materialized_bytes))
        .ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic("mutation global footprint".into())
        })?;
    if newly_materialized_bytes > u64::from(policy.maximum_stake_state_bytes_per_block)
        || successor_total_stake_state_bytes > policy.maximum_total_stake_state_bytes
        || usage.signature_checks > policy.maximum_stake_signature_checks_per_block
        || usage.state_reads > policy.maximum_stake_state_reads_per_block
        || usage.state_writes > policy.maximum_stake_state_writes_per_block
    {
        return Err(StakeResourceAccountingError::HardLimit(
            "fee-only unbond mutation exceeds an authenticated policy limit".into(),
        ));
    }
    let charged_fee = quote_execution_fee(
        policy,
        StakeStateResourceKindV1::Unbond,
        usage.wire_bytes,
        usage.signature_checks,
        usage.state_reads,
        usage.state_writes,
    )?;
    let net_released_bytes = if predecessor_total_bytes > successor_total_bytes {
        predecessor_total_bytes
            .checked_sub(successor_total_bytes)
            .ok_or_else(|| {
                StakeResourceAccountingError::Arithmetic("mutation released footprint".into())
            })?
    } else {
        0
    };
    Ok(StakeStateResourceMutationQuoteV1 {
        charged_fee,
        refundable_bond_delta: Amount::ZERO,
        predecessor_total_bytes,
        successor_total_bytes,
        successor_total_stake_state_bytes,
        newly_materialized_bytes,
        net_released_bytes,
    })
}

fn quote(
    policy: &StakeStateResourcePolicyV1,
    kind: StakeStateResourceKindV1,
    usage: StakeStateResourceUsageV1,
) -> Result<(Amount, Amount), StakeResourceAccountingError> {
    if kind == StakeStateResourceKindV1::SlashEvidence
        && usage.persistent_bytes > u64::from(policy.maximum_slash_record_bytes)
    {
        return Err(StakeResourceAccountingError::HardLimit(
            "slash record bytes".into(),
        ));
    }
    let fee = quote_execution_fee(
        policy,
        kind,
        usage.wire_bytes,
        usage.signature_checks,
        usage.state_reads,
        usage.state_writes,
    )?;
    let byte_bond = u128::from(usage.persistent_bytes)
        .checked_mul(policy.bond_per_persistent_byte.0)
        .map(Amount)
        .ok_or_else(|| StakeResourceAccountingError::Arithmetic("bond multiplication".into()))?;
    let minimum = match kind {
        StakeStateResourceKindV1::Candidate => policy.minimum_candidate_bond,
        StakeStateResourceKindV1::Position => policy.minimum_position_bond,
        StakeStateResourceKindV1::Epoch
        | StakeStateResourceKindV1::Unbond
        | StakeStateResourceKindV1::SlashEvidence => Amount::ZERO,
    };
    Ok((fee, byte_bond.max(minimum)))
}

/// Independently reproducible renewal price. The renewal fee uses the active
/// policy and the new tranche's derived work. The additional bond covers both
/// the immutable tranche bytes and a ceiling-prorated extension of the
/// original covered bytes over the policy's maximum lease horizon.
pub fn quote_renewal(
    policy: &StakeStateResourcePolicyV1,
    kind: StakeStateResourceKindV1,
    original_persistent_bytes: u64,
    extension_blocks: u64,
    renewal_usage: StakeStateResourceUsageV1,
) -> Result<(Amount, Amount), StakeResourceAccountingError> {
    if original_persistent_bytes == 0 || extension_blocks == 0 {
        return Err(StakeResourceAccountingError::InvalidRequest(
            "renewal requires retained bytes and a positive extension".into(),
        ));
    }
    let charged_fee = quote(policy, kind, renewal_usage)?.0;
    let denominator = u128::from(policy.maximum_lease_blocks);
    let prorated = u128::from(original_persistent_bytes)
        .checked_mul(policy.bond_per_persistent_byte.0)
        .and_then(|value| value.checked_mul(u128::from(extension_blocks)))
        .and_then(|value| value.checked_add(denominator - 1))
        .ok_or_else(|| StakeResourceAccountingError::Arithmetic("renewal lease bond".into()))?
        / denominator;
    let record_bond = u128::from(renewal_usage.persistent_bytes)
        .checked_mul(policy.bond_per_persistent_byte.0)
        .ok_or_else(|| StakeResourceAccountingError::Arithmetic("renewal record bond".into()))?;
    let additional = prorated
        .checked_add(record_bond)
        .map(Amount)
        .ok_or_else(|| StakeResourceAccountingError::Arithmetic("renewal total bond".into()))?;
    Ok((charged_fee, additional))
}

fn pool_totals(
    buckets: &[StakeStateMaintenancePoolPolicyBucketV2],
) -> Result<(Amount, Amount, Amount, Amount, u64, u64), StakeResourceAccountingError> {
    buckets.iter().try_fold(
        (
            Amount::ZERO,
            Amount::ZERO,
            Amount::ZERO,
            Amount::ZERO,
            0u64,
            0u64,
        ),
        |(fees, forfeited, live, refunded, active, terminal), bucket| {
            if bucket.bucket_commitment != bucket.compute_bucket_commitment() {
                return Err(StakeResourceAccountingError::InvalidState(
                    "policy-bucket commitment mismatch".into(),
                ));
            }
            Ok((
                checked_add(fees, bucket.charged_fees)?,
                checked_add(forfeited, bucket.forfeited_bonds)?,
                checked_add(live, bucket.live_bonds)?,
                checked_add(refunded, bucket.refunded_bonds)?,
                active
                    .checked_add(bucket.active_bond_records)
                    .ok_or_else(|| {
                        StakeResourceAccountingError::Arithmetic("active pool records".into())
                    })?,
                terminal
                    .checked_add(bucket.terminal_bond_records)
                    .ok_or_else(|| {
                        StakeResourceAccountingError::Arithmetic("terminal pool records".into())
                    })?,
            ))
        },
    )
}

fn checked_add(left: Amount, right: Amount) -> Result<Amount, StakeResourceAccountingError> {
    left.checked_add(right)
        .map_err(|_| StakeResourceAccountingError::Arithmetic("Amount addition".into()))
}

fn checked_sub(left: Amount, right: Amount) -> Result<Amount, StakeResourceAccountingError> {
    left.checked_sub(right)
        .map_err(|_| StakeResourceAccountingError::Arithmetic("Amount subtraction".into()))
}

fn child_coin(
    parent: &CoinObject,
    object_id: String,
    owner: String,
    amount: Amount,
    state: CoinState,
    version: u64,
    height: u64,
) -> CoinObject {
    CoinObject {
        object_id,
        lineage_root: parent.lineage_root.clone(),
        parent_ids: vec![parent.object_id.clone()],
        owner,
        zone_id: parent.zone_id.clone(),
        amount,
        state,
        version,
        created_height: height,
        transit_id: None,
        imported_from: parent.imported_from.clone(),
        origin_zone: parent.origin_zone.clone(),
        origin_genesis_root: parent.origin_genesis_root.clone(),
    }
}

fn validate_bond_coin(
    record: &StakeStateBondRecordV2,
    funding_source: &CoinObject,
    bond_coin: &CoinObject,
) -> Result<(), StakeResourceAccountingError> {
    let expected_version = funding_source
        .version
        .checked_add(1)
        .ok_or_else(|| StakeResourceAccountingError::Arithmetic("bond Coin version".into()))?;
    if funding_source.object_id != record.funding_source_coin_id
        || funding_source.state != CoinState::Consumed
        || bond_coin.object_id != record.bond_coin_id
        || bond_coin.state != CoinState::Reserved
        || bond_coin.owner != record.sponsor
        || bond_coin.amount != record.locked_amount
        || bond_coin.parent_ids != [funding_source.object_id.clone()]
        || bond_coin.lineage_root != funding_source.lineage_root
        || bond_coin.version != expected_version
        || bond_coin.created_height != record.created_height
        || bond_coin.transit_id.is_some()
    {
        return Err(StakeResourceAccountingError::FundingCoin(
            "bond Coin does not match its consumed funding source and record".into(),
        ));
    }
    Ok(())
}

fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        generate_identity, sign_bytes, ConsensusEpochDescriptor, ConsensusQuorumRule,
        ConsensusStakeEpochLiabilityV2, ConsensusStakePositionKind, ConsensusStakeSlashPolicyV2,
        ConsensusStakeSlashTermsV2, DeriveNextStakeEpochRequestV2, LockConsensusStakeRequestV3,
        MigrateConsensusCandidateResourceRequestV1, MigrateConsensusStakeResourceRequestV1,
        SignedActionAuthorization, StakeEpochRecordStatus, StakePositionTypeV1, ValidatorRecord,
    };

    const ACCOUNTING_VECTORS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/stake-resource-accounting-v1/vectors.json"
    ));

    const ROOT: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const OUTER: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const PARENT: &str = "3333333333333333333333333333333333333333333333333333333333333333";
    const TERMINAL: &str = "4444444444444444444444444444444444444444444444444444444444444444";

    fn context() -> StakeStateResourceContextV1 {
        StakeStateResourceContextV1 {
            network_domain: RLDCOIN_TESTNET_DOMAIN.into(),
            zone_id: "zone-resource-test".into(),
            currency_genesis_root: ROOT.into(),
            protocol_era: 1,
            crypto_era: 1,
        }
    }

    fn policy() -> StakeStateResourcePolicyV1 {
        StakeStateResourcePolicyV1 {
            policy_version: 1,
            sequence: 1,
            previous_policy_commitment: ZERO_SHA256.into(),
            activation_delay_blocks: 100,
            base_candidate_fee: Amount(100),
            base_position_fee: Amount(200),
            base_epoch_fee: Amount(300),
            base_unbond_fee: Amount(400),
            base_slash_evidence_fee: Amount(500),
            fee_per_wire_byte: Amount(2),
            fee_per_signature_verification: Amount(10),
            fee_per_state_read: Amount(3),
            fee_per_state_write: Amount(5),
            bond_per_persistent_byte: Amount(20),
            minimum_candidate_bond: Amount(2_000),
            minimum_position_bond: Amount(4_000),
            minimum_lease_blocks: 10,
            maximum_lease_blocks: 1_000,
            expiry_grace_blocks: 20,
            terminal_retention_blocks: 30,
            maximum_active_candidates: 2,
            maximum_candidates_per_owner: 1,
            maximum_active_positions: 4,
            maximum_positions_per_owner: 2,
            maximum_pending_unbonds: 2,
            maximum_pending_unbonds_per_owner: 1,
            maximum_slash_record_bytes: 2_000,
            maximum_total_stake_state_bytes: 10_000,
            maximum_stake_state_bytes_per_block: 2_000,
            maximum_stake_signature_checks_per_block: 20,
            maximum_stake_state_reads_per_block: 50,
            maximum_stake_state_writes_per_block: 20,
        }
    }

    fn usage() -> StakeStateResourceUsageV1 {
        StakeStateResourceUsageV1 {
            wire_bytes: 100,
            persistent_bytes: 300,
            signature_checks: 2,
            state_reads: 4,
            state_writes: 3,
        }
    }

    fn fee_only_mutation_usage() -> StakeStateResourceMutationUsageV1 {
        StakeStateResourceMutationUsageV1 {
            wire_bytes: 640,
            predecessor_total_stake_state_bytes: 4_000,
            predecessor_live_bytes: 800,
            removed_live_bytes: 800,
            replacement_live_bytes: 210,
            predecessor_history_bytes: 800,
            predecessor_history_commitment: [0x55; 32],
            successor_history_bytes: 1_100,
            successor_history_prefix_commitment: [0x55; 32],
            appended_history_bytes: 300,
            prepaid_terminal_capacity_bytes: 510,
            signature_checks: 1,
            state_reads: 9,
            state_writes: 8,
            cpu_units: 0,
            proof_verification_units: 0,
        }
    }

    fn terminal_reserve_input(request_id: &str) -> StakeUnbondTerminalReserveInputV1 {
        StakeUnbondTerminalReserveInputV1 {
            request_id: request_id.into(),
            resource_key: format!("UNBOND/{request_id}"),
            unbond_bond_record_hash: "66".repeat(32),
            owner: "rld:zone-resource-test:owner-星际".into(),
            prepaid_terminal_capacity_bytes: 500,
            predecessor_history_root: "55".repeat(32),
            predecessor_history_bytes: 281,
            request_materialized_bytes: 200,
            height: 100,
            signature_checks: 2,
            state_reads: 4,
            state_writes: 3,
            cpu_units: 0,
            proof_verification_units: 0,
        }
    }

    #[test]
    fn terminal_reservation_is_single_use_and_branch_bound() {
        let mut state = StakeUnbondTerminalReservationAccountingV1::new(100, 100);
        let record = state
            .reserve(&policy(), terminal_reserve_input("request-1"))
            .unwrap();
        assert_eq!(state.materialized_persistent_bytes, 300);
        assert_eq!(state.reserved_terminal_capacity_bytes, 500);
        let before_wrong = state.state_commitment.clone();
        let mut wrong = StakeUnbondTerminalConsumeInputV1 {
            request_id: "request-1".into(),
            expected_unbond_bond_record_hash: "66".repeat(32),
            expected_predecessor_history_root: "77".repeat(32),
            expected_predecessor_history_bytes: 281,
            branch: StakeUnbondTerminalBranchV1::Complete,
            terminal_record_bytes: vec![0x5a; 300],
            removed_live_bytes: 100,
            replacement_live_bytes: 100,
            wire_bytes: 640,
            height: 101,
            signature_checks: 1,
            state_reads: 9,
            state_writes: 8,
            cpu_units: 0,
            proof_verification_units: 0,
        };
        assert!(matches!(
            state.consume(&policy(), wrong.clone()),
            Err(StakeResourceAccountingError::InvalidRequest(_))
        ));
        assert_eq!(state.state_commitment, before_wrong);
        wrong.expected_predecessor_history_root = record.request_history_root;
        let outcome = state.consume(&policy(), wrong.clone()).unwrap();
        assert_eq!(outcome.refundable_bond_delta, Amount::ZERO);
        assert_eq!(outcome.newly_materialized_bytes, 400);
        assert_eq!(state.materialized_persistent_bytes, 600);
        assert_eq!(state.reserved_terminal_capacity_bytes, 0);
        let committed = state.state_commitment.clone();
        wrong.branch = StakeUnbondTerminalBranchV1::Slash;
        assert!(matches!(
            state.consume(&policy(), wrong),
            Err(StakeResourceAccountingError::InvalidRequest(_))
        ));
        assert_eq!(state.state_commitment, committed);

        let mut slash_first = StakeUnbondTerminalReservationAccountingV1::new(100, 100);
        let slash_record = slash_first
            .reserve(&policy(), terminal_reserve_input("request-slash"))
            .unwrap();
        let mut slash = StakeUnbondTerminalConsumeInputV1 {
            request_id: "request-slash".into(),
            expected_unbond_bond_record_hash: "66".repeat(32),
            expected_predecessor_history_root: slash_record.request_history_root,
            expected_predecessor_history_bytes: 281,
            branch: StakeUnbondTerminalBranchV1::Slash,
            terminal_record_bytes: vec![0x33; 200],
            removed_live_bytes: 100,
            replacement_live_bytes: 100,
            wire_bytes: 640,
            height: 101,
            signature_checks: 1,
            state_reads: 9,
            state_writes: 8,
            cpu_units: 0,
            proof_verification_units: 0,
        };
        slash_first.consume(&policy(), slash.clone()).unwrap();
        slash.branch = StakeUnbondTerminalBranchV1::Complete;
        assert!(matches!(
            slash_first.consume(&policy(), slash),
            Err(StakeResourceAccountingError::InvalidRequest(_))
        ));
    }

    #[test]
    fn terminal_reservation_meter_accumulates_and_recovery_rejects_tamper() {
        let mut state = StakeUnbondTerminalReservationAccountingV1::new(100, 100);
        state
            .reserve(&policy(), terminal_reserve_input("request-1"))
            .unwrap();
        let before = state.state_commitment.clone();
        let mut second = terminal_reserve_input("request-2");
        second.request_materialized_bytes = 1_000;
        second.prepaid_terminal_capacity_bytes = 301;
        assert!(matches!(
            state.reserve(&policy(), second),
            Err(StakeResourceAccountingError::HardLimit(_))
        ));
        assert_eq!(state.state_commitment, before);

        let bytes = state.canonical_json_bytes().unwrap();
        assert_eq!(
            StakeUnbondTerminalReservationAccountingV1::restore_canonical_json(&bytes).unwrap(),
            state
        );
        let mut tampered: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        tampered["reserved_terminal_capacity_bytes"] = serde_json::json!(499);
        let tampered = serde_json::to_vec(&tampered).unwrap();
        assert!(
            StakeUnbondTerminalReservationAccountingV1::restore_canonical_json(&tampered).is_err()
        );
    }

    #[test]
    fn unbond_identifier_utf8_bounds_are_exact() {
        let terminal_256 = format!("{}x", "界".repeat(85));
        let terminal_257 = format!("{}xx", "界".repeat(85));
        let derived_128 = format!("{}xx", "界".repeat(42));
        let derived_129 = format!("{}xxx", "界".repeat(42));
        assert_eq!(terminal_256.len(), 256);
        assert_eq!(terminal_257.len(), 257);
        assert_eq!(derived_128.len(), 128);
        assert_eq!(derived_129.len(), 129);
        let base = StakeUnbondLifecycleRecordInputV1 {
            request_id: "request-界",
            owner: "owner-界",
            beneficiary: "owner-界",
            completion_id: &terminal_256,
            payout_coin_id: &derived_128,
            slash_id: &terminal_256,
            completion_nullifier_id: &derived_128,
            slash_nullifier_id: &derived_128,
        };
        stake_unbond_lifecycle_record_footprints_v1(base).unwrap();
        let mut too_long = base;
        too_long.completion_id = &terminal_257;
        assert!(matches!(
            stake_unbond_lifecycle_record_footprints_v1(too_long),
            Err(StakeResourceAccountingError::HardLimit(_))
        ));
        too_long = base;
        too_long.payout_coin_id = &derived_129;
        assert!(matches!(
            stake_unbond_lifecycle_record_footprints_v1(too_long),
            Err(StakeResourceAccountingError::HardLimit(_))
        ));
    }

    #[test]
    fn fee_only_unbond_mutation_charges_work_but_never_mints_a_refund() {
        let quote =
            quote_fee_only_unbond_mutation_v1(&policy(), fee_only_mutation_usage()).unwrap();
        assert_eq!(quote.charged_fee, Amount(1_757));
        assert_eq!(quote.refundable_bond_delta, Amount::ZERO);
        assert_eq!(quote.predecessor_total_bytes, 1_600);
        assert_eq!(quote.successor_total_bytes, 1_310);
        assert_eq!(quote.successor_total_stake_state_bytes, 3_710);
        assert_eq!(quote.newly_materialized_bytes, 510);
        assert_eq!(quote.net_released_bytes, 290);
    }

    #[test]
    fn fee_only_unbond_mutation_accepts_terminal_deletion_at_exact_capacity() {
        let mut usage = fee_only_mutation_usage();
        usage.replacement_live_bytes = 0;
        usage.appended_history_bytes = 510;
        usage.successor_history_bytes = 1_310;
        let quote = quote_fee_only_unbond_mutation_v1(&policy(), usage).unwrap();
        assert_eq!(quote.newly_materialized_bytes, 510);
        assert_eq!(quote.successor_total_bytes, 1_310);
        assert_eq!(quote.net_released_bytes, 290);
        assert_eq!(quote.refundable_bond_delta, Amount::ZERO);
    }

    #[test]
    fn fee_only_unbond_mutation_rejects_underreserve_and_history_rewrite() {
        let mut underreserved = fee_only_mutation_usage();
        underreserved.prepaid_terminal_capacity_bytes -= 1;
        assert!(matches!(
            quote_fee_only_unbond_mutation_v1(&policy(), underreserved),
            Err(StakeResourceAccountingError::HardLimit(_))
        ));

        let mut rewritten = fee_only_mutation_usage();
        rewritten.successor_history_bytes -= 1;
        assert!(matches!(
            quote_fee_only_unbond_mutation_v1(&policy(), rewritten),
            Err(StakeResourceAccountingError::InvalidRequest(_))
        ));

        let mut content_rewritten = fee_only_mutation_usage();
        content_rewritten.successor_history_prefix_commitment = [0x56; 32];
        assert!(matches!(
            quote_fee_only_unbond_mutation_v1(&policy(), content_rewritten),
            Err(StakeResourceAccountingError::InvalidRequest(_))
        ));

        let mut truncated = fee_only_mutation_usage();
        truncated.successor_history_bytes = 799;
        assert!(matches!(
            quote_fee_only_unbond_mutation_v1(&policy(), truncated),
            Err(StakeResourceAccountingError::InvalidRequest(_))
        ));
    }

    #[test]
    fn fee_only_unbond_mutation_rejects_unpriced_work_limits_and_overflow() {
        let mut cpu = fee_only_mutation_usage();
        cpu.cpu_units = 1;
        assert!(matches!(
            quote_fee_only_unbond_mutation_v1(&policy(), cpu),
            Err(StakeResourceAccountingError::HardLimit(_))
        ));

        let mut proof = fee_only_mutation_usage();
        proof.proof_verification_units = 1;
        assert!(matches!(
            quote_fee_only_unbond_mutation_v1(&policy(), proof),
            Err(StakeResourceAccountingError::HardLimit(_))
        ));

        let mut overflow = fee_only_mutation_usage();
        overflow.predecessor_history_bytes = u64::MAX;
        overflow.successor_history_bytes = u64::MAX;
        assert!(matches!(
            quote_fee_only_unbond_mutation_v1(&policy(), overflow),
            Err(StakeResourceAccountingError::Arithmetic(_))
        ));

        let mut excessive_reads = fee_only_mutation_usage();
        excessive_reads.state_reads = policy().maximum_stake_state_reads_per_block + 1;
        assert!(matches!(
            quote_fee_only_unbond_mutation_v1(&policy(), excessive_reads),
            Err(StakeResourceAccountingError::HardLimit(_))
        ));
    }

    #[test]
    fn unbond_worst_case_footprint_is_checked_and_keeps_every_dependency() {
        let footprint =
            stake_unbond_worst_case_footprint_v1(StakeUnbondWorstCaseFootprintInputV1 {
                retained_position_bytes: 700,
                retained_candidate_bytes: 100,
                retained_epoch_liability_bytes: 300,
                retained_horizon_history_bytes: 545,
                pending_unbond_bytes: 800,
                completed_terminal_bytes: 300,
                fully_slashed_terminal_bytes: 350,
                terminal_index_and_audit_bytes: 210,
            })
            .unwrap();
        assert_eq!(footprint.dependency_retained_bytes, 1_645);
        assert_eq!(footprint.terminal_branch_upper_bound_bytes, 350);
        assert_eq!(footprint.prepaid_terminal_capacity_bytes, 560);
        assert_eq!(footprint.unbond_bond_persistent_bytes, 1_360);
        assert_eq!(footprint.total_worst_case_retained_bytes, 3_005);

        assert!(matches!(
            stake_unbond_worst_case_footprint_v1(StakeUnbondWorstCaseFootprintInputV1 {
                retained_position_bytes: u64::MAX,
                retained_candidate_bytes: 1,
                retained_epoch_liability_bytes: 1,
                retained_horizon_history_bytes: 1,
                pending_unbond_bytes: 1,
                completed_terminal_bytes: 1,
                fully_slashed_terminal_bytes: 1,
                terminal_index_and_audit_bytes: 1,
            }),
            Err(StakeResourceAccountingError::Arithmetic(_))
        ));
    }

    #[test]
    fn unbond_lifecycle_record_footprints_charge_utf8_and_reject_owner_mismatch() {
        let input = StakeUnbondLifecycleRecordInputV1 {
            request_id: "unbond-request-α-001",
            owner: "rld:zone-resource-test:owner-星际",
            beneficiary: "rld:zone-resource-test:owner-星际",
            completion_id: "unbond-completion-001",
            payout_coin_id: "unbond-payout-coin-001",
            slash_id: "unbond-slash-001",
            completion_nullifier_id: "unbond-completion-nullifier-001",
            slash_nullifier_id: "unbond-slash-nullifier-001",
        };
        let footprint = stake_unbond_lifecycle_record_footprints_v1(input).unwrap();
        assert!(footprint.pending_unbond_bytes > 0);
        assert!(footprint.fully_slashed_terminal_bytes > 0);
        let worst =
            stake_unbond_lifecycle_worst_case_record_footprints_v1(input.request_id, input.owner)
                .unwrap();
        assert_eq!(worst.pending_unbond_bytes, footprint.pending_unbond_bytes);
        assert!(worst.completed_terminal_bytes >= footprint.completed_terminal_bytes);
        assert!(worst.fully_slashed_terminal_bytes >= footprint.fully_slashed_terminal_bytes);
        assert!(worst.terminal_index_and_audit_bytes >= footprint.terminal_index_and_audit_bytes);

        let mut wrong_beneficiary = input;
        wrong_beneficiary.beneficiary = "different-owner";
        assert!(matches!(
            stake_unbond_lifecycle_record_footprints_v1(wrong_beneficiary),
            Err(StakeResourceAccountingError::InvalidRequest(_))
        ));

        let oversized =
            "x".repeat(usize::try_from(MAX_STAKE_UNBOND_TERMINAL_ID_UTF8_BYTES_V1 + 1).unwrap());
        let mut oversized_terminal = input;
        oversized_terminal.completion_id = &oversized;
        assert!(matches!(
            stake_unbond_lifecycle_record_footprints_v1(oversized_terminal),
            Err(StakeResourceAccountingError::HardLimit(_))
        ));
    }

    fn funding_coin(owner: &str, amount: Amount, id: &str) -> CoinObject {
        CoinObject {
            object_id: id.into(),
            lineage_root: format!("lineage-{id}"),
            parent_ids: Vec::new(),
            owner: owner.into(),
            zone_id: context().zone_id,
            amount,
            state: CoinState::Spendable,
            version: 7,
            created_height: 1,
            transit_id: None,
            imported_from: None,
            origin_zone: "zone-resource-test".into(),
            origin_genesis_root: ROOT.into(),
        }
    }

    fn signed_request(
        state: &StakeStateResourceAccountingV1,
        identity: &crate::Identity,
        resource_key: &str,
        resource_kind: StakeStateResourceKindV1,
        funding_coin_id: &str,
        nonce: u64,
    ) -> StakeStateResourceAdmissionRequestV1 {
        let sponsor = format!("rld:{}:{}", context().zone_id, identity.public_key);
        let mut request = StakeStateResourceAdmissionRequestV1 {
            resource_key: resource_key.into(),
            resource_kind,
            resource_owner: sponsor.clone(),
            outer_operation_hash: OUTER.into(),
            expected_parent_commitment: PARENT.into(),
            usage: usage(),
            envelope: StakeStateResourceEnvelopeV1 {
                resource_policy_sequence: state.active_policy_sequence,
                resource_policy_commitment: state.active_policy_commitment().into(),
                sponsor,
                funding_coin_id: funding_coin_id.into(),
                max_resource_fee: Amount(10_000),
                max_state_bond: Amount(10_000),
                lease_end_height: 200,
                resource_subject_hash: ZERO_SHA256.into(),
                authorization: SignedActionAuthorization {
                    authorization_id: format!("resource-auth-{nonce}"),
                    zone_id: context().zone_id,
                    currency_genesis_root: ROOT.into(),
                    protocol_era: 1,
                    crypto_era: 1,
                    signer_public_key: identity.public_key.clone(),
                    action: FUND_STAKE_STATE_RESOURCE_ACTION_V1.into(),
                    payload_hash: ZERO_SHA256.into(),
                    nonce,
                    signature: String::new(),
                },
            },
        };
        let subject = stake_state_resource_subject_hash_v1(&context(), &request);
        request.envelope.resource_subject_hash = subject.clone();
        request.envelope.authorization.payload_hash = subject;
        request.envelope.authorization.signature = sign_bytes(
            &identity.secret_key,
            &request.envelope.authorization.signing_bytes(),
        )
        .unwrap();
        request
    }

    fn admit_position() -> (
        StakeStateResourceAccountingV1,
        StakeStateResourceAdmissionOutcomeV1,
    ) {
        let identity = generate_identity();
        let mut state = StakeStateResourceAccountingV1::new(context(), policy(), 100).unwrap();
        let sponsor = format!("rld:{}:{}", context().zone_id, identity.public_key);
        let funding = funding_coin(&sponsor, Amount(20_000), "funding-1");
        let request = signed_request(
            &state,
            &identity,
            "POSITION/position-1",
            StakeStateResourceKindV1::Position,
            &funding.object_id,
            1,
        );
        let outcome = state
            .admit(request, &funding, &BTreeSet::new(), 101)
            .unwrap();
        (state, outcome)
    }

    #[test]
    fn quote_uses_checked_exact_units_and_position_minimum() {
        let state = StakeStateResourceAccountingV1::new(context(), policy(), 100).unwrap();
        let (fee, bond) = state
            .quote(StakeStateResourceKindV1::Position, usage())
            .unwrap();
        assert_eq!(fee, Amount(447));
        assert_eq!(bond, Amount(6_000));
    }

    #[test]
    fn admission_consumes_exact_funding_and_conserves_pool_bond_and_change() {
        let (state, outcome) = admit_position();
        assert_eq!(outcome.charged_fee, Amount(447));
        assert_eq!(outcome.locked_bond, Amount(6_000));
        assert_eq!(outcome.consumed_funding_coin.state, CoinState::Consumed);
        assert_eq!(outcome.bond_coin.state, CoinState::Reserved);
        assert_eq!(outcome.change_coin.as_ref().unwrap().amount, Amount(13_553));
        assert_eq!(
            outcome.charged_fee.0
                + outcome.bond_coin.amount.0
                + outcome.change_coin.as_ref().unwrap().amount.0,
            20_000
        );
        assert_eq!(state.maintenance_pool.total_charged_fees, Amount(447));
        assert_eq!(state.maintenance_pool.total_live_bonds, Amount(6_000));
        assert!(!state.maintenance_pool.runtime_payout_enabled);
        state.validate().unwrap();
    }

    #[test]
    fn forged_subject_signature_and_wrong_sponsor_fail_atomically() {
        let identity = generate_identity();
        let other = generate_identity();
        let mut state = StakeStateResourceAccountingV1::new(context(), policy(), 100).unwrap();
        let sponsor = format!("rld:{}:{}", context().zone_id, identity.public_key);
        let funding = funding_coin(&sponsor, Amount(20_000), "funding-1");
        let mut request = signed_request(
            &state,
            &identity,
            "POSITION/position-1",
            StakeStateResourceKindV1::Position,
            &funding.object_id,
            1,
        );
        request.resource_owner = "different-owner".into();
        let before = state.state_hash().unwrap();
        assert!(matches!(
            state.admit(request, &funding, &BTreeSet::new(), 101),
            Err(StakeResourceAccountingError::Authorization(_))
        ));
        assert_eq!(state.state_hash().unwrap(), before);

        let mut wrong_sponsor = signed_request(
            &state,
            &identity,
            "POSITION/position-1",
            StakeStateResourceKindV1::Position,
            &funding.object_id,
            2,
        );
        wrong_sponsor.envelope.sponsor = format!("rld:{}:{}", context().zone_id, other.public_key);
        let subject = stake_state_resource_subject_hash_v1(&context(), &wrong_sponsor);
        wrong_sponsor.envelope.resource_subject_hash = subject.clone();
        wrong_sponsor.envelope.authorization.payload_hash = subject;
        wrong_sponsor.envelope.authorization.signature = sign_bytes(
            &identity.secret_key,
            &wrong_sponsor.envelope.authorization.signing_bytes(),
        )
        .unwrap();
        assert!(matches!(
            state.admit(wrong_sponsor, &funding, &BTreeSet::new(), 101),
            Err(StakeResourceAccountingError::Authorization(_))
        ));
        assert_eq!(state.state_hash().unwrap(), before);
    }

    #[test]
    fn protected_or_reused_funding_and_authorization_fail_atomically() {
        let identity = generate_identity();
        let mut state = StakeStateResourceAccountingV1::new(context(), policy(), 100).unwrap();
        let sponsor = format!("rld:{}:{}", context().zone_id, identity.public_key);
        let funding = funding_coin(&sponsor, Amount(20_000), "funding-1");
        let request = signed_request(
            &state,
            &identity,
            "POSITION/position-1",
            StakeStateResourceKindV1::Position,
            &funding.object_id,
            1,
        );
        let before = state.state_hash().unwrap();
        assert!(state
            .admit(
                request.clone(),
                &funding,
                &BTreeSet::from([funding.object_id.clone()]),
                101,
            )
            .is_err());
        assert_eq!(state.state_hash().unwrap(), before);
        state
            .admit(request.clone(), &funding, &BTreeSet::new(), 101)
            .unwrap();
        let after = state.state_hash().unwrap();
        assert!(state
            .admit(request, &funding, &BTreeSet::new(), 101)
            .is_err());
        assert_eq!(state.state_hash().unwrap(), after);
    }

    #[test]
    fn sponsor_maximums_underfunding_and_lease_bounds_fail_atomically() {
        let identity = generate_identity();
        for mode in 0..4 {
            let mut state = StakeStateResourceAccountingV1::new(context(), policy(), 100).unwrap();
            let sponsor = format!("rld:{}:{}", context().zone_id, identity.public_key);
            let amount = if mode == 2 {
                Amount(6_446)
            } else {
                Amount(20_000)
            };
            let funding = funding_coin(&sponsor, amount, "funding-1");
            let mut request = signed_request(
                &state,
                &identity,
                "POSITION/position-1",
                StakeStateResourceKindV1::Position,
                &funding.object_id,
                mode as u64 + 1,
            );
            if mode == 0 {
                request.envelope.max_resource_fee = Amount(446);
            } else if mode == 1 {
                request.envelope.max_state_bond = Amount(5_999);
            } else if mode == 3 {
                request.envelope.lease_end_height = 109;
            }
            let subject = stake_state_resource_subject_hash_v1(&context(), &request);
            request.envelope.resource_subject_hash = subject.clone();
            request.envelope.authorization.payload_hash = subject;
            request.envelope.authorization.signature = sign_bytes(
                &identity.secret_key,
                &request.envelope.authorization.signing_bytes(),
            )
            .unwrap();
            let before = state.state_hash().unwrap();
            assert!(state
                .admit(request, &funding, &BTreeSet::new(), 101)
                .is_err());
            assert_eq!(state.state_hash().unwrap(), before);
        }
    }

    #[test]
    fn per_owner_count_and_per_block_bytes_are_hard_limits_even_when_funded() {
        let identity = generate_identity();
        let mut state = StakeStateResourceAccountingV1::new(context(), policy(), 100).unwrap();
        let sponsor = format!("rld:{}:{}", context().zone_id, identity.public_key);
        let first_coin = funding_coin(&sponsor, Amount(50_000), "funding-1");
        let first = signed_request(
            &state,
            &identity,
            "CANDIDATE/validator-1",
            StakeStateResourceKindV1::Candidate,
            &first_coin.object_id,
            1,
        );
        state
            .admit(first, &first_coin, &BTreeSet::new(), 101)
            .unwrap();
        let second_coin = funding_coin(&sponsor, Amount(50_000), "funding-2");
        let second = signed_request(
            &state,
            &identity,
            "CANDIDATE/validator-2",
            StakeStateResourceKindV1::Candidate,
            &second_coin.object_id,
            2,
        );
        let before = state.state_hash().unwrap();
        assert!(matches!(
            state.admit(second, &second_coin, &BTreeSet::new(), 101),
            Err(StakeResourceAccountingError::HardLimit(_))
        ));
        assert_eq!(state.state_hash().unwrap(), before);

        let mut byte_state = StakeStateResourceAccountingV1::new(context(), policy(), 100).unwrap();
        let mut oversized = signed_request(
            &byte_state,
            &identity,
            "POSITION/position-big",
            StakeStateResourceKindV1::Position,
            &first_coin.object_id,
            3,
        );
        oversized.usage.persistent_bytes = 2_001;
        let subject = stake_state_resource_subject_hash_v1(&context(), &oversized);
        oversized.envelope.resource_subject_hash = subject.clone();
        oversized.envelope.authorization.payload_hash = subject;
        oversized.envelope.authorization.signature = sign_bytes(
            &identity.secret_key,
            &oversized.envelope.authorization.signing_bytes(),
        )
        .unwrap();
        assert!(matches!(
            byte_state.admit(oversized, &first_coin, &BTreeSet::new(), 101),
            Err(StakeResourceAccountingError::HardLimit(_))
        ));
        assert!(byte_state.bonds.is_empty());
    }

    #[test]
    fn release_refund_and_forfeit_preserve_exact_bond_value() {
        let (mut refunded, admitted) = admit_position();
        let before_early = refunded.state_hash().unwrap();
        assert!(refunded
            .mark_releaseable("POSITION/position-1", TERMINAL, 220, 210, 239)
            .is_err());
        assert_eq!(refunded.state_hash().unwrap(), before_early);
        refunded
            .mark_releaseable("POSITION/position-1", TERMINAL, 220, 210, 240)
            .unwrap();
        let refund = refunded
            .refund(
                "POSITION/position-1",
                &admitted.consumed_funding_coin,
                &admitted.bond_coin,
                241,
            )
            .unwrap();
        assert_eq!(refund.refund_coin.amount, admitted.locked_bond);
        assert_eq!(refunded.maintenance_pool.total_live_bonds, Amount::ZERO);
        assert_eq!(
            refunded.maintenance_pool.total_refunded_bonds,
            admitted.locked_bond
        );
        refunded.validate().unwrap();

        let (mut forfeited, admitted) = admit_position();
        let before_early = forfeited.state_hash().unwrap();
        assert!(forfeited
            .forfeit(
                "POSITION/position-1",
                TERMINAL,
                &admitted.consumed_funding_coin,
                &admitted.bond_coin,
                219,
            )
            .is_err());
        assert_eq!(forfeited.state_hash().unwrap(), before_early);
        let outcome = forfeited
            .forfeit(
                "POSITION/position-1",
                TERMINAL,
                &admitted.consumed_funding_coin,
                &admitted.bond_coin,
                220,
            )
            .unwrap();
        assert_eq!(outcome.consumed_bond_coin.amount, admitted.locked_bond);
        assert_eq!(forfeited.maintenance_pool.total_live_bonds, Amount::ZERO);
        assert_eq!(
            forfeited.maintenance_pool.total_forfeited_bonds,
            admitted.locked_bond
        );
        forfeited.validate().unwrap();
    }

    #[test]
    fn canonical_recovery_rejects_whitespace_and_tampered_pool_or_record() {
        let (state, _) = admit_position();
        let bytes = state.canonical_json_bytes().unwrap();
        assert_eq!(
            StakeStateResourceAccountingV1::restore_canonical_json(&bytes).unwrap(),
            state
        );
        let mut whitespace = b" ".to_vec();
        whitespace.extend_from_slice(&bytes);
        assert!(StakeStateResourceAccountingV1::restore_canonical_json(&whitespace).is_err());

        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["maintenance_pool"]["total_live_bonds"] = serde_json::json!("1");
        let tampered = serde_json::to_vec(&value).unwrap();
        assert!(StakeStateResourceAccountingV1::restore_canonical_json(&tampered).is_err());

        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["bonds"]["POSITION/position-1"]["charged_persistent_bytes"] = serde_json::json!(301);
        let tampered = serde_json::to_vec(&value).unwrap();
        assert!(StakeStateResourceAccountingV1::restore_canonical_json(&tampered).is_err());
    }

    #[test]
    fn policy_rotation_is_exact_contiguous_and_failure_atomic() {
        let mut state = StakeStateResourceAccountingV1::new(context(), policy(), 100).unwrap();
        let first_commitment = state.active_policy_commitment().to_owned();
        let first_pool_commitment = state.maintenance_pool().pool_commitment.clone();
        let mut successor = policy();
        successor.sequence = 2;
        successor.previous_policy_commitment = first_commitment.clone();
        successor.base_position_fee = Amount(250);
        let successor_commitment = stake_state_resource_policy_commitment_v1(&successor).unwrap();
        assert_eq!(
            state.activate_policy(successor, 200).unwrap(),
            successor_commitment
        );
        assert_eq!(state.active_policy().sequence, 2);
        assert_eq!(state.policy_generations(), 2);
        assert_eq!(state.policy_commitment(1), Some(first_commitment.as_str()));
        assert_eq!(
            state.policy_commitment(2),
            Some(successor_commitment.as_str())
        );
        assert_eq!(state.maintenance_pool().policy_buckets.len(), 2);
        assert_ne!(
            state.maintenance_pool().pool_commitment,
            first_pool_commitment
        );

        let before = state.state_hash().unwrap();
        let mut skipped = policy();
        skipped.sequence = 4;
        skipped.previous_policy_commitment = successor_commitment.clone();
        assert!(matches!(
            state.activate_policy(skipped, 300),
            Err(StakeResourceAccountingError::InvalidPolicy(_))
        ));
        assert_eq!(state.state_hash().unwrap(), before);

        let mut wrong_predecessor = policy();
        wrong_predecessor.sequence = 3;
        wrong_predecessor.previous_policy_commitment = ZERO_SHA256.into();
        assert!(matches!(
            state.activate_policy(wrong_predecessor, 300),
            Err(StakeResourceAccountingError::InvalidPolicy(_))
        ));
        assert_eq!(state.state_hash().unwrap(), before);
    }

    #[test]
    fn successor_policy_cannot_undercut_live_state_limits() {
        let (mut state, _) = admit_position();
        let before = state.state_hash().unwrap();
        let mut successor = policy();
        successor.sequence = 2;
        successor.previous_policy_commitment = state.active_policy_commitment().to_owned();
        successor.maximum_total_stake_state_bytes = 299;
        successor.maximum_stake_state_bytes_per_block = 299;
        assert!(matches!(
            state.activate_policy(successor, 200),
            Err(StakeResourceAccountingError::HardLimit(_))
        ));
        assert_eq!(state.state_hash().unwrap(), before);
    }

    #[test]
    fn arithmetic_overflow_policy_is_rejected_before_state_exists() {
        let mut bad = policy();
        bad.fee_per_wire_byte = Amount(u128::MAX);
        assert!(matches!(
            StakeStateResourceAccountingV1::new(context(), bad, 100),
            Err(StakeResourceAccountingError::Arithmetic(_))
        ));
    }

    #[test]
    fn rust_executes_every_independent_python_accounting_vector() {
        let bundle: serde_json::Value = serde_json::from_str(ACCOUNTING_VECTORS).unwrap();
        let payload = &bundle["payload"];
        assert_eq!(payload["format"], "rld-stake-resource-accounting-v1");
        assert_eq!(payload["claims"]["independent_python"], true);
        for claim in [
            "existing_admission_runtime_adoption",
            "existing_admission_ledger_integration",
            "generic_consensus_commit_route",
            "fee_only_unbond_mutation_primitive",
            "unbond_worst_case_footprint",
            "unbond_planning_primitive",
            "unbond_reservation_prototype_only",
        ] {
            assert_eq!(payload["claims"][claim], true, "{claim} must be true");
        }
        for claim in [
            "dedicated_node_route",
            "dynamic_membership",
            "other_lifecycle_paths",
            "unbond_ledger_route",
            "unbond_runtime_read_write_catalog",
            "unbond_reservation_state_primitive",
            "mainnet_ready",
        ] {
            assert_eq!(payload["claims"][claim], false, "{claim} must remain false");
        }
        assert_eq!(payload["claims"]["value_cap"], "VALUE_CAP_0");

        let context: StakeStateResourceContextV1 =
            serde_json::from_value(payload["context"].clone()).unwrap();
        let policy: StakeStateResourcePolicyV1 =
            serde_json::from_value(payload["policy"].clone()).unwrap();
        assert_eq!(
            hex::encode(policy.wire_v1_candidate_payload_bytes().unwrap()),
            payload["policy_payload_hex"].as_str().unwrap()
        );
        assert_eq!(
            stake_state_resource_policy_commitment_v1(&policy).unwrap(),
            payload["policy_commitment"].as_str().unwrap()
        );

        let mut accepted = 0usize;
        let mut rejected = 0usize;
        for case in payload["cases"].as_array().unwrap() {
            let mut state =
                StakeStateResourceAccountingV1::new(context.clone(), policy.clone(), 100).unwrap();
            let request: StakeStateResourceAdmissionRequestV1 =
                serde_json::from_value(case["request"].clone()).unwrap();
            let funding: CoinObject = serde_json::from_value(case["funding_coin"].clone()).unwrap();
            let protected = case["protected_coin_ids"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_owned())
                .collect::<BTreeSet<_>>();
            let before = state.state_hash().unwrap();
            let result = state.admit(
                request,
                &funding,
                &protected,
                case["current_height"].as_u64().unwrap(),
            );
            if case["expected"] == "reject" {
                rejected += 1;
                let error = result.unwrap_err();
                let class = match error {
                    StakeResourceAccountingError::InvalidRequest(_) => "invalid_request",
                    StakeResourceAccountingError::Authorization(_) => "authorization",
                    StakeResourceAccountingError::FundingCoin(_) => "funding_coin",
                    StakeResourceAccountingError::HardLimit(_) => "hard_limit",
                    other => panic!("unexpected vector error: {other}"),
                };
                assert_eq!(class, case["expected_error_class"].as_str().unwrap());
                assert_eq!(state.state_hash().unwrap(), before);
                continue;
            }

            accepted += 1;
            let outcome = result.unwrap();
            let expected = &case["expected_outcome"];
            assert_eq!(outcome.charged_fee.to_string(), expected["charged_fee"]);
            assert_eq!(outcome.locked_bond.to_string(), expected["locked_bond"]);
            assert_eq!(outcome.bond_coin.object_id, expected["bond_coin_id"]);
            assert_eq!(
                outcome
                    .change_coin
                    .as_ref()
                    .map(|coin| coin.object_id.as_str()),
                expected["change_coin_id"].as_str()
            );
            assert_eq!(
                outcome
                    .change_coin
                    .as_ref()
                    .map_or(Amount::ZERO, |coin| coin.amount)
                    .to_string(),
                expected["change_amount"]
            );
            assert_eq!(
                outcome.bond_record,
                serde_json::from_value::<StakeStateBondRecordV2>(expected["locked_record"].clone())
                    .unwrap()
            );
            assert_eq!(
                state.maintenance_pool,
                serde_json::from_value::<StakeStateMaintenancePoolV2>(
                    expected["admission_pool"].clone()
                )
                .unwrap()
            );

            let mut refund_state = state.clone();
            let releaseable = refund_state
                .mark_releaseable("POSITION/position-1", TERMINAL, 220, 210, 240)
                .unwrap();
            assert_eq!(releaseable.record_hash, expected["releaseable_record_hash"]);
            let refund = refund_state
                .refund(
                    "POSITION/position-1",
                    &outcome.consumed_funding_coin,
                    &outcome.bond_coin,
                    241,
                )
                .unwrap();
            assert_eq!(
                refund.bond_record.record_hash,
                expected["refunded_record_hash"]
            );
            assert_eq!(
                refund_state.maintenance_pool.pool_commitment,
                expected["refunded_pool_commitment"]
            );

            let mut forfeit_state = state;
            let forfeited = forfeit_state
                .forfeit(
                    "POSITION/position-1",
                    TERMINAL,
                    &outcome.consumed_funding_coin,
                    &outcome.bond_coin,
                    220,
                )
                .unwrap();
            assert_eq!(
                forfeited.bond_record.record_hash,
                expected["forfeited_record_hash"]
            );
            assert_eq!(
                forfeit_state.maintenance_pool.pool_commitment,
                expected["forfeited_pool_commitment"]
            );
        }
        assert_eq!((accepted, rejected), (2, 10));
    }

    #[test]
    fn rust_matches_independent_candidate_persistent_footprint() {
        let bundle: serde_json::Value = serde_json::from_str(ACCOUNTING_VECTORS).unwrap();
        let fixture = &bundle["payload"]["candidate_registration_footprint_v2"];
        let text = |field: &str| fixture[field].as_str().unwrap().to_owned();
        let authorization = |authorization_id: String| SignedActionAuthorization {
            authorization_id,
            zone_id: text("zone_id"),
            currency_genesis_root: ROOT.into(),
            protocol_era: 1,
            crypto_era: 1,
            signer_public_key: "11".repeat(32),
            action: "fixture-only".into(),
            payload_hash: ZERO_SHA256.into(),
            nonce: 1,
            signature: "22".repeat(64),
        };
        let request = RegisterConsensusValidatorRequestV2 {
            request_id: "fixture-only".into(),
            zone_id: text("zone_id"),
            currency_genesis_root: ROOT.into(),
            protocol_era: 1,
            crypto_era: 1,
            proposed_height: 1,
            expires_at_height: 2,
            expected_authority_sequence: 1,
            expected_authority_commitment: ZERO_SHA256.into(),
            validator_id: text("validator_id"),
            owner: text("owner"),
            public_key: "33".repeat(32),
            key_era: 1,
            proof_of_possession: "44".repeat(64),
            resource_envelope: StakeStateResourceEnvelopeV1 {
                resource_policy_sequence: 1,
                resource_policy_commitment: ZERO_SHA256.into(),
                sponsor: text("sponsor"),
                funding_coin_id: text("funding_coin_id"),
                max_resource_fee: Amount::ZERO,
                max_state_bond: Amount::ZERO,
                lease_end_height: 2,
                resource_subject_hash: ZERO_SHA256.into(),
                authorization: authorization(text("sponsor_authorization_id")),
            },
            authorization: authorization(text("owner_authorization_id")),
        };
        assert_eq!(fixture["charges_worst_case_change_coin"], true);
        assert_eq!(
            register_consensus_validator_persistent_bytes_v2(&request).unwrap(),
            fixture["expected_persistent_bytes"].as_u64().unwrap()
        );
    }

    #[test]
    fn rust_matches_independent_position_and_migration_persistent_footprints() {
        let bundle: serde_json::Value = serde_json::from_str(ACCOUNTING_VECTORS).unwrap();
        let fixture = &bundle["payload"]["position_footprint_v3"];
        let text = |field: &str| fixture[field].as_str().unwrap().to_owned();
        let authorization =
            |authorization_id: String, zone_id: String, action: String| SignedActionAuthorization {
                authorization_id,
                zone_id,
                currency_genesis_root: ROOT.into(),
                protocol_era: 1,
                crypto_era: 1,
                signer_public_key: "11".repeat(32),
                action,
                payload_hash: ZERO_SHA256.into(),
                nonce: 1,
                signature: "22".repeat(64),
            };
        let slash_authorization = authorization(
            text("slash_authorization_id"),
            text("slash_authorization_zone_id"),
            text("slash_authorization_action"),
        );
        let sponsor_authorization = authorization(
            text("sponsor_authorization_id"),
            text("zone_id"),
            FUND_STAKE_STATE_RESOURCE_ACTION_V1.into(),
        );
        let owner_authorization = authorization(
            text("owner_authorization_id"),
            text("zone_id"),
            "fixture-only".into(),
        );
        let envelope = StakeStateResourceEnvelopeV1 {
            resource_policy_sequence: 1,
            resource_policy_commitment: ZERO_SHA256.into(),
            sponsor: text("sponsor"),
            funding_coin_id: text("funding_coin_id"),
            max_resource_fee: Amount::ZERO,
            max_state_bond: Amount::ZERO,
            lease_end_height: 2,
            resource_subject_hash: ZERO_SHA256.into(),
            authorization: sponsor_authorization,
        };
        let request = LockConsensusStakeRequestV3 {
            position_id: text("position_id"),
            zone_id: text("zone_id"),
            currency_genesis_root: ROOT.into(),
            protocol_era: 1,
            crypto_era: 1,
            proposed_height: 1,
            expires_at_height: 2,
            expected_authority_sequence: 1,
            expected_authority_commitment: ZERO_SHA256.into(),
            position_type: StakePositionTypeV1::SelfBond,
            validator_id: text("validator_id"),
            owner: text("owner"),
            source_coin_id: text("source_coin_id"),
            amount: Amount(10),
            committed_through_height: 100,
            slash_terms_authorization: slash_authorization.clone(),
            resource_envelope: envelope.clone(),
            authorization: owner_authorization.clone(),
        };
        assert_eq!(fixture["charges_worst_case_stake_change_coin"], true);
        assert_eq!(fixture["charges_worst_case_resource_change_coin"], true);
        assert_eq!(
            lock_consensus_stake_persistent_bytes_v3(&request).unwrap(),
            fixture["new_position_expected_persistent_bytes"]
                .as_u64()
                .unwrap()
        );

        let position = ConsensusStakePosition {
            position_id: text("position_id"),
            kind: ConsensusStakePositionKind::SelfBond {
                validator_id: text("validator_id"),
            },
            owner: text("owner"),
            source_coin_id: text("source_coin_id"),
            escrow_coin_id: text("escrow_coin_id"),
            amount: Amount(10),
            locked_height: 1,
            committed_through_height: 100,
            slash_terms: Some(ConsensusStakeSlashTermsV2 {
                terms_version: ConsensusStakeSlashPolicyV2::protocol_v2().policy_version,
                slash_policy: ConsensusStakeSlashPolicyV2::protocol_v2(),
                owner_authorization: slash_authorization,
            }),
        };
        let migration = MigrateConsensusStakeResourceRequestV1 {
            request_id: "fixture-only".into(),
            zone_id: text("zone_id"),
            currency_genesis_root: ROOT.into(),
            protocol_era: 1,
            crypto_era: 1,
            proposed_height: 1,
            expires_at_height: 2,
            expected_authority_sequence: 1,
            expected_authority_commitment: ZERO_SHA256.into(),
            position_id: text("position_id"),
            escrow_coin_id: text("escrow_coin_id"),
            owner: text("owner"),
            expected_position_commitment: ZERO_SHA256.into(),
            resource_envelope: envelope,
            authorization: owner_authorization,
        };
        assert_eq!(
            fixture["migration_retroactively_accounts_retained_position"],
            true
        );
        assert_eq!(
            migrate_consensus_stake_resource_persistent_bytes_v1(&migration, &position).unwrap(),
            fixture["migration_expected_persistent_bytes"]
                .as_u64()
                .unwrap()
        );
    }

    #[test]
    fn liability_horizon_delta_charges_only_append_and_rejects_rewrite() {
        let mut first = StakePositionLiabilityHorizonV1 {
            horizon_version: crate::STAKE_POSITION_LIABILITY_HORIZON_VERSION_V1,
            position_id: "position-horizon-0001".into(),
            owner: "rld:zone-resource-test:horizon-owner".into(),
            escrow_coin_id: "coin-horizon-escrow-0001".into(),
            retained_liability_count: 1,
            max_evidence_deadline_height: 100,
            last_consensus_epoch: 1,
            liability_accumulator_root: "61".repeat(32),
            previous_horizon_commitment: ZERO_SHA256.into(),
            horizon_commitment: String::new(),
        };
        first.horizon_commitment = first.compute_commitment();
        let mut second = first.clone();
        second.retained_liability_count = 2;
        second.max_evidence_deadline_height = 120;
        second.last_consensus_epoch = 2;
        second.liability_accumulator_root = "62".repeat(32);
        second.previous_horizon_commitment = first.horizon_commitment.clone();
        second.horizon_commitment = second.compute_commitment();

        let previous_current = BTreeMap::from([(first.position_id.clone(), first.clone())]);
        let previous_history = BTreeMap::from([(first.position_id.clone(), vec![first.clone()])]);
        let next_current = BTreeMap::from([(second.position_id.clone(), second.clone())]);
        let next_history = BTreeMap::from([(
            second.position_id.clone(),
            vec![first.clone(), second.clone()],
        )]);
        let delta = stake_liability_horizon_usage_delta_v1(
            &previous_current,
            &previous_history,
            &next_current,
            &next_history,
        )
        .unwrap();
        assert_eq!(delta.appended_records, 1);
        assert_eq!(delta.touched_positions, 1);
        assert_eq!(delta.state_reads, 2);
        assert_eq!(delta.state_writes, 2);
        assert_eq!(
            delta.persistent_bytes,
            stake_liability_horizon_record_bytes_v1(&second).unwrap()
        );

        let rewritten_history =
            BTreeMap::from([(second.position_id.clone(), vec![second.clone()])]);
        assert!(matches!(
            stake_liability_horizon_usage_delta_v1(
                &previous_current,
                &previous_history,
                &next_current,
                &rewritten_history,
            ),
            Err(StakeResourceAccountingError::InvalidRequest(message))
                if message.contains("append-only")
        ));
    }

    #[test]
    fn rust_matches_independent_candidate_migration_and_epoch_footprints() {
        let bundle: serde_json::Value = serde_json::from_str(ACCOUNTING_VECTORS).unwrap();
        let candidate_fixture = &bundle["payload"]["candidate_migration_footprint_v1"];
        let candidate_text = |field: &str| candidate_fixture[field].as_str().unwrap().to_owned();
        let authorization =
            |authorization_id: String, zone_id: String, action: String| SignedActionAuthorization {
                authorization_id,
                zone_id,
                currency_genesis_root: ROOT.into(),
                protocol_era: 1,
                crypto_era: 1,
                signer_public_key: "11".repeat(32),
                action,
                payload_hash: ZERO_SHA256.into(),
                nonce: 1,
                signature: "22".repeat(64),
            };
        let candidate = ValidatorCandidateRecord {
            validator_id: candidate_text("validator_id"),
            owner: candidate_text("owner"),
            public_key: "33".repeat(32),
            key_era: 1,
            registered_height: 1,
            exit_height: None,
            proof_of_possession: "44".repeat(64),
        };
        let candidate_migration = MigrateConsensusCandidateResourceRequestV1 {
            request_id: "fixture-only".into(),
            zone_id: candidate_text("zone_id"),
            currency_genesis_root: ROOT.into(),
            protocol_era: 1,
            crypto_era: 1,
            proposed_height: 1,
            expires_at_height: 2,
            expected_authority_sequence: 1,
            expected_authority_commitment: ZERO_SHA256.into(),
            validator_id: candidate.validator_id.clone(),
            owner: candidate.owner.clone(),
            public_key: candidate.public_key.clone(),
            key_era: candidate.key_era,
            registered_height: 1,
            exit_height: None,
            proof_of_possession: candidate.proof_of_possession.clone(),
            expected_candidate_commitment: candidate.resource_commitment_v1(),
            resource_envelope: StakeStateResourceEnvelopeV1 {
                resource_policy_sequence: 1,
                resource_policy_commitment: ZERO_SHA256.into(),
                sponsor: candidate_text("sponsor"),
                funding_coin_id: candidate_text("funding_coin_id"),
                max_resource_fee: Amount::ZERO,
                max_state_bond: Amount::ZERO,
                lease_end_height: 2,
                resource_subject_hash: ZERO_SHA256.into(),
                authorization: authorization(
                    candidate_text("sponsor_authorization_id"),
                    candidate_text("zone_id"),
                    FUND_STAKE_STATE_RESOURCE_ACTION_V1.into(),
                ),
            },
            authorization: authorization(
                candidate_text("owner_authorization_id"),
                candidate_text("zone_id"),
                "fixture-only".into(),
            ),
        };
        assert_eq!(
            migrate_consensus_candidate_resource_persistent_bytes_v1(
                &candidate_migration,
                &candidate,
            )
            .unwrap(),
            candidate_fixture["expected_persistent_bytes"]
                .as_u64()
                .unwrap()
        );

        let fixture = &bundle["payload"]["epoch_footprint_v2"];
        let text = |field: &str| fixture[field].as_str().unwrap().to_owned();
        let liability_fixture = &fixture["liabilities"][0];
        let liability_text = |field: &str| liability_fixture[field].as_str().unwrap().to_owned();
        let slash_authorization = authorization(
            liability_text("slash_authorization_id"),
            liability_text("slash_authorization_zone_id"),
            liability_text("slash_authorization_action"),
        );
        let position = ConsensusStakePosition {
            position_id: liability_text("position_id"),
            kind: ConsensusStakePositionKind::SelfBond {
                validator_id: liability_text("validator_id"),
            },
            owner: liability_text("owner"),
            source_coin_id: liability_text("source_coin_id"),
            escrow_coin_id: liability_text("escrow_coin_id"),
            amount: Amount(10),
            locked_height: 1,
            committed_through_height: 100,
            slash_terms: Some(ConsensusStakeSlashTermsV2 {
                terms_version: ConsensusStakeSlashPolicyV2::protocol_v2().policy_version,
                slash_policy: ConsensusStakeSlashPolicyV2::protocol_v2(),
                owner_authorization: slash_authorization,
            }),
        };
        let validator_fixture = &fixture["validators"][0];
        let descriptor = ConsensusEpochDescriptor {
            network_domain: text("network_domain"),
            zone_id: text("zone_id"),
            currency_genesis_root: ROOT.into(),
            protocol_era: 1,
            crypto_era: 1,
            consensus_protocol_version: 1,
            consensus_epoch: fixture["consensus_epoch"].as_u64().unwrap(),
            activation_height: 10,
            exit_height: 20,
            stake_snapshot_root: ZERO_SHA256.into(),
            validators: vec![ValidatorRecord {
                validator_id: validator_fixture["validator_id"].as_str().unwrap().into(),
                public_key: "55".repeat(32),
                key_era: 1,
                weight: 10,
                control_group: validator_fixture["control_group"].as_str().unwrap().into(),
                self_bond: 10,
                delegated_weight: 0,
                unbonding_height: 100,
            }],
            total_weight: 10,
            quorum_power: 7,
            quorum_rule: ConsensusQuorumRule::v1(),
        };
        let epoch = LedgerDerivedStakeEpochV1 {
            derivation_version: 2,
            status: StakeEpochRecordStatus::DerivedOnly,
            stake_snapshot_height: 9,
            stake_snapshot_state_root: ZERO_SHA256.into(),
            previous_record_hash: ZERO_SHA256.into(),
            descriptor,
            descriptor_commitment: ZERO_SHA256.into(),
            stake_liability_root: ZERO_SHA256.into(),
            stake_liabilities: vec![ConsensusStakeEpochLiabilityV2 {
                consensus_epoch: fixture["consensus_epoch"].as_u64().unwrap(),
                position,
                validator_public_key: "55".repeat(32),
                validator_key_era: 1,
                activation_height: 10,
                exit_height: 20,
                evidence_window_blocks: 5,
                evidence_deadline_height: 25,
                slash_terms_commitment: ZERO_SHA256.into(),
                liability_commitment: ZERO_SHA256.into(),
            }],
            record_hash: ZERO_SHA256.into(),
        };
        let request = DeriveNextStakeEpochRequestV2 {
            request_id: "fixture-only".into(),
            zone_id: text("zone_id"),
            currency_genesis_root: ROOT.into(),
            protocol_era: 1,
            crypto_era: 1,
            proposed_height: 9,
            expires_at_height: 10,
            expected_authority_sequence: 1,
            expected_authority_commitment: ZERO_SHA256.into(),
            expected_consensus_epoch: fixture["consensus_epoch"].as_u64().unwrap(),
            expected_snapshot_height: 9,
            expected_snapshot_state_root: ZERO_SHA256.into(),
            expected_derived_record_hash: ZERO_SHA256.into(),
            payer: text("payer"),
            resource_envelope: StakeStateResourceEnvelopeV1 {
                resource_policy_sequence: 1,
                resource_policy_commitment: ZERO_SHA256.into(),
                sponsor: text("sponsor"),
                funding_coin_id: text("funding_coin_id"),
                max_resource_fee: Amount::ZERO,
                max_state_bond: Amount::ZERO,
                lease_end_height: 30,
                resource_subject_hash: ZERO_SHA256.into(),
                authorization: authorization(
                    text("sponsor_authorization_id"),
                    text("zone_id"),
                    FUND_STAKE_STATE_RESOURCE_ACTION_V1.into(),
                ),
            },
            authorization: authorization(
                text("payer_authorization_id"),
                text("zone_id"),
                "fixture-only".into(),
            ),
        };
        let liability = &epoch.stake_liabilities[0];
        let mut horizon = StakePositionLiabilityHorizonV1 {
            horizon_version: crate::STAKE_POSITION_LIABILITY_HORIZON_VERSION_V1,
            position_id: liability.position.position_id.clone(),
            owner: liability.position.owner.clone(),
            escrow_coin_id: liability.position.escrow_coin_id.clone(),
            retained_liability_count: 1,
            max_evidence_deadline_height: liability.evidence_deadline_height,
            last_consensus_epoch: liability.consensus_epoch,
            liability_accumulator_root: "66".repeat(32),
            previous_horizon_commitment: ZERO_SHA256.into(),
            horizon_commitment: String::new(),
        };
        horizon.horizon_commitment = horizon.compute_commitment();
        let next_current = BTreeMap::from([(horizon.position_id.clone(), horizon.clone())]);
        let next_history = BTreeMap::from([(horizon.position_id.clone(), vec![horizon])]);
        let horizon_usage = stake_liability_horizon_usage_delta_v1(
            &BTreeMap::new(),
            &BTreeMap::new(),
            &next_current,
            &next_history,
        )
        .unwrap();
        assert_eq!(
            horizon_usage.persistent_bytes,
            fixture["expected_horizon_persistent_bytes"]
                .as_u64()
                .unwrap()
        );
        assert_eq!(
            u64::from(horizon_usage.state_reads),
            fixture["expected_horizon_state_reads"].as_u64().unwrap()
        );
        assert_eq!(
            u64::from(horizon_usage.state_writes),
            fixture["expected_horizon_state_writes"].as_u64().unwrap()
        );
        assert_eq!(
            derive_next_stake_epoch_persistent_bytes_v2(&request, &epoch, horizon_usage).unwrap(),
            fixture["expected_persistent_bytes"].as_u64().unwrap()
        );

        let renewal = &bundle["payload"]["renewal_footprint_v1"];
        let renewal_text = |field: &str| renewal[field].as_str().unwrap().to_owned();
        let renewal_request = RenewStakeStateResourceBondRequestV1 {
            renewal_id: renewal_text("renewal_id"),
            zone_id: renewal_text("zone_id"),
            currency_genesis_root: ROOT.into(),
            protocol_era: 1,
            crypto_era: 1,
            proposed_height: 1,
            expires_at_height: 2,
            resource_key: renewal_text("resource_key"),
            resource_kind: StakeStateResourceKindV1::Candidate,
            resource_owner: renewal_text("resource_owner"),
            expected_bond_id: renewal_text("expected_bond_id"),
            expected_initial_bond_record_hash: ZERO_SHA256.into(),
            expected_previous_renewal_hash: ZERO_SHA256.into(),
            expected_current_lease_end_height: 10,
            new_lease_end_height: 20,
            resource_policy_sequence: 1,
            resource_policy_commitment: ZERO_SHA256.into(),
            sponsor: renewal_text("sponsor"),
            funding_coin_id: renewal_text("funding_coin_id"),
            max_resource_fee: Amount::ZERO,
            max_additional_bond: Amount::ZERO,
            authorization: authorization(
                renewal_text("authorization_id"),
                renewal_text("zone_id"),
                RENEW_STAKE_STATE_RESOURCE_BOND_ACTION_V1.into(),
            ),
        };
        assert_eq!(
            renew_stake_state_resource_bond_persistent_bytes_v1(&renewal_request).unwrap(),
            renewal["expected_persistent_bytes"].as_u64().unwrap()
        );
        let renewal_usage = StakeStateResourceUsageV1 {
            wire_bytes: renewal["usage"]["wire_bytes"]
                .as_u64()
                .unwrap()
                .try_into()
                .unwrap(),
            persistent_bytes: renewal["usage"]["persistent_bytes"].as_u64().unwrap(),
            signature_checks: renewal["usage"]["signature_checks"]
                .as_u64()
                .unwrap()
                .try_into()
                .unwrap(),
            state_reads: renewal["usage"]["state_reads"]
                .as_u64()
                .unwrap()
                .try_into()
                .unwrap(),
            state_writes: renewal["usage"]["state_writes"]
                .as_u64()
                .unwrap()
                .try_into()
                .unwrap(),
        };
        let renewal_quote = quote_renewal(
            &policy(),
            StakeStateResourceKindV1::Candidate,
            renewal["original_persistent_bytes"].as_u64().unwrap(),
            renewal["extension_blocks"].as_u64().unwrap(),
            renewal_usage,
        )
        .unwrap();
        assert_eq!(renewal_quote.0.to_string(), renewal["expected_charged_fee"]);
        assert_eq!(
            renewal_quote.1.to_string(),
            renewal["expected_additional_bond"]
        );

        let unbond = &bundle["payload"]["unbond_worst_case_footprint_v1"];
        let record_fields = &unbond["record_fields"];
        let lifecycle =
            stake_unbond_lifecycle_record_footprints_v1(StakeUnbondLifecycleRecordInputV1 {
                request_id: record_fields["request_id"].as_str().unwrap(),
                owner: record_fields["owner"].as_str().unwrap(),
                beneficiary: record_fields["beneficiary"].as_str().unwrap(),
                completion_id: record_fields["completion_id"].as_str().unwrap(),
                payout_coin_id: record_fields["payout_coin_id"].as_str().unwrap(),
                slash_id: record_fields["slash_id"].as_str().unwrap(),
                completion_nullifier_id: record_fields["completion_nullifier_id"].as_str().unwrap(),
                slash_nullifier_id: record_fields["slash_nullifier_id"].as_str().unwrap(),
            })
            .unwrap();
        let records = &unbond["exact_record_footprints"];
        assert_eq!(
            lifecycle.pending_unbond_bytes,
            records["pending_unbond_bytes"].as_u64().unwrap()
        );
        assert_eq!(
            lifecycle.completed_terminal_bytes,
            records["completed_terminal_bytes"].as_u64().unwrap()
        );
        assert_eq!(
            lifecycle.fully_slashed_terminal_bytes,
            records["fully_slashed_terminal_bytes"].as_u64().unwrap()
        );
        assert_eq!(
            lifecycle.terminal_index_and_audit_bytes,
            records["terminal_index_and_audit_bytes"].as_u64().unwrap()
        );
        let worst = stake_unbond_lifecycle_worst_case_record_footprints_v1(
            record_fields["request_id"].as_str().unwrap(),
            record_fields["owner"].as_str().unwrap(),
        )
        .unwrap();
        let expected_worst = &unbond["worst_case_record_footprints"];
        assert_eq!(
            worst.pending_unbond_bytes,
            expected_worst["pending_unbond_bytes"].as_u64().unwrap()
        );
        assert_eq!(
            worst.completed_terminal_bytes,
            expected_worst["completed_terminal_bytes"].as_u64().unwrap()
        );
        assert_eq!(
            worst.fully_slashed_terminal_bytes,
            expected_worst["fully_slashed_terminal_bytes"]
                .as_u64()
                .unwrap()
        );
        assert_eq!(
            worst.terminal_index_and_audit_bytes,
            expected_worst["terminal_index_and_audit_bytes"]
                .as_u64()
                .unwrap()
        );

        let footprint_input = &unbond["input"];
        let footprint =
            stake_unbond_worst_case_footprint_v1(StakeUnbondWorstCaseFootprintInputV1 {
                retained_position_bytes: footprint_input["retained_position_bytes"]
                    .as_u64()
                    .unwrap(),
                retained_candidate_bytes: footprint_input["retained_candidate_bytes"]
                    .as_u64()
                    .unwrap(),
                retained_epoch_liability_bytes: footprint_input["retained_epoch_liability_bytes"]
                    .as_u64()
                    .unwrap(),
                retained_horizon_history_bytes: footprint_input["retained_horizon_history_bytes"]
                    .as_u64()
                    .unwrap(),
                pending_unbond_bytes: footprint_input["pending_unbond_bytes"].as_u64().unwrap(),
                completed_terminal_bytes: footprint_input["completed_terminal_bytes"]
                    .as_u64()
                    .unwrap(),
                fully_slashed_terminal_bytes: footprint_input["fully_slashed_terminal_bytes"]
                    .as_u64()
                    .unwrap(),
                terminal_index_and_audit_bytes: footprint_input["terminal_index_and_audit_bytes"]
                    .as_u64()
                    .unwrap(),
            })
            .unwrap();
        let expected_footprint = &unbond["expected"];
        assert_eq!(
            footprint.dependency_retained_bytes,
            expected_footprint["dependency_retained_bytes"]
                .as_u64()
                .unwrap()
        );
        assert_eq!(
            footprint.terminal_branch_upper_bound_bytes,
            expected_footprint["terminal_branch_upper_bound_bytes"]
                .as_u64()
                .unwrap()
        );
        assert_eq!(
            footprint.prepaid_terminal_capacity_bytes,
            expected_footprint["prepaid_terminal_capacity_bytes"]
                .as_u64()
                .unwrap()
        );
        assert_eq!(
            footprint.unbond_bond_persistent_bytes,
            expected_footprint["unbond_bond_persistent_bytes"]
                .as_u64()
                .unwrap()
        );
        assert_eq!(
            footprint.total_worst_case_retained_bytes,
            expected_footprint["total_worst_case_retained_bytes"]
                .as_u64()
                .unwrap()
        );

        let mutation_usage = |value: &serde_json::Value| StakeStateResourceMutationUsageV1 {
            wire_bytes: value["wire_bytes"].as_u64().unwrap().try_into().unwrap(),
            predecessor_total_stake_state_bytes: value["predecessor_total_stake_state_bytes"]
                .as_u64()
                .unwrap(),
            predecessor_live_bytes: value["predecessor_live_bytes"].as_u64().unwrap(),
            removed_live_bytes: value["removed_live_bytes"].as_u64().unwrap(),
            replacement_live_bytes: value["replacement_live_bytes"].as_u64().unwrap(),
            predecessor_history_bytes: value["predecessor_history_bytes"].as_u64().unwrap(),
            predecessor_history_commitment: hex::decode(
                value["predecessor_history_commitment"].as_str().unwrap(),
            )
            .unwrap()
            .try_into()
            .unwrap(),
            successor_history_bytes: value["successor_history_bytes"].as_u64().unwrap(),
            successor_history_prefix_commitment: hex::decode(
                value["successor_history_prefix_commitment"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap()
            .try_into()
            .unwrap(),
            appended_history_bytes: value["appended_history_bytes"].as_u64().unwrap(),
            prepaid_terminal_capacity_bytes: value["prepaid_terminal_capacity_bytes"]
                .as_u64()
                .unwrap(),
            signature_checks: value["signature_checks"]
                .as_u64()
                .unwrap()
                .try_into()
                .unwrap(),
            state_reads: value["state_reads"].as_u64().unwrap().try_into().unwrap(),
            state_writes: value["state_writes"].as_u64().unwrap().try_into().unwrap(),
            cpu_units: value["cpu_units"].as_u64().unwrap(),
            proof_verification_units: value["proof_verification_units"].as_u64().unwrap(),
        };
        let mutation_cases = bundle["payload"]["fee_only_mutation_v1"]["cases"]
            .as_array()
            .unwrap();
        assert_eq!(mutation_cases.len(), 15);
        for case in mutation_cases {
            let result =
                quote_fee_only_unbond_mutation_v1(&policy(), mutation_usage(&case["usage"]));
            let expected = case["expected"].as_str().unwrap();
            if expected == "accept" {
                let quote = result.unwrap();
                let outcome = &case["expected_outcome"];
                assert_eq!(quote.charged_fee.to_string(), outcome["charged_fee"]);
                assert_eq!(
                    quote.refundable_bond_delta.to_string(),
                    outcome["refundable_bond_delta"]
                );
                assert_eq!(
                    quote.predecessor_total_bytes,
                    outcome["predecessor_total_bytes"].as_u64().unwrap()
                );
                assert_eq!(
                    quote.successor_total_bytes,
                    outcome["successor_total_bytes"].as_u64().unwrap()
                );
                assert_eq!(
                    quote.successor_total_stake_state_bytes,
                    outcome["successor_total_stake_state_bytes"]
                        .as_u64()
                        .unwrap()
                );
                assert_eq!(
                    quote.newly_materialized_bytes,
                    outcome["newly_materialized_bytes"].as_u64().unwrap()
                );
                assert_eq!(
                    quote.net_released_bytes,
                    outcome["net_released_bytes"].as_u64().unwrap()
                );
                continue;
            }
            let observed = match result.unwrap_err() {
                StakeResourceAccountingError::InvalidRequest(_) => "invalid_request",
                StakeResourceAccountingError::HardLimit(_) => "hard_limit",
                StakeResourceAccountingError::Arithmetic(_) => "arithmetic",
                other => panic!("unexpected mutation vector error: {other}"),
            };
            assert_eq!(observed, expected);
            assert_eq!(observed, case["expected_error_class"]);
        }

        let reservation = &bundle["payload"]["terminal_reservation_accounting_v1"];
        let request = &reservation["request"];
        let mut reservation_state = StakeUnbondTerminalReservationAccountingV1::new(100, 100);
        let reserved = reservation_state
            .reserve(
                &policy(),
                StakeUnbondTerminalReserveInputV1 {
                    request_id: request["request_id"].as_str().unwrap().into(),
                    resource_key: request["resource_key"].as_str().unwrap().into(),
                    unbond_bond_record_hash: request["unbond_bond_record_hash"]
                        .as_str()
                        .unwrap()
                        .into(),
                    owner: request["owner"].as_str().unwrap().into(),
                    prepaid_terminal_capacity_bytes: request["prepaid_terminal_capacity_bytes"]
                        .as_u64()
                        .unwrap(),
                    predecessor_history_root: request["predecessor_history_root"]
                        .as_str()
                        .unwrap()
                        .into(),
                    predecessor_history_bytes: request["predecessor_history_bytes"]
                        .as_u64()
                        .unwrap(),
                    request_materialized_bytes: request["request_materialized_bytes"]
                        .as_u64()
                        .unwrap(),
                    height: request["height"].as_u64().unwrap(),
                    signature_checks: request["signature_checks"]
                        .as_u64()
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    state_reads: request["state_reads"].as_u64().unwrap().try_into().unwrap(),
                    state_writes: request["state_writes"]
                        .as_u64()
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    cpu_units: 0,
                    proof_verification_units: 0,
                },
            )
            .unwrap();
        assert_eq!(
            reserved.request_history_root,
            reservation["request_history_root"]
        );
        let terminal_bytes =
            hex::decode(reservation["terminal_record_hex"].as_str().unwrap()).unwrap();
        let consumed = reservation_state
            .consume(
                &policy(),
                StakeUnbondTerminalConsumeInputV1 {
                    request_id: request["request_id"].as_str().unwrap().into(),
                    expected_unbond_bond_record_hash: request["unbond_bond_record_hash"]
                        .as_str()
                        .unwrap()
                        .into(),
                    expected_predecessor_history_root: reserved.request_history_root,
                    expected_predecessor_history_bytes: request["predecessor_history_bytes"]
                        .as_u64()
                        .unwrap(),
                    branch: StakeUnbondTerminalBranchV1::Complete,
                    terminal_record_bytes: terminal_bytes,
                    removed_live_bytes: 100,
                    replacement_live_bytes: 100,
                    wire_bytes: 640,
                    height: 101,
                    signature_checks: 1,
                    state_reads: 9,
                    state_writes: 8,
                    cpu_units: 0,
                    proof_verification_units: 0,
                },
            )
            .unwrap();
        assert_eq!(
            consumed.terminal_record_digest,
            reservation["terminal_record_digest"]
        );
        assert_eq!(
            consumed.successor_history_root,
            reservation["successor_history_root"]
        );
        assert_eq!(consumed.refundable_bond_delta, Amount::ZERO);
    }
}
