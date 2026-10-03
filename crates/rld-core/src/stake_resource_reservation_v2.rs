//! Closed, accounting-only candidate for a safe unbond reservation primitive.
//!
//! This module is deliberately private.  It has no `Ledger` or command route,
//! and therefore cannot make candidate wire tags 26/27 reachable.  Its purpose
//! is narrower: replace every caller-reported byte/work/height input of the
//! rejected V1 prototype with canonical records, a sealed ledger context,
//! internally-derived resource use, replayable indices and externally
//! authenticated recovery.

// The whole module is intentionally unreachable from production code until a
// later Ledger integration closes the remaining runtime P0s. Keeping it
// compiled (and tested) without exporting an entry point is the safety claim.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    crypto::hash_bytes, stake_state_resource_policy_commitment_v1, Amount,
    StakeResourceAccountingError, StakeStateResourcePolicyV1, ZERO_SHA256,
};

const VERSION: u16 = 2;
const WORK_CATALOG_VERSION: u16 = 1;
const BINARY_MAGIC: &[u8; 8] = b"RLDURSV2";
const BINARY_CODEC_VERSION: u16 = 1;
const BINARY_HASH_ALGORITHM_SHA256: u8 = 1;
const BINARY_SCHEMA_LABEL: &[u8] = b"RLD-UNBOND-RESERVATION-STATE-BINARY-SCHEMA-V1";
const BINARY_STATE_DOMAIN: &[u8] = b"RLD-UNBOND-RESERVATION-STATE-BINARY-V1";
const BINARY_HEADER_BYTES: usize = 56;
const BINARY_TRAILER_BYTES: usize = 32;
const MAX_OWNER_UTF8_BYTES: usize = 256;
const MAX_ID_ASCII_BYTES: usize = 128;
const MAX_TERMINAL_ID_ASCII_BYTES: usize = 256;
const MAX_RESOURCE_KEY_ASCII_BYTES: usize = 7 + MAX_ID_ASCII_BYTES;
const MAX_RETAINED_REQUESTS: usize = 4_096;
const MAX_HISTORY_EVENTS: usize = MAX_RETAINED_REQUESTS * 2;
const MAX_CANONICAL_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;

const RESERVE_SIGNATURE_CHECKS: u64 = 2;
const RESERVE_STATE_READS: u64 = 9;
const RESERVE_STATE_WRITES: u64 = 10;
const COMPLETE_SIGNATURE_CHECKS: u64 = 1;
const COMPLETE_STATE_READS: u64 = 9;
const COMPLETE_STATE_WRITES: u64 = 8;
const SLASH_SIGNATURE_CHECKS: u64 = 2;
const SLASH_STATE_READS: u64 = 11;
const SLASH_STATE_WRITES: u64 = 10;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReservationLimitsV2 {
    maximum_pending: u32,
    maximum_pending_per_owner: u32,
    maximum_total_bytes: u64,
    maximum_bytes_per_block: u32,
    maximum_signature_checks_per_block: u32,
    maximum_state_reads_per_block: u32,
    maximum_state_writes_per_block: u32,
}

impl From<&StakeStateResourcePolicyV1> for ReservationLimitsV2 {
    fn from(policy: &StakeStateResourcePolicyV1) -> Self {
        Self {
            maximum_pending: policy.maximum_pending_unbonds,
            maximum_pending_per_owner: policy.maximum_pending_unbonds_per_owner,
            maximum_total_bytes: policy.maximum_total_stake_state_bytes,
            maximum_bytes_per_block: policy.maximum_stake_state_bytes_per_block,
            maximum_signature_checks_per_block: policy.maximum_stake_signature_checks_per_block,
            maximum_state_reads_per_block: policy.maximum_stake_state_reads_per_block,
            maximum_state_writes_per_block: policy.maximum_stake_state_writes_per_block,
        }
    }
}

/// The only source of height and policy for a V2 transition.  The fields and
/// constructor are private; eventual construction belongs inside a staged
/// `Ledger` transaction, which is intentionally not implemented in this
/// accounting-only candidate.
struct LedgerReservationContextV2<'a> {
    height: u64,
    policy: &'a StakeStateResourcePolicyV1,
    policy_commitment: String,
}

impl<'a> LedgerReservationContextV2<'a> {
    fn from_staged_ledger_for_candidate_tests(
        height: u64,
        policy: &'a StakeStateResourcePolicyV1,
    ) -> Result<Self, StakeResourceAccountingError> {
        validate_reservation_policy(policy)?;
        Ok(Self {
            height,
            policy,
            policy_commitment: stake_state_resource_policy_commitment_v1(policy)?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LedgerPendingFactV2 {
    request_id: String,
    resource_key: String,
    owner: String,
    position_id: String,
    escrow_coin_id: String,
    unbond_bond_record_hash: String,
    amount: Amount,
    requested_height: u64,
    withdraw_after_height: u64,
    pending_record_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum LedgerTerminalFactV2 {
    Complete {
        request_id: String,
        expected_pending_record_hash: String,
        terminal_id: String,
        payout_coin_id: String,
        terminal_record_digest: String,
    },
    FullySlashed {
        request_id: String,
        expected_pending_record_hash: String,
        terminal_id: String,
        slash_evidence_commitment: String,
        terminal_record_digest: String,
    },
}

impl LedgerTerminalFactV2 {
    fn request_id(&self) -> &str {
        match self {
            Self::Complete { request_id, .. } | Self::FullySlashed { request_id, .. } => request_id,
        }
    }

    fn expected_pending_record_hash(&self) -> &str {
        match self {
            Self::Complete {
                expected_pending_record_hash,
                ..
            }
            | Self::FullySlashed {
                expected_pending_record_hash,
                ..
            } => expected_pending_record_hash,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CanonicalUnbondBondV2 {
    version: u16,
    request_id: String,
    resource_key: String,
    owner: String,
    position_id: String,
    escrow_coin_id: String,
    unbond_bond_record_hash: String,
    locked_amount: Amount,
    created_height: u64,
    withdraw_after_height: u64,
    record_hash: String,
}

impl CanonicalUnbondBondV2 {
    fn compute_hash(&self) -> String {
        digest(
            b"RLD-UNBOND-CANONICAL-BOND-V2",
            &[
                &self.version.to_be_bytes(),
                self.request_id.as_bytes(),
                self.resource_key.as_bytes(),
                self.owner.as_bytes(),
                self.position_id.as_bytes(),
                self.escrow_coin_id.as_bytes(),
                self.unbond_bond_record_hash.as_bytes(),
                &self.locked_amount.0.to_be_bytes(),
                &self.created_height.to_be_bytes(),
                &self.withdraw_after_height.to_be_bytes(),
            ],
        )
    }

    fn logical_len(&self) -> Result<u64, StakeResourceAccountingError> {
        framed_sum(&[
            &self.version.to_be_bytes(),
            self.request_id.as_bytes(),
            self.resource_key.as_bytes(),
            self.owner.as_bytes(),
            self.position_id.as_bytes(),
            self.escrow_coin_id.as_bytes(),
            self.unbond_bond_record_hash.as_bytes(),
            &self.locked_amount.0.to_be_bytes(),
            &self.created_height.to_be_bytes(),
            &self.withdraw_after_height.to_be_bytes(),
            self.record_hash.as_bytes(),
        ])
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CanonicalPendingV2 {
    version: u16,
    request_id: String,
    resource_key: String,
    owner: String,
    position_id: String,
    escrow_coin_id: String,
    unbond_bond_record_hash: String,
    amount: Amount,
    requested_height: u64,
    withdraw_after_height: u64,
    pending_record_digest: String,
    record_hash: String,
}

impl CanonicalPendingV2 {
    fn compute_hash(&self) -> String {
        digest(
            b"RLD-UNBOND-CANONICAL-PENDING-V2",
            &[
                &self.version.to_be_bytes(),
                self.request_id.as_bytes(),
                self.resource_key.as_bytes(),
                self.owner.as_bytes(),
                self.position_id.as_bytes(),
                self.escrow_coin_id.as_bytes(),
                self.unbond_bond_record_hash.as_bytes(),
                &self.amount.0.to_be_bytes(),
                &self.requested_height.to_be_bytes(),
                &self.withdraw_after_height.to_be_bytes(),
                self.pending_record_digest.as_bytes(),
            ],
        )
    }

    fn logical_len(&self) -> Result<u64, StakeResourceAccountingError> {
        framed_sum(&[
            &self.version.to_be_bytes(),
            self.request_id.as_bytes(),
            self.resource_key.as_bytes(),
            self.owner.as_bytes(),
            self.position_id.as_bytes(),
            self.escrow_coin_id.as_bytes(),
            self.unbond_bond_record_hash.as_bytes(),
            &self.amount.0.to_be_bytes(),
            &self.requested_height.to_be_bytes(),
            &self.withdraw_after_height.to_be_bytes(),
            self.pending_record_digest.as_bytes(),
            self.record_hash.as_bytes(),
        ])
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum TerminalBranchV2 {
    Complete,
    FullySlashed,
}

impl TerminalBranchV2 {
    fn wire_name(self) -> &'static str {
        match self {
            Self::Complete => "COMPLETE",
            Self::FullySlashed => "FULLY_SLASHED",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CanonicalTerminalV2 {
    version: u16,
    request_id: String,
    resource_key: String,
    owner: String,
    position_id: String,
    escrow_coin_id: String,
    unbond_bond_record_hash: String,
    amount: Amount,
    branch: TerminalBranchV2,
    terminal_id: String,
    terminal_height: u64,
    pending_record_hash: String,
    pending_record_digest: String,
    terminal_record_digest: String,
    payout_coin_id: Option<String>,
    slash_evidence_commitment: Option<String>,
    record_hash: String,
}

impl CanonicalTerminalV2 {
    fn compute_hash(&self) -> String {
        digest(
            b"RLD-UNBOND-CANONICAL-TERMINAL-V2",
            &[
                &self.version.to_be_bytes(),
                self.request_id.as_bytes(),
                self.resource_key.as_bytes(),
                self.owner.as_bytes(),
                self.position_id.as_bytes(),
                self.escrow_coin_id.as_bytes(),
                self.unbond_bond_record_hash.as_bytes(),
                &self.amount.0.to_be_bytes(),
                self.branch.wire_name().as_bytes(),
                self.terminal_id.as_bytes(),
                &self.terminal_height.to_be_bytes(),
                self.pending_record_hash.as_bytes(),
                self.pending_record_digest.as_bytes(),
                self.terminal_record_digest.as_bytes(),
                self.payout_coin_id.as_deref().unwrap_or("").as_bytes(),
                self.slash_evidence_commitment
                    .as_deref()
                    .unwrap_or("")
                    .as_bytes(),
            ],
        )
    }

    fn logical_len(&self) -> Result<u64, StakeResourceAccountingError> {
        framed_sum(&[
            &self.version.to_be_bytes(),
            self.request_id.as_bytes(),
            self.resource_key.as_bytes(),
            self.owner.as_bytes(),
            self.position_id.as_bytes(),
            self.escrow_coin_id.as_bytes(),
            self.unbond_bond_record_hash.as_bytes(),
            &self.amount.0.to_be_bytes(),
            self.branch.wire_name().as_bytes(),
            self.terminal_id.as_bytes(),
            &self.terminal_height.to_be_bytes(),
            self.pending_record_hash.as_bytes(),
            self.pending_record_digest.as_bytes(),
            self.terminal_record_digest.as_bytes(),
            self.payout_coin_id.as_deref().unwrap_or("").as_bytes(),
            self.slash_evidence_commitment
                .as_deref()
                .unwrap_or("")
                .as_bytes(),
            self.record_hash.as_bytes(),
        ])
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum HistoryEventKindV2 {
    Reserve,
    Complete,
    FullySlashed,
}

impl HistoryEventKindV2 {
    fn wire_name(self) -> &'static str {
        match self {
            Self::Reserve => "RESERVE",
            Self::Complete => "COMPLETE",
            Self::FullySlashed => "FULLY_SLASHED",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReservationHistoryEventV2 {
    sequence: u64,
    height: u64,
    request_id: String,
    kind: HistoryEventKindV2,
    object_record_hash: String,
    predecessor_root: String,
    event_root: String,
}

impl ReservationHistoryEventV2 {
    fn compute_root(&self) -> String {
        digest(
            b"RLD-UNBOND-RESERVATION-EVENT-V2",
            &[
                &self.sequence.to_be_bytes(),
                &self.height.to_be_bytes(),
                self.request_id.as_bytes(),
                self.kind.wire_name().as_bytes(),
                self.object_record_hash.as_bytes(),
                self.predecessor_root.as_bytes(),
            ],
        )
    }

    fn logical_len(&self) -> Result<u64, StakeResourceAccountingError> {
        framed_sum(&[
            &self.sequence.to_be_bytes(),
            &self.height.to_be_bytes(),
            self.request_id.as_bytes(),
            self.kind.wire_name().as_bytes(),
            self.object_record_hash.as_bytes(),
            self.predecessor_root.as_bytes(),
            self.event_root.as_bytes(),
        ])
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RequestResourceAccountV2 {
    request_id: String,
    live_bytes: u64,
    history_bytes: u64,
    reserved_bytes: u64,
}

impl RequestResourceAccountV2 {
    fn commitment(&self) -> String {
        digest(
            b"RLD-UNBOND-REQUEST-ACCOUNT-V2",
            &[
                self.request_id.as_bytes(),
                &self.live_bytes.to_be_bytes(),
                &self.history_bytes.to_be_bytes(),
                &self.reserved_bytes.to_be_bytes(),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReservationBlockMeterV2 {
    height: u64,
    accounted_bytes: u64,
    signature_checks: u64,
    state_reads: u64,
    state_writes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct UnbondReservationStateV2 {
    version: u16,
    work_catalog_version: u16,
    work_catalog_commitment: String,
    policy_sequence: u64,
    policy_commitment: String,
    limits: ReservationLimitsV2,
    last_applied_height: u64,
    materialized_live_bytes: u64,
    materialized_history_bytes: u64,
    reserved_bytes: u64,
    history_root: String,
    bonds_by_request: BTreeMap<String, CanonicalUnbondBondV2>,
    pending_by_request: BTreeMap<String, CanonicalPendingV2>,
    terminal_by_request: BTreeMap<String, CanonicalTerminalV2>,
    accounts_by_request: BTreeMap<String, RequestResourceAccountV2>,
    request_by_bond_hash: BTreeMap<String, String>,
    request_by_resource_key: BTreeMap<String, String>,
    request_by_position_id: BTreeMap<String, String>,
    request_by_escrow_coin_id: BTreeMap<String, String>,
    request_by_terminal_id: BTreeMap<String, String>,
    pending_count_by_owner: BTreeMap<String, u32>,
    history_events: Vec<ReservationHistoryEventV2>,
    block_meter: ReservationBlockMeterV2,
    state_commitment: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TerminalOutcomeV2 {
    terminal_record_hash: String,
    refundable_bond_delta: Amount,
}

impl UnbondReservationStateV2 {
    fn new(ctx: &LedgerReservationContextV2<'_>) -> Result<Self, StakeResourceAccountingError> {
        let mut state = Self {
            version: VERSION,
            work_catalog_version: WORK_CATALOG_VERSION,
            work_catalog_commitment: work_catalog_commitment(),
            policy_sequence: ctx.policy.sequence,
            policy_commitment: ctx.policy_commitment.clone(),
            limits: ReservationLimitsV2::from(ctx.policy),
            last_applied_height: ctx.height,
            materialized_live_bytes: 0,
            materialized_history_bytes: 0,
            reserved_bytes: 0,
            history_root: ZERO_SHA256.into(),
            bonds_by_request: BTreeMap::new(),
            pending_by_request: BTreeMap::new(),
            terminal_by_request: BTreeMap::new(),
            accounts_by_request: BTreeMap::new(),
            request_by_bond_hash: BTreeMap::new(),
            request_by_resource_key: BTreeMap::new(),
            request_by_position_id: BTreeMap::new(),
            request_by_escrow_coin_id: BTreeMap::new(),
            request_by_terminal_id: BTreeMap::new(),
            pending_count_by_owner: BTreeMap::new(),
            history_events: Vec::new(),
            block_meter: ReservationBlockMeterV2 {
                height: ctx.height,
                accounted_bytes: 0,
                signature_checks: 0,
                state_reads: 0,
                state_writes: 0,
            },
            state_commitment: String::new(),
        };
        state.state_commitment = state.compute_commitment()?;
        state.validate()?;
        Ok(state)
    }

    fn ensure_context(
        &self,
        ctx: &LedgerReservationContextV2<'_>,
    ) -> Result<(), StakeResourceAccountingError> {
        if ctx.height < self.last_applied_height {
            return Err(StakeResourceAccountingError::InvalidRequest(
                "trusted ledger height moved backwards".into(),
            ));
        }
        if ctx.policy.sequence != self.policy_sequence
            || ctx.policy_commitment != self.policy_commitment
            || ReservationLimitsV2::from(ctx.policy) != self.limits
        {
            return Err(StakeResourceAccountingError::InvalidRequest(
                "trusted ledger policy does not match reservation state".into(),
            ));
        }
        Ok(())
    }

    fn reserve(
        &mut self,
        ctx: &LedgerReservationContextV2<'_>,
        fact: LedgerPendingFactV2,
    ) -> Result<CanonicalPendingV2, StakeResourceAccountingError> {
        self.validate()?;
        self.ensure_context(ctx)?;
        validate_pending_fact(ctx, &fact)?;
        if self.bonds_by_request.len() >= MAX_RETAINED_REQUESTS
            || self.history_events.len() >= MAX_HISTORY_EVENTS
        {
            return Err(StakeResourceAccountingError::HardLimit(
                "reservation record or history hard cap".into(),
            ));
        }
        if self.bonds_by_request.contains_key(&fact.request_id)
            || self
                .request_by_bond_hash
                .contains_key(&fact.unbond_bond_record_hash)
            || self
                .request_by_resource_key
                .contains_key(&fact.resource_key)
            || self.request_by_position_id.contains_key(&fact.position_id)
            || self
                .request_by_escrow_coin_id
                .contains_key(&fact.escrow_coin_id)
        {
            return Err(StakeResourceAccountingError::Duplicate(
                "request, bond, resource, position or escrow already reserved".into(),
            ));
        }
        if self.pending_by_request.len()
            >= usize::try_from(self.limits.maximum_pending).unwrap_or(usize::MAX)
            || self
                .pending_count_by_owner
                .get(&fact.owner)
                .copied()
                .unwrap_or(0)
                >= self.limits.maximum_pending_per_owner
        {
            return Err(StakeResourceAccountingError::HardLimit(
                "pending reservation policy cap".into(),
            ));
        }

        let mut bond = CanonicalUnbondBondV2 {
            version: VERSION,
            request_id: fact.request_id.clone(),
            resource_key: fact.resource_key.clone(),
            owner: fact.owner.clone(),
            position_id: fact.position_id.clone(),
            escrow_coin_id: fact.escrow_coin_id.clone(),
            unbond_bond_record_hash: fact.unbond_bond_record_hash.clone(),
            locked_amount: fact.amount,
            created_height: fact.requested_height,
            withdraw_after_height: fact.withdraw_after_height,
            record_hash: String::new(),
        };
        bond.record_hash = bond.compute_hash();
        let mut pending = CanonicalPendingV2 {
            version: VERSION,
            request_id: fact.request_id.clone(),
            resource_key: fact.resource_key.clone(),
            owner: fact.owner.clone(),
            position_id: fact.position_id.clone(),
            escrow_coin_id: fact.escrow_coin_id.clone(),
            unbond_bond_record_hash: fact.unbond_bond_record_hash.clone(),
            amount: fact.amount,
            requested_height: fact.requested_height,
            withdraw_after_height: fact.withdraw_after_height,
            pending_record_digest: fact.pending_record_digest,
            record_hash: String::new(),
        };
        pending.record_hash = pending.compute_hash();

        let mut staged = self.clone();
        staged
            .bonds_by_request
            .insert(fact.request_id.clone(), bond);
        staged
            .pending_by_request
            .insert(fact.request_id.clone(), pending.clone());
        staged.request_by_bond_hash.insert(
            fact.unbond_bond_record_hash.clone(),
            fact.request_id.clone(),
        );
        staged
            .request_by_resource_key
            .insert(fact.resource_key, fact.request_id.clone());
        staged
            .request_by_position_id
            .insert(fact.position_id, fact.request_id.clone());
        staged
            .request_by_escrow_coin_id
            .insert(fact.escrow_coin_id, fact.request_id.clone());
        *staged.pending_count_by_owner.entry(fact.owner).or_insert(0) += 1;
        staged.append_event(
            ctx.height,
            &fact.request_id,
            HistoryEventKindV2::Reserve,
            &pending.record_hash,
        )?;
        staged.refresh_account_and_totals(&fact.request_id)?;
        let account = &staged.accounts_by_request[&fact.request_id];
        let metered = checked_add3(
            account.live_bytes,
            account.history_bytes,
            account.reserved_bytes,
        )?;
        staged.stage_meter(
            ctx.height,
            metered,
            RESERVE_SIGNATURE_CHECKS,
            RESERVE_STATE_READS,
            RESERVE_STATE_WRITES,
        )?;
        staged.last_applied_height = ctx.height;
        staged.enforce_total_limit()?;
        staged.state_commitment = staged.compute_commitment()?;
        staged.validate()?;
        *self = staged;
        Ok(pending)
    }

    fn consume(
        &mut self,
        ctx: &LedgerReservationContextV2<'_>,
        fact: LedgerTerminalFactV2,
    ) -> Result<TerminalOutcomeV2, StakeResourceAccountingError> {
        self.validate()?;
        self.ensure_context(ctx)?;
        if self.history_events.len() >= MAX_HISTORY_EVENTS {
            return Err(StakeResourceAccountingError::HardLimit(
                "reservation history hard cap".into(),
            ));
        }
        let request_id = fact.request_id().to_owned();
        validate_id(&request_id, MAX_ID_ASCII_BYTES, "terminal request id")?;
        let pending = self.pending_by_request.get(&request_id).ok_or_else(|| {
            StakeResourceAccountingError::InvalidRequest(
                "terminal request is missing, already complete or already slashed".into(),
            )
        })?;
        if fact.expected_pending_record_hash() != pending.record_hash {
            return Err(StakeResourceAccountingError::InvalidRequest(
                "terminal is rebound to a different pending record".into(),
            ));
        }
        let bond = self.bonds_by_request.get(&request_id).ok_or_else(|| {
            StakeResourceAccountingError::InvalidState("pending reservation has no bond".into())
        })?;

        let mut terminal = match fact {
            LedgerTerminalFactV2::Complete {
                terminal_id,
                payout_coin_id,
                terminal_record_digest,
                ..
            } => {
                validate_id(&terminal_id, MAX_TERMINAL_ID_ASCII_BYTES, "completion id")?;
                validate_id(&payout_coin_id, MAX_ID_ASCII_BYTES, "payout Coin id")?;
                validate_hash(&terminal_record_digest, "completion record digest")?;
                if ctx.height < pending.withdraw_after_height {
                    return Err(StakeResourceAccountingError::InvalidRequest(
                        "completion precedes withdraw-after height".into(),
                    ));
                }
                CanonicalTerminalV2 {
                    version: VERSION,
                    request_id: request_id.clone(),
                    resource_key: bond.resource_key.clone(),
                    owner: bond.owner.clone(),
                    position_id: bond.position_id.clone(),
                    escrow_coin_id: bond.escrow_coin_id.clone(),
                    unbond_bond_record_hash: bond.unbond_bond_record_hash.clone(),
                    amount: bond.locked_amount,
                    branch: TerminalBranchV2::Complete,
                    terminal_id,
                    terminal_height: ctx.height,
                    pending_record_hash: pending.record_hash.clone(),
                    pending_record_digest: pending.pending_record_digest.clone(),
                    terminal_record_digest,
                    payout_coin_id: Some(payout_coin_id),
                    slash_evidence_commitment: None,
                    record_hash: String::new(),
                }
            }
            LedgerTerminalFactV2::FullySlashed {
                terminal_id,
                slash_evidence_commitment,
                terminal_record_digest,
                ..
            } => {
                validate_id(&terminal_id, MAX_TERMINAL_ID_ASCII_BYTES, "slash id")?;
                validate_hash(&slash_evidence_commitment, "slash evidence commitment")?;
                validate_hash(&terminal_record_digest, "slash record digest")?;
                CanonicalTerminalV2 {
                    version: VERSION,
                    request_id: request_id.clone(),
                    resource_key: bond.resource_key.clone(),
                    owner: bond.owner.clone(),
                    position_id: bond.position_id.clone(),
                    escrow_coin_id: bond.escrow_coin_id.clone(),
                    unbond_bond_record_hash: bond.unbond_bond_record_hash.clone(),
                    amount: bond.locked_amount,
                    branch: TerminalBranchV2::FullySlashed,
                    terminal_id,
                    terminal_height: ctx.height,
                    pending_record_hash: pending.record_hash.clone(),
                    pending_record_digest: pending.pending_record_digest.clone(),
                    terminal_record_digest,
                    payout_coin_id: None,
                    slash_evidence_commitment: Some(slash_evidence_commitment),
                    record_hash: String::new(),
                }
            }
        };
        if self
            .request_by_terminal_id
            .contains_key(&terminal.terminal_id)
        {
            return Err(StakeResourceAccountingError::Duplicate(
                "terminal id already consumed".into(),
            ));
        }
        terminal.record_hash = terminal.compute_hash();
        let old_account = self.accounts_by_request[&request_id].clone();

        let mut staged = self.clone();
        staged.pending_by_request.remove(&request_id);
        staged
            .terminal_by_request
            .insert(request_id.clone(), terminal.clone());
        staged
            .request_by_terminal_id
            .insert(terminal.terminal_id.clone(), request_id.clone());
        let owner_count = staged
            .pending_count_by_owner
            .get_mut(&bond.owner)
            .ok_or_else(|| {
                StakeResourceAccountingError::InvalidState("pending owner count disappeared".into())
            })?;
        *owner_count = owner_count.checked_sub(1).ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic("pending owner count".into())
        })?;
        if *owner_count == 0 {
            staged.pending_count_by_owner.remove(&bond.owner);
        }
        let kind = match terminal.branch {
            TerminalBranchV2::Complete => HistoryEventKindV2::Complete,
            TerminalBranchV2::FullySlashed => HistoryEventKindV2::FullySlashed,
        };
        let event_len =
            staged.append_event(ctx.height, &request_id, kind, &terminal.record_hash)?;
        staged.refresh_account_and_totals(&request_id)?;
        let new_account = &staged.accounts_by_request[&request_id];
        let old_available = checked_add3(
            old_account.live_bytes,
            old_account.history_bytes,
            old_account.reserved_bytes,
        )?;
        let new_materialized = new_account
            .live_bytes
            .checked_add(new_account.history_bytes)
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("terminal account".into()))?;
        if new_materialized > old_available {
            return Err(StakeResourceAccountingError::HardLimit(
                "typed terminal exceeds its internally-derived reservation".into(),
            ));
        }
        let terminal_index_len = index_len(&terminal.terminal_id, &request_id)?;
        let metered = terminal
            .logical_len()?
            .checked_add(terminal_index_len)
            .and_then(|value| value.checked_add(event_len))
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("terminal meter".into()))?;
        let (signatures, reads, writes) = match terminal.branch {
            TerminalBranchV2::Complete => (
                COMPLETE_SIGNATURE_CHECKS,
                COMPLETE_STATE_READS,
                COMPLETE_STATE_WRITES,
            ),
            TerminalBranchV2::FullySlashed => (
                SLASH_SIGNATURE_CHECKS,
                SLASH_STATE_READS,
                SLASH_STATE_WRITES,
            ),
        };
        staged.stage_meter(ctx.height, metered, signatures, reads, writes)?;
        staged.last_applied_height = ctx.height;
        staged.enforce_total_limit()?;
        staged.state_commitment = staged.compute_commitment()?;
        staged.validate()?;
        *self = staged;
        Ok(TerminalOutcomeV2 {
            terminal_record_hash: terminal.record_hash,
            refundable_bond_delta: Amount::ZERO,
        })
    }

    fn append_event(
        &mut self,
        height: u64,
        request_id: &str,
        kind: HistoryEventKindV2,
        object_record_hash: &str,
    ) -> Result<u64, StakeResourceAccountingError> {
        let sequence = u64::try_from(self.history_events.len())
            .map_err(|_| StakeResourceAccountingError::Arithmetic("history sequence".into()))?
            .checked_add(1)
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("history sequence".into()))?;
        let mut event = ReservationHistoryEventV2 {
            sequence,
            height,
            request_id: request_id.into(),
            kind,
            object_record_hash: object_record_hash.into(),
            predecessor_root: self.history_root.clone(),
            event_root: String::new(),
        };
        event.event_root = event.compute_root();
        let length = event
            .logical_len()?
            .checked_add(8)
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("history map entry".into()))?;
        self.history_root = event.event_root.clone();
        self.history_events.push(event);
        Ok(length)
    }

    fn refresh_account_and_totals(
        &mut self,
        request_id: &str,
    ) -> Result<(), StakeResourceAccountingError> {
        let account = self.derive_account(request_id)?;
        self.accounts_by_request.insert(request_id.into(), account);
        let mut live = 0u64;
        let mut history = 0u64;
        let mut reserved = 0u64;
        for account in self.accounts_by_request.values() {
            live = live.checked_add(account.live_bytes).ok_or_else(|| {
                StakeResourceAccountingError::Arithmetic("global live bytes".into())
            })?;
            history = history.checked_add(account.history_bytes).ok_or_else(|| {
                StakeResourceAccountingError::Arithmetic("global history bytes".into())
            })?;
            reserved = reserved
                .checked_add(account.reserved_bytes)
                .ok_or_else(|| {
                    StakeResourceAccountingError::Arithmetic("global reserved bytes".into())
                })?;
        }
        self.materialized_live_bytes = live;
        self.materialized_history_bytes = history;
        self.reserved_bytes = reserved;
        Ok(())
    }

    fn derive_account(
        &self,
        request_id: &str,
    ) -> Result<RequestResourceAccountV2, StakeResourceAccountingError> {
        let bond = self.bonds_by_request.get(request_id).ok_or_else(|| {
            StakeResourceAccountingError::InvalidState("request account has no bond".into())
        })?;
        let mut live = map_record_len(request_id, bond.logical_len()?)?;
        live = live
            .checked_add(index_len(&bond.unbond_bond_record_hash, request_id)?)
            .and_then(|value| value.checked_add(index_len(&bond.resource_key, request_id).ok()?))
            .and_then(|value| value.checked_add(index_len(&bond.position_id, request_id).ok()?))
            .and_then(|value| value.checked_add(index_len(&bond.escrow_coin_id, request_id).ok()?))
            .and_then(|value| value.checked_add(account_record_len(request_id).ok()?))
            .ok_or_else(|| {
                StakeResourceAccountingError::Arithmetic("request live indices".into())
            })?;
        if let Some(pending) = self.pending_by_request.get(request_id) {
            live = live
                .checked_add(map_record_len(request_id, pending.logical_len()?)?)
                .and_then(|value| value.checked_add(owner_count_len(&pending.owner).ok()?))
                .ok_or_else(|| {
                    StakeResourceAccountingError::Arithmetic("pending live bytes".into())
                })?;
        } else if let Some(terminal) = self.terminal_by_request.get(request_id) {
            live = live
                .checked_add(map_record_len(request_id, terminal.logical_len()?)?)
                .and_then(|value| {
                    value.checked_add(index_len(&terminal.terminal_id, request_id).ok()?)
                })
                .ok_or_else(|| {
                    StakeResourceAccountingError::Arithmetic("terminal live bytes".into())
                })?;
        } else {
            return Err(StakeResourceAccountingError::InvalidState(
                "request is neither pending nor terminal".into(),
            ));
        }
        let history = self
            .history_events
            .iter()
            .filter(|event| event.request_id == request_id)
            .try_fold(0u64, |total, event| {
                total
                    .checked_add(event.logical_len()?)
                    .and_then(|value| value.checked_add(8))
                    .ok_or_else(|| {
                        StakeResourceAccountingError::Arithmetic("request history bytes".into())
                    })
            })?;
        let reserved = if let Some(pending) = self.pending_by_request.get(request_id) {
            let terminal_live = maximum_terminal_live_bytes(bond, pending, request_id)?;
            let terminal_event = maximum_terminal_event_len(request_id)?;
            terminal_live
                .checked_add(history)
                .and_then(|value| value.checked_add(terminal_event))
                .and_then(|future| future.checked_sub(live.checked_add(history)?))
                .ok_or_else(|| {
                    StakeResourceAccountingError::Arithmetic("terminal reservation capacity".into())
                })?
        } else {
            0
        };
        Ok(RequestResourceAccountV2 {
            request_id: request_id.into(),
            live_bytes: live,
            history_bytes: history,
            reserved_bytes: reserved,
        })
    }

    fn stage_meter(
        &mut self,
        height: u64,
        bytes: u64,
        signatures: u64,
        reads: u64,
        writes: u64,
    ) -> Result<(), StakeResourceAccountingError> {
        if height < self.block_meter.height {
            return Err(StakeResourceAccountingError::InvalidRequest(
                "trusted meter height moved backwards".into(),
            ));
        }
        if height > self.block_meter.height {
            self.block_meter = ReservationBlockMeterV2 {
                height,
                accounted_bytes: 0,
                signature_checks: 0,
                state_reads: 0,
                state_writes: 0,
            };
        }
        self.block_meter.accounted_bytes = self
            .block_meter
            .accounted_bytes
            .checked_add(bytes)
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("block bytes".into()))?;
        self.block_meter.signature_checks = self
            .block_meter
            .signature_checks
            .checked_add(signatures)
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("block signatures".into()))?;
        self.block_meter.state_reads = self
            .block_meter
            .state_reads
            .checked_add(reads)
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("block reads".into()))?;
        self.block_meter.state_writes = self
            .block_meter
            .state_writes
            .checked_add(writes)
            .ok_or_else(|| StakeResourceAccountingError::Arithmetic("block writes".into()))?;
        if self.block_meter.accounted_bytes > u64::from(self.limits.maximum_bytes_per_block)
            || self.block_meter.signature_checks
                > u64::from(self.limits.maximum_signature_checks_per_block)
            || self.block_meter.state_reads > u64::from(self.limits.maximum_state_reads_per_block)
            || self.block_meter.state_writes > u64::from(self.limits.maximum_state_writes_per_block)
        {
            return Err(StakeResourceAccountingError::HardLimit(
                "internally-derived reservation work exceeds the block meter".into(),
            ));
        }
        Ok(())
    }

    fn enforce_total_limit(&self) -> Result<(), StakeResourceAccountingError> {
        if checked_add3(
            self.materialized_live_bytes,
            self.materialized_history_bytes,
            self.reserved_bytes,
        )? > self.limits.maximum_total_bytes
        {
            return Err(StakeResourceAccountingError::HardLimit(
                "materialized plus reserved request responsibility".into(),
            ));
        }
        Ok(())
    }

    fn canonical_binary_body(&self) -> Result<Vec<u8>, StakeResourceAccountingError> {
        let mut out = BinaryWriter::default();
        out.u16(self.work_catalog_version);
        out.hash(&self.work_catalog_commitment)?;
        out.u64(self.policy_sequence);
        out.hash(&self.policy_commitment)?;
        out.u32(self.limits.maximum_pending);
        out.u32(self.limits.maximum_pending_per_owner);
        out.u64(self.limits.maximum_total_bytes);
        out.u32(self.limits.maximum_bytes_per_block);
        out.u32(self.limits.maximum_signature_checks_per_block);
        out.u32(self.limits.maximum_state_reads_per_block);
        out.u32(self.limits.maximum_state_writes_per_block);
        out.u64(self.last_applied_height);
        out.u64(self.materialized_live_bytes);
        out.u64(self.materialized_history_bytes);
        out.u64(self.reserved_bytes);
        out.hash(&self.history_root)?;
        out.u64(self.block_meter.height);
        out.u64(self.block_meter.accounted_bytes);
        out.u64(self.block_meter.signature_checks);
        out.u64(self.block_meter.state_reads);
        out.u64(self.block_meter.state_writes);

        out.count(self.bonds_by_request.len())?;
        for (request_id, bond) in &self.bonds_by_request {
            out.text(request_id)?;
            encode_bond(&mut out, bond)?;
        }
        out.count(self.pending_by_request.len())?;
        for (request_id, pending) in &self.pending_by_request {
            out.text(request_id)?;
            encode_pending(&mut out, pending)?;
        }
        out.count(self.terminal_by_request.len())?;
        for (request_id, terminal) in &self.terminal_by_request {
            out.text(request_id)?;
            encode_terminal(&mut out, terminal)?;
        }
        out.count(self.history_events.len())?;
        for event in &self.history_events {
            encode_history_event(&mut out, event)?;
        }
        Ok(out.finish())
    }

    fn canonical_binary_header_and_body(&self) -> Result<Vec<u8>, StakeResourceAccountingError> {
        let body = self.canonical_binary_body()?;
        let total = BINARY_HEADER_BYTES
            .checked_add(body.len())
            .and_then(|value| value.checked_add(BINARY_TRAILER_BYTES))
            .ok_or_else(|| {
                StakeResourceAccountingError::Arithmetic("binary snapshot size".into())
            })?;
        if total > MAX_CANONICAL_SNAPSHOT_BYTES {
            return Err(StakeResourceAccountingError::HardLimit(
                "reservation binary snapshot exceeds hard byte cap".into(),
            ));
        }
        let mut out = BinaryWriter::default();
        out.raw(BINARY_MAGIC);
        out.u16(BINARY_CODEC_VERSION);
        out.u16(VERSION);
        out.u8(BINARY_HASH_ALGORITHM_SHA256);
        out.u8(0);
        out.u16(0);
        out.hash(&hash_bytes(BINARY_SCHEMA_LABEL))?;
        out.u64(
            u64::try_from(body.len()).map_err(|_| {
                StakeResourceAccountingError::Arithmetic("binary body length".into())
            })?,
        );
        out.raw(&body);
        Ok(out.finish())
    }

    fn canonical_binary_bytes(&self) -> Result<Vec<u8>, StakeResourceAccountingError> {
        self.validate()?;
        let mut bytes = self.canonical_binary_header_and_body()?;
        let embedded = decode_hash(&self.state_commitment, "embedded state commitment")?;
        bytes.extend_from_slice(&embedded);
        Ok(bytes)
    }

    fn restore_canonical_binary(
        bytes: &[u8],
        expected_external_commitment: &str,
        expected_policy: &StakeStateResourcePolicyV1,
    ) -> Result<Self, StakeResourceAccountingError> {
        if bytes.len() > MAX_CANONICAL_SNAPSHOT_BYTES
            || bytes.len() < BINARY_HEADER_BYTES + BINARY_TRAILER_BYTES
        {
            return Err(StakeResourceAccountingError::Recovery(
                "reservation binary snapshot length is outside the hard bounds".into(),
            ));
        }
        let expected = decode_hash(
            expected_external_commitment,
            "external reservation commitment",
        )?;
        validate_reservation_policy(expected_policy)?;
        let expected_policy_commitment =
            stake_state_resource_policy_commitment_v1(expected_policy)?;
        let mut header = BinaryReader::new(bytes);
        if header.take(BINARY_MAGIC.len())? != BINARY_MAGIC
            || header.u16()? != BINARY_CODEC_VERSION
            || header.u16()? != VERSION
            || header.u8()? != BINARY_HASH_ALGORITHM_SHA256
            || header.u8()? != 0
            || header.u16()? != 0
            || header.hash_bytes()? != decode_hash(&hash_bytes(BINARY_SCHEMA_LABEL), "schema id")?
        {
            return Err(StakeResourceAccountingError::Recovery(
                "reservation binary header is unknown or non-canonical".into(),
            ));
        }
        let body_len = usize::try_from(header.u64()?).map_err(|_| {
            StakeResourceAccountingError::Recovery("reservation binary body length overflow".into())
        })?;
        let expected_len = BINARY_HEADER_BYTES
            .checked_add(body_len)
            .and_then(|value| value.checked_add(BINARY_TRAILER_BYTES))
            .ok_or_else(|| {
                StakeResourceAccountingError::Recovery(
                    "reservation binary total length overflow".into(),
                )
            })?;
        if expected_len != bytes.len() {
            return Err(StakeResourceAccountingError::Recovery(
                "reservation binary body length or trailing bytes mismatch".into(),
            ));
        }
        let body_end = BINARY_HEADER_BYTES + body_len;
        let computed = binary_state_commitment(&bytes[..body_end])?;
        let embedded: [u8; 32] = bytes[body_end..].try_into().map_err(|_| {
            StakeResourceAccountingError::Recovery("binary commitment length".into())
        })?;
        if !constant_time_eq(&computed, &embedded) || !constant_time_eq(&computed, &expected) {
            return Err(StakeResourceAccountingError::Recovery(
                "reservation binary commitment is not externally authenticated".into(),
            ));
        }

        let mut input = BinaryReader::new(&bytes[BINARY_HEADER_BYTES..body_end]);
        let work_catalog_version = input.u16()?;
        let work_catalog_commitment = input.hash()?;
        let policy_sequence = input.u64()?;
        let policy_commitment = input.hash()?;
        let limits = ReservationLimitsV2 {
            maximum_pending: input.u32()?,
            maximum_pending_per_owner: input.u32()?,
            maximum_total_bytes: input.u64()?,
            maximum_bytes_per_block: input.u32()?,
            maximum_signature_checks_per_block: input.u32()?,
            maximum_state_reads_per_block: input.u32()?,
            maximum_state_writes_per_block: input.u32()?,
        };
        let last_applied_height = input.u64()?;
        let materialized_live_bytes = input.u64()?;
        let materialized_history_bytes = input.u64()?;
        let reserved_bytes = input.u64()?;
        let history_root = input.hash()?;
        let block_meter = ReservationBlockMeterV2 {
            height: input.u64()?,
            accounted_bytes: input.u64()?,
            signature_checks: input.u64()?,
            state_reads: input.u64()?,
            state_writes: input.u64()?,
        };
        if policy_sequence != expected_policy.sequence
            || policy_commitment != expected_policy_commitment
            || limits != ReservationLimitsV2::from(expected_policy)
        {
            return Err(StakeResourceAccountingError::Recovery(
                "reservation binary policy is not the trusted ledger policy".into(),
            ));
        }

        let mut bonds_by_request = BTreeMap::new();
        let bond_count = input.count(MAX_RETAINED_REQUESTS, "bond")?;
        let mut previous = None;
        for _ in 0..bond_count {
            let key = input.sorted_id(&mut previous, MAX_ID_ASCII_BYTES, "bond map key")?;
            let record = decode_bond(&mut input)?;
            if key != record.request_id || bonds_by_request.insert(key, record).is_some() {
                return Err(StakeResourceAccountingError::Recovery(
                    "bond map key is duplicated or differs from its record".into(),
                ));
            }
        }
        let mut pending_by_request = BTreeMap::new();
        let pending_cap = MAX_RETAINED_REQUESTS
            .min(usize::try_from(limits.maximum_pending).unwrap_or(usize::MAX));
        let pending_count = input.count(pending_cap, "pending")?;
        let mut previous = None;
        for _ in 0..pending_count {
            let key = input.sorted_id(&mut previous, MAX_ID_ASCII_BYTES, "pending map key")?;
            let record = decode_pending(&mut input)?;
            if key != record.request_id || pending_by_request.insert(key, record).is_some() {
                return Err(StakeResourceAccountingError::Recovery(
                    "pending map key is duplicated or differs from its record".into(),
                ));
            }
        }
        let mut terminal_by_request = BTreeMap::new();
        let terminal_count = input.count(MAX_RETAINED_REQUESTS, "terminal")?;
        let mut previous = None;
        for _ in 0..terminal_count {
            let key = input.sorted_id(&mut previous, MAX_ID_ASCII_BYTES, "terminal map key")?;
            let record = decode_terminal(&mut input)?;
            if key != record.request_id || terminal_by_request.insert(key, record).is_some() {
                return Err(StakeResourceAccountingError::Recovery(
                    "terminal map key is duplicated or differs from its record".into(),
                ));
            }
        }
        let event_count = input.count(MAX_HISTORY_EVENTS, "history")?;
        let mut history_events = Vec::with_capacity(event_count);
        for _ in 0..event_count {
            history_events.push(decode_history_event(&mut input)?);
        }
        if !input.is_finished() {
            return Err(StakeResourceAccountingError::Recovery(
                "reservation binary body has trailing bytes".into(),
            ));
        }

        let mut state = Self {
            version: VERSION,
            work_catalog_version,
            work_catalog_commitment,
            policy_sequence,
            policy_commitment,
            limits,
            last_applied_height,
            materialized_live_bytes,
            materialized_history_bytes,
            reserved_bytes,
            history_root,
            bonds_by_request,
            pending_by_request,
            terminal_by_request,
            accounts_by_request: BTreeMap::new(),
            request_by_bond_hash: BTreeMap::new(),
            request_by_resource_key: BTreeMap::new(),
            request_by_position_id: BTreeMap::new(),
            request_by_escrow_coin_id: BTreeMap::new(),
            request_by_terminal_id: BTreeMap::new(),
            pending_count_by_owner: BTreeMap::new(),
            history_events,
            block_meter,
            state_commitment: hex::encode(embedded),
        };
        state.rebuild_derived_caches()?;
        state.validate()?;
        if state.canonical_binary_bytes()? != bytes {
            return Err(StakeResourceAccountingError::Recovery(
                "reservation binary snapshot is not its canonical re-encoding".into(),
            ));
        }
        Ok(state)
    }

    fn rebuild_derived_caches(&mut self) -> Result<(), StakeResourceAccountingError> {
        for (request_id, bond) in &self.bonds_by_request {
            insert_unique(
                &mut self.request_by_bond_hash,
                &bond.unbond_bond_record_hash,
                request_id,
            )?;
            insert_unique(
                &mut self.request_by_resource_key,
                &bond.resource_key,
                request_id,
            )?;
            insert_unique(
                &mut self.request_by_position_id,
                &bond.position_id,
                request_id,
            )?;
            insert_unique(
                &mut self.request_by_escrow_coin_id,
                &bond.escrow_coin_id,
                request_id,
            )?;
        }
        for pending in self.pending_by_request.values() {
            let count = self
                .pending_count_by_owner
                .entry(pending.owner.clone())
                .or_insert(0);
            *count = count.checked_add(1).ok_or_else(|| {
                StakeResourceAccountingError::Arithmetic("decoded owner count".into())
            })?;
        }
        for (request_id, terminal) in &self.terminal_by_request {
            insert_unique(
                &mut self.request_by_terminal_id,
                &terminal.terminal_id,
                request_id,
            )?;
        }
        for request_id in self.bonds_by_request.keys() {
            self.accounts_by_request
                .insert(request_id.clone(), self.derive_account(request_id)?);
        }
        Ok(())
    }

    #[cfg(test)]
    fn canonical_json_bytes(&self) -> Result<Vec<u8>, StakeResourceAccountingError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| StakeResourceAccountingError::Recovery(error.to_string()))?;
        if bytes.len() > MAX_CANONICAL_SNAPSHOT_BYTES {
            return Err(StakeResourceAccountingError::HardLimit(
                "reservation snapshot exceeds hard byte cap".into(),
            ));
        }
        Ok(bytes)
    }

    #[cfg(test)]
    fn restore_canonical_json(
        bytes: &[u8],
        expected_external_commitment: &str,
    ) -> Result<Self, StakeResourceAccountingError> {
        if bytes.len() > MAX_CANONICAL_SNAPSHOT_BYTES {
            return Err(StakeResourceAccountingError::Recovery(
                "reservation snapshot exceeds hard byte cap".into(),
            ));
        }
        validate_hash(
            expected_external_commitment,
            "external reservation commitment",
        )?;
        let state: Self = serde_json::from_slice(bytes)
            .map_err(|error| StakeResourceAccountingError::Recovery(error.to_string()))?;
        let canonical = serde_json::to_vec(&state)
            .map_err(|error| StakeResourceAccountingError::Recovery(error.to_string()))?;
        if canonical != bytes {
            return Err(StakeResourceAccountingError::Recovery(
                "reservation snapshot is not canonical JSON".into(),
            ));
        }
        state.validate()?;
        if state.state_commitment != expected_external_commitment {
            return Err(StakeResourceAccountingError::Recovery(
                "reservation snapshot does not match the externally authenticated commitment"
                    .into(),
            ));
        }
        Ok(state)
    }

    fn validate(&self) -> Result<(), StakeResourceAccountingError> {
        if self.version != VERSION
            || self.work_catalog_version != WORK_CATALOG_VERSION
            || self.work_catalog_commitment != work_catalog_commitment()
            || !is_hash(&self.policy_commitment)
            || self.bonds_by_request.len() > MAX_RETAINED_REQUESTS
            || self.history_events.len() > MAX_HISTORY_EVENTS
        {
            return Err(StakeResourceAccountingError::InvalidState(
                "reservation version, catalog, policy or hard cap mismatch".into(),
            ));
        }
        if self.pending_by_request.len()
            > usize::try_from(self.limits.maximum_pending).unwrap_or(usize::MAX)
        {
            return Err(StakeResourceAccountingError::InvalidState(
                "pending reservation total exceeds policy".into(),
            ));
        }

        let mut bond_index = BTreeMap::new();
        let mut resource_index = BTreeMap::new();
        let mut position_index = BTreeMap::new();
        let mut escrow_index = BTreeMap::new();
        for (request_id, bond) in &self.bonds_by_request {
            validate_bond(request_id, bond)?;
            insert_unique(&mut bond_index, &bond.unbond_bond_record_hash, request_id)?;
            insert_unique(&mut resource_index, &bond.resource_key, request_id)?;
            insert_unique(&mut position_index, &bond.position_id, request_id)?;
            insert_unique(&mut escrow_index, &bond.escrow_coin_id, request_id)?;
        }

        let mut owner_count = BTreeMap::new();
        for (request_id, pending) in &self.pending_by_request {
            let bond = self.bonds_by_request.get(request_id).ok_or_else(|| {
                StakeResourceAccountingError::InvalidState("pending has no canonical bond".into())
            })?;
            validate_pending(request_id, pending, bond)?;
            if self.terminal_by_request.contains_key(request_id) {
                return Err(StakeResourceAccountingError::InvalidState(
                    "request is both pending and terminal".into(),
                ));
            }
            let next = owner_count
                .get(&pending.owner)
                .copied()
                .unwrap_or(0u32)
                .checked_add(1)
                .ok_or_else(|| StakeResourceAccountingError::Arithmetic("owner count".into()))?;
            if next > self.limits.maximum_pending_per_owner {
                return Err(StakeResourceAccountingError::InvalidState(
                    "pending owner count exceeds policy".into(),
                ));
            }
            owner_count.insert(pending.owner.clone(), next);
        }

        let mut terminal_index = BTreeMap::new();
        for (request_id, terminal) in &self.terminal_by_request {
            let bond = self.bonds_by_request.get(request_id).ok_or_else(|| {
                StakeResourceAccountingError::InvalidState("terminal has no canonical bond".into())
            })?;
            validate_terminal(request_id, terminal, bond)?;
            if self.pending_by_request.contains_key(request_id) {
                return Err(StakeResourceAccountingError::InvalidState(
                    "request is both terminal and pending".into(),
                ));
            }
            insert_unique(&mut terminal_index, &terminal.terminal_id, request_id)?;
        }
        if self.bonds_by_request.len()
            != self.pending_by_request.len() + self.terminal_by_request.len()
            || self.request_by_bond_hash != bond_index
            || self.request_by_resource_key != resource_index
            || self.request_by_position_id != position_index
            || self.request_by_escrow_coin_id != escrow_index
            || self.request_by_terminal_id != terminal_index
            || self.pending_count_by_owner != owner_count
        {
            return Err(StakeResourceAccountingError::InvalidState(
                "reservation reverse index or pending/terminal partition mismatch".into(),
            ));
        }

        let mut root = ZERO_SHA256.to_owned();
        let mut seen_reserve = BTreeSet::new();
        let mut seen_terminal = BTreeSet::new();
        let mut previous_height = 0u64;
        for (index, event) in self.history_events.iter().enumerate() {
            if event.sequence != u64::try_from(index).unwrap_or(u64::MAX) + 1
                || event.predecessor_root != root
                || event.event_root != event.compute_root()
                || event.height < previous_height
                || event.height > self.last_applied_height
                || !self.bonds_by_request.contains_key(&event.request_id)
            {
                return Err(StakeResourceAccountingError::InvalidState(
                    "reservation history chain is malformed".into(),
                ));
            }
            match event.kind {
                HistoryEventKindV2::Reserve => {
                    if !seen_reserve.insert(event.request_id.clone())
                        || seen_terminal.contains(&event.request_id)
                    {
                        return Err(StakeResourceAccountingError::InvalidState(
                            "reservation history repeats or reorders reserve".into(),
                        ));
                    }
                    let expected = self
                        .pending_by_request
                        .get(&event.request_id)
                        .map(|record| record.record_hash.as_str())
                        .or_else(|| {
                            self.terminal_by_request
                                .get(&event.request_id)
                                .map(|record| record.pending_record_hash.as_str())
                        });
                    if expected != Some(event.object_record_hash.as_str()) {
                        return Err(StakeResourceAccountingError::InvalidState(
                            "reserve event is not bound to the canonical pending record".into(),
                        ));
                    }
                    if self.bonds_by_request[&event.request_id].created_height != event.height {
                        return Err(StakeResourceAccountingError::InvalidState(
                            "reserve event height differs from its canonical bond".into(),
                        ));
                    }
                }
                HistoryEventKindV2::Complete | HistoryEventKindV2::FullySlashed => {
                    if !seen_reserve.contains(&event.request_id)
                        || !seen_terminal.insert(event.request_id.clone())
                    {
                        return Err(StakeResourceAccountingError::InvalidState(
                            "terminal event has no unique reserve predecessor".into(),
                        ));
                    }
                    let terminal =
                        self.terminal_by_request
                            .get(&event.request_id)
                            .ok_or_else(|| {
                                StakeResourceAccountingError::InvalidState(
                                    "terminal event has no terminal record".into(),
                                )
                            })?;
                    let kind_matches = matches!(
                        (event.kind, terminal.branch),
                        (HistoryEventKindV2::Complete, TerminalBranchV2::Complete)
                            | (
                                HistoryEventKindV2::FullySlashed,
                                TerminalBranchV2::FullySlashed
                            )
                    );
                    if !kind_matches || event.object_record_hash != terminal.record_hash {
                        return Err(StakeResourceAccountingError::InvalidState(
                            "terminal event branch or record binding mismatch".into(),
                        ));
                    }
                    if terminal.terminal_height != event.height {
                        return Err(StakeResourceAccountingError::InvalidState(
                            "terminal event height differs from its typed record".into(),
                        ));
                    }
                }
            }
            previous_height = event.height;
            root = event.event_root.clone();
        }
        if root != self.history_root
            || seen_reserve.len() != self.bonds_by_request.len()
            || seen_terminal.len() != self.terminal_by_request.len()
        {
            return Err(StakeResourceAccountingError::InvalidState(
                "reservation history coverage or root mismatch".into(),
            ));
        }

        let mut derived_accounts = BTreeMap::new();
        let mut live = 0u64;
        let mut history = 0u64;
        let mut reserved = 0u64;
        for request_id in self.bonds_by_request.keys() {
            let account = self.derive_account(request_id)?;
            live = live.checked_add(account.live_bytes).ok_or_else(|| {
                StakeResourceAccountingError::Arithmetic("validated live bytes".into())
            })?;
            history = history.checked_add(account.history_bytes).ok_or_else(|| {
                StakeResourceAccountingError::Arithmetic("validated history bytes".into())
            })?;
            reserved = reserved
                .checked_add(account.reserved_bytes)
                .ok_or_else(|| {
                    StakeResourceAccountingError::Arithmetic("validated reserved bytes".into())
                })?;
            derived_accounts.insert(request_id.clone(), account);
        }
        if derived_accounts != self.accounts_by_request
            || live != self.materialized_live_bytes
            || history != self.materialized_history_bytes
            || reserved != self.reserved_bytes
            || self.block_meter.height != self.last_applied_height
            || self.block_meter.accounted_bytes > u64::from(self.limits.maximum_bytes_per_block)
            || self.block_meter.signature_checks
                > u64::from(self.limits.maximum_signature_checks_per_block)
            || self.block_meter.state_reads > u64::from(self.limits.maximum_state_reads_per_block)
            || self.block_meter.state_writes > u64::from(self.limits.maximum_state_writes_per_block)
        {
            return Err(StakeResourceAccountingError::InvalidState(
                "per-request or global resource account mismatch".into(),
            ));
        }
        self.enforce_total_limit()?;
        if self.state_commitment != self.compute_commitment()? {
            return Err(StakeResourceAccountingError::InvalidState(
                "reservation state commitment mismatch".into(),
            ));
        }
        Ok(())
    }

    fn compute_commitment(&self) -> Result<String, StakeResourceAccountingError> {
        Ok(hex::encode(binary_state_commitment(
            &self.canonical_binary_header_and_body()?,
        )?))
    }
}

#[derive(Default)]
struct BinaryWriter {
    bytes: Vec<u8>,
}

impl BinaryWriter {
    fn raw(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.raw(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.raw(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.raw(&value.to_be_bytes());
    }

    fn u128(&mut self, value: u128) {
        self.raw(&value.to_be_bytes());
    }

    fn count(&mut self, value: usize) -> Result<(), StakeResourceAccountingError> {
        self.u32(u32::try_from(value).map_err(|_| {
            StakeResourceAccountingError::Arithmetic("binary collection count".into())
        })?);
        Ok(())
    }

    fn text(&mut self, value: &str) -> Result<(), StakeResourceAccountingError> {
        self.u16(
            u16::try_from(value.len()).map_err(|_| {
                StakeResourceAccountingError::Arithmetic("binary text length".into())
            })?,
        );
        self.raw(value.as_bytes());
        Ok(())
    }

    fn hash(&mut self, value: &str) -> Result<(), StakeResourceAccountingError> {
        self.raw(&decode_hash(value, "binary hash field")?);
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

struct BinaryReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BinaryReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], StakeResourceAccountingError> {
        let end = self.offset.checked_add(length).ok_or_else(|| {
            StakeResourceAccountingError::Recovery("binary cursor overflow".into())
        })?;
        let value = self.bytes.get(self.offset..end).ok_or_else(|| {
            StakeResourceAccountingError::Recovery("truncated reservation binary".into())
        })?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, StakeResourceAccountingError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, StakeResourceAccountingError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(
            |_| StakeResourceAccountingError::Recovery("binary u16 width".into()),
        )?))
    }

    fn u32(&mut self) -> Result<u32, StakeResourceAccountingError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(
            |_| StakeResourceAccountingError::Recovery("binary u32 width".into()),
        )?))
    }

    fn u64(&mut self) -> Result<u64, StakeResourceAccountingError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(
            |_| StakeResourceAccountingError::Recovery("binary u64 width".into()),
        )?))
    }

    fn u128(&mut self) -> Result<u128, StakeResourceAccountingError> {
        Ok(u128::from_be_bytes(self.take(16)?.try_into().map_err(
            |_| StakeResourceAccountingError::Recovery("binary u128 width".into()),
        )?))
    }

    fn hash_bytes(&mut self) -> Result<[u8; 32], StakeResourceAccountingError> {
        self.take(32)?
            .try_into()
            .map_err(|_| StakeResourceAccountingError::Recovery("binary hash width".into()))
    }

    fn hash(&mut self) -> Result<String, StakeResourceAccountingError> {
        Ok(hex::encode(self.hash_bytes()?))
    }

    fn text(&mut self, maximum: usize) -> Result<String, StakeResourceAccountingError> {
        let length = usize::from(self.u16()?);
        if length == 0 || length > maximum {
            return Err(StakeResourceAccountingError::Recovery(
                "binary text length is outside its canonical bounds".into(),
            ));
        }
        let bytes = self.take(length)?;
        let text = std::str::from_utf8(bytes).map_err(|_| {
            StakeResourceAccountingError::Recovery("binary text is not UTF-8".into())
        })?;
        Ok(text.to_owned())
    }

    fn id(&mut self, maximum: usize, label: &str) -> Result<String, StakeResourceAccountingError> {
        let value = self.text(maximum)?;
        validate_id(&value, maximum, label)
            .map_err(|error| StakeResourceAccountingError::Recovery(error.to_string()))?;
        Ok(value)
    }

    fn owner(&mut self) -> Result<String, StakeResourceAccountingError> {
        let value = self.text(MAX_OWNER_UTF8_BYTES)?;
        validate_owner(&value)
            .map_err(|error| StakeResourceAccountingError::Recovery(error.to_string()))?;
        Ok(value)
    }

    fn resource_key(&mut self) -> Result<String, StakeResourceAccountingError> {
        let value = self.text(MAX_RESOURCE_KEY_ASCII_BYTES)?;
        if !value.is_ascii() {
            return Err(StakeResourceAccountingError::Recovery(
                "binary resource key is not ASCII".into(),
            ));
        }
        Ok(value)
    }

    fn count(
        &mut self,
        maximum: usize,
        label: &str,
    ) -> Result<usize, StakeResourceAccountingError> {
        let value = usize::try_from(self.u32()?).map_err(|_| {
            StakeResourceAccountingError::Recovery(format!("{label} count overflow"))
        })?;
        if value > maximum {
            return Err(StakeResourceAccountingError::Recovery(format!(
                "{label} count exceeds its pre-allocation hard cap"
            )));
        }
        Ok(value)
    }

    fn sorted_id(
        &mut self,
        previous: &mut Option<Vec<u8>>,
        maximum: usize,
        label: &str,
    ) -> Result<String, StakeResourceAccountingError> {
        let value = self.id(maximum, label)?;
        if previous
            .as_deref()
            .is_some_and(|prior| prior >= value.as_bytes())
        {
            return Err(StakeResourceAccountingError::Recovery(format!(
                "{label} is duplicated or not strictly byte-sorted"
            )));
        }
        *previous = Some(value.as_bytes().to_vec());
        Ok(value)
    }

    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn decode_hash(value: &str, label: &str) -> Result<[u8; 32], StakeResourceAccountingError> {
    validate_hash(value, label)?;
    hex::decode(value)
        .map_err(|_| StakeResourceAccountingError::Recovery(format!("{label} is not hex")))?
        .try_into()
        .map_err(|_| StakeResourceAccountingError::Recovery(format!("{label} has wrong width")))
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn binary_state_commitment(
    header_and_body: &[u8],
) -> Result<[u8; 32], StakeResourceAccountingError> {
    let mut preimage = BinaryWriter::default();
    preimage.u16(u16::try_from(BINARY_STATE_DOMAIN.len()).map_err(|_| {
        StakeResourceAccountingError::Arithmetic("binary state domain length".into())
    })?);
    preimage.raw(BINARY_STATE_DOMAIN);
    preimage.raw(header_and_body);
    decode_hash(&hash_bytes(&preimage.finish()), "binary state commitment")
}

fn encode_bond(
    out: &mut BinaryWriter,
    bond: &CanonicalUnbondBondV2,
) -> Result<(), StakeResourceAccountingError> {
    out.u16(bond.version);
    out.text(&bond.request_id)?;
    out.text(&bond.resource_key)?;
    out.text(&bond.owner)?;
    out.text(&bond.position_id)?;
    out.text(&bond.escrow_coin_id)?;
    out.hash(&bond.unbond_bond_record_hash)?;
    out.u128(bond.locked_amount.0);
    out.u64(bond.created_height);
    out.u64(bond.withdraw_after_height);
    out.hash(&bond.record_hash)?;
    Ok(())
}

fn decode_bond(
    input: &mut BinaryReader<'_>,
) -> Result<CanonicalUnbondBondV2, StakeResourceAccountingError> {
    Ok(CanonicalUnbondBondV2 {
        version: input.u16()?,
        request_id: input.id(MAX_ID_ASCII_BYTES, "bond request id")?,
        resource_key: input.resource_key()?,
        owner: input.owner()?,
        position_id: input.id(MAX_ID_ASCII_BYTES, "bond position id")?,
        escrow_coin_id: input.id(MAX_ID_ASCII_BYTES, "bond escrow id")?,
        unbond_bond_record_hash: input.hash()?,
        locked_amount: Amount(input.u128()?),
        created_height: input.u64()?,
        withdraw_after_height: input.u64()?,
        record_hash: input.hash()?,
    })
}

fn encode_pending(
    out: &mut BinaryWriter,
    pending: &CanonicalPendingV2,
) -> Result<(), StakeResourceAccountingError> {
    out.u16(pending.version);
    out.text(&pending.request_id)?;
    out.text(&pending.resource_key)?;
    out.text(&pending.owner)?;
    out.text(&pending.position_id)?;
    out.text(&pending.escrow_coin_id)?;
    out.hash(&pending.unbond_bond_record_hash)?;
    out.u128(pending.amount.0);
    out.u64(pending.requested_height);
    out.u64(pending.withdraw_after_height);
    out.hash(&pending.pending_record_digest)?;
    out.hash(&pending.record_hash)?;
    Ok(())
}

fn decode_pending(
    input: &mut BinaryReader<'_>,
) -> Result<CanonicalPendingV2, StakeResourceAccountingError> {
    Ok(CanonicalPendingV2 {
        version: input.u16()?,
        request_id: input.id(MAX_ID_ASCII_BYTES, "pending request id")?,
        resource_key: input.resource_key()?,
        owner: input.owner()?,
        position_id: input.id(MAX_ID_ASCII_BYTES, "pending position id")?,
        escrow_coin_id: input.id(MAX_ID_ASCII_BYTES, "pending escrow id")?,
        unbond_bond_record_hash: input.hash()?,
        amount: Amount(input.u128()?),
        requested_height: input.u64()?,
        withdraw_after_height: input.u64()?,
        pending_record_digest: input.hash()?,
        record_hash: input.hash()?,
    })
}

fn encode_option_text(
    out: &mut BinaryWriter,
    value: Option<&str>,
) -> Result<(), StakeResourceAccountingError> {
    match value {
        None => out.u8(0),
        Some(value) => {
            out.u8(1);
            out.text(value)?;
        }
    }
    Ok(())
}

fn decode_option_id(
    input: &mut BinaryReader<'_>,
) -> Result<Option<String>, StakeResourceAccountingError> {
    match input.u8()? {
        0 => Ok(None),
        1 => Ok(Some(input.id(MAX_ID_ASCII_BYTES, "optional payout id")?)),
        _ => Err(StakeResourceAccountingError::Recovery(
            "unknown binary option tag".into(),
        )),
    }
}

fn encode_option_hash(
    out: &mut BinaryWriter,
    value: Option<&str>,
) -> Result<(), StakeResourceAccountingError> {
    match value {
        None => out.u8(0),
        Some(value) => {
            out.u8(1);
            out.hash(value)?;
        }
    }
    Ok(())
}

fn decode_option_hash(
    input: &mut BinaryReader<'_>,
) -> Result<Option<String>, StakeResourceAccountingError> {
    match input.u8()? {
        0 => Ok(None),
        1 => Ok(Some(input.hash()?)),
        _ => Err(StakeResourceAccountingError::Recovery(
            "unknown binary option tag".into(),
        )),
    }
}

fn encode_terminal(
    out: &mut BinaryWriter,
    terminal: &CanonicalTerminalV2,
) -> Result<(), StakeResourceAccountingError> {
    out.u16(terminal.version);
    out.text(&terminal.request_id)?;
    out.text(&terminal.resource_key)?;
    out.text(&terminal.owner)?;
    out.text(&terminal.position_id)?;
    out.text(&terminal.escrow_coin_id)?;
    out.hash(&terminal.unbond_bond_record_hash)?;
    out.u128(terminal.amount.0);
    out.u8(match terminal.branch {
        TerminalBranchV2::Complete => 0,
        TerminalBranchV2::FullySlashed => 1,
    });
    out.text(&terminal.terminal_id)?;
    out.u64(terminal.terminal_height);
    out.hash(&terminal.pending_record_hash)?;
    out.hash(&terminal.pending_record_digest)?;
    out.hash(&terminal.terminal_record_digest)?;
    encode_option_text(out, terminal.payout_coin_id.as_deref())?;
    encode_option_hash(out, terminal.slash_evidence_commitment.as_deref())?;
    out.hash(&terminal.record_hash)?;
    Ok(())
}

fn decode_terminal(
    input: &mut BinaryReader<'_>,
) -> Result<CanonicalTerminalV2, StakeResourceAccountingError> {
    let version = input.u16()?;
    let request_id = input.id(MAX_ID_ASCII_BYTES, "terminal request id")?;
    let resource_key = input.resource_key()?;
    let owner = input.owner()?;
    let position_id = input.id(MAX_ID_ASCII_BYTES, "terminal position id")?;
    let escrow_coin_id = input.id(MAX_ID_ASCII_BYTES, "terminal escrow id")?;
    let unbond_bond_record_hash = input.hash()?;
    let amount = Amount(input.u128()?);
    let branch = match input.u8()? {
        0 => TerminalBranchV2::Complete,
        1 => TerminalBranchV2::FullySlashed,
        _ => {
            return Err(StakeResourceAccountingError::Recovery(
                "unknown binary terminal branch".into(),
            ))
        }
    };
    let terminal_id = input.id(MAX_TERMINAL_ID_ASCII_BYTES, "terminal id")?;
    let terminal_height = input.u64()?;
    let pending_record_hash = input.hash()?;
    let pending_record_digest = input.hash()?;
    let terminal_record_digest = input.hash()?;
    let payout_coin_id = decode_option_id(input)?;
    let slash_evidence_commitment = decode_option_hash(input)?;
    let record_hash = input.hash()?;
    if !matches!(
        (branch, &payout_coin_id, &slash_evidence_commitment),
        (TerminalBranchV2::Complete, Some(_), None)
            | (TerminalBranchV2::FullySlashed, None, Some(_))
    ) {
        return Err(StakeResourceAccountingError::Recovery(
            "binary terminal options do not match its branch".into(),
        ));
    }
    Ok(CanonicalTerminalV2 {
        version,
        request_id,
        resource_key,
        owner,
        position_id,
        escrow_coin_id,
        unbond_bond_record_hash,
        amount,
        branch,
        terminal_id,
        terminal_height,
        pending_record_hash,
        pending_record_digest,
        terminal_record_digest,
        payout_coin_id,
        slash_evidence_commitment,
        record_hash,
    })
}

fn encode_history_event(
    out: &mut BinaryWriter,
    event: &ReservationHistoryEventV2,
) -> Result<(), StakeResourceAccountingError> {
    out.u64(event.sequence);
    out.u64(event.height);
    out.text(&event.request_id)?;
    out.u8(match event.kind {
        HistoryEventKindV2::Reserve => 0,
        HistoryEventKindV2::Complete => 1,
        HistoryEventKindV2::FullySlashed => 2,
    });
    out.hash(&event.object_record_hash)?;
    out.hash(&event.predecessor_root)?;
    out.hash(&event.event_root)?;
    Ok(())
}

fn decode_history_event(
    input: &mut BinaryReader<'_>,
) -> Result<ReservationHistoryEventV2, StakeResourceAccountingError> {
    Ok(ReservationHistoryEventV2 {
        sequence: input.u64()?,
        height: input.u64()?,
        request_id: input.id(MAX_ID_ASCII_BYTES, "history request id")?,
        kind: match input.u8()? {
            0 => HistoryEventKindV2::Reserve,
            1 => HistoryEventKindV2::Complete,
            2 => HistoryEventKindV2::FullySlashed,
            _ => {
                return Err(StakeResourceAccountingError::Recovery(
                    "unknown binary history kind".into(),
                ))
            }
        },
        object_record_hash: input.hash()?,
        predecessor_root: input.hash()?,
        event_root: input.hash()?,
    })
}

fn validate_reservation_policy(
    policy: &StakeStateResourcePolicyV1,
) -> Result<(), StakeResourceAccountingError> {
    if policy.policy_version != 1
        || policy.sequence == 0
        || !is_hash(&policy.previous_policy_commitment)
        || policy.maximum_pending_unbonds == 0
        || policy.maximum_pending_unbonds_per_owner == 0
        || policy.maximum_pending_unbonds_per_owner > policy.maximum_pending_unbonds
        || policy.maximum_total_stake_state_bytes == 0
        || policy.maximum_stake_state_bytes_per_block == 0
        || u64::from(policy.maximum_stake_state_bytes_per_block)
            > policy.maximum_total_stake_state_bytes
        || policy.maximum_stake_signature_checks_per_block == 0
        || policy.maximum_stake_state_reads_per_block == 0
        || policy.maximum_stake_state_writes_per_block == 0
    {
        return Err(StakeResourceAccountingError::InvalidPolicy(
            "reservation policy version, sequence or resource bounds are invalid".into(),
        ));
    }
    Ok(())
}

fn validate_pending_fact(
    ctx: &LedgerReservationContextV2<'_>,
    fact: &LedgerPendingFactV2,
) -> Result<(), StakeResourceAccountingError> {
    validate_id(&fact.request_id, MAX_ID_ASCII_BYTES, "request id")?;
    if fact.resource_key != format!("UNBOND/{}", fact.request_id) {
        return Err(StakeResourceAccountingError::InvalidRequest(
            "resource key is not canonically derived from request id".into(),
        ));
    }
    validate_owner(&fact.owner)?;
    validate_id(&fact.position_id, MAX_ID_ASCII_BYTES, "position id")?;
    validate_id(&fact.escrow_coin_id, MAX_ID_ASCII_BYTES, "escrow Coin id")?;
    validate_hash(&fact.unbond_bond_record_hash, "unbond bond hash")?;
    validate_hash(&fact.pending_record_digest, "pending record digest")?;
    if fact.amount == Amount::ZERO
        || fact.requested_height != ctx.height
        || fact.withdraw_after_height < fact.requested_height
    {
        return Err(StakeResourceAccountingError::InvalidRequest(
            "pending amount or trusted heights are invalid".into(),
        ));
    }
    Ok(())
}

fn validate_bond(
    request_id: &str,
    bond: &CanonicalUnbondBondV2,
) -> Result<(), StakeResourceAccountingError> {
    validate_id(request_id, MAX_ID_ASCII_BYTES, "bond map request id")?;
    validate_owner(&bond.owner)?;
    validate_id(&bond.position_id, MAX_ID_ASCII_BYTES, "bond position id")?;
    validate_id(&bond.escrow_coin_id, MAX_ID_ASCII_BYTES, "bond escrow id")?;
    validate_hash(&bond.unbond_bond_record_hash, "bond hash")?;
    if bond.version != VERSION
        || bond.request_id != request_id
        || bond.resource_key != format!("UNBOND/{request_id}")
        || bond.locked_amount == Amount::ZERO
        || bond.withdraw_after_height < bond.created_height
        || bond.record_hash != bond.compute_hash()
    {
        return Err(StakeResourceAccountingError::InvalidState(
            "canonical unbond bond is malformed".into(),
        ));
    }
    Ok(())
}

fn validate_pending(
    request_id: &str,
    pending: &CanonicalPendingV2,
    bond: &CanonicalUnbondBondV2,
) -> Result<(), StakeResourceAccountingError> {
    validate_hash(&pending.pending_record_digest, "pending digest")?;
    if pending.version != VERSION
        || pending.request_id != request_id
        || pending.resource_key != bond.resource_key
        || pending.owner != bond.owner
        || pending.position_id != bond.position_id
        || pending.escrow_coin_id != bond.escrow_coin_id
        || pending.unbond_bond_record_hash != bond.unbond_bond_record_hash
        || pending.amount != bond.locked_amount
        || pending.requested_height != bond.created_height
        || pending.withdraw_after_height != bond.withdraw_after_height
        || pending.record_hash != pending.compute_hash()
    {
        return Err(StakeResourceAccountingError::InvalidState(
            "canonical pending record is rebound or malformed".into(),
        ));
    }
    Ok(())
}

fn validate_terminal(
    request_id: &str,
    terminal: &CanonicalTerminalV2,
    bond: &CanonicalUnbondBondV2,
) -> Result<(), StakeResourceAccountingError> {
    validate_id(
        &terminal.terminal_id,
        MAX_TERMINAL_ID_ASCII_BYTES,
        "terminal id",
    )?;
    validate_hash(&terminal.pending_record_hash, "terminal pending hash")?;
    validate_hash(&terminal.pending_record_digest, "terminal pending digest")?;
    validate_hash(&terminal.terminal_record_digest, "terminal record digest")?;
    let branch_fields_valid =
        match terminal.branch {
            TerminalBranchV2::Complete => {
                terminal.payout_coin_id.as_deref().is_some_and(|value| {
                    validate_id(value, MAX_ID_ASCII_BYTES, "payout id").is_ok()
                }) && terminal.slash_evidence_commitment.is_none()
                    && terminal.terminal_height >= bond.withdraw_after_height
            }
            TerminalBranchV2::FullySlashed => {
                terminal.payout_coin_id.is_none()
                    && terminal
                        .slash_evidence_commitment
                        .as_deref()
                        .is_some_and(is_hash)
            }
        };
    let reconstructed_pending = CanonicalPendingV2 {
        version: VERSION,
        request_id: request_id.into(),
        resource_key: bond.resource_key.clone(),
        owner: bond.owner.clone(),
        position_id: bond.position_id.clone(),
        escrow_coin_id: bond.escrow_coin_id.clone(),
        unbond_bond_record_hash: bond.unbond_bond_record_hash.clone(),
        amount: bond.locked_amount,
        requested_height: bond.created_height,
        withdraw_after_height: bond.withdraw_after_height,
        pending_record_digest: terminal.pending_record_digest.clone(),
        record_hash: terminal.pending_record_hash.clone(),
    };
    validate_pending(request_id, &reconstructed_pending, bond)?;
    if terminal.version != VERSION
        || terminal.request_id != request_id
        || terminal.resource_key != bond.resource_key
        || terminal.owner != bond.owner
        || terminal.position_id != bond.position_id
        || terminal.escrow_coin_id != bond.escrow_coin_id
        || terminal.unbond_bond_record_hash != bond.unbond_bond_record_hash
        || terminal.amount != bond.locked_amount
        || terminal.terminal_height < bond.created_height
        || !branch_fields_valid
        || terminal.record_hash != terminal.compute_hash()
    {
        return Err(StakeResourceAccountingError::InvalidState(
            "typed terminal record is rebound or malformed".into(),
        ));
    }
    Ok(())
}

fn maximum_terminal_live_bytes(
    bond: &CanonicalUnbondBondV2,
    pending: &CanonicalPendingV2,
    request_id: &str,
) -> Result<u64, StakeResourceAccountingError> {
    let common = |branch, terminal_id: String, payout, evidence| {
        let mut terminal = CanonicalTerminalV2 {
            version: VERSION,
            request_id: request_id.into(),
            resource_key: bond.resource_key.clone(),
            owner: bond.owner.clone(),
            position_id: bond.position_id.clone(),
            escrow_coin_id: bond.escrow_coin_id.clone(),
            unbond_bond_record_hash: bond.unbond_bond_record_hash.clone(),
            amount: bond.locked_amount,
            branch,
            terminal_id,
            terminal_height: u64::MAX,
            pending_record_hash: pending.record_hash.clone(),
            pending_record_digest: pending.pending_record_digest.clone(),
            terminal_record_digest: "f".repeat(64),
            payout_coin_id: payout,
            slash_evidence_commitment: evidence,
            record_hash: "f".repeat(64),
        };
        terminal.record_hash = terminal.compute_hash();
        terminal
    };
    let complete = common(
        TerminalBranchV2::Complete,
        "x".repeat(MAX_TERMINAL_ID_ASCII_BYTES),
        Some("x".repeat(MAX_ID_ASCII_BYTES)),
        None,
    );
    let slash = common(
        TerminalBranchV2::FullySlashed,
        "x".repeat(MAX_TERMINAL_ID_ASCII_BYTES),
        None,
        Some("f".repeat(64)),
    );
    let base = map_record_len(request_id, bond.logical_len()?)?
        .checked_add(index_len(&bond.unbond_bond_record_hash, request_id)?)
        .and_then(|value| value.checked_add(index_len(&bond.resource_key, request_id).ok()?))
        .and_then(|value| value.checked_add(index_len(&bond.position_id, request_id).ok()?))
        .and_then(|value| value.checked_add(index_len(&bond.escrow_coin_id, request_id).ok()?))
        .and_then(|value| value.checked_add(account_record_len(request_id).ok()?))
        .ok_or_else(|| {
            StakeResourceAccountingError::Arithmetic("terminal base live bytes".into())
        })?;
    [complete, slash]
        .into_iter()
        .try_fold(0u64, |largest, terminal| {
            let total = base
                .checked_add(map_record_len(request_id, terminal.logical_len()?)?)
                .and_then(|value| {
                    value.checked_add(index_len(&terminal.terminal_id, request_id).ok()?)
                })
                .ok_or_else(|| {
                    StakeResourceAccountingError::Arithmetic("maximum terminal live bytes".into())
                })?;
            Ok(largest.max(total))
        })
}

fn maximum_terminal_event_len(request_id: &str) -> Result<u64, StakeResourceAccountingError> {
    let event = ReservationHistoryEventV2 {
        sequence: u64::MAX,
        height: u64::MAX,
        request_id: request_id.into(),
        kind: HistoryEventKindV2::FullySlashed,
        object_record_hash: "f".repeat(64),
        predecessor_root: "f".repeat(64),
        event_root: "f".repeat(64),
    };
    event
        .logical_len()?
        .checked_add(8)
        .ok_or_else(|| StakeResourceAccountingError::Arithmetic("terminal event length".into()))
}

fn validate_owner(owner: &str) -> Result<(), StakeResourceAccountingError> {
    if owner.is_empty()
        || owner.len() > MAX_OWNER_UTF8_BYTES
        || !owner.is_ascii()
        || !owner
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-'))
    {
        return Err(StakeResourceAccountingError::InvalidRequest(
            "owner is not a bounded canonical ASCII ledger identifier".into(),
        ));
    }
    Ok(())
}

fn validate_id(
    value: &str,
    maximum: usize,
    label: &str,
) -> Result<(), StakeResourceAccountingError> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(StakeResourceAccountingError::InvalidRequest(format!(
            "{label} is not canonical bounded ASCII"
        )));
    }
    Ok(())
}

fn validate_hash(value: &str, label: &str) -> Result<(), StakeResourceAccountingError> {
    if !is_hash(value) {
        return Err(StakeResourceAccountingError::InvalidRequest(format!(
            "{label} is not a lowercase SHA-256 digest"
        )));
    }
    Ok(())
}

fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn insert_unique(
    map: &mut BTreeMap<String, String>,
    key: &str,
    request_id: &str,
) -> Result<(), StakeResourceAccountingError> {
    if map.insert(key.into(), request_id.into()).is_some() {
        return Err(StakeResourceAccountingError::InvalidState(
            "canonical reverse index is not one-to-one".into(),
        ));
    }
    Ok(())
}

fn digest(domain: &[u8], fields: &[&[u8]]) -> String {
    let mut bytes = Vec::new();
    append_frame(&mut bytes, domain);
    for field in fields {
        append_frame(&mut bytes, field);
    }
    hash_bytes(&bytes)
}

fn append_frame(output: &mut Vec<u8>, value: &[u8]) {
    let length = u64::try_from(value.len()).expect("bounded canonical field length");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

fn framed_sum(fields: &[&[u8]]) -> Result<u64, StakeResourceAccountingError> {
    fields.iter().try_fold(0u64, |total, field| {
        total
            .checked_add(8)
            .and_then(|value| value.checked_add(u64::try_from(field.len()).ok()?))
            .ok_or_else(|| {
                StakeResourceAccountingError::Arithmetic("canonical field length".into())
            })
    })
}

fn framed_len(value: &str) -> Result<u64, StakeResourceAccountingError> {
    u64::try_from(value.len())
        .ok()
        .and_then(|length| length.checked_add(8))
        .ok_or_else(|| StakeResourceAccountingError::Arithmetic("canonical string frame".into()))
}

fn index_len(key: &str, request_id: &str) -> Result<u64, StakeResourceAccountingError> {
    framed_len(key)?
        .checked_add(framed_len(request_id)?)
        .ok_or_else(|| StakeResourceAccountingError::Arithmetic("canonical index entry".into()))
}

fn map_record_len(request_id: &str, record_len: u64) -> Result<u64, StakeResourceAccountingError> {
    framed_len(request_id)?
        .checked_add(record_len)
        .ok_or_else(|| StakeResourceAccountingError::Arithmetic("canonical record map".into()))
}

fn account_record_len(request_id: &str) -> Result<u64, StakeResourceAccountingError> {
    framed_len(request_id)?
        .checked_add(framed_len(request_id)?)
        .and_then(|value| value.checked_add(24))
        .ok_or_else(|| StakeResourceAccountingError::Arithmetic("request account record".into()))
}

fn owner_count_len(owner: &str) -> Result<u64, StakeResourceAccountingError> {
    framed_len(owner)?
        .checked_add(4)
        .ok_or_else(|| StakeResourceAccountingError::Arithmetic("owner count record".into()))
}

fn checked_add3(a: u64, b: u64, c: u64) -> Result<u64, StakeResourceAccountingError> {
    a.checked_add(b)
        .and_then(|value| value.checked_add(c))
        .ok_or_else(|| StakeResourceAccountingError::Arithmetic("three-part resource total".into()))
}

fn work_catalog_commitment() -> String {
    digest(
        b"RLD-UNBOND-RESERVATION-WORK-CATALOG-V2",
        &[
            &WORK_CATALOG_VERSION.to_be_bytes(),
            &RESERVE_SIGNATURE_CHECKS.to_be_bytes(),
            &RESERVE_STATE_READS.to_be_bytes(),
            &RESERVE_STATE_WRITES.to_be_bytes(),
            &COMPLETE_SIGNATURE_CHECKS.to_be_bytes(),
            &COMPLETE_STATE_READS.to_be_bytes(),
            &COMPLETE_STATE_WRITES.to_be_bytes(),
            &SLASH_SIGNATURE_CHECKS.to_be_bytes(),
            &SLASH_STATE_READS.to_be_bytes(),
            &SLASH_STATE_WRITES.to_be_bytes(),
        ],
    )
}

fn record_table_root<'a, I, V>(domain: &[u8], entries: I) -> String
where
    I: Iterator<Item = (&'a str, V)>,
    V: AsRef<str>,
{
    let entries: Vec<_> = entries.collect();
    let mut bytes = Vec::new();
    append_frame(&mut bytes, domain);
    bytes.extend_from_slice(&(entries.len() as u64).to_be_bytes());
    for (key, value) in entries {
        append_frame(&mut bytes, key.as_bytes());
        append_frame(&mut bytes, value.as_ref().as_bytes());
    }
    hash_bytes(&bytes)
}

fn index_table_root(domain: &[u8], entries: &BTreeMap<String, String>) -> String {
    record_table_root(
        domain,
        entries
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str())),
    )
}

fn owner_table_root(entries: &BTreeMap<String, u32>) -> String {
    let mut bytes = Vec::new();
    append_frame(&mut bytes, b"OWNER_COUNT");
    bytes.extend_from_slice(&(entries.len() as u64).to_be_bytes());
    for (owner, count) in entries {
        append_frame(&mut bytes, owner.as_bytes());
        bytes.extend_from_slice(&count.to_be_bytes());
    }
    hash_bytes(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const H1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const H2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const H3: &str = "3333333333333333333333333333333333333333333333333333333333333333";

    fn reservation_policy_for_v2_tests() -> StakeStateResourcePolicyV1 {
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
            maximum_active_candidates: 16,
            maximum_candidates_per_owner: 4,
            maximum_active_positions: 32,
            maximum_positions_per_owner: 8,
            maximum_pending_unbonds: 16,
            maximum_pending_unbonds_per_owner: 4,
            maximum_slash_record_bytes: 20_000,
            maximum_total_stake_state_bytes: 10_000_000,
            maximum_stake_state_bytes_per_block: 1_000_000,
            maximum_stake_signature_checks_per_block: 1_000,
            maximum_stake_state_reads_per_block: 1_000,
            maximum_stake_state_writes_per_block: 1_000,
        }
    }

    fn fact(request: &str, owner: &str, height: u64) -> LedgerPendingFactV2 {
        LedgerPendingFactV2 {
            request_id: request.into(),
            resource_key: format!("UNBOND/{request}"),
            owner: owner.into(),
            position_id: format!("position-{request}"),
            escrow_coin_id: format!("escrow-{request}"),
            unbond_bond_record_hash: hash_bytes(format!("bond-{request}").as_bytes()),
            amount: Amount(50_000),
            requested_height: height,
            withdraw_after_height: height + 5,
            pending_record_digest: hash_bytes(format!("pending-{request}").as_bytes()),
        }
    }

    fn complete(request: &str, pending_hash: &str) -> LedgerTerminalFactV2 {
        LedgerTerminalFactV2::Complete {
            request_id: request.into(),
            expected_pending_record_hash: pending_hash.into(),
            terminal_id: format!("complete-{request}"),
            payout_coin_id: format!("payout-{request}"),
            terminal_record_digest: H2.into(),
        }
    }

    fn slash(request: &str, pending_hash: &str) -> LedgerTerminalFactV2 {
        LedgerTerminalFactV2::FullySlashed {
            request_id: request.into(),
            expected_pending_record_hash: pending_hash.into(),
            terminal_id: format!("slash-{request}"),
            slash_evidence_commitment: H3.into(),
            terminal_record_digest: H2.into(),
        }
    }

    #[test]
    fn typed_complete_is_single_use_and_zero_refund() {
        let policy = reservation_policy_for_v2_tests();
        let ctx100 =
            LedgerReservationContextV2::from_staged_ledger_for_candidate_tests(100, &policy)
                .unwrap();
        let mut state = UnbondReservationStateV2::new(&ctx100).unwrap();
        let pending = state
            .reserve(&ctx100, fact("request-1", "owner-a", 100))
            .unwrap();
        let history_before = state.materialized_history_bytes;
        let ctx105 =
            LedgerReservationContextV2::from_staged_ledger_for_candidate_tests(105, &policy)
                .unwrap();
        let outcome = state
            .consume(&ctx105, complete("request-1", &pending.record_hash))
            .unwrap();
        assert!(is_hash(&outcome.terminal_record_hash));
        assert_eq!(outcome.refundable_bond_delta, Amount::ZERO);
        assert!(state.materialized_history_bytes > history_before);
        assert_eq!(state.reserved_bytes, 0);
        let committed = state.state_commitment.clone();
        assert!(state
            .consume(&ctx105, slash("request-1", &pending.record_hash))
            .is_err());
        assert_eq!(state.state_commitment, committed);
    }

    #[test]
    fn same_bond_resource_position_and_escrow_are_one_to_one() {
        let mut policy = reservation_policy_for_v2_tests();
        policy.maximum_pending_unbonds_per_owner = 4;
        let ctx = LedgerReservationContextV2::from_staged_ledger_for_candidate_tests(100, &policy)
            .unwrap();
        let mut state = UnbondReservationStateV2::new(&ctx).unwrap();
        let first = fact("request-1", "owner-a", 100);
        state.reserve(&ctx, first.clone()).unwrap();
        for field in 0..4 {
            let mut duplicate = fact(&format!("request-{}", field + 2), "owner-b", 100);
            match field {
                0 => duplicate.unbond_bond_record_hash = first.unbond_bond_record_hash.clone(),
                1 => duplicate.resource_key = first.resource_key.clone(),
                2 => duplicate.position_id = first.position_id.clone(),
                3 => duplicate.escrow_coin_id = first.escrow_coin_id.clone(),
                _ => unreachable!(),
            }
            let before = state.state_commitment.clone();
            assert!(state.reserve(&ctx, duplicate).is_err());
            assert_eq!(state.state_commitment, before);
        }
    }

    #[test]
    fn owner_and_global_pending_caps_fail_closed() {
        let mut policy = reservation_policy_for_v2_tests();
        policy.maximum_pending_unbonds = 2;
        policy.maximum_pending_unbonds_per_owner = 1;
        let ctx = LedgerReservationContextV2::from_staged_ledger_for_candidate_tests(100, &policy)
            .unwrap();
        let mut state = UnbondReservationStateV2::new(&ctx).unwrap();
        state
            .reserve(&ctx, fact("request-1", "owner-a", 100))
            .unwrap();
        assert!(state
            .reserve(&ctx, fact("request-2", "owner-a", 100))
            .is_err());
        state
            .reserve(&ctx, fact("request-2", "owner-b", 100))
            .unwrap();
        assert!(state
            .reserve(&ctx, fact("request-3", "owner-c", 100))
            .is_err());
    }

    #[test]
    fn trusted_height_can_skip_empty_blocks_but_never_roll_back() {
        let mut policy = reservation_policy_for_v2_tests();
        policy.maximum_pending_unbonds_per_owner = 4;
        let ctx100 =
            LedgerReservationContextV2::from_staged_ledger_for_candidate_tests(100, &policy)
                .unwrap();
        let mut state = UnbondReservationStateV2::new(&ctx100).unwrap();
        state
            .reserve(&ctx100, fact("request-1", "owner-a", 100))
            .unwrap();
        let ctx110 =
            LedgerReservationContextV2::from_staged_ledger_for_candidate_tests(110, &policy)
                .unwrap();
        state
            .reserve(&ctx110, fact("request-2", "owner-b", 110))
            .unwrap();
        assert_eq!(state.block_meter.height, 110);
        assert_eq!(state.block_meter.signature_checks, RESERVE_SIGNATURE_CHECKS);
        let ctx109 =
            LedgerReservationContextV2::from_staged_ledger_for_candidate_tests(109, &policy)
                .unwrap();
        let before = state.state_commitment.clone();
        assert!(state
            .reserve(&ctx109, fact("request-3", "owner-c", 109))
            .is_err());
        assert_eq!(state.state_commitment, before);
    }

    #[test]
    fn terminal_rebind_garbage_and_branch_races_are_rejected_atomically() {
        let mut policy = reservation_policy_for_v2_tests();
        policy.maximum_pending_unbonds_per_owner = 4;
        let ctx100 =
            LedgerReservationContextV2::from_staged_ledger_for_candidate_tests(100, &policy)
                .unwrap();
        let mut state = UnbondReservationStateV2::new(&ctx100).unwrap();
        let a = state
            .reserve(&ctx100, fact("request-a", "owner-a", 100))
            .unwrap();
        let b = state
            .reserve(&ctx100, fact("request-b", "owner-b", 100))
            .unwrap();
        let ctx105 =
            LedgerReservationContextV2::from_staged_ledger_for_candidate_tests(105, &policy)
                .unwrap();
        let before = state.state_commitment.clone();
        assert!(state
            .consume(&ctx105, complete("request-a", &b.record_hash))
            .is_err());
        assert_eq!(state.state_commitment, before);
        let mut garbage = complete("request-a", &a.record_hash);
        if let LedgerTerminalFactV2::Complete {
            terminal_record_digest,
            ..
        } = &mut garbage
        {
            *terminal_record_digest = "not-a-hash".into();
        }
        assert!(state.consume(&ctx105, garbage).is_err());
        state
            .consume(&ctx105, slash("request-a", &a.record_hash))
            .unwrap();
        let committed = state.state_commitment.clone();
        assert!(state
            .consume(&ctx105, complete("request-a", &a.record_hash))
            .is_err());
        assert_eq!(state.state_commitment, committed);
    }

    #[test]
    fn reverse_index_account_and_cross_object_tamper_are_detected() {
        let mut policy = reservation_policy_for_v2_tests();
        policy.maximum_pending_unbonds_per_owner = 4;
        let ctx = LedgerReservationContextV2::from_staged_ledger_for_candidate_tests(100, &policy)
            .unwrap();
        let mut state = UnbondReservationStateV2::new(&ctx).unwrap();
        state
            .reserve(&ctx, fact("request-a", "owner-a", 100))
            .unwrap();
        state
            .reserve(&ctx, fact("request-b", "owner-b", 100))
            .unwrap();
        let mut index_tamper = state.clone();
        let bond_hash = index_tamper.bonds_by_request["request-a"]
            .unbond_bond_record_hash
            .clone();
        index_tamper
            .request_by_bond_hash
            .insert(bond_hash, "request-b".into());
        index_tamper.state_commitment = index_tamper.compute_commitment().unwrap();
        assert!(index_tamper.validate().is_err());
        let mut account_tamper = state.clone();
        account_tamper
            .accounts_by_request
            .get_mut("request-b")
            .unwrap()
            .live_bytes -= 1;
        account_tamper.state_commitment = account_tamper.compute_commitment().unwrap();
        assert!(account_tamper.validate().is_err());
        let mut cross_delete = state.clone();
        cross_delete.pending_by_request.remove("request-b");
        cross_delete.state_commitment = cross_delete.compute_commitment().unwrap();
        assert!(cross_delete.validate().is_err());

        let mut height_tamper = state.clone();
        height_tamper.history_events[0].height += 1;
        height_tamper.history_events[0].event_root = height_tamper.history_events[0].compute_root();
        height_tamper.history_events[1].predecessor_root =
            height_tamper.history_events[0].event_root.clone();
        height_tamper.history_events[1].event_root = height_tamper.history_events[1].compute_root();
        height_tamper.history_root = height_tamper.history_events[1].event_root.clone();
        height_tamper.state_commitment = height_tamper.compute_commitment().unwrap();
        assert!(height_tamper.validate().is_err());

        let original_commitment = state.compute_commitment().unwrap();
        let mut limit_tamper = state.clone();
        limit_tamper.limits.maximum_total_bytes += 1;
        assert_ne!(
            limit_tamper.compute_commitment().unwrap(),
            original_commitment
        );

        let pending_hash = state.pending_by_request["request-a"].record_hash.clone();
        let ctx105 =
            LedgerReservationContextV2::from_staged_ledger_for_candidate_tests(105, &policy)
                .unwrap();
        let mut terminal_tamper = state;
        terminal_tamper
            .consume(&ctx105, complete("request-a", &pending_hash))
            .unwrap();
        let terminal = terminal_tamper
            .terminal_by_request
            .get_mut("request-a")
            .unwrap();
        terminal.pending_record_digest = H3.into();
        terminal.record_hash = terminal.compute_hash();
        terminal_tamper.state_commitment = terminal_tamper.compute_commitment().unwrap();
        assert!(terminal_tamper.validate().is_err());
    }

    #[test]
    fn restore_requires_an_external_commitment_even_after_embedded_rehash() {
        let policy = reservation_policy_for_v2_tests();
        let ctx = LedgerReservationContextV2::from_staged_ledger_for_candidate_tests(100, &policy)
            .unwrap();
        let mut state = UnbondReservationStateV2::new(&ctx).unwrap();
        state
            .reserve(&ctx, fact("request-1", "owner-a", 100))
            .unwrap();
        let bytes = state.canonical_json_bytes().unwrap();
        assert_eq!(
            UnbondReservationStateV2::restore_canonical_json(&bytes, &state.state_commitment)
                .unwrap(),
            state
        );
        assert!(UnbondReservationStateV2::restore_canonical_json(&bytes, H1).is_err());

        let mut attacker: UnbondReservationStateV2 = serde_json::from_slice(&bytes).unwrap();
        attacker.materialized_live_bytes += 1;
        attacker.state_commitment = attacker.compute_commitment().unwrap();
        let forged = serde_json::to_vec(&attacker).unwrap();
        assert!(
            UnbondReservationStateV2::restore_canonical_json(&forged, &state.state_commitment)
                .is_err()
        );
    }

    #[test]
    fn binary_codec_roundtrips_typed_states_and_rejects_envelope_mutations() {
        fn assert_roundtrip(state: &UnbondReservationStateV2, policy: &StakeStateResourcePolicyV1) {
            let bytes = state.canonical_binary_bytes().unwrap();
            assert_eq!(&bytes[..8], BINARY_MAGIC);
            assert_eq!(
                bytes.len(),
                BINARY_HEADER_BYTES
                    + BINARY_TRAILER_BYTES
                    + usize::try_from(u64::from_be_bytes(bytes[48..56].try_into().unwrap()))
                        .unwrap()
            );
            assert_eq!(
                UnbondReservationStateV2::restore_canonical_binary(
                    &bytes,
                    &state.state_commitment,
                    policy,
                )
                .unwrap(),
                *state
            );
        }

        let policy = reservation_policy_for_v2_tests();
        let ctx100 =
            LedgerReservationContextV2::from_staged_ledger_for_candidate_tests(100, &policy)
                .unwrap();
        let empty = UnbondReservationStateV2::new(&ctx100).unwrap();
        assert_roundtrip(&empty, &policy);

        let mut reserved = empty.clone();
        let pending = reserved
            .reserve(&ctx100, fact("request-a", "owner-a", 100))
            .unwrap();
        assert_roundtrip(&reserved, &policy);

        let ctx105 =
            LedgerReservationContextV2::from_staged_ledger_for_candidate_tests(105, &policy)
                .unwrap();
        let mut completed = reserved.clone();
        completed
            .consume(&ctx105, complete("request-a", &pending.record_hash))
            .unwrap();
        assert_roundtrip(&completed, &policy);

        let mut slashed = reserved.clone();
        slashed
            .consume(&ctx105, slash("request-a", &pending.record_hash))
            .unwrap();
        assert_roundtrip(&slashed, &policy);

        let bytes = reserved.canonical_binary_bytes().unwrap();
        for mutation in [0usize, 8, 10, 12, 13, 14, 16, 48, bytes.len() - 1] {
            let mut altered = bytes.clone();
            altered[mutation] ^= 1;
            assert!(UnbondReservationStateV2::restore_canonical_binary(
                &altered,
                &reserved.state_commitment,
                &policy,
            )
            .is_err());
        }
        assert!(UnbondReservationStateV2::restore_canonical_binary(
            &bytes[..bytes.len() - 1],
            &reserved.state_commitment,
            &policy,
        )
        .is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(UnbondReservationStateV2::restore_canonical_binary(
            &trailing,
            &reserved.state_commitment,
            &policy,
        )
        .is_err());
        assert!(UnbondReservationStateV2::restore_canonical_binary(&bytes, H1, &policy).is_err());
        let mut wrong_policy = policy.clone();
        wrong_policy.maximum_pending_unbonds += 1;
        assert!(UnbondReservationStateV2::restore_canonical_binary(
            &bytes,
            &reserved.state_commitment,
            &wrong_policy,
        )
        .is_err());
        assert!(UnbondReservationStateV2::restore_canonical_binary(
            br#"{"legacy":"json"}"#,
            &reserved.state_commitment,
            &policy,
        )
        .is_err());
    }

    #[test]
    fn owner_identifier_and_internal_work_bounds_are_enforced() {
        let mut policy = reservation_policy_for_v2_tests();
        policy.maximum_pending_unbonds_per_owner = 4;
        let ctx = LedgerReservationContextV2::from_staged_ledger_for_candidate_tests(100, &policy)
            .unwrap();
        let mut state = UnbondReservationStateV2::new(&ctx).unwrap();
        assert!(state
            .reserve(&ctx, fact("request-1", &"x".repeat(257), 100))
            .is_err());
        assert!(state
            .reserve(&ctx, fact(&"x".repeat(129), "owner-a", 100))
            .is_err());

        let mut tiny = policy.clone();
        tiny.maximum_stake_state_bytes_per_block = 1;
        let tiny_ctx =
            LedgerReservationContextV2::from_staged_ledger_for_candidate_tests(100, &tiny).unwrap();
        let mut tiny_state = UnbondReservationStateV2::new(&tiny_ctx).unwrap();
        let before = tiny_state.state_commitment.clone();
        assert!(tiny_state
            .reserve(&tiny_ctx, fact("request-1", "owner-a", 100))
            .is_err());
        assert_eq!(tiny_state.state_commitment, before);
    }

    #[test]
    fn independent_candidate_vector_declares_all_attack_classes() {
        fn assert_checkpoint(
            candidate: &serde_json::Value,
            name: &str,
            state: &UnbondReservationStateV2,
            policy: &StakeStateResourcePolicyV1,
        ) {
            let expected = &candidate["checkpoints"][name];
            let bytes = state.canonical_binary_bytes().unwrap();
            assert_eq!(hex::encode(&bytes), expected["snapshot_hex"]);
            assert_eq!(state.state_commitment, expected["state_commitment"]);
            assert_eq!(
                state.materialized_live_bytes,
                expected["materialized_live_bytes"].as_u64().unwrap()
            );
            assert_eq!(
                state.materialized_history_bytes,
                expected["materialized_history_bytes"].as_u64().unwrap()
            );
            assert_eq!(
                state.reserved_bytes,
                expected["reserved_bytes"].as_u64().unwrap()
            );
            assert_eq!(state.history_root, expected["history_root"]);
            assert_eq!(
                UnbondReservationStateV2::restore_canonical_binary(
                    &bytes,
                    &state.state_commitment,
                    policy,
                )
                .unwrap(),
                *state
            );
        }

        let bundle: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/stake-resource-accounting-v1/vectors.json"
        )))
        .unwrap();
        let claims = &bundle["payload"]["claims"];
        assert_eq!(claims["unbond_reservation_state_primitive"], false);
        assert_eq!(claims["unbond_reservation_prototype_only"], true);
        assert_eq!(claims["unbond_reservation_v2_candidate"], true);
        assert_eq!(
            claims["unbond_reservation_binary_codec_cross_implementation"],
            true
        );
        let candidate = &bundle["payload"]["terminal_reservation_v2_candidate"];
        assert_eq!(candidate["model"], "STDLIB_BINARY_STATE_V1");
        assert_eq!(candidate["spec"], "UNBOND-RESERVATION-STATE-BINARY-V1");
        let policy: StakeStateResourcePolicyV1 =
            serde_json::from_value(candidate["policy"].clone()).unwrap();
        assert_eq!(
            stake_state_resource_policy_commitment_v1(&policy).unwrap(),
            candidate["policy_commitment"]
        );
        assert_eq!(
            work_catalog_commitment(),
            candidate["codec"]["work_catalog_commitment"]
        );

        let ctx100 =
            LedgerReservationContextV2::from_staged_ledger_for_candidate_tests(100, &policy)
                .unwrap();
        let empty = UnbondReservationStateV2::new(&ctx100).unwrap();
        assert_checkpoint(candidate, "empty", &empty, &policy);
        let mut reserved = empty.clone();
        let pending = reserved
            .reserve(&ctx100, fact("request-a", "owner-a", 100))
            .unwrap();
        assert_checkpoint(candidate, "reserve", &reserved, &policy);
        let ctx105 =
            LedgerReservationContextV2::from_staged_ledger_for_candidate_tests(105, &policy)
                .unwrap();
        let mut completed = reserved.clone();
        completed
            .consume(&ctx105, complete("request-a", &pending.record_hash))
            .unwrap();
        assert_checkpoint(candidate, "complete", &completed, &policy);
        let mut slashed = reserved.clone();
        slashed
            .consume(&ctx100, slash("request-a", &pending.record_hash))
            .unwrap();
        assert_checkpoint(candidate, "slash", &slashed, &policy);
        let ctx110 =
            LedgerReservationContextV2::from_staged_ledger_for_candidate_tests(110, &policy)
                .unwrap();
        let mut skipped = reserved.clone();
        skipped
            .reserve(&ctx110, fact("request-b", "owner-b", 110))
            .unwrap();
        assert_checkpoint(candidate, "trusted-height-skip", &skipped, &policy);

        let negatives = candidate["binary_negative_cases"].as_array().unwrap();
        assert_eq!(negatives.len(), 12);
        for negative in negatives {
            let bytes = hex::decode(negative["snapshot_hex"].as_str().unwrap()).unwrap();
            assert!(UnbondReservationStateV2::restore_canonical_binary(
                &bytes,
                negative["external_commitment"].as_str().unwrap(),
                &policy,
            )
            .is_err());
        }

        let cases = candidate["cases"].as_array().unwrap();
        assert_eq!(
            cases
                .iter()
                .filter(|case| case["result"] == "accept")
                .count(),
            2
        );
        assert_eq!(
            cases
                .iter()
                .filter(|case| case["result"] == "reject")
                .count(),
            12
        );
        for required in [
            "reject-same-bond-double-reserve",
            "reject-same-resource-double-reserve",
            "reject-cross-object-delete",
            "reject-pending-rebind",
            "reject-terminal-rebind",
            "reject-garbage-terminal",
            "reject-complete-then-slash",
            "reject-slash-then-complete",
            "reject-forged-restore",
            "reject-owner-too-long",
            "reject-record-cap",
            "reject-height-rollback",
        ] {
            assert!(cases.iter().any(|case| case["name"] == required));
        }
    }
}
