//! Rldcoin consensus-domain reference types and deterministic state machine.
//!
//! This crate deliberately contains no network or storage code. A Zone node can
//! execute the same commands and obtain the same state root on any platform.

pub mod admission;
pub mod amount;
pub mod causal;
pub mod command_wire;
pub mod consensus_epoch;
pub mod crypto;
pub mod genesis;
pub mod hybrid_archive;
pub mod hybrid_authorization;
pub mod hybrid_quorum;
pub mod implementation_source;
pub mod ledger;
pub mod m0_candidate_replay;
pub mod permanent_import_candidate;
pub mod stake_epoch;
pub mod stake_evidence;
pub mod stake_resource_accounting;
mod stake_resource_reservation_v2;
pub mod stake_resource_wire;
pub mod types;
pub mod view_change;
pub mod wire;

// R7.2's first-gate model is deliberately test-only.  It must not become a
// runtime or consensus activation path before the later atomic ledger gate.
#[cfg(test)]
mod open_contribution_candidate;

pub use admission::*;
pub use amount::{Amount, AmountError, RUNLAI_PER_RLD, TOTAL_SUPPLY_RLD, TOTAL_SUPPLY_RUNLAI};
pub use causal::{CausalDecision, CausalFirewall};
pub use consensus_epoch::*;
pub use crypto::{
    generate_identity, hash_bytes, sign_bytes, validate_ed25519_public_key, verify_bytes, Identity,
};
pub use genesis::*;
pub use ledger::{
    currency_genesis_root, local_payment_price_schedule,
    AuthenticatedAdmissionCheckpointVoteLockV1, AuthenticatedConsensusCommitMetadataV1, Ledger,
    LedgerError, LOCAL_PAYMENT_MAX_FEE_RUNLAI, LOCAL_PAYMENT_PRICING_EPOCH,
};
pub use stake_epoch::*;
pub use stake_evidence::*;
pub use stake_resource_accounting::*;
pub use stake_resource_wire::*;
pub use types::*;
pub use view_change::*;
pub use wire::{WireError, WirePurpose, WireSchema};
