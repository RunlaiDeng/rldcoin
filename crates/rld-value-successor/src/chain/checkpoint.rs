//! Replay-authenticated candidate state checkpoints.
//!
//! A checkpoint is an auxiliary copy of a state, not a substitute for the
//! underlying blocks. Opening the store replays those blocks and compares the
//! complete state before accepting the checkpoint. No pruning or fast-trust
//! path is provided here.

use super::CandidateChain;
use crate::{key, require, Ledger, ReservedChallengeFee, Result};
use rld_core::{AdmissionHash32 as Hash, AdmissionWork as Work, Amount};
use rld_cross_region::value::ExportRecord;
use rld_fast_payments::successor::Escrow;
use rld_pow::{Coin, OutPoint};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub(crate) const MAX_CHECKPOINT_BYTES: usize = 256 * 1024 * 1024;
const FORMAT: &str = "RLD-EARTH-UNIFIED-REPLAYED-CHECKPOINT";

/// A complete state image tied to one replayed successor block. The image
/// uses ordered entry arrays because JSON objects cannot use structured keys.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    format: String,
    chain_id: Hash,
    v1_tip: Hash,
    tip: Hash,
    #[serde(with = "rld_pow::decimal")]
    height: u128,
    chainwork: Work,
    state_root: Hash,
    state: LedgerSnapshot,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LedgerSnapshot {
    chain_id: Hash,
    v1_tip: Hash,
    v1_root: Hash,
    #[serde(with = "rld_pow::decimal")]
    anchor_height: u128,
    emitted: Amount,
    coins: Vec<(OutPoint, Coin)>,
    escrows: Vec<(Hash, Escrow)>,
    reserved_fees: Vec<(OutPoint, ReservedChallengeFee)>,
    exports: Vec<(Hash, ExportRecord)>,
}

fn strictly_ordered<K: Ord, V>(items: &[(K, V)]) -> bool {
    items.windows(2).all(|pair| pair[0].0 < pair[1].0)
}

impl LedgerSnapshot {
    fn from_ledger(ledger: &Ledger) -> Self {
        Self {
            chain_id: ledger.chain_id,
            v1_tip: ledger.v1_tip,
            v1_root: ledger.v1_root,
            anchor_height: ledger.anchor_height,
            emitted: ledger.emitted,
            coins: ledger
                .coins
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            escrows: ledger
                .escrows
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect(),
            reserved_fees: ledger
                .reserved_fees
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            exports: ledger
                .exports
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect(),
        }
    }

    fn restore(&self) -> Result<Ledger> {
        require(
            strictly_ordered(&self.coins)
                && strictly_ordered(&self.escrows)
                && strictly_ordered(&self.reserved_fees)
                && strictly_ordered(&self.exports),
            "checkpoint entries are duplicated or out of order",
        )?;
        // Ledger::totals normally avoids repeating curve checks for already
        // verified coins. Snapshot bytes are an untrusted new entry point.
        for (_, coin) in &self.coins {
            key(&coin.output.owner)?;
        }
        for (_, reservation) in &self.reserved_fees {
            key(&reservation.coin.output.owner)?;
        }
        let ledger = Ledger {
            chain_id: self.chain_id,
            v1_tip: self.v1_tip,
            v1_root: self.v1_root,
            anchor_height: self.anchor_height,
            emitted: self.emitted,
            coins: self.coins.iter().cloned().collect::<BTreeMap<_, _>>(),
            escrows: self.escrows.iter().cloned().collect::<BTreeMap<_, _>>(),
            reserved_fees: self
                .reserved_fees
                .iter()
                .cloned()
                .collect::<BTreeMap<_, _>>(),
            exports: self.exports.iter().cloned().collect::<BTreeMap<_, _>>(),
        };
        ledger.root()?;
        Ok(ledger)
    }
}

impl CandidateChain {
    pub fn replayed_checkpoint(&self) -> Result<Checkpoint> {
        let entry = self
            .entries
            .get(&self.tip)
            .ok_or("no successor block to checkpoint")?;
        let state = self.state_at(self.tip)?;
        require(
            state.root()? == entry.block.header.state_root,
            "selected state differs from successor block",
        )?;
        Ok(Checkpoint {
            format: FORMAT.into(),
            chain_id: self.chain_id,
            v1_tip: self.v1_tip,
            tip: self.tip,
            height: entry.block.header.height,
            chainwork: entry.cumulative_work,
            state_root: entry.block.header.state_root,
            state: LedgerSnapshot::from_ledger(&state),
        })
    }

    /// A caller cannot use a file's claimed root as proof. The locally
    /// retained blocks must already have passed full command replay, and the
    /// complete image must equal the reconstructed state of its own branch.
    pub fn verify_replayed_checkpoint(&self, checkpoint: &Checkpoint) -> Result<()> {
        require(
            checkpoint.format == FORMAT
                && checkpoint.chain_id == self.chain_id
                && checkpoint.v1_tip == self.v1_tip,
            "checkpoint format or anchor mismatch",
        )?;
        let entry = self
            .entries
            .get(&checkpoint.tip)
            .ok_or("checkpoint block absent from replayed history")?;
        require(
            checkpoint.height == entry.block.header.height
                && checkpoint.chainwork == entry.cumulative_work
                && checkpoint.state_root == entry.block.header.state_root,
            "checkpoint block commitment mismatch",
        )?;
        let restored = checkpoint.state.restore()?;
        require(
            restored.chain_id == self.chain_id
                && restored.v1_tip == self.v1_tip
                && restored.v1_root == self.base_state.v1_root
                && restored.anchor_height == self.anchor_height
                && restored.root()? == checkpoint.state_root,
            "checkpoint value anchor or state root mismatch",
        )?;
        require(
            restored == self.state_at(checkpoint.tip)?,
            "checkpoint differs from fully replayed state",
        )
    }
}
