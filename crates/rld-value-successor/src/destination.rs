//! Isolated destination import simulation backed by replayed source evidence.
//!
//! It has no destination PoW, durable consensus, independently adopted source
//! trust policy or live spend path. Its receipt cannot authorize live RLD credit.

use crate::{
    chain::{CandidateChain, ObservationPolicy},
    hash, key, require, Result,
};
use rld_core::{verify_bytes, AdmissionHash32 as Hash, Amount, TOTAL_SUPPLY_RUNLAI};
use rld_cross_region::{value::ExportRecord, ProofBundle, MAX_BUNDLES};
use rld_pow::{Coin, OutPoint, Output, Transfer, COINBASE_MATURITY};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub mod ack;
pub mod pow;
pub mod storage;
const MAX_EVENTS: u64 = 100_000;

#[derive(Clone, Debug)]
struct Import {
    bundle: ProofBundle,
    record: ExportRecord,
    destination_height: u128,
    miner: String,
}

/// Unsigned local simulation result. No destination consensus has committed it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SimulatedReceipt {
    pub id: Hash,
    pub source_chain_id: Hash,
    pub destination_chain_id: Hash,
    pub export_id: Hash,
    pub source_checkpoint: Hash,
    #[serde(with = "rld_pow::decimal")]
    pub destination_height: u128,
    pub state_root: Hash,
    pub recipient_outpoint: OutPoint,
    pub miner_fee_outpoint: OutPoint,
}

/// Candidate-only signed transfer of a previously imported destination coin.
/// The height is caller-supplied until a destination consensus exists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulatedTransferReceipt {
    pub transaction: Hash,
    pub destination_chain_id: Hash,
    pub destination_height: u128,
    pub state_root: Hash,
    pub outputs: Vec<OutPoint>,
    pub miner_fee_outpoint: OutPoint,
}

#[derive(Clone, Debug)]
pub struct DestinationSimulation {
    chain_id: Hash,
    source_policy: ObservationPolicy,
    imports: BTreeMap<(Hash, Hash), Import>,
    coins: BTreeMap<OutPoint, Coin>,
    imported_total: Amount,
    event_count: u64,
    halted: bool,
}

impl DestinationSimulation {
    /// A zero-native-issuance destination fixture. It is not a region genesis.
    pub fn new_empty(chain_id: Hash, source_policy: ObservationPolicy) -> Result<Self> {
        require(
            !chain_id.is_zero()
                && !source_policy.source_chain_id.is_zero()
                && source_policy.source_chain_id != chain_id
                && !source_policy.accepted_v1_tip.is_zero()
                && source_policy.minimum_confirmations >= 2
                && !source_policy.minimum_cumulative_work.is_zero(),
            "invalid simulated destination source policy",
        )?;
        Ok(Self {
            chain_id,
            source_policy,
            imports: BTreeMap::new(),
            coins: BTreeMap::new(),
            imported_total: Amount::ZERO,
            event_count: 0,
            halted: false,
        })
    }

    pub fn halted(&self) -> bool {
        self.halted
    }

    pub fn imported_total(&self) -> Amount {
        self.imported_total
    }

    pub fn coin(&self, outpoint: &OutPoint) -> Option<&Coin> {
        self.coins.get(outpoint)
    }

    /// Read-only selected-branch view. A pending imported coin remains in the
    /// supply commitment but cannot fund a transfer at `next_height`.
    pub fn balance(&self, owner: &str, next_height: u128) -> Result<(Amount, Amount)> {
        key(owner)?;
        let mut spendable = Amount::ZERO;
        let mut pending = Amount::ZERO;
        for coin in self
            .coins
            .values()
            .filter(|coin| coin.output.owner == owner)
        {
            let bucket = if coin.spendable_height <= next_height {
                &mut spendable
            } else {
                &mut pending
            };
            *bucket = bucket
                .checked_add(coin.output.amount)
                .map_err(|error| error.to_string())?;
        }
        Ok((spendable, pending))
    }

    pub fn root(&self) -> Result<Hash> {
        let liquid = self.coins.values().try_fold(Amount::ZERO, |sum, coin| {
            key(&coin.output.owner)?;
            require(!coin.output.amount.is_zero(), "zero simulated import coin")?;
            sum.checked_add(coin.output.amount)
                .map_err(|error| error.to_string())
        })?;
        require(
            liquid == self.imported_total && liquid.0 <= TOTAL_SUPPLY_RUNLAI,
            "simulated destination supply mismatch",
        )?;
        let recorded =
            self.imports
                .iter()
                .try_fold(Amount::ZERO, |sum, ((source, export), import)| {
                    let intent = &import.record.command.intent;
                    require(
                        *source == intent.source_chain_id
                            && *export == import.record.id()?
                            && intent.destination_chain_id == self.chain_id
                            && import.bundle.source_chain_id == *source
                            && import.bundle.destination_chain_id == self.chain_id
                            && import.bundle.export_id == *export
                            && import.bundle.source_checkpoint != Hash::ZERO
                            && import.destination_height > 0,
                        "invalid simulated import record",
                    )?;
                    key(&import.miner)?;
                    sum.checked_add(intent.amount)
                        .map_err(|error| error.to_string())
                })?;
        require(
            recorded == self.imported_total,
            "import record sum mismatch",
        )?;
        #[derive(Serialize)]
        struct ImportCommitment<'a> {
            key: &'a (Hash, Hash),
            bundle: &'a ProofBundle,
            record: &'a ExportRecord,
            destination_height: String,
            miner: &'a str,
        }
        #[derive(Serialize)]
        struct Commitment<'a> {
            chain_id: &'a Hash,
            source_chain_id: &'a Hash,
            accepted_v1_tip: &'a Hash,
            minimum_confirmations: String,
            minimum_cumulative_work: String,
            imported_total: &'a Amount,
            halted: bool,
            coins: Vec<(&'a OutPoint, &'a Coin)>,
            imports: Vec<ImportCommitment<'a>>,
        }
        let value = Commitment {
            chain_id: &self.chain_id,
            source_chain_id: &self.source_policy.source_chain_id,
            accepted_v1_tip: &self.source_policy.accepted_v1_tip,
            minimum_confirmations: self.source_policy.minimum_confirmations.to_string(),
            minimum_cumulative_work: self.source_policy.minimum_cumulative_work.to_hex(),
            imported_total: &self.imported_total,
            halted: self.halted,
            coins: self.coins.iter().collect(),
            imports: self
                .imports
                .iter()
                .map(|(key, import)| ImportCommitment {
                    key,
                    bundle: &import.bundle,
                    record: &import.record,
                    destination_height: import.destination_height.to_string(),
                    miner: import.miner.as_str(),
                })
                .collect(),
        };
        let mut bytes = b"RLD-DESTINATION-IMPORT-SIMULATION-V1\0".to_vec();
        bytes.extend(serde_json::to_vec(&value).map_err(|error| error.to_string())?);
        Ok(hash(&bytes))
    }

    /// Recheck source PoW and bundle claims before one isolated import. There
    /// is no live destination chain and no spendable public balance.
    pub fn import_from_replayed_source(
        &mut self,
        source: &CandidateChain,
        bundle: ProofBundle,
        destination_height: u128,
        miner: &str,
    ) -> Result<SimulatedReceipt> {
        let record = source
            .observe_export_bundle(&bundle, &self.source_policy)?
            .record;
        self.apply_record(
            bundle,
            record,
            destination_height,
            destination_height,
            b"RLD-DESTINATION-IMPORT-OUTPUT-SIMULATION-V1\0",
            miner,
        )
    }

    /// Reconstruct an import already committed to the candidate event log.
    /// An orphaned but fully replayed historical source checkpoint remains
    /// reconstructable; the store separately audits and halts before use.
    pub(crate) fn replay_recorded_import(
        &mut self,
        source: &CandidateChain,
        bundle: ProofBundle,
        destination_height: u128,
        miner: &str,
    ) -> Result<SimulatedReceipt> {
        let record = source.replay_known_export_bundle(&bundle)?;
        self.apply_record(
            bundle,
            record,
            destination_height,
            destination_height,
            b"RLD-DESTINATION-IMPORT-OUTPUT-SIMULATION-V1\0",
            miner,
        )
    }

    /// The PoW destination withholds an imported recipient coin until the
    /// importing block has two prior confirmations. The earlier event-log
    /// simulation retains its historical immediate-spend semantics.
    pub(crate) fn import_into_pow(
        &mut self,
        source: &CandidateChain,
        bundle: ProofBundle,
        destination_height: u128,
        miner: &str,
    ) -> Result<SimulatedReceipt> {
        let record = source
            .observe_export_bundle(&bundle, &self.source_policy)?
            .record;
        self.apply_record(
            bundle,
            record,
            destination_height,
            destination_height
                .checked_add(pow::MIN_IMPORT_CONFIRMATIONS)
                .ok_or("destination import maturity overflow")?,
            b"RLD-EARTH-DESTINATION-POW-IMPORT-OUTPUT\0",
            miner,
        )
    }

    pub(crate) fn replay_pow_import(
        &mut self,
        source: &CandidateChain,
        bundle: ProofBundle,
        destination_height: u128,
        miner: &str,
    ) -> Result<SimulatedReceipt> {
        let record = source.replay_known_export_bundle(&bundle)?;
        self.apply_record(
            bundle,
            record,
            destination_height,
            destination_height
                .checked_add(pow::MIN_IMPORT_CONFIRMATIONS)
                .ok_or("destination import maturity overflow")?,
            b"RLD-EARTH-DESTINATION-POW-IMPORT-OUTPUT\0",
            miner,
        )
    }

    fn apply_record(
        &mut self,
        bundle: ProofBundle,
        record: ExportRecord,
        destination_height: u128,
        recipient_spendable_height: u128,
        output_domain: &[u8],
        miner: &str,
    ) -> Result<SimulatedReceipt> {
        require(!self.halted, "simulated destination is halted")?;
        require(
            destination_height > 0 && recipient_spendable_height >= destination_height,
            "invalid destination import maturity",
        )?;
        key(miner)?;
        let intent = &record.command.intent;
        require(
            bundle.destination_chain_id == self.chain_id
                && intent.destination_chain_id == self.chain_id,
            "wrong destination for import",
        )?;
        let export_id = record.id()?;
        let import_key = (intent.source_chain_id, export_id);
        require(
            !self.imports.contains_key(&import_key),
            "export already imported",
        )?;
        require(
            self.imports.len() < MAX_BUNDLES,
            "simulated import capacity reached",
        )?;
        let recipient_amount = intent
            .amount
            .checked_sub(intent.destination_fee)
            .map_err(|error| error.to_string())?;
        require(!recipient_amount.is_zero(), "empty destination recipient")?;
        let mut bytes = output_domain.to_vec();
        bytes.extend(self.chain_id.0);
        bytes.extend(intent.source_chain_id.0);
        bytes.extend(export_id.0);
        let transaction = hash(&bytes);
        let recipient_outpoint = OutPoint {
            transaction,
            index: 0,
        };
        let miner_fee_outpoint = OutPoint {
            transaction,
            index: 1,
        };
        require(
            self.event_count < MAX_EVENTS,
            "destination event capacity reached",
        )?;
        let mut next = self.clone();
        require(
            next.coins
                .insert(
                    recipient_outpoint.clone(),
                    Coin {
                        output: Output {
                            owner: intent.recipient.clone(),
                            amount: recipient_amount,
                        },
                        spendable_height: recipient_spendable_height,
                    },
                )
                .is_none(),
            "recipient import collision",
        )?;
        require(
            next.coins
                .insert(
                    miner_fee_outpoint.clone(),
                    Coin {
                        output: Output {
                            owner: miner.into(),
                            amount: intent.destination_fee,
                        },
                        spendable_height: destination_height
                            .checked_add(COINBASE_MATURITY)
                            .ok_or("destination fee maturity overflow")?,
                    },
                )
                .is_none(),
            "destination fee collision",
        )?;
        next.imported_total = next
            .imported_total
            .checked_add(intent.amount)
            .map_err(|error| error.to_string())?;
        next.event_count = next
            .event_count
            .checked_add(1)
            .ok_or("destination event overflow")?;
        next.imports.insert(
            import_key,
            Import {
                bundle: bundle.clone(),
                record,
                destination_height,
                miner: miner.into(),
            },
        );
        let state_root = next.root()?;
        let mut receipt = SimulatedReceipt {
            id: Hash::ZERO,
            source_chain_id: import_key.0,
            destination_chain_id: self.chain_id,
            export_id,
            source_checkpoint: bundle.source_checkpoint,
            destination_height,
            state_root,
            recipient_outpoint,
            miner_fee_outpoint,
        };
        receipt.id = receipt.derived_id();
        *self = next;
        Ok(receipt)
    }

    /// Apply one signed candidate destination payment only while all source
    /// imports remain qualified on the supplied replayed source branch.
    pub fn transfer_from_replayed_source(
        &mut self,
        source: &CandidateChain,
        tx: Transfer,
        destination_height: u128,
        miner: &str,
    ) -> Result<SimulatedTransferReceipt> {
        self.audit_source(source)?;
        self.apply_transfer(tx, destination_height, miner)
    }

    /// Replay an already durable destination payment before auditing the
    /// source at startup. This cannot authorize a new payment.
    pub(crate) fn replay_recorded_transfer(
        &mut self,
        tx: Transfer,
        destination_height: u128,
        miner: &str,
    ) -> Result<SimulatedTransferReceipt> {
        self.apply_transfer(tx, destination_height, miner)
    }

    fn apply_transfer(
        &mut self,
        tx: Transfer,
        destination_height: u128,
        miner: &str,
    ) -> Result<SimulatedTransferReceipt> {
        require(!self.halted, "simulated destination is halted")?;
        require(
            destination_height > 0
                && tx.chain_id == self.chain_id
                && destination_height <= tx.valid_through_height
                && tx.fee.0 >= 1,
            "destination transfer network, height, expiry or fee mismatch",
        )?;
        key(miner)?;
        verify_bytes(&tx.owner, &tx.signing_bytes()?, &tx.signature)?;
        let transaction = tx.id().map_err(|error| error.to_string())?;
        let input_total = tx.inputs.iter().try_fold(Amount::ZERO, |total, input| {
            let coin = self
                .coins
                .get(input)
                .ok_or("unknown or spent destination input")?;
            require(
                coin.output.owner == tx.owner && coin.spendable_height <= destination_height,
                "destination input owner or maturity mismatch",
            )?;
            total
                .checked_add(coin.output.amount)
                .map_err(|error| error.to_string())
        })?;
        let output_total = tx.outputs.iter().try_fold(tx.fee, |total, output| {
            key(&output.owner)?;
            total
                .checked_add(output.amount)
                .map_err(|error| error.to_string())
        })?;
        require(
            input_total == output_total,
            "destination transfer does not conserve value",
        )?;
        let fee_maturity = destination_height
            .checked_add(COINBASE_MATURITY)
            .ok_or("destination fee maturity overflow")?;
        require(
            self.event_count < MAX_EVENTS,
            "destination event capacity reached",
        )?;
        let mut next = self.clone();
        for input in &tx.inputs {
            next.coins.remove(input);
        }
        let mut outputs = Vec::with_capacity(tx.outputs.len());
        for (index, output) in tx.outputs.into_iter().enumerate() {
            let point = OutPoint {
                transaction,
                index: index as u16,
            };
            require(
                next.coins
                    .insert(
                        point.clone(),
                        Coin {
                            output,
                            spendable_height: destination_height,
                        },
                    )
                    .is_none(),
                "destination transfer output collision",
            )?;
            outputs.push(point);
        }
        let miner_fee_outpoint = OutPoint {
            transaction,
            index: u16::MAX,
        };
        require(
            next.coins
                .insert(
                    miner_fee_outpoint.clone(),
                    Coin {
                        output: Output {
                            owner: miner.into(),
                            amount: tx.fee,
                        },
                        spendable_height: fee_maturity,
                    },
                )
                .is_none(),
            "destination transfer fee collision",
        )?;
        next.event_count = next
            .event_count
            .checked_add(1)
            .ok_or("destination event overflow")?;
        let state_root = next.root()?;
        *self = next;
        Ok(SimulatedTransferReceipt {
            transaction,
            destination_chain_id: self.chain_id,
            destination_height,
            state_root,
            outputs,
            miner_fee_outpoint,
        })
    }

    /// A source reorganization after simulated credit is a safety failure.
    /// Freeze this model rather than silently keep treating the receipt as
    /// backed. Existing credits are not thereby rolled back or made safe.
    pub fn audit_source(&mut self, source: &CandidateChain) -> Result<()> {
        if self.halted {
            return Err("simulated destination is halted".into());
        }
        for import in self.imports.values() {
            if source
                .observe_export_bundle(&import.bundle, &self.source_policy)
                .is_err()
            {
                self.halted = true;
                return Err("imported source checkpoint no longer qualifies".into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
