//! Replay-verified import inclusion in a destination PoW chain.
//! A receipt is only an index into a separately replayed selected chain.

use super::{Command, DestinationPowChain, MIN_IMPORT_CONFIRMATIONS};
use crate::{chain::CandidateChain, require, Result};
use rld_core::{AdmissionHash32 as Hash, AdmissionWork as Work};
use rld_cross_region::ProofBundle;
use rld_pow::MAX_TRACKED_BLOCKS;
use serde::{Deserialize, Serialize};

const FORMAT: &str = "RLD-EARTH-DESTINATION-POW-IMPORT-INCLUSION";

/// Local candidate acceptance thresholds, not an independently adopted
/// destination trust policy. Work is measured at the inclusion block.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InclusionPolicy {
    pub destination_chain_id: Hash,
    pub accepted_genesis: Hash,
    #[serde(with = "rld_pow::decimal")]
    pub minimum_confirmations: u128,
    pub minimum_inclusion_work: Work,
}

/// A stable pointer to an import command. It contains no standalone proof of
/// work, finality, or spendability; verification needs both replayed chains.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ImportInclusionReceipt {
    pub format: String,
    pub live_rld: bool,
    pub destination_chain_id: Hash,
    pub destination_genesis: Hash,
    pub source_chain_id: Hash,
    pub source_checkpoint: Hash,
    pub export_id: Hash,
    pub bundle_id: Hash,
    pub block: Hash,
    #[serde(with = "rld_pow::decimal")]
    pub block_height: u128,
    #[serde(with = "rld_pow::decimal")]
    pub recipient_spendable_height: u128,
    pub command_index: u16,
    pub state_root: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedImport {
    pub selected_tip: Hash,
    pub confirmations: u128,
    pub inclusion_work: Work,
    pub selected_work: Work,
}

impl DestinationPowChain {
    fn validate_inclusion_policy(&self, policy: &InclusionPolicy) -> Result<()> {
        require(
            policy.destination_chain_id == self.context.chain_id
                && policy.accepted_genesis == self.genesis
                && policy.minimum_confirmations >= 2
                && policy.minimum_confirmations <= MAX_TRACKED_BLOCKS as u128
                && !policy.minimum_inclusion_work.is_zero(),
            "unaccepted destination inclusion policy",
        )
    }

    fn included_import(
        &self,
        source: &CandidateChain,
        bundle: &ProofBundle,
        policy: &InclusionPolicy,
    ) -> Result<(ImportInclusionReceipt, ObservedImport)> {
        require(!self.halted, "destination candidate permanently halted")?;
        self.source_network(source)?;
        self.validate_inclusion_policy(policy)?;
        // A source reorganization may invalidate an otherwise selected import.
        let mut state = self.state().clone();
        state.audit_source(source)?;
        source.observe_export_bundle(bundle, &self.context.source_policy)?;
        require(
            bundle.destination_chain_id == self.context.chain_id,
            "bundle routed to another destination",
        )?;
        let bundle_id = bundle.id()?;
        for block in self.best_blocks()? {
            for (index, command) in block.commands.iter().enumerate() {
                let import = match command {
                    Command::Import(import) => import,
                    Command::FinalizedImport { bundle, .. } => bundle,
                    Command::Transfer(_) => continue,
                };
                {
                    if import.id()? != bundle_id {
                        continue;
                    }
                    require(import == bundle, "import bundle bytes differ")?;
                    let block_id = block.header.id()?;
                    let entry = self.entries.get(&block_id).ok_or("missing import block")?;
                    let confirmations = self
                        .height()
                        .checked_sub(block.header.height)
                        .and_then(|distance| distance.checked_add(1))
                        .ok_or("destination confirmation height mismatch")?;
                    require(
                        confirmations >= policy.minimum_confirmations
                            && entry.cumulative_work >= policy.minimum_inclusion_work,
                        "insufficient destination confirmations or inclusion work",
                    )?;
                    return Ok((
                        ImportInclusionReceipt {
                            format: FORMAT.into(),
                            live_rld: false,
                            destination_chain_id: self.context.chain_id,
                            destination_genesis: self.genesis,
                            source_chain_id: bundle.source_chain_id,
                            source_checkpoint: bundle.source_checkpoint,
                            export_id: bundle.export_id,
                            bundle_id,
                            block: block_id,
                            block_height: block.header.height,
                            recipient_spendable_height: block
                                .header
                                .height
                                .checked_add(MIN_IMPORT_CONFIRMATIONS)
                                .ok_or("destination receipt maturity overflow")?,
                            command_index: u16::try_from(index)
                                .map_err(|_| "destination command index overflow")?,
                            state_root: block.header.state_root,
                        },
                        ObservedImport {
                            selected_tip: self.tip,
                            confirmations,
                            inclusion_work: entry.cumulative_work,
                            selected_work: self.chainwork(),
                        },
                    ));
                }
            }
        }
        Err("import absent from selected destination branch".into())
    }

    pub fn observe_import(
        &self,
        source: &CandidateChain,
        bundle: &ProofBundle,
        policy: &InclusionPolicy,
    ) -> Result<ImportInclusionReceipt> {
        self.included_import(source, bundle, policy)
            .map(|(receipt, _)| receipt)
    }

    /// Recompute every claim from locally replayed source and destination
    /// branches. Re-run after head changes; a stronger fork can revoke this.
    pub fn verify_import_receipt(
        &self,
        source: &CandidateChain,
        bundle: &ProofBundle,
        policy: &InclusionPolicy,
        receipt: &ImportInclusionReceipt,
    ) -> Result<ObservedImport> {
        let (expected, observed) = self.included_import(source, bundle, policy)?;
        require(
            receipt == &expected,
            "destination inclusion receipt differs",
        )?;
        Ok(observed)
    }
}
