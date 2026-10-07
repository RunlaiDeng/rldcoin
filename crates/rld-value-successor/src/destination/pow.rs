//! Zero-native-issuance destination PoW chain.
//! Adopted Earth imports require a signed, source-enforced finality checkpoint.
//! Destination PoW itself remains probabilistic after import maturity.

use super::DestinationSimulation;
use crate::{
    chain::{finality::FinalityCertificate, scale_target, CandidateChain, ObservationPolicy},
    hash, key, require, Result,
};
use rld_core::{header_work, AdmissionHash32 as Hash, AdmissionWork as Work};
use rld_cross_region::{ProofBundle, MAX_BUNDLE_BYTES};
use rld_pow::{target_limit, Transfer, BLOCK_SECONDS, MAX_TRACKED_BLOCKS, RETARGET_BLOCKS};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const MAX_DESTINATION_BLOCK_BYTES: usize = 2 * MAX_BUNDLE_BYTES + 8192;
/// An import at H first becomes usable in a block at H + 6. This remains
/// probabilistic: a deeper destination reorganization can still revoke it.
pub const MIN_IMPORT_CONFIRMATIONS: u128 = 6;
const MAX_DESTINATION_COMMANDS: usize = 16;

fn implementation_source_hash() -> Result<Hash> {
    let source = Hash::from_hex(rld_core::implementation_source::IMPLEMENTATION_SOURCE_COMMITMENT)
        .map_err(|error| error.to_string())?;
    require(
        !source.is_zero(),
        "missing destination candidate source commitment",
    )?;
    Ok(source)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub chain_id: Hash,
    pub source_policy: ObservationPolicy,
    pub started_at: u64,
    pub initial_target: Work,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_finality: Option<SourceFinalityTrust>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceFinalityTrust {
    pub earth_adoption_id: Hash,
    pub validator_keys: Vec<String>,
}

impl Context {
    pub fn validate(&self) -> Result<()> {
        DestinationSimulation::new_empty(self.chain_id, self.source_policy.clone())?;
        if let Some(trust) = &self.source_finality {
            require(
                !trust.earth_adoption_id.is_zero()
                    && self.source_policy.minimum_confirmations >= 12
                    && trust.validator_keys.len() == 4
                    && trust
                        .validator_keys
                        .windows(2)
                        .all(|pair| pair[0] < pair[1]),
                "invalid destination source finality trust",
            )?;
            for validator in &trust.validator_keys {
                key(validator)?;
            }
        }
        require(
            self.started_at > 0
                && !self.initial_target.is_zero()
                && self.initial_target <= target_limit(),
            "invalid destination PoW start or target",
        )
    }

    pub fn genesis(&self) -> Result<Hash> {
        self.validate()?;
        let root =
            DestinationSimulation::new_empty(self.chain_id, self.source_policy.clone())?.root()?;
        let mut bytes = b"RLD-EARTH-DESTINATION-POW-GENESIS\0".to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|e| e.to_string())?);
        bytes.extend(root.0);
        bytes.extend(implementation_source_hash()?.0);
        Ok(hash(&bytes))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum Command {
    Import(ProofBundle),
    FinalizedImport {
        bundle: ProofBundle,
        certificate: Box<FinalityCertificate>,
    },
    Transfer(Transfer),
}

fn commands_root(commands: &[Command]) -> Result<Hash> {
    require(
        commands.len() <= MAX_DESTINATION_COMMANDS,
        "destination command count bound",
    )?;
    let mut bytes = b"RLD-EARTH-DESTINATION-COMMANDS\0".to_vec();
    bytes.extend(serde_json::to_vec(commands).map_err(|e| e.to_string())?);
    Ok(hash(&bytes))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub chain_id: Hash,
    pub parent: Hash,
    #[serde(with = "rld_pow::decimal")]
    pub height: u128,
    pub timestamp: u64,
    pub target: Work,
    pub miner: String,
    pub commands_root: Hash,
    pub state_root: Hash,
    #[serde(with = "rld_pow::decimal")]
    pub nonce: u128,
}

impl Header {
    fn canonical_bytes(&self) -> Result<Vec<u8>> {
        key(&self.miner)?;
        let mut bytes = b"RLD-EARTH-DESTINATION-POW-HEADER\0".to_vec();
        bytes.extend(self.chain_id.0);
        bytes.extend(self.parent.0);
        bytes.extend(self.height.to_be_bytes());
        bytes.extend(self.timestamp.to_be_bytes());
        bytes.extend(self.target.to_be_bytes());
        bytes.extend(hex::decode(&self.miner).map_err(|e| e.to_string())?);
        bytes.extend(self.commands_root.0);
        bytes.extend(self.state_root.0);
        bytes.extend(self.nonce.to_be_bytes());
        Ok(bytes)
    }

    pub fn id(&self) -> Result<Hash> {
        Ok(hash(&Sha256::digest(self.canonical_bytes()?)))
    }

    pub fn work_valid(&self) -> Result<bool> {
        Ok(Work::from_be_bytes(self.id()?.0) <= self.target)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Block {
    pub header: Header,
    pub commands: Vec<Command>,
}

pub fn mine_batch(block: &mut Block, attempts: u64) -> Result<bool> {
    let mut bytes = block.header.canonical_bytes()?;
    let nonce_offset = bytes.len() - 16;
    for _ in 0..attempts {
        bytes[nonce_offset..].copy_from_slice(&block.header.nonce.to_be_bytes());
        let proof = hash(&Sha256::digest(&bytes));
        if Work::from_be_bytes(proof.0) <= block.header.target {
            return Ok(true);
        }
        block.header.nonce = block.header.nonce.checked_add(1).ok_or("nonce exhausted")?;
    }
    Ok(false)
}

#[derive(Clone, Copy)]
struct Predecessor {
    height: u128,
    timestamp: u64,
    target: Work,
}

#[derive(Clone)]
struct Entry {
    block: Block,
    cumulative_work: Work,
}

#[derive(Clone)]
pub struct DestinationPowChain {
    context: Context,
    genesis: Hash,
    base_state: DestinationSimulation,
    entries: BTreeMap<Hash, Entry>,
    tip: Hash,
    selected_state: Option<DestinationSimulation>,
    side_state: Option<(Hash, DestinationSimulation)>,
    halted: bool,
}

pub mod authorization;
pub mod receipt;
pub mod storage;

impl DestinationPowChain {
    pub fn new(context: Context) -> Result<Self> {
        let genesis = context.genesis()?;
        let base_state =
            DestinationSimulation::new_empty(context.chain_id, context.source_policy.clone())?;
        Ok(Self {
            context,
            genesis,
            base_state,
            entries: BTreeMap::new(),
            tip: genesis,
            selected_state: None,
            side_state: None,
            halted: false,
        })
    }

    pub fn genesis(&self) -> Hash {
        self.genesis
    }
    pub fn chain_id(&self) -> Hash {
        self.context.chain_id
    }
    pub fn tip(&self) -> Hash {
        self.tip
    }
    pub fn halted(&self) -> bool {
        self.halted
    }
    pub fn height(&self) -> u128 {
        self.entries
            .get(&self.tip)
            .map_or(0, |entry| entry.block.header.height)
    }
    pub fn chainwork(&self) -> Work {
        self.entries
            .get(&self.tip)
            .map_or(Work::ZERO, |entry| entry.cumulative_work)
    }
    pub fn state(&self) -> &DestinationSimulation {
        self.selected_state.as_ref().unwrap_or(&self.base_state)
    }
    pub fn block(&self, id: Hash) -> Option<&Block> {
        self.entries.get(&id).map(|entry| &entry.block)
    }
    pub fn best_blocks(&self) -> Result<Vec<&Block>> {
        let mut result = Vec::new();
        let mut parent = self.tip;
        while parent != self.genesis {
            let block = &self
                .entries
                .get(&parent)
                .ok_or("missing destination ancestor")?
                .block;
            result.push(block);
            require(
                result.len() <= MAX_TRACKED_BLOCKS,
                "destination ancestry bound",
            )?;
            parent = block.header.parent;
        }
        result.reverse();
        Ok(result)
    }

    pub fn template_time(&self, now: u64) -> Result<u64> {
        let mut times = self
            .history_at(self.tip)?
            .iter()
            .rev()
            .take(11)
            .map(|entry| entry.timestamp)
            .collect::<Vec<_>>();
        times.sort_unstable();
        Ok(now.max(times[times.len() / 2].saturating_add(1)))
    }

    fn source_network(&self, source: &CandidateChain) -> Result<()> {
        require(
            source.chain_id() == self.context.source_policy.source_chain_id
                && source.v1_tip() == self.context.source_policy.accepted_v1_tip,
            "destination source network or v1 anchor differs",
        )
    }

    /// A later source branch can invalidate a previously imported proof. Do
    /// not silently switch to a destination fork that erases the observation.
    pub fn audit_source(&mut self, source: &CandidateChain) -> Result<()> {
        require(!self.halted, "destination candidate permanently halted")?;
        self.source_network(source)?;
        let mut probe = self.state().clone();
        if let Err(error) = probe.audit_source(source) {
            self.halted = true;
            return Err(error);
        }
        Ok(())
    }

    fn state_at(&self, parent: Hash, source: &CandidateChain) -> Result<DestinationSimulation> {
        if parent == self.tip {
            return Ok(self.state().clone());
        }
        if parent == self.genesis {
            return Ok(self.base_state.clone());
        }
        if let Some((id, state)) = &self.side_state {
            if *id == parent {
                return Ok(state.clone());
            }
        }
        // Keep two working states rather than one complete asset map per
        // retained block. Historical states are rebuilt from the fixed anchor;
        // every committed root must match, including on orphaned branches.
        let mut path = Vec::new();
        let mut cursor = parent;
        while cursor != self.genesis {
            let block = &self
                .entries
                .get(&cursor)
                .ok_or("unknown destination parent")?
                .block;
            path.push(block);
            require(path.len() <= MAX_TRACKED_BLOCKS, "destination replay bound")?;
            cursor = block.header.parent;
        }
        let mut state = self.base_state.clone();
        for block in path.into_iter().rev() {
            state = self.execute_from(state, &block.header, &block.commands, source, true)?;
            require(
                state.root()? == block.header.state_root,
                "replayed destination state root mismatch",
            )?;
        }
        Ok(state)
    }

    fn work_at(&self, parent: Hash) -> Result<Work> {
        if parent == self.genesis {
            return Ok(Work::ZERO);
        }
        self.entries
            .get(&parent)
            .map(|entry| entry.cumulative_work)
            .ok_or("unknown destination parent".into())
    }

    fn history_at(&self, mut parent: Hash) -> Result<Vec<Predecessor>> {
        let mut history = Vec::new();
        while parent != self.genesis && history.len() < RETARGET_BLOCKS {
            let block = &self
                .entries
                .get(&parent)
                .ok_or("unknown destination parent")?
                .block;
            history.push(Predecessor {
                height: block.header.height,
                timestamp: block.header.timestamp,
                target: block.header.target,
            });
            parent = block.header.parent;
        }
        history.reverse();
        if parent == self.genesis {
            history.insert(
                0,
                Predecessor {
                    height: 0,
                    timestamp: self.context.started_at,
                    target: self.context.initial_target,
                },
            );
        }
        Ok(history)
    }

    fn next_header(
        &self,
        parent: Hash,
        miner: String,
        timestamp: u64,
        commands: &[Command],
    ) -> Result<Header> {
        key(&miner)?;
        let history = self.history_at(parent)?;
        let last = history.last().ok_or("missing destination predecessor")?;
        let height = last
            .height
            .checked_add(1)
            .ok_or("destination height overflow")?;
        let mut times = history
            .iter()
            .rev()
            .take(11)
            .map(|entry| entry.timestamp)
            .collect::<Vec<_>>();
        times.sort_unstable();
        require(
            timestamp > times[times.len() / 2],
            "destination timestamp below median",
        )?;
        let mut target = last.target;
        if last.height > 0 && last.height % RETARGET_BLOCKS as u128 == 0 {
            require(
                history.len() >= RETARGET_BLOCKS,
                "missing destination retarget history",
            )?;
            let begin = history[history.len() - RETARGET_BLOCKS].timestamp;
            let expected = (RETARGET_BLOCKS as u64 - 1) * BLOCK_SECONDS;
            let elapsed = last
                .timestamp
                .saturating_sub(begin)
                .clamp(expected / 4, expected * 4);
            target = scale_target(target, elapsed, expected)?;
        }
        Ok(Header {
            chain_id: self.context.chain_id,
            parent,
            height,
            timestamp,
            target,
            miner,
            commands_root: commands_root(commands)?,
            state_root: Hash::ZERO,
            nonce: 0,
        })
    }

    fn execute(
        &self,
        parent: Hash,
        header: &Header,
        commands: &[Command],
        source: &CandidateChain,
        replay: bool,
    ) -> Result<DestinationSimulation> {
        self.execute_from(
            self.state_at(parent, source)?,
            header,
            commands,
            source,
            replay,
        )
    }

    fn execute_from(
        &self,
        mut state: DestinationSimulation,
        header: &Header,
        commands: &[Command],
        source: &CandidateChain,
        replay: bool,
    ) -> Result<DestinationSimulation> {
        if !replay {
            state.audit_source(source)?;
        }
        for command in commands {
            match command {
                Command::Import(bundle) => {
                    require(
                        self.context.source_finality.is_none(),
                        "adopted destination requires finalized import",
                    )?;
                    if replay {
                        state.replay_pow_import(
                            source,
                            bundle.clone(),
                            header.height,
                            &header.miner,
                        )?;
                    } else {
                        state.import_into_pow(
                            source,
                            bundle.clone(),
                            header.height,
                            &header.miner,
                        )?;
                    }
                }
                Command::FinalizedImport {
                    bundle,
                    certificate,
                } => {
                    let trust = self
                        .context
                        .source_finality
                        .as_ref()
                        .ok_or("finalized import requires pinned Earth finality trust")?;
                    certificate.verify(source, trust.earth_adoption_id, &trust.validator_keys)?;
                    require(
                        source.is_ancestor_of(
                            bundle.source_checkpoint,
                            certificate.statement.block,
                        )?,
                        "export checkpoint is not covered by source finality",
                    )?;
                    let (finalized, _) = source
                        .finalized()
                        .ok_or("source has not installed finality")?;
                    require(
                        source.is_ancestor_of(certificate.statement.block, finalized)?,
                        "certificate is not covered by source's immutable checkpoint",
                    )?;
                    if replay {
                        state.replay_pow_import(
                            source,
                            bundle.clone(),
                            header.height,
                            &header.miner,
                        )?;
                    } else {
                        state.import_into_pow(
                            source,
                            bundle.clone(),
                            header.height,
                            &header.miner,
                        )?;
                    }
                }
                Command::Transfer(tx) => {
                    if replay {
                        state.replay_recorded_transfer(tx.clone(), header.height, &header.miner)?;
                    } else {
                        state.transfer_from_replayed_source(
                            source,
                            tx.clone(),
                            header.height,
                            &header.miner,
                        )?;
                    }
                }
            }
        }
        state.root()?;
        Ok(state)
    }

    pub fn template(
        &mut self,
        source: &CandidateChain,
        miner: String,
        timestamp: u64,
        commands: Vec<Command>,
    ) -> Result<Block> {
        self.audit_source(source)?;
        let mut header = self.next_header(self.tip, miner, timestamp, &commands)?;
        header.state_root = self
            .execute(self.tip, &header, &commands, source, false)?
            .root()?;
        let block = Block { header, commands };
        require(
            serde_json::to_vec(&block).map_err(|e| e.to_string())?.len()
                <= MAX_DESTINATION_BLOCK_BYTES,
            "destination block byte bound",
        )?;
        Ok(block)
    }

    /// Full validation precedes insertion. Equal cumulative work preserves
    /// the first selected branch; no destination native reward is minted.
    pub fn accept(&mut self, source: &CandidateChain, block: Block, now: u64) -> Result<bool> {
        self.accept_inner(source, block, now, false)
    }

    /// Reconstruct an already durable historical block even when its source
    /// checkpoint became orphaned. The store audits the selected branch and
    /// persists a halt marker after all blocks have been replayed.
    pub(crate) fn replay_block(
        &mut self,
        source: &CandidateChain,
        block: Block,
        now: u64,
    ) -> Result<bool> {
        self.accept_inner(source, block, now, true)
    }

    fn accept_inner(
        &mut self,
        source: &CandidateChain,
        block: Block,
        now: u64,
        replay: bool,
    ) -> Result<bool> {
        if replay {
            self.source_network(source)?;
        } else {
            self.audit_source(source)?;
        }
        require(
            self.entries.len() < MAX_TRACKED_BLOCKS,
            "destination tracked block capacity reached",
        )?;
        require(
            serde_json::to_vec(&block).map_err(|e| e.to_string())?.len()
                <= MAX_DESTINATION_BLOCK_BYTES,
            "destination block byte bound",
        )?;
        require(
            block.header.timestamp <= now.checked_add(7200).ok_or("clock overflow")?,
            "future destination timestamp",
        )?;
        let id = block.header.id()?;
        if self.entries.contains_key(&id) {
            return Ok(false);
        }
        let expected = self.next_header(
            block.header.parent,
            block.header.miner.clone(),
            block.header.timestamp,
            &block.commands,
        )?;
        require(
            block.header.chain_id == expected.chain_id
                && block.header.height == expected.height
                && block.header.target == expected.target
                && block.header.commands_root == expected.commands_root,
            "destination header or command root mismatch",
        )?;
        require(block.header.work_valid()?, "insufficient destination work")?;
        let state = self.execute(
            block.header.parent,
            &block.header,
            &block.commands,
            source,
            replay,
        )?;
        require(
            state.root()? == block.header.state_root,
            "destination state root mismatch",
        )?;
        let parent_work = self.work_at(block.header.parent)?;
        let work = parent_work
            .checked_add(header_work(block.header.target))
            .ok_or("destination cumulative work overflow")?;
        require(work > parent_work, "zero destination block work")?;
        let preferred = work > self.chainwork();
        self.entries.insert(
            id,
            Entry {
                block,
                cumulative_work: work,
            },
        );
        if preferred {
            self.side_state = self
                .selected_state
                .replace(state)
                .map(|prior| (self.tip, prior));
            self.tip = id;
        } else {
            self.side_state = Some((id, state));
        }
        Ok(preferred)
    }
}

#[cfg(test)]
mod tests;
