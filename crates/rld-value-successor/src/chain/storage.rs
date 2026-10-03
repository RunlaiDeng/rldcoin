//! Replay-verified durable storage for candidate and adopted successor blocks.
//! The adopted caller pins signed Earth rules and validator keys separately.

use super::finality::FinalityCertificate;
use super::{
    checkpoint::{Checkpoint, MAX_CHECKPOINT_BYTES},
    Block, CandidateChain, Command,
};
use crate::{require, Result};
use rld_core::AdmissionHash32 as Hash;
use rld_pow::{Chain, MAX_BLOCK_BYTES, MAX_TRACKED_BLOCKS};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub struct CandidateStore {
    root: PathBuf,
    _lock: File,
    chain: CandidateChain,
    selected_commands: BTreeMap<Hash, BTreeMap<u128, Hash>>,
    submitted: Vec<Command>,
    submitted_positions: BTreeMap<Hash, usize>,
    pending_submissions: BTreeSet<usize>,
    submitted_bytes: usize,
    poisoned: bool,
    finality: Option<FinalityCertificate>,
    finality_trust: Option<(Hash, Vec<String>)>,
}

const MAX_SUBMITTED_COMMANDS: usize = MAX_TRACKED_BLOCKS;
const MAX_SUBMITTED_BYTES: usize = 64 * 1024 * 1024;
const MAX_COMMAND_BYTES: usize = 32768;

pub fn command_id(command: &Command) -> Result<Hash> {
    let mut bytes = b"RLD-EARTH-SUCCESSOR-SUBMITTED-COMMAND\0".to_vec();
    bytes.extend(serde_json::to_vec(command).map_err(|error| error.to_string())?);
    Ok(Hash(Sha256::digest(bytes).into()))
}

fn io<T>(value: std::io::Result<T>) -> Result<T> {
    value.map_err(|error| error.to_string())
}

fn bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let metadata = io(fs::symlink_metadata(path))?;
    require(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= limit as u64,
        "unsafe or oversized successor file",
    )?;
    let mut bytes = Vec::new();
    io(io(File::open(path))?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes))?;
    require(bytes.len() <= limit, "successor file exceeded bound")?;
    Ok(bytes)
}

fn sync_directory(path: &Path) -> Result<()> {
    io(io(File::open(path))?.sync_all())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or("missing successor directory")?;
    let pending = path.with_extension("pending");
    if pending.exists() {
        io(fs::remove_file(&pending))?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = io(options.open(&pending))?;
    io(file.write_all(bytes))?;
    io(file.sync_all())?;
    io(fs::rename(&pending, path))?;
    sync_directory(parent)
}

fn identity(chain: &CandidateChain) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct Identity {
        format: &'static str,
        chain_id: Hash,
        v1_manifest_pin: Hash,
        v1_adoption_id: Hash,
        v1_tip: Hash,
        #[serde(with = "rld_pow::decimal")]
        v1_height: u128,
        v1_state_root: Hash,
        v1_chainwork: rld_core::AdmissionWork,
        v1_emitted: rld_core::Amount,
        successor_base_root: Hash,
        successor_source_commitment: Hash,
    }
    let commitment = chain.anchor_commitment()?;
    serde_json::to_vec(&Identity {
        format: "RLD-EARTH-UNIFIED-SUCCESSOR-STORE",
        chain_id: chain.chain_id,
        v1_manifest_pin: chain.v1_manifest_pin,
        v1_adoption_id: chain.v1_adoption_id,
        v1_tip: chain.v1_tip,
        v1_height: chain.anchor_height,
        v1_state_root: commitment.v1_root,
        v1_chainwork: chain.base_work,
        v1_emitted: commitment.emitted,
        successor_base_root: chain.base_state.root()?,
        successor_source_commitment: Hash::from_hex(
            rld_core::implementation_source::IMPLEMENTATION_SOURCE_COMMITMENT,
        )
        .map_err(|error| error.to_string())?,
    })
    .map_err(|error| error.to_string())
}

fn block_height(chain: &CandidateChain, id: Hash) -> Result<u128> {
    if id == chain.v1_tip {
        Ok(chain.anchor_height)
    } else {
        chain
            .entries
            .get(&id)
            .map(|entry| entry.block.header.height)
            .ok_or("missing successor block while comparing selected branches".into())
    }
}

fn block_parent(chain: &CandidateChain, id: Hash) -> Result<Hash> {
    chain
        .entries
        .get(&id)
        .map(|entry| entry.block.header.parent)
        .ok_or("missing successor parent while comparing selected branches".into())
}

fn indexed_commands(block: &Block) -> Result<Vec<(Hash, u128, Hash)>> {
    let id = block.header.id()?;
    block
        .commands
        .iter()
        .map(|command| Ok((command_id(command)?, block.header.height, id)))
        .collect()
}

fn selected_commands(chain: &CandidateChain) -> Result<BTreeMap<Hash, BTreeMap<u128, Hash>>> {
    let mut selected = BTreeMap::<Hash, BTreeMap<u128, Hash>>::new();
    for block in chain.best_blocks()? {
        for (command, height, block_id) in indexed_commands(block)? {
            selected
                .entry(command)
                .or_default()
                .insert(height, block_id);
        }
    }
    Ok(selected)
}

struct SelectedCommandDelta {
    removed: Vec<(Hash, u128)>,
    added: Vec<(Hash, u128, Hash)>,
}

/// Find only the blocks displaced or added by the newly preferred branch.
/// Normal extension touches just one block, regardless of total chain length.
fn selected_command_delta(
    chain: &CandidateChain,
    new_block: &Block,
) -> Result<SelectedCommandDelta> {
    let mut old = chain.tip();
    let mut new = new_block.header.parent;
    let mut removed_blocks = Vec::new();
    let mut added_blocks = Vec::new();
    while old != new {
        let old_height = block_height(chain, old)?;
        let new_height = block_height(chain, new)?;
        if old_height >= new_height {
            require(old != chain.v1_tip, "selected branch ancestry mismatch")?;
            removed_blocks.push(old);
            old = block_parent(chain, old)?;
        }
        if new_height >= old_height {
            require(new != chain.v1_tip, "candidate branch ancestry mismatch")?;
            added_blocks.push(new);
            new = block_parent(chain, new)?;
        }
    }
    let mut removed = Vec::new();
    for id in removed_blocks {
        let block = &chain
            .entries
            .get(&id)
            .ok_or("missing displaced block")?
            .block;
        removed.extend(
            indexed_commands(block)?
                .into_iter()
                .map(|(command, height, _)| (command, height)),
        );
    }
    let mut added = Vec::new();
    for id in added_blocks.into_iter().rev() {
        let block = &chain.entries.get(&id).ok_or("missing adopted block")?.block;
        added.extend(indexed_commands(block)?);
    }
    added.extend(indexed_commands(new_block)?);
    Ok(SelectedCommandDelta { removed, added })
}

impl CandidateStore {
    pub fn open(root: &Path, v1: &Chain, now: u64) -> Result<Self> {
        Self::open_inner(root, v1, now, None)
    }

    pub fn open_finalized(
        root: &Path,
        v1: &Chain,
        now: u64,
        adoption: Hash,
        validator_keys: Vec<String>,
    ) -> Result<Self> {
        require(
            !adoption.is_zero() && validator_keys.len() == 4,
            "missing adopted Earth finality trust",
        )?;
        Self::open_inner(root, v1, now, Some((adoption, validator_keys)))
    }

    fn open_inner(
        root: &Path,
        v1: &Chain,
        now: u64,
        finality_trust: Option<(Hash, Vec<String>)>,
    ) -> Result<Self> {
        let mut chain = CandidateChain::from_replayed_pow_chain(v1)?;
        if root.exists() {
            require(
                !io(fs::symlink_metadata(root))?.file_type().is_symlink(),
                "successor root cannot be a symlink",
            )?;
        }
        io(fs::create_dir_all(root))?;
        let lock_path = root.join(".candidate.lock");
        if lock_path.exists() {
            require(
                !io(fs::symlink_metadata(&lock_path))?
                    .file_type()
                    .is_symlink(),
                "successor lock cannot be a symlink",
            )?;
        }
        let lock = io(OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path))?;
        lock.try_lock()
            .map_err(|error| format!("successor directory is already owned: {error}"))?;

        let identity_path = root.join("anchor.json");
        let expected_identity = identity(&chain)?;
        if identity_path.exists() {
            require(
                bounded(&identity_path, 1536)? == expected_identity,
                "successor store anchor or implementation binding differs",
            )?;
        } else {
            require(
                !root.join("HEAD").exists() && !root.join("blocks").exists(),
                "missing successor anchor in existing store",
            )?;
            atomic_write(&identity_path, &expected_identity)?;
        }

        let block_dir = root.join("blocks");
        if block_dir.exists() {
            require(
                !io(fs::symlink_metadata(&block_dir))?
                    .file_type()
                    .is_symlink(),
                "successor block directory cannot be a symlink",
            )?;
        }
        io(fs::create_dir_all(&block_dir))?;
        sync_directory(root)?;

        // Index only replay order and location; decoded command bodies are
        // discarded until their turn so recovery need not retain every file.
        let mut blocks = Vec::new();
        for item in io(fs::read_dir(&block_dir))? {
            let item = io(item)?;
            let name = item.file_name();
            let name = name.to_str().ok_or("non-UTF8 successor filename")?;
            require(
                !io(item.file_type())?.is_symlink(),
                "symlink in successor block store",
            )?;
            if name.ends_with(".pending") {
                continue;
            }
            require(
                name.len() == 69 && name.ends_with(".json"),
                "unexpected successor block file",
            )?;
            let bytes = bounded(&item.path(), MAX_BLOCK_BYTES)?;
            let block: Block = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            require(
                name == format!("{}.json", block.header.id()?.to_hex()),
                "stored successor block name/hash mismatch",
            )?;
            require(
                bytes == serde_json::to_vec(&block).map_err(|error| error.to_string())?,
                "noncanonical stored successor block",
            )?;
            blocks.push((block.header.height, block.header.id()?, item.path()));
            require(
                blocks.len() <= MAX_TRACKED_BLOCKS,
                "successor block capacity reached",
            )?;
        }
        blocks.sort_unstable_by_key(|(height, id, _)| (*height, *id));
        for (height, id, path) in blocks {
            let bytes = bounded(&path, MAX_BLOCK_BYTES)?;
            let block: Block = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            require(
                block.header.height == height
                    && block.header.id()? == id
                    && bytes == serde_json::to_vec(&block).map_err(|error| error.to_string())?,
                "successor block changed during replay",
            )?;
            chain.accept(block, now)?;
        }

        let head = root.join("HEAD");
        if head.exists() {
            let bytes = bounded(&head, 64)?;
            let text = String::from_utf8(bytes).map_err(|error| error.to_string())?;
            let previous = Hash::from_hex(&text).map_err(|error| error.to_string())?;
            if previous != chain.v1_tip {
                let prior = chain
                    .entries
                    .get(&previous)
                    .ok_or("published successor head is missing from durable blocks")?;
                if prior.cumulative_work == chain.chainwork() {
                    chain.selected_state = Some(chain.state_at(previous)?);
                    chain.tip = previous;
                }
            }
        }
        let checkpoint_path = root.join("CHECKPOINT");
        if checkpoint_path.exists() {
            let bytes = bounded(&checkpoint_path, MAX_CHECKPOINT_BYTES)?;
            let checkpoint: Checkpoint =
                serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            require(
                bytes == serde_json::to_vec(&checkpoint).map_err(|error| error.to_string())?,
                "noncanonical successor checkpoint",
            )?;
            chain.verify_replayed_checkpoint(&checkpoint)?;
        }
        let finality_path = root.join("FINALITY");
        let finality = if finality_path.exists() {
            let (adoption, keys) = finality_trust
                .as_ref()
                .ok_or("finalized Earth store requires pinned finality trust")?;
            let bytes = bounded(&finality_path, 8192)?;
            let certificate: FinalityCertificate =
                serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            require(
                bytes == serde_json::to_vec(&certificate).map_err(|error| error.to_string())?,
                "noncanonical durable Earth finality certificate",
            )?;
            certificate.verify(&chain, *adoption, keys)?;
            chain.install_finality(certificate.statement.block)?;
            Some(certificate)
        } else {
            None
        };
        let selected_commands = selected_commands(&chain)?;
        atomic_write(&head, chain.tip().to_hex().as_bytes())?;
        // The former single-file journal is read as a prefix, subject to the
        // store's exact source-anchor binding. New submissions use immutable,
        // numbered files: admitting one no longer rewrites every earlier one.
        let submitted_path = root.join("submitted.json");
        let mut submitted: Vec<Command> = if submitted_path.exists() {
            let bytes = bounded(&submitted_path, MAX_BLOCK_BYTES)?;
            let commands = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            require(
                bytes == serde_json::to_vec(&commands).map_err(|error| error.to_string())?,
                "noncanonical submitted candidate commands",
            )?;
            commands
        } else {
            Vec::new()
        };
        let mut submitted_bytes = 0usize;
        for command in &submitted {
            submitted_bytes = submitted_bytes
                .checked_add(
                    serde_json::to_vec(command)
                        .map_err(|error| error.to_string())?
                        .len(),
                )
                .ok_or("candidate submission byte overflow")?;
        }
        let submission_dir = root.join("submissions");
        if submission_dir.exists() {
            require(
                !io(fs::symlink_metadata(&submission_dir))?
                    .file_type()
                    .is_symlink(),
                "successor submission directory cannot be a symlink",
            )?;
        }
        io(fs::create_dir_all(&submission_dir))?;
        sync_directory(root)?;
        let mut numbered = BTreeSet::new();
        for item in io(fs::read_dir(&submission_dir))? {
            let item = io(item)?;
            let name = item.file_name();
            let name = name
                .to_str()
                .ok_or("non-UTF8 successor submission filename")?;
            require(
                !io(item.file_type())?.is_symlink(),
                "symlink in successor submission store",
            )?;
            if name.ends_with(".pending") {
                continue;
            }
            require(
                name.len() == 13 && name.ends_with(".json"),
                "unexpected successor submission file",
            )?;
            let index = name[..8]
                .parse::<usize>()
                .map_err(|error| error.to_string())?;
            require(
                index >= submitted.len() && index < MAX_SUBMITTED_COMMANDS,
                "successor submission index out of range",
            )?;
            require(
                numbered.insert(index),
                "duplicate successor submission index",
            )?;
        }
        for index in submitted.len()..submitted.len() + numbered.len() {
            require(
                numbered.contains(&index),
                "gap in successor submission journal",
            )?;
            let path = submission_dir.join(format!("{index:08}.json"));
            let bytes = bounded(&path, MAX_COMMAND_BYTES)?;
            let command: Command =
                serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            require(
                bytes == serde_json::to_vec(&command).map_err(|error| error.to_string())?,
                "noncanonical successor submission",
            )?;
            submitted_bytes = submitted_bytes
                .checked_add(bytes.len())
                .ok_or("candidate submission byte overflow")?;
            require(
                submitted_bytes <= MAX_SUBMITTED_BYTES,
                "submitted candidate byte capacity reached",
            )?;
            submitted.push(command);
        }
        require(
            submitted.len() <= MAX_SUBMITTED_COMMANDS,
            "submitted candidate command capacity reached",
        )?;
        let mut submitted_positions = BTreeMap::new();
        for (index, command) in submitted.iter().enumerate() {
            require(
                submitted_positions
                    .insert(command_id(command)?, index)
                    .is_none(),
                "duplicate submitted candidate command",
            )?;
        }
        let pending_submissions = submitted_positions
            .iter()
            .filter_map(|(command, &index)| {
                (!selected_commands.contains_key(command)).then_some(index)
            })
            .collect();
        Ok(Self {
            root: root.into(),
            _lock: lock,
            chain,
            selected_commands,
            submitted,
            submitted_positions,
            pending_submissions,
            submitted_bytes,
            poisoned: false,
            finality,
            finality_trust,
        })
    }

    pub fn chain(&self) -> &CandidateChain {
        &self.chain
    }

    pub fn finality(&self) -> Option<&FinalityCertificate> {
        self.finality.as_ref()
    }

    pub fn install_finality(&mut self, certificate: FinalityCertificate) -> Result<Hash> {
        require(
            !self.poisoned,
            "successor store stopped after an I/O failure",
        )?;
        let (adoption, keys) = self
            .finality_trust
            .as_ref()
            .ok_or("Earth finality is not active in this store")?;
        certificate.verify(&self.chain, *adoption, keys)?;
        if self.finality.as_ref() == Some(&certificate) {
            return certificate.statement.id();
        }
        let mut prepared = self.chain.clone();
        prepared.install_finality(certificate.statement.block)?;
        let bytes = serde_json::to_vec(&certificate).map_err(|error| error.to_string())?;
        if let Err(error) = atomic_write(&self.root.join("FINALITY"), &bytes) {
            self.poisoned = true;
            return Err(error);
        }
        self.chain = prepared;
        let id = certificate.statement.id()?;
        self.finality = Some(certificate);
        Ok(id)
    }

    /// Persist a complete image only after the block and its state have been
    /// validated. Reopening still replays all blocks before checking this
    /// image; no block is discarded or trusted solely because it is here.
    pub fn write_replayed_checkpoint(&mut self) -> Result<Hash> {
        require(
            !self.poisoned,
            "successor store stopped after an I/O failure",
        )?;
        let checkpoint = self.chain.replayed_checkpoint()?;
        self.chain.verify_replayed_checkpoint(&checkpoint)?;
        let bytes = serde_json::to_vec(&checkpoint).map_err(|error| error.to_string())?;
        require(
            bytes.len() <= MAX_CHECKPOINT_BYTES,
            "successor checkpoint byte capacity reached",
        )?;
        if let Err(error) = atomic_write(&self.root.join("CHECKPOINT"), &bytes) {
            self.poisoned = true;
            return Err(error);
        }
        Ok(self.chain.tip())
    }

    pub fn healthy(&self) -> bool {
        !self.poisoned
    }

    pub fn submitted_count(&self) -> usize {
        self.submitted.len()
    }

    pub fn submitted_commands(&self) -> &[Command] {
        &self.submitted
    }

    /// Commands absent from the selected branch, including ones displaced by
    /// a reorganization. A peer must still validate each command itself.
    pub fn pending_commands(&self) -> Result<Vec<&Command>> {
        Ok(self
            .pending_submissions
            .iter()
            .map(|&index| &self.submitted[index])
            .collect())
    }

    pub fn has_submission(&self, id: Hash) -> Result<bool> {
        Ok(self.submitted_positions.contains_key(&id))
    }

    /// Selected-branch inclusion only, never irreversible finality.
    pub fn selected_inclusion(&self, id: Hash) -> Result<Option<(Hash, u128, u128)>> {
        let Some((&height, &block)) = self
            .selected_commands
            .get(&id)
            .and_then(|occurrences| occurrences.first_key_value())
        else {
            return Ok(None);
        };
        let confirmations = self
            .chain
            .height()
            .checked_sub(height)
            .and_then(|n| n.checked_add(1))
            .ok_or("candidate command confirmation overflow")?;
        Ok(Some((block, height, confirmations)))
    }

    /// Rebuild the mineable command set from the durable submission history.
    /// A branch reorganization can make an earlier included command pending
    /// again. Invalid or expired commands stay in the journal for inspection,
    /// but are never silently added to a block template.
    pub fn mineable_commands(&self, miner: &str, timestamp: u64) -> Result<Vec<Command>> {
        let mut chosen = Vec::new();
        for command in self.pending_commands()? {
            if chosen.len() >= rld_pow::MAX_TRANSACTIONS {
                break;
            }
            let mut next = chosen.clone();
            next.push(command.clone());
            if self
                .chain
                .template(miner.to_owned(), timestamp, next)
                .is_ok()
            {
                chosen.push(command.clone());
            }
        }
        Ok(chosen)
    }

    /// Admit only a command that is valid with the currently mineable queue,
    /// then fsync its canonical durable journal before acknowledging it.
    pub fn submit_command(
        &mut self,
        command: Command,
        miner: &str,
        timestamp: u64,
    ) -> Result<(Hash, bool)> {
        require(
            !self.poisoned,
            "successor store stopped after an I/O failure",
        )?;
        let bytes = serde_json::to_vec(&command).map_err(|error| error.to_string())?;
        require(
            bytes.len() <= MAX_COMMAND_BYTES,
            "submitted candidate command byte bound",
        )?;
        let id = command_id(&command)?;
        if self.submitted_positions.contains_key(&id) {
            return Ok((id, false));
        }
        if self.selected_inclusion(id)?.is_some() {
            return Ok((id, false));
        }
        require(
            self.submitted.len() < MAX_SUBMITTED_COMMANDS,
            "submitted candidate command capacity reached",
        )?;
        require(
            self.submitted_bytes
                .checked_add(bytes.len())
                .is_some_and(|total| total <= MAX_SUBMITTED_BYTES),
            "submitted candidate byte capacity reached",
        )?;
        let mut candidate = self.mineable_commands(miner, timestamp)?;
        candidate.push(command.clone());
        self.chain
            .template(miner.to_owned(), timestamp, candidate)?;
        let path = self
            .root
            .join("submissions")
            .join(format!("{:08}.json", self.submitted.len()));
        if let Err(error) = atomic_write(&path, &bytes) {
            self.poisoned = true;
            return Err(error);
        }
        self.submitted_bytes += bytes.len();
        self.submitted_positions.insert(id, self.submitted.len());
        self.pending_submissions.insert(self.submitted.len());
        self.submitted.push(command);
        Ok((id, true))
    }

    /// Fully validate a staged block; publish the immutable block and new
    /// head before making it visible through this process.
    pub fn accept(&mut self, block: Block, now: u64) -> Result<bool> {
        require(
            !self.poisoned,
            "successor store stopped after an I/O failure; restart for replay",
        )?;
        let id = block.header.id()?;
        if self.chain.block(id).is_some() {
            return Ok(false);
        }
        let Some(prepared) = self.chain.prepare(block.clone(), now)? else {
            return Ok(false);
        };
        let preferred = prepared.preferred;
        let delta = if preferred {
            Some(selected_command_delta(&self.chain, &block)?)
        } else {
            None
        };
        if let Some(delta) = &delta {
            require(
                delta.removed.iter().all(|(command, height)| {
                    self.selected_commands
                        .get(command)
                        .is_some_and(|occurrences| occurrences.contains_key(height))
                }),
                "selected command index differs from replayed branch",
            )?;
        }
        let bytes = serde_json::to_vec(&block).map_err(|error| error.to_string())?;
        let result = (|| {
            atomic_write(
                &self
                    .root
                    .join("blocks")
                    .join(format!("{}.json", id.to_hex())),
                &bytes,
            )?;
            if preferred {
                atomic_write(&self.root.join("HEAD"), id.to_hex().as_bytes())?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.poisoned = true;
            return Err(error);
        }
        self.chain.commit(prepared);
        if let Some(delta) = delta {
            let changed = delta
                .removed
                .iter()
                .map(|(command, _)| *command)
                .chain(delta.added.iter().map(|(command, _, _)| *command))
                .collect::<BTreeSet<_>>();
            for (command, height) in delta.removed {
                let occurrences = self
                    .selected_commands
                    .get_mut(&command)
                    .expect("selected command index lost displaced block");
                occurrences.remove(&height);
                if occurrences.is_empty() {
                    self.selected_commands.remove(&command);
                }
            }
            for (command, height, block) in delta.added {
                self.selected_commands
                    .entry(command)
                    .or_default()
                    .insert(height, block);
            }
            for command in changed {
                if let Some(&index) = self.submitted_positions.get(&command) {
                    if self.selected_commands.contains_key(&command) {
                        self.pending_submissions.remove(&index);
                    } else {
                        self.pending_submissions.insert(index);
                    }
                }
            }
        }
        Ok(preferred)
    }
}

#[cfg(test)]
mod tests;
