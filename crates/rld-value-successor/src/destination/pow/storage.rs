//! Replay-verified file store for destination PoW blocks.
//! It preserves blocks, a selected head and an irreversible local halt marker.

use super::receipt::{ImportInclusionReceipt, InclusionPolicy, ObservedImport};
use super::{
    implementation_source_hash, Block, Command, Context, DestinationPowChain,
    MAX_DESTINATION_BLOCK_BYTES,
};
use crate::{chain::CandidateChain, require, Result};
use rld_core::AdmissionHash32 as Hash;
use rld_cross_region::ProofBundle;
use rld_pow::MAX_TRACKED_BLOCKS;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const HALTED_MARKER: &[u8] = b"RLD-DESTINATION-POW-CANDIDATE-HALTED-V2\n";
const MAX_LEGACY_SUBMITTED_COMMANDS: usize = 32;
const MAX_LEGACY_SUBMITTED_BYTES: usize = MAX_DESTINATION_BLOCK_BYTES * 2;
const MAX_SUBMITTED_COMMANDS: usize = MAX_TRACKED_BLOCKS;
const MAX_SUBMITTED_BYTES: usize = 64 * 1024 * 1024;

pub struct DestinationPowStore {
    root: PathBuf,
    _lock: File,
    chain: DestinationPowChain,
    submitted: Vec<Command>,
    submitted_ids: BTreeSet<Hash>,
    submitted_bytes: usize,
    poisoned: bool,
}

fn command_id(command: &Command) -> Result<Hash> {
    let mut bytes = b"RLD-EARTH-DESTINATION-SUBMITTED-COMMAND\0".to_vec();
    bytes.extend(serde_json::to_vec(command).map_err(|error| error.to_string())?);
    Ok(Hash(Sha256::digest(bytes).into()))
}

fn io<T>(result: std::io::Result<T>) -> Result<T> {
    result.map_err(|error| error.to_string())
}

fn bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let metadata = io(fs::symlink_metadata(path))?;
    require(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= limit as u64,
        "unsafe or oversized destination PoW file",
    )?;
    let mut bytes = Vec::new();
    io(io(File::open(path))?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes))?;
    require(bytes.len() <= limit, "destination PoW file exceeded bound")?;
    Ok(bytes)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or("destination PoW file needs a directory")?;
    let pending = path.with_extension("pending");
    if pending.exists() {
        require(
            !io(fs::symlink_metadata(&pending))?.file_type().is_symlink(),
            "unsafe pending destination PoW file",
        )?;
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
    io(io(File::open(parent))?.sync_all())
}

fn identity(context: &Context) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct Identity<'a> {
        format: &'static str,
        context: &'a Context,
        genesis: Hash,
        implementation_source_sha256: Hash,
    }
    serde_json::to_vec(&Identity {
        format: "RLD-EARTH-DESTINATION-POW-STORE",
        context,
        genesis: context.genesis()?,
        implementation_source_sha256: implementation_source_hash()?,
    })
    .map_err(|error| error.to_string())
}

impl DestinationPowStore {
    pub fn open(root: &Path, context: Context, source: &CandidateChain, now: u64) -> Result<Self> {
        let mut chain = DestinationPowChain::new(context.clone())?;
        if root.exists() {
            require(
                !io(fs::symlink_metadata(root))?.file_type().is_symlink(),
                "destination PoW root cannot be a symlink",
            )?;
        }
        io(fs::create_dir_all(root))?;
        let lock_path = root.join(".destination-pow.lock");
        if lock_path.exists() {
            require(
                !io(fs::symlink_metadata(&lock_path))?
                    .file_type()
                    .is_symlink(),
                "destination PoW lock cannot be a symlink",
            )?;
        }
        let lock = io(OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path))?;
        lock.try_lock()
            .map_err(|error| format!("destination PoW directory already owned: {error}"))?;
        let identity_path = root.join("identity.json");
        let expected_identity = identity(&context)?;
        if identity_path.exists() {
            require(
                bounded(&identity_path, 4096)? == expected_identity,
                "destination PoW store belongs to another context",
            )?;
            if !root.join("HEAD").exists() {
                require(
                    !root.join("blocks").exists() && !root.join("HALTED").exists(),
                    "missing destination PoW head with stored data",
                )?;
                atomic_write(&root.join("HEAD"), chain.genesis().to_hex().as_bytes())?;
            }
        } else {
            require(
                !root.join("blocks").exists()
                    && !root.join("HEAD").exists()
                    && !root.join("HALTED").exists()
                    && !root.join("submitted.json").exists()
                    && !root.join("submissions").exists(),
                "missing identity in existing destination PoW store",
            )?;
            atomic_write(&identity_path, &expected_identity)?;
            atomic_write(&root.join("HEAD"), chain.genesis().to_hex().as_bytes())?;
        }
        let block_dir = root.join("blocks");
        if block_dir.exists() {
            require(
                !io(fs::symlink_metadata(&block_dir))?
                    .file_type()
                    .is_symlink(),
                "destination PoW blocks cannot be a symlink",
            )?;
        }
        io(fs::create_dir_all(&block_dir))?;
        io(io(File::open(root))?.sync_all())?;
        // Keep a compact replay index instead of all decoded proof bundles.
        let mut blocks = Vec::new();
        for item in io(fs::read_dir(&block_dir))? {
            let item = io(item)?;
            require(
                !io(item.file_type())?.is_symlink(),
                "symlink in destination PoW blocks",
            )?;
            let name = item.file_name();
            let name = name.to_str().ok_or("non-UTF8 destination PoW block name")?;
            if name.ends_with(".pending") {
                continue;
            }
            require(
                name.len() == 69 && name.ends_with(".json"),
                "unexpected destination PoW block file",
            )?;
            let bytes = bounded(&item.path(), MAX_DESTINATION_BLOCK_BYTES)?;
            let block: Block = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            require(
                name == format!("{}.json", block.header.id()?.to_hex())
                    && bytes == serde_json::to_vec(&block).map_err(|e| e.to_string())?,
                "noncanonical or misnamed destination PoW block",
            )?;
            blocks.push((block.header.height, block.header.id()?, item.path()));
            require(
                blocks.len() <= MAX_TRACKED_BLOCKS,
                "destination PoW stored block capacity reached",
            )?;
        }
        blocks.sort_unstable_by_key(|(height, id, _)| (*height, *id));
        for (height, id, path) in blocks {
            let bytes = bounded(&path, MAX_DESTINATION_BLOCK_BYTES)?;
            let block: Block = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            require(
                block.header.height == height
                    && block.header.id()? == id
                    && bytes == serde_json::to_vec(&block).map_err(|error| error.to_string())?,
                "destination PoW block changed during replay",
            )?;
            chain.replay_block(source, block, now)?;
        }
        let head_path = root.join("HEAD");
        let previous_text =
            String::from_utf8(bounded(&head_path, 64)?).map_err(|error| error.to_string())?;
        let previous = Hash::from_hex(&previous_text).map_err(|error| error.to_string())?;
        if previous != chain.genesis() {
            let prior = chain
                .entries
                .get(&previous)
                .ok_or("published destination head missing from durable blocks")?;
            if prior.cumulative_work == chain.chainwork() {
                chain.selected_state = Some(chain.state_at(previous, source)?);
                chain.tip = previous;
            }
        }
        if previous != chain.tip() {
            atomic_write(&head_path, chain.tip().to_hex().as_bytes())?;
        }
        let halted_path = root.join("HALTED");
        chain.source_network(source)?;
        if halted_path.exists() {
            require(
                bounded(&halted_path, HALTED_MARKER.len())? == HALTED_MARKER,
                "invalid destination PoW halt marker",
            )?;
            chain.halted = true;
        } else if let Err(error) = chain.audit_source(source) {
            if !chain.halted {
                return Err(error);
            }
            atomic_write(&halted_path, HALTED_MARKER)?;
        }
        // The old single-file journal is a bounded prefix. Each new command
        // gets an immutable numbered file, so admission never rewrites every
        // earlier command and a restart can reject gaps or modified entries.
        let submitted_path = root.join("submitted.json");
        let mut submitted: Vec<Command> = if submitted_path.exists() {
            let bytes = bounded(&submitted_path, MAX_LEGACY_SUBMITTED_BYTES)?;
            let commands = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            require(
                bytes == serde_json::to_vec(&commands).map_err(|error| error.to_string())?,
                "noncanonical destination submitted commands",
            )?;
            commands
        } else {
            Vec::new()
        };
        require(
            submitted.len() <= MAX_LEGACY_SUBMITTED_COMMANDS,
            "destination legacy submitted command capacity exceeded",
        )?;
        let mut submitted_bytes = 0usize;
        for command in &submitted {
            submitted_bytes = submitted_bytes
                .checked_add(
                    serde_json::to_vec(command)
                        .map_err(|error| error.to_string())?
                        .len(),
                )
                .ok_or("destination submission byte overflow")?;
        }
        let submission_dir = root.join("submissions");
        if submission_dir.exists() {
            require(
                !io(fs::symlink_metadata(&submission_dir))?
                    .file_type()
                    .is_symlink(),
                "destination submissions cannot be a symlink",
            )?;
        }
        io(fs::create_dir_all(&submission_dir))?;
        io(io(File::open(root))?.sync_all())?;
        let mut numbered = BTreeSet::new();
        for item in io(fs::read_dir(&submission_dir))? {
            let item = io(item)?;
            require(
                !io(item.file_type())?.is_symlink(),
                "symlink in destination submissions",
            )?;
            let name = item.file_name();
            let name = name
                .to_str()
                .ok_or("non-UTF8 destination submission name")?;
            if name.ends_with(".pending") {
                continue;
            }
            require(
                name.len() == 13 && name.ends_with(".json"),
                "unexpected destination submission file",
            )?;
            let index = name[..8]
                .parse::<usize>()
                .map_err(|error| error.to_string())?;
            require(
                index >= submitted.len() && index < MAX_SUBMITTED_COMMANDS,
                "destination submission index out of range",
            )?;
            require(
                numbered.insert(index),
                "duplicate destination submission index",
            )?;
        }
        for index in submitted.len()..submitted.len() + numbered.len() {
            require(
                numbered.contains(&index),
                "gap in destination submission journal",
            )?;
            let bytes = bounded(
                &submission_dir.join(format!("{index:08}.json")),
                MAX_DESTINATION_BLOCK_BYTES,
            )?;
            let command: Command =
                serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            require(
                bytes == serde_json::to_vec(&command).map_err(|error| error.to_string())?,
                "noncanonical destination submission",
            )?;
            submitted_bytes = submitted_bytes
                .checked_add(bytes.len())
                .ok_or("destination submission byte overflow")?;
            require(
                submitted_bytes <= MAX_SUBMITTED_BYTES,
                "destination submission byte capacity reached",
            )?;
            submitted.push(command);
        }
        let mut ids = BTreeSet::new();
        for command in &submitted {
            require(
                ids.insert(command_id(command)?),
                "duplicate destination submitted command",
            )?;
        }
        Ok(Self {
            root: root.into(),
            _lock: lock,
            chain,
            submitted,
            submitted_ids: ids,
            submitted_bytes,
            poisoned: false,
        })
    }

    pub fn chain(&self) -> &DestinationPowChain {
        &self.chain
    }

    pub fn healthy(&self) -> bool {
        !self.poisoned
    }

    pub fn submitted_count(&self) -> usize {
        self.submitted.len()
    }

    pub fn selected_inclusion(&self, id: Hash) -> Result<Option<(Hash, u128, u128)>> {
        for block in self.chain.best_blocks()? {
            for command in &block.commands {
                if command_id(command)? == id {
                    let confirmations = self
                        .chain
                        .height()
                        .checked_sub(block.header.height)
                        .and_then(|distance| distance.checked_add(1))
                        .ok_or("destination inclusion height mismatch")?;
                    return Ok(Some((
                        block.header.id()?,
                        block.header.height,
                        confirmations,
                    )));
                }
            }
        }
        Ok(None)
    }

    pub fn mineable_commands(
        &mut self,
        source: &CandidateChain,
        miner: &str,
        timestamp: u64,
    ) -> Result<Vec<Command>> {
        self.audit_source(source)?;
        let mut included = BTreeSet::new();
        for block in self.chain.best_blocks()? {
            for command in &block.commands {
                included.insert(command_id(command)?);
            }
        }
        let mut chosen = Vec::new();
        for command in &self.submitted {
            if included.contains(&command_id(command)?) {
                continue;
            }
            let mut next = chosen.clone();
            next.push(command.clone());
            let mut probe = self.chain.clone();
            if probe
                .template(source, miner.to_owned(), timestamp, next)
                .is_ok()
            {
                chosen.push(command.clone());
            }
        }
        Ok(chosen)
    }

    pub fn submit_command(
        &mut self,
        source: &CandidateChain,
        command: Command,
        miner: &str,
        timestamp: u64,
    ) -> Result<(Hash, bool)> {
        require(
            !self.poisoned,
            "destination PoW store stopped after I/O failure",
        )?;
        self.audit_source(source)?;
        let id = command_id(&command)?;
        if self.submitted_ids.contains(&id) {
            return Ok((id, false));
        }
        let bytes = serde_json::to_vec(&command).map_err(|error| error.to_string())?;
        require(
            bytes.len() <= MAX_DESTINATION_BLOCK_BYTES,
            "destination submitted command byte bound",
        )?;
        require(
            self.submitted.len() < MAX_SUBMITTED_COMMANDS,
            "destination submitted command capacity reached",
        )?;
        require(
            self.submitted_bytes
                .checked_add(bytes.len())
                .is_some_and(|total| total <= MAX_SUBMITTED_BYTES),
            "destination submitted journal byte bound",
        )?;
        let mut candidate = self.mineable_commands(source, miner, timestamp)?;
        candidate.push(command.clone());
        let mut probe = self.chain.clone();
        probe.template(source, miner.to_owned(), timestamp, candidate)?;
        let path = self
            .root
            .join("submissions")
            .join(format!("{:08}.json", self.submitted.len()));
        if let Err(error) = atomic_write(&path, &bytes) {
            self.poisoned = true;
            return Err(error);
        }
        self.submitted_bytes += bytes.len();
        self.submitted_ids.insert(id);
        self.submitted.push(command);
        Ok((id, true))
    }

    fn persist_halt(&mut self, prepared: DestinationPowChain) -> Result<()> {
        if let Err(error) = atomic_write(&self.root.join("HALTED"), HALTED_MARKER) {
            self.poisoned = true;
            return Err(error);
        }
        self.chain = prepared;
        Ok(())
    }

    pub fn audit_source(&mut self, source: &CandidateChain) -> Result<()> {
        require(
            !self.poisoned,
            "destination PoW store stopped after I/O failure",
        )?;
        let mut prepared = self.chain.clone();
        match prepared.audit_source(source) {
            Ok(()) => Ok(()),
            Err(error) if prepared.halted => {
                self.persist_halt(prepared)?;
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    /// A durable block is already on disk before its inclusion can be
    /// observed. Source reorganization audits persist the local halt marker.
    pub fn observe_import(
        &mut self,
        source: &CandidateChain,
        bundle: &ProofBundle,
        policy: &InclusionPolicy,
    ) -> Result<ImportInclusionReceipt> {
        self.audit_source(source)?;
        self.chain.observe_import(source, bundle, policy)
    }

    pub fn verify_import_receipt(
        &mut self,
        source: &CandidateChain,
        bundle: &ProofBundle,
        policy: &InclusionPolicy,
        receipt: &ImportInclusionReceipt,
    ) -> Result<ObservedImport> {
        self.audit_source(source)?;
        self.chain
            .verify_import_receipt(source, bundle, policy, receipt)
    }

    pub fn template(
        &mut self,
        source: &CandidateChain,
        miner: String,
        timestamp: u64,
        commands: Vec<Command>,
    ) -> Result<Block> {
        require(
            !self.poisoned,
            "destination PoW store stopped after I/O failure",
        )?;
        let mut prepared = self.chain.clone();
        match prepared.template(source, miner, timestamp, commands) {
            Ok(block) => Ok(block),
            Err(error) if prepared.halted => {
                self.persist_halt(prepared)?;
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    pub fn accept(&mut self, source: &CandidateChain, block: Block, now: u64) -> Result<bool> {
        require(
            !self.poisoned,
            "destination PoW store stopped after I/O failure",
        )?;
        let id = block.header.id()?;
        if self.chain.block(id).is_some() {
            self.audit_source(source)?;
            return Ok(false);
        }
        let mut prepared = self.chain.clone();
        let preferred = match prepared.accept(source, block.clone(), now) {
            Ok(preferred) => preferred,
            Err(error) if prepared.halted => {
                self.persist_halt(prepared)?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        let bytes = serde_json::to_vec(&block).map_err(|error| error.to_string())?;
        let persisted = (|| {
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
        if let Err(error) = persisted {
            self.poisoned = true;
            return Err(error);
        }
        self.chain = prepared;
        Ok(preferred)
    }
}
