//! Durable event replay for the isolated destination simulation only.
//!
//! This is not a destination consensus store or authority to import on a live
//! regional chain. It preserves duplicate-import history and a halted marker.

use super::ack::CandidateImportAck;
use super::{DestinationSimulation, SimulatedReceipt, SimulatedTransferReceipt, MAX_EVENTS};
use crate::{
    chain::{CandidateChain, ObservationPolicy},
    hash, require, Result,
};
use rld_core::AdmissionHash32 as Hash;
use rld_cross_region::{ProofBundle, MAX_BUNDLE_BYTES};
use rld_pow::Transfer;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const MAX_EVENT_BYTES: usize = MAX_BUNDLE_BYTES + 4096;
const HALTED_MARKER: &[u8] = b"RLD-DESTINATION-SIMULATION-HALTED-V1\n";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportEvent {
    sequence: u64,
    bundle: ProofBundle,
    #[serde(with = "rld_pow::decimal")]
    destination_height: u128,
    miner: String,
    receipt_id: Hash,
    resulting_root: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferEvent {
    sequence: u64,
    transaction: Transfer,
    #[serde(with = "rld_pow::decimal")]
    destination_height: u128,
    miner: String,
    transaction_id: Hash,
    resulting_root: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum Event {
    Import(ImportEvent),
    Transfer(TransferEvent),
}

impl Event {
    fn sequence(&self) -> u64 {
        match self {
            Self::Import(event) => event.sequence,
            Self::Transfer(event) => event.sequence,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Head {
    sequence: u64,
    root: Hash,
    halted: bool,
}

fn head_for(state: &DestinationSimulation) -> Result<Head> {
    Ok(Head {
        sequence: state.event_count,
        root: state.root()?,
        halted: state.halted,
    })
}

fn root_with_halt(state: &DestinationSimulation, halted: bool) -> Result<Hash> {
    let mut copy = state.clone();
    copy.halted = halted;
    copy.root()
}

pub struct DestinationStore {
    root: PathBuf,
    _lock: File,
    state: DestinationSimulation,
    imports: BTreeMap<Hash, SimulatedReceipt>,
    poisoned: bool,
}

fn io<T>(value: std::io::Result<T>) -> Result<T> {
    value.map_err(|error| error.to_string())
}

fn bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let metadata = io(fs::symlink_metadata(path))?;
    require(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= limit as u64,
        "unsafe or oversized simulated destination file",
    )?;
    let mut bytes = Vec::new();
    io(io(File::open(path))?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes))?;
    require(
        bytes.len() <= limit,
        "simulated destination file exceeded bound",
    )?;
    Ok(bytes)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or("missing simulated destination directory")?;
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
    io(io(File::open(parent))?.sync_all())
}

fn identity(chain_id: Hash, policy: &ObservationPolicy) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct Identity<'a> {
        format: &'static str,
        destination_chain_id: Hash,
        source_chain_id: &'a Hash,
        accepted_v1_tip: &'a Hash,
        minimum_confirmations: String,
        minimum_cumulative_work: String,
    }
    serde_json::to_vec(&Identity {
        format: "RLD-DESTINATION-IMPORT-STORE-SIMULATION-V1",
        destination_chain_id: chain_id,
        source_chain_id: &policy.source_chain_id,
        accepted_v1_tip: &policy.accepted_v1_tip,
        minimum_confirmations: policy.minimum_confirmations.to_string(),
        minimum_cumulative_work: policy.minimum_cumulative_work.to_hex(),
    })
    .map_err(|error| error.to_string())
}

impl DestinationStore {
    pub fn open(
        root: &Path,
        destination_chain_id: Hash,
        policy: ObservationPolicy,
        source: &CandidateChain,
    ) -> Result<Self> {
        let mut state = DestinationSimulation::new_empty(destination_chain_id, policy.clone())?;
        if root.exists() {
            require(
                !io(fs::symlink_metadata(root))?.file_type().is_symlink(),
                "simulated destination root cannot be a symlink",
            )?;
        }
        io(fs::create_dir_all(root))?;
        let lock_path = root.join(".destination.lock");
        if lock_path.exists() {
            require(
                !io(fs::symlink_metadata(&lock_path))?
                    .file_type()
                    .is_symlink(),
                "simulated destination lock cannot be a symlink",
            )?;
        }
        let lock = io(OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path))?;
        lock.try_lock()
            .map_err(|error| format!("simulated destination directory already owned: {error}"))?;

        let identity_path = root.join("identity.json");
        let expected_identity = identity(destination_chain_id, &policy)?;
        let identity_existing = identity_path.exists();
        if identity_existing {
            require(
                bounded(&identity_path, 512)? == expected_identity,
                "simulated destination store belongs to another policy",
            )?;
        } else {
            require(
                !root.join("events").exists()
                    && !root.join("HEAD").exists()
                    && !root.join("HALTED").exists()
                    && !root.join("OPERATOR").exists(),
                "missing identity in existing destination store",
            )?;
            atomic_write(&identity_path, &expected_identity)?;
        }

        let event_dir = root.join("events");
        if event_dir.exists() {
            require(
                !io(fs::symlink_metadata(&event_dir))?
                    .file_type()
                    .is_symlink(),
                "simulated destination events cannot be a symlink",
            )?;
        }
        io(fs::create_dir_all(&event_dir))?;
        io(io(File::open(root))?.sync_all())?;
        let head_path = root.join("HEAD");
        let previous_head = if head_path.exists() {
            let bytes = bounded(&head_path, 256)?;
            let value: Head = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            require(
                bytes == serde_json::to_vec(&value).map_err(|error| error.to_string())?,
                "noncanonical simulated destination head",
            )?;
            Some(value)
        } else {
            None
        };
        let mut events = Vec::new();
        for item in io(fs::read_dir(&event_dir))? {
            let item = io(item)?;
            require(
                !io(item.file_type())?.is_symlink(),
                "symlink in simulated import log",
            )?;
            let name = item.file_name();
            let name = name.to_str().ok_or("non-UTF8 simulated import filename")?;
            if name.ends_with(".pending") {
                continue;
            }
            let (sequence_text, hash_text) = name
                .strip_suffix(".json")
                .and_then(|stem| stem.split_once('-'))
                .ok_or("unexpected simulated import file")?;
            require(
                sequence_text.len() == 8
                    && hash_text.len() == 64
                    && sequence_text.bytes().all(|b| b.is_ascii_digit()),
                "invalid simulated import filename",
            )?;
            let sequence: u64 = sequence_text
                .parse()
                .map_err(|_| "invalid import sequence")?;
            let bytes = bounded(&item.path(), MAX_EVENT_BYTES)?;
            require(
                hash_text == hash(&bytes).to_hex(),
                "simulated import event hash mismatch",
            )?;
            let event: Event = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            require(
                bytes == serde_json::to_vec(&event).map_err(|error| error.to_string())?
                    && event.sequence() == sequence,
                "noncanonical simulated import event",
            )?;
            events.push((sequence, event));
            require(
                events.len() <= MAX_EVENTS as usize,
                "simulated destination event capacity reached",
            )?;
        }
        events.sort_by_key(|(sequence, _)| *sequence);
        require(
            previous_head.is_some() || (!identity_existing && events.is_empty()),
            "missing head for stored simulated imports",
        )?;
        if let Some(head) = &previous_head {
            if head.sequence == 0 {
                require(
                    head.root == root_with_halt(&state, head.halted)?,
                    "simulated destination head does not match empty state",
                )?;
            }
        }
        let mut imports = BTreeMap::new();
        for (index, (sequence, event)) in events.into_iter().enumerate() {
            require(
                sequence == index as u64 + 1,
                "gap or duplicate in simulated import log",
            )?;
            match event {
                Event::Import(event) => {
                    let bundle = event.bundle.clone();
                    let receipt = state.replay_recorded_import(
                        source,
                        event.bundle,
                        event.destination_height,
                        &event.miner,
                    )?;
                    require(
                        receipt.id == event.receipt_id
                            && receipt.state_root == event.resulting_root,
                        "simulated import replay differs from durable receipt",
                    )?;
                    require(
                        imports.insert(bundle.id()?, receipt).is_none(),
                        "duplicate simulated import bundle",
                    )?;
                }
                Event::Transfer(event) => {
                    let receipt = state.replay_recorded_transfer(
                        event.transaction,
                        event.destination_height,
                        &event.miner,
                    )?;
                    require(
                        receipt.transaction == event.transaction_id
                            && receipt.state_root == event.resulting_root,
                        "simulated transfer replay differs from durable receipt",
                    )?;
                }
            }
            if previous_head
                .as_ref()
                .is_some_and(|head| head.sequence == sequence)
            {
                let head = previous_head.as_ref().ok_or("missing import head")?;
                require(
                    head.root == root_with_halt(&state, head.halted)?,
                    "simulated destination head differs from committed import",
                )?;
            }
        }
        if let Some(head) = &previous_head {
            require(
                head.sequence <= state.event_count,
                "simulated destination committed import is missing",
            )?;
            require(
                head.sequence == state.event_count || !head.halted,
                "events appeared after simulated destination halt",
            )?;
        }
        let halted_path = root.join("HALTED");
        let has_halt_marker = halted_path.exists();
        if has_halt_marker {
            require(
                bounded(&halted_path, HALTED_MARKER.len())? == HALTED_MARKER,
                "invalid simulated destination halt marker",
            )?;
            state.halted = true;
        } else if previous_head.as_ref().is_some_and(|head| head.halted) {
            state.halted = true;
            atomic_write(&halted_path, HALTED_MARKER)?;
        } else if state.audit_source(source).is_err() {
            atomic_write(&halted_path, HALTED_MARKER)?;
        }
        let current_head = head_for(&state)?;
        if previous_head.as_ref() != Some(&current_head) {
            atomic_write(
                &head_path,
                &serde_json::to_vec(&current_head).map_err(|error| error.to_string())?,
            )?;
        }
        Ok(Self {
            root: root.into(),
            _lock: lock,
            state,
            imports,
            poisoned: false,
        })
    }

    pub fn state(&self) -> &DestinationSimulation {
        &self.state
    }

    pub fn healthy(&self) -> bool {
        !self.poisoned
    }

    /// Validate on a temporary state and sync the event before exposing its
    /// simulated output or receipt to this process.
    pub fn import(
        &mut self,
        source: &CandidateChain,
        bundle: ProofBundle,
        destination_height: u128,
        miner: &str,
    ) -> Result<SimulatedReceipt> {
        require(
            !self.poisoned,
            "simulated destination stopped after I/O failure",
        )?;
        require(!self.state.halted, "simulated destination is halted")?;
        self.audit_source(source)?;
        let mut prepared = self.state.clone();
        let receipt = prepared.import_from_replayed_source(
            source,
            bundle.clone(),
            destination_height,
            miner,
        )?;
        let bundle_id = bundle.id()?;
        let sequence = self.state.event_count + 1;
        let event = ImportEvent {
            sequence,
            bundle: bundle.clone(),
            destination_height,
            miner: miner.into(),
            receipt_id: receipt.id,
            resulting_root: receipt.state_root,
        };
        let bytes = serde_json::to_vec(&event).map_err(|error| error.to_string())?;
        require(
            bytes.len() <= MAX_EVENT_BYTES,
            "simulated import event too large",
        )?;
        let filename = format!("{sequence:08}-{}.json", hash(&bytes).to_hex());
        let path = self.root.join("events").join(filename);
        require(!path.exists(), "simulated import event collision")?;
        let persisted = (|| {
            atomic_write(&path, &bytes)?;
            atomic_write(
                &self.root.join("HEAD"),
                &serde_json::to_vec(&head_for(&prepared)?).map_err(|error| error.to_string())?,
            )
        })();
        if let Err(error) = persisted {
            self.poisoned = true;
            return Err(error);
        }
        self.state = prepared;
        self.imports.insert(bundle_id, receipt.clone());
        Ok(receipt)
    }

    /// Idempotent one-shot candidate handoff. New simulated heights are
    /// derived from the durable local event sequence, never trusted from a
    /// remote courier. This is still not a destination block height.
    pub fn import_or_reuse(
        &mut self,
        source: &CandidateChain,
        bundle: ProofBundle,
        miner: &str,
    ) -> Result<SimulatedReceipt> {
        require(
            !self.poisoned,
            "simulated destination stopped after I/O failure",
        )?;
        self.audit_source(source)?;
        if let Some(receipt) = self.imports.get(&bundle.id()?) {
            return Ok(receipt.clone());
        }
        let height = self
            .state
            .event_count
            .checked_add(1)
            .ok_or("candidate destination event height overflow")? as u128;
        self.import(source, bundle, height, miner)
    }

    /// A signed claim about a previously fsynced candidate import event.
    /// The exact source proof is rechecked before signing; a reorg halts the
    /// store rather than issuing a fresh acknowledgment.
    pub fn attest_import(
        &mut self,
        source: &CandidateChain,
        bundle: &ProofBundle,
        operator_public: &str,
        operator_secret: &str,
    ) -> Result<CandidateImportAck> {
        require(
            !self.poisoned,
            "simulated destination stopped after I/O failure",
        )?;
        self.audit_source(source)?;
        let receipt = self
            .imports
            .get(&bundle.id()?)
            .ok_or("candidate import has no durable event")?;
        let ack = CandidateImportAck::sign(
            receipt.clone(),
            bundle,
            &self.state.source_policy,
            operator_public,
            operator_secret,
        )?;
        let pin_path = self.root.join("OPERATOR");
        if pin_path.exists() {
            require(
                bounded(&pin_path, 128)? == operator_public.as_bytes(),
                "candidate destination operator pin changed",
            )?;
        } else if let Err(error) = atomic_write(&pin_path, operator_public.as_bytes()) {
            self.poisoned = true;
            return Err(error);
        }
        Ok(ack)
    }

    /// Persist a signed candidate destination transfer only after checking
    /// that every imported source proof still qualifies on this branch.
    pub fn transfer(
        &mut self,
        source: &CandidateChain,
        transaction: Transfer,
        destination_height: u128,
        miner: &str,
    ) -> Result<SimulatedTransferReceipt> {
        require(
            !self.poisoned,
            "simulated destination stopped after I/O failure",
        )?;
        require(!self.state.halted, "simulated destination is halted")?;
        self.audit_source(source)?;
        let mut prepared = self.state.clone();
        let receipt =
            prepared.replay_recorded_transfer(transaction.clone(), destination_height, miner)?;
        let sequence = self.state.event_count + 1;
        let event = TransferEvent {
            sequence,
            transaction,
            destination_height,
            miner: miner.into(),
            transaction_id: receipt.transaction,
            resulting_root: receipt.state_root,
        };
        let bytes = serde_json::to_vec(&event).map_err(|error| error.to_string())?;
        require(
            bytes.len() <= MAX_EVENT_BYTES,
            "simulated transfer event too large",
        )?;
        let filename = format!("{sequence:08}-{}.json", hash(&bytes).to_hex());
        let path = self.root.join("events").join(filename);
        require(!path.exists(), "simulated transfer event collision")?;
        if let Err(error) = (|| {
            atomic_write(&path, &bytes)?;
            atomic_write(
                &self.root.join("HEAD"),
                &serde_json::to_vec(&head_for(&prepared)?).map_err(|error| error.to_string())?,
            )
        })() {
            self.poisoned = true;
            return Err(error);
        }
        self.state = prepared;
        Ok(receipt)
    }

    pub fn audit_source(&mut self, source: &CandidateChain) -> Result<()> {
        require(
            !self.poisoned,
            "simulated destination stopped after I/O failure",
        )?;
        let mut prepared = self.state.clone();
        let result = prepared.audit_source(source);
        if result.is_err() && !self.state.halted {
            let persisted = (|| {
                atomic_write(&self.root.join("HALTED"), HALTED_MARKER)?;
                atomic_write(
                    &self.root.join("HEAD"),
                    &serde_json::to_vec(&head_for(&prepared)?)
                        .map_err(|error| error.to_string())?,
                )
            })();
            if let Err(error) = persisted {
                self.poisoned = true;
                return Err(error);
            }
        }
        self.state = prepared;
        result
    }
}

#[cfg(test)]
mod tests;
