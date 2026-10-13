//! Existing V2 companion archive custody, separate from native ledger authority.
//! Shared complete bytes do not initialize a ledger; cold native checks remain mandatory.
use crate::{
    bft, bft_client, bft_network, require, storage::Store, wallet_client as files, Hash, Result,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

pub const FORMAT: &str = "RLD-REGIONAL-BFT-RETENTION-V2";
pub const ONWARD_FORMAT: &str = "RLD-REGIONAL-BFT-ONWARD-RETENTION-V1";
pub const MAX_STATE: usize = 32 * 1024 * 1024;
const MAX_MESSAGES: usize = 512;
const MAX_REFS: usize = 64;

#[cfg(test)]
pub(crate) mod cost {
    use std::cell::Cell;
    thread_local! {
        static COUNTS: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
        static PHASES: Cell<[u128; 5]> = const { Cell::new([0; 5]) };
    }
    pub(crate) fn take() -> (usize, usize) {
        COUNTS.with(|counts| counts.replace((0, 0)))
    }
    pub(crate) fn take_phases() -> [u128; 5] {
        PHASES.with(|phases| phases.replace([0; 5]))
    }
    pub(super) fn phase(index: usize, started: std::time::Instant) {
        PHASES.with(|phases| {
            let mut values = phases.get();
            values[index] += started.elapsed().as_nanos();
            phases.set(values);
        });
    }
    pub(super) fn archive() {
        COUNTS.with(|counts| {
            let (a, e) = counts.get();
            counts.set((a + 1, e));
        });
    }
    pub(super) fn envelope() {
        COUNTS.with(|counts| {
            let (a, e) = counts.get();
            counts.set((a, e + 1));
        });
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub format: String,
    pub currency: Hash,
    pub region: Hash,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub header: Header,
    pub body: Value,
    pub refs: Vec<Hash>,
    pub sha256: Hash,
    pub size_bytes: usize,
    pub value: Option<Hash>,
    pub local: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_refs: Option<Vec<Hash>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub onward_history_ref: Option<Hash>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Runtime {
    pub format: String,
    pub binding: bft::Binding,
    pub messages: BTreeMap<Hash, Record>,
    pub height: u64,
    pub tip: Hash,
    pub snapshot_cache: Vec<Hash>,
    pub cursor: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Archive {
    pub format: String,
    pub runtime: Runtime,
    pub snapshots: BTreeMap<Hash, Value>,
}
#[derive(Serialize)]
pub struct Receipt {
    pub format: &'static str,
    pub currency: Hash,
    pub region: Hash,
    pub runtime_format: String,
    pub key: String,
    pub state_sha256: Hash,
    pub state_bytes: usize,
    pub message_count: usize,
    pub new_envelopes_authenticated: usize,
    pub full_cold_authentication_required: bool,
    pub ledger_changed: bool,
    pub signing_authority: bool,
}
fn hash(raw: &[u8]) -> Hash {
    Hash(Sha256::digest(raw).into())
}
fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    files::canonical_with_limit(value, MAX_STATE)
}

impl Archive {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let archive = Self::decode_canonical(raw)?;
        archive.check_bytes()?;
        Ok(archive)
    }
    // Parsing alone grants no byte-integrity or Native authority. A store call
    // must fully check this graph or inherit only its exact immutable byte facts
    // from that call's fully checked retained graph below.
    fn decode_canonical(raw: &[u8]) -> Result<Self> {
        let value = crate::wallet_http::decode_unique_with_limit(raw, MAX_STATE)?;
        require(
            value.as_object().is_some_and(|object| {
                object.len() == 3
                    && object.contains_key("runtime")
                    && object.contains_key("snapshots")
                    && matches!(
                        object.get("format").and_then(Value::as_str),
                        Some(FORMAT | ONWARD_FORMAT)
                    )
            }),
            "BFT retention version differs; preserve old fixture and use fresh state",
        )?;
        let archive: Self = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
        require(
            serde_json::to_value(&archive).map_err(|e| e.to_string())? == value,
            "BFT archive lost typed fields or noncanonical identifiers",
        )?;
        require(
            canonical(&archive)? == raw,
            "BFT archive canonical bytes differ",
        )?;
        Ok(archive)
    }
    fn check_limits(&self) -> Result<()> {
        require(
            (self.format == FORMAT || self.format == ONWARD_FORMAT)
                && self.runtime.messages.len() <= MAX_MESSAGES
                && self.snapshots.len() <= MAX_MESSAGES * MAX_REFS
                && self.runtime.snapshot_cache.len() <= MAX_REFS
                && self.runtime.height <= 64
                && self.runtime.cursor <= i64::MAX as u64,
            "BFT archive format/count/observation bound",
        )
    }
    fn same_complete_graph(&self, other: &Self) -> Result<bool> {
        if self.runtime.messages != other.runtime.messages || self.snapshots != other.snapshots {
            return Ok(false);
        }
        // Generic JSON numeric equality can equate distinct encodings such as
        // positive and negative zero. Inherit only exact canonical graph bytes.
        Ok(canonical(&(&self.runtime.messages, &self.snapshots))?
            == canonical(&(&other.runtime.messages, &other.snapshots))?)
    }
    fn check_bytes(&self) -> Result<()> {
        #[cfg(test)]
        cost::archive();
        self.check_limits()?;
        let sizes = self.snapshot_sizes(None)?;
        let mut referenced = BTreeSet::new();
        for (ident, record) in &self.runtime.messages {
            self.check_record_bytes(ident, record, &sizes, &mut referenced)?;
        }
        self.check_referenced(&referenced)
    }
    // The previous archive must have completed full retained validation in this
    // exact store call. Inherit only immutable canonical byte facts, never Native
    // authentication, a ledger or a persistent witness. Cold decode stays full.
    fn check_delta_bytes(&self, previous: &Self) -> Result<()> {
        #[cfg(test)]
        cost::archive();
        self.check_limits()?;
        require(
            previous
                .runtime
                .messages
                .keys()
                .all(|id| self.runtime.messages.contains_key(id))
                && previous
                    .snapshots
                    .keys()
                    .all(|id| self.snapshots.contains_key(id)),
            "BFT archive cannot discard retained graph bytes",
        )?;
        let sizes = self.snapshot_sizes(Some(previous))?;
        let mut referenced = BTreeSet::new();
        for (ident, record) in &self.runtime.messages {
            if let Some(old) = previous.runtime.messages.get(ident) {
                let mut exact = old.clone();
                exact.local |= record.local;
                require(
                    canonical(&exact)? == canonical(record)?,
                    "BFT archive immutable canonical record bytes differ",
                )?;
                referenced.extend(record.refs.iter().copied());
                if let Some(origins) = &record.origin_refs {
                    referenced.extend(origins.iter().copied());
                }
                referenced.extend(record.onward_history_ref);
            } else {
                self.check_record_bytes(ident, record, &sizes, &mut referenced)?;
            }
        }
        self.check_referenced(&referenced)
    }
    fn snapshot_sizes(&self, previous: Option<&Self>) -> Result<BTreeMap<Hash, usize>> {
        let mut sizes = BTreeMap::new();
        for (reference, value) in &self.snapshots {
            let raw = files::canonical(value)?;
            if let Some(old) = previous.and_then(|archive| archive.snapshots.get(reference)) {
                require(
                    raw == files::canonical(old)?,
                    "BFT archive immutable canonical snapshot bytes differ",
                )?;
            } else {
                require(
                    !raw.is_empty()
                        && raw.len() <= crate::contact::MAX_PAYLOAD
                        && hash(&raw) == *reference,
                    "BFT archive snapshot complete bytes differ",
                )?;
            }
            sizes.insert(*reference, raw.len());
        }
        Ok(sizes)
    }
    fn check_referenced(&self, referenced: &BTreeSet<Hash>) -> Result<()> {
        require(
            referenced.len() == self.snapshots.len(),
            "BFT archive orphan shared snapshot refuses",
        )
    }
    fn check_record_bytes(
        &self,
        ident: &Hash,
        record: &Record,
        sizes: &BTreeMap<Hash, usize>,
        referenced: &mut BTreeSet<Hash>,
    ) -> Result<()> {
        #[cfg(test)]
        cost::envelope();
        let origin = record.header.format == bft_network::ORIGIN_FORMAT;
        let onward = record.header.format == crate::bft_onward_network::FORMAT;
        require(
            if self.format == ONWARD_FORMAT {
                onward && record.origin_refs.is_none()
            } else {
                record.onward_history_ref.is_none()
                    && ((origin && record.origin_refs.is_some())
                        || (record.header.format == bft_network::FORMAT
                            && record.origin_refs.is_none()))
            },
            "BFT archive envelope format/reference fields differ",
        )?;
        let origins = record.origin_refs.as_deref().unwrap_or_default();
        require(
            record.refs.len() + origins.len() + usize::from(record.onward_history_ref.is_some())
                <= MAX_REFS
                && origins.len() <= 4
                && record.size_bytes > 0
                && record.size_bytes <= crate::contact::MAX_PAYLOAD
                && hash(&files::canonical(&record.body)?) == *ident,
            "BFT archive record identity/reference/size bound",
        )?;
        // Calculate expansion before cloning or decoding any shared proof.
        let mut base = serde_json::json!({"format":record.header.format,"currency":record.header.currency,
        "region":record.header.region,"body":record.body,"evidence":{"snapshots":[]}});
        if origin {
            base["origins"] = serde_json::json!([]);
        }
        if onward {
            base["history"] = Value::Null;
        }
        let mut size = files::canonical(&base)?.len();
        if let Some(reference) = record.onward_history_ref {
            size = size
                .checked_sub(4)
                .and_then(|n| n.checked_add(*sizes.get(&reference)?))
                .ok_or("BFT onward wrapper missing or expansion overflow")?;
            referenced.insert(reference);
        }
        for refs in [&record.refs[..], origins] {
            size = size
                .checked_add(refs.len().saturating_sub(1))
                .ok_or("BFT archive expansion overflow")?;
            for reference in refs {
                size = size
                    .checked_add(
                        *sizes
                            .get(reference)
                            .ok_or("BFT archive shared snapshot missing")?,
                    )
                    .ok_or("BFT archive expansion overflow")?;
                referenced.insert(*reference);
            }
        }
        require(
            size == record.size_bytes && size <= crate::contact::MAX_PAYLOAD,
            "BFT archive expansion size/capacity differs",
        )?;
        let raw = files::canonical(&self.envelope(record)?)?;
        require(
            raw.len() == size && hash(&raw) == record.sha256,
            "BFT archive whole envelope bytes differ",
        )?;
        Ok(())
    }
    pub(crate) fn envelope(&self, record: &Record) -> Result<Value> {
        let snapshots = record
            .refs
            .iter()
            .map(|r| {
                self.snapshots
                    .get(r)
                    .cloned()
                    .ok_or("BFT archive shared snapshot missing".into())
            })
            .collect::<Result<Vec<_>>>()?;
        let mut value = serde_json::json!({"format":record.header.format,"currency":record.header.currency,
            "region":record.header.region,"body":record.body,"evidence":{"snapshots":snapshots}});
        if let Some(refs) = &record.origin_refs {
            let origins = refs
                .iter()
                .map(|r| {
                    self.snapshots
                        .get(r)
                        .cloned()
                        .ok_or("BFT archive shared origin missing".into())
                })
                .collect::<Result<Vec<_>>>()?;
            value["origins"] = serde_json::to_value(origins).map_err(|e| e.to_string())?;
        }
        if record.header.format == crate::bft_onward_network::FORMAT {
            value["history"] = match record.onward_history_ref {
                Some(reference) => self
                    .snapshots
                    .get(&reference)
                    .cloned()
                    .ok_or("BFT archive complete onward wrapper missing")?,
                None => Value::Null,
            };
        }
        Ok(value)
    }
}
fn capacity(root: &Path, additional_files: u64, additional_bytes: u64) -> Result<()> {
    let mut pending = vec![root.to_path_buf()];
    let (mut count, mut bytes) = (additional_files, additional_bytes);
    require(
        count <= 4096 && bytes <= 256 * 1024 * 1024,
        "BFT archive directory capacity",
    )?;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).map_err(|e| e.to_string())? {
            let path = entry.map_err(|e| e.to_string())?.path();
            let metadata = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
            require(
                !metadata.file_type().is_symlink() && (metadata.is_file() || metadata.is_dir()),
                "BFT archive inventory refuses links or special objects",
            )?;
            count = count
                .checked_add(1)
                .ok_or("BFT archive inventory overflow")?;
            if metadata.is_dir() {
                pending.push(path);
            } else {
                bytes = bytes
                    .checked_add(metadata.len())
                    .ok_or("BFT archive retained byte overflow")?;
            }
            require(
                count <= 4096 && bytes <= 256 * 1024 * 1024,
                "BFT archive directory retained object/byte capacity",
            )?;
        }
    }
    Ok(())
}

pub struct Client {
    root: PathBuf,
    binding: bft::Binding,
    format: String,
    _lock: File,
}
impl Client {
    pub fn lock(root: &Path, key: String, format: String, node: &Store) -> Result<Self> {
        crate::bft_runtime_envelope::require_profile(&format, node)?;
        require(
            cfg!(unix),
            "native companion custody requires Unix private file operations",
        )?;
        files::private_path(root, true)?;
        require(
            !root.starts_with(node.directory()) && !node.directory().starts_with(root),
            "BFT companion archive must be separate from native ledger",
        )?;
        crate::verification_keys::validate_ed25519_public_key(&key)?;
        let rules = &node.trust.region(node.chain.region)?.rules;
        require(
            (format == bft_client::FORMAT && bft::is_profile(rules) && !bft::is_joint(rules))
                || (format == bft_client::ORIGIN_FORMAT
                    && rules == crate::paged_bft::ORIGIN_NETWORK_RULES)
                || (format == bft_client::ONWARD_FORMAT
                    && rules == crate::paged_bft::ONWARD_NETWORK_RULES),
            "BFT archive runtime/admission profile differs",
        )?;
        let context = bft::Context::current(node)?;
        require(
            context.keys(&node.trust, &node.evidence)?.contains(&key),
            "BFT archive key outside native admitted membership",
        )?;
        let extra_lock = match fs::symlink_metadata(root.join(".archive.lock")) {
            Ok(_) => 0,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 1,
            Err(e) => return Err(e.to_string()),
        };
        capacity(root, extra_lock, 0)?;
        let lock = files::options()
            .read(true)
            .write(true)
            .create(true)
            .open(root.join(".archive.lock"))
            .map_err(|e| e.to_string())?;
        files::private_metadata(&lock)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let dir = fs::symlink_metadata(root).map_err(|e| e.to_string())?;
            require(
                dir.uid() == unsafe { libc::getuid() }
                    && dir.mode() & 0o077 == 0
                    && lock.metadata().map_err(|e| e.to_string())?.nlink() == 1,
                "BFT archive private directory/lock invalid",
            )?;
        }
        lock.try_lock().map_err(|e| e.to_string())?;
        Ok(Self {
            root: root.into(),
            binding: bft::Binding {
                currency: node.trust.currency()?,
                region: node.chain.region,
                key,
            },
            format,
            _lock: lock,
        })
    }
    fn validate(&self, archive: &Archive, node: &Store) -> Result<()> {
        let runtime = &archive.runtime;
        require(
            runtime.format == self.format
                && runtime.binding == self.binding
                && archive.format
                    == if self.format == bft_client::ONWARD_FORMAT {
                        ONWARD_FORMAT
                    } else {
                        FORMAT
                    },
            "BFT archive currency/region/key/runtime binding differs",
        )?;
        let tip = if runtime.height == 0 {
            self.binding.region
        } else {
            node.block_at(runtime.height)?.header.id()?
        };
        require(
            runtime.tip == tip,
            "BFT archive observation differs from fully native executed prefix",
        )?;
        for record in runtime.messages.values() {
            require(
                record.header.currency == self.binding.currency
                    && record.header.region == self.binding.region,
                "BFT archive retained envelope domain differs",
            )?;
        }
        Ok(())
    }
    fn retained(&self, node: &Store) -> Result<(Archive, Vec<u8>)> {
        capacity(&self.root, 0, 0)?;
        let path = self.root.join("state.json");
        let raw = files::private_read_with_limit(&path, MAX_STATE)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            require(
                fs::symlink_metadata(&path)
                    .map_err(|e| e.to_string())?
                    .nlink()
                    == 1,
                "BFT archive state hard link refuses",
            )?;
        }
        let archive = Archive::decode(&raw)?;
        self.validate(&archive, node)?;
        Ok((archive, raw))
    }
    fn receipt(&self, archive: &Archive, raw: &[u8], count: usize) -> Receipt {
        Receipt {
            format: "RLD-NATIVE-BFT-ARCHIVE-RECEIPT-V1",
            currency: self.binding.currency,
            region: self.binding.region,
            runtime_format: self.format.clone(),
            key: self.binding.key.clone(),
            state_sha256: hash(raw),
            state_bytes: raw.len(),
            message_count: archive.runtime.messages.len(),
            new_envelopes_authenticated: count,
            full_cold_authentication_required: true,
            ledger_changed: false,
            signing_authority: false,
        }
    }
    pub fn read(&self, node: &Store) -> Result<Receipt> {
        let (archive, raw) = self.retained(node)?;
        Ok(self.receipt(&archive, &raw, 0))
    }
    /// The same fully byte-checked graph is authenticated before startup may
    /// reconcile custody. This does not change the public byte-only read API.
    pub(crate) fn read_authenticated(&self, node: &Store) -> Result<(Archive, Hash)> {
        self.read_authenticated_inner(
            node,
            #[cfg(test)]
            None,
        )
    }
    #[cfg(test)]
    pub(crate) fn read_authenticated_with_limit_for_test(
        &self,
        node: &Store,
        limit: usize,
    ) -> Result<(Archive, Hash)> {
        self.read_authenticated_inner(node, Some(limit))
    }
    fn read_authenticated_inner(
        &self,
        node: &Store,
        #[cfg(test)] limit: Option<usize>,
    ) -> Result<(Archive, Hash)> {
        let (archive, raw) = self.retained(node)?;
        let mut witness = (self.format == bft_client::ONWARD_FORMAT).then(|| {
            #[cfg(test)]
            if let Some(limit) = limit {
                return crate::bft_onward_network::ArchiveReadWitness::with_limit_for_test(limit);
            }
            crate::bft_onward_network::ArchiveReadWitness::new()
        });
        let result = (|| {
            for record in archive.runtime.messages.values() {
                if let Some(witness) = witness.as_mut() {
                    witness.begin_record();
                }
                let wire = crate::bft_runtime_envelope::Wire::decode(
                    archive.envelope(record)?,
                    &self.format,
                )?;
                let value = match witness.as_mut() {
                    Some(witness) => wire.verify_cold_with_archive(node, witness)?,
                    None => wire.verify_cold(node)?,
                };
                require(
                    value == record.value,
                    "BFT cold archive value differs from complete Native envelope",
                )?;
                if let Some(witness) = witness.as_mut() {
                    witness.commit_record();
                }
            }
            Ok((archive, hash(&raw)))
        })();
        if result.is_err() {
            if let Some(witness) = witness.as_mut() {
                witness.disable();
            }
        }
        result
    }
    /// Authenticate complete current-parent proposal/timeout envelopes, one at
    /// a time. Other retained records still require the ordinary full cold check.
    pub(crate) fn proposal_messages(
        &self,
        node: &Store,
        expected: Hash,
        context: &bft::Context,
    ) -> Result<Vec<bft::Message>> {
        self.scheduling_messages(node, expected, context, false, None)
    }
    pub(crate) fn scheduling_messages(
        &self,
        node: &Store,
        expected: Hash,
        context: &bft::Context,
        include_votes: bool,
        order: Option<&[Hash]>,
    ) -> Result<Vec<bft::Message>> {
        let (archive, raw) = self.retained(node)?;
        require(hash(&raw) == expected, "BFT scheduling archive changed")?;
        let mut messages = Vec::new();
        let records = if let Some(order) = order {
            let unique = order.iter().copied().collect::<BTreeSet<_>>();
            require(
                order.len() == archive.runtime.messages.len()
                    && unique.len() == order.len()
                    && unique.iter().eq(archive.runtime.messages.keys()),
                "BFT scheduling order must name every exact retained record once",
            )?;
            order
                .iter()
                .map(|id| &archive.runtime.messages[id])
                .collect::<Vec<_>>()
        } else {
            archive.runtime.messages.values().collect()
        };
        for record in records {
            let body: bft_network::Body =
                serde_json::from_value(record.body.clone()).map_err(|e| e.to_string())?;
            require(
                serde_json::to_value(&body).map_err(|e| e.to_string())? == record.body,
                "BFT scheduling body loses typed fields",
            )?;
            let message = match &body {
                bft_network::Body::Signed(message)
                | bft_network::Body::EpochSigned { message, .. } => message,
                _ => continue,
            };
            let relevant = match message.as_ref() {
                bft::Message::Proposal(p) => {
                    let s = &p.snapshot.statement;
                    s.currency == context.currency
                        && s.region == context.region
                        && s.epoch == context.epoch
                        && s.previous == context.previous
                        && Some(s.height) == context.parent_height.checked_add(1)
                }
                bft::Message::Timeout(t) => t.context == *context,
                bft::Message::Vote(v) => include_votes && v.context == *context,
                _ => false,
            };
            if !relevant {
                continue;
            }
            let value = archive.envelope(record)?;
            let wire = crate::bft_runtime_envelope::Wire::decode(value, &self.format)?;
            require(
                wire.verify(node)? == record.value,
                "BFT scheduling envelope/value differs",
            )?;
            messages.push(message.as_ref().clone());
        }
        Ok(messages)
    }
    pub fn store_file(&self, node: &Store, path: &Path, expected: Option<Hash>) -> Result<Receipt> {
        self.store(
            node,
            &files::private_read_with_limit(path, MAX_STATE)?,
            expected,
        )
    }
    pub fn store(&self, node: &Store, raw: &[u8], expected: Option<Hash>) -> Result<Receipt> {
        self.store_inner(node, raw, expected, None)
    }
    pub(crate) fn store_with_receive(
        &self,
        node: &Store,
        raw: &[u8],
        expected: Option<Hash>,
        witness: &mut crate::bft_onward_network::ReceiveWitness,
    ) -> Result<Receipt> {
        let result = self.store_inner(node, raw, expected, Some(&mut *witness));
        if result.is_err() {
            witness.disable();
        }
        result
    }
    fn store_inner(
        &self,
        node: &Store,
        raw: &[u8],
        expected: Option<Hash>,
        mut witness: Option<&mut crate::bft_onward_network::ReceiveWitness>,
    ) -> Result<Receipt> {
        #[cfg(test)]
        let started = std::time::Instant::now();
        let proposed = Archive::decode_canonical(raw)?;
        proposed.check_limits()?;
        self.validate(&proposed, node)?;
        #[cfg(test)]
        cost::phase(0, started);
        #[cfg(test)]
        let started = std::time::Instant::now();
        let previous = match fs::symlink_metadata(self.root.join("state.json")) {
            Ok(_) => {
                let (old, old_raw) = self.retained(node)?;
                require(
                    expected == Some(hash(&old_raw)),
                    "BFT archive changed before publication",
                )?;
                require(
                    proposed.runtime.height >= old.runtime.height,
                    "BFT archive observation cannot roll back",
                )?;
                for (ident, record) in &old.runtime.messages {
                    let next = proposed
                        .runtime
                        .messages
                        .get(ident)
                        .ok_or("BFT archive cannot delete retained messages")?;
                    let mut same = record.clone();
                    same.local |= next.local;
                    require(
                        same == *next,
                        "BFT archive cannot replace retained envelope/value or clear local custody",
                    )?;
                }
                for (reference, value) in &old.snapshots {
                    require(
                        proposed.snapshots.get(reference) == Some(value),
                        "BFT archive cannot discard or alter retained shared bytes",
                    )?;
                }
                Some(old)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                require(
                    expected.is_none()
                        && proposed.runtime.messages.is_empty()
                        && proposed.runtime.height == 0
                        && proposed.runtime.snapshot_cache.is_empty()
                        && proposed.runtime.cursor == 0,
                    "fresh BFT archive requires explicit empty state, never inferred recovery",
                )?;
                None
            }
            Err(e) => return Err(e.to_string()),
        };
        #[cfg(test)]
        cost::phase(1, started);
        #[cfg(test)]
        let started = std::time::Instant::now();
        // The retained archive was fully decoded, byte checked and bound to the
        // current Native prefix in this call. Identical complete record and
        // snapshot maps inherit only those byte facts. All metadata is checked
        // independently above; every new graph member still receives full checks.
        // This witness is never stored and never initializes Native execution.
        let exact_graph = match &previous {
            Some(old) => old.same_complete_graph(&proposed)?,
            None => false,
        };
        if !exact_graph {
            match &previous {
                Some(old) => proposed.check_delta_bytes(old)?,
                None => proposed.check_bytes()?,
            }
        }
        #[cfg(test)]
        cost::phase(2, started);
        #[cfg(test)]
        let started = std::time::Instant::now();
        let mut verified = 0;
        for (ident, record) in &proposed.runtime.messages {
            if previous
                .as_ref()
                .and_then(|a| a.runtime.messages.get(ident))
                .is_some_and(|old| old.local == record.local)
            {
                continue;
            }
            let value = proposed.envelope(record)?;
            let wire = crate::bft_runtime_envelope::Wire::decode(value, &self.format)?;
            let value = match witness.as_deref_mut() {
                Some(witness) => wire.verify_with_receive(node, witness)?,
                None => wire.verify(node)?,
            };
            require(
                value == record.value,
                "BFT archive value metadata differs from complete native envelope",
            )?;
            verified += 1;
        }
        #[cfg(test)]
        cost::phase(3, started);
        #[cfg(test)]
        let started = std::time::Instant::now();
        // Count every retained object, including interrupted publications and
        // active input files. Reserve the complete new temporary before writing.
        capacity(&self.root, 1, raw.len() as u64)?;
        let mut random = [0; 16];
        getrandom::getrandom(&mut random).map_err(|e| e.to_string())?;
        let temporary = self.root.join(format!(".write-{}", hex::encode(random)));
        let mut file = files::options()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|e| e.to_string())?;
        files::private_metadata(&file)?;
        file.write_all(raw).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        fs::rename(&temporary, self.root.join("state.json")).map_err(|e| e.to_string())?;
        File::open(&self.root)
            .map_err(|e| e.to_string())?
            .sync_all()
            .map_err(|e| e.to_string())?;
        #[cfg(test)]
        cost::phase(4, started);
        Ok(self.receipt(&proposed, raw, verified))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn archive(origin: bool) -> Archive {
        let first = serde_json::json!({"bytes":"whole","number":1e-7});
        let second = serde_json::json!({"bytes":"different"});
        let a = hash(&files::canonical(&first).unwrap());
        let b = hash(&files::canonical(&second).unwrap());
        let mut archive = Archive {
            format: FORMAT.into(),
            runtime: Runtime {
                format: bft_client::FORMAT.into(),
                binding: bft::Binding {
                    currency: Hash([1; 32]),
                    region: Hash([2; 32]),
                    key: "public-no-value-codec-fixture".into(),
                },
                messages: BTreeMap::new(),
                height: 0,
                tip: Hash([2; 32]),
                snapshot_cache: vec![],
                cursor: 0,
            },
            snapshots: BTreeMap::from([(a, first), (b, second)]),
        };
        let mut record = Record {
            header: Header {
                format: if origin {
                    bft_network::ORIGIN_FORMAT
                } else {
                    bft_network::FORMAT
                }
                .into(),
                currency: Hash([1; 32]),
                region: Hash([2; 32]),
            },
            body: serde_json::json!({"codec_only":"unauthenticated"}),
            refs: vec![a, b, a],
            sha256: Hash::ZERO,
            size_bytes: 1,
            value: None,
            local: false,
            origin_refs: origin.then_some(vec![b, b]),
            onward_history_ref: None,
        };
        let raw = files::canonical(&archive.envelope(&record).unwrap()).unwrap();
        record.size_bytes = raw.len();
        record.sha256 = hash(&raw);
        archive
            .runtime
            .messages
            .insert(hash(&files::canonical(&record.body).unwrap()), record);
        archive
    }
    #[test]
    fn exact_graph_witness_refuses_equal_json_numbers_with_different_canonical_bytes() {
        let mut original = archive(false);
        let (_, mut record) = original.runtime.messages.pop_first().unwrap();
        record.body["number"] = serde_json::json!(-0.0);
        let raw = files::canonical(&original.envelope(&record).unwrap()).unwrap();
        record.size_bytes = raw.len();
        record.sha256 = hash(&raw);
        original
            .runtime
            .messages
            .insert(hash(&files::canonical(&record.body).unwrap()), record);
        let original = Archive::decode(&canonical(&original).unwrap()).unwrap();
        let mut changed = original.clone();
        changed.runtime.messages.values_mut().next().unwrap().body["number"] =
            serde_json::json!(0.0);
        assert_eq!(original.runtime.messages, changed.runtime.messages);
        assert!(!original.same_complete_graph(&changed).unwrap());
        assert!(changed.check_bytes().is_err());
        assert!(changed.check_delta_bytes(&original).is_err());
        let mut metadata = original.clone();
        metadata.runtime.cursor = 1;
        assert!(original.same_complete_graph(&metadata).unwrap());
    }
    #[test]
    fn delta_byte_checks_preserve_complete_prefix_and_reject_every_changed_old_byte() {
        for origin in [false, true] {
            let previous = Archive::decode(&canonical(&archive(origin)).unwrap()).unwrap();
            let mut proposed = previous.clone();
            let mut record = previous.runtime.messages.values().next().unwrap().clone();
            record.body["new_record"] = serde_json::json!(true);
            let raw = files::canonical(&proposed.envelope(&record).unwrap()).unwrap();
            record.size_bytes = raw.len();
            record.sha256 = hash(&raw);
            let ident = hash(&files::canonical(&record.body).unwrap());
            proposed.runtime.messages.insert(ident, record);
            proposed.check_delta_bytes(&previous).unwrap();
            proposed.check_bytes().unwrap();
            for case in 0..8 {
                let mut bad = proposed.clone();
                let old_id = *previous.runtime.messages.keys().next().unwrap();
                match case {
                    0 => {
                        bad.runtime.messages.remove(&old_id);
                    }
                    1 => bad
                        .runtime
                        .messages
                        .get_mut(&old_id)
                        .unwrap()
                        .refs
                        .push(Hash::ZERO),
                    2 => bad.runtime.messages.get_mut(&old_id).unwrap().sha256 = Hash::ZERO,
                    3 => {
                        bad.snapshots.pop_first();
                    }
                    4 => bad.runtime.messages.get_mut(&ident).unwrap().size_bytes += 1,
                    5 => bad.runtime.messages.get_mut(&ident).unwrap().sha256 = Hash::ZERO,
                    6 => {
                        bad.snapshots.insert(hash(b"{}"), serde_json::json!({}));
                    }
                    _ => bad.runtime.snapshot_cache = vec![Hash::ZERO; 65],
                }
                assert!(
                    bad.check_delta_bytes(&previous).is_err(),
                    "delta attack {case}"
                );
            }
            let mut local = proposed.clone();
            local
                .runtime
                .messages
                .values_mut()
                .for_each(|record| record.local = true);
            local.check_delta_bytes(&previous).unwrap();
            local.check_bytes().unwrap();
            let mut cleared = local.clone();
            cleared.runtime.messages.values_mut().next().unwrap().local = false;
            assert!(cleared.check_delta_bytes(&local).is_err());
        }
    }
    #[test]
    fn delta_snapshot_inheritance_refuses_equal_numbers_with_different_bytes() {
        let mut previous = archive(false);
        let reference = *previous.snapshots.keys().next().unwrap();
        previous.snapshots.get_mut(&reference).unwrap()["zero"] = serde_json::json!(-0.0);
        let replacement = hash(&files::canonical(&previous.snapshots[&reference]).unwrap());
        let value = previous.snapshots.remove(&reference).unwrap();
        previous.snapshots.insert(replacement, value);
        for record in previous.runtime.messages.values_mut() {
            for refs in [
                &mut record.refs,
                record.origin_refs.get_or_insert_with(Vec::new),
            ] {
                for id in refs {
                    if *id == reference {
                        *id = replacement;
                    }
                }
            }
            if record.header.format != bft_network::ORIGIN_FORMAT {
                record.origin_refs = None;
            }
        }
        let mut updated = previous.clone();
        for record in previous.runtime.messages.values_mut() {
            let raw = files::canonical(&updated.envelope(record).unwrap()).unwrap();
            record.sha256 = hash(&raw);
            record.size_bytes = raw.len();
        }
        previous.check_bytes().unwrap();
        updated = previous.clone();
        updated.snapshots.get_mut(&replacement).unwrap()["zero"] = serde_json::json!(0.0);
        assert_eq!(updated.snapshots, previous.snapshots);
        assert!(updated.check_delta_bytes(&previous).is_err());
    }
    #[test]
    fn native_archive_exact_order_multiple_references_and_corruption_boundaries() {
        for origin in [false, true] {
            let archive = archive(origin);
            let raw = canonical(&archive).unwrap();
            assert_eq!(canonical(&Archive::decode(&raw).unwrap()).unwrap(), raw);
            for case in 0..5 {
                let mut bad = archive.clone();
                let record = bad.runtime.messages.values_mut().next().unwrap();
                match case {
                    0 => record.sha256 = Hash::ZERO,
                    1 => record.refs.reverse(),
                    2 => record.refs.push(Hash::ZERO),
                    3 => record.size_bytes = crate::contact::MAX_PAYLOAD + 1,
                    _ => {
                        bad.snapshots.insert(hash(b"{}"), serde_json::json!({}));
                    }
                }
                // a,b,a is a palindrome; replacing a reference is a real change.
                if case == 1 {
                    bad.runtime.messages.values_mut().next().unwrap().refs[0] = Hash::ZERO;
                }
                assert!(Archive::decode(&canonical(&bad).unwrap()).is_err());
            }
        }
    }
    #[test]
    fn native_archive_keeps_companion_32mib_separate_from_ledger_and_envelope_caps() {
        let mut archive = archive(false);
        archive.runtime.messages.clear();
        archive.snapshots.clear();
        for n in 0..9 {
            let snapshot = serde_json::json!({"codec_only":n,"padding":"x".repeat(1024*1024)});
            let reference = hash(&files::canonical(&snapshot).unwrap());
            archive.snapshots.insert(reference, snapshot);
            let body = serde_json::json!({"codec_only":n});
            let ident = hash(&files::canonical(&body).unwrap());
            let mut record = Record {
                header: Header {
                    format: bft_network::FORMAT.into(),
                    currency: Hash([1; 32]),
                    region: Hash([2; 32]),
                },
                body,
                refs: vec![reference],
                sha256: Hash::ZERO,
                size_bytes: 1,
                value: None,
                local: false,
                origin_refs: None,
                onward_history_ref: None,
            };
            let raw = files::canonical(&archive.envelope(&record).unwrap()).unwrap();
            record.size_bytes = raw.len();
            record.sha256 = hash(&raw);
            archive.runtime.messages.insert(ident, record);
        }
        let raw = canonical(&archive).unwrap();
        assert!(raw.len() > crate::MAX_BYTES && raw.len() < MAX_STATE);
        assert!(Archive::decode(&raw).is_ok());
        assert!(crate::wallet_http::decode_unique(&raw).is_err());
        assert!(Archive::decode(&vec![b' '; MAX_STATE + 1]).is_err());
        let record = archive.runtime.messages.values_mut().next().unwrap();
        record.refs = vec![record.refs[0]; 4];
        assert!(Archive::decode(&canonical(&archive).unwrap()).is_err());
    }
    mod onward_codec_guards {
        use super::*;

        fn wrapper() -> Value {
            serde_json::json!({
                "codec_only": "whole unauthenticated wrapper",
                "history": {
                    "origin": {"snapshots": [{"retained": "first"}, {"retained": "later"}]},
                    "snapshots": [{"retained": "complete"}, {"retained": "duplicate"}],
                    "metadata": {"unicode": "café", "zero": -0.0}
                }
            })
        }

        // Commit an independently assembled expected wire, not Archive::envelope.
        // Repeated references keep their multiplicity/order in the expected array.
        fn onward(history: Option<Value>, snapshots: Vec<Value>) -> (Archive, Value) {
            let mut archive = archive(false);
            let (_, mut record) = archive.runtime.messages.pop_first().unwrap();
            archive.format = ONWARD_FORMAT.into();
            archive.runtime.format = bft_client::ONWARD_FORMAT.into();
            archive.snapshots.clear();
            record.header.format = crate::bft_onward_network::FORMAT.into();
            record.origin_refs = None;
            record.refs = snapshots
                .iter()
                .map(|value| {
                    let reference = hash(&files::canonical(value).unwrap());
                    archive.snapshots.insert(reference, value.clone());
                    reference
                })
                .collect();
            record.onward_history_ref = history.as_ref().map(|value| {
                let reference = hash(&files::canonical(value).unwrap());
                archive.snapshots.insert(reference, value.clone());
                reference
            });
            let expected = serde_json::json!({
                "format": crate::bft_onward_network::FORMAT,
                "currency": record.header.currency,
                "region": record.header.region,
                "body": record.body,
                "evidence": {"snapshots": snapshots},
                "history": history
            });
            let raw = files::canonical(&expected).unwrap();
            record.size_bytes = raw.len();
            record.sha256 = hash(&raw);
            archive
                .runtime
                .messages
                .insert(hash(&files::canonical(&record.body).unwrap()), record);
            (archive, expected)
        }

        fn round_trip(archive: &Archive, expected: &Value) -> Archive {
            let raw = canonical(archive).unwrap();
            let decoded = Archive::decode(&raw).unwrap();
            assert_eq!(canonical(&decoded).unwrap(), raw);
            let record = decoded.runtime.messages.values().next().unwrap();
            assert_eq!(
                files::canonical(&decoded.envelope(record).unwrap()).unwrap(),
                files::canonical(expected).unwrap(),
            );
            decoded
        }

        #[test]
        fn onward_archive_preserves_null_whole_wrapper_and_ordered_duplicate_refs() {
            let a = serde_json::json!({"codec_only": "first", "number": 1e-7});
            let b = serde_json::json!({"codec_only": "second", "unicode": "café"});
            for history in [None, Some(wrapper())] {
                let (archive, expected) =
                    onward(history.clone(), vec![a.clone(), b.clone(), a.clone()]);
                let decoded = round_trip(&archive, &expected);
                let record = decoded.runtime.messages.values().next().unwrap();
                assert_eq!(record.refs.len(), 3);
                assert_eq!(record.refs[0], record.refs[2]);
                assert_ne!(record.refs[0], record.refs[1]);
                let actual = decoded.envelope(record).unwrap();
                assert_eq!(
                    actual["evidence"]["snapshots"],
                    serde_json::json!([a, b, a])
                );
                assert!(actual.as_object().unwrap().contains_key("history"));
                match history {
                    None => {
                        assert!(actual["history"].is_null());
                        assert!(record.onward_history_ref.is_none());
                        assert_eq!(decoded.snapshots.len(), 2);
                    }
                    Some(whole) => {
                        assert_eq!(
                            files::canonical(&actual["history"]).unwrap(),
                            files::canonical(&whole).unwrap()
                        );
                        assert_eq!(decoded.snapshots.len(), 3);
                        assert_eq!(
                            decoded.snapshots[&record.onward_history_ref.unwrap()],
                            whole
                        );
                    }
                }
                // The unchanged-graph fast path must retain the history reference.
                let mut metadata = decoded.clone();
                metadata.runtime.cursor += 1;
                metadata.runtime.messages.values_mut().next().unwrap().local = true;
                metadata.check_delta_bytes(&decoded).unwrap();
                round_trip(&metadata, &expected);
                let mut reordered = decoded.clone();
                // a,b,a is a palindrome: an actual swap changes complete wire bytes.
                reordered
                    .runtime
                    .messages
                    .values_mut()
                    .next()
                    .unwrap()
                    .refs
                    .swap(0, 1);
                assert!(Archive::decode(&canonical(&reordered).unwrap()).is_err());
                assert!(reordered.check_delta_bytes(&decoded).is_err());
            }
        }

        #[test]
        fn onward_archive_refuses_missing_altered_or_orphan_history_and_mixed_profiles() {
            let (archive, expected) = onward(
                Some(wrapper()),
                vec![serde_json::json!({"codec_only": "local"})],
            );
            let archive = round_trip(&archive, &expected);
            let reference = archive
                .runtime
                .messages
                .values()
                .next()
                .unwrap()
                .onward_history_ref
                .unwrap();
            for case in 0..7 {
                let mut bad = archive.clone();
                match case {
                    0 => {
                        bad.snapshots.remove(&reference);
                    }
                    1 => {
                        bad.snapshots.get_mut(&reference).unwrap()["history"]["snapshots"][1]
                            ["retained"] = serde_json::json!("altered later member");
                    }
                    2 => {
                        let orphan = serde_json::json!({"codec_only": "orphan whole wrapper"});
                        bad.snapshots
                            .insert(hash(&files::canonical(&orphan).unwrap()), orphan);
                    }
                    3 => {
                        bad.runtime
                            .messages
                            .values_mut()
                            .next()
                            .unwrap()
                            .onward_history_ref = None;
                    }
                    4 => {
                        bad.format = FORMAT.into();
                    }
                    5 => {
                        bad.runtime
                            .messages
                            .values_mut()
                            .next()
                            .unwrap()
                            .origin_refs = Some(vec![]);
                    }
                    _ => {
                        bad.runtime
                            .messages
                            .values_mut()
                            .next()
                            .unwrap()
                            .onward_history_ref = Some(Hash::ZERO);
                    }
                }
                assert!(
                    Archive::decode(&canonical(&bad).unwrap()).is_err(),
                    "onward codec attack {case}"
                );
            }
            for origin in [false, true] {
                let mut old_record = super::archive(origin);
                old_record.format = ONWARD_FORMAT.into();
                let error = Archive::decode(&canonical(&old_record).unwrap()).unwrap_err();
                assert!(error.contains("envelope format/reference fields differ"));
            }
            // Generic JSON equality must not authorize altered complete wrapper bytes.
            let mut equal_json = archive.clone();
            equal_json.snapshots.get_mut(&reference).unwrap()["history"]["metadata"]["zero"] =
                serde_json::json!(0.0);
            assert_eq!(equal_json.snapshots, archive.snapshots);
            assert!(Archive::decode(&canonical(&equal_json).unwrap()).is_err());
            assert!(equal_json.check_delta_bytes(&archive).is_err());
        }

        #[test]
        fn onward_archive_counts_wrapper_ref_and_checks_full_expansion_at_original_cap() {
            let local = serde_json::json!({"codec_only": "repeated reference"});
            let (without, expected) = onward(None, vec![local.clone(); MAX_REFS]);
            round_trip(&without, &expected);
            let (with, expected) = onward(Some(wrapper()), vec![local.clone(); MAX_REFS - 1]);
            round_trip(&with, &expected);
            let (too_many, _) = onward(Some(wrapper()), vec![local.clone(); MAX_REFS]);
            let error = Archive::decode(&canonical(&too_many).unwrap()).unwrap_err();
            assert!(error.contains("record identity/reference/size bound"));

            let mut whole = wrapper();
            whole["padding"] = serde_json::json!("");
            let (_, empty_wire) = onward(Some(whole.clone()), vec![local.clone(); 3]);
            let base = files::canonical(&empty_wire).unwrap().len();
            let padding = crate::contact::MAX_PAYLOAD.checked_sub(base).unwrap();
            whole["padding"] = serde_json::json!("x".repeat(padding));
            let (at_cap, expected) = onward(Some(whole.clone()), vec![local.clone(); 3]);
            assert_eq!(
                files::canonical(&expected).unwrap().len(),
                crate::contact::MAX_PAYLOAD
            );
            // The complete stored object is smaller than the expanded whole wire.
            assert!(files::canonical(&whole).unwrap().len() < crate::contact::MAX_PAYLOAD);
            round_trip(&at_cap, &expected);

            whole["padding"] = serde_json::json!("x".repeat(padding + 1));
            let (mut over, expected) = onward(Some(whole.clone()), vec![local; 3]);
            assert_eq!(
                files::canonical(&expected).unwrap().len(),
                crate::contact::MAX_PAYLOAD + 1
            );
            assert!(files::canonical(&whole).unwrap().len() < crate::contact::MAX_PAYLOAD);
            assert!(Archive::decode(&canonical(&over).unwrap()).is_err());
            // A lying in-range size cannot hide the expansion from small shared refs.
            over.runtime
                .messages
                .values_mut()
                .next()
                .unwrap()
                .size_bytes = crate::contact::MAX_PAYLOAD;
            let error = Archive::decode(&canonical(&over).unwrap()).unwrap_err();
            assert!(error.contains("expansion size/capacity differs"));
        }

        #[test]
        fn onward_archive_extension_keeps_old_v2_bytes_and_omits_absent_fields() {
            for origin in [false, true] {
                let old = super::archive(origin);
                let (ident, record) = old.runtime.messages.iter().next().unwrap();
                let mut old_record = serde_json::json!({
                    "header": record.header, "body": record.body, "refs": record.refs,
                    "sha256": record.sha256, "size_bytes": record.size_bytes,
                    "value": record.value, "local": record.local
                });
                if origin {
                    old_record["origin_refs"] = serde_json::json!(record.origin_refs);
                }
                let mut messages = serde_json::Map::new();
                messages.insert(ident.to_hex(), old_record);
                let expected_old = serde_json::json!({
                    "format": FORMAT,
                    "runtime": {
                        "format": old.runtime.format, "binding": old.runtime.binding,
                        "messages": messages, "height": old.runtime.height,
                        "tip": old.runtime.tip, "snapshot_cache": old.runtime.snapshot_cache,
                        "cursor": old.runtime.cursor
                    },
                    "snapshots": old.snapshots
                });
                assert_eq!(canonical(&old).unwrap(), canonical(&expected_old).unwrap());
                let decoded = Archive::decode(&canonical(&expected_old).unwrap()).unwrap();
                let stored =
                    serde_json::to_value(decoded.runtime.messages.values().next().unwrap())
                        .unwrap();
                assert!(stored.get("onward_history_ref").is_none());
                assert_eq!(stored.get("origin_refs").is_some(), origin);
                let wire = decoded
                    .envelope(decoded.runtime.messages.values().next().unwrap())
                    .unwrap();
                assert!(wire.get("history").is_none());
                // Explicit null is not an accepted alternate old serialization.
                let mut added_null = expected_old;
                added_null["runtime"]["messages"][ident.to_hex()]["onward_history_ref"] =
                    Value::Null;
                assert!(Archive::decode(&canonical(&added_null).unwrap()).is_err());
            }
        }
    }
}
