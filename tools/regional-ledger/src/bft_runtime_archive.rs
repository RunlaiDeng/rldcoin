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
pub const MAX_STATE: usize = 32 * 1024 * 1024;
const MAX_MESSAGES: usize = 512;
const MAX_REFS: usize = 64;

#[cfg(test)]
pub(crate) mod cost {
    use std::cell::Cell;
    thread_local! {
        static COUNTS: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
    }
    pub(crate) fn take() -> (usize, usize) {
        COUNTS.with(|counts| counts.replace((0, 0)))
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
                    && object.get("format").and_then(Value::as_str) == Some(FORMAT)
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
            self.format == FORMAT
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
        let mut sizes = BTreeMap::new();
        for (reference, value) in &self.snapshots {
            let raw = files::canonical(value)?;
            require(
                !raw.is_empty()
                    && raw.len() <= crate::contact::MAX_PAYLOAD
                    && hash(&raw) == *reference,
                "BFT archive snapshot complete bytes differ",
            )?;
            sizes.insert(*reference, raw.len());
        }
        let mut referenced = BTreeSet::new();
        for (ident, record) in &self.runtime.messages {
            #[cfg(test)]
            cost::envelope();
            let origin = record.header.format == bft_network::ORIGIN_FORMAT;
            require(
                (origin && record.origin_refs.is_some())
                    || (record.header.format == bft_network::FORMAT
                        && record.origin_refs.is_none()),
                "BFT archive envelope format/reference fields differ",
            )?;
            let origins = record.origin_refs.as_deref().unwrap_or_default();
            require(
                record.refs.len() + origins.len() <= MAX_REFS
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
            let mut size = files::canonical(&base)?.len();
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
        }
        require(
            referenced.len() == self.snapshots.len(),
            "BFT archive orphan shared snapshot refuses",
        )
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
                    && rules == crate::paged_bft::ORIGIN_NETWORK_RULES),
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
            runtime.format == self.format && runtime.binding == self.binding,
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
            let wire: bft_network::WireEnvelope =
                serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
            require(
                serde_json::to_value(&wire).map_err(|e| e.to_string())? == value,
                "BFT scheduling envelope loses typed fields",
            )?;
            let envelope = wire.expand()?;
            envelope.verify(node)?;
            require(
                envelope.value()? == record.value,
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
        let proposed = Archive::decode_canonical(raw)?;
        proposed.check_limits()?;
        self.validate(&proposed, node)?;
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
        // The retained archive was fully decoded, byte checked and bound to the
        // current Native prefix in this call. Identical complete record and
        // snapshot maps inherit only those byte facts. All metadata is checked
        // independently above; every changed graph still receives full checks.
        // This witness is never stored and never initializes Native execution.
        let exact_graph = match &previous {
            Some(old) => old.same_complete_graph(&proposed)?,
            None => false,
        };
        if !exact_graph {
            proposed.check_bytes()?;
        }
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
            let wire: bft_network::WireEnvelope =
                serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
            require(
                serde_json::to_value(&wire).map_err(|e| e.to_string())? == value,
                "BFT archive envelope loses native typed fields",
            )?;
            let envelope = wire.expand()?;
            envelope.verify(node)?;
            require(
                envelope.value()? == record.value,
                "BFT archive value metadata differs from complete native envelope",
            )?;
            verified += 1;
        }
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
        let mut metadata = original.clone();
        metadata.runtime.cursor = 1;
        assert!(original.same_complete_graph(&metadata).unwrap());
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
}
