//! One locked Native replay, bounded complete batches, no partial authority.
use crate::{bft_network, history, require, storage, Hash, Result, MAX_BYTES};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Read,
    path::Path,
};

pub const FORMAT: &str = "RLD-BFT-COLD-NETWORK-PLAN-V1";
pub const MAX_ENVELOPES: usize = 512;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Batch {
    pub sha256: Hash,
    pub bytes: usize,
    pub envelopes: usize,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub format: String,
    pub currency: Hash,
    pub region: Hash,
    pub batches: Vec<Batch>,
}
#[derive(Debug, Serialize)]
pub struct CheckedBatch {
    pub request_sha256: Hash,
    pub results: Vec<bft_network::ColdChecked>,
}
#[derive(Debug, Serialize)]
pub struct Checked {
    pub format: String,
    pub currency: Hash,
    pub region: Hash,
    pub history_head: Hash,
    pub request_sha256: Hash,
    pub batches: Vec<CheckedBatch>,
    pub verified: bool,
    pub ledger_changed: bool,
    pub signing_authority: bool,
}
fn digest(raw: &[u8]) -> Hash {
    Hash(Sha256::digest(raw).into())
}
fn read(path: &Path) -> Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|e| e.to_string())?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    require(
        meta.is_file() && meta.len() <= MAX_BYTES as u64,
        "cold plan unsafe or oversized file",
    )?;
    let mut raw = Vec::new();
    file.take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    require(
        raw.len() <= MAX_BYTES && raw.len() as u64 == meta.len(),
        "cold plan input size changed",
    )?;
    Ok(raw)
}
fn inventory(root: &Path) -> Result<BTreeMap<String, (u64, Hash)>> {
    storage::safe_dir(root)?;
    let mut rows = BTreeMap::new();
    let mut total = 0u64;
    for entry in fs::read_dir(root).map_err(|e| e.to_string())? {
        let path = entry.map_err(|e| e.to_string())?.path();
        let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        require(
            meta.is_file() && !meta.file_type().is_symlink(),
            "cold plan unsafe archive entry",
        )?;
        require(
            rows.len() < history::MAX_FILES,
            "cold plan archive file bound",
        )?;
        total = total
            .checked_add(meta.len())
            .ok_or("cold plan archive byte overflow")?;
        require(
            total <= history::MAX_ARCHIVE_BYTES,
            "cold plan archive byte bound",
        )?;
        let raw = read(&path)?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("cold plan non-UTF8 name")?;
        rows.insert(name.into(), (raw.len() as u64, digest(&raw)));
    }
    Ok(rows)
}
pub fn check(file: &Path, node: &storage::Store, head: Hash) -> Result<Checked> {
    node.require_cold_head(head)?;
    let root = file.parent().ok_or("cold plan parent missing")?;
    let before = inventory(root)?;
    let raw = read(file)?;
    let name = file
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("cold plan filename")?;
    require(
        before.get(name) == Some(&(raw.len() as u64, digest(&raw))),
        "cold plan manifest changed",
    )?;
    let plan: Plan = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    require(
        plan.format == FORMAT
            && plan.currency == node.trust.currency()?
            && plan.region == node.chain.region,
        "cold plan format/currency/region binding",
    )?;
    require(
        !plan.batches.is_empty() && plan.batches.len() <= MAX_ENVELOPES,
        "cold plan batch count bound",
    )?;
    let mut count = 0usize;
    let mut bytes = 0u64;
    for batch in &plan.batches {
        require(
            batch.envelopes > 0
                && batch.envelopes <= bft_network::MAX_COLD_BATCH
                && batch.bytes > 0
                && batch.bytes <= MAX_BYTES,
            "cold plan per-batch bound",
        )?;
        count = count
            .checked_add(batch.envelopes)
            .ok_or("cold plan envelope overflow")?;
        bytes = bytes
            .checked_add(batch.bytes as u64)
            .ok_or("cold plan byte overflow")?;
        require(
            count <= MAX_ENVELOPES && bytes <= history::MAX_ARCHIVE_BYTES,
            "cold plan total bound",
        )?;
    }
    let mut batches = Vec::new();
    for batch in plan.batches {
        let name = format!("{}.json", batch.sha256.to_hex());
        require(
            before.get(&name) == Some(&(batch.bytes as u64, batch.sha256)),
            "cold plan missing or altered batch",
        )?;
        let raw = read(&root.join(name))?;
        require(
            raw.len() == batch.bytes && digest(&raw) == batch.sha256,
            "cold plan exact batch changed",
        )?;
        let wires: Vec<bft_network::WireEnvelope> =
            serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        require(
            wires.len() == batch.envelopes,
            "cold plan batch declaration differs",
        )?;
        // Never reuse a body/hash result: check every later complete envelope.
        batches.push(CheckedBatch {
            request_sha256: batch.sha256,
            results: bft_network::check_cold_batch(wires, node)?,
        });
    }
    require(
        inventory(root)? == before,
        "cold plan archive changed during authentication",
    )?;
    node.require_cold_head(head)?;
    let checked = Checked {
        format: FORMAT.into(),
        currency: plan.currency,
        region: plan.region,
        history_head: head,
        request_sha256: digest(&raw),
        batches,
        verified: true,
        ledger_changed: false,
        signing_authority: false,
    };
    require(
        serde_json::to_vec(&checked)
            .map_err(|e| e.to_string())?
            .len()
            <= MAX_BYTES,
        "cold plan response bound",
    )?;
    Ok(checked)
}
