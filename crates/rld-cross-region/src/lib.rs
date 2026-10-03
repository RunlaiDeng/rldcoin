//! Candidate store-and-forward transport for future interregional proofs.
//!
//! The current PoW v1 chain cannot create source export locks or validate a
//! destination import. A bundle accepted here is only a byte-preserved message;
//! it is never authority to credit RLD to a destination wallet.

use rld_core::AdmissionHash32 as Hash;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub type Result<T> = std::result::Result<T, String>;
pub mod value;
pub const MAX_PROOF_BYTES: usize = 512 * 1024;
pub const MAX_BUNDLE_BYTES: usize = 2 * MAX_PROOF_BYTES + 1024;
pub const MAX_BUNDLES: usize = 10_000;

fn require(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn io<T>(r: std::io::Result<T>) -> Result<T> {
    r.map_err(|e| e.to_string())
}

fn hash(bytes: &[u8]) -> Hash {
    Hash(Sha256::digest(bytes).into())
}

/// Bounded opaque proof with an integrity-checked transport identity. Neither
/// the bundle ID nor its digest authenticates source-chain consensus claims.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProofBundle {
    pub source_chain_id: Hash,
    pub destination_chain_id: Hash,
    pub export_id: Hash,
    pub source_checkpoint: Hash,
    #[serde(with = "decimal")]
    pub source_height: u128,
    pub proof_sha256: Hash,
    pub proof_hex: String,
}

mod decimal {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(n: &u128, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&n.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u128, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s.is_empty()
            || (s.len() > 1 && s.starts_with('0'))
            || !s.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(serde::de::Error::custom(
                "canonical decimal string required",
            ));
        }
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl ProofBundle {
    pub fn from_proof(
        source_chain_id: Hash,
        destination_chain_id: Hash,
        export_id: Hash,
        source_checkpoint: Hash,
        source_height: u128,
        proof: &[u8],
    ) -> Result<Self> {
        require(
            !proof.is_empty() && proof.len() <= MAX_PROOF_BYTES,
            "proof size outside bound",
        )?;
        let bundle = Self {
            source_chain_id,
            destination_chain_id,
            export_id,
            source_checkpoint,
            source_height,
            proof_sha256: hash(proof),
            proof_hex: hex::encode(proof),
        };
        bundle.validate()?;
        Ok(bundle)
    }

    pub fn validate(&self) -> Result<()> {
        require(
            !self.source_chain_id.is_zero()
                && !self.destination_chain_id.is_zero()
                && self.source_chain_id != self.destination_chain_id,
            "invalid source or destination chain",
        )?;
        require(
            !self.export_id.is_zero()
                && !self.source_checkpoint.is_zero()
                && self.source_height > 0,
            "missing source commitment",
        )?;
        require(
            !self.proof_hex.is_empty()
                && self.proof_hex.len() <= MAX_PROOF_BYTES * 2
                && self.proof_hex.len().is_multiple_of(2),
            "proof size outside bound",
        )?;
        let proof = hex::decode(&self.proof_hex).map_err(|e| e.to_string())?;
        require(
            hex::encode(&proof) == self.proof_hex,
            "noncanonical proof hex",
        )?;
        require(hash(&proof) == self.proof_sha256, "proof digest mismatch")
    }

    pub fn proof(&self) -> Result<Vec<u8>> {
        self.validate()?;
        hex::decode(&self.proof_hex).map_err(|e| e.to_string())
    }

    pub fn id(&self) -> Result<Hash> {
        self.validate()?;
        let mut bytes = b"RLD-EARTH-CROSS-REGION-PROOF-BUNDLE\0".to_vec();
        bytes.extend(self.source_chain_id.0);
        bytes.extend(self.destination_chain_id.0);
        bytes.extend(self.export_id.0);
        bytes.extend(self.source_checkpoint.0);
        bytes.extend(self.source_height.to_be_bytes());
        bytes.extend(self.proof_sha256.0);
        Ok(hash(&bytes))
    }
}

/// Durable, exclusively owned inbox. It may retransmit stored bundles but
/// cannot mark a transfer final, import value or release source funds.
pub struct CourierStore {
    root: PathBuf,
    _lock: File,
    by_export: BTreeMap<(Hash, Hash), BTreeSet<Hash>>,
    bundle_count: usize,
    poisoned: bool,
}

fn bounded_file(path: &Path) -> Result<Vec<u8>> {
    let metadata = io(fs::symlink_metadata(path))?;
    require(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.len() <= MAX_BUNDLE_BYTES as u64,
        "unsafe or oversized bundle file",
    )?;
    let mut bytes = Vec::new();
    io(io(File::open(path))?
        .take(MAX_BUNDLE_BYTES as u64 + 1)
        .read_to_end(&mut bytes))?;
    require(bytes.len() <= MAX_BUNDLE_BYTES, "bundle grew beyond bound")?;
    Ok(bytes)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let temp = path.with_extension("pending");
    if temp.exists() {
        require(
            !io(fs::symlink_metadata(&temp))?.file_type().is_symlink(),
            "unsafe pending bundle",
        )?;
        io(fs::remove_file(&temp))?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = io(options.open(&temp))?;
    io(file.write_all(bytes))?;
    io(file.sync_all())?;
    io(fs::rename(&temp, path))?;
    io(io(File::open(path.parent().ok_or("missing bundle directory")?))?.sync_all())
}

impl CourierStore {
    pub fn open(root: &Path) -> Result<Self> {
        if root.exists() {
            let metadata = io(fs::symlink_metadata(root))?;
            require(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "unsafe courier directory",
            )?;
        }
        io(fs::create_dir_all(root))?;
        if let Some(parent) = root.parent().filter(|p| !p.as_os_str().is_empty()) {
            io(io(File::open(parent))?.sync_all())?;
        }
        let lock_path = root.join(".courier.lock");
        if lock_path.exists() {
            require(
                !io(fs::symlink_metadata(&lock_path))?
                    .file_type()
                    .is_symlink(),
                "unsafe courier lock",
            )?;
        }
        let lock = io(OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path))?;
        lock.try_lock()
            .map_err(|e| format!("courier directory already owned: {e}"))?;
        let mut by_export = BTreeMap::new();
        let mut bundle_count = 0usize;
        for item in io(fs::read_dir(root))? {
            let item = io(item)?;
            let name = item.file_name();
            let name = name.to_str().ok_or("non-UTF8 bundle filename")?;
            if name == ".courier.lock" {
                continue;
            }
            if name.ends_with(".pending") {
                require(!io(item.file_type())?.is_symlink(), "unsafe pending bundle")?;
                continue;
            }
            require(
                name.len() == 69
                    && name.ends_with(".json")
                    && name.as_bytes()[..64]
                        .iter()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                "unexpected courier file",
            )?;
            let bytes = bounded_file(&item.path())?;
            let bundle: ProofBundle = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            let id = bundle.id()?;
            require(
                name == format!("{}.json", id.to_hex()),
                "bundle filename mismatch",
            )?;
            require(
                bytes == serde_json::to_vec(&bundle).map_err(|e| e.to_string())?,
                "noncanonical stored bundle",
            )?;
            by_export
                .entry((bundle.source_chain_id, bundle.export_id))
                .or_insert_with(BTreeSet::new)
                .insert(id);
            bundle_count += 1;
            require(bundle_count <= MAX_BUNDLES, "courier capacity reached")?;
        }
        Ok(Self {
            root: root.into(),
            _lock: lock,
            by_export,
            bundle_count,
            poisoned: false,
        })
    }

    pub fn enqueue(&mut self, bundle: ProofBundle) -> Result<bool> {
        self.enqueue_inner(bundle, false)
    }

    /// Retain another exact byte variant for the same claimed export. The
    /// caller must authenticate both claims externally. No variant becomes
    /// preferred merely because it was delivered later.
    pub fn enqueue_variant(&mut self, bundle: ProofBundle) -> Result<bool> {
        self.enqueue_inner(bundle, true)
    }

    fn enqueue_inner(&mut self, bundle: ProofBundle, allow_variant: bool) -> Result<bool> {
        require(!self.poisoned, "courier stopped after storage failure")?;
        let id = bundle.id()?;
        let key = (bundle.source_chain_id, bundle.export_id);
        if let Some(existing) = self.by_export.get(&key) {
            if existing.contains(&id) {
                return Ok(false);
            }
            require(allow_variant, "conflicting proof for export")?;
        }
        require(self.bundle_count < MAX_BUNDLES, "courier capacity reached")?;
        let bytes = serde_json::to_vec(&bundle).map_err(|e| e.to_string())?;
        require(bytes.len() <= MAX_BUNDLE_BYTES, "encoded bundle too large")?;
        let path = self.root.join(format!("{}.json", id.to_hex()));
        require(!path.exists(), "bundle filename collision")?;
        if let Err(error) = atomic_write(&path, &bytes) {
            self.poisoned = true;
            return Err(error);
        }
        self.by_export.entry(key).or_default().insert(id);
        self.bundle_count += 1;
        Ok(true)
    }

    /// Return the sole stored variant, or reject an ambiguous source/export
    /// pair. A retained revision must be selected by its exact bundle ID.
    pub fn bundle_for_export(
        &self,
        source_chain_id: Hash,
        export_id: Hash,
    ) -> Result<Option<ProofBundle>> {
        let Some(ids) = self.by_export.get(&(source_chain_id, export_id)) else {
            return Ok(None);
        };
        require(
            ids.len() == 1,
            "multiple proof variants; select an exact bundle ID",
        )?;
        let id = *ids.iter().next().ok_or("empty export bundle index")?;
        Ok(Some(self.bundle_by_id(id)?))
    }

    pub fn bundle_ids_for_export(&self, source_chain_id: Hash, export_id: Hash) -> Vec<Hash> {
        self.by_export
            .get(&(source_chain_id, export_id))
            .map(|ids| ids.iter().copied().collect())
            .unwrap_or_default()
    }

    pub fn bundle_by_id(&self, id: Hash) -> Result<ProofBundle> {
        let bytes = bounded_file(&self.root.join(format!("{}.json", id.to_hex())))?;
        let bundle: ProofBundle = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        require(
            bundle.id()? == id
                && self
                    .by_export
                    .get(&(bundle.source_chain_id, bundle.export_id))
                    .is_some_and(|ids| ids.contains(&id)),
            "bundle changed",
        )?;
        require(
            bytes == serde_json::to_vec(&bundle).map_err(|e| e.to_string())?,
            "noncanonical stored bundle",
        )?;
        Ok(bundle)
    }

    pub fn len(&self) -> usize {
        self.bundle_count
    }

    pub fn is_empty(&self) -> bool {
        self.by_export.is_empty()
    }
}

#[cfg(test)]
mod tests;
