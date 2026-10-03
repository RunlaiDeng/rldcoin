//! Immutable block files, atomic head publication and exclusive directory owner.
use super::*;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub struct Store {
    root: PathBuf,
    _lock: File,
    chain: Chain,
    poisoned: bool,
}

/// Retains exclusive ownership of a PoW data directory without retaining its
/// replayed chain in memory. Dropping this lease releases the directory lock.
pub struct DirectoryLease {
    _lock: File,
}
fn io<T>(value: std::io::Result<T>) -> Result<T> {
    value.map_err(|e| e.to_string())
}
fn bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let metadata = io(fs::symlink_metadata(path))?;
    check(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= limit as u64,
        "unsafe or oversized stored file",
    )?;
    let mut bytes = Vec::new();
    io(io(File::open(path))?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes))?;
    check(bytes.len() <= limit, "stored file grew beyond bound")?;
    Ok(bytes)
}
fn sync_directory(path: &Path) -> Result<()> {
    io(io(File::open(path))?.sync_all())
}
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or("missing storage directory")?;
    let temp = path.with_extension("pending");
    // Only this Store owns the directory. Leftover partial temporary writes have
    // no authority; they can be removed after acquisition of the writer lock.
    if temp.exists() {
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
    sync_directory(parent)
}
impl Store {
    pub fn into_directory_lease(self) -> DirectoryLease {
        DirectoryLease { _lock: self._lock }
    }

    pub fn open(root: &Path, context: Context, now: u64) -> Result<Self> {
        if root.exists() {
            check(
                !io(fs::symlink_metadata(root))?.file_type().is_symlink(),
                "storage root cannot be a symlink",
            )?;
        }
        io(fs::create_dir_all(root))?;
        let lock_path = root.join(".node.lock");
        if lock_path.exists() {
            check(
                !io(fs::symlink_metadata(&lock_path))?
                    .file_type()
                    .is_symlink(),
                "lock cannot be a symlink",
            )?;
        }
        let lock = io(OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path))?;
        lock.try_lock()
            .map_err(|e| format!("state directory is already owned: {e}"))?;
        let id = context.chain_id()?.to_hex();
        let identity = root.join("network-id");
        if identity.exists() {
            check(
                bounded(&identity, 128)? == id.as_bytes(),
                "storage belongs to another chain",
            )?;
        } else {
            atomic_write(&identity, id.as_bytes())?;
        }
        let block_dir = root.join("blocks");
        if block_dir.exists() {
            check(
                !io(fs::symlink_metadata(&block_dir))?
                    .file_type()
                    .is_symlink(),
                "block directory cannot be a symlink",
            )?;
        }
        io(fs::create_dir_all(&block_dir))?;
        sync_directory(root)?;
        // Keep only the sort key and path. Retaining every decoded block here
        // can consume the sum of all block bodies before replay even begins.
        let mut blocks = Vec::new();
        for item in io(fs::read_dir(&block_dir))? {
            let item = io(item)?;
            let path = item.path();
            let name = item.file_name();
            let name = name.to_str().ok_or("non-UTF8 block filename")?;
            check(
                !io(item.file_type())?.is_symlink(),
                "symlink in block store",
            )?;
            if name.ends_with(".pending") {
                continue;
            }
            check(
                name.len() == 69 && name.ends_with(".json"),
                "unexpected file in block store",
            )?;
            let bytes = bounded(&path, MAX_BLOCK_BYTES)?;
            let block: Block = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            check(
                name == format!("{}.json", block.header.id()?.to_hex()),
                "stored block name/hash mismatch",
            )?;
            check(
                bytes == serde_json::to_vec(&block).map_err(|e| e.to_string())?,
                "noncanonical stored block encoding",
            )?;
            blocks.push((block.header.height, block.header.id()?, path));
            check(
                blocks.len() <= MAX_TRACKED_BLOCKS,
                "local block index capacity reached",
            )?;
        }
        blocks.sort_unstable_by_key(|(height, id, _)| (*height, *id));
        let mut chain = Chain::new(context)?;
        for (height, id, path) in blocks {
            // Re-read under the directory lease. A changed or removed file
            // must fail recovery rather than replay a different sort order.
            let bytes = bounded(&path, MAX_BLOCK_BYTES)?;
            let block: Block = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            check(
                block.header.height == height
                    && block.header.id()? == id
                    && bytes == serde_json::to_vec(&block).map_err(|e| e.to_string())?,
                "stored block changed during replay",
            )?;
            chain.accept(block, now)?;
        }
        let head = root.join("HEAD");
        if head.exists() {
            let text = String::from_utf8(bounded(&head, 64)?).map_err(|e| e.to_string())?;
            let previous = Hash::from_hex(&text).map_err(|e| e.to_string())?;
            if previous != chain.context.chain_id()? {
                let prior = chain
                    .blocks
                    .get(&previous)
                    .ok_or("published head is missing from durable blocks")?;
                if prior.work == chain.chainwork() {
                    chain.state = chain.state_at(previous)?;
                    chain.tip = previous;
                }
            }
        }
        atomic_write(&head, chain.tip().to_hex().as_bytes())?;
        Ok(Self {
            root: root.into(),
            _lock: lock,
            chain,
            poisoned: false,
        })
    }
    pub fn chain(&self) -> &Chain {
        &self.chain
    }
    pub fn healthy(&self) -> bool {
        !self.poisoned
    }
    pub fn accept(&mut self, block: Block, now: u64) -> Result<bool> {
        check(
            !self.poisoned,
            "storage is stopped after an I/O failure; restart for replay",
        )?;
        let id = block.header.id()?;
        if self.chain.block(id).is_some() {
            return Ok(false);
        }
        let Some(prepared) = self.chain.prepare(block.clone(), now)? else {
            return Ok(false);
        };
        let adopted = prepared.preferred;
        let bytes = serde_json::to_vec(&block).map_err(|e| e.to_string())?;
        let result = (|| {
            atomic_write(
                &self
                    .root
                    .join("blocks")
                    .join(format!("{}.json", id.to_hex())),
                &bytes,
            )?;
            if adopted {
                atomic_write(&self.root.join("HEAD"), id.to_hex().as_bytes())?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.poisoned = true;
            return Err(error);
        }
        self.chain.commit(prepared);
        Ok(adopted)
    }
}
