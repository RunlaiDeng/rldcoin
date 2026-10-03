//! Watchtower-owned high-water state, separate from the merchant journal.
//! A whole-directory rollback still requires an independent external anchor.

use super::WatchPackage;
use crate::Result;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const MAX_PACKAGE_BYTES: usize = 32_768;

pub struct WatchStore {
    root: PathBuf,
    _lock: File,
    latest: WatchPackage,
    poisoned: bool,
}

fn io<T>(result: std::io::Result<T>) -> Result<T> {
    result.map_err(|error| error.to_string())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or("missing watchtower state directory")?;
    let pending = path.with_extension("pending");
    if pending.exists() {
        let metadata = io(fs::symlink_metadata(&pending))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("unsafe pending watchtower state".into());
        }
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

fn read_package(path: &Path) -> Result<WatchPackage> {
    let metadata = io(fs::symlink_metadata(path))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_PACKAGE_BYTES as u64
    {
        return Err("unsafe or oversized watchtower state".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("watchtower state must be owner-only".into());
        }
    }
    let mut bytes = Vec::new();
    io(io(File::open(path))?
        .take(MAX_PACKAGE_BYTES as u64 + 1)
        .read_to_end(&mut bytes))?;
    if bytes.len() > MAX_PACKAGE_BYTES {
        return Err("watchtower state exceeded byte bound".into());
    }
    let package: WatchPackage =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if bytes != serde_json::to_vec(&package).map_err(|error| error.to_string())? {
        return Err("noncanonical watchtower state".into());
    }
    package.validate()?;
    Ok(package)
}

impl WatchStore {
    /// A new store needs an initial signed package. An existing store always
    /// resumes its own durable latest package, even if the merchant lost one.
    pub fn open(root: &Path, initial: Option<WatchPackage>) -> Result<Self> {
        let existing = root.exists();
        if existing {
            let metadata = io(fs::symlink_metadata(root))?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err("unsafe watchtower state directory".into());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err("watchtower directory must be owner-only".into());
                }
            }
        } else {
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            io(builder.create(root))?;
            if let Some(parent) = root.parent().filter(|path| !path.as_os_str().is_empty()) {
                io(io(File::open(parent))?.sync_all())?;
            }
        }
        let lock_path = root.join(".watch.lock");
        if lock_path.exists()
            && io(fs::symlink_metadata(&lock_path))?
                .file_type()
                .is_symlink()
        {
            return Err("unsafe watchtower lock".into());
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = io(options.open(lock_path))?;
        lock.try_lock()
            .map_err(|error| format!("watchtower state already owned: {error}"))?;
        let state_path = root.join("latest.json");
        let latest = if existing {
            let latest = read_package(&state_path)?;
            if initial
                .as_ref()
                .is_some_and(|package| package.funding != latest.funding)
            {
                return Err("watchtower state belongs to another channel".into());
            }
            latest
        } else {
            let package = initial.ok_or("new watchtower state requires signed initial package")?;
            package.validate()?;
            let bytes = serde_json::to_vec(&package).map_err(|error| error.to_string())?;
            if bytes.len() > MAX_PACKAGE_BYTES {
                return Err("watchtower package too large".into());
            }
            atomic_write(&state_path, &bytes)?;
            package
        };
        Ok(Self {
            root: root.into(),
            _lock: lock,
            latest,
            poisoned: false,
        })
    }

    pub fn latest(&self) -> &WatchPackage {
        &self.latest
    }

    pub fn healthy(&self) -> bool {
        !self.poisoned
    }

    /// Never replace a higher signed state with a merchant-side rollback.
    pub fn observe(&mut self, package: WatchPackage) -> Result<bool> {
        if self.poisoned {
            return Err("watchtower stopped after storage failure".into());
        }
        package.validate()?;
        if package.funding != self.latest.funding {
            return Err("watchtower channel identity changed".into());
        }
        let sequence = package.state.state.sequence;
        let previous = self.latest.state.state.sequence;
        if sequence == previous {
            if package != self.latest {
                return Err("watchtower package conflicts at same sequence".into());
            }
            return Ok(false);
        }
        if previous.checked_add(1) != Some(sequence) {
            return Err("watchtower package moved backward or skipped sequence".into());
        }
        let bytes = serde_json::to_vec(&package).map_err(|error| error.to_string())?;
        if bytes.len() > MAX_PACKAGE_BYTES {
            return Err("watchtower package too large".into());
        }
        if let Err(error) = atomic_write(&self.root.join("latest.json"), &bytes) {
            self.poisoned = true;
            return Err(error);
        }
        self.latest = package;
        Ok(true)
    }
}

#[cfg(test)]
mod tests;
