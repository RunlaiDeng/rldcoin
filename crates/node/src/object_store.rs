//! Bounded immutable private objects. A digest is equality, never ledger authority.
use crate::store::{private_create, read_bounded, sync_dir};
use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use rand::{RngCore, rngs::OsRng};
use rld_protocol::{codec::Id, record};
use std::{
    collections::VecDeque,
    fs::{self, File},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
record!(Object{digest:Id => 0,bytes:u64 => 1});
record!(ObjectStatus{accounted_bytes:u64 => 0,accounted_files:u64 => 1,cache_bytes:u64 => 2,cache_objects:u64 => 3,byte_limit:u64 => 4,file_limit:u64 => 5,cache_byte_limit:u64 => 6,cache_object_limit:u64 => 7});
const BYTES: u64 = 1024 * 1024 * 1024 * 1024;
const FILES: u64 = 4_194_304;
const CACHE_BYTES: usize = 16 * 1024 * 1024;
const CACHE_OBJECTS: usize = 4096;
struct Cache {
    values: VecDeque<(Object, Arc<Vec<u8>>)>,
    bytes: usize,
}
struct Usage {
    bytes: u64,
    files: u64,
    serial: u64,
}
pub(crate) struct Objects {
    root: PathBuf,
    nonce: Id,
    usage: Mutex<Usage>,
    cache: Mutex<Cache>,
    _lock: File,
}
fn regular(path: &Path) -> Result<()> {
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_file(),
        "private object regular file required"
    );
    Ok(())
}
impl Objects {
    pub(crate) fn open(root: &Path, binding: &[u8]) -> Result<Arc<Self>> {
        ensure!(!root.is_symlink(), "private object root symlink");
        let fresh = !root.exists();
        fs::create_dir_all(root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if fresh {
                fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
            }
        }
        let lock_path = root.join("LOCK");
        if lock_path.exists() {
            regular(&lock_path)?;
        }
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(lock_path)?;
        lock.try_lock_exclusive()
            .context("private object store already in use")?;
        let path = root.join("BINDING.cbor");
        if path.exists() {
            regular(&path)?;
            ensure!(
                read_bounded(&path, 4096)? == binding,
                "private object binding mismatch"
            );
        } else {
            ensure!(
                fs::read_dir(root)?.all(|e| e.is_ok_and(|e| e.file_name() == "LOCK")),
                "unbound object directory; retain unchanged"
            );
            private_create(&path, binding)?;
        }
        let objects = root.join("objects");
        fs::create_dir_all(&objects)?;
        ensure!(
            fs::symlink_metadata(&objects)?.file_type().is_dir(),
            "private objects directory type"
        );
        sync_dir(root)?;
        let (mut files, mut bytes) = (0u64, 0u64);
        for e in fs::read_dir(root)? {
            let e = e?;
            if e.file_name() == "objects" {
                continue;
            }
            ensure!(
                (e.file_name() == "LOCK" || e.file_name() == "BINDING.cbor")
                    && e.file_type()?.is_file(),
                "unexpected object root entry"
            );
            files += 1;
            bytes = bytes
                .checked_add(e.metadata()?.len())
                .context("object byte overflow")?;
        }
        for shard in fs::read_dir(&objects)? {
            let shard = shard?;
            let name = shard.file_name();
            let name = name.to_str().context("object shard UTF8")?;
            ensure!(
                shard.file_type()?.is_dir()
                    && name.len() == 2
                    && name
                        .bytes()
                        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
                "unexpected object shard"
            );
            for e in fs::read_dir(shard.path())? {
                let e = e?;
                ensure!(e.file_type()?.is_file(), "unexpected private object type");
                files = files.checked_add(1).context("object file overflow")?;
                bytes = bytes
                    .checked_add(e.metadata()?.len())
                    .context("object byte overflow")?;
                ensure!(files <= FILES, "private object retained file limit");
            }
        }
        let mut nonce = [0; 32];
        OsRng.fill_bytes(&mut nonce);
        Ok(Arc::new(Self {
            root: root.into(),
            nonce: Id(nonce),
            usage: Mutex::new(Usage {
                bytes,
                files,
                serial: 0,
            }),
            cache: Mutex::new(Cache {
                values: VecDeque::new(),
                bytes: 0,
            }),
            _lock: lock,
        }))
    }
    fn path(&self, id: Id) -> PathBuf {
        let id = id.to_string();
        self.root
            .join("objects")
            .join(&id[..2])
            .join(format!("{}.blob", &id[2..]))
    }
    fn remember(&self, object: Object, data: Arc<Vec<u8>>) -> Result<()> {
        if data.len() > CACHE_BYTES {
            return Ok(());
        }
        let mut c = self
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("object cache unavailable"))?;
        if let Some(i) = c.values.iter().position(|(o, _)| o.digest == object.digest) {
            let (old, bytes) = c.values.remove(i).context("object cache index")?;
            ensure!(
                old == object && bytes.as_slice() == data.as_slice(),
                "changed immutable object cache"
            );
            c.bytes -= bytes.len();
        }
        while c.values.len() >= CACHE_OBJECTS || c.bytes + data.len() > CACHE_BYTES {
            let (_, old) = c.values.pop_front().context("object cache eviction")?;
            c.bytes -= old.len();
        }
        c.bytes += data.len();
        c.values.push_back((object, data));
        Ok(())
    }
    pub(crate) fn read(&self, object: &Object, limit: usize) -> Result<Arc<Vec<u8>>> {
        ensure!(
            object.bytes > 0 && object.bytes <= limit as u64,
            "private object read bound"
        );
        {
            let mut c = self
                .cache
                .lock()
                .map_err(|_| anyhow::anyhow!("object cache unavailable"))?;
            if let Some(i) = c.values.iter().position(|(o, _)| o.digest == object.digest) {
                let entry = c.values.remove(i).context("object cache index")?;
                ensure!(entry.0 == *object, "object cached length mismatch");
                let data = entry.1.clone();
                c.values.push_back(entry);
                return Ok(data);
            }
        }
        let path = self.path(object.digest);
        regular(&path)?;
        let data = Arc::new(read_bounded(&path, usize::try_from(object.bytes)?)?);
        ensure!(
            data.len() as u64 == object.bytes && Id::digest(data.as_slice()) == object.digest,
            "private object digest/length mismatch; retain damaged bytes"
        );
        self.remember(object.clone(), data.clone())?;
        Ok(data)
    }
    pub(crate) fn put(&self, data: Vec<u8>, limit: usize) -> Result<Object> {
        ensure!(
            !data.is_empty() && data.len() <= limit,
            "private object publication bound"
        );
        let object = Object {
            digest: Id::digest(&data),
            bytes: data.len() as u64,
        };
        let path = self.path(object.digest);
        let parent = path.parent().context("object shard parent")?;
        let mut usage = self
            .usage
            .lock()
            .map_err(|_| anyhow::anyhow!("object storage unavailable"))?;
        if !parent.exists() {
            fs::create_dir(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            }
            sync_dir(&self.root.join("objects"))?;
        }
        ensure!(
            fs::symlink_metadata(parent)?.file_type().is_dir(),
            "private object shard type"
        );
        if path.exists() {
            regular(&path)?;
            ensure!(
                read_bounded(&path, data.len())? == data,
                "changed retained private object"
            );
            File::open(&path)?.sync_all()?;
            sync_dir(parent)?;
        } else {
            ensure!(
                usage.files < FILES
                    && usage
                        .bytes
                        .checked_add(object.bytes)
                        .is_some_and(|n| n <= BYTES),
                "private object capacity exhausted; retain all evidence"
            );
            usage.serial = usage
                .serial
                .checked_add(1)
                .context("object publication exhaustion")?;
            usage.files += 1;
            usage.bytes += object.bytes;
            let pending = parent.join(format!(".partial-{}-{}", self.nonce, usage.serial));
            private_create(&pending, &data)?;
            sync_dir(parent)?;
            fs::rename(pending, &path)?;
            sync_dir(parent)?;
        }
        drop(usage);
        self.remember(object.clone(), Arc::new(data))?;
        Ok(object)
    }
    pub(crate) fn status(&self) -> Result<ObjectStatus> {
        let u = self
            .usage
            .lock()
            .map_err(|_| anyhow::anyhow!("object usage unavailable"))?;
        let c = self
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("object cache unavailable"))?;
        Ok(ObjectStatus {
            accounted_bytes: u.bytes,
            accounted_files: u.files,
            cache_bytes: c.bytes as u64,
            cache_objects: c.values.len() as u64,
            byte_limit: BYTES,
            file_limit: FILES,
            cache_byte_limit: CACHE_BYTES as u64,
            cache_object_limit: CACHE_OBJECTS as u64,
        })
    }
}
