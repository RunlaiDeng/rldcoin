//! Append-only content-authenticated event journal with a separately retained
//! head. A head is a storage anchor, never a monetary certificate.
use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use rld_protocol::{
    codec::{Blob, Id, decode, encode},
    record,
};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub const MAX_RECORD: usize = 1024 * 1024 * 1024;
record!(Tip {generation:u64  =>  0,head:Id  =>  1});
record!(Frame {generation:u64  =>  0,previous:Id  =>  1,payload:Blob  =>  2});
record!(Pending {old:Tip  =>  0,new:Tip  =>  1});
pub struct Store {
    root: PathBuf,
    anchor: PathBuf,
    _lock: File,
    pub tip: Tip,
    recovering: Option<Pending>,
    archive: crate::archive::Archive,
    frame_heads: std::collections::BTreeMap<u64, Id>,
}

pub fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut f = File::open(path).with_context(|| format!("read {}", path.display()))?;
    ensure!(f.metadata()?.len() <= limit as u64, "file size limit");
    let mut b = Vec::new();
    (&mut f).take(limit as u64 + 1).read_to_end(&mut b)?;
    ensure!(b.len() <= limit, "file grew beyond limit");
    Ok(b)
}
pub fn private_create(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut f = options.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
pub fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}
pub fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let next = path.with_extension("next");
    ensure!(
        !next.exists(),
        "unfinished publication at {}",
        next.display()
    );
    private_create(&next, bytes)?;
    fs::rename(&next, path)?;
    sync_dir(path.parent().context("publication parent")?)
}
fn head_paths(root: &Path, anchor: &Path) -> Result<(PathBuf, PathBuf)> {
    let r = fs::canonicalize(root)?;
    let parent = fs::canonicalize(anchor.parent().context("head parent")?)?;
    ensure!(
        !parent.starts_with(&r),
        "latest head must be outside the store"
    );
    let a = parent.join(anchor.file_name().context("head name")?);
    ensure!(!a.is_symlink(), "head symlink");
    Ok((r, a))
}
impl Store {
    pub fn create(root: &Path, anchor: &Path, initial: &[u8]) -> Result<Self> {
        ensure!(
            !root.exists() && !anchor.exists(),
            "fresh store and separately retained head required"
        );
        fs::create_dir(root)?;
        #[cfg(unix)]
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
        fs::create_dir(root.join("events"))?;
        let (root, anchor) = head_paths(root, anchor)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(root.join("LOCK"))?;
        lock.try_lock_exclusive()?;
        let tip = Tip {
            generation: 0,
            head: Id::ZERO,
        };
        private_create(&root.join("MANIFEST"), &encode(&tip))?;
        private_create(&anchor, &encode(&tip))?;
        sync_dir(&root)?;
        sync_dir(anchor.parent().context("anchor parent")?)?;
        let archive = crate::archive::Archive::open(&root, &tip, false)?;
        let mut store = Self {
            root,
            anchor,
            _lock: lock,
            tip,
            recovering: None,
            archive,
            frame_heads: Default::default(),
        };
        store.append(initial)?;
        Ok(store)
    }
    pub fn open(root: &Path, anchor: &Path, recover: bool) -> Result<Self> {
        let (root, anchor) = head_paths(root, anchor)?;
        ensure!(!root.join("RESTORING").exists(), "interrupted restore");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join("LOCK"))?;
        lock.try_lock_exclusive()?;
        let disk: Tip = decode(&read_bounded(&root.join("MANIFEST"), 128)?, 128)?;
        let head: Tip = decode(&read_bounded(&anchor, 128)?, 128)?;
        let mut tip = disk.clone();
        let mut recovering = if root.join("PENDING").exists() {
            ensure!(
                recover,
                "unfinished transaction: explicit recover-store required"
            );
            let pending: Pending = decode(&read_bounded(&root.join("PENDING"), 512)?, 512)?;
            ensure!(
                (disk == pending.old || disk == pending.new)
                    && (head == pending.old || head == pending.new)
                    && pending.new.generation
                        == pending
                            .old
                            .generation
                            .checked_add(1)
                            .context("generation overflow")?,
                "publication/head mismatch"
            );
            tip = pending.new.clone();
            Some(pending)
        } else {
            ensure!(
                disk == head
                    && !root.join("MANIFEST.next").exists()
                    && !anchor.with_extension("next").exists(),
                "stale/unfinished latest head"
            );
            None
        };
        if recovering.is_none() {
            let n = disk
                .generation
                .checked_add(1)
                .context("generation exhaustion")?;
            let orphan = root.join("events").join(format!("{n:020}.cbor"));
            if orphan.exists() {
                ensure!(
                    recover,
                    "retained unpublished event: explicit recover-store required"
                );
                let bytes = read_bounded(&orphan, MAX_RECORD)?;
                let frame: Frame = decode(&bytes, MAX_RECORD)?;
                ensure!(
                    frame.generation == n && frame.previous == disk.head,
                    "unpublished event binding; preserve damaged residue"
                );
                let new = Tip {
                    generation: n,
                    head: Id::digest(&bytes),
                };
                tip = new.clone();
                recovering = Some(Pending {
                    old: disk.clone(),
                    new,
                });
            }
        }
        let archive = crate::archive::Archive::open(&root, &tip, recover)?;
        let expected_count = tip.generation;
        for entry in fs::read_dir(root.join("events"))? {
            let entry = entry?;
            ensure!(entry.file_type()?.is_file(), "unexpected journal entry");
            let name = entry.file_name();
            let name = name.to_str().context("event filename")?;
            let n = name
                .strip_suffix(".cbor")
                .context("event extension")?
                .parse::<u64>()?;
            ensure!(
                n > 0 && n <= expected_count && name == format!("{n:020}.cbor"),
                "unaccounted journal residue; preserve before recovery"
            );
        }
        Ok(Self {
            root,
            anchor,
            _lock: lock,
            tip,
            recovering,
            archive,
            frame_heads: Default::default(),
        })
    }
    fn event_path(&self, n: u64) -> PathBuf {
        self.root.join("events").join(format!("{n:020}.cbor"))
    }
    pub fn walk(&mut self, mut apply: impl FnMut(u64, &[u8]) -> Result<()>) -> Result<()> {
        let mut previous = Id::ZERO;
        let mut verified_heads = std::collections::BTreeMap::new();
        let archived = self.archive.archived_last();
        let mut count = 0u64;
        let mut replay = |n: u64, bytes: &[u8]| -> Result<()> {
            let frame: Frame = decode(bytes, MAX_RECORD)?;
            ensure!(
                frame.generation == n
                    && frame.previous == previous
                    && n == count
                        .checked_add(1)
                        .context("journal position exhaustion")?,
                "event chain mismatch"
            );
            apply(n, &frame.payload.0)?;
            previous = Id::digest(bytes);
            self.archive.check_source_observation(n, previous)?;
            if n > archived {
                verified_heads.insert(n, previous);
            }
            count = n;
            Ok(())
        };
        self.archive.walk(&mut replay)?;
        for n in self
            .archive
            .archived_last()
            .checked_add(1)
            .context("archive position exhaustion")?..=self.tip.generation
        {
            let bytes = read_bounded(&self.event_path(n), MAX_RECORD)?;
            replay(n, &bytes)?;
        }
        ensure!(previous == self.tip.head, "journal/latest head mismatch");
        self.frame_heads = verified_heads;
        Ok(())
    }
    pub fn finish_recovery(&mut self) -> Result<()> {
        if let Some(p) = &self.recovering {
            // Caller has already replayed every native transition and certificate.
            if !self.root.join("PENDING").exists() {
                private_create(&self.root.join("PENDING"), &encode(p))?;
                sync_dir(&self.root)?;
            }
            for path in [
                self.root.join("MANIFEST.next"),
                self.anchor.with_extension("next"),
            ] {
                if path.exists() {
                    let bytes = read_bounded(&path, 128)?;
                    let next: Tip = decode(&bytes, 128)?;
                    ensure!(next == p.new, "unrelated publication residue");
                    fs::remove_file(path)?;
                }
            }
            atomic_replace(&self.root.join("MANIFEST"), &encode(&p.new))?;
            atomic_replace(&self.anchor, &encode(&p.new))?;
            fs::remove_file(self.root.join("PENDING"))?;
            sync_dir(&self.root)?;
            self.recovering = None;
        }
        self.archive.finish_recovery()?;
        Ok(())
    }
    pub fn archive_completed(&mut self) -> Result<bool> {
        ensure!(self.recovering.is_none(), "unreconciled journal");
        let head: Tip = decode(&read_bounded(&self.anchor, 128)?, 128)?;
        ensure!(head == self.tip, "archive latest head mismatch");
        let rotated = self.archive.rotate(&self.tip, &self.frame_heads)?;
        let archived = self.archive.archived_last();
        self.frame_heads.retain(|n, _| *n > archived);
        Ok(rotated)
    }
    pub fn append(&mut self, payload: &[u8]) -> Result<Id> {
        ensure!(
            self.recovering.is_none()
                && !self.root.join("PENDING").exists()
                && payload.len() < MAX_RECORD - 128,
            "unreconciled transaction/record size"
        );
        let current: Tip = decode(&read_bounded(&self.anchor, 128)?, 128)?;
        ensure!(current == self.tip, "external latest head changed");
        let generation = self
            .tip
            .generation
            .checked_add(1)
            .context("journal generation exhaustion")?;
        let frame = Frame {
            generation,
            previous: self.tip.head,
            payload: Blob(payload.to_vec()),
        };
        let bytes = encode(&frame);
        let digest = Id::digest(&bytes);
        let path = self.event_path(generation);
        if path.exists() {
            ensure!(
                read_bounded(&path, MAX_RECORD)? == bytes,
                "retained conflicting publication; recover before append"
            );
            File::open(&path)?.sync_all()?;
        } else {
            private_create(&path, &bytes)?;
        }
        sync_dir(&self.root.join("events"))?;
        let new = Tip {
            generation,
            head: digest,
        };
        let pending = Pending {
            old: self.tip.clone(),
            new: new.clone(),
        };
        private_create(&self.root.join("PENDING"), &encode(&pending))?;
        sync_dir(&self.root)?;
        atomic_replace(&self.root.join("MANIFEST"), &encode(&new))?;
        atomic_replace(&self.anchor, &encode(&new))?;
        fs::remove_file(self.root.join("PENDING"))?;
        sync_dir(&self.root)?;
        self.tip = new;
        self.frame_heads.insert(generation, digest);
        if generation % 64 == 0 {
            self.archive_completed()?;
        }
        Ok(digest)
    }
    pub fn root_path(&self) -> &Path {
        &self.root
    }
}
