//! An explicitly trusted local head input; never independently fresh or money.
use super::codec;
use crate::{
    fast_payment::ensure,
    fast_retainer::{io, parent, private, sync, Reader},
    kernel::{Hash, Result},
};
use fs2::FileExt;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
pub(super) const MAX_RECORD: usize = 89 + codec::MAX_PACKET;
const LIMIT: usize = 144 + MAX_RECORD;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Boundary {
    PrepareNextDurable,
    Prepared,
    PeerDurable,
    CommitNextDurable,
    Committed,
}
#[derive(Clone)]
pub(super) struct Snapshot {
    pub binding: Hash,
    pub previous: Hash,
    pub head: Hash,
    pub pending: Vec<u8>,
    pub digest: Hash,
    raw: Vec<u8>,
}
impl Snapshot {
    fn make(binding: Hash, previous: Hash, head: Hash, pending: Vec<u8>) -> Result<Self> {
        ensure(
            pending.len() <= MAX_RECORD,
            "RESOURCE_WAIT control pending bound",
        )?;
        let mut raw = b"RLDFHEAD".to_vec();
        raw.extend([0, 1, 0, 1]);
        raw.extend(binding);
        raw.extend(previous);
        raw.extend(head);
        raw.extend((pending.len() as u32).to_be_bytes());
        raw.extend(&pending);
        let digest = codec::hash("CONTROL-HEAD", &raw);
        raw.extend(digest);
        Ok(Self {
            binding,
            previous,
            head,
            pending,
            digest,
            raw,
        })
    }
    fn read(path: &Path) -> Result<Self> {
        private(parent(path)?, false)?;
        private(path, true)?;
        let mut file = File::open(path).map_err(io)?;
        ensure(
            file.metadata().map_err(io)?.len() <= LIMIT as u64,
            "RESOURCE_WAIT control snapshot size",
        )?;
        let mut raw = vec![];
        Read::by_ref(&mut file)
            .take(LIMIT as u64 + 1)
            .read_to_end(&mut raw)
            .map_err(io)?;
        ensure(raw.len() <= LIMIT, "RESOURCE_WAIT control snapshot grew")?;
        let mut r = Reader { raw: &raw, at: 0 };
        ensure(
            r.take(8)? == b"RLDFHEAD" && r.take(4)? == [0, 1, 0, 1],
            "UNSUPPORTED trusted peer head",
        )?;
        let binding = r.hash()?;
        let previous = r.hash()?;
        let head = r.hash()?;
        let n = r.u32()? as usize;
        ensure(n <= MAX_RECORD, "RESOURCE_WAIT control pending length")?;
        let pending = r.take(n)?.to_vec();
        if !pending.is_empty() {
            ensure(
                record_heads(&pending)?.0 == head,
                "INVALID control pending predecessor",
            )?;
        }
        let digest = r.hash()?;
        ensure(
            r.at == raw.len() && digest == codec::hash("CONTROL-HEAD", &raw[..raw.len() - 32]),
            "INVALID control snapshot digest/tail",
        )?;
        Ok(Self {
            binding,
            previous,
            head,
            pending,
            digest,
            raw,
        })
    }
}
pub(super) struct Control {
    path: PathBuf,
    next: PathBuf,
    lock_path: PathBuf,
    lock: File,
    pub snapshot: Snapshot,
}
fn suffix(path: &Path, s: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(s);
    PathBuf::from(name)
}
fn fresh(path: &Path, raw: &[u8]) -> Result<()> {
    let mut o = OpenOptions::new();
    o.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path).map_err(io)?;
    f.write_all(raw).map_err(io)?;
    sync(&f, path)
}
impl Control {
    pub fn create(path: &Path, binding: Hash, head: Hash) -> Result<Self> {
        private(parent(path)?, false)?;
        let snapshot = Snapshot::make(binding, [0; 32], head, vec![])?;
        let lock_path = suffix(path, ".lock");
        fresh(&lock_path, &binding)?;
        fresh(path, &snapshot.raw)?;
        Self::open(path, false)
    }
    pub fn open(path: &Path, recovering: bool) -> Result<Self> {
        let snapshot = Snapshot::read(path)?;
        let lock_path = suffix(path, ".lock");
        private(&lock_path, true)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(io)?;
        FileExt::try_lock_exclusive(&lock).map_err(|_| "RESOURCE_WAIT trusted peer head writer")?;
        let mut raw = vec![];
        File::open(&lock_path)
            .map_err(io)?
            .take(33)
            .read_to_end(&mut raw)
            .map_err(io)?;
        ensure(raw == snapshot.binding, "INVALID control lease binding")?;
        let next = suffix(path, ".next");
        let mut c = Self {
            path: path.to_path_buf(),
            next,
            lock_path,
            lock,
            snapshot,
        };
        c.check_files()?;
        if !recovering {
            ensure(
                !c.next.try_exists().map_err(io)? && c.snapshot.pending.is_empty(),
                "RESOURCE_WAIT trusted peer head reconciliation required",
            )?;
        }
        Ok(c)
    }
    fn check_files(&mut self) -> Result<()> {
        private(parent(&self.path)?, false)?;
        private(&self.lock_path, true)?;
        let actual = fs::symlink_metadata(&self.lock_path).map_err(io)?;
        let opened = self.lock.metadata().map_err(io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ensure(
                actual.ino() == opened.ino() && actual.dev() == opened.dev(),
                "INVALID replaced control lease",
            )?;
        }
        ensure(
            actual.len() == 32 && opened.len() == 32,
            "INVALID control lease length",
        )?;
        let mut binding = vec![];
        File::open(&self.lock_path)
            .map_err(io)?
            .take(33)
            .read_to_end(&mut binding)
            .map_err(io)?;
        ensure(
            binding == self.snapshot.binding,
            "INVALID changed control lease binding",
        )?;
        ensure(
            Snapshot::read(&self.path)?.raw == self.snapshot.raw,
            "INVALID changed trusted peer head",
        )?;
        Ok(())
    }
    pub fn check(&mut self, head: Hash) -> Result<()> {
        self.check_files()?;
        ensure(
            !self.next.try_exists().map_err(io)?
                && self.snapshot.pending.is_empty()
                && self.snapshot.head == head,
            "RESOURCE_WAIT inconsistent trusted peer head",
        )
    }
    pub fn candidate(&mut self) -> Result<Option<Snapshot>> {
        self.check_files()?;
        if !self.next.try_exists().map_err(io)? {
            return Ok(None);
        }
        let candidate = Snapshot::read(&self.next)?;
        ensure(
            candidate.binding == self.snapshot.binding
                && candidate.previous == self.snapshot.digest,
            "INVALID control publication predecessor",
        )?;
        if self.snapshot.pending.is_empty() {
            ensure(
                !candidate.pending.is_empty() && candidate.head == self.snapshot.head,
                "INVALID control prepare publication",
            )?;
        } else {
            ensure(
                candidate.pending.is_empty()
                    && candidate.head == record_heads(&self.snapshot.pending)?.1,
                "INVALID control commit publication",
            )?;
        }
        Ok(Some(candidate))
    }
    pub fn publish_candidate(&mut self, candidate: Snapshot) -> Result<()> {
        self.check_files()?;
        ensure(
            Snapshot::read(&self.next)?.raw == candidate.raw
                && candidate.previous == self.snapshot.digest
                && candidate.binding == self.snapshot.binding,
            "INVALID changed control publication",
        )?;
        fs::rename(&self.next, &self.path).map_err(io)?;
        File::open(parent(&self.path)?)
            .and_then(|f| f.sync_all())
            .map_err(io)?;
        self.snapshot = candidate;
        self.check_files()
    }
    fn publish(
        &mut self,
        next: Snapshot,
        boundary: Boundary,
        observe: &mut dyn FnMut(Boundary) -> Result<()>,
    ) -> Result<()> {
        self.check_files()?;
        fresh(&self.next, &next.raw)?;
        observe(boundary)?;
        self.publish_candidate(next)
    }
    pub fn begin(
        &mut self,
        record: &[u8],
        prior: Hash,
        observe: &mut dyn FnMut(Boundary) -> Result<()>,
    ) -> Result<()> {
        self.check(prior)?;
        ensure(
            record_heads(record)?.0 == prior,
            "INVALID control record prior",
        )?;
        let next = Snapshot::make(
            self.snapshot.binding,
            self.snapshot.digest,
            prior,
            record.to_vec(),
        )?;
        self.publish(next, Boundary::PrepareNextDurable, observe)?;
        observe(Boundary::Prepared)
    }
    pub fn finish(
        &mut self,
        head: Hash,
        observe: &mut dyn FnMut(Boundary) -> Result<()>,
    ) -> Result<()> {
        self.check_files()?;
        ensure(
            !self.snapshot.pending.is_empty() && record_heads(&self.snapshot.pending)?.1 == head,
            "INVALID control record completion",
        )?;
        let next = Snapshot::make(self.snapshot.binding, self.snapshot.digest, head, vec![])?;
        self.publish(next, Boundary::CommitNextDurable, observe)?;
        observe(Boundary::Committed)
    }
}
pub(super) fn record_heads(raw: &[u8]) -> Result<(Hash, Hash)> {
    ensure(
        (89..=MAX_RECORD).contains(&raw.len())
            && u32::from_be_bytes(raw[..4].try_into().unwrap()) as usize == raw.len() - 4,
        "INVALID controlled record length",
    )?;
    let prior = raw[12..44].try_into().unwrap();
    let next: Hash = raw[raw.len() - 32..].try_into().unwrap();
    ensure(
        next == codec::hash("BOX-RECORD", &raw[4..raw.len() - 32]),
        "INVALID controlled record digest",
    )?;
    Ok((prior, next))
}
