//! Explicitly trusted local caller input, never independent freshness or value.
use super::{hash, journal::Intent, sync_dir, write_new, Session};
use crate::{
    fast_payment::ensure,
    fast_retainer::{io, parent, private, Reader},
    kernel::{Hash, Result},
};
use fs2::FileExt;
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
};
pub(super) const PENDING_LIMIT: usize = 1048576 - 69;
pub(super) const LIMIT: usize = 144 + PENDING_LIMIT;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Boundary {
    PrepareNextDurable,
    Prepared,
    CommitNextDurable,
    Committed,
}
#[derive(Clone)]
struct Snapshot {
    binding: Hash,
    previous: Hash,
    head: Hash,
    pending: Vec<u8>,
    digest: Hash,
    raw: Vec<u8>,
}
impl Snapshot {
    fn make(binding: Hash, previous: Hash, head: Hash, pending: Vec<u8>) -> Result<Self> {
        ensure(
            pending.len() <= PENDING_LIMIT,
            "RESOURCE_WAIT caller control pending size",
        )?;
        let mut raw = b"RLDFCALL".to_vec();
        raw.extend([0, 1, 0, 1]);
        raw.extend(binding);
        raw.extend(previous);
        raw.extend(head);
        raw.extend((pending.len() as u32).to_be_bytes());
        raw.extend(&pending);
        let digest = hash("CONTROL", &raw);
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
        let f = File::open(path).map_err(io)?;
        ensure(
            f.metadata().map_err(io)?.len() <= LIMIT as u64,
            "RESOURCE_WAIT caller control size",
        )?;
        let mut raw = vec![];
        f.take(LIMIT as u64 + 1).read_to_end(&mut raw).map_err(io)?;
        ensure(raw.len() <= LIMIT, "RESOURCE_WAIT caller control grew")?;
        let mut r = Reader { raw: &raw, at: 0 };
        ensure(
            r.take(8)? == b"RLDFCALL" && r.take(4)? == [0, 1, 0, 1],
            "UNSUPPORTED caller control",
        )?;
        let binding = r.hash()?;
        let previous = r.hash()?;
        let head = r.hash()?;
        let n = r.u32()? as usize;
        ensure(
            n <= PENDING_LIMIT,
            "RESOURCE_WAIT caller control pending length",
        )?;
        let pending = r.take(n)?.to_vec();
        let digest = r.hash()?;
        ensure(
            r.at == raw.len() && digest == hash("CONTROL", &raw[..raw.len() - 32]),
            "INVALID caller control digest/tail",
        )?;
        if !pending.is_empty() {
            intent(&pending)?;
        }
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
pub(super) fn intent(raw: &[u8]) -> Result<Intent> {
    let i: Intent = serde_json::from_slice(raw).map_err(|_| "INVALID caller control intent")?;
    ensure(
        serde_json::to_vec(&i).map_err(io)? == raw && i.id.0 != [0; 32],
        "INVALID caller control canonical intent",
    )?;
    i.action.shape()?;
    Ok(i)
}
fn suffix(p: &Path, s: &str) -> PathBuf {
    let mut b = p.as_os_str().to_os_string();
    b.push(s);
    PathBuf::from(b)
}
pub(super) struct SnapshotControl {
    path: PathBuf,
    next: PathBuf,
    lock_path: PathBuf,
    lock: File,
    snapshot: Snapshot,
    observer: Option<Box<dyn FnMut(Boundary) -> Result<()> + Send>>,
}
impl SnapshotControl {
    pub fn create(path: &Path, binding: Hash, head: Hash) -> Result<Self> {
        private(parent(path)?, false)?;
        let s = Snapshot::make(binding, [0; 32], head, vec![])?;
        write_new(&suffix(path, ".lock"), &binding)?;
        write_new(path, &s.raw)?;
        Self::open(path, false)
    }
    fn open(path: &Path, recovery: bool) -> Result<Self> {
        let snapshot = Snapshot::read(path)?;
        let lock_path = suffix(path, ".lock");
        private(&lock_path, true)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(io)?;
        FileExt::try_lock_exclusive(&lock).map_err(|_| "RESOURCE_WAIT caller control writer")?;
        let mut c = Self {
            path: path.to_path_buf(),
            next: suffix(path, ".next"),
            lock_path,
            lock,
            snapshot,
            observer: None,
        };
        c.files()?;
        if !recovery {
            c.check(c.snapshot.head)?;
        }
        Ok(c)
    }
    fn files(&mut self) -> Result<()> {
        private(parent(&self.path)?, false)?;
        private(&self.lock_path, true)?;
        let actual = fs::symlink_metadata(&self.lock_path).map_err(io)?;
        let opened = self.lock.metadata().map_err(io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ensure(
                actual.ino() == opened.ino() && actual.dev() == opened.dev(),
                "INVALID replaced caller control lease",
            )?;
        }
        ensure(
            actual.len() == 32 && opened.len() == 32,
            "INVALID caller control lease size",
        )?;
        let mut binding = vec![];
        File::open(&self.lock_path)
            .map_err(io)?
            .take(33)
            .read_to_end(&mut binding)
            .map_err(io)?;
        ensure(
            binding == self.snapshot.binding,
            "INVALID caller control lease binding",
        )?;
        ensure(
            Snapshot::read(&self.path)?.raw == self.snapshot.raw,
            "INVALID changed caller control",
        )
    }
    pub fn check(&mut self, head: Hash) -> Result<()> {
        self.files()?;
        ensure(
            !self.next.try_exists().map_err(io)? && self.snapshot.pending.is_empty(),
            "RESOURCE_WAIT caller control reconciliation required",
        )?;
        ensure(
            self.snapshot.head == head,
            "INVALID controlled caller latest head",
        )
    }
    fn observe(&mut self, b: Boundary) -> Result<()> {
        if let Some(f) = &mut self.observer {
            f(b)?;
        }
        Ok(())
    }
    fn publish_candidate(&mut self, s: Snapshot) -> Result<()> {
        self.files()?;
        ensure(
            Snapshot::read(&self.next)?.raw == s.raw
                && s.previous == self.snapshot.digest
                && s.binding == self.snapshot.binding,
            "INVALID caller control publication predecessor",
        )?;
        fs::rename(&self.next, &self.path).map_err(io)?;
        sync_dir(parent(&self.path)?)?;
        self.snapshot = s;
        self.files()
    }
    fn publish(&mut self, s: Snapshot, b: Boundary) -> Result<()> {
        self.files()?;
        write_new(&self.next, &s.raw)?;
        self.observe(b)?;
        self.publish_candidate(s)
    }
    pub fn begin(&mut self, prior: Hash, i: &Intent) -> Result<()> {
        self.check(prior)?;
        let raw = serde_json::to_vec(i).map_err(io)?;
        intent(&raw)?;
        let s = Snapshot::make(self.snapshot.binding, self.snapshot.digest, prior, raw)?;
        self.publish(s, Boundary::PrepareNextDurable)?;
        self.observe(Boundary::Prepared)
    }
    pub fn finish(&mut self, head: Hash) -> Result<()> {
        self.files()?;
        ensure(
            !self.snapshot.pending.is_empty(),
            "INVALID caller control missing request",
        )?;
        let s = Snapshot::make(self.snapshot.binding, self.snapshot.digest, head, vec![])?;
        self.publish(s, Boundary::CommitNextDurable)?;
        self.observe(Boundary::Committed)
    }
}
impl Session {
    pub fn create_controlled(
        root: &Path,
        g: &[u8],
        chain: Hash,
        file: &Path,
        now: u64,
    ) -> Result<Self> {
        Self::create_profile(root, g, chain, now, Some((file, false)))
    }
    pub fn open_controlled(
        root: &Path,
        g: &[u8],
        chain: Hash,
        file: &Path,
        now: u64,
    ) -> Result<Self> {
        let c = SnapshotControl::open(file, false)?;
        let mut s = Self::open_profile(root, g, chain, c.snapshot.head, now, 2)?;
        ensure(
            s.caller.binding() == c.snapshot.binding,
            "INVALID caller control header binding",
        )?;
        s.control = Some(Control::Snapshot(c));
        s.check_control(s.head())?;
        Ok(s)
    }
    pub fn set_control_observer(
        &mut self,
        observer: impl FnMut(Boundary) -> Result<()> + Send + 'static,
    ) -> Result<()> {
        self.control
            .as_mut()
            .ok_or("INVALID uncontrolled caller observer")?
            .set_observer(Box::new(observer));
        Ok(())
    }
    pub fn controlled(&self) -> bool {
        self.control.is_some()
    }
    pub(super) fn check_control(&mut self, head: Hash) -> Result<()> {
        if let Some(c) = &mut self.control {
            c.check(head)?;
        }
        Ok(())
    }
    /// Finish only the exact pre-retained request or its fully audited absence.
    /// No request is first-executed and no signing key is loaded here.
    pub fn recover_controlled(
        root: &Path,
        g: &[u8],
        chain: Hash,
        file: &Path,
        now: u64,
    ) -> Result<(Self, serde_json::Value)> {
        let mut c = SnapshotControl::open(file, true)?;
        let candidate = if c.next.try_exists().map_err(io)? {
            let next = Snapshot::read(&c.next)?;
            ensure(
                next.binding == c.snapshot.binding && next.previous == c.snapshot.digest,
                "INVALID caller control candidate predecessor",
            )?;
            if c.snapshot.pending.is_empty() {
                ensure(
                    !next.pending.is_empty() && next.head == c.snapshot.head,
                    "INVALID caller control prepare candidate",
                )?;
            } else {
                ensure(
                    next.pending.is_empty(),
                    "INVALID caller control commit candidate",
                )?;
            }
            Some(next)
        } else {
            None
        };
        let pending = if c.snapshot.pending.is_empty() {
            candidate
                .as_ref()
                .map(|s| s.pending.clone())
                .unwrap_or_default()
        } else {
            c.snapshot.pending.clone()
        };
        let prior = c.snapshot.head;
        if pending.is_empty() {
            let mut s = Self::open_profile(root, g, chain, prior, now, 2)?;
            ensure(
                s.caller.binding() == c.snapshot.binding,
                "INVALID caller control recovery binding",
            )?;
            let proof = if s.caller.ops.is_empty() {
                None
            } else {
                Some(s.output(now)?)
            };
            s.control = Some(Control::Snapshot(c));
            let mut out = s.status(s.head(), now)?;
            if let Some(serde_json::Value::Object(proof)) = proof {
                out.as_object_mut().unwrap().extend(proof);
            }
            out["recovery_first_execution"] = false.into();
            out["recovery_key_loaded"] = false.into();
            return Ok((s, out));
        }
        let i = intent(&pending)?;
        ensure(i.at <= now, "CLOCK_WAIT caller control intent")?;
        // Inspect exact canonical framing under its own lease before selecting
        // a recovery path. This inspection grants no child/native authority.
        let j = super::Journal::open(&root.join("caller.journal"), g, chain, None, now, 2)?;
        ensure(
            j.binding() == c.snapshot.binding,
            "INVALID caller control recovery binding",
        )?;
        let unchanged = j.head == prior;
        let exact = j.ops.last().is_some_and(|o| {
            o.prior == prior && serde_json::to_vec(&o.intent).is_ok_and(|b| b == pending)
        });
        drop(j);
        if c.snapshot.pending.is_empty() {
            ensure(
                unchanged,
                "INVALID request before control prepare publication",
            )?;
        }
        let mut s = if let Some(next) = candidate.as_ref().filter(|n| n.pending.is_empty()) {
            // A commit candidate can exist only after a complete audited reply.
            ensure(
                exact || (unchanged && next.head == prior),
                "INVALID caller commit candidate request",
            )?;
            Self::open_profile(root, g, chain, next.head, now, 2)?
        } else if unchanged {
            Self::open_profile(root, g, chain, prior, now, 2)?
        } else {
            ensure(exact, "INVALID exact controlled recovery request")?;
            Self::recover_profile(root, g, chain, prior, (i.id, i.action.digest()?), now, 2)?.0
        };
        ensure(
            s.caller.binding() == c.snapshot.binding,
            "INVALID recovered caller control binding",
        )?;
        let proof = if exact { Some(s.output(now)?) } else { None };
        if c.snapshot.pending.is_empty() {
            c.publish_candidate(
                candidate
                    .clone()
                    .ok_or("MISSING caller prepare candidate")?,
            )?;
        }
        if let Some(next) = candidate.filter(|n| n.pending.is_empty()) {
            c.publish_candidate(next)?;
        } else {
            c.finish(s.head())?;
        }
        c.check(s.head())?;
        s.control = Some(Control::Snapshot(c));
        let mut out = s.status(s.head(), now)?;
        if let Some(serde_json::Value::Object(proof)) = proof {
            out.as_object_mut().unwrap().extend(proof);
        }
        out["recovery_first_execution"] = false.into();
        out["recovery_key_loaded"] = false.into();
        out["retained_request"] = serde_json::to_value(i.id).map_err(io)?;
        Ok((s, out))
    }
}
pub(super) enum Control {
    Snapshot(SnapshotControl),
    Logged(super::head_log::HeadLog),
}
impl Control {
    pub(super) fn authorize(&mut self, prior: Hash, i: &Intent) -> Result<()> {
        match self {
            Self::Snapshot(c) => {
                c.files()?;
                ensure(
                    c.snapshot.head == prior
                        && c.snapshot.pending == serde_json::to_vec(i).map_err(io)?,
                    "INVALID snapshot prepared caller binding",
                )
            }
            Self::Logged(c) => c.authorize(prior, i),
        }
    }
    pub(super) fn check(&mut self, head: Hash) -> Result<()> {
        match self {
            Self::Snapshot(c) => c.check(head),
            Self::Logged(c) => c.check(head),
        }
    }
    pub(super) fn begin(&mut self, head: Hash, intent: &Intent) -> Result<()> {
        match self {
            Self::Snapshot(c) => c.begin(head, intent),
            Self::Logged(c) => c.begin(head, intent),
        }
    }
    pub(super) fn finish(&mut self, head: Hash) -> Result<()> {
        match self {
            Self::Snapshot(c) => c.finish(head),
            Self::Logged(c) => c.finish(head),
        }
    }
    pub(super) fn set_observer(&mut self, f: Box<dyn FnMut(Boundary) -> Result<()> + Send>) {
        match self {
            Self::Snapshot(c) => c.observer = Some(f),
            Self::Logged(c) => c.set_observer(f),
        }
    }
    pub(super) fn storage(&self) -> &'static str {
        match self {
            Self::Snapshot(_) => "SNAPSHOT",
            Self::Logged(_) => "APPEND_ONLY",
        }
    }
    pub(super) fn create(path: &Path, binding: Hash, head: Hash, logged: bool) -> Result<Self> {
        if logged {
            Ok(Self::Logged(super::head_log::HeadLog::create(
                path, binding, head,
            )?))
        } else {
            Ok(Self::Snapshot(SnapshotControl::create(
                path, binding, head,
            )?))
        }
    }
}
