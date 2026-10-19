//! Key-free caller requests and verified child-head effects. These bytes never
//! initialize a ledger or authorize a signature without complete child audits.
use super::{hash, Action, Id};
use crate::{
    fast_payment::ensure,
    fast_retainer::{io, parent, private, sync, Reader},
    kernel::{Hash, Result},
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
pub const LIMIT: usize = 32 * 1024 * 1024;
const REPLY: usize = 4096;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub id: Id,
    pub action: Action,
    pub at: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Done {
    pub id: Id,
    pub request: Id,
    pub effect: Option<Id>,
    pub review: Option<Id>,
    pub diagnostic: Option<String>,
}
#[derive(Clone)]
pub struct Op {
    pub intent: Intent,
    pub prior: Hash,
    pub done: Option<Done>,
}
pub struct Journal {
    path: PathBuf,
    file: File,
    prefix: Vec<u8>,
    pub head: Hash,
    pub native_initial: Hash,
    pub created: u64,
    pub ops: Vec<Op>,
    poisoned: bool,
}
fn record(kind: u8, prior: Hash, payload: &[u8]) -> Vec<u8> {
    let mut b = vec![kind];
    b.extend(prior);
    b.extend((payload.len() as u32).to_be_bytes());
    b.extend(payload);
    let h = hash("RECORD", &b);
    b.extend(h);
    [(b.len() as u32).to_be_bytes().as_slice(), &b].concat()
}
fn file(path: &Path) -> Result<File> {
    private(parent(path)?, false)?;
    private(path, true)?;
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(io)?;
    FileExt::try_lock_exclusive(&f).map_err(|_| "RESOURCE_WAIT caller writer")?;
    Ok(f)
}
impl Journal {
    pub fn create(
        path: &Path,
        genesis: &[u8],
        chain: Hash,
        native: Hash,
        now: u64,
    ) -> Result<Self> {
        ensure(genesis.len() == 113, "INVALID caller genesis")?;
        private(parent(path)?, false)?;
        let mut options = OpenOptions::new();
        options.create_new(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut f = options.open(path).map_err(io)?;
        FileExt::try_lock_exclusive(&f).map_err(|_| "RESOURCE_WAIT caller writer")?;
        let mut h = b"RLDFSES1".to_vec();
        h.extend([0, 1, 0, 1]);
        h.extend(chain);
        h.extend(genesis);
        h.extend(native);
        h.extend(now.to_be_bytes());
        f.write_all(&h).map_err(io)?;
        sync(&f, path)?;
        let head = hash("HEADER", &h);
        Self::read(path, f, genesis, chain, Some(head), now)
    }
    pub fn open(path: &Path, g: &[u8], c: Hash, expected: Option<Hash>, now: u64) -> Result<Self> {
        Self::read(path, file(path)?, g, c, expected, now)
    }
    fn read(
        path: &Path,
        mut file: File,
        g: &[u8],
        chain: Hash,
        expected: Option<Hash>,
        now: u64,
    ) -> Result<Self> {
        ensure(
            file.metadata().map_err(io)?.len() <= LIMIT as u64,
            "RESOURCE_WAIT caller bytes",
        )?;
        file.seek(SeekFrom::Start(0)).map_err(io)?;
        let mut prefix = Vec::new();
        Read::by_ref(&mut file)
            .take(LIMIT as u64 + 1)
            .read_to_end(&mut prefix)
            .map_err(io)?;
        ensure(prefix.len() <= LIMIT, "RESOURCE_WAIT caller grew")?;
        let mut r = Reader {
            raw: &prefix,
            at: 0,
        };
        ensure(
            r.take(8)? == b"RLDFSES1" && r.take(4)? == [0, 1, 0, 1],
            "UNSUPPORTED caller journal",
        )?;
        ensure(
            r.hash()? == chain && r.take(113)? == g,
            "INVALID caller genesis binding",
        )?;
        let native_initial = r.hash()?;
        let created = r.u64()?;
        ensure(created <= now, "CLOCK_WAIT caller creation")?;
        let mut head = hash("HEADER", &prefix[..r.at]);
        let mut ops: Vec<Op> = vec![];
        let mut clock = created;
        while r.at < prefix.len() {
            let n = r.u32()? as usize;
            ensure(
                (69..=1024 * 1024).contains(&n),
                "INVALID caller record bound",
            )?;
            let b = r.take(n)?;
            let mut p = Reader { raw: b, at: 0 };
            let kind = p.take(1)?[0];
            ensure(p.hash()? == head, "INVALID caller record predecessor")?;
            let size = p.u32()? as usize;
            ensure(size + 69 == n, "INVALID caller payload size")?;
            let payload = p.take(size)?;
            let next = p.hash()?;
            ensure(
                next == hash("RECORD", &b[..n - 32]),
                "INVALID caller record digest",
            )?;
            if kind == 1 {
                ensure(
                    ops.last().is_none_or(|o| o.done.is_some()) && ops.len() < 65536,
                    "RESOURCE_WAIT caller pending/count",
                )?;
                let intent: Intent =
                    serde_json::from_slice(payload).map_err(|_| "INVALID caller intent")?;
                ensure(
                    serde_json::to_vec(&intent).map_err(io)? == payload
                        && intent.id.0 != [0; 32]
                        && !ops.iter().any(|o| o.intent.id == intent.id),
                    "INVALID caller canonical/unique intent",
                )?;
                ensure(
                    intent.at >= clock && intent.at <= now,
                    "CLOCK_WAIT caller intent",
                )?;
                intent.action.shape()?;
                clock = intent.at;
                ops.push(Op {
                    intent,
                    prior: head,
                    done: None,
                });
            } else if kind == 2 {
                ensure(size <= REPLY, "INVALID caller reply bound")?;
                let done: Done =
                    serde_json::from_slice(payload).map_err(|_| "INVALID caller reply")?;
                ensure(
                    serde_json::to_vec(&done).map_err(io)? == payload
                        && done.diagnostic.as_ref().is_none_or(|s| s.len() <= 256),
                    "INVALID caller canonical reply",
                )?;
                let o = ops.last_mut().ok_or("INVALID caller unprepared reply")?;
                ensure(
                    o.done.is_none()
                        && done.id == o.intent.id
                        && done.request == o.intent.action.digest()?,
                    "INVALID caller response binding",
                )?;
                o.done = Some(done);
            } else {
                return Err("UNSUPPORTED caller record kind".into());
            }
            head = next;
        }
        ensure(
            expected.is_none_or(|e| e == head),
            "INVALID caller independently pinned latest head",
        )?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            prefix,
            head,
            native_initial,
            created,
            ops,
            poisoned: false,
        })
    }
    pub fn check(&mut self, head: Hash) -> Result<()> {
        ensure(!self.poisoned, "RESOURCE_WAIT caller restart required")?;
        ensure(head == self.head, "INVALID caller latest head")?;
        self.poisoned = true;
        private(parent(&self.path)?, false)?;
        private(&self.path, true)?;
        let path = fs::symlink_metadata(&self.path).map_err(io)?;
        let opened = self.file.metadata().map_err(io)?;
        ensure(
            path.len() == self.prefix.len() as u64 && path.len() == opened.len(),
            "INVALID caller changed length",
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ensure(
                path.dev() == opened.dev() && path.ino() == opened.ino(),
                "INVALID caller replaced file",
            )?;
        }
        self.file.seek(SeekFrom::Start(0)).map_err(io)?;
        let mut b = [0; 65536];
        for c in self.prefix.chunks(b.len()) {
            self.file.read_exact(&mut b[..c.len()]).map_err(io)?;
            ensure(c == &b[..c.len()], "INVALID caller changed prefix")?;
        }
        self.poisoned = false;
        Ok(())
    }
    fn append(&mut self, kind: u8, payload: &[u8]) -> Result<()> {
        self.check(self.head)?;
        let raw = record(kind, self.head, payload);
        ensure(
            self.prefix.len() + raw.len() <= LIMIT,
            "RESOURCE_WAIT caller capacity",
        )?;
        self.poisoned = true;
        self.file
            .seek(SeekFrom::End(0))
            .and_then(|_| self.file.write_all(&raw))
            .map_err(io)?;
        sync(&self.file, &self.path)?;
        self.head = raw[raw.len() - 32..].try_into().unwrap();
        self.prefix.extend(raw);
        self.poisoned = false;
        self.check(self.head)
    }
    pub fn begin(&mut self, id: Id, action: Action, now: u64) -> Result<()> {
        self.check(self.head)?;
        action.shape()?;
        ensure(
            id.0 != [0; 32]
                && self.ops.len() < 65536
                && !self.ops.iter().any(|o| o.intent.id == id),
            "CONFLICT caller request ID/count",
        )?;
        ensure(
            self.ops.last().is_none_or(|o| o.done.is_some()),
            "RESOURCE_WAIT caller pending recovery",
        )?;
        ensure(
            now >= self.ops.last().map_or(self.created, |o| o.intent.at),
            "CLOCK_WAIT caller request",
        )?;
        let intent = Intent {
            id,
            action,
            at: now,
        };
        let raw = serde_json::to_vec(&intent).map_err(io)?;
        ensure(
            raw.len() + 69 <= 1024 * 1024
                && self.prefix.len() + raw.len() + 73 + REPLY + 73 <= LIMIT,
            "RESOURCE_WAIT caller complete response reservation",
        )?;
        let prior = self.head;
        self.append(1, &raw)?;
        self.ops.push(Op {
            intent,
            prior,
            done: None,
        });
        Ok(())
    }
    pub fn finish(
        &mut self,
        effect: Option<Id>,
        review: Option<Id>,
        diagnostic: Option<String>,
    ) -> Result<()> {
        let o = self.ops.last().ok_or("MISSING caller pending")?;
        ensure(o.done.is_none(), "CONFLICT caller already complete")?;
        let done = Done {
            id: o.intent.id,
            request: o.intent.action.digest()?,
            effect,
            review,
            diagnostic,
        };
        let raw = serde_json::to_vec(&done).map_err(io)?;
        ensure(
            raw.len() <= REPLY && done.diagnostic.as_ref().is_none_or(|s| s.len() <= 256),
            "INVALID caller reply size",
        )?;
        self.append(2, &raw)?;
        self.ops.last_mut().unwrap().done = Some(done);
        Ok(())
    }
}
