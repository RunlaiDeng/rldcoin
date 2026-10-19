//! One exclusive native fast-node selector, replayed from pinned genesis.
//! All known full branches persist; storage hashes never initialize a ledger.
use crate::{
    fast_payment::ensure,
    fast_retainer::{io, parent, private, sync, Current, Reader},
    kernel::{
        fast::{self, Ledger},
        Hash, Result, Tip,
    },
};
use fs2::FileExt;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
#[derive(Clone, Copy)]
pub struct Limits {
    pub bytes: usize,
    pub blocks: usize,
    pub coins: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            bytes: 256 * 1024 * 1024,
            blocks: 262144,
            coins: 100000,
        }
    }
}
impl Limits {
    fn check(self) -> Result<()> {
        ensure(
            (165..=256 * 1024 * 1024).contains(&self.bytes)
                && (1..=262144).contains(&self.blocks)
                && (1..=1000000).contains(&self.coins),
            "INVALID native local limits",
        )
    }
}
fn hash(label: &str, raw: &[u8]) -> Hash {
    Sha256::digest([b"RLD-FAST-NODE-1/".as_slice(), label.as_bytes(), &[0], raw].concat()).into()
}
struct Block {
    raw: Vec<u8>,
    tip: Tip,
    observed: u64,
}
struct Branches {
    genesis: Vec<u8>,
    ledger: Ledger,
    blocks: BTreeMap<Hash, Block>,
    revision: u128,
    coins: usize,
}
impl Branches {
    fn new(genesis: &[u8], chain: Hash, coins: usize) -> Result<Self> {
        Ok(Self {
            genesis: genesis.to_vec(),
            ledger: Ledger::from_genesis(genesis, chain, coins)?,
            blocks: BTreeMap::new(),
            revision: 0,
            coins,
        })
    }
    fn replay(&self, mut tip: Hash) -> Result<Ledger> {
        if tip == self.ledger.tip().id() {
            return Ok(self.ledger.clone());
        }
        let mut route = Vec::new();
        while tip != self.ledger.chain_id() {
            let block = self
                .blocks
                .get(&tip)
                .ok_or("WAITING_FOR_HISTORY native parent")?;
            ensure(
                route.len() < self.blocks.len(),
                "INVALID native ancestry cycle",
            )?;
            ensure(
                fast::block_id(&block.raw)? == tip,
                "INVALID native retained block index",
            )?;
            route.push(block);
            tip = block.raw[36..68].try_into().unwrap();
        }
        let mut ledger = Ledger::from_genesis(&self.genesis, self.ledger.chain_id(), self.coins)?;
        for block in route.into_iter().rev() {
            ledger.execute(&block.raw, block.observed)?;
            ensure(ledger.tip() == &block.tip, "INVALID native retained tip")?;
        }
        Ok(ledger)
    }
    fn candidate(&self, raw: &[u8], now: u64) -> Result<(Ledger, bool, u128)> {
        fast::block_id(raw)?;
        ensure(raw[4..36] == self.ledger.chain_id(), "INVALID native chain")?;
        let parent = raw[36..68].try_into().unwrap();
        let mut ledger = self.replay(parent)?;
        ledger.execute(raw, now)?;
        ensure(ledger.tip().eligible(now), "CLOCK_WAIT native candidate")?;
        let selected = ledger.tip().preferred_to(self.ledger.tip());
        let revision = self
            .revision
            .checked_add(u128::from(selected))
            .ok_or("RESOURCE_WAIT native revision exhausted")?;
        Ok((ledger, selected, revision))
    }
    fn install(
        &mut self,
        raw: &[u8],
        observed: u64,
        candidate: Ledger,
        selected: bool,
        revision: u128,
    ) {
        self.blocks.insert(
            candidate.tip().id(),
            Block {
                raw: raw.to_vec(),
                tip: candidate.tip().clone(),
                observed,
            },
        );
        if selected {
            self.ledger = candidate;
        }
        self.revision = revision;
    }
}
#[derive(Clone, Debug)]
pub struct Outcome {
    pub head: Hash,
    pub tip: Hash,
    pub revision: u128,
    pub block: Hash,
    pub selected: bool,
    pub already_known: bool,
}
pub struct Store {
    path: PathBuf,
    file: File,
    prefix: Vec<u8>,
    native: Branches,
    head: Hash,
    prior: Hash,
    index: u64,
    clock: u64,
    last_block: Option<Hash>,
    limits: Limits,
    poisoned: bool,
}
impl Store {
    pub fn create(
        path: &Path,
        genesis: &[u8],
        chain: Hash,
        now: u64,
        limits: Limits,
    ) -> Result<Self> {
        limits.check()?;
        let native = Branches::new(genesis, chain, limits.coins)?;
        ensure(
            native.ledger.tip().eligible(now),
            "CLOCK_WAIT native genesis",
        )?;
        let mut header = b"RLDFSEL1".to_vec();
        header.extend([0, 1, 0, 1]);
        header.extend(chain);
        header.extend(genesis);
        header.extend(now.to_be_bytes());
        private(parent(path)?, false)?;
        let mut options = OpenOptions::new();
        options.create_new(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path).map_err(io)?;
        FileExt::try_lock_exclusive(&file).map_err(|_| "RESOURCE_WAIT native writer")?;
        file.write_all(&header).map_err(io)?;
        sync(&file, path)?;
        let head = hash("HEADER", &header);
        Self::from_file(path, file, genesis, chain, Some(head), now, limits)
    }
    fn file(path: &Path) -> Result<File> {
        private(parent(path)?, false)?;
        private(path, true)?;
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(io)?;
        FileExt::try_lock_exclusive(&f).map_err(|_| "RESOURCE_WAIT native writer")?;
        Ok(f)
    }
    pub fn open(
        path: &Path,
        genesis: &[u8],
        chain: Hash,
        head: Hash,
        now: u64,
        limits: Limits,
    ) -> Result<Self> {
        Self::from_file(
            path,
            Self::file(path)?,
            genesis,
            chain,
            Some(head),
            now,
            limits,
        )
    }
    fn from_file(
        path: &Path,
        mut file: File,
        genesis: &[u8],
        chain: Hash,
        expected: Option<Hash>,
        now: u64,
        limits: Limits,
    ) -> Result<Self> {
        limits.check()?;
        ensure(
            file.metadata().map_err(io)?.len() <= limits.bytes as u64,
            "RESOURCE_WAIT native byte budget",
        )?;
        let mut prefix = Vec::new();
        file.seek(SeekFrom::Start(0)).map_err(io)?;
        Read::by_ref(&mut file)
            .take(limits.bytes as u64 + 1)
            .read_to_end(&mut prefix)
            .map_err(io)?;
        ensure(
            prefix.len() <= limits.bytes,
            "RESOURCE_WAIT native journal grew",
        )?;
        let mut r = Reader {
            raw: &prefix,
            at: 0,
        };
        ensure(
            r.take(8)? == b"RLDFSEL1" && r.take(4)? == [0, 1, 0, 1],
            "UNSUPPORTED native store",
        )?;
        ensure(
            r.hash()? == chain && r.take(113)? == genesis,
            "INVALID native genesis binding",
        )?;
        let mut clock = r.u64()?;
        ensure(clock <= now, "CLOCK_WAIT native opening clock")?;
        let mut native = Branches::new(genesis, chain, limits.coins)?;
        ensure(
            native.ledger.tip().eligible(clock),
            "CLOCK_WAIT native genesis",
        )?;
        let mut head = hash("HEADER", &prefix[..r.at]);
        let mut prior = head;
        let mut index = 0;
        let mut last_block = None;
        while r.at < prefix.len() {
            ensure(
                native.blocks.len() < limits.blocks,
                "RESOURCE_WAIT native block count",
            )?;
            let n = r.u32()? as usize;
            ensure((402..=262276).contains(&n), "INVALID native record size")?;
            let raw = r.take(n)?;
            let mut entry = Reader { raw, at: 0 };
            let number = entry.u64()?;
            let previous = entry.hash()?;
            let observed = entry.u64()?;
            let size = entry.u32()? as usize;
            ensure(
                (270..=262144).contains(&size) && n == 132 + size,
                "INVALID native recorded block length",
            )?;
            let block = entry.take(size)?;
            let selected_tip = entry.hash()?;
            let revision = u128::from_be_bytes(entry.take(16)?.try_into().unwrap());
            let digest = entry.hash()?;
            ensure(
                number == index + 1 && previous == head && digest == hash("RECORD", &raw[..n - 32]),
                "INVALID native record chain",
            )?;
            ensure(
                observed >= clock && observed <= now,
                "CLOCK_WAIT native admission clock",
            )?;
            let id = fast::block_id(block)?;
            ensure(
                !native.blocks.contains_key(&id),
                "INVALID native duplicate journal block",
            )?;
            let (candidate, selected, new_revision) = native.candidate(block, observed)?;
            let selected_id = if selected {
                candidate.tip().id()
            } else {
                native.ledger.tip().id()
            };
            ensure(
                selected_tip == selected_id && revision == new_revision,
                "INVALID native recorded selection",
            )?;
            native.install(block, observed, candidate, selected, new_revision);
            prior = head;
            head = digest;
            index = number;
            clock = observed;
            last_block = Some(id);
        }
        ensure(
            expected.is_none_or(|h| h == head),
            "INVALID native independently pinned latest head",
        )?;
        ensure(
            native.ledger.tip().eligible(now),
            "CLOCK_WAIT native selected head",
        )?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            prefix,
            native,
            head,
            prior,
            index,
            clock,
            last_block,
            limits,
            poisoned: false,
        })
    }
    fn prefix(&mut self, expected: Hash) -> Result<()> {
        ensure(!self.poisoned, "RESOURCE_WAIT native restart required")?;
        ensure(expected == self.head, "INVALID native caller storage head")?;
        // A stale caller head is harmless; an actual custody/prefix fault needs
        // complete cold verification even if the path later looks repaired.
        self.poisoned = true;
        private(parent(&self.path)?, false)?;
        private(&self.path, true)?;
        let path = fs::symlink_metadata(&self.path).map_err(io)?;
        let opened = self.file.metadata().map_err(io)?;
        ensure(
            path.len() == self.prefix.len() as u64 && opened.len() == path.len(),
            "INVALID native changed length",
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ensure(
                path.dev() == opened.dev() && path.ino() == opened.ino(),
                "INVALID native replaced file",
            )?;
        }
        self.file.seek(SeekFrom::Start(0)).map_err(io)?;
        let mut buffer = [0; 65536];
        for chunk in self.prefix.chunks(buffer.len()) {
            self.file
                .read_exact(&mut buffer[..chunk.len()])
                .map_err(io)?;
            ensure(
                chunk == &buffer[..chunk.len()],
                "INVALID native changed prefix",
            )?;
        }
        self.poisoned = false;
        Ok(())
    }
    pub fn check(&mut self, head: Hash, tip: Hash, now: u64) -> Result<()> {
        self.prefix(head)?;
        ensure(
            tip == self.native.ledger.tip().id(),
            "CONFLICT native selected head",
        )?;
        ensure(now >= self.clock, "CLOCK_WAIT native clock rollback")?;
        ensure(
            self.native.ledger.tip().eligible(now),
            "CLOCK_WAIT native selected head",
        )?;
        self.clock = now;
        Ok(())
    }
    pub fn current(&mut self, head: Hash, tip: Hash, now: u64) -> Result<Current<'_>> {
        self.check(head, tip, now)?;
        Ok(Current {
            ledger: &self.native.ledger,
            expected_tip: tip,
            now,
        })
    }
    pub fn ledger(&self) -> &Ledger {
        &self.native.ledger
    }
    pub fn head(&self) -> Hash {
        self.head
    }
    pub fn revision(&self) -> u128 {
        self.native.revision
    }
    pub fn known_blocks(&self) -> usize {
        self.native.blocks.len()
    }
    pub fn storage_ready(&self) -> bool {
        !self.poisoned
    }
    pub fn block(&self, id: Hash) -> Result<&[u8]> {
        self.native
            .blocks
            .get(&id)
            .map(|b| b.raw.as_slice())
            .ok_or("WAITING_FOR_HISTORY native block".into())
    }
    pub fn accept(&mut self, raw: &[u8], head: Hash, tip: Hash, now: u64) -> Result<Outcome> {
        self.check(head, tip, now)?;
        let id = fast::block_id(raw)?;
        if let Some(known) = self.native.blocks.get(&id) {
            ensure(known.raw == raw, "INVALID native changed duplicate bytes")?;
            sync(&self.file, &self.path)?;
            self.prefix(head)?;
            return Ok(Outcome {
                head,
                tip,
                revision: self.revision(),
                block: id,
                selected: tip == id,
                already_known: true,
            });
        }
        ensure(
            self.native.blocks.len() < self.limits.blocks,
            "RESOURCE_WAIT native block count",
        )?;
        let (candidate, selected, revision) = self.native.candidate(raw, now)?;
        let next = if selected { candidate.tip().id() } else { tip };
        let mut body = (self.index + 1).to_be_bytes().to_vec();
        body.extend(head);
        body.extend(now.to_be_bytes());
        body.extend((raw.len() as u32).to_be_bytes());
        body.extend(raw);
        body.extend(next);
        body.extend(revision.to_be_bytes());
        let new_head = hash("RECORD", &body);
        body.extend(new_head);
        let mut record = (body.len() as u32).to_be_bytes().to_vec();
        record.extend(body);
        ensure(
            self.prefix
                .len()
                .checked_add(record.len())
                .is_some_and(|n| n <= self.limits.bytes),
            "RESOURCE_WAIT native byte capacity",
        )?;
        self.prefix(head)?;
        let write = self
            .file
            .seek(SeekFrom::End(0))
            .and_then(|_| self.file.write_all(&record))
            .map_err(io)
            .and_then(|_| sync(&self.file, &self.path));
        if let Err(e) = write {
            self.poisoned = true;
            return Err(e);
        }
        self.prior = head;
        self.head = new_head;
        self.index += 1;
        self.last_block = Some(id);
        self.prefix.extend(record);
        if let Err(e) = self.prefix(new_head) {
            self.poisoned = true;
            return Err(e);
        }
        self.native.install(raw, now, candidate, selected, revision);
        Ok(Outcome {
            head: new_head,
            tip: next,
            revision,
            block: id,
            selected,
            already_known: false,
        })
    }
    pub fn recover(
        path: &Path,
        genesis: &[u8],
        chain: Hash,
        prior: Hash,
        block: Hash,
        now: u64,
        limits: Limits,
    ) -> Result<Self> {
        let mut s = Self::from_file(path, Self::file(path)?, genesis, chain, None, now, limits)?;
        ensure(
            s.index > 0 && s.prior == prior && s.last_block == Some(block),
            "INVALID native recovery exact prior/block",
        )?;
        s.prefix(s.head)?;
        sync(&s.file, path)?;
        s.prefix(s.head)?;
        Ok(s)
    }
}
