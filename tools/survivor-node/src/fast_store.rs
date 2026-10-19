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
#[derive(Clone)]
pub(crate) struct NativeAuditStep {
    pub prior: Hash,
    pub next: Hash,
    pub before_tip: Hash,
    pub at: u64,
    pub block: Vec<u8>,
}

#[cfg(test)]
mod audit_tests {
    use super::*;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    fn fixture() -> (Store, Vec<NativeAuditStep>, PathBuf) {
        let deadline = Instant::now() + Duration::from_secs(180);
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/protocol/native-fast-escrow-v1-vectors.json"
        ))
        .unwrap();
        let mut genesis = hex::decode(v["genesis_hex"].as_str().unwrap()).unwrap();
        getrandom::getrandom(&mut genesis[13..45]).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        genesis[45..53].copy_from_slice(&(now - 7200).to_be_bytes());
        let chain = fast::genesis_id(&genesis);
        let root = std::env::temp_dir().join(format!(
            "rld-native-step-audit-{}-{}",
            std::process::id(),
            hex::encode(chain)
        ));
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = root.join("native.journal");
        let mut s = Store::create(&path, &genesis, chain, now, Limits::default()).unwrap();
        let original = s.ledger().clone();
        let mut steps = vec![];
        // Deliberately public NO-VALUE mining fixture identities only.
        for (i, seed) in [141u8, 141, 142].into_iter().enumerate() {
            let ledger = if i == 2 { &original } else { s.ledger() };
            let miner = ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes();
            let mut job = ledger
                .mining_job(
                    miner,
                    vec![],
                    ledger.tip().timestamp() + 600 + i as u64,
                    now,
                )
                .unwrap();
            let block = loop {
                assert!(
                    Instant::now() < deadline,
                    "original180 native audit fixture"
                );
                if let (Some(raw), _) = job.search(4096) {
                    break raw;
                }
            };
            let prior = s.head();
            let before_tip = s.ledger().tip().id();
            let outcome = s.accept(&block, prior, before_tip, now).unwrap();
            steps.push(NativeAuditStep {
                prior,
                next: outcome.head,
                before_tip,
                at: now,
                block,
            });
        }
        (s, steps, path)
    }
    #[test]
    fn complete_ordered_audit_covers_selected_and_unselected_native_records() {
        let (mut s, steps, path) = fixture();
        let raw = fs::read(&path).unwrap();
        let selected = s.ledger().tip().id();
        let tips = s.audit_steps(steps.clone().into_iter().map(Ok)).unwrap();
        assert_eq!(tips.len(), 3);
        assert_eq!(tips[1], selected);
        assert_eq!(tips[2], selected);
        assert_ne!(fast::block_id(&steps[2].block).unwrap(), selected);
        let mut cases = vec![
            steps[..2].to_vec(),
            vec![steps[1].clone(), steps[0].clone(), steps[2].clone()],
        ];
        let mut extra = steps.clone();
        extra.push(steps[2].clone());
        cases.push(extra);
        for kind in 0..5 {
            let mut bad = steps.clone();
            match kind {
                0 => bad[1].prior = [1; 32],
                1 => bad[1].next = [1; 32],
                2 => bad[1].before_tip = [1; 32],
                3 => bad[1].at += 1,
                _ => {
                    let n = bad[1].block.len();
                    bad[1].block[n - 1] ^= 1;
                }
            }
            cases.push(bad);
        }
        for bad in cases {
            assert!(s.audit_steps(bad.into_iter().map(Ok)).is_err());
            assert_eq!(fs::read(&path).unwrap(), raw);
        }
        assert_eq!(s.audit_steps(steps.into_iter().map(Ok)).unwrap(), tips);
    }
    #[test]
    fn complete_native_audit_rechecks_actual_prefix_and_never_repairs_damage() {
        let (mut s, steps, path) = fixture();
        let mut raw = fs::read(&path).unwrap();
        let n = raw.len();
        raw[n - 1] ^= 1;
        fs::write(&path, &raw).unwrap();
        assert!(s.audit_steps(steps.into_iter().map(Ok)).is_err());
        assert!(!s.storage_ready());
        assert_eq!(fs::read(path).unwrap(), raw);
    }
    #[test]
    fn complete_native_audit_checks_actual_file_again_after_all_steps() {
        let (mut s, steps, path) = fixture();
        let mut damaged = fs::read(&path).unwrap();
        let n = damaged.len();
        damaged[n - 1] ^= 1;
        let mut count = 0;
        let injected = steps.into_iter().map(|step| {
            count += 1;
            if count == 2 {
                fs::write(&path, &damaged).unwrap();
            }
            Ok(step)
        });
        assert!(s.audit_steps(injected).is_err());
        assert!(!s.storage_ready());
        assert_eq!(fs::read(path).unwrap(), damaged);
    }
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
    pub(crate) fn initial_head(&self) -> Hash {
        hash("HEADER", &self.prefix[..165])
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
    pub(crate) fn historical(&mut self, tip: Hash) -> Result<Ledger> {
        self.prefix(self.head)?;
        self.native.replay(tip)
    }
    pub(crate) fn funding_history(
        &mut self,
        head: Hash,
        tip: Hash,
        channel: Hash,
        now: u64,
    ) -> Result<Vec<u8>> {
        self.check(head, tip, now)?;
        let origin = self.native.ledger.funding_origin(channel)?;
        origin.check_current(&self.native.ledger, tip, now)?;
        self.history_to_height(tip, origin.birth_height())
    }
    pub(crate) fn history_to_height(&self, mut tip: Hash, height: u128) -> Result<Vec<u8>> {
        let mut route = Vec::new();
        while tip != self.native.ledger.chain_id() {
            let b = self
                .native
                .blocks
                .get(&tip)
                .ok_or("WAITING_FOR_HISTORY funding history")?;
            if b.tip.height() <= height {
                route.push(b);
            }
            ensure(
                route.len() <= self.limits.blocks,
                "RESOURCE_WAIT funding history route",
            )?;
            tip = b.raw[36..68].try_into().unwrap();
        }
        let mut result = Vec::new();
        for b in route.into_iter().rev() {
            result.extend((b.raw.len() as u32).to_be_bytes());
            result.extend(&b.raw);
        }
        Ok(result)
    }
    pub(crate) fn audit_steps(
        &mut self,
        steps: impl IntoIterator<Item = Result<NativeAuditStep>>,
    ) -> Result<Vec<Hash>> {
        self.prefix(self.head)?;
        let mut r = Reader {
            raw: &self.prefix,
            at: 165,
        };
        let mut prior = self.initial_head();
        let mut selected = self.native.ledger.chain_id();
        let mut result = Vec::new();
        for step in steps {
            let step = step?;
            ensure(
                r.at < self.prefix.len(),
                "INVALID extra caller native transition",
            )?;
            let n = r.u32()? as usize;
            ensure(
                (402..=262276).contains(&n),
                "INVALID native audit record size",
            )?;
            let raw = r.take(n)?;
            let size = u32::from_be_bytes(raw[48..52].try_into().unwrap()) as usize;
            ensure(
                (270..=262144).contains(&size) && n == 132 + size,
                "INVALID native audit block size",
            )?;
            ensure(
                u64::from_be_bytes(raw[..8].try_into().unwrap()) == result.len() as u64 + 1
                    && raw[8..40] == prior
                    && step.prior == prior
                    && raw[n - 32..] == step.next
                    && hash("RECORD", &raw[..n - 32]) == step.next,
                "INVALID caller native ordered transition",
            )?;
            ensure(
                raw[52..52 + size] == step.block,
                "INVALID session native step bytes",
            )?;
            ensure(
                step.before_tip == selected
                    && step.at == u64::from_be_bytes(raw[40..48].try_into().unwrap()),
                "INVALID caller native context/time",
            )?;
            selected = raw[52 + size..84 + size].try_into().unwrap();
            prior = step.next;
            result.push(selected);
        }
        ensure(
            r.at == self.prefix.len()
                && prior == self.head
                && selected == self.native.ledger.tip().id(),
            "INVALID incomplete caller native coverage",
        )?;
        self.prefix(self.head)?;
        Ok(result)
    }
    /// Selected-history observation from this store's complete native-executed
    /// immutable blocks, never a peer/cache-supplied inclusion assertion.
    pub(crate) fn pool_inclusions(
        &mut self,
        wanted: &BTreeMap<Hash, Vec<u8>>,
        now: u64,
    ) -> Result<BTreeMap<Hash, (Hash, u128)>> {
        self.check(self.head, self.native.ledger.tip().id(), now)?;
        let mut result = BTreeMap::new();
        let mut cursor = self.native.ledger.tip().id();
        let mut seen = 0;
        while cursor != self.native.ledger.chain_id() {
            let block = self
                .native
                .blocks
                .get(&cursor)
                .ok_or("WAITING_FOR_HISTORY pool observation")?;
            seen += 1;
            ensure(
                seen <= self.limits.blocks,
                "RESOURCE_WAIT pool history route",
            )?;
            let mut r = Reader {
                raw: &block.raw,
                at: 268,
            };
            let count = r.u16()?;
            ensure(count <= 128, "INVALID retained pool block count")?;
            for _ in 0..count {
                let size = r.u32()? as usize;
                ensure(
                    (1..=4096).contains(&size),
                    "INVALID retained pool operation size",
                )?;
                let raw = r.take(size)?;
                let id = fast::operation_id(raw);
                if let Some(expected) = wanted.get(&id) {
                    ensure(raw == *expected, "INVALID selected pool operation bytes")?;
                    ensure(
                        result.insert(id, (cursor, block.tip.height())).is_none(),
                        "INVALID repeated selected pool operation",
                    )?;
                }
            }
            ensure(r.at == block.raw.len(), "INVALID retained pool block tail")?;
            cursor = block.raw[36..68].try_into().unwrap();
        }
        self.prefix(self.head)?;
        Ok(result)
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
