//! Private append-only delegated receipt custody. Native funding is replayed;
//! acknowledgments never grant principal, finality, issuance or fast qualification.
use crate::{
    fast_payment::{self, ensure, hash, tag, Acknowledgment, Delegation, Payment},
    kernel::{
        fast::{FundingOrigin, Ledger},
        Hash, Result,
    },
};
use ed25519_dalek::{Signer, SigningKey};
use fs2::FileExt;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
const MAX_BYTES: usize = 256 * 1024 * 1024;
pub(crate) fn io(error: impl std::fmt::Display) -> String {
    format!("RESOURCE_WAIT fast retention {error}")
}
pub(crate) struct Reader<'a> {
    pub(crate) raw: &'a [u8],
    pub(crate) at: usize,
}
impl<'a> Reader<'a> {
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(n).ok_or("INVALID retention length")?;
        ensure(
            end <= self.raw.len(),
            "WAITING_FOR_HISTORY retention truncation",
        )?;
        let raw = &self.raw[self.at..end];
        self.at = end;
        Ok(raw)
    }
    pub(crate) fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub(crate) fn hash(&mut self) -> Result<Hash> {
        Ok(self.take(32)?.try_into().unwrap())
    }
}
pub struct Current<'a> {
    pub ledger: &'a Ledger,
    pub expected_tip: Hash,
    pub now: u64,
}
pub struct Creation<'a> {
    pub genesis: &'a [u8],
    pub chain: Hash,
    pub history: &'a [u8],
    pub delegation: &'a [u8],
    pub current: Current<'a>,
    pub limit: usize,
}
pub struct Review {
    pub head: Hash,
    pub digest: Hash,
    pub receipt_id: Hash,
    pub logical_id: Hash,
}
pub struct Recovery {
    pub head: Hash,
    pub receipt: Vec<u8>,
    pub acknowledgment: Option<Vec<u8>>,
}
struct Pending {
    payment: Payment,
    head: Hash,
}
struct Last {
    payment: Payment,
    ack: Acknowledgment,
}

pub struct Journal {
    path: PathBuf,
    file: File,
    prefix: Vec<u8>,
    origin: FundingOrigin,
    delegation: Delegation,
    head: Hash,
    index: u64,
    previous_head: Hash,
    last_kind: u8,
    last: Option<Last>,
    pending: Option<Pending>,
    limit: usize,
    poisoned: bool,
}
pub(crate) fn private(path: &Path, file: bool) -> Result<()> {
    ensure(cfg!(unix), "UNSUPPORTED retention file-identity platform")?;
    let m = fs::symlink_metadata(path).map_err(io)?;
    ensure(
        if file { m.is_file() } else { m.is_dir() },
        "INVALID retention regular private path",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure(
            m.permissions().mode() & 0o077 == 0,
            "INVALID retention private permissions",
        )?;
    }
    Ok(())
}
pub(crate) fn parent(path: &Path) -> Result<&Path> {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or("INVALID retention parent".into())
}
pub(crate) fn sync(file: &File, path: &Path) -> Result<()> {
    file.sync_all().map_err(io)?;
    File::open(parent(path)?)
        .and_then(|p| p.sync_all())
        .map_err(io)
}
pub(crate) fn origin(
    genesis: &[u8],
    chain: Hash,
    history: &[u8],
    channel: Hash,
    now: u64,
) -> Result<FundingOrigin> {
    let mut ledger = Ledger::from_genesis(genesis, chain, 100_000)?;
    let mut r = Reader {
        raw: history,
        at: 0,
    };
    let mut count = 0;
    while r.at < history.len() {
        count += 1;
        ensure(count <= 262144, "RESOURCE_WAIT retention history count")?;
        let n = r.u32()? as usize;
        ensure(
            (270..=262144).contains(&n),
            "INVALID retention native block size",
        )?;
        ledger.execute(r.take(n)?, now)?;
    }
    let origin = ledger.funding_origin(channel)?;
    ensure(
        origin.birth_height() == ledger.tip().height(),
        "INVALID retention proof must end at funding birth",
    )?;
    Ok(origin)
}
fn record(index: u64, previous: Hash, kind: u8, payload: &[u8]) -> Result<(Vec<u8>, Hash)> {
    let mut body = index.to_be_bytes().to_vec();
    body.extend(previous);
    body.push(kind);
    body.extend(payload);
    let head = hash("JOURNAL-RECORD", &body);
    body.extend(head);
    ensure(
        (73..=1024).contains(&body.len()),
        "INVALID retention record size",
    )?;
    let mut raw = (body.len() as u32).to_be_bytes().to_vec();
    raw.extend(body);
    Ok((raw, head))
}
impl Journal {
    pub fn create(path: &Path, input: Creation<'_>) -> Result<Self> {
        ensure(
            input.limit > 0 && input.limit <= MAX_BYTES && input.genesis.len() == 113,
            "INVALID retention limits/genesis",
        )?;
        ensure(
            input.delegation.len() == 245 && input.history.len() < input.limit,
            "RESOURCE_WAIT retention header budget",
        )?;
        let channel: Hash = input.delegation[36..68].try_into().unwrap();
        let origin = origin(
            input.genesis,
            input.chain,
            input.history,
            channel,
            input.current.now,
        )?;
        Delegation::verify(&origin, input.delegation)?;
        origin.check_current(
            input.current.ledger,
            input.current.expected_tip,
            input.current.now,
        )?;
        let mut header = b"RLDFRET1".to_vec();
        header.extend([0, 1, 0, 1]);
        header.extend(input.chain);
        header.extend(channel);
        header.extend(input.genesis);
        header.extend((input.history.len() as u64).to_be_bytes());
        header.extend(input.history);
        header.extend(input.delegation);
        ensure(
            header.len() <= input.limit,
            "RESOURCE_WAIT retention header budget",
        )?;
        private(parent(path)?, false)?;
        let mut options = OpenOptions::new();
        options.create_new(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path).map_err(io)?;
        FileExt::try_lock_exclusive(&file).map_err(|_| "RESOURCE_WAIT retention writer")?;
        file.write_all(&header).map_err(io)?;
        sync(&file, path)?;
        let head = hash("JOURNAL-HEADER", &header);
        Self::from_file(
            path,
            file,
            input.chain,
            Some(head),
            input.current.now,
            input.limit,
        )
    }
    pub fn open(
        path: &Path,
        chain: Hash,
        expected_head: Hash,
        now: u64,
        limit: usize,
    ) -> Result<Self> {
        let file = Self::file(path)?;
        Self::from_file(path, file, chain, Some(expected_head), now, limit)
    }
    fn file(path: &Path) -> Result<File> {
        private(parent(path)?, false)?;
        private(path, true)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(io)?;
        FileExt::try_lock_exclusive(&file).map_err(|_| "RESOURCE_WAIT retention writer")?;
        Ok(file)
    }
    fn from_file(
        path: &Path,
        mut file: File,
        chain: Hash,
        expected: Option<Hash>,
        now: u64,
        limit: usize,
    ) -> Result<Self> {
        ensure(
            limit > 0 && limit <= MAX_BYTES,
            "INVALID retention local limit",
        )?;
        ensure(
            file.metadata().map_err(io)?.len() <= limit as u64,
            "RESOURCE_WAIT retention byte budget",
        )?;
        let mut prefix = Vec::new();
        file.seek(SeekFrom::Start(0)).map_err(io)?;
        Read::by_ref(&mut file)
            .take(limit as u64 + 1)
            .read_to_end(&mut prefix)
            .map_err(io)?;
        ensure(
            prefix.len() <= limit,
            "RESOURCE_WAIT retention grew beyond budget",
        )?;
        let mut r = Reader {
            raw: &prefix,
            at: 0,
        };
        ensure(
            r.take(8)? == b"RLDFRET1" && r.take(4)? == [0, 1, 0, 1],
            "UNSUPPORTED retention header",
        )?;
        ensure(r.hash()? == chain, "INVALID retention pinned chain")?;
        let channel = r.hash()?;
        let genesis = r.take(113)?;
        let n = usize::try_from(r.u64()?).map_err(|_| "RESOURCE_WAIT retention history length")?;
        ensure(n <= limit, "RESOURCE_WAIT retention history budget")?;
        let origin = origin(genesis, chain, r.take(n)?, channel, now)?;
        let delegation = Delegation::verify(&origin, r.take(245)?)?;
        let header_end = r.at;
        let mut head = hash("JOURNAL-HEADER", &prefix[..header_end]);
        let mut index = 0;
        let mut previous_head = head;
        let mut last_kind = 0;
        let mut pending: Option<Pending> = None;
        let mut last: Option<Last> = None;
        while r.at < prefix.len() {
            let n = r.u32()? as usize;
            ensure((73..=1024).contains(&n), "INVALID retention record bound")?;
            let raw = r.take(n)?;
            let mut entry = Reader { raw, at: 0 };
            let number = entry.u64()?;
            let previous = entry.hash()?;
            let kind = entry.take(1)?[0];
            ensure(
                number == index + 1 && previous == head,
                "INVALID retention record chain",
            )?;
            let payload = entry.take(n - 73)?;
            let digest = entry.hash()?;
            ensure(
                digest == hash("JOURNAL-RECORD", &raw[..n - 32]),
                "INVALID retention record digest",
            )?;
            if kind == 1 {
                ensure(pending.is_none(), "INVALID retention concurrent prepare")?;
                let mut p = Reader {
                    raw: payload,
                    at: 0,
                };
                p.hash()?;
                let n = p.u16()? as usize;
                let payment = Payment::verify(&origin, p.take(n)?)?;
                ensure(
                    p.at == payload.len(),
                    "INVALID retention prepare trailing bytes",
                )?;
                Self::prior(&last, &payment)?;
                pending = Some(Pending {
                    payment,
                    head: digest,
                });
            } else if kind == 2 {
                let p = pending
                    .take()
                    .ok_or("INVALID retention acknowledgment without prepare")?;
                let ack = Acknowledgment::verify(&origin, &delegation, &p.payment, payload)?;
                ensure(
                    ack.prepared == p.head
                        && last.as_ref().is_none_or(|old| old.ack.time <= ack.time),
                    "INVALID retention acknowledgment head/time",
                )?;
                last = Some(Last {
                    payment: p.payment,
                    ack,
                });
            } else {
                return Err("UNSUPPORTED retention record kind".into());
            }
            previous_head = head;
            head = digest;
            index = number;
            last_kind = kind;
        }
        ensure(
            expected.is_none_or(|value| value == head),
            "INVALID retention independently pinned latest head",
        )?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            prefix,
            origin,
            delegation,
            head,
            index,
            previous_head,
            last_kind,
            last,
            pending,
            limit,
            poisoned: false,
        })
    }
    fn prior(last: &Option<Last>, payment: &Payment) -> Result<()> {
        if let Some(last) = last {
            ensure(
                payment.previous == last.payment.id && payment.before == last.payment.after,
                "INVALID retention prior receipt/state",
            )
        } else {
            ensure(
                payment.previous == [0; 32] && payment.before.is_empty(),
                "INVALID retention initial receipt",
            )
        }
    }
    fn check_prefix(&mut self) -> Result<()> {
        ensure(!self.poisoned, "RESOURCE_WAIT retention restart required")?;
        private(parent(&self.path)?, false)?;
        private(&self.path, true)?;
        let metadata = fs::symlink_metadata(&self.path).map_err(io)?;
        let opened = self.file.metadata().map_err(io)?;
        ensure(
            metadata.len() == self.prefix.len() as u64 && opened.len() == metadata.len(),
            "INVALID retention changed length",
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ensure(
                metadata.dev() == opened.dev() && metadata.ino() == opened.ino(),
                "INVALID retention replaced file",
            )?;
        }
        self.file.seek(SeekFrom::Start(0)).map_err(io)?;
        let mut buffer = [0; 65536];
        for chunk in self.prefix.chunks(buffer.len()) {
            self.file
                .read_exact(&mut buffer[..chunk.len()])
                .map_err(io)?;
            ensure(
                &buffer[..chunk.len()] == chunk,
                "INVALID retention changed prefix",
            )?;
        }
        Ok(())
    }
    fn current(&mut self, expected: Hash, current: &Current<'_>) -> Result<()> {
        self.check_prefix()?;
        ensure(
            expected == self.head,
            "INVALID retention caller latest head",
        )?;
        self.origin
            .check_current(current.ledger, current.expected_tip, current.now)?;
        ensure(
            self.last
                .as_ref()
                .is_none_or(|last| current.now >= last.ack.time),
            "CLOCK_WAIT retention observed clock rollback",
        )
    }
    fn append(&mut self, kind: u8, payload: &[u8]) -> Result<()> {
        self.check_prefix()?;
        let (raw, head) = record(self.index + 1, self.head, kind, payload)?;
        ensure(
            self.prefix
                .len()
                .checked_add(raw.len())
                .is_some_and(|n| n <= self.limit),
            "RESOURCE_WAIT retention capacity",
        )?;
        let write = self
            .file
            .seek(SeekFrom::End(0))
            .and_then(|_| self.file.write_all(&raw))
            .map_err(io)
            .and_then(|_| sync(&self.file, &self.path));
        if let Err(error) = write {
            self.poisoned = true;
            return Err(error);
        }
        self.previous_head = self.head;
        self.head = head;
        self.index += 1;
        self.last_kind = kind;
        self.prefix.extend(raw);
        if let Err(error) = self.check_prefix() {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }
    pub fn head(&self) -> Hash {
        self.head
    }
    pub fn latest_sequence(&self) -> u64 {
        self.last.as_ref().map_or(0, |last| last.payment.sequence)
    }
    pub fn latest_certificate(&self) -> Option<&[u8]> {
        self.last.as_ref().map(|last| last.payment.after.as_slice())
    }
    pub fn retained_ack(&mut self, expected: Hash, receipt: Hash) -> Result<Vec<u8>> {
        self.check_prefix()?;
        ensure(
            expected == self.head,
            "INVALID retention caller latest head",
        )?;
        let last = self
            .last
            .as_ref()
            .ok_or("MISSING retention acknowledged receipt")?;
        ensure(
            last.payment.id == receipt,
            "INVALID retention acknowledged receipt ID",
        )?;
        sync(&self.file, &self.path)?;
        Ok(last.ack.raw.clone())
    }
    pub fn prepare(
        &mut self,
        receipt: &[u8],
        expected: Hash,
        current: Current<'_>,
    ) -> Result<Review> {
        self.current(expected, &current)?;
        let payment = Payment::verify(&self.origin, receipt)?;
        if let Some(pending) = &self.pending {
            ensure(
                pending.payment.raw == receipt,
                "INVALID retention another pending receipt",
            )?;
            return self.review(expected, current);
        }
        Self::prior(&self.last, &payment)?;
        let mut payload = current.expected_tip.to_vec();
        payload.extend((receipt.len() as u16).to_be_bytes());
        payload.extend(receipt);
        let (prepare, _) = record(self.index + 1, self.head, 1, &payload)?;
        let (ack, _) = record(self.index + 2, [0; 32], 2, &[0; 340])?;
        ensure(
            self.prefix
                .len()
                .checked_add(prepare.len() + ack.len())
                .is_some_and(|n| n <= self.limit),
            "RESOURCE_WAIT retention prepare/ack reservation",
        )?;
        self.append(1, &payload)?;
        self.pending = Some(Pending {
            payment,
            head: self.head,
        });
        self.review(self.head, current)
    }
    pub fn review(&mut self, expected: Hash, current: Current<'_>) -> Result<Review> {
        self.current(expected, &current)?;
        let p = self
            .pending
            .as_ref()
            .ok_or("MISSING retention prepared receipt")?;
        Ok(Review {
            head: self.head,
            digest: fast_payment::review_digest(
                current.expected_tip,
                self.head,
                p.payment.id,
                self.delegation.id,
            ),
            receipt_id: p.payment.id,
            logical_id: p.payment.logical,
        })
    }
    /// The key loader runs only after native/caller/review and full prefix checks.
    /// A signed response is never released before its own durable record.
    pub fn acknowledge(
        &mut self,
        expected: Hash,
        review: Hash,
        current: Current<'_>,
        load_key: impl FnOnce() -> Result<SigningKey>,
    ) -> Result<(Hash, Vec<u8>)> {
        self.current(expected, &current)?;
        let p = self
            .pending
            .as_ref()
            .ok_or("MISSING retention prepared receipt")?;
        ensure(
            review
                == fast_payment::review_digest(
                    current.expected_tip,
                    self.head,
                    p.payment.id,
                    self.delegation.id,
                ),
            "INVALID retention review digest",
        )?;
        let payment = Payment::verify(&self.origin, &p.payment.raw)?;
        let key = load_key()?;
        ensure(
            key.verifying_key().to_bytes() == self.delegation.retainer,
            "INVALID retention delegated key",
        )?;
        let mut raw = Acknowledgment::unsigned(
            &self.origin,
            &self.delegation,
            &payment,
            current.expected_tip,
            self.head,
            current.now,
        );
        let signature = key.sign(&[tag("ACK"), raw.clone()].concat());
        raw.extend(signature.to_bytes());
        let ack = Acknowledgment::verify(&self.origin, &self.delegation, &payment, &raw)?;
        self.append(2, &raw)?;
        self.pending = None;
        self.last = Some(Last { payment, ack });
        Ok((self.head, raw))
    }
    /// Keyless exact-tail recovery; the caller must separately retain prior head
    /// and receipt ID. A prepared record returns no acknowledgment or first sign.
    pub fn recover(
        path: &Path,
        chain: Hash,
        prior: Hash,
        receipt: Hash,
        now: u64,
        limit: usize,
    ) -> Result<Recovery> {
        let file = Self::file(path)?;
        let mut journal = Self::from_file(path, file, chain, None, now, limit)?;
        ensure(
            journal.index > 0 && journal.previous_head == prior,
            "INVALID retention recover prior head",
        )?;
        journal.check_prefix()?;
        let (raw, ack) = if journal.last_kind == 1 {
            let p = journal
                .pending
                .as_ref()
                .ok_or("MISSING retention pending")?;
            ensure(p.payment.id == receipt, "INVALID retention recover receipt")?;
            (p.payment.raw.clone(), None)
        } else {
            let last = journal
                .last
                .as_ref()
                .ok_or("MISSING retention acknowledgment")?;
            ensure(
                last.payment.id == receipt,
                "INVALID retention recover receipt",
            )?;
            (last.payment.raw.clone(), Some(last.ack.raw.clone()))
        };
        sync(&journal.file, path)?;
        journal.check_prefix()?;
        Ok(Recovery {
            head: journal.head,
            receipt: raw,
            acknowledgment: ack,
        })
    }
}
