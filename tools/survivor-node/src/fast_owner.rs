//! Per-owner durable partial authorization over replayed native escrow funding.
//! No cancellation, automatic first signing, current selection or fast completion.
use crate::{
    fast_payment::{ensure, Acknowledgment, Delegation, Invoice, Payment},
    fast_retainer::{io, origin, parent, private, sync, Creation, Current, Reader},
    kernel::{fast::FundingOrigin, Hash, Result},
};
use ed25519_dalek::SigningKey;
use fs2::FileExt;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
const MAX_BYTES: usize = 256 * 1024 * 1024;
fn hash(label: &str, raw: &[u8]) -> Hash {
    Sha256::digest([b"RLD-FAST-OWNER-1/".as_slice(), label.as_bytes(), &[0], raw].concat()).into()
}
fn record(index: u64, previous: Hash, kind: u8, payload: &[u8]) -> Result<(Vec<u8>, Hash)> {
    let mut body = index.to_be_bytes().to_vec();
    body.extend(previous);
    body.push(kind);
    body.extend(payload);
    let head = hash("RECORD", &body);
    body.extend(head);
    ensure(
        (73..=2048).contains(&body.len()),
        "INVALID owner record size",
    )?;
    let mut raw = (body.len() as u32).to_be_bytes().to_vec();
    raw.extend(body);
    Ok((raw, head))
}
struct Pending {
    invoice: Invoice,
    partial: Option<Vec<u8>>,
}
/// An explicit human/caller review token. No authority follows from displaying it.
pub struct Review {
    pub head: Hash,
    pub digest: Hash,
    pub invoice_id: Hash,
    pub logical_id: Hash,
    pub chain: Hash,
    pub channel: Hash,
    pub owner: Hash,
    pub payer: Hash,
    pub recipient: Hash,
    pub miner: Hash,
    pub retainer: Hash,
    pub amount: u128,
    pub fee: u128,
    pub sequence: u64,
}
pub struct Recovery {
    pub head: Hash,
    pub invoice: Vec<u8>,
    pub partial: Option<Vec<u8>>,
}
pub struct Journal {
    path: PathBuf,
    file: File,
    prefix: Vec<u8>,
    origin: FundingOrigin,
    delegation: Delegation,
    owner: u8,
    head: Hash,
    prior_head: Hash,
    index: u64,
    last_kind: u8,
    clock: u64,
    pending: Option<Pending>,
    last: Option<(Payment, Acknowledgment)>,
    limit: usize,
    poisoned: bool,
}
impl Journal {
    pub fn create(path: &Path, input: Creation<'_>, owner: u8) -> Result<Self> {
        ensure(
            owner < 2 && input.genesis.len() == 113 && input.limit > 0 && input.limit <= MAX_BYTES,
            "INVALID owner creation",
        )?;
        ensure(
            input.delegation.len() == 245 && input.history.len() < input.limit,
            "RESOURCE_WAIT owner header",
        )?;
        let channel = input.delegation[36..68].try_into().unwrap();
        let funded = origin(
            input.genesis,
            input.chain,
            input.history,
            channel,
            input.current.now,
        )?;
        Delegation::verify(&funded, input.delegation)?;
        funded.check_current(
            input.current.ledger,
            input.current.expected_tip,
            input.current.now,
        )?;
        let mut header = b"RLDFOWN1".to_vec();
        header.extend([0, 1, 0, 1]);
        header.extend(input.chain);
        header.extend(channel);
        header.extend(input.genesis);
        header.extend((input.history.len() as u64).to_be_bytes());
        header.extend(input.history);
        header.extend(input.delegation);
        header.push(owner);
        ensure(
            header.len() <= input.limit,
            "RESOURCE_WAIT owner header budget",
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
        FileExt::try_lock_exclusive(&file).map_err(|_| "RESOURCE_WAIT owner writer")?;
        file.write_all(&header).map_err(io)?;
        sync(&file, path)?;
        let head = hash("HEADER", &header);
        Self::from_file(
            path,
            file,
            input.chain,
            Some(head),
            input.current.now,
            input.limit,
        )
    }
    fn file(path: &Path) -> Result<File> {
        private(parent(path)?, false)?;
        private(path, true)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(io)?;
        FileExt::try_lock_exclusive(&file).map_err(|_| "RESOURCE_WAIT owner writer")?;
        Ok(file)
    }
    pub fn open(
        path: &Path,
        chain: Hash,
        expected_head: Hash,
        now: u64,
        limit: usize,
    ) -> Result<Self> {
        Self::from_file(
            path,
            Self::file(path)?,
            chain,
            Some(expected_head),
            now,
            limit,
        )
    }
    fn from_file(
        path: &Path,
        mut file: File,
        chain: Hash,
        expected: Option<Hash>,
        now: u64,
        limit: usize,
    ) -> Result<Self> {
        ensure(limit > 0 && limit <= MAX_BYTES, "INVALID owner byte limit")?;
        ensure(
            file.metadata().map_err(io)?.len() <= limit as u64,
            "RESOURCE_WAIT owner journal size",
        )?;
        file.seek(SeekFrom::Start(0)).map_err(io)?;
        let mut prefix = Vec::new();
        Read::by_ref(&mut file)
            .take(limit as u64 + 1)
            .read_to_end(&mut prefix)
            .map_err(io)?;
        ensure(prefix.len() <= limit, "RESOURCE_WAIT owner journal grew")?;
        let mut r = Reader {
            raw: &prefix,
            at: 0,
        };
        ensure(
            r.take(8)? == b"RLDFOWN1" && r.take(4)? == [0, 1, 0, 1],
            "UNSUPPORTED owner journal",
        )?;
        ensure(r.hash()? == chain, "INVALID owner pinned chain")?;
        let channel = r.hash()?;
        let genesis = r.take(113)?;
        let n = usize::try_from(r.u64()?).map_err(|_| "RESOURCE_WAIT owner history length")?;
        ensure(n <= limit, "RESOURCE_WAIT owner history size")?;
        let funded = origin(genesis, chain, r.take(n)?, channel, now)?;
        let delegation = Delegation::verify(&funded, r.take(245)?)?;
        let owner = r.take(1)?[0];
        ensure(owner < 2, "INVALID owner role")?;
        let mut head = hash("HEADER", &prefix[..r.at]);
        let mut prior_head = head;
        let mut index = 0;
        let mut last_kind = 0;
        let mut clock = 0;
        let mut pending: Option<Pending> = None;
        let mut last: Option<(Payment, Acknowledgment)> = None;
        while r.at < prefix.len() {
            let n = r.u32()? as usize;
            ensure((73..=2048).contains(&n), "INVALID owner record bound")?;
            let raw = r.take(n)?;
            let mut e = Reader { raw, at: 0 };
            let i = e.u64()?;
            let previous = e.hash()?;
            let kind = e.take(1)?[0];
            let payload = e.take(n - 73)?;
            let digest = e.hash()?;
            ensure(
                i == index + 1 && previous == head && digest == hash("RECORD", &raw[..n - 32]),
                "INVALID owner journal chain",
            )?;
            let mut p = Reader {
                raw: payload,
                at: 0,
            };
            let time = p.u64()?;
            ensure(
                time >= clock && time <= now,
                "CLOCK_WAIT owner journal clock",
            )?;
            if kind == 1 {
                ensure(pending.is_none(), "INVALID owner concurrent prepare")?;
                p.hash()?;
                let n = p.u16()? as usize;
                let invoice = Invoice::verify(&funded, p.take(n)?)?;
                Self::prior(&last, &invoice)?;
                pending = Some(Pending {
                    invoice,
                    partial: None,
                });
            } else if kind == 2 {
                p.hash()?;
                let pending = pending
                    .as_mut()
                    .ok_or("INVALID owner unprepared signature")?;
                ensure(
                    pending.partial.is_none(),
                    "INVALID owner repeated signature",
                )?;
                let partial = p.take(129)?;
                ensure(partial[0] == owner, "INVALID owner partial role")?;
                pending.invoice.verify_partial(&funded, partial)?;
                pending.partial = Some(partial.to_vec());
            } else if kind == 3 {
                let pending = pending
                    .take()
                    .ok_or("INVALID owner unprepared completion")?;
                let n = p.u16()? as usize;
                let payment = Payment::verify(&funded, p.take(n)?)?;
                let ack = Acknowledgment::verify(&funded, &delegation, &payment, p.take(340)?)?;
                Self::completed(&pending, &payment, owner)?;
                ensure(
                    ack.observed_at() <= time
                        && last
                            .as_ref()
                            .is_none_or(|(_, old)| old.observed_at() <= ack.observed_at()),
                    "CLOCK_WAIT owner acknowledgment clock",
                )?;
                last = Some((payment, ack));
            } else {
                return Err("UNSUPPORTED owner record kind".into());
            }
            ensure(p.at == payload.len(), "INVALID owner trailing payload")?;
            clock = time;
            prior_head = head;
            head = digest;
            index = i;
            last_kind = kind;
        }
        ensure(
            expected.is_none_or(|h| h == head),
            "INVALID owner independently pinned latest head",
        )?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            prefix,
            origin: funded,
            delegation,
            owner,
            head,
            prior_head,
            index,
            last_kind,
            clock,
            pending,
            last,
            limit,
            poisoned: false,
        })
    }
    fn prior(last: &Option<(Payment, Acknowledgment)>, invoice: &Invoice) -> Result<()> {
        ensure(
            if let Some((last, _)) = last {
                invoice.previous == last.id && invoice.before == last.after
            } else {
                invoice.previous == [0; 32] && invoice.before.is_empty()
            },
            "INVALID owner prior complete payment",
        )
    }
    fn completed(pending: &Pending, payment: &Payment, owner: u8) -> Result<()> {
        let end = payment.raw.len() - 256;
        ensure(
            payment.raw[..end] == *pending.invoice.bytes(),
            "INVALID owner completed invoice",
        )?;
        let i = owner as usize;
        let partial = [
            vec![owner],
            payment.raw[end + i * 64..end + (i + 1) * 64].to_vec(),
            payment.raw[end + 128 + i * 64..end + 192 + i * 64].to_vec(),
        ]
        .concat();
        ensure(
            pending.partial.as_ref() == Some(&partial),
            "INVALID owner completion without exact retained signature",
        )
    }
    fn prefix(&mut self, expected: Hash) -> Result<()> {
        ensure(!self.poisoned, "RESOURCE_WAIT owner restart required")?;
        ensure(expected == self.head, "INVALID owner caller head")?;
        private(parent(&self.path)?, false)?;
        private(&self.path, true)?;
        let path = fs::symlink_metadata(&self.path).map_err(io)?;
        let opened = self.file.metadata().map_err(io)?;
        ensure(
            path.len() == self.prefix.len() as u64 && opened.len() == path.len(),
            "INVALID owner changed journal length",
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ensure(
                path.dev() == opened.dev() && path.ino() == opened.ino(),
                "INVALID owner replaced journal",
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
                "INVALID owner changed journal prefix",
            )?;
        }
        Ok(())
    }
    fn current(&mut self, expected: Hash, current: &Current<'_>) -> Result<()> {
        self.prefix(expected)?;
        ensure(current.now >= self.clock, "CLOCK_WAIT owner clock rollback")?;
        self.origin
            .check_current(current.ledger, current.expected_tip, current.now)
    }
    fn append(&mut self, kind: u8, payload: &[u8]) -> Result<()> {
        self.prefix(self.head)?;
        let (raw, head) = record(self.index + 1, self.head, kind, payload)?;
        ensure(
            self.prefix
                .len()
                .checked_add(raw.len())
                .is_some_and(|n| n <= self.limit),
            "RESOURCE_WAIT owner journal capacity",
        )?;
        let result = self
            .file
            .seek(SeekFrom::End(0))
            .and_then(|_| self.file.write_all(&raw))
            .map_err(io)
            .and_then(|_| sync(&self.file, &self.path));
        if let Err(e) = result {
            self.poisoned = true;
            return Err(e);
        }
        self.prior_head = self.head;
        self.head = head;
        self.index += 1;
        self.last_kind = kind;
        self.prefix.extend(raw);
        if let Err(e) = self.prefix(self.head) {
            self.poisoned = true;
            return Err(e);
        }
        Ok(())
    }
    pub fn head(&self) -> Hash {
        self.head
    }
    pub(crate) fn scope(&self) -> (FundingOrigin, Delegation, u8) {
        (self.origin.clone(), self.delegation.clone(), self.owner)
    }
    pub(crate) fn initial_head(&self) -> Hash {
        let n = u64::from_be_bytes(self.prefix[189..197].try_into().unwrap()) as usize;
        hash("HEADER", &self.prefix[..443 + n])
    }
    pub(crate) fn audit_step(&mut self, prior: Hash, next: Hash) -> Result<(u8, Vec<u8>)> {
        self.prefix(self.head)?;
        let n = u64::from_be_bytes(self.prefix[189..197].try_into().unwrap()) as usize;
        crate::fast_retainer::retained_step(&self.prefix, 443 + n, prior, next)
    }
    pub fn owner(&self) -> Hash {
        self.origin.owners()[self.owner as usize]
    }
    pub fn latest_sequence(&self) -> u64 {
        self.last.as_ref().map_or(0, |(p, _)| p.sequence)
    }
    /// Exact last complete exit evidence remains available during a pending
    /// next invoice. Reading never asserts current backing or signs.
    pub fn retained_complete(&mut self, expected: Hash) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        self.prefix(expected)?;
        sync(&self.file, &self.path)?;
        let result = self
            .last
            .as_ref()
            .map(|(p, a)| (p.bytes().to_vec(), a.bytes().to_vec()));
        self.prefix(expected)?;
        Ok(result)
    }
    pub fn retained_pending(&mut self, expected: Hash, invoice_id: Hash) -> Result<Recovery> {
        self.prefix(expected)?;
        let p = self
            .pending
            .as_ref()
            .ok_or("MISSING owner recovery pending")?;
        ensure(
            p.invoice.id() == invoice_id,
            "INVALID owner recover invoice",
        )?;
        let result = Recovery {
            head: self.head,
            invoice: p.invoice.bytes().to_vec(),
            partial: p.partial.clone(),
        };
        sync(&self.file, &self.path)?;
        self.prefix(expected)?;
        Ok(result)
    }
    pub fn prepare(&mut self, raw: &[u8], expected: Hash, current: Current<'_>) -> Result<Review> {
        self.current(expected, &current)?;
        let invoice = Invoice::verify(&self.origin, raw)?;
        if let Some(p) = &self.pending {
            ensure(
                p.invoice.bytes() == raw,
                "CONFLICT owner reserved transition",
            )?;
            return self.review(expected, current);
        }
        Self::prior(&self.last, &invoice)?;
        let mut payload = current.now.to_be_bytes().to_vec();
        payload.extend(current.expected_tip);
        payload.extend((raw.len() as u16).to_be_bytes());
        payload.extend(raw);
        let (prepare, _) = record(self.index + 1, self.head, 1, &payload)?;
        let (sign, _) = record(self.index + 2, [0; 32], 2, &[0; 169])?;
        let complete_size = 8 + 2 + raw.len() + 256 + 340;
        let (complete, _) = record(self.index + 3, [0; 32], 3, &vec![0; complete_size])?;
        ensure(
            self.prefix
                .len()
                .checked_add(prepare.len() + sign.len() + complete.len())
                .is_some_and(|n| n <= self.limit),
            "RESOURCE_WAIT owner full lifecycle reservation",
        )?;
        self.append(1, &payload)?;
        self.clock = current.now;
        self.pending = Some(Pending {
            invoice,
            partial: None,
        });
        self.review(self.head, current)
    }
    pub fn review(&mut self, expected: Hash, current: Current<'_>) -> Result<Review> {
        self.current(expected, &current)?;
        let p = self
            .pending
            .as_ref()
            .ok_or("MISSING owner prepared invoice")?;
        let owners = self.origin.owners();
        let digest = hash(
            "REVIEW",
            &[
                current.expected_tip.to_vec(),
                self.head.to_vec(),
                self.delegation.id().to_vec(),
                vec![self.owner],
                p.invoice.id().to_vec(),
            ]
            .concat(),
        );
        Ok(Review {
            head: self.head,
            digest,
            invoice_id: p.invoice.id(),
            logical_id: p.invoice.logical_id(),
            chain: self.origin.chain(),
            channel: self.origin.channel(),
            owner: self.owner(),
            payer: owners[p.invoice.payer()],
            recipient: owners[1 - p.invoice.payer()],
            miner: self.origin.miner(),
            retainer: self.delegation.retainer(),
            amount: p.invoice.amount(),
            fee: p.invoice.fee(),
            sequence: p.invoice.sequence(),
        })
    }
    /// Explicit signing only; key loading occurs after native/head/review checks.
    pub fn sign(
        &mut self,
        expected: Hash,
        digest: Hash,
        current: Current<'_>,
        load_key: impl FnOnce() -> Result<SigningKey>,
    ) -> Result<(Hash, Vec<u8>)> {
        let review = self.review(
            expected,
            Current {
                ledger: current.ledger,
                expected_tip: current.expected_tip,
                now: current.now,
            },
        )?;
        ensure(review.digest == digest, "INVALID owner review digest")?;
        let pending = self.pending.as_ref().ok_or("MISSING owner pending")?;
        ensure(
            pending.partial.is_none(),
            "ALREADY_SIGNED owner use keyless recovery",
        )?;
        let invoice = Invoice::verify(&self.origin, pending.invoice.bytes())?;
        let key = load_key()?;
        let partial = invoice.sign(&self.origin, self.owner, &key)?;
        let mut payload = current.now.to_be_bytes().to_vec();
        payload.extend(current.expected_tip);
        payload.extend(&partial);
        self.append(2, &payload)?;
        self.clock = current.now;
        self.pending.as_mut().unwrap().partial = Some(partial.clone());
        Ok((self.head, partial))
    }
    /// Retain historical complete proof even if backing later closes/disappears.
    /// This grants no currentness or fast-completion status and never signs.
    pub fn retain_complete(
        &mut self,
        expected: Hash,
        receipt: &[u8],
        acknowledgment: &[u8],
        now: u64,
    ) -> Result<Hash> {
        self.prefix(expected)?;
        ensure(now >= self.clock, "CLOCK_WAIT owner retention clock")?;
        let payment = Payment::verify(&self.origin, receipt)?;
        let ack = Acknowledgment::verify(&self.origin, &self.delegation, &payment, acknowledgment)?;
        let pending = self
            .pending
            .as_ref()
            .ok_or("MISSING owner pending transition")?;
        Self::completed(pending, &payment, self.owner)?;
        ensure(
            ack.observed_at() <= now
                && self
                    .last
                    .as_ref()
                    .is_none_or(|(_, a)| a.observed_at() <= ack.observed_at()),
            "CLOCK_WAIT owner acknowledgment time",
        )?;
        let mut payload = now.to_be_bytes().to_vec();
        payload.extend((receipt.len() as u16).to_be_bytes());
        payload.extend(receipt);
        payload.extend(acknowledgment);
        self.append(3, &payload)?;
        self.clock = now;
        self.pending = None;
        self.last = Some((payment, ack));
        Ok(self.head)
    }
    /// Exact pending tail only. No key input, first signing or new authorization.
    pub fn recover(
        path: &Path,
        chain: Hash,
        prior: Hash,
        invoice_id: Hash,
        now: u64,
        limit: usize,
    ) -> Result<Recovery> {
        let mut j = Self::from_file(path, Self::file(path)?, chain, None, now, limit)?;
        ensure(
            j.index > 0 && j.prior_head == prior && (j.last_kind == 1 || j.last_kind == 2),
            "INVALID owner recover prior/tail",
        )?;
        j.retained_pending(j.head, invoice_id)
    }
    /// Keyless exact-tail completion recovery after an ambiguous caller response.
    pub fn recover_complete(
        path: &Path,
        chain: Hash,
        prior: Hash,
        receipt_id: Hash,
        now: u64,
        limit: usize,
    ) -> Result<(Hash, Vec<u8>, Vec<u8>)> {
        let mut j = Self::from_file(path, Self::file(path)?, chain, None, now, limit)?;
        ensure(
            j.index > 0 && j.prior_head == prior && j.last_kind == 3,
            "INVALID owner recover complete prior/tail",
        )?;
        j.prefix(j.head)?;
        let (p, a) = j.last.as_ref().ok_or("MISSING owner complete proof")?;
        ensure(
            p.id() == receipt_id,
            "INVALID owner recover complete receipt",
        )?;
        let result = (j.head, p.bytes().to_vec(), a.bytes().to_vec());
        sync(&j.file, path)?;
        j.prefix(j.head)?;
        Ok(result)
    }
}
