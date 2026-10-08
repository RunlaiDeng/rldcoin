//! Bounded full native replay from immutable pages; locked fsync/rename head.
//! An external monotonic checkpoint is still required against old-backup rollback.
use super::*;
use crate::conflict::{CertifiedHistory, Conflict, Incident, Safety, MAX_INCIDENTS};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Event {
    Block(Box<Block>),
    Finalize(Hash),
    Epoch(Hash),
    ChannelReceipt(Box<crate::channel_receipt::Receipt>),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    pub bootstrap: Bootstrap,
    pub region: Hash,
    pub evidence: Evidence,
    pub events: Vec<Event>,
    /// Complete immutable event pages for the explicit segmented profile only.
    /// These references are integrity metadata; replay still reads every event.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_prefix: Vec<crate::history::Reference>,
    pub incident_ids: BTreeSet<Hash>,
    pub epoch_proofs: Vec<epoch::Transition>,
    pub contact_records: BTreeMap<Hash, crate::contact::Record>,
}
impl Journal {
    pub fn replay(&self, authority: &str, pin: Hash) -> Result<(Trust, VerifiedEvidence, Chain)> {
        require(
            self.event_prefix.is_empty(),
            "paged history requires native disk replay",
        )?;
        self.replay_inner(authority, pin, None)
    }
    pub(crate) fn replay_at(
        &self,
        authority: &str,
        pin: Hash,
        dir: &Path,
    ) -> Result<(Trust, VerifiedEvidence, Chain)> {
        self.replay_inner(authority, pin, Some(dir))
    }
    fn replay_inner(
        &self,
        authority: &str,
        pin: Hash,
        dir: Option<&Path>,
    ) -> Result<(Trust, VerifiedEvidence, Chain)> {
        encode("journal", self)?;
        let trust = Trust::verify(&self.bootstrap, authority, pin)?;
        require(
            !crate::paged_bft::is_profile(&trust.region(self.region)?.rules),
            "paged BFT requires complete native disk event replay; bounded view cannot authorize",
        )?;
        let segmented = crate::segmented::is_profile(&trust.region(self.region)?.rules);
        require(
            if segmented {
                self.event_prefix.len() <= crate::history::MAX_FILES
                    && self.events.len() <= crate::history::PAGE_EVENTS + 1
            } else {
                self.event_prefix.is_empty()
                    && self.events.len() <= MAX_BLOCKS + MAX_SNAPSHOTS + epoch::MAX_EPOCHS
            },
            "journal event bound or profile",
        )?;
        let mut evidence = VerifiedEvidence::verify(&self.evidence, &trust)?;
        require(
            self.epoch_proofs.len() <= epoch::MAX_EPOCHS,
            "local epoch proof bound",
        )?;
        for proof in &self.epoch_proofs {
            evidence.install_epoch(proof.clone(), &trust)?;
        }
        let mut chain = Chain::new(self.region, &trust)?;
        let mut receipts = crate::channel_receipt::Replay::default();
        for event in crate::history::events(dir, self)? {
            let event = event?;
            if let Event::ChannelReceipt(receipt) = event {
                receipt.verify_selected(&chain, &trust, &evidence)?;
                receipts.record(*receipt)?;
            } else {
                self.replay_event(&mut chain, &trust, &evidence, event)?;
            }
        }
        if crate::bft::is_profile(&trust.region(chain.region)?.rules) && chain.height() > 0 {
            let finality = evidence.snapshot(
                chain
                    .finalized
                    .ok_or("BFT history contains uncertified blocks")?,
            )?;
            require(
                finality.blocks == chain.blocks,
                "BFT tip lacks exact final certificate",
            )?;
        }
        require(
            self.contact_records
                .len()
                .checked_add(receipts.len())
                .is_some_and(|n| n <= crate::contact::MAX_CONTACTS),
            "combined native contact/receipt record bound",
        )?;
        for (ident, record) in &self.contact_records {
            require(
                *ident == record.message_id,
                "native contact record index mismatch",
            )?;
            record.verify(&trust, &evidence, chain.region)?;
        }
        Ok((trust, evidence, chain))
    }
    /// Replay one ordered native event; callers start at pinned genesis.
    pub(crate) fn replay_event(
        &self,
        chain: &mut Chain,
        trust: &Trust,
        evidence: &VerifiedEvidence,
        event: Event,
    ) -> Result<()> {
        match event {
            Event::ChannelReceipt(receipt) => receipt.verify_selected(chain, trust, evidence)?,
            Event::Block(block) => {
                if crate::paged_bft::is_profile(&trust.region(chain.region)?.rules) {
                    crate::paged_bft::prepare_parent(chain, evidence)?;
                }
                chain.accept(*block, trust, evidence)?;
            }
            Event::Finalize(id) => {
                require(
                    evidence.snapshot(id)?.statement.epoch == chain.epoch,
                    "local finality event uses another era",
                )?;
                chain.install(id, evidence)?;
            }
            Event::Epoch(id) => {
                let proof = self
                    .epoch_proofs
                    .iter()
                    .find(|p| p.statement.id().ok() == Some(id))
                    .ok_or("epoch event lacks durable proof")?;
                require(
                    proof.statement.region == chain.region
                        && proof.statement.previous_epoch == chain.epoch
                        && chain.finalized == Some(proof.statement.closing_checkpoint)
                        && chain.height() == proof.statement.closing_height,
                    "local epoch event has wrong region, predecessor or closing checkpoint",
                )?;
                chain.epoch = id;
            }
        }
        Ok(())
    }
}
fn io(error: std::io::Error) -> String {
    error.to_string()
}
pub(crate) fn safe_dir(path: &Path) -> Result<()> {
    require(path.is_absolute(), "store directory must be absolute")?;
    for part in path.ancestors() {
        let meta = fs::symlink_metadata(part).map_err(io)?;
        require(
            meta.is_dir() && !meta.file_type().is_symlink(),
            "symlink or non-directory in store path",
        )?;
    }
    Ok(())
}
pub fn read_bytes(path: &Path, limit: usize) -> Result<Vec<u8>> {
    require(limit <= MAX_BYTES, "input limit outside native bounds")?;
    let meta = fs::symlink_metadata(path).map_err(io)?;
    require(
        meta.is_file() && !meta.file_type().is_symlink() && meta.len() <= limit as u64,
        "unsafe or oversized input file",
    )?;
    let mut bytes = vec![];
    File::open(path)
        .map_err(io)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    require(bytes.len() <= limit, "input grew beyond bound")?;
    Ok(bytes)
}
pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_slice(&read_bytes(path, MAX_BYTES)?).map_err(|e| e.to_string())
}
pub struct Store {
    dir: PathBuf,
    _lock: File,
    pub journal: Journal,
    pub trust: Trust,
    pub evidence: VerifiedEvidence,
    pub chain: Chain,
    pub safety: Safety,
    pub conflicts: Vec<Incident>,
    authority: String,
    pin: Hash,
    healthy: bool,
    paged: Option<crate::retained_pages::Stream<paged::Record>>,
    paged_replay: Option<paged::CurrentReplay>,
}
pub fn ensure_not_restoring(dir: &Path) -> Result<()> {
    match fs::symlink_metadata(dir.join("RESTORING")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err("native store restoration is incomplete; retain target unchanged".into()),
    }
}
struct Loaded {
    journal: Journal,
    trust: Trust,
    evidence: VerifiedEvidence,
    chain: Chain,
    conflicts: Vec<Incident>,
    safety: Safety,
}
fn load_image(dir: &Path, authority: &str, pin: Hash, head: Option<Hash>) -> Result<Loaded> {
    if let Some(expected) = head {
        require(
            crate::history::manifest(dir)?.head()? == expected,
            "native history differs from external retained head",
        )?;
        require(
            read_guard(dir)?.is_zero(),
            "pinned history has a pending incident; explicit recovery required",
        )?;
    }
    let journal = crate::history::read_journal(dir)?;
    let (trust, evidence, chain) = journal.replay_at(authority, pin, dir)?;
    let (conflicts, safety) = read_incidents(dir, &journal, &trust, None)?;
    if head.is_some() {
        let retained = conflicts
            .iter()
            .map(|p| p.id())
            .collect::<Result<BTreeSet<_>>>()?;
        require(retained == journal.incident_ids,
            "pinned history has unindexed authenticated incidents; explicit reconciliation required")?;
    }
    Ok(Loaded {
        journal,
        trust,
        evidence,
        chain,
        conflicts,
        safety,
    })
}
/// Pure replay only. The archive controller holds its lock; this cannot open a
/// mutable Store, reconcile incidents or authorize a signer/wallet head.
pub(crate) fn verify_pinned_image(
    dir: &Path,
    authority: &str,
    pin: Hash,
    head: Hash,
) -> Result<()> {
    safe_dir(dir)?;
    if paged::present(dir) {
        paged::verify_pinned_image(dir, authority, pin, head)?;
        return Ok(());
    }
    load_image(dir, authority, pin, Some(head))?;
    Ok(())
}
/// Archive/restore transaction must hold its own lock and recheck complete
/// inventory around this full cold read. This grants no signer/caller recovery.
pub(crate) fn verify_paged_image_binding(
    dir: &Path,
    authority: &str,
    pin: Hash,
    head: Hash,
) -> Result<Hash> {
    safe_dir(dir)?;
    paged::verify_pinned_image(dir, authority, pin, head)
}
impl Store {
    pub(crate) fn require_storage_head(&self, expected: Hash) -> Result<()> {
        require(
            self.healthy && !expected.is_zero() && self.storage_head()? == expected,
            "healthy native store and separately retained exact current storage head required",
        )
    }
    pub fn accept_channel_receipt(
        &mut self,
        receipt: crate::channel_receipt::Receipt,
        expected: &crate::channel_receipt::Expectation,
        expected_head: Hash,
    ) -> Result<crate::channel_receipt::Accepted> {
        require(
            self.healthy,
            "store requires replay after persistence failure",
        )?;
        require(
            !expected_head.is_zero() && self.storage_head()? == expected_head,
            "separately retained exact current native storage head required for receipt acceptance",
        )?;
        let before = self.chain.ledger.clone();
        let (receipt, exact_retry) = crate::channel_receipt::accept(self, receipt, expected)?;
        require(
            self.chain.ledger == before,
            "receipt changed monetary ledger",
        )?;
        Ok(crate::channel_receipt::Accepted {
            format: crate::channel_receipt::FORMAT,
            receipt_id: receipt.id()?,
            accepted_sequence: receipt.next.statement.sequence,
            receipt,
            history_head: self.storage_head()?,
            exact_retry,
            new_fast_payment_accepted: !exact_retry,
            historical_funded_state: true,
            monetary_ledger_unchanged: true,
            on_chain_balance_credit: false,
            independent_latest_state_protection: false,
            monitoring_or_inclusion_guarantee: false,
            live_rld: false,
        })
    }
    pub fn channel_watch(
        &self,
        miner: String,
        expected_head: Hash,
    ) -> Result<crate::channel_receipt::Watch> {
        crate::channel_receipt::watch(self, miner, expected_head)
    }
    pub fn create(
        dir: &Path,
        bootstrap: Bootstrap,
        region: Hash,
        authority: &str,
        pin: Hash,
    ) -> Result<Self> {
        let trust = Trust::verify(&bootstrap, authority, pin)?;
        if crate::paged_bft::is_profile(&trust.region(region)?.rules) {
            return Self::create_paged(dir, bootstrap, region, authority, pin);
        }
        let journal = Journal {
            bootstrap,
            region,
            evidence: Evidence::default(),
            events: vec![],
            event_prefix: vec![],
            incident_ids: BTreeSet::new(),
            epoch_proofs: vec![],
            contact_records: BTreeMap::new(),
        };
        let (trust, evidence, chain) = journal.replay(authority, pin)?;
        safe_dir(dir.parent().ok_or("store parent missing")?)?;
        fs::create_dir(dir).map_err(io)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(dir.join("LOCK"))
            .map_err(io)?;
        lock.try_lock().map_err(|e| e.to_string())?;
        fs::create_dir(dir.join("incidents")).map_err(io)?;
        let mut history_dir = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            history_dir.mode(0o700);
        }
        history_dir.create(dir.join("history")).map_err(io)?;
        let mut guard = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join("INCIDENT_GUARD"))
            .map_err(io)?;
        guard.write_all(&Hash::ZERO.0).map_err(io)?;
        guard.sync_all().map_err(io)?;
        let mut store = Self {
            dir: dir.into(),
            _lock: lock,
            journal,
            trust,
            evidence,
            chain,
            authority: authority.into(),
            pin,
            healthy: true,
            paged: None,
            paged_replay: None,
            safety: Safety::default(),
            conflicts: vec![],
        };
        store.journal = store.persist(&store.journal)?;
        Ok(store)
    }
    pub fn open(dir: &Path, authority: &str, pin: Hash) -> Result<Self> {
        Self::open_internal(dir, authority, pin, None, true)
    }
    /// Open and replay under the ordinary OS lock without incident recovery.
    /// This observation supplies no independent latest-state protection.
    pub fn open_inspection(dir: &Path, authority: &str, pin: Hash) -> Result<Self> {
        Self::open_internal(dir, authority, pin, None, false)
    }
    /// Explicit caller pin, no incident reconciliation or custody mutation.
    pub fn open_pinned_inspection(
        dir: &Path,
        authority: &str,
        pin: Hash,
        head: Hash,
    ) -> Result<Self> {
        require(
            !head.is_zero(),
            "cold inspection requires external latest head",
        )?;
        Self::open_internal(dir, authority, pin, Some(head), false)
    }
    pub(crate) fn require_cold_head(&self, head: Hash) -> Result<()> {
        self.require_storage_head(head)?;
        require(
            read_guard(&self.dir)?.is_zero(),
            "cold inspection pending incident",
        )?;
        if self.paged.is_some() {
            self.require_paged_inspection_head(head)?;
        }
        let (incidents, _) = read_incidents(&self.dir, &self.journal, &self.trust, None)?;
        require(
            incidents
                .iter()
                .map(|p| p.id())
                .collect::<Result<BTreeSet<_>>>()?
                == self.journal.incident_ids,
            "cold inspection unindexed retained incident",
        )
    }
    /// The caller must retain the latest exact head outside this rollback domain.
    /// Check under the native OS lock before any incident reconciliation or replay.
    pub fn open_pinned(dir: &Path, authority: &str, pin: Hash, head: Hash) -> Result<Self> {
        Self::open_internal(dir, authority, pin, Some(head), true)
    }
    fn open_internal(
        dir: &Path,
        authority: &str,
        pin: Hash,
        head: Option<Hash>,
        reconcile: bool,
    ) -> Result<Self> {
        safe_dir(dir)?;
        ensure_not_restoring(dir)?;
        let lock_path = dir.join("LOCK");
        let meta = fs::symlink_metadata(&lock_path).map_err(io)?;
        require(
            meta.is_file() && !meta.file_type().is_symlink(),
            "unsafe lock file",
        )?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(lock_path)
            .map_err(io)?;
        lock.try_lock().map_err(|e| e.to_string())?;
        if paged::present(dir) {
            return Self::open_paged(dir, lock, authority, pin, head);
        }
        if !reconcile {
            require(
                read_guard(dir)?.is_zero(),
                "cold inspection has a pending incident; explicit recovery required",
            )?;
        }
        let Loaded {
            journal,
            trust,
            evidence,
            chain,
            conflicts,
            safety,
        } = load_image(dir, authority, pin, head)?;
        let mut store = Self {
            dir: dir.into(),
            _lock: lock,
            journal,
            trust,
            evidence,
            chain,
            authority: authority.into(),
            pin,
            healthy: true,
            paged: None,
            paged_replay: None,
            safety,
            conflicts,
        };
        let pending = read_guard(dir)?;
        if !pending.is_zero() {
            require(reconcile, "cold inspection refuses incident reconciliation")?;
            require(store.conflicts.iter().any(|p|p.id().ok()==Some(pending)),"pending authenticated incident is not durably retained; recovery proof is required")?;
            store.commit(store.journal.clone())?;
            write_guard(dir, Hash::ZERO)?;
        }
        Ok(store)
    }
    fn persist(&self, journal: &Journal) -> Result<Journal> {
        let (retained, bytes) = crate::history::prepare_journal(&self.dir, journal)?;
        let dest = self.dir.join("journal.json");
        if dest.exists() {
            let meta = fs::symlink_metadata(&dest).map_err(io)?;
            require(
                meta.is_file() && !meta.file_type().is_symlink(),
                "unsafe journal destination",
            )?;
        }
        let temp = self.dir.join("journal.next");
        // A residue after interruption is never trusted, removed or overwritten
        // automatically; the operator can inspect it while the store is closed.
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(io)?;
        let result = (|| {
            file.write_all(&bytes).map_err(io)?;
            file.sync_all().map_err(io)?;
            fs::rename(&temp, &dest).map_err(io)?;
            File::open(&self.dir).map_err(io)?.sync_all().map_err(io)
        })();
        // Failed publication residue is evidence, never automatic cleanup.
        result?;
        Ok(retained)
    }
    pub(crate) fn commit(&mut self, mut journal: Journal) -> Result<()> {
        for proof in &self.conflicts {
            journal.incident_ids.insert(proof.id()?);
        }
        if self.paged.is_some() {
            return self.commit_paged_journal(journal);
        }
        require(
            self.healthy,
            "store requires replay after persistence failure",
        )?;
        let (trust, evidence, chain) = journal.replay_at(&self.authority, self.pin, &self.dir)?;
        let journal = match self.persist(&journal) {
            Ok(retained) => retained,
            Err(error) => {
                self.healthy = false;
                return Err(error);
            }
        };
        self.journal = journal;
        self.trust = trust;
        self.evidence = evidence;
        self.chain = chain;
        Ok(())
    }
    /// Read one complete immutable page at a time, authenticating its bytes again.
    /// Value authority was established by the full native replay under this lock.
    pub fn blocks(&self) -> Result<Box<dyn Iterator<Item = Result<Block>> + '_>> {
        Ok(Box::new(self.events()?.filter_map(|event| match event {
            Ok(Event::Block(block)) => Some(Ok(*block)),
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })))
    }
    pub(crate) fn events(&self) -> Result<Box<dyn Iterator<Item = Result<Event>> + '_>> {
        if let Some(stream) = &self.paged {
            return paged::events(stream);
        }
        Ok(Box::new(crate::history::events(
            Some(&self.dir),
            &self.journal,
        )?))
    }
    /// Locked current integrity observation only; independent freshness is separate.
    pub fn storage_head(&self) -> Result<Hash> {
        require(
            self.healthy,
            "native store requires cold replay after persistence failure",
        )?;
        if let Some(stream) = &self.paged {
            return Ok(stream.storage_head());
        }
        crate::history::manifest(&self.dir)?.head()
    }
    pub fn history_layout(&self) -> Result<(String, usize, usize)> {
        if let Some(stream) = &self.paged {
            let count = usize::try_from(stream.record_count())
                .map_err(|_| "native history record count")?;
            return Ok((
                "RLD-NATIVE-PAGED-BFT-STORE-V1".into(),
                count / crate::history::PAGE_EVENTS,
                count % crate::history::PAGE_EVENTS,
            ));
        }
        let manifest = crate::history::manifest(&self.dir)?;
        Ok((
            manifest.format,
            self.journal.event_prefix.len(),
            self.journal.events.len(),
        ))
    }
    pub fn block_at(&self, height: u64) -> Result<Block> {
        for block in self.blocks()? {
            let block = block?;
            if block.header.height == height {
                return Ok(block);
            }
        }
        Err("native historical block missing".into())
    }
    pub(crate) fn import_height(&self, export: Hash) -> Result<Option<u64>> {
        for block in self.blocks()? {
            let block = block?;
            if block
                .commands
                .iter()
                .any(|c| matches!(c, Command::Import { export: id, .. } if *id == export))
            {
                return Ok(Some(block.header.height));
            }
        }
        Ok(None)
    }
    pub fn template(&self, commands: Vec<Command>, miner: String) -> Result<Block> {
        require(
            self.healthy,
            "store requires replay after persistence failure",
        )?;
        self.safety.check(&self.chain, &commands, &self.evidence)?;
        self.chain
            .template(commands, miner, &self.trust, &self.evidence)
    }
    pub(crate) fn validate_partial_owner(&self, signed: SignedIntent) -> Result<()> {
        require(
            self.healthy,
            "store requires replay after persistence failure",
        )?;
        let command = Command::Spend(Box::new(signed.clone()));
        self.safety.check(&self.chain, &[command], &self.evidence)?;
        self.chain
            .validate_partial_owner(signed, &self.trust, &self.evidence)
    }
    pub fn accept(&mut self, block: Block) -> Result<()> {
        require(
            !crate::bft::is_profile(&self.trust.region(self.chain.region)?.rules),
            "BFT profile requires atomic certified block/finality application",
        )?;
        self.safety
            .check(&self.chain, &block.commands, &self.evidence)?;
        let mut journal = self.journal.clone();
        journal.events.push(Event::Block(Box::new(block)));
        self.commit(journal)
    }
    pub fn observe_conflict<P: Into<Incident>>(&mut self, proof: P) -> Result<Hash> {
        let proof = proof.into();
        require(
            self.healthy,
            "store requires replay after persistence failure",
        )?;
        proof.verify(&self.trust)?;
        let iid = proof.id()?;
        if self.conflicts.iter().any(|p| p.id().ok() == Some(iid)) {
            return Ok(iid);
        }
        if let Err(error) = write_guard(&self.dir, iid) {
            self.healthy = false;
            return Err(error);
        }
        if self.conflicts.len() >= MAX_INCIDENTS {
            self.healthy = false;
            return Err(
                "incident capacity full; pending guard refuses restart without retained proof"
                    .into(),
            );
        }
        let mut conflicts = self.conflicts.clone();
        conflicts.push(proof.clone());
        let safety = Safety::from_incidents(&conflicts, &self.trust)?;
        // Persist a separately bounded immutable proof before changing the
        // journal. Reopening finds a valid orphan if interrupted between writes.
        let result = publish_incident(&self.dir, &proof, iid, &self.trust);
        self.safety = safety;
        self.conflicts = conflicts;
        if let Err(error) = result {
            self.healthy = false;
            return Err(error);
        }
        self.commit(self.journal.clone())?;
        if let Err(error) = write_guard(&self.dir, Hash::ZERO) {
            self.healthy = false;
            return Err(error);
        }
        Ok(iid)
    }
    pub fn add_evidence(&mut self, evidence: Evidence) -> Result<()> {
        if self.paged.is_some() {
            return self.add_paged_evidence(evidence);
        }
        let journal = self.stage_evidence(evidence)?;
        self.commit(journal)
    }
    pub(crate) fn stage_evidence(&mut self, evidence: Evidence) -> Result<Journal> {
        require(
            self.paged.is_none(),
            "paged BFT needs typed complete evidence event, not legacy journal mutation",
        )?;
        require(
            evidence.snapshots.len() <= MAX_SNAPSHOTS,
            "incoming snapshot bound",
        )?;
        encode("evidence", &evidence)?;
        // Preserve independently authenticated signer failures even though the
        // accompanying value archive is rejected. No branch is installed.
        for (index, snapshot) in evidence.snapshots.iter().enumerate() {
            let incoming = CertifiedHistory::from_snapshot(snapshot);
            incoming.verify(&self.trust)?;
            for old in self
                .journal
                .evidence
                .snapshots
                .iter()
                .chain(evidence.snapshots[..index].iter())
            {
                if old.statement.region == snapshot.statement.region {
                    let proof = Conflict::from_snapshots(old, snapshot)?;
                    if proof.verify(&self.trust).is_ok() {
                        let iid = self.observe_conflict(proof)?;
                        return Err(format!("authenticated conflicting checkpoint retained as {}; archive not installed",iid.to_hex()));
                    }
                }
            }
        }
        // Authenticate complete incoming variants even when retained bytes win.
        let mut checked = self.evidence.clone();
        for snapshot in &evidence.snapshots {
            checked.add(snapshot.clone(), &self.trust)?;
        }
        let mut journal = self.journal.clone();
        for snapshot in evidence.snapshots {
            let sid = snapshot.statement.id()?;
            if let Some(old) = journal
                .evidence
                .snapshots
                .iter()
                .find(|s| s.statement.id().ok() == Some(sid))
            {
                require(
                    old == &snapshot
                        || (crate::bft::is_profile(
                            &self.trust.region(snapshot.statement.region)?.rules,
                        ) && old.statement == snapshot.statement
                            && old.blocks == snapshot.blocks
                            && (old.epochs == snapshot.epochs
                                || crate::bft::is_joint(
                                    &self.trust.region(snapshot.statement.region)?.rules,
                                ) && old
                                    .epochs
                                    .iter()
                                    .map(|p| p.statement.id())
                                    .collect::<Result<Vec<_>>>()?
                                    == snapshot
                                        .epochs
                                        .iter()
                                        .map(|p| p.statement.id())
                                        .collect::<Result<Vec<_>>>()?)),
                    "inconsistent duplicate evidence",
                )?;
            } else {
                journal.evidence.snapshots.push(snapshot);
            }
        }
        Ok(journal)
    }
    pub fn snapshot_request(&self) -> Result<Snapshot> {
        self.safety.check_region(self.chain.region)?;
        let mut proof = self.evidence.epoch_proofs(self.chain.region);
        if self.chain.epoch == epoch::Registry::initial(&self.trust, self.chain.region)? {
            proof.clear();
        } else {
            let count = proof
                .iter()
                .position(|p| p.statement.id().ok() == Some(self.chain.epoch))
                .ok_or("local epoch lacks verified authority")?
                + 1;
            proof.truncate(count);
        }
        Ok(Snapshot {
            base: self.chain.snapshot_base(),
            bft: None,
            statement: self.chain.statement(&self.trust)?,
            approvals: vec![],
            blocks: self.chain.blocks.clone(),
            epochs: proof,
        })
    }
    pub fn bft_submit(&self, commands: Vec<Command>) -> Result<Hash> {
        let envelope = bft_network::Envelope {
            format: bft_network::FORMAT.into(),
            currency: self.trust.currency()?,
            region: self.chain.region,
            // The paged diagnostic view orders regional heights, not causal
            // imports. Carry the complete independently authenticated closure;
            // a submission must verify without the receiver's local history.
            evidence: self.proof()?,
            body: if crate::bft::is_joint(&self.trust.region(self.chain.region)?.rules) {
                bft_network::Body::EpochSubmission {
                    commands: commands.clone(),
                    epochs: self.evidence.epoch_proofs(self.chain.region),
                }
            } else {
                bft_network::Body::Submission(commands.clone())
            },
        };
        let ident = envelope.verify(self)?;
        self.bft_candidate(
            commands,
            self.trust.region(self.chain.region)?.validators[0].clone(),
        )?;
        let queue = self.dir.join("bft-submissions");
        if !queue.exists() {
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(&queue).map_err(io)?;
            File::open(&self.dir).map_err(io)?.sync_all().map_err(io)?;
        }
        safe_dir(&queue)?;
        let path = queue.join(format!("{}.json", ident.to_hex()));
        let raw = serde_json::to_vec(&envelope.pack()?).map_err(|e| e.to_string())?;
        if path.exists() {
            if read_bytes(&path, MAX_BYTES)? != raw {
                return Err("BFT submission filename collision".into());
            }
        } else {
            let entries = std::fs::read_dir(&queue)
                .map_err(|e| e.to_string())?
                .count();
            if entries >= 32 {
                return Err("BFT submission capacity; retain all previous commands".into());
            }
            crate::keystore::private_create(&path, &raw)?;
        }
        Ok(ident)
    }
    pub fn bft_candidate(&self, commands: Vec<Command>, miner: String) -> Result<Snapshot> {
        crate::bft::Context::current(self)?;
        let commands = if self.trust.region(self.chain.region)?.rules == channels::BFT_RULES
            || self.paged.is_some()
        {
            // Ordinary startup already calls this native candidate path. This
            // current-head read is a locked local observation, not an independent
            // freshness witness or permission to first-sign an owner response.
            let head = self.storage_head()?;
            let mut watched = self.channel_watch(miner.clone(), head)?.commands;
            let automatic = watched.len();
            for command in commands {
                // Exact complete typed equality only; no body/hash-only auth.
                if !watched.contains(&command) {
                    watched.push(command);
                }
            }
            require(
                automatic == 0 || watched.len() <= crate::channel_receipt::WATCH_SLOTS,
                "automatic challenges occupy existing four candidate slots",
            )?;
            watched
        } else {
            commands
        };
        self.safety.check(&self.chain, &commands, &self.evidence)?;
        let mut block = self
            .chain
            .template(commands, miner, &self.trust, &self.evidence)?;
        mine(&mut block)?;
        let mut chain = self.chain.clone();
        if self.paged.is_some() {
            crate::paged_bft::prepare_parent(&mut chain, &self.evidence)?;
        }
        chain.accept(block, &self.trust, &self.evidence)?;
        let mut snapshot = self.snapshot_request()?;
        snapshot.statement = chain.statement(&self.trust)?;
        snapshot.blocks = chain.blocks;
        Ok(snapshot)
    }
    pub fn epoch_request(&self, validators: Vec<String>) -> Result<epoch::Transition> {
        require(
            self.trust.region(self.chain.region)?.rules == DOMAIN
                || crate::bft::has_epochs(&self.trust.region(self.chain.region)?.rules),
            "BFT-profile joint epoch signer activation is not implemented",
        )?;
        self.safety.check_region(self.chain.region)?;
        let sid = self
            .chain
            .finalized
            .ok_or("handoff needs an installed closing checkpoint")?;
        let closing = epoch::Anchor::from_snapshot(self.evidence.snapshot(sid)?);
        require(
            closing.statement.height == self.chain.height(),
            "handoff must close the exact local tip",
        )?;
        let (previous, number, keys, floor) =
            self.evidence.epoch_state(&self.trust, self.chain.region)?;
        require(
            previous == self.chain.epoch,
            "local epoch must match latest authority",
        )?;
        let joint = crate::bft::is_joint(&self.trust.region(self.chain.region)?.rules);
        let proposal = epoch::Transition {
            selection: if joint {
                self.chain.blocks.last().cloned().map(Box::new)
            } else {
                None
            },
            statement: epoch::EpochStatement {
                activation: if joint {
                    Some(
                        crate::joint_epoch::activation(
                            &self.trust.region(self.chain.region)?.rules,
                        )?
                        .into(),
                    )
                } else {
                    None
                },
                currency: self.trust.currency()?,
                region: self.chain.region,
                number: number + 1,
                previous_epoch: previous,
                closing_checkpoint: sid,
                closing_height: self.chain.height(),
                validators,
            },
            closing,
            old_approvals: vec![],
            new_approvals: vec![],
        };
        proposal.validate_request(&self.trust, previous, number, &keys, floor)?;
        self.evidence.epochs.fresh_bft_keys(
            &self.trust,
            self.chain.region,
            &proposal.statement.validators,
        )?;
        Ok(proposal)
    }
    /// Observation of epochs selected by the already fully replayed local
    /// journal. Verified remote evidence alone never enters this list.
    pub fn observed_installed_epochs(&self) -> Result<Vec<epoch::Transition>> {
        require(
            self.healthy,
            "native store requires restart after publication failure",
        )?;
        self.safety.check_region(self.chain.region)?;
        crate::bft::Context::current(self)?;
        let mut previous = epoch::Registry::initial(&self.trust, self.chain.region)?;
        let mut selected = Vec::new();
        for event in self.events()? {
            if let Event::Epoch(eid) = event? {
                require(
                    selected.len() < epoch::MAX_EPOCHS,
                    "installed epoch observation bound",
                )?;
                let proof = self
                    .journal
                    .epoch_proofs
                    .iter()
                    .find(|p| p.statement.id().ok() == Some(eid))
                    .ok_or("installed epoch event lacks exact retained proof")?;
                require(
                    proof.statement.region == self.chain.region
                        && proof.statement.previous_epoch == previous,
                    "installed epoch observation ordered predecessor mismatch",
                )?;
                selected.push(proof.clone());
                previous = eid;
            }
        }
        require(
            previous == self.chain.epoch,
            "installed epoch observation differs from replayed chain",
        )?;
        encode("installed-epoch-observation", &selected)?;
        Ok(selected)
    }

    pub fn install_epoch(&mut self, proof: epoch::Transition) -> Result<Hash> {
        self.safety.check_region(self.chain.region)?;
        let existing = self.evidence.epoch_proofs(proof.statement.region);
        for (i, old) in existing.iter().enumerate() {
            if old.statement.previous_epoch == proof.statement.previous_epoch
                && old.statement.id()? != proof.statement.id()?
            {
                let conflict = Conflict::from_handoffs(old, &proof, &existing[..i])?;
                if conflict.verify(&self.trust).is_ok() {
                    let iid = self.observe_conflict(conflict)?;
                    return Err(format!(
                        "authenticated incompatible handoffs retained as {}",
                        iid.to_hex()
                    ));
                }
            }
        }
        let mut authority_path = existing.clone();
        authority_path.push(proof.clone());
        let authority = CertifiedHistory {
            bft: proof.closing.bft.clone(),
            statement: proof.closing.statement.clone(),
            approvals: proof.closing.approvals.clone(),
            headers: proof.closing.headers.clone(),
            epochs: authority_path,
        };
        if authority.verify(&self.trust).is_ok() {
            for old in &self.journal.evidence.snapshots {
                if old.statement.region == proof.statement.region {
                    let conflict = Conflict::canonical(
                        authority.clone(),
                        CertifiedHistory::from_snapshot(old),
                    )?;
                    if conflict.verify(&self.trust).is_ok() {
                        let iid = self.observe_conflict(conflict)?;
                        return Err(format!(
                            "retired-era finality conflicts with handoff retained as {}",
                            iid.to_hex()
                        ));
                    }
                }
            }
        }
        require(
            proof.statement.region == self.chain.region
                && proof.statement.previous_epoch == self.chain.epoch
                && self.chain.finalized == Some(proof.statement.closing_checkpoint)
                && self.chain.height() == proof.statement.closing_height,
            "local handoff identity, current epoch or finality mismatch",
        )?;
        let mut verified = self.evidence.clone();
        let eid = verified.install_epoch(proof.clone(), &self.trust)?;
        let mut journal = self.journal.clone();
        journal.epoch_proofs.push(proof);
        journal.events.push(Event::Epoch(eid));
        self.commit(journal)?;
        Ok(eid)
    }
    pub fn finalize(&mut self, snapshot: Snapshot) -> Result<Hash> {
        if self.paged.is_some() {
            return self.finalize_paged(snapshot);
        }
        CertifiedHistory::from_snapshot(&snapshot).verify(&self.trust)?;
        if crate::bft::is_profile(&self.trust.region(self.chain.region)?.rules)
            && self.chain.blocks.starts_with(&snapshot.blocks)
            && self
                .journal
                .events
                .iter()
                .any(|e| matches!(e,Event::Finalize(id) if snapshot.statement.id().ok()==Some(*id)))
        {
            return snapshot.statement.id();
        }
        for old in &self.journal.evidence.snapshots {
            if old.statement.region == snapshot.statement.region {
                let proof = Conflict::from_snapshots(old, &snapshot)?;
                if proof.verify(&self.trust).is_ok() {
                    let iid = self.observe_conflict(proof)?;
                    return Err(format!(
                        "conflicting finalization retained as {}; neither branch adopted",
                        iid.to_hex()
                    ));
                }
            }
        }
        self.safety.check_region(self.chain.region)?;
        if crate::bft::is_profile(&self.trust.region(self.chain.region)?.rules) {
            let mut unsigned = snapshot.clone();
            unsigned.bft = None;
            crate::bft::validate_next(&unsigned, self)?;
            let block = snapshot.blocks.last().ok_or("BFT block missing")?.clone();
            self.safety
                .check(&self.chain, &block.commands, &self.evidence)?;
            let sid = snapshot.statement.id()?;
            let mut journal = self.journal.clone();
            journal.evidence.snapshots.push(snapshot);
            journal.events.push(Event::Block(Box::new(block)));
            journal.events.push(Event::Finalize(sid));
            self.commit(journal)?;
            return Ok(sid);
        }
        require(
            snapshot.statement == self.chain.statement(&self.trust)?
                && snapshot.blocks == self.chain.blocks,
            "local checkpoint does not match actual chain",
        )?;
        let sid = snapshot.statement.id()?;
        let mut journal = self.journal.clone();
        journal.evidence.snapshots.push(snapshot);
        journal.events.push(Event::Finalize(sid));
        self.commit(journal)?;
        Ok(sid)
    }
}

fn read_incidents(
    dir: &Path,
    journal: &Journal,
    trust: &Trust,
    ignore: Option<Hash>,
) -> Result<(Vec<Incident>, Safety)> {
    let path = dir.join("incidents");
    safe_dir(&path)?;
    let mut conflicts = vec![];
    let mut ids = BTreeSet::new();
    for entry in fs::read_dir(&path).map_err(io)? {
        require(
            conflicts.len() < MAX_INCIDENTS,
            "incident directory exceeds bound",
        )?;
        let entry = entry.map_err(io)?;
        if ignore
            .is_some_and(|id| entry.file_name().to_str() == Some(&format!("{}.json", id.to_hex())))
        {
            continue;
        }
        let proof: Incident = read_json(&entry.path())?;
        proof.verify(trust)?;
        let iid = proof.id()?;
        require(
            entry.file_name().to_str() == Some(&format!("{}.json", iid.to_hex()))
                && ids.insert(iid),
            "incident filename mismatch or duplicate",
        )?;
        conflicts.push(proof);
    }
    require(
        journal.incident_ids.is_subset(&ids),
        "indexed incident is missing; refuse recovery",
    )?;
    let safety = Safety::from_incidents(&conflicts, trust)?;
    Ok((conflicts, safety))
}
fn publish_incident(dir: &Path, proof: &Incident, iid: Hash, trust: &Trust) -> Result<()> {
    let path = dir.join("incidents");
    safe_dir(&path)?;
    let final_path = path.join(format!("{}.json", iid.to_hex()));
    if final_path.exists() {
        let saved: Incident = read_json(&final_path)?;
        require(saved.id()? == iid, "immutable incident mismatch")?;
        saved.verify(trust)?;
        return Ok(());
    }
    let bytes = serde_json::to_vec(proof).map_err(|e| e.to_string())?;
    require(bytes.len() <= MAX_BYTES, "incident byte bound")?;
    // A partial write is intentionally left behind. It fails closed on replay,
    // rather than permitting known signer faults to disappear after a crash.
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(final_path).map_err(io)?;
    file.write_all(&bytes).map_err(io)?;
    file.sync_all().map_err(io)?;
    File::open(path).map_err(io)?.sync_all().map_err(io)
}

fn read_guard(dir: &Path) -> Result<Hash> {
    let path = dir.join("INCIDENT_GUARD");
    let meta = fs::symlink_metadata(&path).map_err(io)?;
    require(
        meta.is_file() && !meta.file_type().is_symlink() && meta.len() == 32,
        "invalid incident guard",
    )?;
    let bytes = fs::read(path).map_err(io)?;
    let value: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "invalid incident guard bytes")?;
    Ok(Hash(value))
}
fn write_guard(dir: &Path, iid: Hash) -> Result<()> {
    read_guard(dir)?;
    let mut file = OpenOptions::new()
        .write(true)
        .open(dir.join("INCIDENT_GUARD"))
        .map_err(io)?;
    file.write_all(&iid.0).map_err(io)?;
    file.sync_all().map_err(io)
}
/// Retry the exact authenticated proof named by a failed/pending guard. This
/// never clears safety state or removes an incident, and takes the same lock.
pub fn recover_incident<P: Into<Incident>>(
    dir: &Path,
    authority: &str,
    pin: Hash,
    proof: P,
) -> Result<()> {
    let proof = proof.into();
    safe_dir(dir)?;
    ensure_not_restoring(dir)?;
    let lock_path = dir.join("LOCK");
    let metadata = fs::symlink_metadata(&lock_path).map_err(io)?;
    require(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "unsafe recovery lock",
    )?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock_path)
        .map_err(io)?;
    lock.try_lock().map_err(|e| e.to_string())?;
    let journal = crate::history::read_journal(dir)?;
    let (trust, _, _) = journal.replay_at(authority, pin, dir)?;
    proof.verify(&trust)?;
    let iid = proof.id()?;
    let pending = read_guard(dir)?;
    require(
        pending == iid || (pending.is_zero() && journal.incident_ids.contains(&iid)),
        "recovery proof differs from pending or indexed incident",
    )?;
    let mut remaining = journal.clone();
    remaining.incident_ids.remove(&iid);
    let (retained, _) = read_incidents(dir, &remaining, &trust, Some(iid))?;
    require(
        retained.len() < MAX_INCIDENTS || retained.iter().any(|p| p.id().ok() == Some(iid)),
        "recovery incident capacity full; existing records remain retained",
    )?;
    write_guard(dir, iid)?;
    let target = dir.join("incidents").join(format!("{}.json", iid.to_hex()));
    if target.exists()
        && !read_json::<Incident>(&target)
            .ok()
            .is_some_and(|p| p.id().ok() == Some(iid) && p.verify(&trust).is_ok())
    {
        let meta = fs::symlink_metadata(&target).map_err(io)?;
        require(
            meta.is_file() && !meta.file_type().is_symlink() && meta.len() <= MAX_BYTES as u64,
            "unsafe damaged incident",
        )?;
        let residue = dir.join(format!("damaged-incident-{}.bin", iid.to_hex()));
        require(
            !residue.exists(),
            "damaged incident residue already exists; retain it for review",
        )?;
        fs::rename(&target, &residue).map_err(io)?;
        File::open(dir).map_err(io)?.sync_all().map_err(io)?;
    }
    publish_incident(dir, &proof, iid, &trust)
}

#[path = "paged_store.rs"]
mod paged;

pub(crate) use paged::Historical as PagedSigningHistory;
#[cfg(test)]
pub(crate) use paged::Record as PagedRecord;
pub use paged::{
    inspect_export_archive_candidate, inspect_lossless_packed_native_candidate,
    inspect_packed_native_candidate, ExportArchiveObservationCandidate,
    ExportArchiveQueryCandidate, NativeContinuationCandidate, NativeContinuationPinsCandidate,
    NativePrefixPinsCandidate, PackedNativeBoundaryCandidate,
};
