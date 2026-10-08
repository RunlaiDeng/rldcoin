//! Ordinary Store persistence for the explicit signed paged BFT profile.
//! Cold open executes all records from genesis. Live commits stage only the
//! privately retained actual Native replay after complete current-byte checks.
use super::*;
use crate::retained_pages::{Purpose, Scope, Stream};
#[path = "paged_store/body_witness.rs"]
mod body_witness;
const HEADER: &str = "ledger-header.json";
const EVENTS: &str = "ledger-events";
const FORMAT: &str = "RLD-NATIVE-PAGED-BFT-STORE-V1";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    format: String,
    bootstrap: Bootstrap,
    region: Hash,
}
impl Header {
    fn scope(&self, trust: &Trust) -> Result<Scope> {
        require(
            self.format == FORMAT
                && crate::paged_bft::is_profile(&trust.region(self.region)?.rules),
            "ordinary paged BFT store explicit signed profile",
        )?;
        Scope::bind(
            trust,
            self.region,
            Purpose::Ledger,
            id("paged-bft-store-origin-v1", self)?,
        )
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum Record {
    Certified(Box<Snapshot>),
    OriginHistory(Box<CompleteOriginHistory>),
    Evidence(Box<Evidence>),
    Receipt(Box<crate::channel_receipt::Receipt>),
    Contact(Box<crate::contact::Frame>),
    Incidents(BTreeSet<Hash>),
}
impl Record {
    fn snapshots(&self) -> Result<Vec<Snapshot>> {
        Ok(match self {
            Self::Certified(s) => vec![*s.clone()],
            Self::OriginHistory(proof) => proof.snapshots.clone(),
            Self::Evidence(e) => e.snapshots.clone(),
            Self::Contact(frame) => {
                crate::contact::Frame::unpack(&frame.retained_bytes()?)?
                    .1
                    .evidence
                    .snapshots
            }
            _ => vec![],
        })
    }
}
#[derive(Clone)]
struct Replay {
    trust: Trust,
    chain: Chain,
    evidence: VerifiedEvidence,
    // Created only by this process's full native execution, never loaded.
    bodies: body_witness::Bodies,
    executed: body_witness::ExecutedPrefix,
    receipts: crate::channel_receipt::Replay,
    receipt_anchors: BTreeSet<Hash>,
    incidents: BTreeSet<Hash>,
    contacts: BTreeMap<Hash, crate::contact::Record>,
    // Derived only from complete origin events; never deserialized state.
    origin_imports: BTreeMap<Hash, (Hash, Hash)>,
}
/// Process-only Native execution, created only by authenticated genesis or full
/// cold replay. Never serialized and never initialized from Store projections.
pub(super) struct CurrentReplay {
    header: Header,
    replay: Replay,
    head: Hash,
}
impl CurrentReplay {
    fn stage(&self, node: &Store, header: &Header, stream: &Stream<Record>) -> Result<Replay> {
        require(
            self.head == stream.storage_head()
                && serde_json::to_vec(&self.header).map_err(|e| e.to_string())?
                    == serde_json::to_vec(header).map_err(|e| e.to_string())?,
            "paged actual process header/head differs",
        )?;
        let scope = header.scope(&self.replay.trust)?;
        stream.require_scope(&scope)?;
        stream.require_unchanged(self.head)?;
        self.replay
            .executed
            .require_boundary(&scope, stream.record_count(), self.head)?;
        let actual = &self.replay.chain;
        require(
            node.trust.binding == self.replay.trust.binding
                && node.evidence.trust_binding == self.replay.evidence.trust_binding
                && node.evidence.snapshots == self.replay.evidence.snapshots
                && node.evidence.epochs.regions == self.replay.evidence.epochs.regions
                && node.chain.region == actual.region
                && node.chain.trust_binding == actual.trust_binding
                && node.chain.currency == actual.currency
                && node.chain.prefix_height == actual.prefix_height
                && node.chain.prefix_tip == actual.prefix_tip
                && node.chain.segmented == actual.segmented
                && node.chain.blocks == actual.blocks
                && node.chain.ledger == actual.ledger
                && node.chain.finalized == actual.finalized
                && node.chain.epoch == actual.epoch
                && serde_json::to_vec(&node.journal).map_err(|e| e.to_string())?
                    == serde_json::to_vec(&self.replay.journal(header))
                        .map_err(|e| e.to_string())?,
            "public paged Store projection differs from actual Native execution",
        )?;
        Ok(self.replay.clone())
    }
}
fn body(snapshot: &Snapshot) -> Result<Hash> {
    id(
        "paged-bft-complete-native-body-v1",
        &(
            &snapshot.base,
            &snapshot.statement,
            &snapshot.blocks,
            &snapshot.epochs,
            &snapshot.approvals,
        ),
    )
}
impl Replay {
    fn new(header: &Header, authority: &str, pin: Hash) -> Result<Self> {
        let trust = Trust::verify(&header.bootstrap, authority, pin)?;
        header.scope(&trust)?;
        let chain = Chain::new(header.region, &trust)?;
        let evidence = VerifiedEvidence::verify(&Evidence::default(), &trust)?;
        let executed = body_witness::ExecutedPrefix::new(header.scope(&trust)?)?;
        Ok(Self {
            trust,
            chain,
            evidence,
            bodies: Default::default(),
            executed,
            receipts: Default::default(),
            receipt_anchors: BTreeSet::new(),
            incidents: BTreeSet::new(),
            contacts: BTreeMap::new(),
            origin_imports: BTreeMap::new(),
        })
    }
    fn retain_for_next(&mut self) -> Result<()> {
        let mut needed = self.receipt_anchors.clone();
        needed.extend(
            self.origin_imports
                .values()
                .map(|(_, checkpoint)| *checkpoint),
        );
        needed.extend(self.contacts.values().map(|record| record.snapshot));
        if let Some(id) = self.chain.finalized {
            needed.insert(id);
        }
        let ledger = &self.chain.ledger;
        for coin in ledger.coins.values() {
            needed.extend(&coin.dependencies);
        }
        for export in ledger.exports.values() {
            needed.extend(&export.dependencies);
        }
        if let Some(native) = &ledger.channel_state {
            for escrow in native.book.channels.values() {
                needed.extend(&escrow.dependencies);
            }
            for reserve in native.book.reserves.values() {
                needed.extend(&reserve.coin.dependencies);
            }
        }
        let mut latest: BTreeMap<Hash, (u64, Hash)> = BTreeMap::new();
        for (id, (s, _)) in &self.evidence.snapshots {
            let entry = latest.entry(s.statement.region).or_insert((0, *id));
            if s.statement.height >= entry.0 {
                *entry = (s.statement.height, *id);
            }
        }
        needed.extend(latest.values().map(|(_, id)| *id));
        while self.evidence.snapshots.len() >= MAX_SNAPSHOTS {
            let remove = self
                .evidence
                .snapshots
                .iter()
                .filter(|(id, _)| !needed.contains(id))
                .min_by_key(|(id, (s, _))| (s.statement.height, **id))
                .map(|(id, _)| *id)
                .ok_or("paged BFT complete active dependency capacity; retain all evidence")?;
            self.evidence.snapshots.remove(&remove);
        }
        Ok(())
    }
    fn authenticate(
        &mut self,
        snapshot: &Snapshot,
        stream: &dyn body_witness::History,
    ) -> Result<(Hash, bool)> {
        let sid = snapshot.statement.id()?;
        let complete = body(snapshot)?;
        if let Some(old) = self.prior_body(sid, stream)? {
            // A body hash is usable only after native genesis execution in THIS
            // invocation. Every new complete envelope/certificate authenticates.
            crate::conflict::CertifiedHistory::from_snapshot(snapshot).verify(&self.trust)?;
            crate::segmented::shape(snapshot, &self.trust)?;
            require(
                old == complete,
                "historical certificate changes native complete body",
            )?;
            return Ok((sid, false));
        }
        self.retain_for_next()?;
        self.evidence.add(snapshot.clone(), &self.trust)?;
        self.bodies.remember(sid, complete)?;
        Ok((sid, true))
    }
    fn prior_body(
        &mut self,
        sid: Hash,
        stream: &dyn body_witness::History,
    ) -> Result<Option<Hash>> {
        if let Some(complete) = self.bodies.get(&sid) {
            return Ok(Some(*complete));
        }
        let found = self.executed.find(stream, sid)?;
        if let Some(complete) = found {
            self.bodies.remember(sid, complete)?;
        }
        Ok(found)
    }
    fn apply_retained(
        &mut self,
        record: &Record,
        stream: &dyn body_witness::History,
    ) -> Result<()> {
        stream.require_scope(&self.executed.scope)?;
        self.apply(record, stream)?;
        self.executed.advance(record)
    }
    fn apply(&mut self, record: &Record, stream: &dyn body_witness::History) -> Result<()> {
        let _signature_inputs = crate::verification_keys::history_inputs::NativeRecord::enter();
        #[cfg(test)]
        let mut cost = crate::bft::sign_cost::NativeRecordClock::new();
        #[cfg(test)]
        current_tests::note_actual_record_execution();
        match record {
            Record::Certified(snapshot) => {
                require(
                    snapshot.statement.region == self.chain.region,
                    "paged BFT local certificate region",
                )?;
                crate::paged_bft::shape(snapshot, &self.trust)?;
                crate::conflict::CertifiedHistory::from_snapshot(snapshot).verify(&self.trust)?;
                let sid = snapshot.statement.id()?;
                let complete = body(snapshot)?;
                if snapshot.statement.height <= self.chain.height() {
                    require(
                        self.prior_body(sid, stream)? == Some(complete),
                        "historical paged certificate body not natively executed",
                    )?;
                } else {
                    require(
                        snapshot.statement.previous == self.chain.finalized,
                        "paged BFT local certificate predecessor",
                    )?;
                    if let Some(old) = self.bodies.get(&sid) {
                        require(*old == complete, "paged BFT later certificate body differs")?;
                    }
                    // A new local height executes fully under its exact current
                    // native predecessor; cache occupancy grants no authority.
                    self.retain_for_next()?;
                    let mut chain =
                        crate::paged_bft::replay(snapshot, &self.trust, &self.evidence)?;
                    require(
                        chain.statement(&self.trust)? == snapshot.statement,
                        "paged BFT local native certified state",
                    )?;
                    // This ledger comes from pinned genesis and the fully
                    // executed native predecessor in this invocation. Never
                    // initialize it from a serialized body/head witness.
                    self.evidence
                        .snapshots
                        .entry(sid)
                        .or_insert_with(|| (*snapshot.clone(), chain.ledger.clone()));
                    self.bodies.remember(sid, complete)?;
                    chain.install(sid, &self.evidence)?;
                    self.chain = chain;
                }
            }
            Record::Evidence(evidence) => {
                require(
                    evidence.snapshots.len() <= MAX_SNAPSHOTS,
                    "paged BFT incoming evidence bound",
                )?;
                encode("evidence", evidence)?;
                for s in &evidence.snapshots {
                    self.authenticate(s, stream)?;
                }
            }
            Record::OriginHistory(proof) => self.apply_origin_history(proof, stream)?,
            Record::Receipt(receipt) => {
                receipt.verify_selected(&self.chain, &self.trust, &self.evidence)?;
                self.receipts.record(*receipt.clone())?;
                self.receipt_anchors.insert(receipt.statement.checkpoint);
            }
            Record::Contact(frame) => {
                let (frame, bundle) = crate::contact::Frame::unpack(&frame.retained_bytes()?)?;
                require(
                    bundle.currency == self.trust.currency()?
                        && bundle.destination == self.chain.region,
                    "paged contact currency/destination",
                )?;
                self.trust.region(bundle.source)?;
                require(
                    bundle.incidents.len() <= MAX_INCIDENTS,
                    "paged contact incident bound",
                )?;
                for proof in &bundle.incidents {
                    proof.verify(&self.trust)?;
                    require(
                        self.incidents.contains(&proof.id()?),
                        "paged contact unindexed incident",
                    )?;
                }
                let record = crate::contact::Record {
                    message_id: frame.message_id,
                    payload_sha256: frame.payload_sha256,
                    source: bundle.source,
                    destination: bundle.destination,
                    snapshot: bundle.snapshot,
                    export: bundle.export,
                };
                // The complete frame must stand alone under the original64 bound.
                // Never fill an omitted predecessor from this Store's cache.
                let checked = VerifiedEvidence::verify(&bundle.evidence, &self.trust)?;
                record.verify(&self.trust, &checked, self.chain.region)?;
                for snapshot in &bundle.evidence.snapshots {
                    self.authenticate(snapshot, stream)?;
                }
                record.verify(&self.trust, &self.evidence, self.chain.region)?;
                if let Some(old) = self.contacts.get(&record.message_id) {
                    require(old == &record, "paged contact retained record differs")?;
                } else {
                    require(
                        self.contacts.len() < crate::contact::MAX_CONTACTS,
                        "paged contact record capacity",
                    )?;
                    self.contacts.insert(record.message_id, record);
                }
            }
            Record::Incidents(ids) => {
                require(
                    ids.len() <= MAX_INCIDENTS && self.incidents.is_subset(ids),
                    "paged BFT incident index rollback/bound",
                )?;
                self.incidents = ids.clone();
            }
        }
        #[cfg(test)]
        cost.mark(0);
        self.origin_imports
            .retain(|export, _| !self.chain.ledger.imports.contains_key(export));
        require(
            self.origin_imports.len() <= MAX_COINS,
            "complete origin pending import bound",
        )?;
        encode("paged-bft-native-ledger", &self.chain.ledger)?;
        #[cfg(test)]
        cost.mark(1);
        let active = Evidence {
            snapshots: self
                .evidence
                .snapshots
                .values()
                .map(|(s, _)| s.clone())
                .collect(),
        };
        #[cfg(not(test))]
        encode("evidence", &active)?;
        #[cfg(test)]
        {
            let encoded = encode("evidence", &active)?;
            cost.mark(2);
            cost.finish(encoded.len());
        }
        Ok(())
    }
    fn journal(&self, header: &Header) -> Journal {
        let mut snapshots = self
            .evidence
            .snapshots
            .values()
            .map(|(s, _)| s.clone())
            .collect::<Vec<_>>();
        snapshots.sort_by_key(|s| (s.statement.height, s.statement.region));
        Journal {
            bootstrap: header.bootstrap.clone(),
            region: header.region,
            evidence: Evidence { snapshots },
            events: vec![],
            event_prefix: vec![],
            incident_ids: self.incidents.clone(),
            epoch_proofs: vec![],
            contact_records: self.contacts.clone(),
        }
    }
}
fn private_root(dir: &Path) -> Result<()> {
    let mut options = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        options.mode(0o700);
    }
    options.create(dir).map_err(io)
}
fn read_header(dir: &Path) -> Result<Header> {
    safe_dir(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(dir).map_err(io)?;
        require(
            meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0,
            "paged BFT root ownership/private permissions",
        )?;
    }
    let raw = crate::keystore::private_read(&dir.join(HEADER), MAX_BYTES)?;
    let header: Header =
        serde_json::from_slice(&raw).map_err(|_| "invalid native paged store header")?;
    require(
        serde_json::to_vec(&header).map_err(|_| "native paged header encoding")? == *raw,
        "noncanonical native paged header",
    )?;
    Ok(header)
}
/// Count ALL root-side retained files (including proofs and residue), not just
/// ledger pages. Stream itself checks every complete page/orphan/publication.
fn outside_usage(dir: &Path) -> Result<(usize, u64)> {
    fn walk(path: &Path, count: &mut usize, total: &mut u64) -> Result<()> {
        for entry in fs::read_dir(path).map_err(io)? {
            let path = entry.map_err(io)?.path();
            let m = fs::symlink_metadata(&path).map_err(io)?;
            require(
                !m.file_type().is_symlink(),
                "unsafe paged BFT archive entry",
            )?;
            if m.is_dir() {
                walk(&path, count, total)?;
            } else {
                let raw = crate::keystore::private_read(&path, MAX_BYTES)?;
                *count = count.checked_add(1).ok_or("paged file count overflow")?;
                *total = total
                    .checked_add(raw.len() as u64)
                    .ok_or("paged file byte overflow")?;
            }
        }
        Ok(())
    }
    let mut count = 0;
    let mut total = 0;
    for entry in fs::read_dir(dir).map_err(io)? {
        let path = entry.map_err(io)?.path();
        if path.file_name().and_then(|n| n.to_str()) == Some(EVENTS) {
            continue;
        }
        let meta = fs::symlink_metadata(&path).map_err(io)?;
        require(
            !meta.file_type().is_symlink(),
            "unsafe paged BFT root entry",
        )?;
        if meta.is_dir() {
            walk(&path, &mut count, &mut total)?;
        } else {
            let raw = crate::keystore::private_read(&path, MAX_BYTES)?;
            count += 1;
            total = total
                .checked_add(raw.len() as u64)
                .ok_or("paged root byte overflow")?;
        }
    }
    require(
        count <= crate::history::MAX_FILES && total <= crate::history::MAX_ARCHIVE_BYTES,
        "paged BFT complete outside archive capacity",
    )?;
    Ok((count, total))
}
struct ColdImage {
    header: Header,
    replay: Replay,
    stream: Stream<Record>,
    conflicts: Vec<Incident>,
    safety: Safety,
}
// Caller holds the native or archive transaction lock; Stream owns its own lock.
// Full cold execution is required even for a previously inspected byte image.
fn load_image(dir: &Path, authority: &str, pin: Hash, head: Option<Hash>) -> Result<ColdImage> {
    require(
        read_guard(dir)?.is_zero(),
        "paged BFT pending incident requires explicit recovery",
    )?;
    let header = read_header(dir)?;
    let mut replay = Replay::new(&header, authority, pin)?;
    let scope = header.scope(&replay.trust)?;
    let expected = match head {
        Some(head) => head,
        None => Stream::<Record>::observe_head(&dir.join(EVENTS), &scope)?,
    };
    let stream = Stream::open(&dir.join(EVENTS), &scope, expected)?;
    stream.visit(expected, |record| replay.apply_retained(record, &stream))?;
    let journal = replay.journal(&header);
    let (conflicts, safety) = read_incidents(dir, &journal, &replay.trust, None)?;
    let retained = conflicts
        .iter()
        .map(|p| p.id())
        .collect::<Result<BTreeSet<_>>>()?;
    require(
        retained == journal.incident_ids,
        "paged BFT unindexed retained incidents refuse",
    )?;
    // Full stream capacity is checked on open; root-side files are counted
    // together here using private full reads, never pruned on a refusal.
    let (outside, bytes) = outside_usage(dir)?;
    let mut files = outside;
    let mut total = bytes;
    fn count_tree(dir: &Path, files: &mut usize, total: &mut u64) -> Result<()> {
        for e in fs::read_dir(dir).map_err(io)? {
            let p = e.map_err(io)?.path();
            if fs::symlink_metadata(&p).map_err(io)?.is_dir() {
                count_tree(&p, files, total)?;
            } else {
                let raw = crate::keystore::private_read(&p, MAX_BYTES)?;
                *files += 1;
                *total = total
                    .checked_add(raw.len() as u64)
                    .ok_or("paged archive overflow")?;
            }
        }
        Ok(())
    }
    count_tree(&dir.join(EVENTS), &mut files, &mut total)?;
    require(
        files <= crate::history::MAX_FILES && total <= crate::history::MAX_ARCHIVE_BYTES,
        "paged BFT complete archive capacity",
    )?;
    Ok(ColdImage {
        header,
        replay,
        stream,
        conflicts,
        safety,
    })
}
pub(super) fn verify_pinned_image(
    dir: &Path,
    authority: &str,
    pin: Hash,
    head: Hash,
) -> Result<Hash> {
    let image = load_image(dir, authority, pin, Some(head))?;
    Ok(image.replay.chain.region)
}
impl Store {
    pub(super) fn create_paged(
        dir: &Path,
        bootstrap: Bootstrap,
        region: Hash,
        authority: &str,
        pin: Hash,
    ) -> Result<Self> {
        safe_dir(dir.parent().ok_or("paged store parent missing")?)?;
        let header = Header {
            format: FORMAT.into(),
            bootstrap,
            region,
        };
        let replay = Replay::new(&header, authority, pin)?;
        private_root(dir)?;
        crate::keystore::private_create(&dir.join("LOCK"), b"")?;
        let lock = crate::bft::lock(dir)?;
        private_root(&dir.join("incidents"))?;
        crate::keystore::private_create(&dir.join("INCIDENT_GUARD"), &Hash::ZERO.0)?;
        crate::keystore::private_create(
            &dir.join(HEADER),
            &serde_json::to_vec(&header).map_err(|_| "paged header encoding")?,
        )?;
        let stream = Stream::create(&dir.join(EVENTS), header.scope(&replay.trust)?)?;
        Ok(Self {
            dir: dir.into(),
            _lock: lock,
            journal: replay.journal(&header),
            paged_replay: Some(CurrentReplay {
                header: header.clone(),
                replay: replay.clone(),
                head: stream.storage_head(),
            }),
            trust: replay.trust,
            evidence: replay.evidence,
            chain: replay.chain,
            safety: Safety::default(),
            conflicts: vec![],
            authority: authority.into(),
            pin,
            healthy: true,
            paged: Some(stream),
        })
    }
    pub(super) fn open_paged(
        dir: &Path,
        lock: File,
        authority: &str,
        pin: Hash,
        head: Option<Hash>,
    ) -> Result<Self> {
        let ColdImage {
            header,
            replay,
            stream,
            conflicts,
            safety,
        } = load_image(dir, authority, pin, head)?;
        let journal = replay.journal(&header);
        Ok(Self {
            dir: dir.into(),
            _lock: lock,
            journal,
            paged_replay: Some(CurrentReplay {
                header: header.clone(),
                replay: replay.clone(),
                head: stream.storage_head(),
            }),
            trust: replay.trust,
            evidence: replay.evidence,
            chain: replay.chain,
            safety,
            conflicts,
            authority: authority.into(),
            pin,
            healthy: true,
            paged: Some(stream),
        })
    }
    pub(super) fn require_paged_inspection_head(&self, head: Hash) -> Result<()> {
        let header = read_header(&self.dir)?;
        let stream = self.paged.as_ref().ok_or("cold paged store missing")?;
        stream.require_scope(&header.scope(&self.trust)?)?;
        stream.require_unchanged(head)
    }
    pub(super) fn append_paged(&mut self, records: &[Record]) -> Result<()> {
        require(
            self.healthy,
            "paged BFT store requires cold replay after persistence failure",
        )?;
        let header = read_header(&self.dir)?;
        require(
            !records.is_empty() && records.len() <= 16,
            "paged original complete append batch bound",
        )?;
        let stream = self.paged.as_ref().ok_or("not a native paged store")?;
        let head = stream.storage_head();
        let mut replay = self
            .paged_replay
            .as_ref()
            .ok_or("paged actual process replay missing")?
            .stage(self, &header, stream)?;
        for record in records {
            replay.apply(record, stream)?;
        }
        // During this bounded batch, the resolver may consult only the committed
        // prefix. Its newly authenticated bodies remain in the bounded process
        // witness; unpublished records cannot resolve historical identities.
        for record in records {
            replay.executed.advance(record)?;
        }
        let journal = replay.journal(&header);
        let (conflicts, safety) = read_incidents(&self.dir, &journal, &replay.trust, None)?;
        require(
            conflicts
                .iter()
                .map(|p| p.id())
                .collect::<Result<BTreeSet<_>>>()?
                == journal.incident_ids,
            "paged commit omits retained authenticated incident",
        )?;
        let (files, bytes) = outside_usage(&self.dir)?;
        let result = self
            .paged
            .as_mut()
            .ok_or("not a native paged store")?
            .append_accounted(records, head, files, bytes);
        if let Err(error) = result {
            self.healthy = false;
            return Err(error);
        }
        self.paged_replay = Some(CurrentReplay {
            header,
            replay: replay.clone(),
            head: self
                .paged
                .as_ref()
                .ok_or("paged committed stream missing")?
                .storage_head(),
        });
        self.journal = journal;
        self.trust = replay.trust;
        self.evidence = replay.evidence;
        self.chain = replay.chain;
        self.conflicts = conflicts;
        self.safety = safety;
        Ok(())
    }
    pub(super) fn add_paged_evidence(&mut self, evidence: Evidence) -> Result<()> {
        self.check_paged_evidence_conflicts(&evidence)?;
        self.append_paged(&[Record::Evidence(Box::new(evidence))])
    }
    fn check_paged_evidence_conflicts(&mut self, evidence: &Evidence) -> Result<()> {
        require(
            evidence.snapshots.len() <= MAX_SNAPSHOTS,
            "paged BFT incoming evidence count",
        )?;
        encode("evidence", evidence)?;
        self.check_paged_snapshot_conflicts(&evidence.snapshots)
    }
    fn check_paged_snapshot_conflicts(&mut self, snapshots: &[Snapshot]) -> Result<()> {
        let stream = self.paged.as_ref().ok_or("paged store missing")?;
        let mut incident = None;
        stream.visit(stream.storage_head(), |record| {
            let previous = record.snapshots()?;
            for new in snapshots {
                for old in &previous {
                    if old.statement.region == new.statement.region {
                        let proof = Conflict::from_snapshots(old, new)?;
                        if proof.verify(&self.trust).is_ok() {
                            incident = Some(proof);
                        }
                    }
                }
            }
            Ok(())
        })?;
        for (n, new) in snapshots.iter().enumerate() {
            for old in &snapshots[..n] {
                if old.statement.region == new.statement.region {
                    let proof = Conflict::from_snapshots(old, new)?;
                    if proof.verify(&self.trust).is_ok() {
                        incident = Some(proof);
                    }
                }
            }
        }
        if let Some(proof) = incident {
            let id = self.observe_conflict(proof)?;
            return Err(format!(
                "paged evidence conflict retained as {}; archive not installed",
                id.to_hex()
            ));
        }
        Ok(())
    }
    fn current_paged_replay(&self) -> Result<Replay> {
        require(
            self.healthy && read_guard(&self.dir)?.is_zero(),
            "paged current read requires healthy current Store without pending native incident",
        )?;
        let header = read_header(&self.dir)?;
        let stream = self.paged.as_ref().ok_or("paged current stream missing")?;
        let replay = self
            .paged_replay
            .as_ref()
            .ok_or("paged actual process replay missing")?
            .stage(self, &header, stream)?;
        let (retained, safety) = read_incidents(&self.dir, &self.journal, &replay.trust, None)?;
        require(
            retained
                .iter()
                .map(|p| p.id())
                .collect::<Result<BTreeSet<_>>>()?
                == replay.incidents
                && safety.regions == self.safety.regions
                && safety.channels == self.safety.channels,
            "paged current complete retained incident set/safety differs",
        )?;
        let outside = outside_usage(&self.dir)?;
        let usage = stream.retained_usage_candidate()?;
        require(
            outside
                .0
                .checked_add(usage.0)
                .is_some_and(|n| n <= crate::history::MAX_FILES)
                && outside
                    .1
                    .checked_add(usage.1)
                    .is_some_and(|n| n <= crate::history::MAX_ARCHIVE_BYTES),
            "paged current complete archive capacity",
        )?;
        Ok(replay)
    }
    pub(crate) fn add_paged_contact(
        &mut self,
        frame: crate::contact::Frame,
        evidence: &Evidence,
    ) -> Result<()> {
        let mut replay = self.current_paged_replay()?;
        self.check_paged_evidence_conflicts(evidence)?;
        let record = Record::Contact(Box::new(frame));
        let stream = self.paged.as_ref().ok_or("paged current stream missing")?;
        replay.apply(&record, stream)?;
        // Authenticate every complete later frame before exact retry suppression.
        // An exact retained retry neither grows the archive nor grants an import.
        if replay.contacts == self.journal.contact_records {
            self.current_paged_replay()?;
            return Ok(());
        }
        self.append_paged(&[record])
    }
    pub(super) fn commit_paged_journal(&mut self, journal: Journal) -> Result<()> {
        require(
            journal.bootstrap == self.journal.bootstrap
                && journal.region == self.chain.region
                && journal.evidence == self.journal.evidence
                && journal.event_prefix.is_empty()
                && journal.epoch_proofs.is_empty()
                && journal.contact_records == self.journal.contact_records,
            "paged BFT mutation requires complete typed native stream events",
        )?;
        let mut records = Vec::new();
        for event in journal.events {
            match event {
                Event::ChannelReceipt(receipt) => records.push(Record::Receipt(receipt)),
                _ => return Err("paged BFT refuses legacy block/epoch event mutation".into()),
            }
        }
        if journal.incident_ids != self.journal.incident_ids {
            records.push(Record::Incidents(journal.incident_ids));
        }
        require(
            !records.is_empty(),
            "paged BFT commit has no complete native event",
        )?;
        self.append_paged(&records)
    }
    pub(super) fn finalize_paged(&mut self, snapshot: Snapshot) -> Result<Hash> {
        let sid = snapshot.statement.id()?;
        let stream = self.paged.as_ref().ok_or("paged store missing")?;
        let mut incident = None;
        // Scan ALL original certified/evidence events, including evicted active
        // observations. Historical conflicting finality cannot hide in a page.
        stream.visit(stream.storage_head(), |record| {
            let snapshots = record.snapshots()?;
            for old in &snapshots {
                if old.statement.region == snapshot.statement.region {
                    let proof = Conflict::from_snapshots(old, &snapshot)?;
                    if proof.verify(&self.trust).is_ok() {
                        incident = Some(proof);
                    }
                }
            }
            Ok(())
        })?;
        if let Some(proof) = incident {
            let id = self.observe_conflict(proof)?;
            return Err(format!(
                "historical paged conflict retained as {}; no branch adopted",
                id.to_hex()
            ));
        }
        self.safety.check_region(self.chain.region)?;
        // Complete sequential replay also authenticates a historical exact retry
        // or certificate variant before preserving its complete original bytes.
        self.append_paged(&[Record::Certified(Box::new(snapshot))])?;
        Ok(sid)
    }
    pub(crate) fn paged_receipt_history(&self) -> Result<crate::channel_receipt::Replay> {
        // Only this invocation's actual committed Native replay can supply receipts.
        // The same complete current byte/projection/incident/capacity guards used
        // by contact preflight must succeed; cold opens still execute from genesis.
        Ok(self.current_paged_replay()?.receipts)
    }
    pub(crate) fn paged_history_at(&self, height: u64) -> Result<(Chain, VerifiedEvidence)> {
        let header = read_header(&self.dir)?;
        let mut replay = Replay::new(&header, &self.authority, self.pin)?;
        let mut selected = if height == 0 {
            Some((replay.chain.clone(), replay.evidence.clone()))
        } else {
            None
        };
        let stream = self.paged.as_ref().ok_or("not a native paged store")?;
        stream.visit(stream.storage_head(), |record| {
            replay.apply_retained(record, stream)?;
            if replay.chain.height() == height {
                selected = Some((replay.chain.clone(), replay.evidence.clone()));
            }
            Ok(())
        })?;
        selected.ok_or("paged BFT historical native height missing".into())
    }
}
pub(super) fn present(dir: &Path) -> bool {
    dir.join(HEADER).exists()
}
pub(super) fn events(
    stream: &Stream<Record>,
) -> Result<Box<dyn Iterator<Item = Result<Event>> + '_>> {
    let mut selected_height = 0;
    Ok(Box::new(stream.records(stream.storage_head())?.flat_map(
        move |record| {
            let events = (|| -> Result<Vec<Event>> {
                match record? {
                    Record::Certified(snapshot) if snapshot.statement.height > selected_height => {
                        selected_height = snapshot.statement.height;
                        Ok(vec![
                            Event::Block(Box::new(
                                snapshot
                                    .blocks
                                    .last()
                                    .ok_or("paged certified block missing")?
                                    .clone(),
                            )),
                            Event::Finalize(snapshot.statement.id()?),
                        ])
                    }
                    Record::Receipt(receipt) => Ok(vec![Event::ChannelReceipt(receipt)]),
                    _ => Ok(vec![]),
                }
            })();
            match events {
                Ok(events) => events.into_iter().map(Ok).collect::<Vec<_>>(),
                Err(e) => vec![Err(e)],
            }
        },
    )))
}

/// One native cursor from pinned genesis, shared by historical signer records.
/// Any look-ahead remains complete and is executed before state can be released.
pub(crate) struct Historical<'a> {
    replay: Replay,
    stream: &'a Stream<Record>,
    records: crate::retained_pages::Records<'a, Record>,
    pending: Option<Record>,
    last_requested: u64,
    scope: Scope,
    storage_head: Hash,
}
impl Historical<'_> {
    pub(crate) fn at(&mut self, height: u64) -> Result<(&Trust, &VerifiedEvidence, &Chain)> {
        require(
            height >= self.last_requested,
            "paged signing history cursor rollback",
        )?;
        self.last_requested = height;
        loop {
            let next = match self.pending.take() {
                Some(record) => Some(record),
                None => self.records.next().transpose()?,
            };
            let Some(record) = next else {
                break;
            };
            if matches!(&record, Record::Certified(s) if s.statement.height > height) {
                self.pending = Some(record);
                break;
            }
            self.replay.apply_retained(&record, self.stream)?;
        }
        require(
            self.replay.chain.height() == height,
            "paged historical signing prefix missing",
        )?;
        Ok((
            &self.replay.trust,
            &self.replay.evidence,
            &self.replay.chain,
        ))
    }
    pub(crate) fn at_with_executed_head(
        &mut self,
        height: u64,
    ) -> Result<(Hash, &Trust, &VerifiedEvidence, &Chain)> {
        self.at(height)?;
        Ok((
            self.replay.executed.observed_executed_head(),
            &self.replay.trust,
            &self.replay.evidence,
            &self.replay.chain,
        ))
    }
    pub(crate) fn finish(mut self, node: &Store) -> Result<()> {
        self.check_complete(node)
    }
    /// Complete native execution happens once per cursor. Every subsequent
    /// boundary rechecks exact retained bytes, header, selection and incidents.
    pub(crate) fn check_complete(&mut self, node: &Store) -> Result<()> {
        if let Some(record) = self.pending.take() {
            self.replay.apply_retained(&record, self.stream)?;
        }
        for record in self.records.by_ref() {
            self.replay.apply_retained(&record?, self.stream)?;
        }
        let stream = node
            .paged
            .as_ref()
            .ok_or("native historical stream missing")?;
        require(
            stream.storage_head() == self.storage_head,
            "native stream changed within signing invocation",
        )?;
        stream.require_scope(&self.scope)?;
        require(
            read_header(&node.dir)?.scope(&self.replay.trust)? == self.scope,
            "native immutable header changed within signing invocation",
        )?;
        stream.visit(self.storage_head, |_| Ok(()))?;
        self.last_requested = self.replay.chain.height();
        require(
            node.healthy && read_guard(&node.dir)?.is_zero(),
            "paged signing history cannot release state with pending native incident",
        )?;
        let (retained, safety) =
            read_incidents(&node.dir, &node.journal, &self.replay.trust, None)?;
        require(
            retained
                .iter()
                .map(|p| p.id())
                .collect::<Result<BTreeSet<_>>>()?
                == self.replay.incidents
                && safety.regions == node.safety.regions
                && safety.channels == node.safety.channels,
            "paged signing full retained incident set/safety differs",
        )?;
        require(
            self.replay.chain.height() == node.chain.height()
                && self.replay.chain.ledger == node.chain.ledger
                && self.replay.chain.finalized == node.chain.finalized
                && self.replay.chain.epoch == node.chain.epoch
                && self.replay.contacts == node.journal.contact_records
                && self.replay.incidents == node.journal.incident_ids,
            "complete historical cursor differs from native current selection",
        )
    }
}
impl Store {
    pub(crate) fn paged_signing_history(&self) -> Result<Historical<'_>> {
        require(
            self.healthy && read_guard(&self.dir)?.is_zero(),
            "paged signing requires healthy native Store without pending incident",
        )?;
        let header = read_header(&self.dir)?;
        let replay = Replay::new(&header, &self.authority, self.pin)?;
        let stream = self
            .paged
            .as_ref()
            .ok_or("paged signing history requires native stream")?;
        let scope = header.scope(&replay.trust)?;
        stream.require_scope(&scope)?;
        let storage_head = stream.storage_head();
        Ok(Historical {
            replay,
            stream,
            records: stream.records(storage_head)?,
            pending: None,
            last_requested: 0,
            scope,
            storage_head,
        })
    }
}

#[cfg(test)]
#[path = "paged_store/body_witness_tests.rs"]
mod body_witness_tests;

#[path = "paged_store/packed_inspection.rs"]
mod packed_inspection;
pub use packed_inspection::{
    inspect_lossless_packed_native_candidate, inspect_packed_native_candidate,
    PackedNativeBoundaryCandidate,
};

#[path = "paged_store/origin_history.rs"]
mod origin_history;
pub use origin_history::CompleteOriginHistory;

#[cfg(test)]
#[path = "paged_store/origin_history_tests.rs"]
mod origin_history_tests;

#[cfg(test)]
#[path = "paged_store/origin_custody_tests.rs"]
mod origin_custody_tests;

#[path = "paged_store/export_archive.rs"]
mod export_archive;
pub use export_archive::{
    inspect_export_archive_candidate, inspect_lossless_export_archive_candidate,
    ExportArchiveObservationCandidate, ExportArchiveQueryCandidate,
};

#[cfg(test)]
#[path = "paged_store/export_archive_tests.rs"]
mod export_archive_tests;

#[cfg(test)]
#[path = "paged_store/packed_inspection_tests.rs"]
mod packed_inspection_tests;

#[path = "paged_store/continuation.rs"]
mod continuation;
pub use continuation::{
    NativeContinuationCandidate, NativeContinuationPinsCandidate, NativePrefixPinsCandidate,
};

#[cfg(test)]
#[path = "paged_store/continuation_tests.rs"]
mod continuation_tests;

#[cfg(test)]
#[path = "paged_store/current_tests.rs"]
mod current_tests;
