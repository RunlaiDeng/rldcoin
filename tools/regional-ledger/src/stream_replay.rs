//! Replay-only bounded history cursor. State is derived from signed genesis and
//! every native block; no serialized ledger, hash or sender snapshot is a base.
//! Ordinary stores, snapshot bounds, BFT, signers and wallets are not upgraded.
use super::*;
use std::collections::VecDeque;

pub const FORMAT: &str = "RLD-NATIVE-STREAM-REPLAY-V1";
pub const MAX_ARCHIVE_BYTES: u64 = history::MAX_ARCHIVE_BYTES;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub height: u64,
    pub tip: Hash,
    pub history: Hash,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Head {
    pub format: String,
    pub currency: Hash,
    pub region: Hash,
    pub observation: Observation,
    pub state: Hash,
    pub finalized: Option<Hash>,
    pub epoch: Hash,
}
impl Head {
    pub fn id(&self) -> Result<Hash> {
        id("native-stream-replay-head-v1", self)
    }
}
pub struct Cursor {
    currency: Hash,
    binding: Hash,
    region: Hash,
    current: Observation,
    ledger: Ledger,
    finalized: Option<Hash>,
    epoch: Hash,
    recent: VecDeque<Observation>,
    anchors: BTreeMap<Hash, (u64, Option<Hash>)>,
}
fn genesis_history(currency: Hash, region: Hash) -> Result<Hash> {
    id("native-stream-genesis-v1", &(currency, region))
}
fn link(previous: Hash, height: u64, block: Hash) -> Result<Hash> {
    id("native-stream-history-v1", &(previous, height, block))
}
fn snapshot_history(snapshot: &Snapshot) -> Result<Hash> {
    let mut hash = genesis_history(snapshot.statement.currency, snapshot.statement.region)?;
    for block in &snapshot.blocks {
        hash = link(hash, block.header.height, block.header.id()?)?;
    }
    Ok(hash)
}
impl Cursor {
    pub fn new(region: Hash, trust: &Trust) -> Result<Self> {
        require(
            trust.region(region)?.rules == DOMAIN,
            "stream replay requires explicit initial unanimous PoW region; BFT is not downgraded",
        )?;
        let currency = trust.currency()?;
        let current = Observation {
            height: 0,
            tip: region,
            history: genesis_history(currency, region)?,
        };
        Ok(Self {
            currency,
            binding: trust.binding,
            region,
            current: current.clone(),
            ledger: Ledger::default(),
            finalized: None,
            epoch: epoch::Registry::initial(trust, region)?,
            recent: VecDeque::from([current]),
            anchors: BTreeMap::new(),
        })
    }
    fn context(&self, trust: &Trust, evidence: &VerifiedEvidence) -> Result<()> {
        require(
            trust.binding == self.binding && trust.currency()? == self.currency,
            "stream replay trust binding differs",
        )?;
        evidence.check_trust(trust)?;
        require(
            evidence.epoch_state(trust, self.region)?.0 == self.epoch,
            "stream replay does not implement local epoch handoff",
        )
    }
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }
    pub fn head(&self) -> Result<Head> {
        Ok(Head {
            format: FORMAT.into(),
            currency: self.currency,
            region: self.region,
            observation: self.current.clone(),
            state: self.ledger.root()?,
            finalized: self.finalized,
            epoch: self.epoch,
        })
    }
    pub fn retained_observations(&self) -> usize {
        self.recent.len()
    }
    /// Bounded historic certificates still require complete native verification.
    /// Record their exact prefix only while the observed position is retained.
    pub fn observe_evidence(&mut self, trust: &Trust, evidence: &VerifiedEvidence) -> Result<()> {
        self.context(trust, evidence)?;
        let mut anchors = self.anchors.clone();
        for (sid, (snapshot, _)) in &evidence.snapshots {
            if snapshot.statement.region != self.region || anchors.contains_key(sid) {
                continue;
            }
            if let Some(point) = self
                .recent
                .iter()
                .find(|p| p.height == snapshot.statement.height)
            {
                require(
                    snapshot.statement.epoch == self.epoch
                        && point.tip == snapshot.statement.block
                        && point.history == snapshot_history(snapshot)?,
                    "stream checkpoint differs from exact replayed history",
                )?;
                require(
                    anchors.len() < MAX_SNAPSHOTS,
                    "stream verified anchor bound",
                )?;
                anchors.insert(
                    *sid,
                    (snapshot.statement.height, snapshot.statement.previous),
                );
            }
        }
        self.anchors = anchors;
        Ok(())
    }
    fn check_anchor(&self, sid: Hash) -> Result<()> {
        let (height, previous) = self
            .anchors
            .get(&sid)
            .ok_or("stream anchor was not observed on exact native history")?;
        require(
            *height <= self.current.height && *previous == self.finalized,
            "stream anchor predecessor or height",
        )
    }
    pub fn install(&mut self, sid: Hash, trust: &Trust, evidence: &VerifiedEvidence) -> Result<()> {
        self.context(trust, evidence)?;
        evidence.snapshot(sid)?;
        self.check_anchor(sid)?;
        self.finalized = Some(sid);
        Ok(())
    }
    /// Fixture construction only; not an ordinary-node template or signer API.
    pub fn template(
        &self,
        commands: Vec<Command>,
        miner: String,
        trust: &Trust,
        evidence: &VerifiedEvidence,
    ) -> Result<Block> {
        self.context(trust, evidence)?;
        let state = execution::Execution {
            region: self.region,
            height: self.current.height,
            tip: self.current.tip,
            ledger: &self.ledger,
        }
        .execute(&commands, &miner, trust, evidence, true, self.finalized)?;
        Ok(Block {
            header: Header {
                currency: self.currency,
                region: self.region,
                parent: self.current.tip,
                anchor: self.finalized,
                height: self
                    .current
                    .height
                    .checked_add(1)
                    .ok_or("stream height overflow")?,
                miner,
                commands: id("commands", &commands)?,
                state: state.root()?,
                nonce: 0,
            },
            commands,
        })
    }
    pub fn accept(
        &mut self,
        block: &Block,
        trust: &Trust,
        evidence: &VerifiedEvidence,
    ) -> Result<()> {
        self.context(trust, evidence)?;
        encode("block", block)?;
        let height = self
            .current
            .height
            .checked_add(1)
            .ok_or("stream height overflow")?;
        let finalized = if block.header.anchor != self.finalized {
            let sid = block.header.anchor.ok_or("stream checkpoint rollback")?;
            self.check_anchor(sid)?;
            Some(sid)
        } else {
            self.finalized
        };
        require(
            block.header.currency == self.currency
                && block.header.region == self.region
                && block.header.parent == self.current.tip
                && block.header.height == height
                && block.header.commands == id("commands", &block.commands)?
                && block.header.work_valid()?,
            "invalid streamed block identity, order, commitment or work",
        )?;
        let ledger = execution::Execution {
            region: self.region,
            height: self.current.height,
            tip: self.current.tip,
            ledger: &self.ledger,
        }
        .execute(
            &block.commands,
            &block.header.miner,
            trust,
            evidence,
            true,
            finalized,
        )?;
        require(
            ledger.root()? == block.header.state,
            "streamed native state root mismatch",
        )?;
        let tip = block.header.id()?;
        let observation = Observation {
            height,
            tip,
            history: link(self.current.history, height, tip)?,
        };
        // Stage checkpoint observations before changing any root, value or anchor.
        let mut anchors = self.anchors.clone();
        for (sid, (snapshot, _)) in &evidence.snapshots {
            if snapshot.statement.region == self.region
                && snapshot.statement.height == height
                && !anchors.contains_key(sid)
            {
                require(
                    snapshot.statement.epoch == self.epoch
                        && snapshot.statement.block == tip
                        && snapshot.statement.state == block.header.state
                        && snapshot_history(snapshot)? == observation.history,
                    "stream checkpoint differs from exact replayed history",
                )?;
                require(
                    anchors.len() < MAX_SNAPSHOTS,
                    "stream verified anchor bound",
                )?;
                anchors.insert(*sid, (height, snapshot.statement.previous));
            }
        }
        self.ledger = ledger;
        self.finalized = finalized;
        self.current = observation.clone();
        self.anchors = anchors;
        if self.recent.len() == MAX_BLOCKS {
            self.recent.pop_front();
        }
        self.recent.push_back(observation);
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Record {
    Evidence { evidence: Evidence },
    Block { block: Box<Block> },
    Finalize { checkpoint: Hash },
}
/// Read-only complete replay of a bounded private archive, from pinned genesis.
/// Evidence records replace the complete bounded proof set; they never import
/// a ledger or confer new local epoch/BFT authority. No store is adopted.
pub fn check_archive(
    path: &std::path::Path,
    bootstrap: &Bootstrap,
    authority: &str,
    currency: Hash,
    region: &str,
    expected_head: Hash,
) -> Result<Head> {
    let trust = Trust::verify(bootstrap, authority, currency)?;
    check_archive_records(path, &trust, region, expected_head, |line| {
        serde_json::from_slice(line)
            .map(Some)
            .map_err(|e| e.to_string())
    })
}

/// Shared bounded file reader and complete native execution. A codec can return
/// no record for its authenticated format binding only; it cannot supply state.
pub(crate) fn check_archive_records(
    path: &std::path::Path,
    trust: &Trust,
    region: &str,
    expected_head: Hash,
    mut decode: impl FnMut(&[u8]) -> Result<Option<Record>>,
) -> Result<Head> {
    use std::io::{BufRead, BufReader};
    let meta = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    require(
        meta.is_file() && !meta.file_type().is_symlink() && meta.len() <= MAX_ARCHIVE_BYTES,
        "unsafe or oversized stream archive",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        require(
            meta.nlink() == 1 && meta.mode() & 0o077 == 0,
            "stream archive must be private and singly linked",
        )?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // A replacement symlink or FIFO must not bypass the metadata check or
        // make this bounded read-only verifier wait inside open indefinitely.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|e| e.to_string())?;
    let opened = file.metadata().map_err(|e| e.to_string())?;
    require(
        opened.is_file(),
        "opened stream archive is not a regular file",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        require(
            meta.ino() == opened.ino() && meta.dev() == opened.dev(),
            "stream archive changed during open",
        )?;
        require(
            opened.nlink() == 1 && opened.mode() & 0o077 == 0,
            "opened stream archive is not private and singly linked",
        )?;
    }
    let mut cursor = Cursor::new(trust.named(region)?, trust)?;
    let mut evidence = VerifiedEvidence::default();
    let mut reader = BufReader::new(file);
    let mut total = 0u64;
    loop {
        let mut line = vec![];
        // take caps allocation before parsing even a malformed unbroken line.
        use std::io::Read;
        let n = reader
            .by_ref()
            .take((MAX_BYTES + 1) as u64)
            .read_until(b'\n', &mut line)
            .map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(n as u64)
            .ok_or("stream archive length overflow")?;
        require(
            n <= MAX_BYTES && total <= MAX_ARCHIVE_BYTES && line.ends_with(b"\n"),
            "stream record or archive bound/truncated record",
        )?;
        let Some(record) = decode(&line)? else {
            continue;
        };
        match record {
            Record::Evidence { evidence: raw } => {
                let verified = VerifiedEvidence::verify(&raw, trust)?;
                cursor.observe_evidence(trust, &verified)?;
                evidence = verified;
            }
            Record::Block { block } => cursor.accept(&block, trust, &evidence)?,
            Record::Finalize { checkpoint } => cursor.install(checkpoint, trust, &evidence)?,
        }
    }
    let after = reader.get_ref().metadata().map_err(|e| e.to_string())?;
    require(
        total == meta.len()
            && after.len() == meta.len()
            && after.modified().ok() == meta.modified().ok(),
        "stream archive changed during replay",
    )?;
    let head = cursor.head()?;
    require(
        head.id()? == expected_head,
        "stream replay differs from separately retained exact head",
    )?;
    Ok(head)
}
