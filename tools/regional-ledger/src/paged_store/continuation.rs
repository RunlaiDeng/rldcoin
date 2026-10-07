//! Explicit fresh continuation of a complete immutable Native prefix.
//! This entry has no ordinary Store, incident-proof or signer adoption rights.
use super::body_witness::History;
use super::*;
use crate::retained_pages::packed::archive::PackedArchiveCandidate;

/// Caller-retained prefix anchors, not a serialized Native initializer.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct NativePrefixPinsCandidate {
    pub storage_head: Hash,
    pub manifest: crate::history::Reference,
    pub latest: PackedNativeBoundaryCandidate,
}
/// All current anchors must be retained by the caller independently of the
/// supplied storage. No Deserialize or cached ledger is provided.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct NativeContinuationPinsCandidate {
    pub prefix: NativePrefixPinsCandidate,
    pub tail_head: Hash,
    pub complete_head: Hash,
    pub latest: PackedNativeBoundaryCandidate,
}

struct Source<'a> {
    prefix: &'a PackedArchiveCandidate<Record>,
    tail: &'a Stream<Record>,
    scope: &'a Scope,
    pins: &'a NativeContinuationPinsCandidate,
}
impl body_witness::History for Source<'_> {
    fn require_scope(&self, scope: &Scope) -> Result<()> {
        require(
            *scope == *self.scope,
            "continuation Native consumer scope differs",
        )?;
        self.prefix.require_scope(scope)
    }
    fn visit(&self, consumer: &mut dyn FnMut(&Record) -> Result<()>) -> Result<u64> {
        let mut count = 0u64;
        let mut head = self.scope.initial()?;
        let mut consume = |record: &Record| {
            consumer(record)?;
            head = crate::retained_pages::next_head(head, count, record)?;
            count = count
                .checked_add(1)
                .ok_or("continuation record count overflow")?;
            Ok(())
        };
        let prefix_count = self
            .prefix
            .visit(self.pins.prefix.storage_head, &mut consume)?;
        require(
            prefix_count == self.pins.prefix.latest.record_count,
            "continuation complete prefix count differs",
        )?;
        self.tail.visit(self.pins.tail_head, &mut consume)?;
        require(
            head == self.pins.complete_head,
            "continuation complete current head differs",
        )?;
        Ok(count)
    }
}
fn boundary(replay: &Replay, count: u64) -> Result<PackedNativeBoundaryCandidate> {
    Ok(PackedNativeBoundaryCandidate {
        currency: replay.trust.currency()?,
        region: replay.chain.region,
        height: replay.chain.height(),
        finalized: replay.chain.finalized,
        epoch: replay.chain.epoch,
        ledger_root: replay.chain.ledger.root()?,
        record_count: count,
    })
}
fn record_guard(record: &Record) -> Result<()> {
    if let Record::Incidents(ids) = record {
        require(
            ids.is_empty(),
            "continuation needs complete separate incident proof store",
        )?;
    }
    Ok(())
}
fn capacity(prefix: (usize, u64), tail: (usize, u64)) -> Result<()> {
    require(
        prefix
            .0
            .checked_add(tail.0)
            .is_some_and(|n| n <= crate::history::MAX_FILES)
            && prefix
                .1
                .checked_add(tail.1)
                .is_some_and(|n| n <= crate::history::MAX_ARCHIVE_BYTES),
        "continuation aggregate retained capacity",
    )
}
fn tail_scope(header: &Header, trust: &Trust, prefix: &NativePrefixPinsCandidate) -> Result<Scope> {
    Scope::bind(
        trust,
        header.region,
        Purpose::Ledger,
        id(
            "native-lossless-prefix-continuation-origin-v1",
            &(header.scope(trust)?, prefix),
        )?,
    )
}

/// Locked no-value candidate persistence, preserving every prefix and tail
/// record. Open and inspection reconstruct Native state from signed genesis. Live
/// appends stage only this process's actually executed Native state; no
/// deserialized cache, wallet, signature lock or normal node adopts it implicitly.
pub struct NativeContinuationCandidate {
    header: Header,
    authority: String,
    pin: Hash,
    prefix: PackedArchiveCandidate<Record>,
    prefix_pins: NativePrefixPinsCandidate,
    tail: Stream<Record>,
    scope: Scope,
    healthy: bool,
    warm: Replay,
    current: NativeContinuationPinsCandidate,
}
impl NativeContinuationCandidate {
    /// Fresh empty prefix only, derived from independently authenticated Native
    /// genesis before any writes. No existing history, balance or key migrates.
    pub fn create_genesis_prefix(
        dir: &Path,
        bootstrap: &Bootstrap,
        authority: &str,
        pin: Hash,
        region: Hash,
    ) -> Result<NativePrefixPinsCandidate> {
        let header = Header {
            format: FORMAT.into(),
            bootstrap: bootstrap.clone(),
            region,
        };
        let replay = Replay::new(&header, authority, pin)?;
        let scope = header.scope(&replay.trust)?;
        let storage_head = scope.initial()?;
        let latest = boundary(&replay, 0)?;
        let prefix = PackedArchiveCandidate::<Record>::seal_lossless_candidate(
            dir,
            scope,
            storage_head,
            std::iter::empty::<Result<Vec<u8>>>(),
        )?;
        Ok(NativePrefixPinsCandidate {
            storage_head,
            manifest: prefix.manifest_reference_candidate()?,
            latest,
        })
    }
    fn prefix(
        dir: &Path,
        bootstrap: &Bootstrap,
        authority: &str,
        pin: Hash,
        pins: &NativePrefixPinsCandidate,
    ) -> Result<(Header, Replay, Scope, PackedArchiveCandidate<Record>)> {
        require(
            pins.latest.currency == pin,
            "continuation independent prefix currency",
        )?;
        let header = Header {
            format: FORMAT.into(),
            bootstrap: bootstrap.clone(),
            region: pins.latest.region,
        };
        let mut replay = Replay::new(&header, authority, pin)?;
        let scope = header.scope(&replay.trust)?;
        let archive = PackedArchiveCandidate::<Record>::open_lossless_candidate(
            dir,
            &scope,
            pins.storage_head,
            &pins.manifest,
        )?;
        let source = packed_inspection::PackedHistory {
            archive: &archive,
            scope: scope.clone(),
            current_head: pins.storage_head,
        };
        let count = archive.visit(pins.storage_head, |record| {
            record_guard(record)?;
            replay.apply_retained(record, &source)
        })?;
        require(
            boundary(&replay, count)? == pins.latest,
            "continuation independent Native prefix differs",
        )?;
        Ok((header, replay, scope, archive))
    }
    /// A new empty tail only. An existing or interrupted target never resumes.
    pub fn create(
        prefix_dir: &Path,
        tail_dir: &Path,
        bootstrap: &Bootstrap,
        authority: &str,
        pin: Hash,
        prefix_pins: &NativePrefixPinsCandidate,
    ) -> Result<(Self, NativeContinuationPinsCandidate)> {
        // Reject a target inside the immutable prefix before any creation.
        let parent = fs::canonicalize(
            tail_dir
                .parent()
                .ok_or("continuation tail parent missing")?,
        )
        .map_err(|_| "continuation tail parent unavailable")?;
        let prefix_path =
            fs::canonicalize(prefix_dir).map_err(|_| "continuation prefix unavailable")?;
        require(
            !parent.starts_with(prefix_path),
            "continuation tail cannot alter immutable prefix",
        )?;
        let (header, replay, scope, prefix) =
            Self::prefix(prefix_dir, bootstrap, authority, pin, prefix_pins)?;
        let tail_scope = tail_scope(&header, &replay.trust, prefix_pins)?;
        capacity(
            prefix.retained_usage_candidate()?,
            Stream::<Record>::initial_usage_candidate(&tail_scope)?,
        )?;
        let tail = Stream::create(tail_dir, tail_scope)?;
        let pins = NativeContinuationPinsCandidate {
            prefix: prefix_pins.clone(),
            tail_head: tail.storage_head(),
            complete_head: prefix_pins.storage_head,
            latest: prefix_pins.latest.clone(),
        };
        Ok((
            Self {
                header,
                authority: authority.into(),
                pin,
                prefix,
                prefix_pins: prefix_pins.clone(),
                tail,
                scope,
                healthy: true,
                warm: replay,
                current: pins.clone(),
            },
            pins,
        ))
    }
    pub fn open(
        prefix_dir: &Path,
        tail_dir: &Path,
        bootstrap: &Bootstrap,
        authority: &str,
        pin: Hash,
        pins: &NativeContinuationPinsCandidate,
    ) -> Result<Self> {
        let (header, replay, scope, prefix) =
            Self::prefix(prefix_dir, bootstrap, authority, pin, &pins.prefix)?;
        let tail = Stream::open(
            tail_dir,
            &tail_scope(&header, &replay.trust, &pins.prefix)?,
            pins.tail_head,
        )?;
        let mut result = Self {
            header,
            authority: authority.into(),
            pin,
            prefix,
            prefix_pins: pins.prefix.clone(),
            tail,
            scope,
            healthy: true,
            warm: replay,
            current: pins.clone(),
        };
        result.warm = result.replay(pins)?;
        Ok(result)
    }
    fn replay(&self, pins: &NativeContinuationPinsCandidate) -> Result<Replay> {
        require(
            self.healthy && pins.prefix == self.prefix_pins,
            "continuation unhealthy or independent prefix differs",
        )?;
        capacity(
            self.prefix.retained_usage_candidate()?,
            self.tail.retained_usage_candidate()?,
        )?;
        self.tail.require_scope(&tail_scope(
            &self.header,
            &Trust::verify(&self.header.bootstrap, &self.authority, self.pin)?,
            &pins.prefix,
        )?)?;
        let source = Source {
            prefix: &self.prefix,
            tail: &self.tail,
            scope: &self.scope,
            pins,
        };
        let mut replay = Replay::new(&self.header, &self.authority, self.pin)?;
        let mut count = 0u64;
        if pins.prefix.latest.record_count == 0 {
            require(
                boundary(&replay, 0)? == pins.prefix.latest,
                "continuation executed Native genesis prefix differs",
            )?;
        }
        source.visit(&mut |record| {
            record_guard(record)?;
            replay.apply_retained(record, &source)?;
            count += 1;
            if count == pins.prefix.latest.record_count {
                require(
                    boundary(&replay, count)? == pins.prefix.latest,
                    "continuation executed Native prefix differs",
                )?;
            }
            Ok(())
        })?;
        require(
            boundary(&replay, count)? == pins.latest,
            "continuation complete latest Native boundary differs",
        )?;
        Ok(replay)
    }
    fn require_current(
        &self,
        independently_current: &NativeContinuationPinsCandidate,
    ) -> Result<()> {
        require(
            self.healthy && *independently_current == self.current,
            "continuation unhealthy or independently current process boundary differs",
        )?;
        self.prefix.require_unchanged_candidate(
            &self.scope,
            self.prefix_pins.storage_head,
            &self.prefix_pins.manifest,
        )?;
        self.tail
            .require_unchanged(independently_current.tail_head)?;
        capacity(
            self.prefix.retained_usage_candidate()?,
            self.tail.retained_usage_candidate()?,
        )?;
        require(
            boundary(&self.warm, self.current.latest.record_count)? == self.current.latest,
            "continuation actual process Native state differs",
        )?;
        Ok(())
    }
    fn context(&self) -> Result<crate::bft::Context> {
        let chain = &self.warm.chain;
        Ok(crate::bft::Context {
            currency: self.warm.trust.currency()?,
            region: chain.region,
            epoch: chain.epoch,
            previous: chain.finalized,
            parent_height: chain.height(),
            parent_block: chain.tip()?,
            parent_state: chain.ledger.root()?,
        })
    }
    /// Unsigned template only; no balance, signature lock or record changes.
    /// Owner authorization and exact native execution precede its return.
    pub fn template(
        &self,
        commands: Vec<Command>,
        miner: String,
        independently_current: &NativeContinuationPinsCandidate,
    ) -> Result<(crate::bft::Context, Block)> {
        self.require_current(independently_current)?;
        encode("commands", &commands)?;
        let context = self.context()?;
        let mut chain = self.warm.chain.clone();
        crate::paged_bft::prepare_parent(&mut chain, &self.warm.evidence)?;
        let block = chain.template(commands, miner, &self.warm.trust, &self.warm.evidence)?;
        encode("block", &block)?;
        Ok((context, block))
    }
    /// Public ledger coins at this exact Native boundary, including explicit
    /// maturity. Private wallet reservations are not part of this projection.
    pub fn coins(
        &self,
        owner: &str,
        independently_current: &NativeContinuationPinsCandidate,
    ) -> Result<Vec<(Hash, Coin)>> {
        self.require_current(independently_current)?;
        validate_ed25519_public_key(owner)?;
        let coins = self
            .warm
            .chain
            .ledger
            .coins
            .iter()
            .filter(|(_, coin)| coin.payment.owner == owner)
            .map(|(id, coin)| (*id, coin.clone()))
            .collect::<Vec<_>>();
        encode("continuation-public-coins", &coins)?;
        Ok(coins)
    }
    /// Build complete original Native evidence only after actual block work,
    /// commands, current parent and all configured prepare/commit votes verify.
    /// Construction itself neither publishes the block nor authorizes signing.
    pub fn snapshot_for_certificate(
        &self,
        block: &Block,
        certificate: &crate::bft::Certificate,
        independently_current: &NativeContinuationPinsCandidate,
    ) -> Result<Snapshot> {
        self.require_current(independently_current)?;
        encode("block", block)?;
        encode("bft-certificate", certificate)?;
        let context = self.context()?;
        let mut chain = self.warm.chain.clone();
        crate::paged_bft::prepare_parent(&mut chain, &self.warm.evidence)?;
        chain.accept(block.clone(), &self.warm.trust, &self.warm.evidence)?;
        let snapshot = Snapshot {
            base: chain.snapshot_base(),
            bft: Some(certificate.clone()),
            statement: chain.statement(&self.warm.trust)?,
            blocks: chain.blocks,
            epochs: vec![],
            approvals: vec![],
        };
        encode("snapshot", &snapshot)?;
        certificate.verify(
            &context,
            snapshot.statement.id()?,
            &context.keys(&self.warm.trust, &self.warm.evidence)?,
        )?;
        let source = Source {
            prefix: &self.prefix,
            tail: &self.tail,
            scope: &self.scope,
            pins: independently_current,
        };
        let mut staged = self.warm.clone();
        staged.apply_retained(&Record::Certified(Box::new(snapshot.clone())), &source)?;
        Ok(snapshot)
    }
    /// Return only after full Native authentication and durable complete tail
    /// publication. Caller stores these resulting anchors independently.
    pub fn append_certified(
        &mut self,
        snapshot: &Snapshot,
        independently_current: &NativeContinuationPinsCandidate,
    ) -> Result<NativeContinuationPinsCandidate> {
        self.require_current(independently_current)?;
        let mut replay = self.warm.clone();
        let record = Record::Certified(Box::new(snapshot.clone()));
        require(
            serde_json::to_vec(&record)
                .map_err(|_| "continuation record encoding")?
                .len()
                <= MAX_BYTES,
            "continuation complete record byte capacity",
        )?;
        let source = Source {
            prefix: &self.prefix,
            tail: &self.tail,
            scope: &self.scope,
            pins: independently_current,
        };
        replay.apply_retained(&record, &source)?;
        let count = independently_current
            .latest
            .record_count
            .checked_add(1)
            .ok_or("continuation record count overflow")?;
        let complete_head = crate::retained_pages::next_head(
            independently_current.complete_head,
            count - 1,
            &record,
        )?;
        let latest = boundary(&replay, count)?;
        let (files, bytes) = self.prefix.retained_usage_candidate()?;
        let tail_head = match self.tail.append_accounted(
            &[record],
            independently_current.tail_head,
            files,
            bytes,
        ) {
            Ok(head) => head,
            Err(error) => {
                self.healthy = false;
                return Err(error);
            }
        };
        let result = NativeContinuationPinsCandidate {
            prefix: self.prefix_pins.clone(),
            tail_head,
            complete_head,
            latest,
        };
        self.warm = replay;
        self.current = result.clone();
        Ok(result)
    }
    pub fn inspect(
        &self,
        independently_current: &NativeContinuationPinsCandidate,
    ) -> Result<PackedNativeBoundaryCandidate> {
        let replay = self.replay(independently_current)?;
        boundary(&replay, independently_current.latest.record_count)
    }
    #[cfg(test)]
    pub(super) fn interrupt_at(&mut self, boundary: u8) {
        self.tail.interrupt_at(boundary);
    }
}
