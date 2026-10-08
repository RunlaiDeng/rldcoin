//! Full origin execution under a separate signed receiver profile.
//! No serialized Ledger, sender state, latest-state claim or proof truncation.
use super::*;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompleteOriginHistory {
    pub source: Hash,
    pub destination: Hash,
    pub export: Hash,
    pub snapshots: Vec<Snapshot>,
}
impl CompleteOriginHistory {
    pub(super) fn shape(&self, destination: Hash, trust: &Trust) -> Result<()> {
        require(
            trust.region(destination)?.rules == crate::paged_bft::ORIGIN_HISTORY_RULES
                && self.destination == destination
                && self.source != destination
                && trust.region(self.source)?.region == trust.currency.origin
                && trust.region(self.source)?.rules == crate::paged_bft::RULES
                && !self.snapshots.is_empty()
                && self.snapshots.len() <= MAX_COINS,
            "complete origin history requires explicit receiver profile/origin/route/bound",
        )?;
        encode("complete-origin-history-v1", self)?;
        for (index, snapshot) in self.snapshots.iter().enumerate() {
            require(
                snapshot.statement.region == self.source
                    && snapshot.statement.currency == trust.currency()?
                    && snapshot.statement.height == index as u64 + 1,
                "complete origin history exact genesis order/domain",
            )?;
            crate::paged_bft::shape(snapshot, trust)?;
        }
        Ok(())
    }
}

struct SourceHistory {
    scope: Scope,
    records: Vec<Record>,
}
impl body_witness::History for SourceHistory {
    fn require_scope(&self, scope: &Scope) -> Result<()> {
        require(
            self.scope == *scope,
            "complete origin history source scope differs",
        )
    }
    fn visit(&self, consumer: &mut dyn FnMut(&Record) -> Result<()>) -> Result<u64> {
        for record in &self.records {
            consumer(record)?;
        }
        Ok(self.records.len() as u64)
    }
}

#[cfg(test)]
pub(super) fn test_history(
    header: &Header,
    replay: &Replay,
    records: &[Record],
) -> impl body_witness::History {
    SourceHistory {
        scope: header.scope(&replay.trust).unwrap(),
        records: records.to_vec(),
    }
}

/// Private derived state: never serialized, deserialized or supplied by callers.
struct ExecutedOrigin {
    checkpoint: Hash,
    snapshot: Snapshot,
    ledger: Ledger,
}
fn execute(
    proof: &CompleteOriginHistory,
    destination: Hash,
    trust: &Trust,
) -> Result<ExecutedOrigin> {
    proof.shape(destination, trust)?;
    // Bootstrap comes from receiver-verified trust, never from arriving bytes.
    let header = Header {
        format: FORMAT.into(),
        bootstrap: Bootstrap {
            currency: trust.currency.clone(),
            admissions: trust.regions.values().cloned().collect(),
        },
        region: proof.source,
    };
    let mut source = Replay::new(&header, &trust.currency.authority, trust.currency()?)?;
    require(
        source.trust.binding == trust.binding,
        "complete origin trust binding differs",
    )?;
    let history = SourceHistory {
        scope: header.scope(&source.trust)?,
        records: proof
            .snapshots
            .iter()
            .cloned()
            .map(|s| Record::Certified(Box::new(s)))
            .collect(),
    };
    for record in &history.records {
        source.apply_retained(record, &history)?;
    }
    let checkpoint = source
        .chain
        .finalized
        .ok_or("complete origin has no finalized tail")?;
    let snapshot = source.evidence.snapshot(checkpoint)?.clone();
    require(
        source.chain.height() == proof.snapshots.len() as u64
            && snapshot.statement.height == source.chain.height(),
        "complete origin tail is not finalized",
    )?;
    let export = source
        .chain
        .ledger
        .exports
        .get(&proof.export)
        .ok_or("export absent from complete origin history")?;
    require(
        export.source == proof.source
            && export.destination == destination
            && export.id == proof.export
            && export.height <= source.chain.height(),
        "complete origin export route differs",
    )?;
    source.chain.ledger.audit()?;
    Ok(ExecutedOrigin {
        checkpoint,
        snapshot,
        ledger: source.chain.ledger,
    })
}

impl Replay {
    pub(super) fn apply_origin_history(
        &mut self,
        proof: &CompleteOriginHistory,
        stream: &dyn body_witness::History,
    ) -> Result<()> {
        let executed = execute(proof, self.chain.region, &self.trust)?;
        // Compare only already executed prior events. Future retained bytes may
        // not supply an overlap anchor or overwrite the selected source branch.
        let prior_count = self.executed.count();
        let mut index = 0u64;
        stream.visit(&mut |record| {
            if index < prior_count {
                for old in record.snapshots()? {
                    if old.statement.region == proof.source
                        && old.statement.height > 0
                        && old.statement.height <= proof.snapshots.len() as u64
                    {
                        let incoming = &proof.snapshots[(old.statement.height - 1) as usize];
                        require(
                            old.statement == incoming.statement
                                && old.blocks == incoming.blocks
                                && old.epochs == incoming.epochs,
                            "complete origin history differs from executed retained source branch",
                        )?;
                    }
                }
            }
            index = index
                .checked_add(1)
                .ok_or("complete origin retained count overflow")?;
            Ok(())
        })?;
        if let Some((old, ledger)) = self.evidence.snapshots.get(&executed.checkpoint) {
            require(
                old.statement == executed.snapshot.statement
                    && old.blocks == executed.snapshot.blocks
                    && old.epochs == executed.snapshot.epochs
                    && *ledger == executed.ledger,
                "complete origin duplicate differs from fully executed state",
            )?;
        } else {
            self.retain_for_next()?;
            self.evidence
                .snapshots
                .insert(executed.checkpoint, (executed.snapshot, executed.ledger));
        }
        if !self.chain.ledger.imports.contains_key(&proof.export) {
            // Preserve an existing pending checkpoint. It already proves the
            // same immutable export and remains an active dependency anchor.
            self.origin_imports
                .entry(proof.export)
                .or_insert((proof.source, executed.checkpoint));
        }
        // Evidence never selects local finality, applies Import or creates money.
        Ok(())
    }
}

impl Store {
    /// Pending tasks derived from full Native events, with no automatic credit.
    pub fn complete_origin_pending_imports(&self) -> Result<Vec<Command>> {
        if self.trust.region(self.chain.region)?.rules != crate::paged_bft::ORIGIN_HISTORY_RULES {
            return Ok(vec![]);
        }
        let replay = self.current_paged_replay()?;
        let mut commands = Vec::new();
        for (export, (source, checkpoint)) in &replay.origin_imports {
            self.safety.check_region(*source)?;
            // No queue entry can act as a substitute for retained derived state.
            let record = replay.evidence.export(*checkpoint, *export)?;
            require(
                record.source == *source && record.destination == self.chain.region,
                "complete origin pending export route differs",
            )?;
            commands.push(Command::Import {
                snapshot: *checkpoint,
                export: *export,
            });
        }
        encode("complete-origin-pending-imports", &commands)?;
        Ok(commands)
    }
    /// Complete evidence only; original local Import/finality/maturity still needed.
    pub fn accept_complete_origin_history(&mut self, proof: CompleteOriginHistory) -> Result<Hash> {
        proof.shape(self.chain.region, &self.trust)?;
        self.current_paged_replay()?;
        self.check_paged_snapshot_conflicts(&proof.snapshots)?;
        self.safety.check_region(proof.source)?;
        let last = proof
            .snapshots
            .last()
            .ok_or("complete origin tail absent")?
            .statement
            .id()?;
        // Equality only against a record already fully executed by the current
        // native replay. Tail identity alone cannot deduplicate arriving bodies.
        let mut identical = false;
        let stream = self
            .paged
            .as_ref()
            .ok_or("complete origin native stream missing")?;
        stream.visit(stream.storage_head(), |record| {
            if let Record::OriginHistory(old) = record {
                identical |= old.as_ref() == &proof;
            }
            Ok(())
        })?;
        if identical {
            return Ok(last);
        }
        self.append_paged(&[Record::OriginHistory(Box::new(proof))])?;
        Ok(last)
    }
}
