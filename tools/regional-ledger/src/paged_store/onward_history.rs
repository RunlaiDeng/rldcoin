//! Complete two-hop evidence under an explicit new receiver admission.
//! Every derived ledger comes from Native genesis replay, never from input state.
use super::*;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompleteOnwardHistory {
    pub source: Hash,
    pub destination: Hash,
    pub export: Hash,
    pub origin: CompleteOriginHistory,
    pub snapshots: Vec<Snapshot>,
}

impl CompleteOnwardHistory {
    fn bound(&self) -> Result<()> {
        require(
            !self.origin.snapshots.is_empty()
                && !self.snapshots.is_empty()
                && self
                    .origin
                    .snapshots
                    .len()
                    .checked_add(self.snapshots.len())
                    .is_some_and(|n| n <= MAX_COINS),
            "complete onward aggregate certificate bound",
        )?;
        crate::encoded_size::check("complete-onward-history-v1", self)?;
        Ok(())
    }
    // Routing and resource checks only: later malformed bodies must not conceal
    // a separately authenticated incident in another complete certificate.
    fn admission(&self, destination: Hash, trust: &Trust) -> Result<()> {
        self.bound()?;
        require(
            trust.regions.len() == 3
                && self.source != destination
                && self.origin.source != self.source
                && self.origin.source != destination
                && self.destination == destination
                && self.origin.destination == self.source
                && !self.export.is_zero()
                && !self.origin.export.is_zero()
                && trust.region(destination)?.rules == crate::paged_bft::ONWARD_HISTORY_RULES
                && trust.region(self.source)?.rules == crate::paged_bft::ORIGIN_HISTORY_RULES
                && trust.region(self.origin.source)?.rules == crate::paged_bft::RULES
                && trust.region(self.origin.source)?.region == trust.currency.origin,
            "complete onward requires exact two-hop route and three signed profiles",
        )
    }
    fn shape(&self, destination: Hash, trust: &Trust) -> Result<()> {
        self.admission(destination, trust)?;
        self.origin.shape(self.source, trust)?;
        for s in &self.origin.snapshots {
            for command in s.blocks.iter().flat_map(|b| &b.commands) {
                require(
                    matches!(command, Command::Spend(_)),
                    "complete onward origin command unsupported",
                )?;
            }
        }
        let origin_checkpoint = self
            .origin
            .snapshots
            .last()
            .ok_or("complete onward origin tail absent")?
            .statement
            .id()?;
        for (index, snapshot) in self.snapshots.iter().enumerate() {
            require(
                snapshot.statement.region == self.source
                    && snapshot.statement.currency == trust.currency()?
                    && snapshot.statement.height == index as u64 + 1,
                "complete onward exact source genesis order/domain",
            )?;
            crate::paged_bft::shape(snapshot, trust)?;
            for command in snapshot.blocks.iter().flat_map(|b| &b.commands) {
                require(
                    match command {
                        Command::Spend(_) => true,
                        Command::Import { snapshot, export } => {
                            *snapshot == origin_checkpoint && *export == self.origin.export
                        }
                        _ => false,
                    },
                    "complete onward intermediate command unsupported",
                )?;
            }
        }
        Ok(())
    }
    pub(super) fn complete_snapshots(&self) -> Result<Vec<Snapshot>> {
        self.bound()?;
        Ok(self
            .origin
            .snapshots
            .iter()
            .chain(&self.snapshots)
            .cloned()
            .collect())
    }
}

struct SourceHistory {
    scope: Scope,
    records: Vec<Record>,
}
impl body_witness::History for SourceHistory {
    fn require_scope(&self, scope: &Scope) -> Result<()> {
        require(self.scope == *scope, "complete onward source scope differs")
    }
    fn visit(&self, consumer: &mut dyn FnMut(&Record) -> Result<()>) -> Result<u64> {
        for record in &self.records {
            consumer(record)?;
        }
        Ok(self.records.len() as u64)
    }
}

// Private, bounded and derived by this invocation's complete Native execution.
// Neither this closure nor its pending facts can be deserialized or supplied.
struct Executed {
    checkpoint: Hash,
    anchors: BTreeMap<Hash, (Snapshot, Ledger)>,
}
#[derive(Clone)]
pub(super) struct Pending {
    checkpoint: Hash,
    pub(super) anchors: BTreeSet<Hash>,
}

fn execute(proof: &CompleteOnwardHistory, destination: Hash, trust: &Trust) -> Result<Executed> {
    proof.shape(destination, trust)?;
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
        "complete onward trust binding differs",
    )?;
    let mut records = Vec::with_capacity(proof.snapshots.len() + 1);
    records.push(Record::OriginHistory(Box::new(proof.origin.clone())));
    records.extend(
        proof
            .snapshots
            .iter()
            .cloned()
            .map(|s| Record::Certified(Box::new(s))),
    );
    let history = SourceHistory {
        scope: header.scope(&source.trust)?,
        records,
    };
    source.apply_retained(&history.records[0], &history)?;
    let origin_checkpoint = proof
        .origin
        .snapshots
        .last()
        .ok_or("complete onward origin tail absent")?
        .statement
        .id()?;
    let origin_ledger = &source
        .evidence
        .snapshots
        .get(&origin_checkpoint)
        .ok_or("complete onward executed origin absent")?
        .1;
    let origin_export = origin_ledger
        .exports
        .get(&proof.origin.export)
        .ok_or("complete onward executed origin export absent")?;
    require(
        origin_ledger.imports.is_empty()
            && origin_ledger.channel_state.is_none()
            && origin_ledger.exports.len() == 1
            && origin_export.dependencies.is_empty()
            && origin_export.channel_dependencies.is_empty(),
        "complete onward origin has unsupported value ancestry or route",
    )?;
    for record in &history.records[1..] {
        source.apply_retained(record, &history)?;
        require(
            source.chain.ledger.channel_state.is_none()
                && source.chain.ledger.exports.iter().all(|(id, export)| {
                    *id == proof.export
                        && export.id == proof.export
                        && export.source == proof.source
                        && export.destination == destination
                }),
            "complete onward intermediate has unsupported value route",
        )?;
    }
    let checkpoint = source
        .chain
        .finalized
        .ok_or("complete onward tail absent")?;
    let snapshot = source.evidence.snapshot(checkpoint)?;
    let ledger = &source.chain.ledger;
    let export = ledger
        .exports
        .get(&proof.export)
        .ok_or("complete onward native export absent")?;
    let ancestors = BTreeSet::from([origin_checkpoint]);
    require(
        source.chain.height() == proof.snapshots.len() as u64
            && snapshot.statement.height == source.chain.height()
            && source.executed.count() == history.records.len() as u64
            && ledger.imports == BTreeMap::from([(proof.origin.export, origin_checkpoint)])
            && ledger.exports.len() == 1
            && export.dependencies == ancestors
            && export.channel_dependencies.is_empty()
            && ledger.coins.values().all(|coin| {
                coin.dependencies.is_subset(&ancestors) && coin.channel_dependencies.is_empty()
            }),
        "complete onward native tail or permanent dependency closure differs",
    )?;
    ledger.audit()?;
    let mut anchors = BTreeMap::new();
    for sid in ancestors.into_iter().chain(std::iter::once(checkpoint)) {
        anchors.insert(
            sid,
            source
                .evidence
                .snapshots
                .get(&sid)
                .ok_or("complete onward native dependency absent")?
                .clone(),
        );
    }
    crate::encoded_size::check("complete-onward-derived-closure-v1", &anchors)?;
    Ok(Executed {
        checkpoint,
        anchors,
    })
}

impl Replay {
    pub(super) fn apply_onward_history(
        &mut self,
        proof: &CompleteOnwardHistory,
        stream: &dyn body_witness::History,
    ) -> Result<()> {
        let executed = execute(proof, self.chain.region, &self.trust)?;
        // Complete incoming execution precedes any body comparison. Only this
        // invocation's already-executed prefix may constrain the incoming branch.
        let prior_count = self.executed.count();
        let mut index = 0u64;
        stream.visit(&mut |record| {
            if index < prior_count {
                for old in record.snapshots()? {
                    let incoming = if old.statement.region == proof.origin.source {
                        Some(&proof.origin.snapshots)
                    } else if old.statement.region == proof.source {
                        Some(&proof.snapshots)
                    } else {
                        None
                    };
                    if let Some(incoming) = incoming {
                        if old.statement.height > 0 && old.statement.height <= incoming.len() as u64
                        {
                            require(
                                body(&old)?
                                    == body(&incoming[(old.statement.height - 1) as usize])?,
                                "complete onward differs from executed retained source branch",
                            )?;
                        }
                    }
                }
            }
            index = index
                .checked_add(1)
                .ok_or("complete onward retained count overflow")?;
            Ok(())
        })?;
        let protected = executed.anchors.keys().copied().collect::<BTreeSet<_>>();
        // Install the complete native closure on a staged copy. Protected includes
        // every incoming ancestor even before insertion and even on a later retry.
        let mut staged = self.clone();
        if !staged.chain.ledger.imports.contains_key(&proof.export) {
            staged
                .onward_imports
                .entry(proof.export)
                .or_insert(Pending {
                    checkpoint: executed.checkpoint,
                    anchors: protected.clone(),
                });
        }
        require(
            staged.onward_imports.len() <= MAX_COINS,
            "complete onward pending bound",
        )?;
        for (sid, (snapshot, ledger)) in executed.anchors {
            if let Some((old, old_ledger)) = staged.evidence.snapshots.get(&sid) {
                require(
                    body(old)? == body(&snapshot)? && *old_ledger == ledger,
                    "complete onward retained native anchor differs",
                )?;
            } else {
                staged.retain_for_next_with(&protected)?;
                staged.evidence.snapshots.insert(sid, (snapshot, ledger));
            }
        }
        require(
            staged.evidence.snapshots.len() <= MAX_SNAPSHOTS,
            "complete onward active closure bound",
        )?;
        crate::encoded_size::check("evidence", &ActiveEvidence(&staged.evidence))?;
        self.evidence = staged.evidence;
        self.onward_imports = staged.onward_imports;
        Ok(())
    }
}

impl Store {
    fn onward_safety(&self, proof: &CompleteOnwardHistory) -> Result<()> {
        for region in [proof.origin.source, proof.source, proof.destination] {
            self.safety.check_region(region)?;
        }
        Ok(())
    }
    /// Complete evidence receipt only. Certified local Import still controls value.
    pub fn accept_complete_onward_history(&mut self, proof: CompleteOnwardHistory) -> Result<Hash> {
        proof.admission(self.chain.region, &self.trust)?;
        self.current_paged_replay()?;
        self.check_paged_snapshot_conflicts(&proof.complete_snapshots()?)?;
        proof.shape(self.chain.region, &self.trust)?;
        self.onward_safety(&proof)?;
        let checkpoint = proof
            .snapshots
            .last()
            .ok_or("complete onward tail absent")?
            .statement
            .id()?;
        let mut identical = false;
        let stream = self
            .paged
            .as_ref()
            .ok_or("complete onward native stream missing")?;
        stream.visit(stream.storage_head(), |record| {
            if let Record::OnwardHistory(old) = record {
                identical |= old.as_ref() == &proof;
            }
            Ok(())
        })?;
        if !identical {
            self.append_paged(&[Record::OnwardHistory(Box::new(proof))])?;
        }
        Ok(checkpoint)
    }
    /// Tasks derived from complete Native events, with safety over every ancestor.
    pub fn complete_onward_pending_imports(&self) -> Result<Vec<Command>> {
        if self.trust.region(self.chain.region)?.rules != crate::paged_bft::ONWARD_HISTORY_RULES {
            return Ok(vec![]);
        }
        let replay = self.current_paged_replay()?;
        let mut commands = Vec::new();
        self.safety.check_region(self.chain.region)?;
        for (export, pending) in &replay.onward_imports {
            for anchor in &pending.anchors {
                self.safety
                    .check_region(replay.evidence.snapshot(*anchor)?.statement.region)?;
            }
            commands.push(Command::Import {
                snapshot: pending.checkpoint,
                export: *export,
            });
        }
        self.safety
            .check(&replay.chain, &commands, &replay.evidence)?;
        encode("complete-onward-pending-imports-v1", &commands)?;
        Ok(commands)
    }
    /// Select the earliest certified onward debit after full current native replay.
    /// This public evidence constructor neither signs nor changes the origin path.
    pub fn complete_onward_export(&self, export: Hash) -> Result<CompleteOnwardHistory> {
        require(
            self.trust.region(self.chain.region)?.rules == crate::paged_bft::ORIGIN_HISTORY_RULES
                && self.trust.region(self.chain.region)?.region != self.trust.currency.origin,
            "onward export requires exact intermediate complete-origin profile",
        )?;
        self.current_paged_replay()?;
        let native = self
            .chain
            .ledger
            .exports
            .get(&export)
            .ok_or("onward export absent from Native debit")?;
        self.safety.check_region(self.chain.region)?;
        self.safety.check_region(native.destination)?;
        let stream = self
            .paged
            .as_ref()
            .ok_or("onward export complete stream absent")?;
        let mut origin = None;
        let mut snapshots = BTreeMap::new();
        let mut index = 0u64;
        stream.visit(stream.storage_head(), |record| {
            match record {
                Record::OriginHistory(proof) => {
                    require(
                        index == 0 && origin.is_none(),
                        "onward export requires one first complete origin event",
                    )?;
                    origin = Some(*proof.clone());
                }
                Record::Certified(snapshot) => {
                    require(
                        snapshot.statement.region == self.chain.region,
                        "onward export local certificate required",
                    )?;
                    if snapshot.statement.height <= native.height {
                        require(
                            snapshots.len() < MAX_COINS
                                || snapshots.contains_key(&snapshot.statement.height),
                            "onward export source certificate bound",
                        )?;
                        snapshots
                            .entry(snapshot.statement.height)
                            .or_insert_with(|| *snapshot.clone());
                    }
                }
                _ => return Err("onward export retained event unsupported".into()),
            }
            index = index.checked_add(1).ok_or("onward export count overflow")?;
            Ok(())
        })?;
        let proof = CompleteOnwardHistory {
            source: self.chain.region,
            destination: native.destination,
            export,
            origin: origin.ok_or("onward export complete origin event absent")?,
            snapshots: snapshots.into_values().collect(),
        };
        proof.admission(native.destination, &self.trust)?;
        self.onward_safety(&proof)?;
        let executed = execute(&proof, native.destination, &self.trust)?;
        let (snapshot, ledger) = executed
            .anchors
            .get(&executed.checkpoint)
            .ok_or("onward export executed tail absent")?;
        require(
            snapshot.statement.height == native.height
                && ledger.exports.get(&export) == Some(native),
            "onward export earliest complete prefix differs from Native debit",
        )?;
        Ok(proof)
    }
}
