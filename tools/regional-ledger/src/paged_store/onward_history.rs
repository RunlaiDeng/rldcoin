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

#[derive(Clone, Copy)]
enum Profile {
    History,
    Network,
}
impl Profile {
    fn regions(self) -> (&'static str, &'static str) {
        match self {
            Self::History => (
                crate::paged_bft::ORIGIN_HISTORY_RULES,
                crate::paged_bft::ONWARD_HISTORY_RULES,
            ),
            Self::Network => (
                crate::paged_bft::ORIGIN_NETWORK_RULES,
                crate::paged_bft::ONWARD_NETWORK_RULES,
            ),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompleteOnwardNetworkHistory {
    pub history: CompleteOnwardHistory,
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
        self.admission_for(destination, trust, Profile::History)
    }
    fn admission_for(&self, destination: Hash, trust: &Trust, profile: Profile) -> Result<()> {
        self.bound()?;
        let (intermediate_rules, destination_rules) = profile.regions();
        require(
            trust.regions.len() == 3
                && self.source != destination
                && self.origin.source != self.source
                && self.origin.source != destination
                && self.destination == destination
                && self.origin.destination == self.source
                && !self.export.is_zero()
                && !self.origin.export.is_zero()
                && trust.region(destination)?.rules == destination_rules
                && trust.region(self.source)?.rules == intermediate_rules
                && trust.region(self.origin.source)?.rules == crate::paged_bft::RULES
                && trust.region(self.origin.source)?.region == trust.currency.origin,
            "complete onward requires exact two-hop route and three signed profiles",
        )
    }
    fn shape(&self, destination: Hash, trust: &Trust) -> Result<()> {
        self.shape_for(destination, trust, Profile::History)
    }
    fn shape_for(&self, destination: Hash, trust: &Trust, profile: Profile) -> Result<()> {
        self.admission_for(destination, trust, profile)?;
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
    execute_for(proof, destination, trust, Profile::History)
}
fn execute_for(
    proof: &CompleteOnwardHistory,
    destination: Hash,
    trust: &Trust,
    profile: Profile,
) -> Result<Executed> {
    #[cfg(test)]
    let mut execution_cost = crate::bft_onward_network::execution_cost::Span::start();
    proof.shape_for(destination, trust, profile)?;
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
    #[cfg(test)]
    execution_cost.succeeded();
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
        self.apply_onward_history_for(proof, stream, Profile::History)
    }
    pub(super) fn apply_onward_network_history(
        &mut self,
        proof: &CompleteOnwardNetworkHistory,
        stream: &dyn body_witness::History,
    ) -> Result<()> {
        self.apply_onward_history_for(&proof.history, stream, Profile::Network)
    }
    fn apply_onward_history_for(
        &mut self,
        proof: &CompleteOnwardHistory,
        stream: &dyn body_witness::History,
        profile: Profile,
    ) -> Result<()> {
        let executed = execute_for(proof, self.chain.region, &self.trust, profile)?;
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
        self.onward_pending_imports()
    }
    pub fn complete_onward_network_pending_imports(&self) -> Result<Vec<Command>> {
        require(
            self.trust.region(self.chain.region)?.rules == crate::paged_bft::ONWARD_NETWORK_RULES,
            "complete onward network pending requires explicit profile",
        )?;
        self.check_onward_network_safety()?;
        self.onward_pending_imports()
    }
    fn onward_pending_imports(&self) -> Result<Vec<Command>> {
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

impl CompleteOnwardNetworkHistory {
    pub(crate) fn require_route(&self, destination: Hash, trust: &Trust) -> Result<()> {
        crate::encoded_size::check("complete-onward-network-history-v1", self)?;
        self.history
            .admission_for(destination, trust, Profile::Network)
    }
    pub(crate) fn complete_snapshots(&self) -> Result<Vec<Snapshot>> {
        crate::encoded_size::check("complete-onward-network-history-v1", self)?;
        self.history.complete_snapshots()
    }
    pub(crate) fn verify_anchors(
        &self,
        destination: Hash,
        trust: &Trust,
    ) -> Result<VerifiedEvidence> {
        self.require_route(destination, trust)?;
        #[cfg(test)]
        let verification = crate::bft_onward_network::execution_cost::Verification::enter();
        let executed = execute_for(&self.history, destination, trust, Profile::Network)?;
        #[cfg(test)]
        drop(verification);
        Ok(VerifiedEvidence {
            snapshots: executed.anchors,
            trust_binding: Some(trust.binding),
            ..VerifiedEvidence::default()
        })
    }
}

fn network_regions(destination: Hash, trust: &Trust) -> Result<[Hash; 3]> {
    let origin = trust.named(&trust.currency.origin)?;
    require(
        trust.regions.len() == 3
            && origin != destination
            && trust.region(origin)?.rules == crate::paged_bft::RULES
            && trust.region(destination)?.rules == crate::paged_bft::ONWARD_NETWORK_RULES,
        "complete onward network requires three exact admitted regions",
    )?;
    let intermediate = trust
        .regions
        .keys()
        .copied()
        .find(|r| *r != origin && *r != destination)
        .ok_or("complete onward network intermediate absent")?;
    require(
        trust.region(intermediate)?.rules == crate::paged_bft::ORIGIN_NETWORK_RULES,
        "complete onward network intermediate profile differs",
    )?;
    Ok([origin, intermediate, destination])
}

impl Store {
    /// Complete local certificates and one whole retained two-hop closure. All
    /// records have just executed natively; no archive or projected cache is an
    /// authority source. More than one independent closure explicitly refuses.
    // The sole production caller now owns a construction witness. Keep this
    // crate-private independent full path as the test comparison control.
    #[cfg(test)]
    pub(crate) fn onward_network_material(
        &self,
    ) -> Result<(Option<CompleteOnwardNetworkHistory>, Evidence)> {
        self.onward_network_material_inner(None)
    }

    pub(crate) fn onward_network_material_for_construction(
        &self,
        witness: &mut crate::bft_onward_network::LocalConstructionWitness,
    ) -> Result<(Option<CompleteOnwardNetworkHistory>, Evidence)> {
        let result = self.onward_network_material_inner(Some(&mut *witness));
        if result.is_err() {
            witness.disable();
        }
        result
    }

    fn onward_network_material_inner(
        &self,
        mut witness: Option<&mut crate::bft_onward_network::LocalConstructionWitness>,
    ) -> Result<(Option<CompleteOnwardNetworkHistory>, Evidence)> {
        self.require_onward_network_state()?;
        self.check_onward_network_safety()?;
        let replay = self.current_paged_replay()?;
        let mut required = replay
            .evidence
            .snapshots
            .iter()
            .filter(|(_, (s, _))| s.statement.region != self.chain.region)
            .map(|(id, _)| *id)
            .collect::<BTreeSet<_>>();
        for pending in replay.onward_imports.values() {
            required.extend(&pending.anchors);
        }
        required.extend(replay.chain.ledger.imports.values().copied());
        let stream = self.paged.as_ref().ok_or("onward network stream absent")?;
        let mut local = BTreeMap::new();
        stream.visit(stream.storage_head(), |record| {
            match record {
                Record::Certified(snapshot) => {
                    require(
                        snapshot.statement.region == self.chain.region,
                        "onward network local certificate region differs",
                    )?;
                    require(
                        local.len() < MAX_SNAPSHOTS
                            || local.contains_key(&snapshot.statement.height),
                        "onward network complete local prefix bound",
                    )?;
                    local
                        .entry(snapshot.statement.height)
                        .or_insert_with(|| *snapshot.clone());
                }
                Record::OnwardNetworkHistory(proof) => {
                    let anchors = match witness.as_deref_mut() {
                        Some(witness) => {
                            witness.verify_anchors(proof, self.chain.region, &self.trust)?
                        }
                        None => proof.verify_anchors(self.chain.region, &self.trust)?,
                    };
                    required.extend(anchors.snapshots.keys().copied());
                    require(
                        required.len() <= MAX_SNAPSHOTS,
                        "onward network complete dependency count bound",
                    )?;
                }
                _ => return Err("onward network local material event unsupported".into()),
            }
            Ok(())
        })?;
        let mut selected = None;
        stream.visit(stream.storage_head(), |record| {
            if let Record::OnwardNetworkHistory(proof) = record {
                if selected.is_none() {
                    let anchors = match witness.as_deref_mut() {
                        Some(witness) => {
                            witness.verify_anchors(proof, self.chain.region, &self.trust)?
                        }
                        None => proof.verify_anchors(self.chain.region, &self.trust)?,
                    };
                    if required.iter().all(|id| anchors.snapshots.contains_key(id)) {
                        selected = Some(*proof.clone());
                    }
                }
            }
            Ok(())
        })?;
        require(
            required.is_empty() || selected.is_some(),
            "onward network needs one complete retained closure for every dependency",
        )?;
        let evidence = Evidence {
            snapshots: local.into_values().collect(),
        };
        require(
            evidence.snapshots.len() as u64 == self.chain.height()
                && evidence
                    .snapshots
                    .iter()
                    .enumerate()
                    .all(|(i, s)| s.statement.height == i as u64 + 1),
            "onward network complete C genesis prefix absent",
        )?;
        crate::encoded_size::check("onward-network-local-material-v1", &(&selected, &evidence))?;
        Ok((selected, evidence))
    }

    /// Cold Runtime may authenticate only material already installed through
    /// Native receipt/finality. Exact immutable bytes, not statement IDs, bind
    /// this check; a valid but uninstalled proof is not startup authority.
    pub(crate) fn require_retained_onward_material(
        &self,
        proof: Option<&CompleteOnwardNetworkHistory>,
        snapshots: &[Snapshot],
    ) -> Result<()> {
        self.require_onward_network_state()?;
        self.check_onward_network_safety()?;
        require(
            snapshots.len() <= MAX_SNAPSHOTS + 1,
            "onward cold certificate bound",
        )?;
        crate::encoded_size::check("onward-cold-material-v1", &(proof, snapshots))?;
        let mut proof_found = proof.is_none();
        let mut found = vec![false; snapshots.len()];
        let stream = self.paged.as_ref().ok_or("onward cold stream absent")?;
        stream.visit(stream.storage_head(), |record| {
            match record {
                Record::OnwardNetworkHistory(old) => {
                    proof_found |= proof.is_some_and(|p| p == old.as_ref());
                }
                Record::Certified(old) => {
                    for (i, snapshot) in snapshots.iter().enumerate() {
                        found[i] |= old.as_ref() == snapshot;
                    }
                }
                _ => (),
            }
            Ok(())
        })?;
        require(
            proof_found && found.iter().all(|v| *v),
            "onward cold complete material absent from Native history",
        )
    }

    pub(crate) fn finalize_onward_network_certificate(&mut self, snapshot: Snapshot) -> Result<()> {
        self.require_onward_network_state()?;
        self.check_onward_network_safety()?;
        let stream = self
            .paged
            .as_ref()
            .ok_or("onward certificate stream absent")?;
        let mut identical = false;
        stream.visit(stream.storage_head(), |record| {
            if let Record::Certified(old) = record {
                identical |= old.as_ref() == &snapshot;
            }
            Ok(())
        })?;
        if !identical {
            self.finalize(snapshot)?;
        }
        Ok(())
    }

    pub(crate) fn require_onward_network_state(&self) -> Result<()> {
        network_regions(self.chain.region, &self.trust)?;
        self.current_paged_replay()?;
        Ok(())
    }
    pub(crate) fn check_onward_network_safety(&self) -> Result<()> {
        for region in network_regions(self.chain.region, &self.trust)? {
            self.safety.check_region(region)?;
        }
        Ok(())
    }
    pub(crate) fn observe_onward_network_conflicts(
        &mut self,
        snapshots: &[Snapshot],
    ) -> Result<()> {
        self.require_onward_network_state()?;
        require(
            snapshots.len() <= MAX_COINS + MAX_SNAPSHOTS + 1,
            "complete onward network conflict certificate bound",
        )?;
        crate::encoded_size::check("complete-onward-network-conflicts-v1", &snapshots)?;
        self.check_paged_snapshot_conflicts(snapshots)
    }
    pub fn accept_complete_onward_network_history(
        &mut self,
        proof: CompleteOnwardNetworkHistory,
    ) -> Result<Hash> {
        proof.require_route(self.chain.region, &self.trust)?;
        self.require_onward_network_state()?;
        self.check_paged_snapshot_conflicts(&proof.complete_snapshots()?)?;
        proof
            .history
            .shape_for(self.chain.region, &self.trust, Profile::Network)?;
        self.check_onward_network_safety()?;
        let checkpoint = proof
            .history
            .snapshots
            .last()
            .ok_or("complete onward network tail absent")?
            .statement
            .id()?;
        let mut identical = false;
        let stream = self
            .paged
            .as_ref()
            .ok_or("complete onward network stream absent")?;
        stream.visit(stream.storage_head(), |record| {
            if let Record::OnwardNetworkHistory(old) = record {
                identical |= old.as_ref() == &proof;
            }
            Ok(())
        })?;
        if !identical {
            self.append_paged(&[Record::OnwardNetworkHistory(Box::new(proof))])?;
        }
        Ok(checkpoint)
    }
    /// Interleaved ordinary B history remains intact; selected proof follows its
    /// actual permanent Import, never event position or a sender-provided balance.
    pub fn complete_onward_network_export(
        &self,
        export: Hash,
    ) -> Result<CompleteOnwardNetworkHistory> {
        require(
            self.trust.region(self.chain.region)?.rules == crate::paged_bft::ORIGIN_NETWORK_RULES,
            "onward network export requires exact intermediate network profile",
        )?;
        self.current_paged_replay()?;
        let native = self
            .chain
            .ledger
            .exports
            .get(&export)
            .ok_or("onward network export absent from Native debit")?;
        let regions = network_regions(native.destination, &self.trust)?;
        require(
            regions[1] == self.chain.region
                && native.dependencies.len() == 1
                && native.channel_dependencies.is_empty(),
            "onward network export ancestry differs",
        )?;
        for region in regions {
            self.safety.check_region(region)?;
        }
        let anchor = *native
            .dependencies
            .iter()
            .next()
            .ok_or("onward network anchor absent")?;
        let imports = self
            .chain
            .ledger
            .imports
            .iter()
            .filter(|(_, checkpoint)| **checkpoint == anchor)
            .collect::<Vec<_>>();
        require(
            imports.len() == 1,
            "onward network requires exact permanent origin Import",
        )?;
        let origin_export = *imports[0].0;
        let stream = self
            .paged
            .as_ref()
            .ok_or("onward network source stream absent")?;
        let mut origin = None;
        let mut snapshots = BTreeMap::new();
        stream.visit(stream.storage_head(), |record| {
            match record {
                Record::OriginHistory(proof) => {
                    require(
                        proof.source == regions[0]
                            && proof.destination == self.chain.region
                            && proof.export == origin_export,
                        "onward network retained foreign route unsupported",
                    )?;
                    if proof
                        .snapshots
                        .last()
                        .ok_or("onward network retained proof empty")?
                        .statement
                        .id()?
                        == anchor
                        && origin.is_none()
                    {
                        origin = Some(*proof.clone());
                    }
                }
                Record::Certified(snapshot) => {
                    require(
                        snapshot.statement.region == self.chain.region,
                        "onward network export local certificate required",
                    )?;
                    if snapshot.statement.height <= native.height {
                        require(
                            snapshots.len() < MAX_COINS
                                || snapshots.contains_key(&snapshot.statement.height),
                            "onward network export source certificate bound",
                        )?;
                        snapshots
                            .entry(snapshot.statement.height)
                            .or_insert_with(|| *snapshot.clone());
                    }
                }
                _ => return Err("onward network export retained event unsupported".into()),
            }
            Ok(())
        })?;
        let proof = CompleteOnwardNetworkHistory {
            history: CompleteOnwardHistory {
                source: self.chain.region,
                destination: native.destination,
                export,
                origin: origin.ok_or("onward network actual imported origin proof absent")?,
                snapshots: snapshots.into_values().collect(),
            },
        };
        proof.require_route(native.destination, &self.trust)?;
        let executed = execute_for(
            &proof.history,
            native.destination,
            &self.trust,
            Profile::Network,
        )?;
        let (snapshot, ledger) = executed
            .anchors
            .get(&executed.checkpoint)
            .ok_or("onward network executed tail absent")?;
        require(
            snapshot.statement.height == native.height
                && ledger.exports.get(&export) == Some(native),
            "onward network earliest complete prefix differs from Native debit",
        )?;
        Ok(proof)
    }
}
