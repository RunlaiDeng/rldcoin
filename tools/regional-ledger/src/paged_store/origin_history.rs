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
    // Bounded routing admission only. A malformed later snapshot must not hide
    // independently authentic signer equivocation in another snapshot.
    fn admission(&self, destination: Hash, trust: &Trust) -> Result<()> {
        require(
            crate::paged_bft::is_origin_profile(&trust.region(destination)?.rules)
                && self.destination == destination
                && self.source != destination
                && trust.region(self.source)?.region == trust.currency.origin
                && trust.region(self.source)?.rules == crate::paged_bft::RULES
                && !self.snapshots.is_empty()
                && self.snapshots.len() <= MAX_COINS,
            "complete origin history requires explicit receiver profile/origin/route/bound",
        )?;
        encode("complete-origin-history-v1", self)?;
        Ok(())
    }
    pub(super) fn shape(&self, destination: Hash, trust: &Trust) -> Result<()> {
        self.admission(destination, trust)?;
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
    /// Historical exact-byte completion only, derived from the current complete
    /// Native replay. Never an Import, spendability, signing or freshness right.
    pub fn retained_origin_contact_messages(&self) -> Result<Vec<Hash>> {
        if !crate::paged_bft::is_origin_profile(&self.trust.region(self.chain.region)?.rules) {
            return Ok(vec![]);
        }
        self.current_paged_replay()?;
        let mut messages = BTreeSet::new();
        let stream = self.paged.as_ref().ok_or("origin contact stream absent")?;
        stream.visit(stream.storage_head(), |record| {
            if let Record::OriginHistory(proof) = record {
                if self.safety.check_region(proof.source).is_ok()
                    && self.safety.check_region(self.chain.region).is_ok()
                    && serde_json::to_vec(proof).map_err(|e| e.to_string())?.len()
                        <= crate::contact::MAX_PAYLOAD
                {
                    messages.insert(crate::contact::Frame::origin_frame(proof)?.message_id);
                    require(
                        messages.len() <= MAX_COINS,
                        "origin contact observation count bound",
                    )?;
                }
            }
            Ok(())
        })?;
        let messages = messages.into_iter().collect::<Vec<_>>();
        encode("retained-origin-contact-messages", &messages)?;
        Ok(messages)
    }

    /// Pending tasks derived from full Native events, with no automatic credit.
    pub fn complete_origin_pending_imports(&self) -> Result<Vec<Command>> {
        if !crate::paged_bft::is_origin_profile(&self.trust.region(self.chain.region)?.rules) {
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
        proof.admission(self.chain.region, &self.trust)?;
        self.current_paged_replay()?;
        // Conflict verification authenticates both complete certificates under
        // independent receiver trust. It never executes or installs a branch.
        // Retain that incident before rejecting unrelated malformed value tails.
        self.check_paged_snapshot_conflicts(&proof.snapshots)?;
        proof.shape(self.chain.region, &self.trust)?;
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
            // The entire input is already authenticated and executed in this
            // current replay. Known incidents still prohibit its acknowledgement.
            self.safety.check_region(proof.source)?;
            return Ok(last);
        }
        self.safety.check_region(proof.source)?;
        self.append_paged(&[Record::OriginHistory(Box::new(proof))])?;
        Ok(last)
    }
}

impl CompleteOriginHistory {
    /// All initial state is derived in this call from complete signed genesis history.
    pub(crate) fn verify_network_set(
        proofs: &[Self],
        destination: Hash,
        trust: &Trust,
    ) -> Result<VerifiedEvidence> {
        require(
            trust.region(destination)?.rules == crate::paged_bft::ORIGIN_NETWORK_RULES
                && proofs.len() <= 4,
            "origin network profile/history bound",
        )?;
        encode("origin-network-histories-v2", &proofs)?;
        let mut verified = VerifiedEvidence {
            trust_binding: Some(trust.binding),
            ..VerifiedEvidence::default()
        };
        for (index, proof) in proofs.iter().enumerate() {
            let executed = execute(proof, destination, trust)?;
            for old in &proofs[..index] {
                for (a, b) in old.snapshots.iter().zip(&proof.snapshots) {
                    require(
                        a.statement == b.statement && a.blocks == b.blocks && a.epochs == b.epochs,
                        "origin network histories conflict in complete prefix",
                    )?;
                }
            }
            if let Some((snapshot, ledger)) = verified.snapshots.get(&executed.checkpoint) {
                require(
                    snapshot.statement == executed.snapshot.statement
                        && snapshot.blocks == executed.snapshot.blocks
                        && snapshot.epochs == executed.snapshot.epochs
                        && *ledger == executed.ledger,
                    "origin network duplicate execution differs",
                )?;
            } else {
                verified
                    .snapshots
                    .insert(executed.checkpoint, (executed.snapshot, executed.ledger));
            }
        }
        Ok(verified)
    }
}
impl Store {
    /// Complete immutable proof bytes from current fully replayed typed events.
    pub(crate) fn origin_network_material(&self) -> Result<(Vec<CompleteOriginHistory>, Evidence)> {
        require(
            self.trust.region(self.chain.region)?.rules == crate::paged_bft::ORIGIN_NETWORK_RULES,
            "origin network material requires explicit signed V2 profile",
        )?;
        self.current_paged_replay()?;
        let source = self.trust.named(&self.trust.currency.origin)?;
        self.safety.check_region(source)?;
        let required = self
            .journal
            .evidence
            .snapshots
            .iter()
            .filter(|s| s.statement.region == source)
            .map(|s| s.statement.id())
            .collect::<Result<BTreeSet<_>>>()?;
        let mut selected = BTreeMap::new();
        let stream = self.paged.as_ref().ok_or("origin network stream absent")?;
        stream.visit(stream.storage_head(), |record| {
            if let Record::OriginHistory(proof) = record {
                let tail = proof
                    .snapshots
                    .last()
                    .ok_or("origin network history empty")?
                    .statement
                    .id()?;
                if required.contains(&tail) {
                    selected.entry(tail).or_insert_with(|| *proof.clone());
                }
            }
            Ok(())
        })?;
        require(
            selected.len() == required.len() && selected.len() <= 4,
            "origin network complete active dependencies absent or exceed bound",
        )?;
        let mut local = self
            .journal
            .evidence
            .snapshots
            .iter()
            .filter(|s| s.statement.region == self.chain.region)
            .cloned()
            .collect::<Vec<_>>();
        require(
            local.len() + required.len() == self.journal.evidence.snapshots.len(),
            "origin network contains unsupported foreign dependency",
        )?;
        local.sort_by_key(|s| s.statement.height);
        let proofs = selected.into_values().collect::<Vec<_>>();
        let evidence = Evidence { snapshots: local };
        let mut verified =
            CompleteOriginHistory::verify_network_set(&proofs, self.chain.region, &self.trust)?;
        for snapshot in &evidence.snapshots {
            verified.add(snapshot.clone(), &self.trust)?;
        }
        Ok((proofs, evidence))
    }
}

impl Store {
    /// Exact original certificate retry after whole-envelope authentication.
    /// No altered certificate, historical body hint or incident may skip finalize.
    pub(crate) fn finalize_origin_network_certificate(&mut self, snapshot: Snapshot) -> Result<()> {
        require(
            self.trust.region(self.chain.region)?.rules == crate::paged_bft::ORIGIN_NETWORK_RULES,
            "origin certificate sync requires explicit V2 profile",
        )?;
        self.current_paged_replay()?;
        self.safety.check_region(self.chain.region)?;
        let stream = self
            .paged
            .as_ref()
            .ok_or("origin certificate stream absent")?;
        let mut identical = false;
        stream.visit(stream.storage_head(), |record| {
            if let Record::Certified(old) = record {
                if old.as_ref() == &snapshot {
                    identical = true;
                }
            }
            Ok(())
        })?;
        if !identical {
            self.finalize(snapshot)?;
        }
        Ok(())
    }
}

impl Store {
    /// Signature-authenticated incidents persist even when the envelope is refused.
    /// This preflight never admits history, creates an Import or signs anything.
    pub fn observe_origin_network_conflicts(
        &mut self,
        envelope: &crate::bft_network::Envelope,
    ) -> Result<()> {
        self.observe_origin_network_batch_conflicts(std::slice::from_ref(envelope))
    }

    /// Compare arriving histories across the complete bounded batch as well as
    /// retained history. No shape/body refusal may hide an admitted conflict.
    pub(crate) fn observe_origin_network_batch_conflicts(
        &mut self,
        envelopes: &[crate::bft_network::Envelope],
    ) -> Result<()> {
        require(
            !envelopes.is_empty() && envelopes.len() <= 4,
            "origin conflict batch bound",
        )?;
        self.current_paged_replay()?;
        let mut snapshots = Vec::new();
        for envelope in envelopes {
            require(
                envelope.format == crate::bft_network::ORIGIN_FORMAT
                    && self.trust.region(self.chain.region)?.rules
                        == crate::paged_bft::ORIGIN_NETWORK_RULES
                    && envelope.currency == self.trust.currency()?
                    && envelope.region == self.chain.region,
                "origin conflict observation domain/profile differs",
            )?;
            encode("origin-conflict-complete-envelope", envelope)?;
            let proofs = envelope
                .origins
                .as_ref()
                .ok_or("origin conflict histories absent")?;
            require(
                proofs.len() <= 4 && envelope.evidence.snapshots.len() <= MAX_SNAPSHOTS,
                "origin conflict histories/evidence bound",
            )?;
            for proof in proofs {
                proof.admission(self.chain.region, &self.trust)?;
            }
            snapshots.extend(proofs.iter().flat_map(|p| p.snapshots.iter().cloned()));
            snapshots.extend(envelope.evidence.snapshots.iter().cloned());
            if let crate::bft_network::Body::Finalized(snapshot) = &envelope.body {
                snapshots.push(*snapshot.clone());
            }
        }
        self.check_paged_snapshot_conflicts(&snapshots)
    }
}

impl Store {
    /// Stable earliest complete certified prefix for an already debited export.
    /// Full current source replay precedes selection; active64 cannot supply it.
    pub(crate) fn complete_origin_export(&self, export: Hash) -> Result<CompleteOriginHistory> {
        require(
            self.trust.region(self.chain.region)?.rules == crate::paged_bft::RULES
                && self.trust.region(self.chain.region)?.region == self.trust.currency.origin,
            "origin export requires independently admitted original paged origin",
        )?;
        self.current_paged_replay()?;
        self.safety.check_region(self.chain.region)?;
        let record = self
            .chain
            .ledger
            .exports
            .get(&export)
            .ok_or("origin export absent from Native debit")?;
        require(
            self.trust.region(record.destination)?.rules == crate::paged_bft::ORIGIN_NETWORK_RULES,
            "origin export destination requires explicit signed network V2",
        )?;
        self.safety.check_region(record.destination)?;
        let stream = self
            .paged
            .as_ref()
            .ok_or("origin export complete stream absent")?;
        let mut snapshots = BTreeMap::new();
        stream.visit(stream.storage_head(), |event| {
            let Record::Certified(snapshot) = event else {
                // Full current replay authenticated every retained event above.
                // Only formally finalized local certificates select this proof;
                // evidence, contacts and receipts cannot supply branch anchors.
                // Complete execution below still refuses missing foreign inputs.
                return Ok(());
            };
            require(
                snapshot.statement.region == self.chain.region,
                "origin export foreign certificate",
            )?;
            if snapshot.statement.height <= record.height {
                snapshots
                    .entry(snapshot.statement.height)
                    .or_insert_with(|| *snapshot.clone());
            }
            Ok(())
        })?;
        let proof = CompleteOriginHistory {
            source: self.chain.region,
            destination: record.destination,
            export,
            snapshots: snapshots.into_values().collect(),
        };
        let executed = execute(&proof, record.destination, &self.trust)?;
        require(
            executed.snapshot.statement.height == record.height
                && executed.ledger.exports.get(&export) == Some(record),
            "origin export complete earliest prefix differs from actual debit",
        )?;
        Ok(proof)
    }
}
