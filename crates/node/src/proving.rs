//! Immutable authenticated host observations for building proof witnesses.
//! These carry no signing authority. Publication still rechecks the exact real
//! receipt and its retained local checkpoint in the live native executor.
use crate::{runtime::Initial, store::MAX_RECORD};
use anyhow::{Context, Result, ensure};
use rld_protocol::{
    codec::{Id, decode, hash},
    model::*,
    proof,
    state::State,
};
use std::sync::Arc;

// Count canonical bytes without allocating a complete encoded State. The guest
// already refuses inputs above MAX_RECORD; enforce that while constructing the
// host witness, before retaining an oversized step vector.
#[derive(Debug)]
struct WitnessBudgetExceeded;
impl std::fmt::Display for WitnessBudgetExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "native witness exceeds guest input byte bound")
    }
}
impl std::error::Error for WitnessBudgetExceeded {}
struct WitnessBudget {
    bytes: usize,
    exceeded: bool,
}
impl minicbor::encode::Write for WitnessBudget {
    type Error = std::io::Error;
    fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let Some(next) = self
            .bytes
            .checked_add(bytes.len())
            .filter(|n| *n <= MAX_RECORD)
        else {
            self.exceeded = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "native witness exceeds guest input byte bound",
            ));
        };
        self.bytes = next;
        Ok(())
    }
}
impl WitnessBudget {
    fn charge<T: minicbor::Encode<()>>(&mut self, value: &T) -> Result<()> {
        let result = value.encode(&mut minicbor::Encoder::new(&mut *self), &mut ());
        if self.exceeded {
            return Err(WitnessBudgetExceeded.into());
        }
        result?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct ProofContext {
    pub(crate) initial: Initial,
    pub(crate) state_index: Option<Arc<crate::state_index::StateIndex>>,
    pub(crate) state: Arc<State>,
    pub(crate) history: crate::history::History,
    pub(crate) proofs: crate::receipts::Receipts,
    pub(crate) mint_certificates: crate::mint_certificates::Certificates,
}
impl ProofContext {
    pub fn mint_claim_at(&self, at: u64) -> Result<rld_protocol::mints::index::Claim> {
        ensure!(at <= self.state.sequence, "future Mint root");
        if at == self.state.sequence {
            return self.state.mints.index_claim();
        }
        if at == 0 {
            return rld_protocol::mints::Mints::new(self.state.currency, self.state.domain)
                .index_claim();
        }
        let (_, snapshot) = self
            .history
            .material(at)?
            .context("Mint native history anchor")?;
        crate::state_storage::Backings::capture(&self.state)
            .historical(&snapshot)?
            .mint_claim()
    }
    pub fn next_mint_index_target(&self) -> Result<Option<u64>> {
        let Some((at, certificate)) = self.mint_certificates.latest()? else {
            return Ok(Some(0));
        };
        let current = self.mint_claim_at(self.state.sequence)?;
        if current == certificate.claim {
            return Ok(None);
        }
        ensure!(
            current.count > certificate.claim.count && at < self.state.sequence,
            "Mint correspondence count/prefix mismatch"
        );
        let (mut lo, mut hi) = (
            at.checked_add(1).context("Mint anchor exhaustion")?,
            self.state.sequence,
        );
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.mint_claim_at(mid)?.count > certificate.claim.count {
                hi = mid
            } else {
                lo = mid + 1
            }
        }
        Ok(Some(lo))
    }
    pub fn mint_index_input(&self, at: u64) -> Result<proof::NativeInput> {
        use rld_protocol::mints::index::{Append, Witness};
        let expected = self.mint_claim_at(at)?;
        let target = self.state_at(at)?;
        let base = self
            .mint_certificates
            .latest()?
            .filter(|(sequence, _)| *sequence <= at);
        let (mut prior, predecessor) = if let Some((sequence, certificate)) = base {
            rld_protocol::mints::index::verify(&self.initial.currency, &certificate)?;
            let state = self.state_at(sequence)?;
            ensure!(
                state.mints.index_claim()? == certificate.claim,
                "Mint correspondence base observation"
            );
            (state.mints, Some(certificate.as_ref().clone()))
        } else {
            (self.state.mints.empty_storage()?, None)
        };
        let mut witness = Witness {
            currency: self.initial.currency.clone(),
            home: self.state.domain,
            predecessor,
            complete: None,
            steps: vec![],
        };
        let budget = rld_protocol::permanent::capture::Budget::new(MAX_RECORD, 128)?;
        budget.charge(&witness)?;
        let result = (|| -> Result<()> {
            for value in target.mints.records() {
                let value = value?;
                if let Some(old) = prior.get(value.event)? {
                    ensure!(old == value, "changed prior Mint correspondence record");
                    continue;
                }
                if witness.steps.len() >= 4096 {
                    return Err(rld_protocol::permanent::capture::CaptureBudgetExceeded.into());
                }
                let (event, absence) = prior.access(value.event)?;
                ensure!(event.is_none(), "Mint correspondence event duplicate");
                let (slot, slot_absence) =
                    prior.slot_access(rld_protocol::mints::slot_key(value.root, value.slot))?;
                ensure!(slot.is_none(), "Mint correspondence slot duplicate");
                let step = Append {
                    record: value.clone(),
                    event_absence: absence.context("Mint event absence")?,
                    slot_absence: slot_absence.context("Mint slot absence")?,
                };
                budget.charge(&step)?;
                let old = prior.index_claim()?;
                let events = rld_protocol::merkle::insert_absent(
                    self.state.currency,
                    &format!("{}/mints", self.state.domain),
                    old.events,
                    &rld_protocol::table::Record::entry(&value, self.state.currency),
                    &step.event_absence,
                )?;
                let slot_record = rld_protocol::mints::Slot {
                    root: value.root,
                    slot: value.slot,
                    event: value.event,
                };
                let slots = rld_protocol::merkle::insert_absent(
                    self.state.currency,
                    &format!("{}/mint-slots-aux", self.state.domain),
                    old.slots,
                    &rld_protocol::table::Record::entry(&slot_record, self.state.currency),
                    &step.slot_absence,
                )?;
                prior.insert(value)?;
                let new = prior.index_claim()?;
                ensure!(
                    new.events == events && new.slots == slots,
                    "Mint correspondence compact/full update differs"
                );
                witness.steps.push(step);
            }
            ensure!(
                prior.index_claim()? == expected,
                "Mint correspondence target differs"
            );
            prior.seal()?;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(proof::NativeInput::MintIndex(witness)),
            Err(error)
                if error
                    .downcast_ref::<rld_protocol::merkle::CompleteSubtreeRequired>()
                    .is_some()
                    || error
                        .downcast_ref::<rld_protocol::permanent::capture::CaptureBudgetExceeded>()
                        .is_some() =>
            {
                let mut witness = Witness {
                    currency: self.initial.currency.clone(),
                    home: self.state.domain,
                    predecessor: None,
                    complete: Some(vec![]),
                    steps: vec![],
                };
                let budget = rld_protocol::permanent::capture::Budget::new(MAX_RECORD, 128)?;
                budget.charge(&witness)?;
                for value in target.mints.records() {
                    let value = value?;
                    budget.charge(&value)?;
                    witness
                        .complete
                        .as_mut()
                        .context("Mint complete fallback")?
                        .push(value)
                }
                Ok(proof::NativeInput::MintIndex(witness))
            }
            Err(error) => Err(error),
        }
    }
    pub fn cancel_draft(&self, id: Id) -> Result<(Controller, Cancellation)> {
        let c = self
            .state
            .controllers
            .iter()
            .find(|c| c.id == id)
            .context("controller")?
            .clone();
        let birth = self.state.births.get(id)?.context("birth")?;
        let h = self.history.at(birth.sequence)?.context("birth header")?;
        let context = self;
        let terminal = Terminal {
            currency: self.state.currency,
            controller: id,
            initial: hash("RLD-CONTROLLER", self.state.currency, &c),
            source_checkpoint: h.header.id(),
            decision: 2,
            ticket_or_return: proof::cancellation_digest(&c),
            material_root: Id::ZERO,
        };
        let cancel = Cancellation {
            controller: id,
            terminal,
            qc: Quorum { votes: vec![] },
            authorization: Authorization {
                owner: c.ticket.cancel_policy.clone(),
                signatures: vec![],
            },
            source_header: h.header.clone(),
            source_qc: h.qc.clone(),
            delegation: context.witness_at(birth.sequence, "controllers", id)?,
            coupon_use: context.witness_at(birth.sequence, "coupon_uses", c.ticket.coupon)?,
        };
        Ok((c, cancel))
    }
    pub fn query_at(
        &self,
        sequence: u64,
        collection: &str,
        key: Id,
    ) -> Result<crate::state_index::StateQuery> {
        let record = self
            .history
            .at(sequence)?
            .context("query requires a retained native checkpoint")?;
        if let Some(index) = &self.state_index {
            match index.query(&record.header, collection, key) {
                Ok(Some(query)) => return Ok(query),
                Ok(None) => {}
                Err(error) => index.note(&error),
            }
        }
        let state = self.state_at(sequence)?;
        ensure!(
            state.root()? == record.header.new_root,
            "query native replay root"
        );
        let top = state.top()?;
        let top_key = hash(
            "RLD-COLLECTION",
            state.currency,
            &(state.domain, collection),
        );
        let top_position = top
            .binary_search_by_key(&top_key, |e| e.key)
            .map_err(|_| anyhow::anyhow!("state collection"))?;
        let top = rld_protocol::merkle::prove(
            state.currency,
            &format!("{}/state", state.domain),
            &top,
            top_position,
        )?;
        let tag = format!("{}/{}", state.domain, collection);
        let (member, absence) =
            if let Some(query) = crate::state_storage::Backings::query(&state, collection, key)? {
                query
            } else {
                let entries = state.collection(collection)?;
                match entries.binary_search_by_key(&key, |e| e.key) {
                    Ok(i) => (
                        Some(rld_protocol::merkle::prove(
                            state.currency,
                            &tag,
                            &entries,
                            i,
                        )?),
                        None,
                    ),
                    Err(i) => (
                        None,
                        Some(rld_protocol::merkle::Absence {
                            left: if i > 0 {
                                Some(rld_protocol::merkle::prove(
                                    state.currency,
                                    &tag,
                                    &entries,
                                    i - 1,
                                )?)
                            } else {
                                None
                            },
                            right: if i < entries.len() {
                                Some(rld_protocol::merkle::prove(
                                    state.currency,
                                    &tag,
                                    &entries,
                                    i,
                                )?)
                            } else {
                                None
                            },
                            count: entries.len() as u64,
                        }),
                    ),
                }
            };
        let query = crate::state_index::StateQuery {
            collection: collection.into(),
            top,
            member,
            absence,
        };
        query.verify(&record.header, key)?;
        Ok(query)
    }
    pub fn witness_at(&self, sequence: u64, collection: &str, key: Id) -> Result<StateWitness> {
        if sequence == 0 {
            return self.state_at(0)?.witness(collection, key);
        }
        self.query_at(sequence, collection, key)?.membership()
    }
    pub fn state_at(&self, sequence: u64) -> Result<State> {
        ensure!(sequence <= self.state.sequence, "future state");
        if sequence == self.state.sequence {
            return Ok(self.state.as_ref().clone());
        }
        if let (Some(index), Some((record, snapshot))) =
            (&self.state_index, self.history.material(sequence)?)
        {
            match crate::state_storage::Backings::capture(&self.state)
                .historical(&snapshot)
                .and_then(|backings| index.load(&record.header, backings))
            {
                Ok(Some(state)) => return Ok(state),
                Ok(None) => {}
                Err(error) => index.note(&error),
            }
        }
        let mut s = State::genesis(&self.initial.currency, &self.initial.genesis)?;
        crate::state_storage::Backings::capture(&self.state)
            .empty()?
            .attach(&mut s)?;
        let mut head = rld_protocol::state::genesis_id(s.currency, &self.initial.genesis);
        for c in self.history.range(0, sequence) {
            let c = c?;
            let (mut next, h) = s.execute_batch(&self.initial.currency, head, &c.batch)?;
            ensure!(h == c.header, "retained history replay");
            crate::state_storage::Backings::seal(&mut next)?;
            head = h.id();
            s = next;
        }
        ensure!(s.sequence == sequence, "history gap");
        Ok(s)
    }
    fn native_base(&self, sequence: u64) -> Result<proof::NativeWitness> {
        ensure!(
            sequence > 0 && sequence <= self.state.sequence,
            "proof target"
        );
        let predecessor = self.proofs.before(sequence)?.map(|p| p.as_ref().clone());
        let base = predecessor.as_ref().map_or(0, |p| p.header.sequence);
        ensure!(
            sequence.checked_sub(base).is_some_and(|n| n <= 4096),
            "native proof span exceeds guest step bound; certify an intermediate checkpoint first"
        );
        let state = self.state_at(base)?;
        Ok(proof::NativeWitness {
            currency: self.initial.currency.clone(),
            genesis: if predecessor.is_none() {
                Some(self.initial.genesis.clone())
            } else {
                None
            },
            predecessor,
            state,
            steps: vec![],
        })
    }
    pub fn native_witness(&self, sequence: u64) -> Result<proof::NativeWitness> {
        let mut witness = self.native_base(sequence)?;
        let base = witness.state.sequence;
        // Reserve a conservative fixed allowance for NativeInput/array framing.
        let mut budget = WitnessBudget {
            bytes: 128,
            exceeded: false,
        };
        budget.charge(&witness)?;
        for c in self.history.range(base, sequence) {
            let c = c?;
            budget.charge(&(&c.batch, &c.header, &c.qc))?;
            witness.steps.push(proof::NativeStep {
                batch: c.batch.clone(),
                header: c.header.clone(),
                qc: c.qc.clone(),
            });
        }
        Ok(witness)
    }
    pub fn native_input(&self, sequence: u64) -> Result<proof::NativeInput> {
        let witness = self.native_base(sequence)?;
        if witness.predecessor.is_none() {
            return Ok(proof::NativeInput::Execution(
                self.native_witness(sequence)?,
            ));
        }
        let claim = witness.state.mints.index_claim()?;
        if let Some(certificate) = self.mint_certificates.get(claim.events)? {
            rld_protocol::mints::index::verify(&witness.currency, &certificate)?;
            ensure!(
                certificate.claim == claim,
                "native Mint correspondence differs from predecessor"
            );
            match self.indexed_mint(witness.clone(), sequence, (*certificate).clone()) {
                Ok(w) => return Ok(proof::NativeInput::IndexedMint(w)),
                Err(e) if e.downcast_ref::<rld_protocol::merkle::CompleteSubtreeRequired>().is_some()
                    || e.downcast_ref::<rld_protocol::permanent::capture::CaptureBudgetExceeded>().is_some() => {},
                Err(e) => return Err(e),
            }
        }
        match self.indexed_utxo(witness.clone(),sequence){
            Ok(w)=>return Ok(proof::NativeInput::IndexedUtxo(w)),
            Err(e) if e.downcast_ref::<rld_protocol::merkle::CompleteSubtreeRequired>().is_some()
                || e.downcast_ref::<rld_protocol::permanent::capture::CaptureBudgetExceeded>().is_some()=>{},
            Err(e)=>return Err(e),
        }
        match self.indexed_permanent(witness.clone(),sequence){
            Ok(w)=>return Ok(proof::NativeInput::IndexedPermanent(w)),
            Err(e) if e.downcast_ref::<rld_protocol::merkle::CompleteSubtreeRequired>().is_some()
                || e.downcast_ref::<rld_protocol::permanent::capture::CaptureBudgetExceeded>().is_some()=>{},
            Err(e)=>return Err(e),
        }
        match self.indexed_native(witness, sequence) {
            Ok(w) => Ok(proof::NativeInput::IndexedExecution(w)),
            Err(e)
                if e.downcast_ref::<rld_protocol::merkle::CompleteSubtreeRequired>()
                    .is_some()
                    || e.downcast_ref::<WitnessBudgetExceeded>().is_some() =>
            {
                Ok(proof::NativeInput::Execution(
                    self.native_witness(sequence)?,
                ))
            }
            Err(e) => Err(e),
        }
    }
    fn indexed_utxo(
        &self,
        n: proof::NativeWitness,
        sequence: u64,
    ) -> Result<proof::IndexedUtxoWitness> {
        let (native, outputs, _) = self.indexed_maps(n, sequence, true, None)?;
        Ok(proof::IndexedUtxoWitness {
            native,
            outputs: outputs.context("UTXO capture missing")?,
        })
    }
    fn indexed_permanent(
        &self,
        n: proof::NativeWitness,
        sequence: u64,
    ) -> Result<proof::IndexedPermanentWitness> {
        Ok(self.indexed_maps(n, sequence, false, None)?.0)
    }
    fn indexed_mint(
        &self,
        n: proof::NativeWitness,
        sequence: u64,
        certificate: rld_protocol::mints::index::Certificate,
    ) -> Result<proof::IndexedMintWitness> {
        let (native, outputs, mints) = self.indexed_maps(n, sequence, true, Some(certificate))?;
        Ok(proof::IndexedMintWitness {
            native: proof::IndexedUtxoWitness {
                native,
                outputs: outputs.context("Mint UTXO capture missing")?,
            },
            mints: mints.context("Mint capture missing")?,
        })
    }
    fn indexed_maps(
        &self,
        mut native: proof::NativeWitness,
        sequence: u64,
        include_outputs: bool,
        mint_certificate: Option<rld_protocol::mints::index::Certificate>,
    ) -> Result<(
        proof::IndexedPermanentWitness,
        Option<rld_protocol::permanent::access::Access<Output>>,
        Option<rld_protocol::mints::IndexedAccess>,
    )> {
        use rld_protocol::permanent::capture::Budget;
        let budget = Budget::new(MAX_RECORD, 128)?;
        let mut state = native.state.clone();
        let c = state.currency;
        let d = state.domain;
        let (map, births) =
            state
                .births
                .clone()
                .capture(c, &format!("{d}/births"), budget.clone())?;
        state.births = map;
        let (map, decisions) =
            state
                .decisions
                .clone()
                .capture(c, &format!("{d}/decisions"), budget.clone())?;
        state.decisions = map;
        let (map, redemptions) =
            state
                .redemptions
                .clone()
                .capture(c, &format!("{d}/redemptions"), budget.clone())?;
        state.redemptions = map;
        let (map, resolutions) =
            state
                .resolutions
                .clone()
                .capture(c, &format!("{d}/resolutions"), budget.clone())?;
        state.resolutions = map;
        let (map, funding) =
            state
                .used_funding
                .clone()
                .capture(c, &format!("{d}/funding"), budget.clone())?;
        state.used_funding = map;
        let outputs = if include_outputs {
            let (map, trace) = state.outputs.clone().capture(budget.clone())?;
            state.outputs = map;
            Some(trace)
        } else {
            None
        };
        let mints = if let Some(certificate) = &mint_certificate {
            ensure!(
                certificate.claim == state.mints.index_claim()?,
                "capture Mint correspondence base"
            );
            let (map, trace) = state.mints.clone().capture(budget.clone())?;
            state.mints = map;
            native.state.mints = rld_protocol::mints::Mints::new(c, d);
            budget.charge(&trace.metadata(certificate.clone()))?;
            Some(trace)
        } else {
            None
        };
        let base = state.sequence;
        let mut head = native
            .predecessor
            .as_ref()
            .context("indexed maps predecessor")?
            .header
            .id();
        let mut complete = state.applied.clone();
        let tag = format!("{d}/applied");
        let mut applied = complete.full_access(c, &tag)?;
        crate::state_storage::Backings::clear_permanent_material(&mut native.state);
        if let Some(trace) = &outputs {
            native.state.outputs = rld_protocol::utxo::Outputs::new(c, d);
            budget.charge(&trace.metadata())?;
        }
        budget.charge(&(
            &native,
            &applied,
            &births.metadata(),
            &decisions.metadata(),
            &redemptions.metadata(),
            &resolutions.metadata(),
            &funding.metadata(),
        ))?;
        for record in self.history.range(base, sequence) {
            let record = record?;
            budget.charge(&(&record.batch, &record.header, &record.qc))?;
            for op in &record.batch.operations {
                let id = op.id();
                let digest = Id::digest(&rld_protocol::codec::encode(op));
                let step = complete.access_step(id)?;
                budget.charge(&step)?;
                if let Some(old) = complete.get(id)? {
                    ensure!(old.digest == digest, "changed indexed maps operation");
                } else {
                    let root = rld_protocol::merkle::insert_absent(
                        c,
                        &tag,
                        complete.commitment(c, &tag)?,
                        &rld_protocol::merkle::Entry {
                            key: id,
                            value: digest,
                        },
                        step.absence
                            .as_ref()
                            .context("indexed maps operation absence")?,
                    )?;
                    complete.insert(Applied { id, digest })?;
                    ensure!(
                        complete.commitment(c, &tag)? == root,
                        "indexed maps operation root"
                    );
                }
                applied.steps.push(step);
            }
            let (mut next, header) = state.execute_batch(&native.currency, head, &record.batch)?;
            ensure!(
                header == record.header
                    && next.applied.commitment(c, &tag)? == complete.commitment(c, &tag)?,
                "captured native replay differs from verified history"
            );
            crate::state_storage::Backings::seal(&mut next)?;
            complete.seal_storage()?;
            head = header.id();
            state = next;
            native.steps.push(proof::NativeStep {
                batch: record.batch.clone(),
                header: record.header.clone(),
                qc: record.qc.clone(),
            });
        }
        // Capture extraction requires every execution observation to be gone.
        // Read-tracking is shared across clones; monetary roots remain per clone.
        drop(state);
        let permanent = proof::PermanentAccess {
            births: births.finish()?,
            decisions: decisions.finish()?,
            redemptions: redemptions.finish()?,
            resolutions: resolutions.finish()?,
            funding: funding.finish()?,
        };
        let outputs = outputs.map(|trace| trace.finish()).transpose()?;
        let mints = match (mints, mint_certificate) {
            (Some(trace), Some(certificate)) => Some(trace.finish(certificate)?),
            (None, None) => None,
            _ => anyhow::bail!("Mint capture/certificate mismatch"),
        };
        Ok((
            proof::IndexedPermanentWitness {
                native: proof::IndexedNativeWitness {
                    currency: native.currency,
                    predecessor: native.predecessor.context("indexed maps predecessor")?,
                    state: native.state,
                    steps: native.steps,
                    applied,
                },
                permanent,
            },
            outputs,
            mints,
        ))
    }
    fn indexed_native(
        &self,
        mut native: proof::NativeWitness,
        sequence: u64,
    ) -> Result<proof::IndexedNativeWitness> {
        let c = native.state.currency;
        let tag = format!("{}/applied", native.state.domain);
        let base = native.state.sequence;
        let mut complete = native.state.applied.clone();
        let mut access = complete.full_access(c, &tag)?;
        native.state.applied = rld_protocol::applied::AppliedIndex::new(c, &tag);
        let mut budget = WitnessBudget {
            bytes: 128,
            exceeded: false,
        };
        budget.charge(&(&native, &access))?;
        for record in self.history.range(base, sequence) {
            let record = record?;
            budget.charge(&(&record.batch, &record.header, &record.qc))?;
            for op in &record.batch.operations {
                let id = op.id();
                let digest = Id::digest(&rld_protocol::codec::encode(op));
                let step = complete.access_step(id)?;
                budget.charge(&step)?;
                if let Some(old) = complete.get(id)? {
                    ensure!(
                        old.digest == digest,
                        "changed retained operation in proof input"
                    );
                } else {
                    let root = rld_protocol::merkle::insert_absent(
                        c,
                        &tag,
                        complete.commitment(c, &tag)?,
                        &rld_protocol::merkle::Entry {
                            key: id,
                            value: digest,
                        },
                        step.absence.as_ref().context("new operation absence")?,
                    )?;
                    complete.insert(Applied { id, digest })?;
                    ensure!(
                        root == complete.commitment(c, &tag)?,
                        "indexed and complete applied roots differ"
                    );
                }
                access.steps.push(step);
            }
            complete.seal_storage()?;
            native.steps.push(proof::NativeStep {
                batch: record.batch.clone(),
                header: record.header.clone(),
                qc: record.qc.clone(),
            });
        }
        Ok(proof::IndexedNativeWitness {
            currency: native.currency,
            predecessor: native.predecessor.context("indexed native predecessor")?,
            state: native.state,
            steps: native.steps,
            applied: access,
        })
    }
    pub fn creation(&self, id: Id) -> Result<Creation> {
        let controller = self
            .state
            .controllers
            .iter()
            .find(|c| c.id == id)
            .context("controller")?
            .clone();
        let birth = self.state.births.get(id)?.context("birth")?;
        let certified = self
            .proofs
            .get(birth.sequence)?
            .context("historical creation proof is not ready")?
            .as_ref()
            .clone();
        Ok(Creation {
            delegation: self.witness_at(birth.sequence, "controllers", id)?,
            coupon_use: self.witness_at(birth.sequence, "coupon_uses", controller.ticket.coupon)?,
            controller,
            source: certified,
        })
    }
    pub fn controller_witness(&self, id: Id) -> Result<proof::ControllerWitness> {
        let creation = self.creation(id)?;
        let c = &creation.controller;
        let birth = self.state.births.get(id)?.context("controller birth")?;
        let born = self
            .history
            .at(birth.sequence)?
            .and_then(|record| {
                record
                    .batch
                    .operations
                    .iter()
                    .find_map(|op| match &op.command {
                        Command::PreparePayment {
                            ticket, material, ..
                        }
                        | Command::PrepareClaim {
                            ticket, material, ..
                        } if ticket.id == id => Some(material.clone()),
                        _ => None,
                    })
            })
            .context("retained preparation material")?;
        let m: Material = decode(&born.0, rld_protocol::MAX_CAPSULE)?;
        let terminal = Terminal {
            currency: c.configuration.currency,
            controller: id,
            initial: hash("RLD-CONTROLLER", c.configuration.currency, c),
            source_checkpoint: creation.source.header.id(),
            decision: 1,
            ticket_or_return: c.ticket.digest(c.configuration.currency),
            material_root: c.material_root,
        };
        Ok(proof::ControllerWitness {
            currency: self.initial.currency.clone(),
            creation,
            terminal,
            material: born,
            covers: m.covers,
            cancellation_authorization: None,
        })
    }
}
