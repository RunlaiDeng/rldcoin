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
}
impl ProofContext {
    pub fn cancel_draft(&self, id: Id) -> Result<(Controller, Cancellation)> {
        let c = self
            .state
            .controllers
            .iter()
            .find(|c| c.id == id)
            .context("controller")?
            .clone();
        let birth = self
            .state
            .births
            .iter()
            .find(|b| b.controller == id)
            .context("birth")?;
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
        let (member, absence) = if collection == "applied" {
            let step = state.applied.access_step(key)?;
            (step.member, step.absence)
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
            match self
                .state
                .applied
                .historical_storage(&snapshot)
                .and_then(|applied| index.load(&record.header, applied))
            {
                Ok(Some(state)) => return Ok(state),
                Ok(None) => {}
                Err(error) => index.note(&error),
            }
        }
        let mut s = State::genesis(&self.initial.currency, &self.initial.genesis)?;
        s.applied = self.state.applied.empty_storage()?;
        let mut head = rld_protocol::state::genesis_id(s.currency, &self.initial.genesis);
        for c in self.history.range(0, sequence) {
            let c = c?;
            let (mut next, h) = s.execute_batch(&self.initial.currency, head, &c.batch)?;
            ensure!(h == c.header, "retained history replay");
            next.applied.seal_storage()?;
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
        let birth = self
            .state
            .births
            .iter()
            .find(|b| b.controller == id)
            .context("birth")?;
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
        let birth = self
            .state
            .births
            .iter()
            .find(|b| b.controller == id)
            .context("controller birth")?;
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
