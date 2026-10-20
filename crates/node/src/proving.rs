//! Immutable authenticated host observations for building proof witnesses.
//! These carry no signing authority. Publication still rechecks the exact real
//! receipt and its retained local checkpoint in the live native executor.
use crate::runtime::Initial;
use anyhow::{Context, Result, ensure};
use rld_protocol::{
    codec::{Id, decode, hash},
    model::*,
    proof,
    state::State,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct ProofContext {
    pub(crate) initial: Initial,
    pub(crate) state_index: Option<Arc<crate::state_index::StateIndex>>,
    pub(crate) state: Arc<State>,
    pub(crate) history: crate::history::History,
    pub(crate) proofs: Arc<Vec<Certified>>,
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
        let h = self.history.at(birth.sequence).context("birth header")?;
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
            .at(sequence)
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
        let entries = state.collection(collection)?;
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
        let (member, absence) = match entries.binary_search_by_key(&key, |e| e.key) {
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
        if let (Some(index), Some(record)) = (&self.state_index, self.history.at(sequence)) {
            match index.load(&record.header) {
                Ok(Some(state)) => return Ok(state),
                Ok(None) => {}
                Err(error) => index.note(&error),
            }
        }
        let mut s = State::genesis(&self.initial.currency, &self.initial.genesis)?;
        let mut head = rld_protocol::state::genesis_id(s.currency, &self.initial.genesis);
        for c in self
            .history
            .iter()
            .take_while(|c| c.header.sequence <= sequence)
        {
            let (next, h) = s.execute_batch(&self.initial.currency, head, &c.batch)?;
            ensure!(h == c.header, "retained history replay");
            head = h.id();
            s = next;
        }
        ensure!(s.sequence == sequence, "history gap");
        Ok(s)
    }
    pub fn native_witness(&self, sequence: u64) -> Result<proof::NativeWitness> {
        ensure!(
            sequence > 0 && sequence <= self.state.sequence,
            "proof target"
        );
        let position = self
            .proofs
            .partition_point(|p| p.header.sequence < sequence);
        let predecessor = position
            .checked_sub(1)
            .and_then(|i| self.proofs.get(i))
            .cloned();
        let base = predecessor.as_ref().map_or(0, |p| p.header.sequence);
        let state = self.state_at(base)?;
        let steps = self
            .history
            .after(base)
            .take_while(|c| c.header.sequence <= sequence)
            .map(|c| proof::NativeStep {
                batch: c.batch.clone(),
                header: c.header.clone(),
                qc: c.qc.clone(),
            })
            .collect();
        Ok(proof::NativeWitness {
            currency: self.initial.currency.clone(),
            genesis: if predecessor.is_none() {
                Some(self.initial.genesis.clone())
            } else {
                None
            },
            predecessor,
            state,
            steps,
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
        let position = self
            .proofs
            .binary_search_by_key(&birth.sequence, |p| p.header.sequence)
            .map_err(|_| anyhow::anyhow!("historical creation proof is not ready"))?;
        let certified = self.proofs[position].clone();
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
            .at(birth.sequence)
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
