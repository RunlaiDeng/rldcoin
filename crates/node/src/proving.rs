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
    pub(crate) state: Arc<State>,
    pub(crate) history: crate::history::History,
    pub(crate) proofs: Arc<Vec<Certified>>,
}
impl ProofContext {
    pub fn state_at(&self, sequence: u64) -> Result<State> {
        ensure!(sequence <= self.state.sequence, "future state");
        if sequence == self.state.sequence {
            return Ok(self.state.as_ref().clone());
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
        let predecessor = self
            .proofs
            .iter()
            .filter(|p| p.header.sequence < sequence)
            .max_by_key(|p| p.header.sequence)
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
        let certified = self
            .proofs
            .iter()
            .find(|p| p.header.sequence == birth.sequence)
            .context("historical creation proof is not ready")?
            .clone();
        let state = self.state_at(birth.sequence)?;
        Ok(Creation {
            delegation: state.witness("controllers", id)?,
            coupon_use: state.witness("coupon_uses", controller.ticket.coupon)?,
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
