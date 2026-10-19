//! Bounded native/data ingress. Peer custody never approves or signs a payment.
use super::{hash, Action, Id, Session};
use crate::{
    fast_payment::ensure,
    fast_peer::{codec, Network},
    kernel::{fast, Hash, Result},
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Default)]
pub struct Ingress {
    cursor: usize,
    diagnostic: Option<String>,
    full_sync: bool,
    binding: Option<(Hash, Hash, Hash)>,
    complete: BTreeSet<Hash>,
    deferred: BTreeMap<Hash, (Hash, u64, String)>,
    pending: bool,
    progressed: bool,
}
impl Ingress {
    pub fn synchronized() -> Self {
        Self {
            full_sync: true,
            ..Self::default()
        }
    }
    pub fn work_pending(&self) -> bool {
        self.full_sync && (self.pending || self.progressed)
    }
    /// One retained packet and at most four newly admitted full blocks per tick.
    /// Unknown parents/time/capacity remain retained. Complete authentication and
    /// native prevalidation precede any new caller intent; no key is loaded.
    pub fn tick(&mut self, s: &mut Session, n: &mut Network, now: u64) -> Result<()> {
        self.progressed = false;
        self.pending = false;
        let result = self.step(s, n, now);
        if let Err(e) = &result {
            self.diagnostic = Some(e.clone());
        }
        result
    }
    fn step(&mut self, s: &mut Session, n: &mut Network, now: u64) -> Result<()> {
        ensure(
            s.controlled(),
            "INVALID automatic ingress requires trusted caller control",
        )?;
        s.status(s.head(), now)?;
        ensure(
            n.status()["head_control"] == "TRUSTED_FILE",
            "INVALID automatic ingress requires trusted peer control",
        )?;
        ensure(
            n.local_scope().0 == s.chain,
            "INVALID automatic ingress currency",
        )?;
        let binding = (s.chain, s.caller.binding(), n.local_scope().1);
        if let Some(old) = self.binding {
            ensure(old == binding, "INVALID automatic ingress runtime binding")?;
        } else {
            self.binding = Some(binding);
        }
        let mut ids = n.received_ids(1)?;
        if self.full_sync {
            ids.extend(n.received_ids(9)?);
            ids.extend(n.received_ids(6)?);
            let native = s.native_head();
            ids.retain(|id| {
                !self.complete.contains(id)
                    && self
                        .deferred
                        .get(id)
                        .is_none_or(|(head, at, _)| *head != native || now > *at)
            });
        }
        if ids.is_empty() {
            return Ok(());
        }
        self.pending = true;
        let id = ids[self.cursor % ids.len()];
        self.cursor = (self.cursor + 1) % ids.len();
        let packet = n.received(id)?;
        let result = match packet.kind {
            1 => self.blocks(s, &[packet.payload.as_slice()], now),
            9 if self.full_sync => {
                let (_, blocks) = codec::decode_block_batch(&packet.payload, s.chain)?;
                self.blocks(s, &blocks, now)
            }
            6 if self.full_sync => {
                self.operation(s, codec::operation(&packet.payload, s.chain)?, now)
            }
            _ => Err("INVALID automatic native packet kind".into()),
        };
        match result {
            Ok(done) => {
                self.deferred.remove(&id);
                self.diagnostic = None;
                if self.full_sync && done {
                    ensure(
                        self.complete.len() < 2048 || self.complete.contains(&id),
                        "RESOURCE_WAIT completed ingress observations",
                    )?;
                    self.complete.insert(id);
                }
                Ok(())
            }
            Err(e) => {
                if self.full_sync {
                    self.deferred.insert(id, (s.native_head(), now, e.clone()));
                    // Deferring this packet does not defer another packet
                    // already eligible under the same local context.
                    self.pending = ids.len() > 1;
                }
                Err(e)
            }
        }
    }
    fn blocks(&mut self, s: &mut Session, blocks: &[&[u8]], now: u64) -> Result<bool> {
        let mut added = 0;
        for raw in blocks {
            let tip = s.tip();
            let prior = s.head();
            let native = s
                .native
                .as_mut()
                .ok_or("RESOURCE_WAIT automatic native restart required")?;
            if native.precheck(raw, native.head(), tip, now)? {
                continue;
            }
            if added == 4 {
                return Ok(false);
            }
            let block = fast::block_id(raw)?;
            let request = Id(hash(
                "AUTO-BLOCK",
                &[s.chain.as_slice(), &block, &prior].concat(),
            ));
            let out = s.execute(
                request,
                prior,
                Action::Native {
                    tip: Id(tip),
                    block: hex::encode(raw),
                },
                None,
                now,
            )?;
            if let Some(error) = out["diagnostic"].as_str() {
                return Err(error.to_string());
            }
            self.progressed = true;
            added += 1;
        }
        Ok(true)
    }
    fn operation(&mut self, s: &mut Session, raw: &[u8], now: u64) -> Result<bool> {
        let id = fast::operation_id(raw);
        for (known, bytes) in s.carriage_pool()? {
            if known == id {
                ensure(bytes == raw, "INVALID incoming changed operation identity")?;
                return Ok(true);
            }
        }
        let request = Id(hash(
            "AUTO-SIGNED-POOL",
            &[s.chain.as_slice(), &id, &s.head()].concat(),
        ));
        let out = s.execute(
            request,
            s.head(),
            Action::PoolSubmit {
                tip: Id(s.tip()),
                operation: hex::encode(raw),
            },
            None,
            now,
        )?;
        if let Some(error) = out["diagnostic"].as_str() {
            return Err(error.to_string());
        }
        self.progressed = true;
        Ok(true)
    }
    pub fn status(&self) -> Value {
        json!({"enabled":true,"scope":if self.full_sync{"NATIVE_BLOCKS_AND_EXISTING_SIGNATURES"}else{"NATIVE_BLOCKS_ONLY"},"diagnostic":self.diagnostic,
            "completed_packet_observations":self.complete.len(),"deferred_packets":self.deferred.iter().map(|(id,(_,at,e))|json!({"packet":Id(*id),"last_attempt_at":at.to_string(),"diagnostic":e})).collect::<Vec<_>>(),
            "work_pending":self.work_pending(),"owner_approval":false,"key_loading":false,"fee_monitoring":false,"independent_freshness":false})
    }
}
