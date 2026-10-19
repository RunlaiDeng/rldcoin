//! Bounded block-only ingress. Peer bytes never approve or sign a payment.
use super::{hash, Action, Id, Session};
use crate::{
    fast_payment::ensure,
    fast_peer::Network,
    kernel::{fast, Result},
};
use serde_json::{json, Value};
#[derive(Default)]
pub struct Ingress {
    cursor: usize,
    diagnostic: Option<String>,
}
impl Ingress {
    /// Select at most one retained incoming block. Missing parents, clocks and
    /// capacity retain the packet for later rounds; no failed caller intent is
    /// written until full nonmutating native prevalidation has succeeded.
    pub fn tick(&mut self, s: &mut Session, n: &mut Network, now: u64) -> Result<()> {
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
        s.check_control(s.head())?;
        ensure(
            n.status()["head_control"] == "TRUSTED_FILE",
            "INVALID automatic ingress requires trusted peer control",
        )?;
        let ids = n.received_ids(1)?;
        if ids.is_empty() {
            return Ok(());
        }
        let id = ids[self.cursor % ids.len()];
        self.cursor = (self.cursor + 1) % ids.len();
        let p = n.received(id)?;
        ensure(p.kind == 1, "INVALID automatic native packet kind")?;
        let tip = s.tip();
        let prior = s.head();
        let native = s
            .native
            .as_mut()
            .ok_or("RESOURCE_WAIT automatic native restart required")?;
        if native.precheck(&p.payload, native.head(), tip, now)? {
            return Ok(());
        }
        let block = fast::block_id(&p.payload)?;
        let request = Id(hash(
            "AUTO-BLOCK",
            &[s.chain.as_slice(), &block, &prior].concat(),
        ));
        s.execute(
            request,
            prior,
            Action::Native {
                tip: Id(tip),
                block: hex::encode(p.payload),
            },
            None,
            now,
        )?;
        self.diagnostic = None;
        Ok(())
    }
    pub fn status(&self) -> Value {
        json!({"enabled":true,"scope":"NATIVE_BLOCKS_ONLY","diagnostic":self.diagnostic,
            "owner_approval":false,"key_loading":false,"fee_monitoring":false,"independent_freshness":false})
    }
}
