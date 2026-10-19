//! Current owner observations never approve/sign or make historical value usable.
use super::*;
impl Session {
    pub fn owner_state(&mut self, expected: Hash, actor: Id, now: u64) -> Result<Value> {
        let mut out = self.status(expected, now)?;
        let state = self
            .actors
            .get(&actor)
            .ok_or("MISSING owner observation actor")?;
        ensure(state.reg.role < 2, "INVALID owner observation role")?;
        let mut child = fast_owner::Journal::open(
            &actor_path(&self.root, actor),
            self.chain,
            state.head,
            now,
            CHILD_LIMIT,
        )?;
        let (origin, delegation, owner) = child.scope();
        let view = child.observation(state.head)?;
        let native = self
            .native
            .as_mut()
            .ok_or("RESOURCE_WAIT owner observation native restart")?;
        let tip = native.ledger().tip().id();
        let current = native.current(native.head(), tip, now)?;
        let backing = origin.check_current(current.ledger, tip, now);
        let own = owner as usize;
        let remaining = origin
            .slot_limit(own)?
            .checked_sub(view.slots[own])
            .ok_or("INVALID retained owner fee slots")?;
        let rates = [origin.rate(0)?, origin.rate(1)?];
        let fee = rates[0]
            .checked_mul(view.slots[0] as u128)
            .and_then(|a| rates[1].checked_mul(view.slots[1] as u128)?.checked_add(a))
            .ok_or("INVALID retained owner fee sum")?;
        let available =
            backing.is_ok() && view.pending.is_none() && remaining > 0 && view.balances[own] > 0;
        let pending = if let Some(p) = view.pending {
            let age = now
                .checked_sub(p.prepared_at)
                .ok_or("CLOCK_WAIT original owner preparation")?;
            json!({"invoice":Id(p.invoice),"logical_payment":Id(p.logical),"amount":p.amount.to_string(),"fee":p.fee.to_string(),
                "sequence":p.sequence.to_string(),"own_signature_retained":p.signed,"original_prepared_at":p.prepared_at.to_string(),
                "original_prepared_native_tip":Id(p.prepared_native),"original_pending_age_seconds":age.to_string()})
        } else {
            Value::Null
        };
        out["actor"] = json!(actor);
        out["actor_head"] = json!(Id(state.head));
        out["channel"] = json!(Id(origin.channel()));
        out["owner"] = json!(Id(origin.owners()[own]));
        out["own_index"] = owner.into();
        out["funding_miner"] = json!(Id(origin.miner()));
        out["delegated_retainer"] = json!(Id(delegation.retainer()));
        out["retained_state_sequence"] = view.sequence.to_string().into();
        out["complete_receipt_retained"] = (view.sequence > 0).into();
        out["retained_principal"] = view.balances[own].to_string().into();
        out["retained_fee_slots"] = json!(view.slots.map(|n| n.to_string()));
        out["retained_miner_fee_entitlement"] = fee.to_string().into();
        out["remaining_own_fee_slots"] = remaining.to_string().into();
        out["next_protocol_fee"] = origin.rate(own)?.to_string().into();
        out["native_backing_usable_now"] = backing.is_ok().into();
        out["native_backing_diagnostic"] = backing.err().map(Value::String).unwrap_or(Value::Null);
        out["conditional_onward_state_available"] = available.into();
        out["conditional_onward_principal"] = if available {
            view.balances[own].to_string().into()
        } else {
            Value::Null
        };
        out["pending_payment"] = pending;
        out["owner_spend_authorized"] = false.into();
        out["wallet_key_loaded"] = false.into();
        out["native_payout_status"] = "NOT_EVALUATED".into();
        out["observation_only"] = true.into();
        Ok(out)
    }
}
