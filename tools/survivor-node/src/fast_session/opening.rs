//! Own-input review and existing-signature combination for native kind1.
use super::transfer::Preparation;
use super::*;
use crate::kernel::fast::opening;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpeningTerms {
    pub nonce: Id,
    pub owners: [Id; 2],
    pub principal: [String; 2],
    pub limits: [String; 2],
    pub rates: [String; 2],
    pub fees: [String; 2],
    pub expiry: String,
    pub inputs: [Vec<String>; 2],
}
impl OpeningTerms {
    fn native(&self) -> Result<opening::OpeningTerms> {
        ensure(
            self.inputs.iter().all(|v| (1..=32).contains(&v.len())),
            "INVALID opening input count",
        )?;
        let inputs = self
            .inputs
            .iter()
            .map(|v| {
                v.iter()
                    .map(|s| {
                        let raw = bytes(s, 34)?;
                        ensure(raw.len() == 34, "INVALID opening input size")?;
                        Ok(raw)
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .collect::<Result<Vec<_>>>()?;
        let ints = |v: &[String; 2]| -> Result<[u128; 2]> {
            Ok([onchain::integer(&v[0])?, onchain::integer(&v[1])?])
        };
        let limits = ints(&self.limits)?;
        Ok(opening::OpeningTerms {
            nonce: self.nonce.0,
            owners: self.owners.map(|i| i.0),
            principal: ints(&self.principal)?,
            limits: [
                u64::try_from(limits[0]).map_err(|_| "INVALID opening slots")?,
                u64::try_from(limits[1]).map_err(|_| "INVALID opening slots")?,
            ],
            rates: ints(&self.rates)?,
            fees: ints(&self.fees)?,
            expiry: onchain::integer(&self.expiry)?,
            inputs: inputs.try_into().map_err(|_| "INVALID opening inputs")?,
        })
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpeningRequest {
    pub proposal: String,
    pub owner: u8,
    pub timestamp: String,
}
impl OpeningRequest {
    pub(super) fn parts(&self) -> Result<(Vec<u8>, u64)> {
        ensure(self.owner < 2, "INVALID opening own index")?;
        let raw = bytes(&self.proposal, 2473)?;
        ensure(raw.len() >= 365, "INVALID opening proposal length")?;
        opening::proposal_id(&raw, raw[5..37].try_into().unwrap())?;
        Ok((
            raw,
            u64::try_from(onchain::integer(&self.timestamp)?)
                .map_err(|_| "INVALID opening timestamp")?,
        ))
    }
    pub(super) fn inputs(&self) -> Result<Vec<Vec<u8>>> {
        let (raw, _) = self.parts()?;
        opening::proposal_inputs(&raw, self.owner, raw[5..37].try_into().unwrap())
    }
    pub(super) fn reservation(&self) -> Result<Hash> {
        let mut exact = self.clone();
        exact.timestamp.clear();
        Ok(hash(
            "OPEN-RESERVATION",
            &serde_json::to_vec(&exact).map_err(fast_retainer::io)?,
        ))
    }
}
pub(super) fn review_json(plan: &opening::OpeningPlan, owner: u8) -> Value {
    json!({"operation":"OPEN","chain_selected_tip":Id(plan.selected_tip()),"evaluation_timestamp":plan.timestamp().to_string(),"own_index":owner,"owners":plan.owners().map(Id),"proposal":Id(plan.proposal()),
        "input_values":plan.input_values.map(|v|v.to_string()),"inputs":plan.inputs().iter().map(|v|v.iter().map(hex::encode).collect::<Vec<_>>()).collect::<Vec<_>>(),
        "principal":plan.principal().map(|v|v.to_string()),"limits":plan.limits().map(|v|v.to_string()),
        "rates":plan.rates().map(|v|v.to_string()),"operation_fees":plan.fees().map(|v|v.to_string()),"change":plan.change().map(|v|v.to_string()),
        "expiry_height":plan.expiry().to_string(),"unsigned_operation_hex":hex::encode(plan.unsigned()),"ledger_admitted":false})
}
impl Session {
    pub fn opening_data(
        &mut self,
        head: Hash,
        request: Id,
        now: u64,
    ) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
        self.status(head, now)?;
        let index = self
            .caller
            .ops
            .iter()
            .position(|op| op.intent.id == request)
            .ok_or("MISSING opening source request")?;
        let op = self.caller.ops[index].clone();
        if let Action::OpenPrepare { plan, .. } = &op.intent.action {
            ensure(
                op.done.as_ref().is_some_and(|d| d.review.is_some()),
                "MISSING retained opening review",
            )?;
            let (raw, _) = plan.parts()?;
            opening::proposal_id(&raw, self.chain)?;
            return Ok((raw, None));
        }
        let (plan, partial) = self
            .opening_signature(index, &op.intent.action)?
            .ok_or("INVALID opening source request type")?;
        let (raw, _) = plan.parts()?;
        Ok((raw, Some(partial)))
    }
    pub fn opening_proposal(
        &mut self,
        head: Hash,
        terms: OpeningTerms,
        timestamp: String,
        now: u64,
    ) -> Result<Value> {
        self.status(head, now)?;
        let time = u64::try_from(onchain::integer(&timestamp)?)
            .map_err(|_| "INVALID opening timestamp")?;
        let n = self.native.as_mut().unwrap();
        let tip = n.ledger().tip().id();
        let current = n.current(n.head(), tip, now)?;
        let plan = current
            .ledger
            .propose_opening(tip, &terms.native()?, time, now)?;
        Ok(
            json!({"proposal":Id(plan.proposal()),"proposal_hex":hex::encode(plan.unsigned()),"change":plan.change().map(|v|v.to_string()),"candidate_only":true,"ledger_admitted":false,"owner_signature_created":false}),
        )
    }
    pub(super) fn opening_signature(
        &self,
        index: usize,
        action: &Action,
    ) -> Result<Option<(OpeningRequest, Vec<u8>)>> {
        let Action::OnchainSign {
            prepare_request,
            review,
            ..
        } = action
        else {
            return Ok(None);
        };
        let (_, plan, _) = self.prepared(index, *prepare_request, *review)?;
        let Preparation::Opening(request) = plan else {
            return Ok(None);
        };
        let raw = bytes(
            self.caller.ops[index]
                .done
                .as_ref()
                .and_then(|d| d.authorization.as_ref())
                .ok_or("MISSING opening partial")?,
            65,
        )?;
        let (proposal, _) = request.parts()?;
        ensure(
            opening::verify_partial(&proposal, &raw, self.chain)? == request.owner,
            "INVALID own opening signature",
        )?;
        Ok(Some((request, raw)))
    }
    pub(super) fn combine_opening(
        &mut self,
        before: usize,
        action: &Action,
        at: u64,
        current: bool,
    ) -> Result<Vec<u8>> {
        let Action::OpenCombine {
            tip,
            prepare_request,
            sign_request,
            review,
            counterparty_partial,
        } = action
        else {
            return Err("INVALID opening combine type".into());
        };
        let (_, prepared, original) = self.prepared(before, *prepare_request, *review)?;
        let Preparation::Opening(request) = prepared else {
            return Err("INVALID opening preparation type".into());
        };
        ensure(original == tip.0, "INVALID opening original review tip")?;
        let index = self.caller.ops[..before]
            .iter()
            .position(|op| op.intent.id == *sign_request)
            .ok_or("MISSING retained own opening signature")?;
        let sign_action = self.caller.ops[index].intent.action.clone();
        ensure(
            matches!(&sign_action,Action::OnchainSign{tip:t,prepare_request:p,review:r,approved:true,..} if *t==*tip && *p==*prepare_request && *r==*review),
            "INVALID own opening signature binding",
        )?;
        let (_, own) = self
            .opening_signature(index, &sign_action)?
            .ok_or("INVALID own opening signature type")?;
        let (proposal, timestamp) = request.parts()?;
        let partner = bytes(counterparty_partial, 65)?;
        let n = self.native.as_mut().unwrap();
        let plan = if current {
            let view = n.current(n.head(), tip.0, at)?;
            view.ledger.plan_opening(tip.0, &proposal, timestamp, at)?
        } else {
            n.historical(tip.0)?
                .plan_opening(tip.0, &proposal, timestamp, at)?
        };
        ensure(
            plan.review(request.owner)? == review.0,
            "INVALID opening combination review",
        )?;
        plan.combine(&own, &partner)
    }
    pub(super) fn retained_authorization(&mut self, index: usize) -> Result<Vec<u8>> {
        let op = self.caller.ops[index].clone();
        if matches!(op.intent.action, Action::OpenCombine { .. }) {
            let expected = op
                .done
                .as_ref()
                .and_then(|d| d.review)
                .ok_or("MISSING complete opening reply")?;
            let raw = self.combine_opening(index, &op.intent.action, op.intent.at, false)?;
            ensure(
                fast::operation_id(&raw) == expected.0,
                "INVALID complete opening commitment",
            )?;
            return Ok(raw);
        }
        ensure(
            matches!(op.intent.action, Action::OnchainSign { .. }),
            "INVALID native signing request type",
        )?;
        ensure(
            self.opening_signature(index, &op.intent.action)?.is_none(),
            "INVALID opening partial is not a complete operation",
        )?;
        let raw = bytes(
            op.done
                .as_ref()
                .and_then(|d| d.authorization.as_ref())
                .ok_or("MISSING retained native authorization")?,
            4096,
        )?;
        fast::validate_operation(&raw, self.chain)?;
        Ok(raw)
    }
}
