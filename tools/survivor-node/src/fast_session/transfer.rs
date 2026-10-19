//! Typed ordinary funding intent; existing escrow preparation bytes are unchanged.
use super::*;
use crate::kernel::fast::{planning::Plan, transfer::TransferPlan};
use ed25519_dalek::Signer;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferOutput {
    pub owner: Id,
    pub amount: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferRequest {
    pub owner: Id,
    pub inputs: Vec<String>,
    pub outputs: Vec<TransferOutput>,
    pub fee: String,
    pub expiry: String,
    pub timestamp: String,
}
impl TransferRequest {
    pub(super) fn request(&self) -> Result<fast::transfer::TransferRequest> {
        ensure(
            (1..=32).contains(&self.inputs.len()) && (1..=8).contains(&self.outputs.len()),
            "INVALID native transfer counts",
        )?;
        let inputs = self
            .inputs
            .iter()
            .map(|input| {
                let raw = bytes(input, 34)?;
                ensure(raw.len() == 34, "INVALID native transfer input size")?;
                Ok(raw)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(fast::transfer::TransferRequest {
            owner: self.owner.0,
            inputs,
            outputs: self
                .outputs
                .iter()
                .map(|output| Ok((output.owner.0, onchain::integer(&output.amount)?)))
                .collect::<Result<Vec<_>>>()?,
            fee: onchain::integer(&self.fee)?,
            expiry: onchain::integer(&self.expiry)?,
            timestamp: u64::try_from(onchain::integer(&self.timestamp)?)
                .map_err(|_| "INVALID native transfer timestamp")?,
        })
    }
    fn reservation(&self) -> Result<Hash> {
        let mut exact = self.clone();
        exact.timestamp.clear();
        Ok(hash(
            "TRANSFER-RESERVATION",
            &serde_json::to_vec(&exact).map_err(fast_retainer::io)?,
        ))
    }
}
#[derive(Clone)]
pub(super) enum Preparation {
    Delegation { channel: Id, retainer: Id },
    Opening(OpeningRequest),
    Escrow(OnchainRequest),
    Transfer(TransferRequest),
}
pub(super) enum Evaluation {
    Delegation(fast::FundingOrigin, Vec<u8>, Hash),
    Opening(crate::kernel::fast::opening::OpeningPlan, u8, Hash),
    Escrow(Plan),
    Transfer(TransferPlan),
}
impl Preparation {
    pub(super) fn inputs(&self) -> Result<Vec<Vec<u8>>> {
        match self {
            Self::Delegation { .. } => Ok(vec![]),
            Self::Opening(p) => p.inputs(),
            Self::Escrow(p) => Ok(p.request()?.inputs),
            Self::Transfer(p) => Ok(p.request()?.inputs),
        }
    }
    pub(super) fn reservation(&self) -> Result<Hash> {
        match self {
            Self::Delegation { channel, retainer } => Ok(hash(
                "DELEGATION-RESERVATION",
                &[channel.0, retainer.0].concat(),
            )),
            Self::Opening(p) => p.reservation(),
            Self::Escrow(p) => p.reservation(),
            Self::Transfer(p) => p.reservation(),
        }
    }
    pub(super) fn evaluate(
        &self,
        ledger: &fast::Ledger,
        tip: Hash,
        now: u64,
    ) -> Result<Evaluation> {
        match self {
            Self::Delegation { channel, retainer } => {
                let origin = ledger.funding_origin(channel.0)?;
                origin.check_current(ledger, tip, now)?;
                let unsigned = Delegation::unsigned(&origin, retainer.0)?;
                let review = hash(
                    "MINER-DELEGATION-REVIEW",
                    &[tip.as_slice(), unsigned.as_slice()].concat(),
                );
                Ok(Evaluation::Delegation(origin, unsigned, review))
            }
            Self::Opening(p) => {
                let (raw, time) = p.parts()?;
                let plan = ledger.plan_opening(tip, &raw, time, now)?;
                let review = plan.review(p.owner)?;
                Ok(Evaluation::Opening(plan, p.owner, review))
            }
            Self::Escrow(p) => ledger
                .plan_action(tip, &p.request()?, now)
                .map(Evaluation::Escrow),
            Self::Transfer(p) => ledger
                .plan_transfer(tip, &p.request()?, now)
                .map(Evaluation::Transfer),
        }
    }
    pub(super) fn review_json(&self, evaluated: &Evaluation, tip: Hash) -> Result<Value> {
        match (self, evaluated) {
            (
                Self::Delegation { channel, retainer },
                Evaluation::Delegation(origin, unsigned, _),
            ) => Ok(json!({
                "operation":"MINER_DELEGATION","chain_selected_tip":Id(tip),"channel":channel,
                "funding_context":Id(origin.context_commitment()),"miner":Id(origin.miner()),"retainer":retainer,
                "unsigned_delegation_hex":hex::encode(unsigned),"authorizes_principal":false,"authorizes_fee_inputs":false,
                "maximum_tip_age_seconds":"7200","maximum_monitoring_gap_seconds":"3600","ledger_admitted":false})),
            (Self::Opening(_), Evaluation::Opening(n, owner, _)) => {
                Ok(super::opening::review_json(n, *owner))
            }
            (Self::Escrow(p), Evaluation::Escrow(n)) => Ok(p.review(n, tip)),
            (Self::Transfer(p), Evaluation::Transfer(n)) => Ok(
                json!({"operation":"TRANSFER","chain_selected_tip":Id(tip),"spending_owner":p.owner,
                "inputs":p.inputs,"input_value":n.input_value.to_string(),"outputs":p.outputs,"operation_fee":p.fee,
                "expiry_height":p.expiry,"evaluation_timestamp":p.timestamp,"transaction_id":Id(n.transaction),
                "unsigned_operation_hex":hex::encode(n.unsigned()),"ledger_admitted":false}),
            ),
            _ => Err("INVALID native preparation evaluation type".into()),
        }
    }
}
impl Evaluation {
    pub(super) fn review(&self) -> Hash {
        match self {
            Self::Delegation(_, _, review) => *review,
            Self::Opening(_, _, review) => *review,
            Self::Escrow(p) => p.review(),
            Self::Transfer(p) => p.review(),
        }
    }
    pub(super) fn sign(&self, key: &ed25519_dalek::SigningKey) -> Result<Vec<u8>> {
        match self {
            Self::Delegation(origin, unsigned, _) => {
                ensure(
                    key.verifying_key().to_bytes() == origin.miner(),
                    "INVALID delegation signing miner",
                )?;
                let mut raw = unsigned.clone();
                raw.extend(
                    key.sign(&[fast_payment::tag("DELEGATION"), unsigned.clone()].concat())
                        .to_bytes(),
                );
                self.verify_signed(&raw)?;
                Ok(raw)
            }
            Self::Opening(p, owner, _) => p.sign(*owner, key),
            Self::Escrow(p) => p.sign(key),
            Self::Transfer(p) => p.sign(key),
        }
    }
    pub(super) fn verify_signed(&self, raw: &[u8]) -> Result<()> {
        match self {
            Self::Delegation(origin, unsigned, _) => {
                let d = Delegation::verify(origin, raw)?;
                ensure(
                    d.bytes()[..181] == *unsigned,
                    "INVALID delegation signed intent",
                )
            }
            Self::Opening(p, owner, _) => p.verify_own(*owner, raw),
            Self::Escrow(p) => p.verify_signed(raw),
            Self::Transfer(p) => p.verify_signed(raw),
        }
    }
}
impl Action {
    pub(super) fn preparation(&self) -> Option<(Hash, Preparation)> {
        match self {
            Self::DelegationPrepare {
                tip,
                channel,
                retainer,
            } => Some((
                tip.0,
                Preparation::Delegation {
                    channel: *channel,
                    retainer: *retainer,
                },
            )),
            Self::OpenPrepare { tip, plan } => Some((tip.0, Preparation::Opening(plan.clone()))),
            Self::OnchainPrepare { tip, plan } => Some((tip.0, Preparation::Escrow(plan.clone()))),
            Self::FeePolicyPrepare { tip, plan, .. } => {
                Some((tip.0, Preparation::Escrow(plan.clone())))
            }
            Self::TransferPrepare { tip, plan } => {
                Some((tip.0, Preparation::Transfer(plan.clone())))
            }
            _ => None,
        }
    }
    pub(super) fn native_authorization(&self) -> bool {
        matches!(
            self,
            Self::FeePolicyApprove { .. }
                | Self::DelegationPrepare { .. }
                | Self::FeePolicyPrepare { .. }
                | Self::FeePolicySign { .. }
                | Self::OpenPrepare { .. }
                | Self::OpenCombine { .. }
                | Self::TransferPrepare { .. }
                | Self::OnchainPrepare { .. }
                | Self::OnchainSign { .. }
        )
    }
}

impl Session {
    /// Recover the latest retained ordinary intent without replacing its terms
    /// or releasing any original reservation.
    pub fn transfer_draft(&mut self, head: Hash, owner: Id, now: u64) -> Result<Value> {
        let mut out = self.status(head, now)?;
        ensure(
            crate::kernel::valid_point(owner.0),
            "INVALID transfer draft owner",
        )?;
        let latest = self
            .caller
            .ops
            .iter()
            .rev()
            .find_map(|op| match &op.intent.action {
                Action::TransferPrepare { plan, .. }
                    if plan.owner == owner
                        && op.done.as_ref().is_some_and(|d| d.review.is_some()) =>
                {
                    Some((op.intent.id, op.intent.at, plan.clone()))
                }
                _ => None,
            });
        out["draft"] = Value::Null;
        if let Some((request, mut first_at, plan)) = latest {
            let binding = plan.reservation()?;
            let mut signed = None;
            for (index, op) in self.caller.ops.iter().enumerate() {
                if let Action::TransferPrepare { plan: old, .. } = &op.intent.action {
                    if op.done.as_ref().is_some_and(|d| d.review.is_some())
                        && old.reservation()? == binding
                    {
                        first_at = first_at.min(op.intent.at);
                    }
                }
                if let Action::OnchainSign {
                    prepare_request,
                    review,
                    ..
                } = &op.intent.action
                {
                    if op.done.as_ref().is_some_and(|d| d.authorization.is_some()) {
                        let (_, prepared, _) = self.prepared(index, *prepare_request, *review)?;
                        if matches!(prepared, Preparation::Transfer(_))
                            && prepared.reservation()? == binding
                        {
                            signed = Some(op.intent.id);
                        }
                    }
                }
            }
            out["draft"] = json!({"prepare_request":request,"plan":plan,"first_prepared_at":first_at.to_string(),
                "retained_sign_request":signed,"native_inclusion_evaluated":false,"reservation_released":false});
        }
        out["wallet_key_loaded"] = false.into();
        out["observation_only"] = true.into();
        self.status(head, now)?;
        Ok(out)
    }
    pub fn retained_delegation(&mut self, head: Hash, request: Id, now: u64) -> Result<Value> {
        let mut out = self.status(head, now)?;
        let index = self
            .caller
            .ops
            .iter()
            .position(|o| o.intent.id == request)
            .ok_or("MISSING delegation signing request")?;
        out["delegation"] = self
            .delegation_signature(index)?
            .ok_or("INVALID delegation signing request")?;
        out["request_id"] = json!(request);
        out["backing_currentness_known"] = false.into();
        out["wallet_key_loaded"] = false.into();
        out["observation_only"] = true.into();
        self.status(head, now)?;
        Ok(out)
    }
    pub(super) fn delegation_signature(&mut self, index: usize) -> Result<Option<Value>> {
        let op = self.caller.ops[index].clone();
        let Action::OnchainSign {
            prepare_request,
            review,
            ..
        } = op.intent.action
        else {
            return Ok(None);
        };
        let (_, plan, tip) = self.prepared(index, prepare_request, review)?;
        let Preparation::Delegation { channel, retainer } = plan else {
            return Ok(None);
        };
        let raw = bytes(
            op.done
                .as_ref()
                .and_then(|d| d.authorization.as_ref())
                .ok_or("MISSING retained delegation")?,
            245,
        )?;
        let ledger = self.native.as_mut().unwrap().historical(tip)?;
        let origin = ledger.funding_origin(channel.0)?;
        let delegation = Delegation::verify(&origin, &raw)?;
        ensure(
            delegation.retainer() == retainer.0,
            "INVALID retained delegation retainer",
        )?;
        Ok(Some(
            json!({"channel":channel,"miner":Id(origin.miner()),"retainer":retainer,
            "delegation_id":Id(delegation.id()),"delegation_hex":hex::encode(raw),"signature_retained":true,
            "authorizes_principal":false,"authorizes_fee_inputs":false}),
        ))
    }
}
