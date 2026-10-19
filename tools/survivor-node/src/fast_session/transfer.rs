//! Typed ordinary funding intent; existing escrow preparation bytes are unchanged.
use super::*;
use crate::kernel::fast::{planning::Plan, transfer::TransferPlan};

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
    Opening(OpeningRequest),
    Escrow(OnchainRequest),
    Transfer(TransferRequest),
}
pub(super) enum Evaluation {
    Opening(crate::kernel::fast::opening::OpeningPlan, u8, Hash),
    Escrow(Plan),
    Transfer(TransferPlan),
}
impl Preparation {
    pub(super) fn inputs(&self) -> Result<Vec<Vec<u8>>> {
        match self {
            Self::Opening(p) => p.inputs(),
            Self::Escrow(p) => Ok(p.request()?.inputs),
            Self::Transfer(p) => Ok(p.request()?.inputs),
        }
    }
    pub(super) fn reservation(&self) -> Result<Hash> {
        match self {
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
            Self::Opening(_, _, review) => *review,
            Self::Escrow(p) => p.review(),
            Self::Transfer(p) => p.review(),
        }
    }
    pub(super) fn sign(&self, key: &ed25519_dalek::SigningKey) -> Result<Vec<u8>> {
        match self {
            Self::Opening(p, owner, _) => p.sign(*owner, key),
            Self::Escrow(p) => p.sign(key),
            Self::Transfer(p) => p.sign(key),
        }
    }
    pub(super) fn verify_signed(&self, raw: &[u8]) -> Result<()> {
        match self {
            Self::Opening(p, owner, _) => p.verify_own(*owner, raw),
            Self::Escrow(p) => p.verify_signed(raw),
            Self::Transfer(p) => p.verify_signed(raw),
        }
    }
}
impl Action {
    pub(super) fn preparation(&self) -> Option<(Hash, Preparation)> {
        match self {
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
