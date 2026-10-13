//! Unsigned group proposals over the ordinary native wallet review path.
//! Building/reviewing never signs, reserves inputs or changes caller custody.
use crate::{require, storage::Store, wallet, wallet_agent, Amount, Hash, Payment, Result};
use serde::{Deserialize, Serialize};

pub const FORMAT: &str = "RLD-REGIONAL-GROUP-PROPOSAL-V1";
pub const MAX_INPUT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildRequest {
    // The caller wallet binding selects the actual reviewer, as in wallet-prepare.
    pub owner: Option<String>,
    #[serde(default)]
    pub participants: Vec<String>,
    pub inputs: Option<Vec<Hash>>,
    #[serde(deserialize_with = "crate::monetary_amount::deserialize_payments")]
    pub outputs: Vec<Payment>,
    pub remote: Option<wallet::Remote>,
    #[serde(deserialize_with = "crate::monetary_amount::deserialize_amount")]
    pub fee: Amount,
    pub valid_for_blocks: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildInput {
    pub request: BuildRequest,
    pub selection_pin: wallet::Pin,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    pub format: String,
    pub currency: Hash,
    pub region: Hash,
    pub intent_id: Hash,
    pub request: wallet::Request,
}

#[derive(Debug, Serialize)]
pub struct Built {
    pub prepared: wallet_agent::Prepared,
    pub proposal: Proposal,
}

pub fn build(
    node: &Store,
    agent: &wallet_agent::Agent,
    expected_head: Hash,
    input: BuildInput,
) -> Result<Built> {
    let pin = wallet::Pin::current(node)?;
    require(
        input.selection_pin == pin,
        "wallet state changed; load proposal inputs again",
    )?;
    let request = input.request;
    require(
        request.participants.len() >= 2 && (1..=32).contains(&request.valid_for_blocks),
        "proposal needs multiple actual owners and bounded expiry",
    )?;
    let expiry = pin
        .height
        .checked_add(request.valid_for_blocks)
        .ok_or("group expiry overflow")?;
    let prepared = agent.prepare(
        node,
        wallet::Request {
            owner: agent.journal.binding.owner.clone(),
            participants: request.participants,
            inputs: request.inputs,
            outputs: request.outputs,
            remote: request.remote,
            fee: request.fee,
            valid_for_blocks: request.valid_for_blocks,
            valid_through: Some(expiry),
        },
        expected_head,
    )?;
    require(prepared.draft.pin == pin, "proposal observation changed")?;
    let proposal = Proposal {
        format: FORMAT.into(),
        currency: pin.currency,
        region: pin.region,
        intent_id: prepared.draft.intent_id,
        request: prepared.draft.request.clone(),
    };
    Ok(Built { prepared, proposal })
}

pub fn review(
    node: &Store,
    agent: &wallet_agent::Agent,
    expected_head: Hash,
    proposal: Proposal,
) -> Result<wallet_agent::Prepared> {
    require(
        proposal.format == FORMAT
            && proposal.currency == node.trust.currency()?
            && proposal.region == node.chain.region,
        "proposal format, currency or region differs",
    )?;
    require(
        proposal.request.participants.len() >= 2 && proposal.request.valid_through.is_some(),
        "proposal must pin actual owners, inputs, outputs and absolute expiry",
    )?;
    let mut request = proposal.request;
    request.owner = agent.journal.binding.owner.clone();
    let prepared = agent.prepare(node, request, expected_head)?;
    require(
        prepared.draft.intent_id == proposal.intent_id,
        "proposal intent differs from verified request",
    )?;
    Ok(prepared)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> serde_json::Value {
        let zero = "00".repeat(32);
        serde_json::json!({
            "request": {"participants": [], "inputs": null, "outputs": [],
                "remote": null, "fee": "1", "valid_for_blocks": 8},
            "selection_pin": {"currency": zero, "region": zero, "height": 3,
                "tip": zero, "state": zero, "epoch": zero, "finality": null,
                "local_journal_and_incidents": zero}
        })
    }

    #[test]
    fn typed_proposal_input_refuses_rebased_expiry_unknown_and_duplicate_fields() {
        // Decoding this shape grants no authority; build still needs native replay.
        let raw = serde_json::to_string(&input()).unwrap();
        assert!(serde_json::from_str::<BuildInput>(&raw).is_ok());
        for replacement in [
            "\"valid_for_blocks\":8,\"valid_through\":null",
            "\"valid_for_blocks\":true",
            "\"valid_for_blocks\":8,\"valid_for_blocks\":8",
            "\"valid_for_blocks\":8,\"unexpected\":null",
        ] {
            let changed = raw.replace("\"valid_for_blocks\":8", replacement);
            assert!(serde_json::from_str::<BuildInput>(&changed).is_err());
        }
        let duplicate_pin = raw.replace("\"height\":3", "\"height\":3,\"height\":3");
        assert!(serde_json::from_str::<BuildInput>(&duplicate_pin).is_err());
        let duplicate_optional = raw.replace("\"remote\":null", "\"remote\":null,\"remote\":null");
        assert!(serde_json::from_str::<BuildInput>(&duplicate_optional).is_err());
    }
}
