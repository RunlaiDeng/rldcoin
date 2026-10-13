//! Exact second-output evidence from the caller's already cold-verified Store.
use super::*;

pub(super) fn second_output(
    node: &Store,
    first_intent: Hash,
    second_intent: Hash,
    input: Hash,
) -> Result<Value> {
    require(
        input == crate::id("output", &(first_intent, 0u32))?,
        "cold second payment input is not first payment output zero",
    )?;
    let output = crate::id("output", &(second_intent, 0u32))?;
    let recipient = public(14);
    let coin = node
        .chain
        .ledger
        .coins
        .get(&output)
        .ok_or("cold exact second payment output absent")?;
    require(
        coin.payment.owner == recipient && coin.payment.amount == crate::Amount(100),
        "cold exact second payment recipient or amount differs",
    )?;
    require(
        !node.chain.ledger.coins.contains_key(&input),
        "cold first payment output remains unconsumed",
    )?;
    let finality = node
        .chain
        .finalized
        .ok_or("cold second payment finality absent")?;
    let finality_height = node.evidence.snapshot(finality)?.statement.height;
    let current_height = node.chain.height();
    require(
        finality_height >= coin.created && current_height >= coin.mature,
        "cold exact second payment is not finalized and mature",
    )?;
    let view = wallet::view(node, &recipient)?;
    let owned = view
        .coins
        .iter()
        .find(|owned| owned.id == output)
        .ok_or("cold wallet omitted exact second payment output")?;
    require(
        owned.amount == crate::Amount(100)
            && owned.mature_height == coin.mature
            && owned.spendable_now
            && owned.eligible_for_onward_export
            && !owned.quarantined,
        "cold exact second payment is not safely onward spendable",
    )?;
    // The caller already replayed the complete history with open_pinned.
    // Read only this coin's creation block; hashes do not grant new authority.
    let block = node.block_at(coin.created)?;
    let mut matched = None;
    for command in &block.commands {
        if let crate::Command::Spend(signed) = command {
            if signed.intent.id()? == second_intent {
                require(
                    matched.is_none(),
                    "cold duplicate second payment creation command",
                )?;
                matched = Some(&signed.intent);
            }
        }
    }
    let intent = matched.ok_or("cold second payment creation command absent")?;
    require(
        intent.inputs == vec![input]
            && intent.outputs.first().is_some_and(|payment| {
                payment.owner == recipient && payment.amount == crate::Amount(100)
            })
            && intent.fee == crate::Amount::ZERO,
        "cold second payment creation command differs from original payment",
    )?;
    let created_block = block.header.id()?;
    let cold_checked_at = monotonic()?;
    Ok(json!({
        "first_intent":first_intent,"intent":second_intent,"input":input,"output":output,
        "owner":recipient,"amount":coin.payment.amount,
        "created_block":created_block,"created":coin.created,"mature":coin.mature,
        "finality":finality,"finality_height":finality_height,"current_height":current_height,
        "spendable_now":owned.spendable_now,
        "eligible_for_onward_export":owned.eligible_for_onward_export,
        "quarantined":owned.quarantined,"input_consumed":true,
        "cold_checked_at":cold_checked_at,"cold_evidence_only":true,
        "original_recipient_clock_backfilled":false,"fixture_only":true,
        "independent_operations":false,"latency_percentiles_qualified":false
    }))
}
