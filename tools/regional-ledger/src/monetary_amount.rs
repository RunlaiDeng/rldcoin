//! Bound new monetary requests before arithmetic. Historical signed facts and
//! cumulative accounting retain the full Amount encoding for authentication.
use super::*;

pub(crate) fn check(value: Amount) -> Result<()> {
    require(
        value <= Amount::TOTAL_SUPPLY,
        "monetary amount exceeds supply cap",
    )
}
pub(crate) fn positive(value: Amount) -> Result<()> {
    check(value)?;
    require(!value.is_zero(), "monetary output must be positive")
}
fn payments(values: &[Payment]) -> Result<()> {
    for value in values {
        positive(value.amount)?;
    }
    Ok(())
}
pub(crate) fn deserialize_amount<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Amount, D::Error> {
    let value = Amount::deserialize(d)?;
    check(value).map_err(serde::de::Error::custom)?;
    Ok(value)
}
pub(crate) fn deserialize_payment<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Payment, D::Error> {
    let value = Payment::deserialize(d)?;
    positive(value.amount).map_err(serde::de::Error::custom)?;
    Ok(value)
}
pub(crate) fn deserialize_payments<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Vec<Payment>, D::Error> {
    let values = Vec::<Payment>::deserialize(d)?;
    payments(&values).map_err(serde::de::Error::custom)?;
    Ok(values)
}
pub(crate) fn wallet(request: &crate::wallet::Request) -> Result<()> {
    payments(&request.outputs)?;
    check(request.fee)?;
    if let Some(remote) = &request.remote {
        positive(remote.recipient.amount)?;
        check(remote.destination_fee)?;
    }
    Ok(())
}
pub(crate) fn owner(intent: &Intent) -> Result<()> {
    payments(&intent.outputs)?;
    check(intent.fee)?;
    check(intent.destination_fee)?;
    if let Some(remote) = &intent.remote {
        positive(remote.amount)?;
    }
    Ok(())
}
pub(crate) fn channel(action: &channels::Action) -> Result<()> {
    use channels::Action;
    match action {
        Action::Open {
            capacity,
            initial,
            change,
            fee,
            ..
        } => {
            positive(*capacity)?;
            for value in initial {
                check(*value)?;
            }
            payments(change)?;
            check(*fee)
        }
        Action::Reserve { fee_limit, .. } => check(*fee_limit),
        Action::ReserveBudget {
            fee_limit, max_fee, ..
        } => {
            check(*fee_limit)?;
            check(*max_fee)
        }
        Action::Close { state, fee, .. } | Action::Challenge { state, fee, .. } => {
            for value in state.statement.payouts {
                check(value)?;
            }
            check(*fee)
        }
        Action::Settle { .. } => Ok(()),
    }
}
