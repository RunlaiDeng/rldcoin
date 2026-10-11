//! One origin receive and read-only phase observation under the actual locks.
//! The separate caller pending request and independently pinned sign are unchanged.
use super::*;
use std::path::Path;

#[derive(Serialize)]
pub struct ReceivedPhase {
    pub checked: Vec<LiveChecked>,
    pub context: bft::Context,
    pub history_head: Hash,
    pub signer: bft::Status,
    #[serde(skip)]
    _custody: bft::Agent,
}

pub fn receive_origin_phase(
    node: &mut Store,
    wires: Vec<WireEnvelope>,
    signer_dir: &Path,
    expected_signer_head: Hash,
    expected_key: &str,
) -> Result<ReceivedPhase> {
    receive_with(
        node,
        wires,
        signer_dir,
        expected_signer_head,
        expected_key,
        Ok,
    )
}
fn receive_with(
    node: &mut Store,
    wires: Vec<WireEnvelope>,
    signer_dir: &Path,
    expected_signer_head: Hash,
    expected_key: &str,
    observe: impl FnOnce(bft::Status) -> Result<bft::Status>,
) -> Result<ReceivedPhase> {
    require(
        node.trust.region(node.chain.region)?.rules == crate::paged_bft::ORIGIN_NETWORK_RULES,
        "receive phase requires explicit origin network profile",
    )?;
    // Keep the original ordering: authenticate/synchronize complete inputs first,
    // then fully replay the signer against that actual current Native Store.
    // A later observation refusal preserves any already-certified prefix and
    // releases no success response or signing rights; it must never fall back.
    let checked = receive_origin_batch(node, wires)?;
    let (agent, status) = bft::Agent::inspect_with_status(signer_dir, node)?;
    require(
        agent.head()? == expected_signer_head
            && agent.journal.binding.key == expected_key
            && agent.journal.binding.currency == node.trust.currency()?
            && agent.journal.binding.region == node.chain.region,
        "receive phase differs from separate caller signer binding/head",
    )?;
    // This exact status came from the complete locked journal replay above. No
    // decoded/cached status initializes a ledger or substitutes for fresh signing.
    let signer = observe(status)?;
    require(
        agent.head()? == expected_signer_head,
        "receive phase final signer head differs",
    )?;
    Ok(ReceivedPhase {
        checked,
        context: bft::Context::current(node)?,
        history_head: node.storage_head()?,
        signer,
        _custody: agent,
    })
}
#[cfg(test)]
pub(crate) fn receive_origin_phase_failure_for_test(
    node: &mut Store,
    wires: Vec<WireEnvelope>,
    signer_dir: &Path,
    expected_signer_head: Hash,
    expected_key: &str,
) -> Result<ReceivedPhase> {
    receive_with(
        node,
        wires,
        signer_dir,
        expected_signer_head,
        expected_key,
        |_| Err("injected observation failure after complete receive".into()),
    )
}
