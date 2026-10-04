//! All-four epoch fencing for a separately admitted BFT ground profile.
//! Fences are native signer records, never signatures from an independent lock.
use super::*;
use crate::{bft::Context, storage::Store};

pub(crate) fn validate_fence(
    node: &Store,
    context: &Context,
    proposal: &epoch::Transition,
    previous_epochs: &[epoch::Transition],
    key: &str,
) -> Result<()> {
    let s = &proposal.statement;
    require(
        bft::has_epochs(&node.trust.region(s.region)?.rules)
            && proposal.old_approvals.is_empty()
            && proposal.new_approvals.is_empty(),
        "epoch fence requires explicitly admitted unsigned handoff proposal",
    )?;
    let registry = epoch::Registry::verify_chain(&node.trust, s.region, previous_epochs)?;
    let (previous, number, keys, floor) = registry.latest(&node.trust, s.region)?;
    proposal.validate_request(&node.trust, previous, number, &keys, floor)?;
    registry.fresh_bft_keys(&node.trust, s.region, &s.validators)?;
    require(
        keys.iter().any(|k| k == key),
        "only active old validators can fence",
    )?;
    let known = node.evidence.epoch_proofs(s.region);
    if crate::bft::is_joint(&node.trust.region(s.region)?.rules) {
        require(
            known
                .iter()
                .take(previous_epochs.len())
                .map(|p| p.statement.id())
                .collect::<Result<Vec<_>>>()?
                == previous_epochs
                    .iter()
                    .map(|p| p.statement.id())
                    .collect::<Result<Vec<_>>>()?,
            "fence omits or changes prior native epochs",
        )?;
        let mut checked = node.evidence.clone();
        for proof in previous_epochs {
            checked.install_epoch(proof.clone(), &node.trust)?;
        }
    } else {
        require(
            known.starts_with(previous_epochs),
            "fence omits or changes prior native epochs",
        )?;
    }

    let closing = node.evidence.snapshot(s.closing_checkpoint)?;
    if crate::bft::is_joint(&node.trust.region(s.region)?.rules) {
        crate::joint_epoch::closing_matches(proposal, closing)?;
    }
    require(
        (crate::bft::is_joint(&node.trust.region(s.region)?.rules)
            || epoch::Anchor::from_snapshot(closing) == proposal.closing)
            && context.currency == s.currency
            && context.region == s.region
            && context.epoch == previous
            && context.previous == Some(s.closing_checkpoint)
            && context.parent_height == s.closing_height
            && context.parent_block == closing.statement.block
            && context.parent_state == closing.statement.state,
        "epoch fence lacks exact fully replayed closing checkpoint/context",
    )
}
