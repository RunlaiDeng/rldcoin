//! Explicit signed ordinary BFT history profile; full native sequential replay.
//! Complete certificates/owners remain authority, never page/index hashes.
use crate::{storage::Store, *};
pub const RULES: &str = "RLD-REGIONAL-BFT-PAGED-VALUE-CHANNELS-FIXTURE-V1";
pub fn is_profile(rules: &str) -> bool {
    rules == RULES
}
pub fn rules_hash() -> Result<Hash> {
    id(
        "paged-bft-rules-v1",
        &(
            include_str!("paged_bft_profile.md"),
            channels::profile_hash()?,
        ),
    )
}
pub(crate) fn shape(snapshot: &Snapshot, trust: &Trust) -> Result<()> {
    let s = &snapshot.statement;
    require(
        is_profile(&trust.region(s.region)?.rules)
            && snapshot.base == s.previous
            && snapshot.epochs.is_empty()
            && s.epoch == epoch::Registry::initial(trust, s.region)?
            && snapshot.approvals.is_empty()
            && snapshot.blocks.len() == if s.previous.is_some() { 2 } else { 1 },
        "paged BFT checkpoint base/authority/complete parent witness",
    )
}
pub(crate) fn headers(s: &Statement, headers: &[Header], trust: &Trust) -> Result<()> {
    require(
        s.currency == trust.currency()?
            && s.height > 0
            && s.epoch == epoch::Registry::initial(trust, s.region)?
            && headers.len() == if s.previous.is_some() { 2 } else { 1 },
        "paged BFT signed header scope",
    )?;
    let last = headers.last().ok_or("paged BFT header missing")?;
    for h in headers {
        require(
            h.currency == s.currency && h.region == s.region && h.work_valid()?,
            "paged BFT signed header domain/work",
        )?;
        validate_ed25519_public_key(&h.miner)?;
    }
    if headers.len() == 1 {
        require(
            last.height == 1 && last.parent == s.region,
            "paged BFT genesis header",
        )?;
    } else {
        require(
            headers[0].height.checked_add(1) == Some(last.height)
                && last.parent == headers[0].id()?,
            "paged BFT parent witness order",
        )?;
    }
    require(
        last.height == s.height
            && last.id()? == s.block
            && last.state == s.state
            && last.anchor == s.previous,
        "paged BFT signed terminal",
    )
}
pub(crate) fn prepare_parent(chain: &mut Chain, evidence: &VerifiedEvidence) -> Result<()> {
    require(
        chain.blocks.is_empty(),
        "paged BFT requires a certified local boundary",
    )?;
    if let Some(previous) = chain.finalized {
        let parent = evidence
            .snapshot(previous)?
            .blocks
            .last()
            .ok_or("paged BFT parent block")?;
        require(
            parent.header.height == chain.height()
                && parent.header.id()? == chain.tip()?
                && parent.header.state == chain.ledger.root()?,
            "paged BFT parent differs from native state",
        )?;
        chain.prefix_height = chain
            .height()
            .checked_sub(1)
            .ok_or("paged BFT parent height")?;
        chain.prefix_tip = parent.header.parent;
        chain.blocks.push(parent.clone());
    }
    Ok(())
}
pub(crate) fn replay(s: &Snapshot, trust: &Trust, evidence: &VerifiedEvidence) -> Result<Chain> {
    shape(s, trust)?;
    evidence.check_trust(trust)?;
    let mut chain = Chain::new(s.statement.region, trust)?;
    if let Some(previous) = s.base {
        let (parent, ledger) = evidence
            .snapshots
            .get(&previous)
            .ok_or("paged BFT missing native predecessor")?;
        require(
            parent.statement.region == s.statement.region
                && parent.statement.currency == s.statement.currency
                && parent.statement.epoch == s.statement.epoch
                && parent.blocks.last() == s.blocks.first(),
            "paged BFT complete predecessor witness differs",
        )?;
        chain.prefix_height = parent.statement.height;
        chain.prefix_tip = parent.statement.block;
        chain.finalized = Some(previous);
        chain.ledger = ledger.clone();
        prepare_parent(&mut chain, evidence)?;
    }
    chain.accept(
        s.blocks
            .last()
            .ok_or("paged BFT new block missing")?
            .clone(),
        trust,
        evidence,
    )?;
    Ok(chain)
}
pub(crate) fn parent_matches(s: &Snapshot, node: &Store) -> Result<bool> {
    if !is_profile(&node.trust.region(node.chain.region)?.rules) {
        return Ok(s.blocks[..s.blocks.len() - 1] == node.chain.blocks);
    }
    Ok(match node.chain.finalized {
        Some(previous) => {
            s.base == Some(previous)
                && s.blocks.len() == 2
                && s.blocks.first() == node.evidence.snapshot(previous)?.blocks.last()
        }
        None => s.base.is_none() && s.blocks.len() == 1 && node.chain.height() == 0,
    })
}
