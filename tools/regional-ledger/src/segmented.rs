//! Explicit signed unanimous profile with bounded checkpoint segments.
//! Only a previously fully executed exact certificate supplies a prefix state.
use super::*;
pub const RULES: &str = "RLD-REGIONAL-SEGMENTED-UNANIMOUS-FIXTURE-V1";
pub fn is_profile(rules: &str) -> bool {
    rules == RULES || rules == channels::SEGMENTED_RULES
}

pub(crate) fn shape(snapshot: &Snapshot, trust: &Trust) -> Result<()> {
    if crate::paged_bft::is_profile(&trust.region(snapshot.statement.region)?.rules) {
        return crate::paged_bft::shape(snapshot, trust);
    }
    if !is_profile(&trust.region(snapshot.statement.region)?.rules) {
        return require(
            snapshot.base.is_none(),
            "legacy/BFT snapshot cannot adopt segmented history",
        );
    }
    require(
        snapshot.base == snapshot.statement.previous
            && snapshot.bft.is_none()
            && snapshot.epochs.is_empty()
            && snapshot.statement.epoch
                == epoch::Registry::initial(trust, snapshot.statement.region)?
            && !snapshot.blocks.is_empty()
            && snapshot.blocks.len() <= MAX_BLOCKS,
        "segmented checkpoint base, authority or block bound",
    )
}

pub(crate) fn replay(
    snapshot: &Snapshot,
    trust: &Trust,
    evidence: &VerifiedEvidence,
) -> Result<Chain> {
    shape(snapshot, trust)?;
    evidence.check_trust(trust)?;
    let mut chain = Chain::new(snapshot.statement.region, trust)?;
    if let Some(previous) = snapshot.base {
        let (parent, ledger) = evidence
            .snapshots
            .get(&previous)
            .ok_or("segmented checkpoint lacks fully replayed predecessor")?;
        require(
            parent.statement.currency == snapshot.statement.currency
                && parent.statement.region == snapshot.statement.region
                && parent.statement.epoch == snapshot.statement.epoch,
            "segmented checkpoint predecessor scope differs",
        )?;
        chain.prefix_height = parent.statement.height;
        chain.prefix_tip = parent.statement.block;
        chain.finalized = Some(previous);
        chain.ledger = ledger.clone();
    }
    for block in &snapshot.blocks {
        // A segment may not sneak an intermediate certificate into its tail.
        require(
            block.header.anchor == snapshot.base,
            "segmented block has another anchor",
        )?;
        chain.accept(block.clone(), trust, evidence)?;
    }
    Ok(chain)
}

/// Structural authentication for incident ancestry and signer request locks.
/// This never executes value or authorizes adoption of a sender's ledger.
pub(crate) fn headers(statement: &Statement, headers: &[Header], trust: &Trust) -> Result<()> {
    require(
        is_profile(&trust.region(statement.region)?.rules)
            && statement.epoch == epoch::Registry::initial(trust, statement.region)?
            && !headers.is_empty()
            && headers.len() <= MAX_BLOCKS,
        "segmented header authority or bound",
    )?;
    let start = statement
        .height
        .checked_sub(headers.len() as u64)
        .ok_or("segmented header range")?;
    require(
        (start == 0) == statement.previous.is_none(),
        "segmented header predecessor range",
    )?;
    let mut parent = if start == 0 {
        statement.region
    } else {
        headers[0].parent
    };
    for (i, header) in headers.iter().enumerate() {
        require(
            header.currency == statement.currency
                && header.region == statement.region
                && header.height == start + i as u64 + 1
                && header.parent == parent
                && header.anchor == statement.previous
                && header.work_valid()?,
            "segmented header identity, parent, anchor or work",
        )?;
        validate_ed25519_public_key(&header.miner)?;
        parent = header.id()?;
    }
    require(
        parent == statement.block && headers.last().unwrap().state == statement.state,
        "segmented terminal statement differs",
    )
}
