//! Test-only observations of already checked objects; no execution or authority.
use super::*;

pub(super) fn intents(commands: &[Command]) -> Result<Vec<Hash>> {
    commands
        .iter()
        .filter_map(|command| match command {
            Command::Spend(signed) => Some(signed.intent.id()),
            _ => None,
        })
        .collect()
}

pub(super) fn snapshot(snapshot: &Snapshot) -> Result<Value> {
    let last = snapshot
        .blocks
        .last()
        .ok_or("payment trace missing new block")?;
    require(
        last.header.height == snapshot.statement.height
            && last.header.id()? == snapshot.statement.block,
        "payment trace last block differs from checkpoint",
    )?;
    Ok(
        json!({"value":snapshot.statement.id()?,"height":snapshot.statement.height,
        "block":snapshot.statement.block,"intents":intents(&last.commands)?}),
    )
}

pub(super) fn body(body: &net::Body) -> Result<Value> {
    match body {
        net::Body::Submission(commands) => {
            Ok(json!({"kind":"submission","intents":intents(commands)?}))
        }
        net::Body::Signed(message) => match message.as_ref() {
            consensus::Message::Proposal(proposal) => Ok(json!({"kind":"proposal",
                "context":proposal.context()?,"round":proposal.round,
                "leader":proposal.leader.key,"snapshot":snapshot(&proposal.snapshot)?})),
            consensus::Message::Vote(vote) => Ok(json!({"kind":match vote.phase {
                consensus::Phase::Prepare => "prepare", consensus::Phase::Commit => "commit"},
                "context":vote.context,"round":vote.round,"value":vote.value,"signer":vote.approval.key})),
            _ => Ok(json!({"kind":"other-signed-control"})),
        },
        net::Body::Finalized(value) => Ok(json!({"kind":"finalized","snapshot":snapshot(value)?})),
        _ => Ok(json!({"kind":"other"})),
    }
}
