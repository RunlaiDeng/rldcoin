//! Native read-only phase policy, with full evidence and current custody replay.
use crate::{
    bft,
    bft_proposal_schedule::{self, Pins},
    require,
    storage::Store,
    Hash, Result, Snapshot,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub context: bft::Context,
    pub order: Vec<Hash>,
}
impl Input {
    pub fn read(path: &std::path::Path) -> Result<Self> {
        let raw = crate::wallet_client::private_read(path)?;
        let value = crate::wallet_http::decode_unique(&raw)?;
        let input: Self = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
        require(
            serde_json::to_value(&input).map_err(|e| e.to_string())? == value
                && crate::wallet_client::canonical(&input)? == raw
                && input.order.len() <= 512,
            "BFT phase typed/canonical input bound",
        )?;
        Ok(input)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    Start,
    Commit,
    Finalize,
    Future,
    Committed,
}
impl Mode {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "start" => Ok(Self::Start),
            "commit" => Ok(Self::Commit),
            "finalize" => Ok(Self::Finalize),
            "future" => Ok(Self::Future),
            "committed" => Ok(Self::Committed),
            _ => Err("BFT phase mode differs".into()),
        }
    }
}
#[derive(Debug, Serialize)]
pub enum Action {
    Idle,
    Prepare {
        proposal: Box<bft::Proposal>,
        prepared: Option<bft::Quorum>,
        value: Hash,
    },
    Commit {
        proposal: Box<bft::Proposal>,
        prepared: bft::Quorum,
        value: Hash,
    },
    Finalize {
        snapshot: Box<Snapshot>,
    },
}
#[derive(Debug, Serialize)]
pub struct Observation {
    pub format: &'static str,
    pub context: bft::Context,
    pub round: u64,
    pub key: String,
    pub caller_head: Hash,
    pub archive_sha256: Hash,
    pub mode: Mode,
    pub authenticated_messages: usize,
    pub request_sha256: Hash,
    pub action: Action,
    pub ledger_changed: bool,
    pub signing_authority: bool,
    pub independent_freshness_qualified: bool,
}
pub(crate) type Votes = BTreeMap<(u64, u8), BTreeMap<String, bft::Vote>>;
fn phase(phase: bft::Phase) -> u8 {
    match phase {
        bft::Phase::Prepare => 0,
        bft::Phase::Commit => 1,
    }
}
fn insert(votes: &mut Votes, vote: bft::Vote) -> Result<()> {
    let retained = votes.entry((vote.round, phase(vote.phase))).or_default();
    if let Some(old) = retained.get(&vote.approval.key) {
        require(
            old == &vote,
            "BFT phase conflicting retained vote from one identity",
        )?;
    }
    retained.insert(vote.approval.key.clone(), vote);
    Ok(())
}
fn quorum(
    votes: &Votes,
    round: u64,
    wanted: bft::Phase,
    value: Hash,
    node: &Store,
) -> Result<Option<bft::Quorum>> {
    let selected = votes
        .get(&(round, phase(wanted)))
        .into_iter()
        .flat_map(|v| v.values())
        .filter(|v| v.value == value)
        .take(3)
        .cloned()
        .collect::<Vec<_>>();
    if selected.len() < 3 {
        return Ok(None);
    }
    Ok(Some(bft::Quorum::combine(
        selected,
        &node.trust,
        &node.evidence,
    )?))
}
pub(crate) fn prepare(
    state: &bft::State,
    proposal: &bft::Proposal,
    key: &str,
    node: &Store,
) -> Result<bool> {
    match state.preview(
        &bft::Request::Prepare(Box::new(proposal.clone())),
        key,
        node,
    ) {
        Ok(()) => Ok(true),
        Err(error)
            if error
                == "proposal violates durable prepared lock without a newer valid prepare QC" =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}
fn certificate(
    proposal: &bft::Proposal,
    prepared: bft::Quorum,
    committed: bft::Quorum,
    node: &Store,
) -> Result<Snapshot> {
    proposal.verify(&node.trust, &node.evidence)?;
    let certificate = bft::Certificate {
        prepared,
        committed,
    };
    let context = proposal.context()?;
    certificate.verify(
        &context,
        proposal.snapshot.statement.id()?,
        &context.keys(&node.trust, &node.evidence)?,
    )?;
    require(
        certificate.prepared.round == proposal.round,
        "BFT phase certificate round differs",
    )?;
    let mut snapshot = *proposal.snapshot.clone();
    snapshot.bft = Some(certificate);
    Ok(snapshot)
}
pub(crate) fn select(
    mode: Mode,
    state: &bft::State,
    signer_state: &bft::State,
    proposals: &[(bft::Proposal, Hash)],
    votes: &Votes,
    key: &str,
    node: &Store,
) -> Result<Action> {
    if mode != Mode::Commit {
        for round in 0..bft::MAX_ROUNDS {
            for (proposal, value) in proposals.iter().filter(|(p, _)| p.round == round) {
                if mode == Mode::Committed
                    && (round != state.round || state.committed != Some(*value))
                {
                    continue;
                }
                let Some(committed) = quorum(votes, round, bft::Phase::Commit, *value, node)?
                else {
                    continue;
                };
                let Some(prepared) = quorum(votes, round, bft::Phase::Prepare, *value, node)?
                else {
                    continue;
                };
                return Ok(Action::Finalize {
                    snapshot: Box::new(certificate(proposal, prepared, committed, node)?),
                });
            }
        }
    }
    if matches!(mode, Mode::Finalize | Mode::Committed) {
        return Ok(Action::Idle);
    }
    for (proposal, value) in proposals.iter().filter(|(p, _)| p.round == state.round) {
        let prepared = quorum(votes, state.round, bft::Phase::Prepare, *value, node)?;
        if state.prepared.is_none() && mode != Mode::Commit {
            if prepare(signer_state, proposal, key, node)? {
                return Ok(Action::Prepare {
                    proposal: Box::new(proposal.clone()),
                    prepared,
                    value: *value,
                });
            }
        } else if state.prepared == Some(*value) && state.committed.is_none() {
            if let Some(prepared) = prepared {
                signer_state.preview(
                    &bft::Request::Commit {
                        proposal: Box::new(proposal.clone()),
                        prepared: prepared.clone(),
                    },
                    key,
                    node,
                )?;
                return Ok(Action::Commit {
                    proposal: Box::new(proposal.clone()),
                    prepared,
                    value: *value,
                });
            }
        }
    }
    if mode == Mode::Future {
        // Stable sorting retains canonical body order within one round.
        let mut future = proposals
            .iter()
            .filter(|(p, _)| p.round > state.round)
            .collect::<Vec<_>>();
        future.sort_by_key(|(p, _)| std::cmp::Reverse(p.round));
        for (proposal, value) in future {
            if prepare(signer_state, proposal, key, node)? {
                return Ok(Action::Prepare {
                    proposal: Box::new(proposal.clone()),
                    prepared: None,
                    value: *value,
                });
            }
        }
    }
    Ok(Action::Idle)
}
pub(crate) fn retained(messages: &[bft::Message]) -> Result<(Vec<(bft::Proposal, Hash)>, Votes)> {
    let mut proposals = Vec::new();
    let mut votes = Votes::new();
    for message in messages {
        match message {
            bft::Message::Proposal(p) => {
                let value = p.snapshot.statement.id()?;
                proposals.push((*p.clone(), value));
            }
            bft::Message::Vote(v) => insert(&mut votes, *v.clone())?,
            bft::Message::Timeout(_) => (),
            _ => return Err("BFT phase unexpected authenticated message".into()),
        }
    }
    Ok((proposals, votes))
}
pub fn observe(node: &Store, pins: Pins<'_>, mode: Mode, input: Input) -> Result<Observation> {
    require(
        pins.context == input.context,
        "BFT phase input context differs",
    )?;
    let request_sha256 = Hash(Sha256::digest(crate::wallet_client::canonical(&input)?).into());
    let bft_proposal_schedule::Inputs {
        context,
        active,
        signer_state,
        client,
        _agent,
        ..
    } = bft_proposal_schedule::inspect(node, &pins)?;
    let messages =
        client.scheduling_messages(node, pins.archive_head, &context, true, Some(&input.order))?;
    let count = messages.len();
    let (proposals, votes) = retained(&messages)?;
    let action = select(
        mode,
        &active,
        &signer_state,
        &proposals,
        &votes,
        &pins.key,
        node,
    )?;
    Ok(Observation {
        format: "RLD-NATIVE-BFT-PHASE-OBSERVATION-V1",
        context,
        round: active.round,
        key: pins.key,
        caller_head: pins.head,
        archive_sha256: pins.archive_head,
        mode,
        authenticated_messages: count,
        request_sha256,
        action,
        ledger_changed: false,
        signing_authority: false,
        independent_freshness_qualified: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_duplicates_cannot_count_twice_or_replace_conflicting_votes() {
        let mut votes = Votes::new();
        let vote = bft::Vote {
            context: bft::Context {
                currency: Hash::ZERO,
                region: Hash::ZERO,
                epoch: Hash::ZERO,
                previous: None,
                parent_height: 0,
                parent_block: Hash::ZERO,
                parent_state: Hash::ZERO,
            },
            round: 0,
            value: Hash([1; 32]),
            phase: bft::Phase::Prepare,
            approval: crate::Approval {
                key: "policy-only".into(),
                signature: String::new(),
            },
        };
        insert(&mut votes, vote.clone()).unwrap();
        insert(&mut votes, vote.clone()).unwrap();
        assert_eq!(votes[&(0, 0)].len(), 1);
        let mut changed = vote;
        changed.value = Hash([2; 32]);
        assert!(insert(&mut votes, changed).is_err());
        assert_eq!(votes[&(0, 0)].len(), 1);
    }
    #[test]
    fn unknown_phase_modes_refuse_without_an_alias() {
        for value in ["", "START", "propose", "timeout", "recover"] {
            assert!(Mode::parse(value).is_err());
        }
    }
}
