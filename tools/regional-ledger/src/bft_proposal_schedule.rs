//! Read-only proposal opportunity policy over freshly authenticated native input.
//! It supplies no signature, clock, ledger installation or freshness authority.
use crate::{bft, bft_runtime_archive, require, storage::Store, Hash, Result};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

pub struct Pins<'a> {
    pub signer: &'a Path,
    pub archive: &'a Path,
    pub key: String,
    pub runtime_format: String,
    pub head: Hash,
    pub archive_head: Hash,
    pub context: bft::Context,
    pub round: u64,
}

#[derive(Debug, Serialize)]
pub struct Opportunity {
    pub format: &'static str,
    pub context: bft::Context,
    pub round: u64,
    pub key: String,
    pub caller_head: Hash,
    pub archive_sha256: Hash,
    pub authenticated_messages: usize,
    pub current_proposals: bool,
    pub future_proposals: bool,
    pub proposed_round: u64,
    pub leader: String,
    pub timeout: Option<bft::TimeoutCertificate>,
    pub high: Option<Hash>,
    pub can_propose: bool,
    pub ledger_changed: bool,
    pub signing_authority: bool,
    pub independent_freshness_qualified: bool,
}

type Timeouts = BTreeMap<u64, BTreeMap<String, bft::TimeoutVote>>;

pub fn context_file(path: &Path) -> Result<bft::Context> {
    let value = crate::wallet_http::decode_unique(&crate::wallet_client::private_read(path)?)?;
    let context: bft::Context = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    require(
        serde_json::to_value(&context).map_err(|e| e.to_string())? == value,
        "BFT scheduling context loses typed fields",
    )?;
    Ok(context)
}

fn timeout_insert(timeouts: &mut Timeouts, vote: bft::TimeoutVote) -> Result<()> {
    let voters = timeouts.entry(vote.round).or_default();
    if let Some(previous) = voters.get(&vote.approval.key) {
        require(
            previous == &vote,
            "BFT scheduling conflicting retained timeout voter",
        )?;
    }
    voters.insert(vote.approval.key.clone(), vote);
    Ok(())
}

fn candidate_round(
    context: &bft::Context,
    round: u64,
    key: &str,
    keys: &[String],
    future: bool,
    timeouts: &Timeouts,
) -> Result<u64> {
    let mut selected = round;
    if !future {
        for later in round + 1..crate::bft::MAX_ROUNDS {
            if bft::leader(context, later, keys)? == key
                && timeouts
                    .get(&(later - 1))
                    .is_some_and(|votes| votes.len() >= 3)
            {
                selected = later;
            }
        }
    }
    Ok(selected)
}

pub(crate) struct Inputs {
    pub context: bft::Context,
    pub keys: Vec<String>,
    pub active: bft::State,
    pub signer_state: bft::State,
    pub client: bft_runtime_archive::Client,
    pub _agent: bft::Agent,
}
pub(crate) fn inspect(node: &Store, pins: &Pins<'_>) -> Result<Inputs> {
    require(
        matches!(std::fs::symlink_metadata(node.directory().join("journal.next")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound),
        "BFT scheduling refuses interrupted ledger publication",
    )?;
    let context = bft::Context::current(node)?;
    require(
        context == pins.context,
        "BFT scheduling native context changed",
    )?;
    let keys = context.keys(&node.trust, &node.evidence)?;
    let (agent, status) = bft::Agent::inspect_with_status(pins.signer, node)?;
    require(
        status.head == pins.head
            && status.binding.currency == context.currency
            && status.binding.region == context.region
            && status.binding.key == pins.key,
        "BFT scheduling differs from separately retained caller binding/head",
    )?;
    let signer_state = status.state.clone();
    let active = if status.state.context.as_ref() == Some(&context) {
        status.state
    } else {
        bft::State::default()
    };
    require(
        active.round == pins.round && active.round < bft::MAX_ROUNDS,
        "BFT scheduling signer round changed",
    )?;
    let client = bft_runtime_archive::Client::lock(
        pins.archive,
        pins.key.clone(),
        pins.runtime_format.clone(),
        node,
    )?;
    Ok(Inputs {
        context,
        keys,
        active,
        signer_state,
        client,
        _agent: agent,
    })
}
pub fn observe(node: &Store, pins: Pins<'_>) -> Result<Opportunity> {
    let Inputs {
        context,
        keys,
        active,
        client,
        _agent,
        ..
    } = inspect(node, &pins)?;
    let messages = client.proposal_messages(node, pins.archive_head, &context)?;
    opportunity(node, &pins, &context, &keys, &active, &messages)
}
pub(crate) fn opportunity(
    node: &Store,
    pins: &Pins<'_>,
    context: &bft::Context,
    keys: &[String],
    active: &bft::State,
    messages: &[bft::Message],
) -> Result<Opportunity> {
    let count = messages.len();
    let mut proposals = BTreeSet::new();
    let mut timeouts = Timeouts::new();
    for message in messages {
        match message {
            bft::Message::Proposal(p) => {
                proposals.insert(p.round);
            }
            bft::Message::Timeout(t) => timeout_insert(&mut timeouts, *t.clone())?,
            bft::Message::Vote(_) => (),
            _ => return Err("BFT scheduling unexpected authenticated message".into()),
        }
    }
    let current = proposals.contains(&active.round);
    let future = proposals.range(active.round + 1..).next().is_some();
    let proposed_round =
        candidate_round(context, active.round, &pins.key, keys, future, &timeouts)?;
    let leader = bft::leader(context, proposed_round, keys)?;
    let timeout = if proposed_round == 0 {
        None
    } else if let Some(votes) = timeouts.get(&(proposed_round - 1)).filter(|v| v.len() >= 3) {
        // All three or four distinct voters participate; the fourth high QC is
        // never discarded by scheduling. Combine and selected fully verify it.
        Some(bft::TimeoutCertificate::combine(
            votes.values().cloned().collect(),
            &node.trust,
            &node.evidence,
        )?)
    } else {
        None
    };
    let high = timeout
        .as_ref()
        .map(|tc| tc.selected(keys))
        .transpose()?
        .flatten()
        .map(|q| q.value);
    let can_propose = !current
        && !future
        && leader == pins.key
        && (proposed_round > active.round || !active.proposed)
        && (proposed_round == 0 || timeout.is_some());
    Ok(Opportunity {
        format: "RLD-NATIVE-BFT-PROPOSAL-OPPORTUNITY-V1",
        context: context.clone(),
        round: active.round,
        key: pins.key.clone(),
        caller_head: pins.head,
        archive_sha256: pins.archive_head,
        authenticated_messages: count,
        current_proposals: current,
        future_proposals: future,
        proposed_round,
        leader,
        timeout,
        high,
        can_propose,
        ledger_changed: false,
        signing_authority: false,
        independent_freshness_qualified: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    // Policy-only inputs. No signature or ledger acceptance is inferred here.
    fn context() -> bft::Context {
        bft::Context {
            currency: Hash::ZERO,
            region: Hash::ZERO,
            epoch: Hash::ZERO,
            previous: None,
            parent_height: 0,
            parent_block: Hash::ZERO,
            parent_state: Hash::ZERO,
        }
    }
    fn vote(round: u64, key: &str) -> bft::TimeoutVote {
        bft::TimeoutVote {
            context: context(),
            round,
            high: None,
            approval: crate::Approval {
                key: key.into(),
                signature: String::new(),
            },
        }
    }
    #[test]
    fn future_proposal_priority_distinct_voters_and_last_round() {
        let keys = ["a", "b", "c", "d"].map(String::from);
        let mut timeouts = Timeouts::new();
        for key in ["a", "b"] {
            timeout_insert(&mut timeouts, vote(30, key)).unwrap();
        }
        assert_eq!(
            candidate_round(&context(), 0, "d", &keys, false, &timeouts).unwrap(),
            0
        );
        timeout_insert(&mut timeouts, vote(30, "c")).unwrap();
        assert_eq!(
            candidate_round(&context(), 0, "d", &keys, false, &timeouts).unwrap(),
            31
        );
        assert_eq!(
            candidate_round(&context(), 0, "d", &keys, true, &timeouts).unwrap(),
            0
        );
        assert_eq!(
            candidate_round(&context(), 31, "d", &keys, false, &timeouts).unwrap(),
            31
        );
        assert_eq!(
            candidate_round(&context(), 0, "a", &keys, false, &timeouts).unwrap(),
            0
        );
    }
    #[test]
    fn duplicate_timeout_never_counts_twice_or_discards_a_conflicting_vote() {
        let mut timeouts = Timeouts::new();
        let original = vote(0, "a");
        timeout_insert(&mut timeouts, original.clone()).unwrap();
        timeout_insert(&mut timeouts, original.clone()).unwrap();
        assert_eq!(timeouts[&0].len(), 1);
        let mut changed = original;
        changed.approval.signature.push('x');
        assert!(timeout_insert(&mut timeouts, changed).is_err());
        assert_eq!(timeouts[&0].len(), 1);
    }
}
