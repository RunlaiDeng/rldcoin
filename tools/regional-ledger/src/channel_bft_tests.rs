use super::super::channel_integration as channel;
use super::*;
use crate::bft_network::{Body, Envelope};

fn certify(h: &mut Harness, commands: Vec<Command>) {
    let candidate = h.node.bft_candidate(commands, public(10)).unwrap();
    let proposal = h.proposal(0, None, candidate);
    let prepared = h.prepare(&proposal, &[0, 1, 2]);
    let committed = h.commit(&proposal, &prepared, &[0, 1, 2]);
    h.node.finalize(committed).unwrap();
}
#[test]
fn native_channel_bft_submission_certified_inclusion_and_cold_head_replay() {
    let mut h = Harness::with_rules(channels::BFT_RULES);
    for _ in 0..3 {
        certify(&mut h, vec![]);
    }
    let open = channel::funding(&h.node.chain, &h.node.trust);
    let before = h.node.chain.ledger.clone();
    let envelope = Envelope {
        format: crate::bft_network::FORMAT.into(),
        currency: h.node.trust.currency().unwrap(),
        region: h.node.chain.region,
        evidence: h.node.journal.evidence.clone(),
        body: Body::Submission(vec![open.clone()]),
    };
    let ident = envelope.verify(&h.node).unwrap();
    let wire = envelope.pack().unwrap();
    let expanded = wire.expand().unwrap();
    assert_eq!(expanded.verify(&h.node).unwrap(), ident);
    h.node.bft_submit(vec![open.clone()]).unwrap();
    assert_eq!(h.node.chain.ledger, before);
    let candidate = h
        .node
        .bft_candidate(vec![open.clone()], public(10))
        .unwrap();
    assert!(h
        .node
        .accept(candidate.blocks.last().unwrap().clone())
        .is_err());
    let Command::Channel(c) = &open else { panic!() };
    let cid = c.action.intent.id().unwrap();
    certify(&mut h, vec![open]);
    assert_eq!(
        h.node
            .chain
            .ledger
            .channel_state
            .as_ref()
            .unwrap()
            .book
            .locked()
            .unwrap(),
        Amount(60)
    );
    assert_eq!(
        h.node.chain.ledger.minted,
        Amount(rld_pow::cumulative_emission(4))
    );
    let value = h.node.chain.ledger.clone();
    let head = crate::history::manifest(&h.root.join("node"))
        .unwrap()
        .head()
        .unwrap();
    let journal = h.node.journal.clone();
    let pin = h.node.trust.currency().unwrap();
    let (_, evidence, cold) = journal.replay(&public(1), pin).unwrap();
    assert_eq!(cold.ledger, value);
    let checked = VerifiedEvidence::verify(&journal.evidence, &h.node.trust).unwrap();
    let latest = h.node.chain.finalized.unwrap();
    assert_eq!(checked.snapshots[&latest].1, value);
    assert_eq!(evidence.snapshots[&latest].1, value);
    assert!(h
        .node
        .chain
        .ledger
        .channel_state
        .as_ref()
        .unwrap()
        .book
        .channels
        .contains_key(&cid));
    crate::storage::verify_pinned_image(&h.root.join("node"), &public(1), pin, head).unwrap();
    assert_eq!(h.node.chain.ledger, value);
    assert!(h
        .node
        .bft_candidate(vec![channel::funding(&cold, &h.node.trust)], public(10))
        .is_ok());
}
