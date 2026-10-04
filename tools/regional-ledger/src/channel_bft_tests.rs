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

#[test]
fn native_channel_watch_bft_ordinary_candidate_two_challenges_full_finality_and_cold_replay() {
    let mut h = Harness::with_rules(channels::BFT_RULES);
    for _ in 0..3 {
        certify(&mut h, vec![]);
    }
    let mut opened = Vec::new();
    for _ in 0..2 {
        let open = channel::funding(&h.node.chain, &h.node.trust);
        let Command::Channel(body) = &open else {
            panic!()
        };
        let cid = body.action.intent.id().unwrap();
        certify(&mut h, vec![open]);
        let input = *h
            .node
            .chain
            .ledger
            .coins
            .iter()
            .find(|(_, c)| {
                c.payment.owner == public(10)
                    && c.mature <= h.node.chain.height() + 1
                    && c.channel_dependencies.is_empty()
            })
            .unwrap()
            .0;
        let reserve = channel::command(
            &h.node.chain,
            &h.node.trust,
            channels::Action::Reserve {
                channel: cid,
                input,
                fee_limit: Amount(3),
            },
            Some(10),
            &[10],
        );
        certify(&mut h, vec![reserve]);
        opened.push((cid, input));
    }
    let mut paid = Vec::new();
    for (cid, reserve) in &opened {
        let prior = channel::signed_state(
            &h.node.chain,
            &h.node.trust,
            *cid,
            0,
            [Amount(60), Amount::ZERO],
        );
        let receipt =
            crate::tests::channel_receipts::receipt(&h.node, *reserve, 1, prior, 10, None);
        let head = crate::history::manifest(&h.root.join("node"))
            .unwrap()
            .head()
            .unwrap();
        h.node
            .accept_channel_receipt(receipt.clone(), &receipt.statement.expected, head)
            .unwrap();
        paid.push(receipt);
    }
    let before = h.node.chain.ledger.clone();
    let mut projected = h.node.chain.clone();
    let mut closes = Vec::new();
    for receipt in &paid {
        let input = *projected
            .ledger
            .coins
            .iter()
            .find(|(_, c)| c.payment.owner == public(10) && c.mature <= projected.height() + 1)
            .unwrap()
            .0;
        let close = channel::command(
            &projected,
            &h.node.trust,
            channels::Action::Close {
                channel: receipt.statement.expected.channel,
                state: Box::new(receipt.prior.clone()),
                fee_input: input,
                fee: Amount(1),
            },
            Some(10),
            &[10],
        );
        let Command::Channel(body) = &close else {
            panic!()
        };
        projected.ledger = channels::execute_native(
            &projected.ledger,
            body,
            &channels::Context {
                declaration: &body.declaration,
                trust: &h.node.trust,
                evidence: &h.node.evidence,
                safety: &h.node.safety,
                height: h.node.chain.height() + 1,
                miner: &public(10),
            },
        )
        .unwrap();
        closes.push(close);
    }
    certify(&mut h, closes);
    let close_height = h.node.chain.height();
    let head = crate::history::manifest(&h.root.join("node"))
        .unwrap()
        .head()
        .unwrap();
    let current = h.node.chain.ledger.clone();
    let watch = h.node.channel_watch(public(10), head).unwrap();
    assert_eq!(watch.commands.len(), 2);
    // Normal companion asks for an empty candidate: native watching adds both.
    let candidate = h.node.bft_candidate(vec![], public(10)).unwrap();
    assert_eq!(candidate.blocks.last().unwrap().commands, watch.commands);
    assert_eq!(h.node.chain.ledger, current);
    assert_eq!(
        crate::history::manifest(&h.root.join("node"))
            .unwrap()
            .head()
            .unwrap(),
        head
    );
    let proposal = h.proposal(0, None, candidate);
    let prepared = h.prepare(&proposal, &[0, 1, 2]);
    let committed = h.commit(&proposal, &prepared, &[0, 1, 2]);
    h.node.finalize(committed).unwrap();
    let book = &h.node.chain.ledger.channel_state.as_ref().unwrap().book;
    for receipt in &paid {
        let channels::Phase::Closing {
            state,
            close_height: original,
            deadline,
        } = &book.channels[&receipt.statement.expected.channel].phase
        else {
            panic!()
        };
        assert_eq!(state.as_ref(), &receipt.next);
        assert_eq!(*original, close_height);
        assert_eq!(*deadline, close_height + channels::WINDOW);
        assert!(!book.reserves.contains_key(&receipt.statement.reserve));
    }
    assert_eq!(
        book.channels.len(),
        before.channel_state.as_ref().unwrap().book.channels.len()
    );
    let (issued, liquid, escrow, outbound) =
        conservation_with_escrow(&[h.node.chain.clone()]).unwrap();
    assert_eq!(issued, add(add(liquid, escrow).unwrap(), outbound).unwrap());
    let head = crate::history::manifest(&h.root.join("node"))
        .unwrap()
        .head()
        .unwrap();
    assert!(h
        .node
        .channel_watch(public(10), head)
        .unwrap()
        .commands
        .is_empty());
    let pin = h.node.trust.currency().unwrap();
    crate::storage::verify_pinned_image(&h.root.join("node"), &public(1), pin, head).unwrap();
    for receipt in &paid {
        receipt
            .verify_anchor(&h.node.trust, &h.node.evidence)
            .unwrap();
    }
    assert_eq!(crate::channel_receipt::WATCH_SLOTS, 4);
}
