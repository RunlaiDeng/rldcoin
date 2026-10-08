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
        origins: None,
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
    channel_watch_cycle(channels::BFT_RULES);
}
#[test]
fn native_paged_channel_watch_ordinary_candidate_two_receipts_full_finality_and_cold_replay() {
    channel_watch_cycle(crate::paged_bft::RULES);
}
fn channel_watch_cycle(rules: &str) {
    let mut h = Harness::with_rules(rules);
    h.retain = true;
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
            channels::Action::ReserveBudget {
                channel: cid,
                input,
                fee_limit: Amount(3),
                max_fee: h.node.chain.ledger.coins[&input].payment.amount,
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
        let head = h.node.storage_head().unwrap();
        h.node
            .accept_channel_receipt(receipt.clone(), &receipt.statement.expected, head)
            .unwrap();
        paid.push(receipt);
    }
    if crate::paged_bft::is_profile(rules) {
        assert_eq!(h.node.paged_receipt_history().unwrap().len(), 2);
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
    let head = h.node.storage_head().unwrap();
    let current = h.node.chain.ledger.clone();
    let watch = h.node.channel_watch(public(10), head).unwrap();
    assert_eq!(watch.commands.len(), 2);
    // Normal companion asks for an empty candidate: native watching adds both.
    let candidate = h.node.bft_candidate(vec![], public(10)).unwrap();
    assert_eq!(candidate.blocks.last().unwrap().commands, watch.commands);
    assert_eq!(h.node.chain.ledger, current);
    assert_eq!(h.node.storage_head().unwrap(), head);
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
        assert_eq!(
            book.reserves[&receipt.statement.reserve]
                .budget
                .as_ref()
                .unwrap()
                .spent,
            Amount(3)
        );
    }
    assert_eq!(
        book.channels.len(),
        before.channel_state.as_ref().unwrap().book.channels.len()
    );
    let (issued, liquid, escrow, outbound) =
        conservation_with_escrow(&[h.node.chain.clone()]).unwrap();
    assert_eq!(issued, add(add(liquid, escrow).unwrap(), outbound).unwrap());
    let head = h.node.storage_head().unwrap();
    assert!(h
        .node
        .channel_watch(public(10), head)
        .unwrap()
        .commands
        .is_empty());
    let pin = h.node.trust.currency().unwrap();
    if crate::paged_bft::is_profile(rules) {
        let pins = ChannelColdPins {
            currency: pin,
            head,
            ledger: h.node.chain.ledger.clone(),
            height: h.node.chain.height(),
            receipts: paid.clone(),
        };
        let root = h.root.clone();
        crate::keystore::private_create(
            &root.join("channel-cold-pins.json"),
            &serde_json::to_vec(&pins).unwrap(),
        )
        .unwrap();
        // Only this newly successful fixture is closed for a full pinned cold
        // child. Prior failed targets are never reopened by this test.
        drop(h);
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::regional_bft::value_channels::native_paged_channel_receipt_cold_child",
                "--ignored",
                "--nocapture",
            ])
            .env("RLD_PAGED_CHANNEL_COLD_ROOT", &root)
            .current_dir("/Users/galaxy/GitHub/rldcoin")
            .output()
            .unwrap();
        println!("{}", String::from_utf8_lossy(&result.stdout));
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(String::from_utf8_lossy(&result.stdout).contains("test result: ok. 1 passed"));
        assert_eq!(crate::channel_receipt::WATCH_SLOTS, 4);
        return;
    }
    crate::storage::verify_pinned_image(&h.root.join("node"), &public(1), pin, head).unwrap();
    for receipt in &paid {
        receipt
            .verify_anchor(&h.node.trust, &h.node.evidence)
            .unwrap();
    }
    assert_eq!(crate::channel_receipt::WATCH_SLOTS, 4);
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelColdPins {
    currency: Hash,
    head: Hash,
    ledger: Ledger,
    height: u64,
    receipts: Vec<crate::channel_receipt::Receipt>,
}
#[test]
#[ignore = "fresh bounded parent supplies independently retained complete caller pins"]
fn native_paged_channel_receipt_cold_child() {
    let root = PathBuf::from(
        std::env::var_os("RLD_PAGED_CHANNEL_COLD_ROOT").expect("private fresh caller root"),
    );
    let pins: ChannelColdPins =
        crate::storage::read_json(&root.join("channel-cold-pins.json")).unwrap();
    let before = super::retained_native_replay::inventory(&root);
    let node =
        Store::open_pinned(&root.join("node"), &public(1), pins.currency, pins.head).unwrap();
    assert_eq!(node.chain.ledger, pins.ledger);
    assert_eq!(node.chain.height(), pins.height);
    assert_eq!(node.paged_receipt_history().unwrap().len(), 2);
    for receipt in &pins.receipts {
        receipt.verify_anchor(&node.trust, &node.evidence).unwrap();
        let channels::Phase::Closing { state, .. } = &node
            .chain
            .ledger
            .channel_state
            .as_ref()
            .unwrap()
            .book
            .channels[&receipt.statement.expected.channel]
            .phase
        else {
            panic!()
        };
        assert_eq!(state.as_ref(), &receipt.next);
    }
    assert!(node
        .channel_watch(public(10), pins.head)
        .unwrap()
        .commands
        .is_empty());
    assert_eq!(super::retained_native_replay::inventory(&root), before);
    println!("paged-channel full_native_genesis_cold=true two_complete_signed_receipts=true two_challenges_finalized=true unchanged_bytes=true");
}
