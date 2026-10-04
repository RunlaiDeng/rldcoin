use super::*;
use crate::channels as c;
use std::fs;

pub(super) fn package(rules: &str) -> Bootstrap {
    let mut p = bootstrap();
    p.currency.cap = Amount::TOTAL_SUPPLY;
    p.currency.block_reward = rld_pow::subsidy(1).unwrap();
    p.currency.signature = signature(1, &p.currency.bytes().unwrap());
    for a in &mut p.admissions {
        a.currency = p.currency.id().unwrap();
        a.rules = rules.into();
        a.value_rules = Some(c::profile_hash().unwrap());
        a.signature = signature(1, &a.bytes().unwrap());
    }
    p
}
pub(super) fn declaration(chain: &Chain, trust: &Trust) -> c::Declaration {
    let mut d = c::Declaration {
        format: c::FORMAT.into(),
        currency: trust.currency().unwrap(),
        region: chain.region,
        implementation: implementation().unwrap(),
        rules: c::rules_hash(),
        authority_signature: String::new(),
    };
    d.authority_signature = signature(1, &d.bytes().unwrap());
    d
}
pub(crate) fn parties() -> [String; 2] {
    let mut parties = [public(10), public(11)];
    parties.sort();
    parties
}
pub(crate) fn command(
    chain: &Chain,
    trust: &Trust,
    action: c::Action,
    actor: Option<u8>,
    seeds: &[u8],
) -> Command {
    let d = declaration(chain, trust);
    let empty = c::Book::default();
    let book = chain
        .ledger
        .channel_state
        .as_ref()
        .map(|s| &s.book)
        .unwrap_or(&empty);
    let intent = c::Intent {
        rules: d.rules,
        currency: d.currency,
        region: d.region,
        nonce: chain.height(),
        valid_through: chain.height() + 10,
        actor: actor.map(public),
        previous: Some(book.head(&chain.ledger, &d).unwrap()),
        action,
    };
    let mut approvals: Vec<_> = seeds
        .iter()
        .map(|s| Approval {
            key: public(*s),
            signature: signature(*s, &intent.bytes().unwrap()),
        })
        .collect();
    approvals.sort_by(|a, b| a.key.cmp(&b.key));
    Command::Channel(Box::new(c::NativeCommand {
        declaration: d,
        action: c::SignedAction { intent, approvals },
    }))
}
pub(crate) fn signed_state(
    chain: &Chain,
    trust: &Trust,
    channel: Hash,
    sequence: u64,
    payouts: [Amount; 2],
) -> c::SignedState {
    let statement = c::StateStatement {
        currency: trust.currency().unwrap(),
        region: chain.region,
        channel,
        sequence,
        payouts,
    };
    let mut approvals: Vec<_> = [10, 11]
        .iter()
        .map(|s| Approval {
            key: public(*s),
            signature: signature(*s, &statement.bytes().unwrap()),
        })
        .collect();
    approvals.sort_by(|a, b| a.key.cmp(&b.key));
    c::SignedState {
        witness: Some(crate::channel_state_witness::fixture(
            &statement,
            parties(),
            None,
        )),
        statement,
        approvals,
    }
}
pub(crate) fn funding(chain: &Chain, trust: &Trust) -> Command {
    let (input, coin) = chain
        .ledger
        .coins
        .iter()
        .find(|(_, c)| {
            c.payment.owner == public(10)
                && c.mature <= chain.height() + 1
                && c.payment.amount >= Amount(61)
        })
        .unwrap();
    command(
        chain,
        trust,
        c::Action::Open {
            witness: Some(public(12)),
            inputs: vec![*input],
            parties: parties(),
            capacity: Amount(60),
            initial: [Amount(60), Amount::ZERO],
            change: vec![Payment {
                owner: public(10),
                amount: coin.payment.amount.checked_sub(Amount(61)).unwrap(),
            }],
            fee: Amount(1),
        },
        Some(10),
        &[10, 11],
    )
}
fn selected(node: &mut Store, commands: Vec<Command>) {
    let mut b = node.template(commands, public(10)).unwrap();
    mine(&mut b).unwrap();
    node.accept(b).unwrap();
}
#[test]
fn native_channel_ordinary_replay_commitment_latest_head_and_issuance() {
    let p = package(c::SEGMENTED_RULES);
    let pin = p.currency.id().unwrap();
    let region = p.admissions[0].id().unwrap();
    let dir = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "rld-channel-ordinary-{}",
            rld_core::generate_identity().public_key
        ));
    let mut node = Store::create(&dir, p.clone(), region, &public(1), pin).unwrap();
    for _ in 0..3 {
        selected(&mut node, vec![]);
    }
    assert_eq!(
        node.chain.ledger.minted,
        Amount(rld_pow::cumulative_emission(3))
    );
    let open = funding(&node.chain, &node.trust);
    let Command::Channel(c) = &open else { panic!() };
    let channel = c.action.intent.id().unwrap();
    let before = node.chain.ledger.clone();
    selected(&mut node, vec![open.clone()]);
    let book = &node.chain.ledger.channel_state.as_ref().unwrap().book;
    assert_eq!(book.locked().unwrap(), Amount(60));
    assert!(!node
        .chain
        .ledger
        .coins
        .values()
        .any(|c| c.payment.amount == Amount(60)));
    assert!(node.template(vec![open], public(10)).is_err());
    let current = state_proof::Commitment::from_ledger(&node.chain.ledger).unwrap();
    assert_eq!(
        current,
        state_proof::Commitment::from_ledger_uncached(&node.chain.ledger).unwrap()
    );
    assert!(current.channel_state.is_some());
    let (issued, liquid, escrow, pending) =
        conservation_with_escrow(&[node.chain.clone()]).unwrap();
    assert_eq!(escrow, Amount(60));
    assert_eq!(issued, add(liquid, escrow).unwrap());
    assert!(pending.is_zero());
    assert!(conservation(&[node.chain.clone()]).is_err());
    let input = *node
        .chain
        .ledger
        .coins
        .iter()
        .find(|(_, c)| {
            c.payment.owner == public(10)
                && c.mature <= node.chain.height() + 1
                && c.payment.amount > Amount(100)
        })
        .unwrap()
        .0;
    let reserve = command(
        &node.chain,
        &node.trust,
        c::Action::Reserve {
            channel,
            input,
            fee_limit: Amount(3),
        },
        Some(10),
        &[10],
    );
    selected(&mut node, vec![reserve]);
    let expected = node.chain.ledger.clone();
    let expected_root = expected.root().unwrap();
    let journal = node.journal.clone();
    let (_, _, cold) = journal.replay_at(&public(1), pin, &dir).unwrap();
    assert_eq!(cold.ledger, expected);
    assert_eq!(cold.ledger.root().unwrap(), expected_root);
    let retained_head = history::manifest(&dir).unwrap().head().unwrap();
    drop(node);
    let mut node = Store::open_pinned(&dir, &public(1), pin, retained_head).unwrap();
    assert_eq!(node.chain.ledger, expected);
    let fee_input = *node
        .chain
        .ledger
        .coins
        .iter()
        .find(|(_, c)| c.payment.owner == public(10) && c.mature <= node.chain.height() + 1)
        .unwrap()
        .0;
    let close = command(
        &node.chain,
        &node.trust,
        c::Action::Close {
            channel,
            state: Box::new(signed_state(
                &node.chain,
                &node.trust,
                channel,
                0,
                [Amount(60), Amount::ZERO],
            )),
            fee_input,
            fee: Amount(1),
        },
        Some(10),
        &[10],
    );
    let mut bad = node.template(vec![close.clone()], public(10)).unwrap();
    bad.header.state = before.root().unwrap();
    mine(&mut bad).unwrap();
    let saved = (
        node.chain.ledger.clone(),
        node.chain.tip().unwrap(),
        history::manifest(&dir).unwrap().head().unwrap(),
    );
    assert!(node.accept(bad).is_err());
    assert_eq!(
        (
            node.chain.ledger.clone(),
            node.chain.tip().unwrap(),
            history::manifest(&dir).unwrap().head().unwrap()
        ),
        saved
    );
    selected(&mut node, vec![close]);
    let h = node.chain.height();
    assert!(
        matches!(node.chain.ledger.channel_state.as_ref().unwrap().book.channels[&channel].phase,
        c::Phase::Closing { close_height,deadline,.. } if close_height==h && deadline==h+2016)
    );
    let challenge = command(
        &node.chain,
        &node.trust,
        c::Action::Challenge {
            channel,
            state: Box::new(signed_state(
                &node.chain,
                &node.trust,
                channel,
                1,
                [Amount(20), Amount(40)],
            )),
            reserve: input,
            fee: Amount(2),
        },
        None,
        &[],
    );
    selected(&mut node, vec![challenge]);
    assert!(node
        .chain
        .ledger
        .channel_state
        .as_ref()
        .unwrap()
        .book
        .reserves
        .is_empty());
    let proof = checkpoint(&node.chain, &node.trust);
    node.add_evidence(Evidence {
        snapshots: vec![proof.clone()],
    })
    .unwrap();
    let checked = VerifiedEvidence::verify(&node.journal.evidence, &node.trust).unwrap();
    assert_eq!(
        &checked.snapshots[&proof.statement.id().unwrap()].1,
        &node.chain.ledger
    );
    let key = *node.chain.ledger.coins.keys().next().unwrap();
    let record =
        state_proof::Proof::from_ledger(&node.chain.ledger, state_proof::Collection::Coins, key)
            .unwrap();
    record
        .verify(
            node.chain.ledger.root().unwrap(),
            state_proof::Collection::Coins,
            key,
        )
        .unwrap();
    let mut changed = record.clone();
    changed.state.channel_state = None;
    assert!(changed
        .verify(
            node.chain.ledger.root().unwrap(),
            state_proof::Collection::Coins,
            key
        )
        .is_err());
    let (_, _, cold) = node.journal.replay_at(&public(1), pin, &dir).unwrap();
    assert_eq!(cold.ledger, node.chain.ledger);
    assert!(Store::open_pinned(&dir, &public(1), pin, retained_head).is_err());
    drop(node);
    fs::remove_dir_all(dir).unwrap();
}
#[test]
fn native_channel_admission_legacy_and_source_fields_refuse() {
    let mut p = package(c::SEGMENTED_RULES);
    let pin = p.currency.id().unwrap();
    p.admissions[0].value_rules = None;
    p.admissions[0].signature = signature(1, &p.admissions[0].bytes().unwrap());
    assert!(Trust::verify(&p, &public(1), pin).is_err());
    p.admissions[0].value_rules = Some(Hash([8; 32]));
    p.admissions[0].signature = signature(1, &p.admissions[0].bytes().unwrap());
    assert!(Trust::verify(&p, &public(1), pin).is_err());
    let mut f = Fixture::new();
    let legacy = funding(&f.earth, &f.trust);
    let before = f.earth.ledger.clone();
    assert!(f
        .earth
        .template(vec![legacy], public(10), &f.trust, &f.evidence)
        .is_err());
    assert_eq!(f.earth.ledger, before);
    let new = package(c::SEGMENTED_RULES);
    let pin = new.currency.id().unwrap();
    let trust = Trust::verify(&new, &public(1), pin).unwrap();
    f.earth = Chain::new(new.admissions[0].id().unwrap(), &trust).unwrap();
    let evidence = VerifiedEvidence::default();
    for _ in 0..3 {
        advance(&mut f.earth, &trust, &evidence, vec![]);
    }
    let mut bad = funding(&f.earth, &trust);
    let Command::Channel(c) = &mut bad else {
        panic!()
    };
    c.action.intent.previous = None;
    for a in &mut c.action.approvals {
        let seed = if a.key == public(10) { 10 } else { 11 };
        a.signature = signature(seed, &c.action.intent.bytes().unwrap());
    }
    assert!(f
        .earth
        .template(vec![bad], public(10), &trust, &evidence)
        .is_err());
}
#[test]
fn native_channel_ordered_block_reservation_replays_without_a_peer_cache() {
    let p = package(c::SEGMENTED_RULES);
    let trust = Trust::verify(&p, &public(1), p.currency.id().unwrap()).unwrap();
    let mut chain = Chain::new(p.admissions[0].id().unwrap(), &trust).unwrap();
    let evidence = VerifiedEvidence::default();
    for _ in 0..3 {
        advance(&mut chain, &trust, &evidence, vec![]);
    }
    let open = funding(&chain, &trust);
    let Command::Channel(open_native) = &open else {
        panic!()
    };
    let channel = open_native.action.intent.id().unwrap();
    let mut projected = chain.clone();
    projected.ledger = c::execute_native(
        &chain.ledger,
        open_native,
        &c::Context {
            declaration: &open_native.declaration,
            trust: &trust,
            evidence: &evidence,
            safety: &conflict::Safety::default(),
            height: chain.height() + 1,
            miner: &public(10),
        },
    )
    .unwrap();
    let reserve_input = *projected
        .ledger
        .coins
        .iter()
        .find(|(_, coin)| coin.payment.owner == public(10) && coin.mature <= chain.height() + 1)
        .unwrap()
        .0;
    let reserve = command(
        &projected,
        &trust,
        c::Action::Reserve {
            channel,
            input: reserve_input,
            fee_limit: Amount(1),
        },
        Some(10),
        &[10],
    );
    let commands = vec![open, reserve];
    conflict::Safety::default()
        .check(&chain, &commands, &evidence)
        .unwrap();
    advance(&mut chain, &trust, &evidence, commands);
    assert_eq!(
        chain
            .ledger
            .channel_state
            .as_ref()
            .unwrap()
            .book
            .reserves
            .len(),
        1
    );
    let proof = checkpoint(&chain, &trust);
    let cold = VerifiedEvidence::verify(
        &Evidence {
            snapshots: vec![proof.clone()],
        },
        &trust,
    )
    .unwrap();
    assert_eq!(
        cold.snapshots[&proof.statement.id().unwrap()].1,
        chain.ledger
    );
}
