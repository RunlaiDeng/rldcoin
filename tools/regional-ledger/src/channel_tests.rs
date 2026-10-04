use super::*;
use crate::channels as c;
fn declaration(f: &Fixture) -> c::Declaration {
    let mut d = c::Declaration {
        format: c::FORMAT.into(),
        currency: f.trust.currency().unwrap(),
        region: f.earth.region,
        implementation: implementation().unwrap(),
        rules: c::rules_hash(),
        authority_signature: String::new(),
    };
    d.authority_signature = signature(1, &d.bytes().unwrap());
    d
}
fn action(d: &c::Declaration, step: c::Action, actor: Option<u8>, seeds: &[u8]) -> c::SignedAction {
    let intent = c::Intent {
        rules: d.rules,
        currency: d.currency,
        region: d.region,
        nonce: 0,
        valid_through: u64::MAX,
        actor: actor.map(public),
        action: step,
    };
    let mut approvals = seeds
        .iter()
        .map(|s| Approval {
            key: public(*s),
            signature: signature(*s, &intent.bytes().unwrap()),
        })
        .collect::<Vec<_>>();
    approvals.sort_by(|a, b| a.key.cmp(&b.key));
    c::SignedAction { intent, approvals }
}
fn state(d: &c::Declaration, channel: Hash, sequence: u64, a: u128, b: u128) -> c::SignedState {
    let statement = c::StateStatement {
        currency: d.currency,
        region: d.region,
        channel,
        sequence,
        payouts: [Amount(a), Amount(b)],
    };
    let mut approvals = [10, 11]
        .into_iter()
        .map(|s| Approval {
            key: public(s),
            signature: signature(s, &statement.bytes().unwrap()),
        })
        .collect::<Vec<_>>();
    approvals.sort_by(|a, b| a.key.cmp(&b.key));
    c::SignedState {
        statement,
        approvals,
    }
}
fn parties() -> [String; 2] {
    let mut p = [public(10), public(11)];
    p.sort();
    p
}
#[allow(clippy::too_many_arguments)] // Keep independent source, safety, value and retained-head fixture inputs explicit.
fn run(
    f: &Fixture,
    d: &c::Declaration,
    safety: &conflict::Safety,
    book: &c::Book,
    value: &Ledger,
    command: &c::SignedAction,
    height: u64,
    head: Hash,
) -> Result<(c::Book, Ledger, Hash)> {
    book.execute(
        value,
        command,
        &c::Context {
            declaration: d,
            trust: &f.trust,
            evidence: &f.evidence,
            safety,
            height,
            miner: &public(10),
        },
        head,
    )
}
fn buckets(book: &c::Book, value: &Ledger) -> (Amount, Amount) {
    (
        sum(value.coins.values().map(|c| c.payment.amount)).unwrap(),
        book.locked().unwrap(),
    )
}
fn inputs(value: &Ledger) -> Vec<Hash> {
    value.coins.keys().copied().collect()
}
#[test]
fn native_channel_funding_reserve_close_challenge_settle_conserve_and_keep_head() {
    let f = Fixture::new();
    let d = declaration(&f);
    let safe = conflict::Safety::default();
    let book = c::Book::default();
    let value = f.earth.ledger.clone();
    let ids = inputs(&value);
    let head = book.head(&value, &d).unwrap();
    let open = action(
        &d,
        c::Action::Open {
            inputs: vec![ids[0]],
            parties: parties(),
            capacity: Amount(60),
            initial: [Amount(60), Amount::ZERO],
            change: vec![Payment {
                owner: public(10),
                amount: Amount(39),
            }],
            fee: Amount(1),
        },
        Some(10),
        &[10, 11],
    );
    let channel = open.intent.id().unwrap();
    let (book, value, h1) = run(&f, &d, &safe, &book, &value, &open, 5, head).unwrap();
    assert_eq!(buckets(&book, &value), (Amount(240), Amount(60)));
    let reserve = action(
        &d,
        c::Action::Reserve {
            channel,
            input: ids[1],
            fee_limit: Amount(5),
        },
        Some(10),
        &[10],
    );
    let old_book = book.clone();
    let old_value = value.clone();
    let (book, value, h2) = run(&f, &d, &safe, &book, &value, &reserve, 5, h1).unwrap();
    assert_eq!(buckets(&book, &value), (Amount(140), Amount(160)));
    let close = action(
        &d,
        c::Action::Close {
            channel,
            state: Box::new(state(&d, channel, 0, 60, 0)),
            fee_input: ids[2],
            fee: Amount(2),
        },
        Some(10),
        &[10],
    );
    assert!(run(&f, &d, &safe, &old_book, &old_value, &close, 5, h2)
        .unwrap_err()
        .contains("latest channel head"));
    let (book, value, h3) = run(&f, &d, &safe, &book, &value, &close, 5, h2).unwrap();
    let settle = action(&d, c::Action::Settle { channel }, None, &[]);
    assert!(run(&f, &d, &safe, &book, &value, &settle, 2021, h3).is_err());
    let challenge = action(
        &d,
        c::Action::Challenge {
            channel,
            state: Box::new(state(&d, channel, 1, 20, 40)),
            reserve: ids[1],
            fee: Amount(3),
        },
        None,
        &[],
    );
    assert!(
        run(&f, &d, &safe, &book, &value, &challenge, 5, h3).is_err(),
        "challenge must wait for a successor of the included close"
    );
    assert!(run(&f, &d, &safe, &book, &value, &challenge, 4, h3).is_err());
    assert!(run(&f, &d, &safe, &book, &value, &challenge, 2022, h3).is_err());
    // Either endpoint succeeds from the same retained pre-challenge state.
    assert!(run(&f, &d, &safe, &book, &value, &challenge, 6, h3).is_ok());
    // Arithmetic-boundary fixture contexts, not 2016 ordinary native blocks.
    let (book, value, h4) = run(&f, &d, &safe, &book, &value, &challenge, 2021, h3).unwrap();
    assert_eq!(buckets(&book, &value), (Amount(240), Amount(60)));
    assert!(run(&f, &d, &safe, &book, &value, &challenge, 2021, h4).is_err());
    let (book, value, h5) = run(&f, &d, &safe, &book, &value, &settle, 2022, h4).unwrap();
    assert_eq!(buckets(&book, &value), (Amount(300), Amount::ZERO));
    assert!(matches!(
        book.channels[&channel].phase,
        c::Phase::Settled { .. }
    ));
    assert!(run(&f, &d, &safe, &book, &value, &settle, 2023, h5).is_err());
    assert_ne!(head, h5);
}
#[test]
fn native_channel_complete_owners_domains_and_failures_are_atomic() {
    let mut f = Fixture::new();
    let input = coins(&f.earth, 10)[0];
    let pay = intent(
        &f.earth,
        &f.trust,
        vec![input],
        vec![
            Payment {
                owner: public(11),
                amount: Amount(70),
            },
            Payment {
                owner: public(12),
                amount: Amount(29),
            },
        ],
        None,
        None,
        1,
        0,
        &[10],
    );
    advance(
        &mut f.earth,
        &f.trust,
        &f.evidence,
        vec![Command::Spend(Box::new(pay))],
    );
    let d = declaration(&f);
    let safe = conflict::Safety::default();
    let book = c::Book::default();
    let value = f.earth.ledger.clone();
    let mut selected = vec![coins(&f.earth, 11)[0], coins(&f.earth, 12)[0]];
    selected.sort();
    let open = action(
        &d,
        c::Action::Open {
            inputs: selected,
            parties: parties(),
            capacity: Amount(80),
            initial: [Amount(80), Amount::ZERO],
            change: vec![Payment {
                owner: public(12),
                amount: Amount(18),
            }],
            fee: Amount(1),
        },
        Some(12),
        &[10, 11, 12],
    );
    let head = book.head(&value, &d).unwrap();
    let before = (book.clone(), value.clone());
    assert!(run(&f, &d, &safe, &book, &value, &open, 6, head).is_ok());
    for i in 0..open.approvals.len() {
        let mut bad = open.clone();
        bad.approvals.remove(i);
        assert!(run(&f, &d, &safe, &book, &value, &bad, 6, head).is_err());
    }
    let mut bad = open.clone();
    bad.intent.rules = Hash([9; 32]);
    assert!(run(&f, &d, &safe, &book, &value, &bad, 6, head).is_err());
    let mut bad = open.clone();
    bad.intent.valid_through = 5;
    assert!(run(&f, &d, &safe, &book, &value, &bad, 6, head).is_err());
    let mut bad = open.clone();
    bad.approvals.reverse();
    assert!(run(&f, &d, &safe, &book, &value, &bad, 6, head).is_err());
    let mut bad = open.clone();
    bad.approvals[0].signature = "00".into();
    assert!(run(&f, &d, &safe, &book, &value, &bad, 6, head).is_err());
    assert_eq!((book, value), before);
    let mut wrong = d.clone();
    wrong.rules = Hash([8; 32]);
    wrong.authority_signature = signature(1, &wrong.bytes().unwrap());
    assert!(wrong.verify(&f.trust, f.earth.region).is_err());
    let mut unknown = serde_json::to_value(&open).unwrap();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("balance".into(), serde_json::json!(99));
    assert!(serde_json::from_value::<c::SignedAction>(unknown).is_err());
}
#[test]
fn native_channel_unused_reserve_returns_once_and_overflow_refuses() {
    let f = Fixture::new();
    let d = declaration(&f);
    let safe = conflict::Safety::default();
    let book = c::Book::default();
    let value = f.earth.ledger.clone();
    let ids = inputs(&value);
    let open = action(
        &d,
        c::Action::Open {
            inputs: vec![ids[0]],
            parties: parties(),
            capacity: Amount(100),
            initial: [Amount(100), Amount::ZERO],
            change: vec![],
            fee: Amount::ZERO,
        },
        Some(10),
        &[10, 11],
    );
    let channel = open.intent.id().unwrap();
    let head = book.head(&value, &d).unwrap();
    let (book, value, head) = run(&f, &d, &safe, &book, &value, &open, 5, head).unwrap();
    let reserve = action(
        &d,
        c::Action::Reserve {
            channel,
            input: ids[1],
            fee_limit: Amount(1),
        },
        Some(10),
        &[10],
    );
    let (book, value, head) = run(&f, &d, &safe, &book, &value, &reserve, 5, head).unwrap();
    let close = action(
        &d,
        c::Action::Close {
            channel,
            state: Box::new(state(&d, channel, 1, 30, 70)),
            fee_input: ids[2],
            fee: Amount(1),
        },
        Some(10),
        &[10],
    );
    assert!(run(&f, &d, &safe, &book, &value, &close, u64::MAX, head).is_err());
    let (book, value, head) = run(&f, &d, &safe, &book, &value, &close, 5, head).unwrap();
    let settle = action(&d, c::Action::Settle { channel }, None, &[]);
    let (book, value, _) = run(&f, &d, &safe, &book, &value, &settle, 2022, head).unwrap();
    assert!(book.reserves.is_empty());
    assert_eq!(buckets(&book, &value), (Amount(300), Amount::ZERO));
}
#[test]
fn native_channel_reservation_capacity_refuses_atomically_without_pruning() {
    let mut f = Fixture::new();
    let original = coins(&f.earth, 10);
    let split = intent(
        &f.earth,
        &f.trust,
        vec![original[0]],
        vec![
            Payment {
                owner: public(10),
                amount: Amount(6)
            };
            16
        ],
        None,
        None,
        4,
        0,
        &[10],
    );
    let tx = split.intent.id().unwrap();
    advance(
        &mut f.earth,
        &f.trust,
        &f.evidence,
        vec![Command::Spend(Box::new(split))],
    );
    for _ in 0..2 {
        advance(&mut f.earth, &f.trust, &f.evidence, vec![]);
    }
    let d = declaration(&f);
    let safe = conflict::Safety::default();
    let mut book = c::Book::default();
    let mut value = f.earth.ledger.clone();
    let mut head = book.head(&value, &d).unwrap();
    let height = f.earth.height() + 1;
    let open = action(
        &d,
        c::Action::Open {
            inputs: vec![original[1]],
            parties: parties(),
            capacity: Amount(100),
            initial: [Amount(100), Amount::ZERO],
            change: vec![],
            fee: Amount::ZERO,
        },
        Some(10),
        &[10, 11],
    );
    let channel = open.intent.id().unwrap();
    (book, value, head) = run(&f, &d, &safe, &book, &value, &open, height, head).unwrap();
    for i in 0..16u32 {
        let reserve = action(
            &d,
            c::Action::Reserve {
                channel,
                input: id("output", &(tx, i)).unwrap(),
                fee_limit: Amount(1),
            },
            Some(10),
            &[10],
        );
        (book, value, head) = run(&f, &d, &safe, &book, &value, &reserve, height, head).unwrap();
    }
    assert_eq!(book.reserves.len(), c::MAX_RESERVES);
    assert_eq!(book.locked().unwrap(), Amount(196));
    let retained = (book.clone(), value.clone(), head);
    let excess = action(
        &d,
        c::Action::Reserve {
            channel,
            input: original[2],
            fee_limit: Amount(1),
        },
        Some(10),
        &[10],
    );
    assert!(run(&f, &d, &safe, &book, &value, &excess, height, head)
        .unwrap_err()
        .contains("reservation count"));
    assert_eq!(
        (book.clone(), value.clone(), book.head(&value, &d).unwrap()),
        retained
    );
    assert!(value.coins.contains_key(&original[2]));
}
#[test]
fn native_channel_real_onward_lineage_and_authenticated_incident_cannot_be_laundered() {
    let mut f = Fixture::new();
    f.imported();
    for _ in 0..2 {
        advance(&mut f.proxima, &f.trust, &f.evidence, vec![]);
    }
    finalize(&mut f.proxima, &f.trust, &mut f.evidence);
    let pay = intent(
        &f.proxima,
        &f.trust,
        vec![coins(&f.proxima, 11)[0]],
        vec![Payment {
            owner: public(11),
            amount: Amount(2),
        }],
        Some(f.earth.region),
        Some(Payment {
            owner: public(10),
            amount: Amount(75),
        }),
        1,
        2,
        &[11],
    );
    let export = pay.intent.id().unwrap();
    advance(
        &mut f.proxima,
        &f.trust,
        &f.evidence,
        vec![Command::Spend(Box::new(pay))],
    );
    let sid = finalize(&mut f.proxima, &f.trust, &mut f.evidence);
    advance(
        &mut f.earth,
        &f.trust,
        &f.evidence,
        vec![Command::Import {
            snapshot: sid,
            export,
        }],
    );
    for _ in 0..2 {
        advance(&mut f.earth, &f.trust, &f.evidence, vec![]);
    }
    let d = declaration(&f);
    let safe = conflict::Safety::default();
    let book = c::Book::default();
    let value = f.earth.ledger.clone();
    let imported = id("output", &(export, 0u32)).unwrap();
    let clean = *value
        .coins
        .iter()
        .find(|(_, c)| c.payment.amount == Amount(100))
        .unwrap()
        .0;
    let mut selected = vec![imported, clean];
    selected.sort();
    let open = action(
        &d,
        c::Action::Open {
            inputs: selected,
            parties: parties(),
            capacity: Amount(150),
            initial: [Amount(150), Amount::ZERO],
            change: vec![Payment {
                owner: public(10),
                amount: Amount(22),
            }],
            fee: Amount(1),
        },
        Some(10),
        &[10, 11],
    );
    let channel = open.intent.id().unwrap();
    let head = book.head(&value, &d).unwrap();
    let (book, value, head) = run(
        &f,
        &d,
        &safe,
        &book,
        &value,
        &open,
        f.earth.height() + 1,
        head,
    )
    .unwrap();
    assert!(book.channels[&channel].dependencies.contains(&sid));
    let tx = open.intent.id().unwrap();
    let change = id("output", &(tx, 0u32)).unwrap();
    let fee = id("output", &(tx, 16u32)).unwrap();
    assert_eq!(
        value.coins[&change].dependencies,
        book.channels[&channel].dependencies
    );
    assert_eq!(
        value.coins[&fee].dependencies,
        book.channels[&channel].dependencies
    );
    let mut fork = Chain::new(f.proxima.region, &f.trust).unwrap();
    let empty = VerifiedEvidence::default();
    for _ in 0..f.proxima.height() {
        advance(&mut fork, &f.trust, &empty, vec![]);
    }
    let proof = conflict::Conflict::from_snapshots(
        f.evidence.snapshot(sid).unwrap(),
        &checkpoint(&fork, &f.trust),
    )
    .unwrap();
    let quarantine = conflict::Safety::from_conflicts(&[proof], &f.trust).unwrap();
    let reserve = action(
        &d,
        c::Action::Reserve {
            channel,
            input: change,
            fee_limit: Amount(1),
        },
        Some(10),
        &[10],
    );
    assert!(run(
        &f,
        &d,
        &quarantine,
        &book,
        &value,
        &reserve,
        f.earth.height() + 1,
        head
    )
    .is_err());
    assert_eq!(book.head(&value, &d).unwrap(), head);
    let unrelated = *value
        .coins
        .iter()
        .find(|(_, c)| c.dependencies.is_empty() && c.payment.amount == Amount(100))
        .unwrap()
        .0;
    let other = action(
        &d,
        c::Action::Open {
            inputs: vec![unrelated],
            parties: parties(),
            capacity: Amount(80),
            initial: [Amount(80), Amount::ZERO],
            change: vec![Payment {
                owner: public(10),
                amount: Amount(19),
            }],
            fee: Amount(1),
        },
        Some(10),
        &[10, 11],
    );
    assert!(run(
        &f,
        &d,
        &quarantine,
        &book,
        &value,
        &other,
        f.earth.height() + 1,
        head
    )
    .is_ok());
}
