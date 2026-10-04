use super::*;

fn setup() -> (Bootstrap, Trust, VerifiedEvidence, Vec<Chain>) {
    let mut b = bootstrap();
    for a in &mut b.admissions {
        a.rules = segmented::RULES.into();
        a.signature = signature(1, &a.bytes().unwrap());
    }
    let trust = Trust::verify(&b, &public(1), b.currency.id().unwrap()).unwrap();
    let chains = ["earth", "proxima", "andromeda"]
        .into_iter()
        .map(|name| Chain::new(trust.named(name).unwrap(), &trust).unwrap())
        .collect();
    (b, trust, VerifiedEvidence::default(), chains)
}
fn signed_local(chain: &Chain, trust: &Trust, input: Hash, from: u8, to: u8) -> Command {
    Command::Spend(Box::new(intent(
        chain,
        trust,
        vec![input],
        vec![Payment {
            owner: public(to),
            amount: Amount(100),
        }],
        None,
        None,
        0,
        0,
        &[from],
    )))
}

#[test]
fn long_certified_owner_payments_onward_return_and_genesis_cold_verification() {
    let (_, trust, mut evidence, mut regions) = setup();
    let mut earth = regions.remove(0);
    let mut proxima = regions.remove(0);
    let mut andromeda = regions.remove(0);
    for _ in 0..4 {
        advance(&mut earth, &trust, &evidence, vec![]);
    }
    finalize(&mut earth, &trust, &mut evidence);
    let mut input = *earth.ledger.coins.keys().next().unwrap();
    let mut owner = 10;
    for n in 0..1024 {
        let next = if owner == 20 { 21 } else { 20 };
        let command = signed_local(&earth, &trust, input, owner, next);
        advance(&mut earth, &trust, &evidence, vec![command]);
        input = *earth
            .ledger
            .coins
            .iter()
            .find(|(_, c)| c.payment.owner == public(next))
            .unwrap()
            .0;
        owner = next;
        if (n + 1) % 128 == 0 {
            finalize(&mut earth, &trust, &mut evidence);
        }
        assert!(earth.blocks.len() <= MAX_BLOCKS);
    }
    let request = intent(
        &earth,
        &trust,
        vec![input],
        vec![Payment {
            owner: public(owner),
            amount: Amount(20),
        }],
        Some(proxima.region),
        Some(Payment {
            owner: public(11),
            amount: Amount(80),
        }),
        0,
        2,
        &[owner],
    );
    let exported = request.intent.id().unwrap();
    advance(
        &mut earth,
        &trust,
        &evidence,
        vec![Command::Spend(Box::new(request))],
    );
    let source = finalize(&mut earth, &trust, &mut evidence);
    advance(
        &mut proxima,
        &trust,
        &evidence,
        vec![Command::Import {
            snapshot: source,
            export: exported,
        }],
    );
    for _ in 0..2 {
        advance(&mut proxima, &trust, &evidence, vec![]);
    }
    finalize(&mut proxima, &trust, &mut evidence);
    let request = intent(
        &proxima,
        &trust,
        coins(&proxima, 11),
        vec![Payment {
            owner: public(11),
            amount: Amount(18),
        }],
        Some(andromeda.region),
        Some(Payment {
            owner: public(12),
            amount: Amount(60),
        }),
        0,
        1,
        &[11],
    );
    let onward = request.intent.id().unwrap();
    advance(
        &mut proxima,
        &trust,
        &evidence,
        vec![Command::Spend(Box::new(request))],
    );
    let source = finalize(&mut proxima, &trust, &mut evidence);
    advance(
        &mut andromeda,
        &trust,
        &evidence,
        vec![Command::Import {
            snapshot: source,
            export: onward,
        }],
    );
    for _ in 0..2 {
        advance(&mut andromeda, &trust, &evidence, vec![]);
    }
    finalize(&mut andromeda, &trust, &mut evidence);
    let request = intent(
        &andromeda,
        &trust,
        coins(&andromeda, 12),
        vec![Payment {
            owner: public(12),
            amount: Amount(9),
        }],
        Some(earth.region),
        Some(Payment {
            owner: public(13),
            amount: Amount(50),
        }),
        0,
        1,
        &[12],
    );
    let returned = request.intent.id().unwrap();
    advance(
        &mut andromeda,
        &trust,
        &evidence,
        vec![Command::Spend(Box::new(request))],
    );
    let source = finalize(&mut andromeda, &trust, &mut evidence);
    advance(
        &mut earth,
        &trust,
        &evidence,
        vec![Command::Import {
            snapshot: source,
            export: returned,
        }],
    );
    for _ in 0..2 {
        advance(&mut earth, &trust, &evidence, vec![]);
    }
    let final_earth = finalize(&mut earth, &trust, &mut evidence);
    assert_eq!(earth.height(), 1032);
    assert!(earth.blocks.is_empty());
    assert_eq!(
        sum(earth
            .ledger
            .coins
            .values()
            .filter(|c| c.payment.owner == public(13))
            .map(|c| c.payment.amount))
        .unwrap(),
        Amount(49)
    );
    assert!(earth
        .template(
            vec![Command::Import {
                snapshot: source,
                export: returned
            }],
            public(10),
            &trust,
            &evidence
        )
        .is_err());
    let raw = Evidence {
        snapshots: evidence
            .snapshots
            .values()
            .map(|(s, _)| s.clone())
            .collect(),
    };
    // BTreeMap hashes are not a causal order. Recover exact preceding dependencies.
    let mut ordered = Evidence::default();
    let mut cold = VerifiedEvidence::default();
    let mut remaining = raw.snapshots;
    while !remaining.is_empty() {
        let i = remaining
            .iter()
            .position(|s| {
                let mut trial = cold.clone();
                trial.add(s.clone(), &trust).is_ok()
            })
            .expect("complete causal closure must make progress");
        let s = remaining.remove(i);
        cold.add(s.clone(), &trust).unwrap();
        ordered.snapshots.push(s);
    }
    let bytes = encode("evidence", &ordered).unwrap();
    let cold = VerifiedEvidence::verify(&ordered, &trust).unwrap();
    assert_eq!(cold.snapshots[&final_earth].1, earth.ledger);
    assert_eq!(
        conservation(&[earth.clone(), proxima, andromeda]).unwrap(),
        (Amount(300), Amount(300), Amount::ZERO)
    );
    assert!(ordered
        .snapshots
        .iter()
        .all(|s| s.blocks.len() <= MAX_BLOCKS));
    assert!(ordered
        .snapshots
        .iter()
        .any(|s| s.statement.height > MAX_BLOCKS as u64 && s.base.is_some()));
    println!(
        "{}",
        serde_json::json!({"format":"RLD-NATIVE-SEGMENTED-VALUE-SAMPLE-V1", "native_implementation":implementation().unwrap(),
        "fixture_only":true,"live_rld":false,"source_height":1032,"actual_owner_payments":1024,
        "onward_return_net":["78","59","49"],"max_segment_blocks":128,"complete_evidence_bytes":bytes.len(),
        "cold_genesis_replay_equal":true,"permanent_duplicate_import_refused":true,
        "ordinary_node_storage_long_history_qualified":false,"BFT_long_history_qualified":false})
    );
}

#[test]
fn invalid_segment_predecessor_tail_authority_and_partial_certificates_refuse() {
    let (_, trust, mut evidence, mut chains) = setup();
    let earth = &mut chains[0];
    for _ in 0..4 {
        advance(earth, &trust, &evidence, vec![]);
    }
    let first = checkpoint(earth, &trust);
    let first_id = evidence.add(first.clone(), &trust).unwrap();
    earth.install(first_id, &evidence).unwrap();
    advance(earth, &trust, &evidence, vec![]);
    let second = checkpoint(earth, &trust);
    assert!(conflict::Conflict::from_snapshots(&first, &second)
        .unwrap()
        .verify(&trust)
        .is_err());
    for mode in 0..6 {
        let mut changed = second.clone();
        match mode {
            0 => changed.base = None,
            1 => changed.base = Some(Hash::ZERO),
            2 => {
                changed.blocks[0].header.parent = Hash::ZERO;
                mine(&mut changed.blocks[0]).unwrap();
            }
            3 => changed.statement.state = Hash::ZERO,
            4 => {
                changed.approvals.pop();
            }
            _ => changed.statement.height += 1,
        }
        if mode == 3 || mode == 5 {
            changed.approvals = keys()
                .into_iter()
                .map(|seed| Approval {
                    key: public(seed),
                    signature: signature(seed, &changed.statement.bytes().unwrap()),
                })
                .collect();
        }
        let mut clone = evidence.clone();
        assert!(clone.add(changed, &trust).is_err());
        assert_eq!(clone.snapshots.len(), evidence.snapshots.len());
    }
    let (_, other_trust, _, _) = setup();
    let mut legacy = bootstrap();
    let legacy_trust = Trust::verify(&legacy, &public(1), legacy.currency.id().unwrap()).unwrap();
    assert!(VerifiedEvidence::default()
        .add(second, &legacy_trust)
        .is_err());
    legacy.admissions[0].rules = bft::RULES.into();
    legacy.admissions[0].signature = signature(1, &legacy.admissions[0].bytes().unwrap());
    assert_ne!(legacy_trust.binding, other_trust.binding);
    let before = earth.statement(&trust).unwrap();
    let mut bad = earth
        .template(vec![], public(10), &trust, &evidence)
        .unwrap();
    bad.header.state = Hash::ZERO;
    mine(&mut bad).unwrap();
    assert!(earth.accept(bad, &trust, &evidence).is_err());
    assert_eq!(before, earth.statement(&trust).unwrap());
}
