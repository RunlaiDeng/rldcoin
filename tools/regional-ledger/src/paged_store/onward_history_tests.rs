//! Fresh two-hop Native library/Store component; no ordinary scheduler or custody claim.
use super::body_witness_tests::{certified, certified_with_commands, replay};
use super::export_archive_tests::{inventory, source_fixture_with_regions};
use super::*;
use crate::tests::{public, signature};
use std::{process::Command as Process, time::Instant};

fn phase(started: &Instant, name: &str) {
    eprintln!(
        "onward_history_phase={}",
        serde_json::json!({
            "phase": name, "elapsed_seconds": started.elapsed().as_secs_f64(),
        })
    );
}
fn spend(
    region: Hash,
    currency: Hash,
    input: Hash,
    owner: u8,
    output: u8,
    amount: Amount,
    remote: Option<(Hash, Payment)>,
) -> Command {
    let intent = Intent {
        currency,
        region,
        inputs: vec![input],
        outputs: vec![Payment {
            owner: public(output),
            amount,
        }],
        fee: Amount(1),
        destination: remote.as_ref().map(|r| r.0),
        remote: remote.as_ref().map(|r| r.1.clone()),
        destination_fee: if remote.is_some() {
            Amount(1)
        } else {
            Amount::ZERO
        },
        valid_through: 128,
    };
    let approval = Approval {
        key: public(owner),
        signature: signature(owner, &intent.bytes().unwrap()),
    };
    Command::Spend(Box::new(SignedIntent {
        intent,
        approvals: vec![approval],
    }))
}
fn empty(node: &mut Store) -> Hash {
    let snapshot = certified(&node.paged_replay.as_ref().unwrap().replay);
    node.finalize(snapshot).unwrap()
}
fn install(node: &mut Store, commands: Vec<Command>) -> Hash {
    let snapshot = certified_with_commands(&node.paged_replay.as_ref().unwrap().replay, commands);
    node.finalize(snapshot).unwrap()
}
#[derive(Serialize, Deserialize)]
struct ColdPins {
    currency: Hash,
    region: Hash,
    head: Hash,
    state: Hash,
    finality: Hash,
    origin: Hash,
    intermediate: Hash,
    export: Hash,
    payment: Hash,
    proof: Hash,
}
#[test]
#[ignore = "fresh onward parent supplies its exact retained scope and caller pins"]
fn complete_onward_history_cold_child() {
    let root = PathBuf::from(std::env::var_os("RLD_ONWARD_HISTORY_COLD_CHILD").unwrap());
    let pins: ColdPins =
        serde_json::from_slice(&fs::read(root.join("onward-cold-pins.json")).unwrap()).unwrap();
    let before = inventory(&root);
    let node = Store::open_pinned(
        &root.join("destination"),
        &public(1),
        pins.currency,
        pins.head,
    )
    .unwrap();
    assert_eq!(
        (node.chain.region, node.chain.height(), node.chain.finalized),
        (pins.region, 68, Some(pins.finality))
    );
    assert_eq!(node.chain.ledger.root().unwrap(), pins.state);
    assert_eq!(
        node.chain.ledger.imports,
        BTreeMap::from([(pins.export, pins.intermediate)])
    );
    assert_eq!(
        (node.chain.ledger.minted, node.chain.ledger.received),
        (Amount::ZERO, Amount(90))
    );
    assert!(!node
        .chain
        .ledger
        .coins
        .contains_key(&id("output", &(pins.export, 0u32)).unwrap()));
    let paid = &node.chain.ledger.coins[&id("output", &(pins.payment, 0u32)).unwrap()];
    assert_eq!(
        paid.payment,
        Payment {
            owner: public(13),
            amount: Amount(88)
        }
    );
    assert_eq!(
        paid.dependencies,
        BTreeSet::from([pins.origin, pins.intermediate])
    );
    for anchor in [pins.origin, pins.intermediate] {
        node.evidence.snapshot(anchor).unwrap();
    }
    assert!(node.complete_onward_pending_imports().unwrap().is_empty());
    node.chain.ledger.audit().unwrap();
    let stream = node.paged.as_ref().unwrap();
    assert_eq!(stream.record_count(), 69);
    let mut onward_count = 0;
    stream
        .visit(stream.storage_head(), |record| {
            if let Record::OnwardHistory(proof) = record {
                onward_count += 1;
                assert_eq!(
                    id("onward-fixture-complete-proof", proof.as_ref()).unwrap(),
                    pins.proof
                );
                assert_eq!(
                    (proof.origin.snapshots.len(), proof.snapshots.len()),
                    (80, 3)
                );
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(onward_count, 1);
    drop(node);
    assert_eq!(inventory(&root), before);
}

#[test]
#[ignore = "fresh complete onward Native import, retained ancestry, local spend and cold replay"]
fn complete_onward_history_native_import_spend_cold_and_closure_guards() {
    let started = Instant::now();
    phase(&started, "source-and-intermediate-begin");
    let (h, source, root, _, records, origin_export) = source_fixture_with_regions(
        80,
        16,
        crate::paged_bft::ORIGIN_HISTORY_RULES,
        "earth",
        &[("andromeda", crate::paged_bft::ONWARD_HISTORY_RULES)],
    );
    let pin = source.trust.currency().unwrap();
    let b = source.trust.named("proxima").unwrap();
    let c = source.trust.named("andromeda").unwrap();
    let origin = CompleteOriginHistory {
        source: h.region,
        destination: b,
        export: origin_export,
        snapshots: records
            .iter()
            .map(|r| match r {
                Record::Certified(s) => *s.clone(),
                _ => panic!("source certificate"),
            })
            .collect(),
    };
    let a80 = origin.snapshots[79].statement.id().unwrap();
    let mut intermediate = Store::create(
        &root.join("intermediate"),
        h.bootstrap.clone(),
        b,
        &public(1),
        pin,
    )
    .unwrap();
    intermediate
        .accept_complete_origin_history(origin.clone())
        .unwrap();
    install(
        &mut intermediate,
        vec![Command::Import {
            snapshot: a80,
            export: origin_export,
        }],
    );
    empty(&mut intermediate);
    let original_input = id("output", &(origin_export, 0u32)).unwrap();
    let command = spend(
        b,
        pin,
        original_input,
        11,
        11,
        Amount(8),
        Some((
            c,
            Payment {
                owner: public(12),
                amount: Amount(90),
            },
        )),
    );
    let Command::Spend(signed) = &command else {
        unreachable!()
    };
    let onward_export = signed.intent.id().unwrap();
    let b3 = install(&mut intermediate, vec![command]);
    assert_ne!(onward_export, origin_export);
    assert!(!intermediate
        .chain
        .ledger
        .coins
        .contains_key(&original_input));
    assert_eq!(
        intermediate.chain.ledger.imports.get(&origin_export),
        Some(&a80)
    );
    assert_eq!(
        intermediate.chain.ledger.exports[&onward_export].dependencies,
        BTreeSet::from([a80])
    );
    let original_onward = intermediate.complete_onward_export(onward_export).unwrap();
    assert_eq!(
        (
            original_onward.source,
            original_onward.destination,
            original_onward.export
        ),
        (b, c, onward_export)
    );
    assert_eq!(original_onward.origin, origin);
    assert_eq!(original_onward.snapshots.len(), 3);
    assert_eq!(original_onward.snapshots[2].statement.id().unwrap(), b3);
    // A real later certificate must not change the earliest export proof.
    let b4 = certified(&intermediate.paged_replay.as_ref().unwrap().replay);
    intermediate.finalize(b4.clone()).unwrap();
    let proof = intermediate.complete_onward_export(onward_export).unwrap();
    assert_eq!(
        serde_json::to_vec(&proof).unwrap(),
        serde_json::to_vec(&original_onward).unwrap()
    );
    assert_eq!(
        conservation_with_escrow(&[source.chain.clone(), intermediate.chain.clone()])
            .unwrap()
            .3,
        Amount(90)
    );
    eprintln!(
        "onward_history_fixture={}",
        serde_json::json!({"root":root,"currency":pin,"source":h.region,"intermediate":b,"destination":c})
    );
    phase(&started, "source-and-intermediate-end");

    // New rules and the value-rules hash both belong to the authority signature.
    let admission = h
        .bootstrap
        .admissions
        .iter()
        .find(|a| a.id().unwrap() == c)
        .unwrap();
    admission.verify(&h.bootstrap.currency).unwrap();
    let mut altered = admission.clone();
    altered.rules = crate::paged_bft::ORIGIN_HISTORY_RULES.into();
    altered.value_rules = Some(crate::paged_bft::rules_hash_for(&altered.rules).unwrap());
    assert!(altered.verify(&h.bootstrap.currency).is_err());
    let mut wrong_domain = h.bootstrap.clone();
    wrong_domain
        .admissions
        .iter_mut()
        .find(|a| a.id().unwrap() == c)
        .unwrap()
        .currency = Hash([9; 32]);
    assert!(Trust::verify(&wrong_domain, &public(1), pin).is_err());

    let create_c = |name: &str| {
        Store::create(&root.join(name), h.bootstrap.clone(), c, &public(1), pin).unwrap()
    };
    let mut destination = create_c("destination");
    let before = inventory(&root);
    let old_error = destination
        .accept_complete_origin_history(CompleteOriginHistory {
            source: b,
            destination: c,
            export: onward_export,
            snapshots: proof.snapshots.clone(),
        })
        .unwrap_err();
    assert_eq!(
        old_error,
        "complete origin history requires explicit receiver profile/origin/route/bound"
    );
    let old_receiver_error = intermediate
        .accept_complete_onward_history(proof.clone())
        .unwrap_err();
    eprintln!("onward_old_receiver_refusal={old_receiver_error}");
    assert_eq!(inventory(&root), before);
    // Separate signature-tail controls cannot manufacture an incident or credit.
    for (name, bad) in [
        ("bad-origin-tail", {
            let mut p = proof.clone();
            p.origin.snapshots[79].bft.as_mut().unwrap().committed.votes[0]
                .approval
                .signature = "00".repeat(64);
            p
        }),
        ("bad-intermediate-extra-tail", {
            let mut p = proof.clone();
            let mut tail = b4.clone();
            tail.bft.as_mut().unwrap().committed.votes[0]
                .approval
                .signature = "00".repeat(64);
            p.snapshots.push(tail);
            p
        }),
        ("complete-origin79-missing-import-anchor80", {
            let mut p = proof.clone();
            p.origin.snapshots.pop();
            // Every remaining A certificate is genuine and genesis-contiguous;
            // B1 still names the distinct A80 anchor and may not be rebased.
            assert_eq!(p.origin.snapshots.last().unwrap().statement.height, 79);
            assert_ne!(
                p.origin.snapshots.last().unwrap().statement.id().unwrap(),
                a80
            );
            p
        }),
    ] {
        let before = inventory(&root);
        let head = destination.storage_head().unwrap();
        let error = destination.accept_complete_onward_history(bad).unwrap_err();
        eprintln!(
            "onward_refusal={}",
            serde_json::json!({"name":name,"error":error})
        );
        if name != "complete-origin79-missing-import-anchor80" {
            assert!(error.contains("signature"), "{name}: {error}");
        }
        assert_eq!(destination.storage_head().unwrap(), head);
        assert!(
            destination.chain.ledger.coins.is_empty()
                && destination.chain.ledger.imports.is_empty()
        );
        assert!(destination.journal.incident_ids.is_empty());
        assert_eq!(inventory(&root), before);
    }

    phase(&started, "pending-complete-closure-begin");
    assert_eq!(
        destination
            .accept_complete_onward_history(proof.clone())
            .unwrap(),
        b3
    );
    assert_eq!(destination.chain.height(), 0);
    assert!(
        destination.chain.ledger.coins.is_empty() && destination.chain.ledger.imports.is_empty()
    );
    let pending = vec![Command::Import {
        snapshot: b3,
        export: onward_export,
    }];
    assert_eq!(
        destination.complete_onward_pending_imports().unwrap(),
        pending
    );
    let retained_head = destination.storage_head().unwrap();
    let before = inventory(&root);
    assert_eq!(
        destination
            .accept_complete_onward_history(proof.clone())
            .unwrap(),
        b3
    );
    assert_eq!(destination.storage_head().unwrap(), retained_head);
    assert_eq!(inventory(&root), before);
    let first_local = empty(&mut destination);
    for height in 2..=65 {
        empty(&mut destination);
        assert_eq!(destination.chain.height(), height);
        assert!(destination.evidence.snapshots.len() <= MAX_SNAPSHOTS);
    }
    assert!(!destination.evidence.snapshots.contains_key(&first_local));
    for anchor in [a80, b3] {
        destination.evidence.snapshot(anchor).unwrap();
    }
    assert_eq!(
        destination.complete_onward_pending_imports().unwrap(),
        pending
    );
    assert!(destination.chain.ledger.coins.is_empty());
    assert_eq!(destination.paged.as_ref().unwrap().record_count(), 66);
    phase(&started, "pending-complete-closure-end");

    phase(&started, "recipient-import-and-spend-begin");
    install(&mut destination, pending);
    let imported = id("output", &(onward_export, 0u32)).unwrap();
    assert_eq!(
        (
            destination.chain.height(),
            destination.chain.ledger.coins[&imported].mature
        ),
        (66, 68)
    );
    assert_eq!(
        destination.chain.ledger.coins[&imported].payment,
        Payment {
            owner: public(12),
            amount: Amount(89)
        }
    );
    assert_eq!(
        destination.chain.ledger.coins[&imported].dependencies,
        BTreeSet::from([a80, b3])
    );
    assert!(destination
        .complete_onward_pending_imports()
        .unwrap()
        .is_empty());
    let payment = spend(c, pin, imported, 12, 13, Amount(88), None);
    let Command::Spend(signed) = &payment else {
        unreachable!()
    };
    let payment_id = signed.intent.id().unwrap();
    let before = inventory(&root);
    let immature = destination
        .bft_candidate(vec![payment.clone()], public(10))
        .unwrap_err();
    assert_eq!(immature, "immature input");
    assert_eq!(inventory(&root), before);
    empty(&mut destination);
    install(&mut destination, vec![payment]);
    assert_eq!(destination.chain.height(), 68);
    assert!(!destination.chain.ledger.coins.contains_key(&imported));
    assert_eq!(
        destination.chain.ledger.imports,
        BTreeMap::from([(onward_export, b3)])
    );
    assert_eq!(
        (
            destination.chain.ledger.minted,
            intermediate.chain.ledger.minted
        ),
        (Amount::ZERO, Amount::ZERO)
    );
    let paid = &destination.chain.ledger.coins[&id("output", &(payment_id, 0u32)).unwrap()];
    assert_eq!(
        paid.payment,
        Payment {
            owner: public(13),
            amount: Amount(88)
        }
    );
    assert_eq!(paid.dependencies, BTreeSet::from([a80, b3]));
    let totals = conservation_with_escrow(&[
        source.chain.clone(),
        intermediate.chain.clone(),
        destination.chain.clone(),
    ])
    .unwrap();
    assert_eq!(
        totals,
        (
            Amount(rld_pow::cumulative_emission(80)),
            Amount(rld_pow::cumulative_emission(80)),
            Amount::ZERO,
            Amount::ZERO
        )
    );
    let before = inventory(&root);
    let duplicate_error = destination
        .bft_candidate(
            vec![Command::Import {
                snapshot: b3,
                export: onward_export,
            }],
            public(10),
        )
        .unwrap_err();
    assert_eq!(duplicate_error, "permanent import tombstone rejects replay");
    assert_eq!(inventory(&root), before);
    let pins = ColdPins {
        currency: pin,
        region: c,
        head: destination.storage_head().unwrap(),
        state: destination.chain.ledger.root().unwrap(),
        finality: destination.chain.finalized.unwrap(),
        origin: a80,
        intermediate: b3,
        export: onward_export,
        payment: payment_id,
        proof: id("onward-fixture-complete-proof", &proof).unwrap(),
    };
    drop(destination);
    crate::keystore::private_create(
        &root.join("onward-cold-pins.json"),
        &serde_json::to_vec(&pins).unwrap(),
    )
    .unwrap();
    let before = inventory(&root);
    phase(&started, "fresh-process-cold-begin");
    let child = Process::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "storage::paged::onward_history_tests::complete_onward_history_cold_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("RLD_ONWARD_HISTORY_COLD_CHILD", &root)
        .current_dir(std::env::current_dir().unwrap())
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "{}{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    assert_eq!(inventory(&root), before);
    phase(&started, "fresh-process-cold-end");

    phase(&started, "authenticated-ancestor-conflict-begin");
    let mut fork = replay(&h);
    let history = super::origin_history::test_history(&h, &fork, &records);
    for record in &records[..79] {
        fork.apply_retained(record, &history).unwrap();
    }
    let (input, coin) = fork
        .chain
        .ledger
        .coins
        .iter()
        .find(|(_, coin)| coin.created == 2 && coin.payment.owner == public(10))
        .unwrap();
    let fork_spend = spend(
        h.region,
        pin,
        *input,
        10,
        15,
        coin.payment.amount.checked_sub(Amount(1)).unwrap(),
        None,
    );
    let alternate = certified_with_commands(&fork, vec![fork_spend]);
    fork.apply_retained(&Record::Certified(Box::new(alternate.clone())), &history)
        .unwrap();
    assert_eq!(fork.chain.height(), 80);
    assert_eq!(
        fork.chain.ledger.exports[&origin_export],
        source.chain.ledger.exports[&origin_export]
    );
    Conflict::from_snapshots(&origin.snapshots[79], &alternate)
        .unwrap()
        .verify(&source.trust)
        .unwrap();
    let mut conflict_tail = proof.clone();
    conflict_tail.origin.snapshots[79] = alternate;
    let mut bad_b4 = b4;
    bad_b4.bft.as_mut().unwrap().committed.votes[0]
        .approval
        .signature = "00".repeat(64);
    conflict_tail.snapshots.push(bad_b4);
    let mut forged = conflict_tail.clone();
    forged.origin.snapshots[79]
        .bft
        .as_mut()
        .unwrap()
        .committed
        .votes[0]
        .approval
        .signature = "00".repeat(64);
    let mut receiver = create_c("conflict-receiver");
    receiver
        .accept_complete_onward_history(proof.clone())
        .unwrap();
    let head = receiver.storage_head().unwrap();
    let state = receiver.chain.ledger.clone();
    let before = inventory(&root);
    let forged_error = receiver.accept_complete_onward_history(forged).unwrap_err();
    eprintln!("onward_forged_conflict_refusal={forged_error}");
    assert!(receiver.journal.incident_ids.is_empty());
    assert_eq!(receiver.storage_head().unwrap(), head);
    assert_eq!(receiver.chain.ledger, state);
    assert_eq!(inventory(&root), before);
    let incident_error = receiver
        .accept_complete_onward_history(conflict_tail)
        .unwrap_err();
    eprintln!("onward_valid_conflict_with_bad_tail={incident_error}");
    assert_eq!(receiver.journal.incident_ids.len(), 1);
    assert!(receiver.safety.check_region(h.region).is_err());
    assert_eq!(receiver.chain.ledger, state);
    assert!(receiver.chain.ledger.coins.is_empty() && receiver.chain.ledger.imports.is_empty());
    let incident_head = receiver.storage_head().unwrap();
    let before = inventory(&root);
    assert!(receiver.accept_complete_onward_history(proof).is_err());
    assert!(receiver.complete_onward_pending_imports().is_err());
    assert_eq!(receiver.storage_head().unwrap(), incident_head);
    assert_eq!(receiver.chain.ledger, state);
    assert_eq!(inventory(&root), before);
    phase(&started, "authenticated-ancestor-conflict-end");
    println!(
        "onward_history_result={}",
        serde_json::json!({
            "fixture_root":root,"source_height":80,"intermediate_height":4,"selected_export_height":3,"recipient_height":68,
            "source_export":origin_export,"onward_export":onward_export,"payment":payment_id,
            "pending_anchors_survived_active_eviction":[a80,b3],"totals":totals,"recipient_head":pins.head,
            "recipient_state":pins.state,"recipient_finality":pins.finality,"cold_child_success":true,
            "duplicate_import_error":duplicate_error,"old_receiver_error":old_receiver_error,
            "elapsed_seconds":started.elapsed().as_secs_f64(),"ordinary_network_qualified":false,
            "independent_custody_qualified":false,"arbitrary_composition_qualified":false,"mainnet_qualified":false,
        })
    );
}
