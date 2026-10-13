//! Fresh Native re-export baseline. Old origin-only carriage must still refuse.
//! Public fixture signing does not qualify signer custody or ordinary scheduling.
use super::body_witness_tests::{certified, certified_with_commands};
use super::export_archive_tests::{inventory, source_fixture_with_regions};
use super::*;
use crate::tests::{public, signature};
use std::time::Instant;

fn phase(started: &Instant, name: &str) {
    eprintln!(
        "nonorigin_export_phase={}",
        serde_json::json!({
            "phase": name, "elapsed_seconds": started.elapsed().as_secs_f64(),
        })
    );
}

fn directories(root: &Path) -> BTreeSet<PathBuf> {
    let mut result = BTreeSet::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        result.insert(dir.clone());
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if fs::symlink_metadata(&path).unwrap().is_dir() {
                pending.push(path);
            }
        }
    }
    result
}

#[test]
#[ignore = "fresh non-origin paged Native debit and precise unchanged origin-only refusal"]
fn nonorigin_paged_export_retains_ancestry_and_refuses_origin_only_carriage() {
    let started = Instant::now();
    phase(&started, "source-construction-begin");
    let (header, source, root, _, records, origin_export) = source_fixture_with_regions(
        80,
        16,
        crate::paged_bft::ORIGIN_HISTORY_RULES,
        "earth",
        &[("andromeda", crate::paged_bft::ORIGIN_HISTORY_RULES)],
    );
    let pin = source.trust.currency().unwrap();
    let b_region = source.trust.named("proxima").unwrap();
    let c_region = source.trust.named("andromeda").unwrap();
    assert_eq!(header.bootstrap.admissions.len(), 3);
    assert_ne!(b_region, c_region);
    let proof = CompleteOriginHistory {
        source: header.region,
        destination: b_region,
        export: origin_export,
        snapshots: records
            .iter()
            .map(|record| {
                let Record::Certified(snapshot) = record else {
                    panic!("actual source certificate")
                };
                *snapshot.clone()
            })
            .collect(),
    };
    assert_eq!(proof.snapshots.len(), 80);
    let origin_checkpoint = proof.snapshots.last().unwrap().statement.id().unwrap();
    assert_eq!(source.chain.finalized, Some(origin_checkpoint));
    let original_export = source.chain.ledger.exports[&origin_export].clone();
    assert_eq!(
        (
            original_export.height,
            original_export.recipient.amount,
            original_export.destination_fee
        ),
        (66, Amount(100), Amount(1))
    );
    let source_ledger = source.chain.ledger.clone();
    eprintln!(
        "nonorigin_export_fixture={}",
        serde_json::json!({
            "root": root, "currency": pin, "source": header.region,
            "intermediate": b_region, "destination": c_region,
        })
    );
    phase(&started, "source-construction-end");

    phase(&started, "intermediate-native-import-begin");
    let mut intermediate = Store::create(
        &root.join("intermediate"),
        header.bootstrap.clone(),
        b_region,
        &public(1),
        pin,
    )
    .unwrap();
    assert_eq!(
        intermediate
            .accept_complete_origin_history(proof.clone())
            .unwrap(),
        origin_checkpoint
    );
    assert_eq!(intermediate.chain.height(), 0);
    assert!(intermediate.chain.ledger.coins.is_empty());
    assert!(intermediate.chain.ledger.imports.is_empty());
    let import_commands = intermediate.complete_origin_pending_imports().unwrap();
    assert_eq!(
        import_commands,
        vec![Command::Import {
            snapshot: origin_checkpoint,
            export: origin_export
        }]
    );
    let b1 = certified_with_commands(
        &intermediate.paged_replay.as_ref().unwrap().replay,
        import_commands,
    );
    intermediate.finalize(b1).unwrap();
    let input = id("output", &(origin_export, 0u32)).unwrap();
    let imported = &intermediate.chain.ledger.coins[&input];
    assert_eq!(
        imported.payment,
        Payment {
            owner: public(11),
            amount: Amount(99)
        }
    );
    assert_eq!((imported.created, imported.mature), (1, 3));
    assert_eq!(imported.dependencies, BTreeSet::from([origin_checkpoint]));
    assert_eq!(
        intermediate.chain.ledger.imports.get(&origin_export),
        Some(&origin_checkpoint)
    );
    assert!(intermediate.chain.ledger.minted.is_zero());
    assert!(intermediate
        .complete_origin_pending_imports()
        .unwrap()
        .is_empty());
    let b2 = certified(&intermediate.paged_replay.as_ref().unwrap().replay);
    intermediate.finalize(b2).unwrap();
    assert_eq!(intermediate.chain.height(), 2);
    phase(&started, "intermediate-native-import-end");

    phase(&started, "intermediate-native-reexport-begin");
    let intent = Intent {
        currency: pin,
        region: b_region,
        inputs: vec![input],
        outputs: vec![Payment {
            owner: public(11),
            amount: Amount(8),
        }],
        fee: Amount(1),
        destination: Some(c_region),
        remote: Some(Payment {
            owner: public(12),
            amount: Amount(90),
        }),
        destination_fee: Amount(1),
        valid_through: 24,
    };
    let onward_export = intent.id().unwrap();
    assert_ne!(onward_export, origin_export);
    let approval = Approval {
        key: public(11),
        signature: signature(11, &intent.bytes().unwrap()),
    };
    let signed = SignedIntent {
        intent,
        approvals: vec![approval],
    };
    let b3 = certified_with_commands(
        &intermediate.paged_replay.as_ref().unwrap().replay,
        vec![Command::Spend(Box::new(signed))],
    );
    let b_checkpoint = b3.statement.id().unwrap();
    intermediate.finalize(b3).unwrap();
    assert_eq!(
        (intermediate.chain.height(), intermediate.chain.finalized),
        (3, Some(b_checkpoint))
    );
    assert!(!intermediate.chain.ledger.coins.contains_key(&input));
    assert_eq!(
        intermediate.chain.ledger.coins[&id("output", &(onward_export, 0u32)).unwrap()].payment,
        Payment {
            owner: public(11),
            amount: Amount(8)
        }
    );
    let onward = intermediate.chain.ledger.exports[&onward_export].clone();
    assert_eq!(
        (onward.id, onward.source, onward.destination, onward.height),
        (onward_export, b_region, c_region, 3)
    );
    assert_eq!(
        (onward.recipient.clone(), onward.destination_fee),
        (
            Payment {
                owner: public(12),
                amount: Amount(90)
            },
            Amount(1)
        )
    );
    assert_eq!(onward.dependencies, BTreeSet::from([origin_checkpoint]));
    assert!(onward.channel_dependencies.is_empty());
    assert_eq!(
        intermediate.chain.ledger.imports,
        BTreeMap::from([(origin_export, origin_checkpoint)])
    );
    assert_eq!(
        (
            intermediate.chain.ledger.minted,
            intermediate.chain.ledger.received
        ),
        (Amount::ZERO, Amount(100))
    );
    intermediate.chain.ledger.audit().unwrap();

    // Observe the records actually committed by Store, not merely producer input.
    let retained = intermediate.fixture_paged_records().unwrap();
    assert_eq!(retained.len(), 4);
    let Record::OriginHistory(retained_origin) = &retained[0] else {
        panic!("complete retained ancestor")
    };
    assert_eq!(retained_origin.as_ref(), &proof);
    let b_certificates = retained[1..]
        .iter()
        .enumerate()
        .map(|(index, record)| {
            let Record::Certified(snapshot) = record else {
                panic!("committed intermediate certificate")
            };
            assert_eq!(
                (snapshot.statement.region, snapshot.statement.height),
                (b_region, index as u64 + 1)
            );
            *snapshot.clone()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        b_certificates.last().unwrap().statement.id().unwrap(),
        b_checkpoint
    );
    phase(&started, "intermediate-native-reexport-complete");

    phase(&started, "old-carriage-refusal-begin");
    let mut destination = Store::create(
        &root.join("destination"),
        header.bootstrap.clone(),
        c_region,
        &public(1),
        pin,
    )
    .unwrap();
    assert_eq!(destination.chain.height(), 0);
    assert!(destination.chain.ledger.coins.is_empty());
    assert!(destination.chain.ledger.imports.is_empty());
    assert!(destination.chain.ledger.exports.is_empty());
    assert!(destination.chain.ledger.minted.is_zero());
    let native_totals = conservation_with_escrow(&[
        source.chain.clone(),
        intermediate.chain.clone(),
        destination.chain.clone(),
    ])
    .unwrap();
    assert_eq!(native_totals.0, Amount(rld_pow::cumulative_emission(80)));
    assert_eq!(
        (native_totals.2, native_totals.3),
        (Amount::ZERO, Amount(90))
    );
    assert_eq!(
        native_totals.0,
        native_totals.1.checked_add(native_totals.3).unwrap()
    );
    let b_head = intermediate.storage_head().unwrap();
    let b_ledger = intermediate.chain.ledger.clone();
    let c_head = destination.storage_head().unwrap();
    let c_ledger = destination.chain.ledger.clone();
    let c_finality = destination.chain.finalized;
    let before = inventory(&root);
    let dirs_before = directories(&root);
    // This contains all three authentic B certificates. The old schema cannot
    // express their complete A ancestry; its origin admission must refuse first.
    let old_input = CompleteOriginHistory {
        source: b_region,
        destination: c_region,
        export: onward_export,
        snapshots: b_certificates,
    };
    let receiver_error = destination
        .accept_complete_origin_history(old_input)
        .unwrap_err();
    assert_eq!(
        receiver_error,
        "complete origin history requires explicit receiver profile/origin/route/bound"
    );
    assert_eq!(destination.chain.ledger, c_ledger);
    assert_eq!(destination.chain.finalized, c_finality);
    assert_eq!(destination.storage_head().unwrap(), c_head);
    assert_eq!(inventory(&root), before);
    assert_eq!(directories(&root), dirs_before);
    let emitter_error = intermediate
        .complete_origin_export(onward_export)
        .unwrap_err();
    assert_eq!(
        emitter_error,
        "origin export requires independently admitted original paged origin"
    );
    assert_eq!(intermediate.chain.ledger, b_ledger);
    assert_eq!(intermediate.storage_head().unwrap(), b_head);
    assert_eq!(intermediate.chain.finalized, Some(b_checkpoint));
    assert_eq!(source.chain.ledger, source_ledger);
    assert_eq!(source.chain.ledger.exports[&origin_export], original_export);
    assert_eq!(inventory(&root), before);
    assert_eq!(directories(&root), dirs_before);
    assert_eq!(
        conservation_with_escrow(&[
            source.chain.clone(),
            intermediate.chain.clone(),
            destination.chain.clone()
        ])
        .unwrap(),
        native_totals
    );
    phase(&started, "old-carriage-refusal-end");
    println!(
        "nonorigin_export_baseline={}",
        serde_json::json!({
            "fixture_root": root, "currency": pin, "source_height": 80,
            "intermediate_height": 3, "destination_height": 0,
            "source_export": origin_export, "source_checkpoint": origin_checkpoint,
            "onward_export": onward_export, "intermediate_checkpoint": b_checkpoint,
            "intermediate_head": b_head, "destination_head": c_head,
            "retained_intermediate_records": retained.len(), "totals": native_totals,
            "receiver_error": receiver_error, "emitter_error": emitter_error,
            "no_refund": true, "destination_imported": false,
            "ordinary_network_qualified": false, "custody_qualified": false,
            "arbitrary_composition_qualified": false, "mainnet_qualified": false,
            "elapsed_seconds": started.elapsed().as_secs_f64(),
        })
    );
}
