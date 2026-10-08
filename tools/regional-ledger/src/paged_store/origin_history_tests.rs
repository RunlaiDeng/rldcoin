//! Fresh public fixture certificates; no reused custody or failed Native input.
use super::body_witness_tests::{certified, certified_with_commands, header, replay};
use super::continuation_tests::inventory;
use super::export_archive_tests::source_fixture_with_profile;
use super::*;
use crate::tests::{public, signature};
use std::process::Command as Process;

#[derive(Serialize, Deserialize)]
struct ColdPins {
    currency: Hash,
    head: Hash,
    region: Hash,
    export: Hash,
    source_checkpoint: Hash,
    root: Hash,
}

#[test]
#[ignore = "fresh complete-origin parent supplies exact destination pins"]
fn complete_origin_history_destination_cold_child() {
    let root = PathBuf::from(std::env::var_os("RLD_COMPLETE_ORIGIN_COLD_CHILD").unwrap());
    let pins: ColdPins =
        serde_json::from_slice(&fs::read(root.join("cold-pins.json")).unwrap()).unwrap();
    let before = inventory(&root);
    let node = Store::open_pinned(
        &root.join("destination"),
        &public(1),
        pins.currency,
        pins.head,
    )
    .unwrap();
    assert_eq!(node.chain.region, pins.region);
    assert_eq!(node.chain.height(), 3);
    assert_eq!(node.chain.ledger.root().unwrap(), pins.root);
    assert_eq!(
        node.chain.ledger.imports[&pins.export],
        pins.source_checkpoint
    );
    assert!(!node
        .chain
        .ledger
        .coins
        .contains_key(&id("output", &(pins.export, 0u32)).unwrap()));
    node.chain.ledger.audit().unwrap();
    assert!(node.complete_origin_pending_imports().unwrap().is_empty());
    drop(node);
    assert_eq!(inventory(&root), before);
}

#[test]
fn complete_origin_history_requires_new_authenticated_receiver_admission() {
    let h = header();
    let mut admission = h.bootstrap.admissions[0].clone();
    let old_bytes = admission.bytes().unwrap();
    admission.rules = crate::paged_bft::ORIGIN_HISTORY_RULES.into();
    assert!(admission.verify(&h.bootstrap.currency).is_err());
    admission.value_rules = Some(crate::paged_bft::rules_hash_for(&admission.rules).unwrap());
    assert!(admission.verify(&h.bootstrap.currency).is_err());
    assert_ne!(admission.bytes().unwrap(), old_bytes);
    admission.signature = signature(1, &admission.bytes().unwrap());
    admission.verify(&h.bootstrap.currency).unwrap();
    assert_ne!(admission.value_rules, h.bootstrap.admissions[0].value_rules);
    assert!(crate::paged_bft::rules_hash_for("unsigned-unknown-profile").is_err());
    let empty = CompleteOriginHistory {
        source: h.region,
        destination: h.region,
        export: Hash::ZERO,
        snapshots: vec![],
    };
    assert!(empty.shape(h.region, &replay(&h).trust).is_err());
}

#[test]
fn complete_origin416_public_input_for_bounded_ordinary_carriage() {
    let (header, source, root, _, records, export) = source_fixture_with_profile(
        416,
        crate::history::PAGE_EVENTS,
        crate::paged_bft::ORIGIN_HISTORY_RULES,
    );
    let destination = source.trust.named("proxima").unwrap();
    let proof = CompleteOriginHistory {
        source: header.region,
        destination,
        export,
        snapshots: records
            .into_iter()
            .map(|record| {
                let Record::Certified(snapshot) = record else {
                    panic!("complete certified source")
                };
                *snapshot
            })
            .collect(),
    };
    proof.shape(destination, &source.trust).unwrap();
    let raw = serde_json::to_vec(&proof).unwrap();
    assert!(raw.len() > 3 * 1024 * 1024 && raw.len() <= MAX_BYTES);
    source.chain.ledger.audit().unwrap();
    assert_eq!(source.chain.height(), 416);
    let query = serde_json::json!({"currency":source.trust.currency().unwrap(),
        "source":header.region,"destination":destination,"export":export,
        "source_checkpoint":source.chain.finalized.unwrap(),"source_height":416,
        "fixture_only":true,"source_signing_custody_qualified":false});
    for (name, bytes) in [
        ("complete-origin-proof416.json", raw),
        (
            "receiver-bootstrap416.json",
            serde_json::to_vec(&header.bootstrap).unwrap(),
        ),
        ("origin-query416.json", serde_json::to_vec(&query).unwrap()),
    ] {
        crate::keystore::private_create(&root.join(name), &bytes).unwrap();
    }
    // This provider constructs public input only. The receiving entry must still
    // authenticate all certificates from its own independently pinned genesis.
}

#[test]
fn complete_origin80_export66_local_import_maturity_owner_spend_cold_and_conflict_guards() {
    let (h, source, root, _scope, records, export) =
        source_fixture_with_profile(80, 16, crate::paged_bft::ORIGIN_HISTORY_RULES);
    let destination_id = source.trust.named("proxima").unwrap();
    let pin = source.trust.currency().unwrap();
    let snapshots = records
        .iter()
        .map(|r| {
            let Record::Certified(s) = r else {
                panic!("fixture is certified only")
            };
            s.as_ref().clone()
        })
        .collect::<Vec<_>>();
    let proof = CompleteOriginHistory {
        source: h.region,
        destination: destination_id,
        export,
        snapshots,
    };
    let checkpoint = proof.snapshots.last().unwrap().statement.id().unwrap();
    let mut destination = Store::create(
        &root.join("destination"),
        h.bootstrap.clone(),
        destination_id,
        &public(1),
        pin,
    )
    .unwrap();
    let before = inventory(&root);
    let bad_inputs = (0..7).map(|case| {
        let mut bad = proof.clone();
        match case {
            0 => {
                bad.snapshots.remove(0);
            }
            1 => bad.destination = h.region,
            2 => bad.source = destination_id,
            3 => bad.export = Hash([9; 32]),
            4 => {
                bad.snapshots[79].bft.as_mut().unwrap().committed.votes[0]
                    .approval
                    .signature = "00".repeat(64)
            }
            5 => bad.snapshots[65]
                .blocks
                .last_mut()
                .unwrap()
                .commands
                .clear(),
            _ => bad.snapshots.swap(78, 79),
        }
        bad
    });
    for bad in bad_inputs {
        assert!(destination.accept_complete_origin_history(bad).is_err());
        assert_eq!(inventory(&root), before);
        assert_eq!(destination.chain.height(), 0);
        assert!(destination.chain.ledger.coins.is_empty());
    }
    // Existing bounded Evidence path cannot be used to silently adopt this proof.
    assert!(destination
        .add_evidence(Evidence {
            snapshots: proof.snapshots.clone()
        })
        .is_err());
    assert_eq!(inventory(&root), before);
    assert_eq!(
        destination
            .accept_complete_origin_history(proof.clone())
            .unwrap(),
        checkpoint
    );
    assert_eq!(destination.chain.height(), 0);
    assert!(destination.chain.ledger.coins.is_empty());
    assert!(destination.chain.ledger.imports.is_empty());
    assert_eq!(
        destination.complete_origin_pending_imports().unwrap(),
        vec![Command::Import {
            snapshot: checkpoint,
            export
        }]
    );
    let evidence_head = destination.storage_head().unwrap();
    let evidence_bytes = inventory(&root);
    destination
        .accept_complete_origin_history(proof.clone())
        .unwrap();
    assert_eq!(destination.storage_head().unwrap(), evidence_head);
    assert_eq!(inventory(&root), evidence_bytes);
    let mut same_tail_changed_certificate = proof.clone();
    same_tail_changed_certificate.snapshots[79]
        .bft
        .as_mut()
        .unwrap()
        .committed
        .votes[0]
        .approval
        .signature = "00".repeat(64);
    assert!(destination
        .accept_complete_origin_history(same_tail_changed_certificate)
        .is_err());
    assert_eq!(destination.storage_head().unwrap(), evidence_head);
    assert_eq!(inventory(&root), evidence_bytes);
    let import = certified_with_commands(
        &destination.paged_replay.as_ref().unwrap().replay,
        vec![Command::Import {
            snapshot: checkpoint,
            export,
        }],
    );
    destination.finalize(import).unwrap();
    assert!(destination
        .complete_origin_pending_imports()
        .unwrap()
        .is_empty());
    let recipient = id("output", &(export, 0u32)).unwrap();
    assert_eq!(
        destination.chain.ledger.coins[&recipient].payment.amount,
        Amount(99)
    );
    assert_eq!(destination.chain.ledger.coins[&recipient].mature, 3);
    assert_eq!(destination.chain.ledger.imports[&export], checkpoint);
    let intent = Intent {
        currency: pin,
        region: destination_id,
        inputs: vec![recipient],
        outputs: vec![Payment {
            owner: public(12),
            amount: Amount(98),
        }],
        fee: Amount(1),
        destination: None,
        remote: None,
        destination_fee: Amount::ZERO,
        valid_through: 24,
    };
    let signed = SignedIntent {
        approvals: vec![Approval {
            key: public(11),
            signature: signature(11, &intent.bytes().unwrap()),
        }],
        intent,
    };
    let after_import = inventory(&root);
    assert!(destination
        .bft_candidate(
            vec![Command::Import {
                snapshot: checkpoint,
                export
            }],
            public(10)
        )
        .is_err());
    assert!(destination
        .bft_candidate(vec![Command::Spend(Box::new(signed.clone()))], public(10))
        .is_err());
    assert_eq!(inventory(&root), after_import);
    destination
        .finalize(certified(
            &destination.paged_replay.as_ref().unwrap().replay,
        ))
        .unwrap();
    let mut forged = signed.clone();
    forged.approvals[0].signature = "00".repeat(64);
    assert!(destination
        .bft_candidate(vec![Command::Spend(Box::new(forged))], public(10))
        .is_err());
    destination
        .finalize(certified_with_commands(
            &destination.paged_replay.as_ref().unwrap().replay,
            vec![Command::Spend(Box::new(signed))],
        ))
        .unwrap();
    assert!(!destination.chain.ledger.coins.contains_key(&recipient));
    assert_eq!(
        conservation(&[source.chain.clone(), destination.chain.clone()])
            .unwrap()
            .2,
        Amount::ZERO
    );
    destination.chain.ledger.audit().unwrap();
    let pins = ColdPins {
        currency: pin,
        head: destination.storage_head().unwrap(),
        region: destination_id,
        export,
        source_checkpoint: checkpoint,
        root: destination.chain.ledger.root().unwrap(),
    };
    drop(destination);
    fs::write(
        root.join("cold-pins.json"),
        serde_json::to_vec(&pins).unwrap(),
    )
    .unwrap();
    let cold_before = inventory(&root);
    let result = Process::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "storage::paged::origin_history_tests::complete_origin_history_destination_cold_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("RLD_COMPLETE_ORIGIN_COLD_CHILD", &root)
        .current_dir(std::env::current_dir().unwrap())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(inventory(&root), cold_before);
    // Generate a genuinely owner-valid incompatible certificate at source80.
    // It is rejection evidence and must remain durable, never replace source80.
    let mut fork = replay(&h);
    let empty_source = super::origin_history::test_history(&h, &fork, &records);
    for record in &records[..79] {
        fork.apply_retained(record, &empty_source).unwrap();
    }
    let (input, coin) = fork
        .chain
        .ledger
        .coins
        .iter()
        .find(|(_, c)| c.created == 2)
        .unwrap();
    let intent = Intent {
        currency: pin,
        region: h.region,
        inputs: vec![*input],
        outputs: vec![Payment {
            owner: public(12),
            amount: Amount(coin.payment.amount.0 - 1),
        }],
        fee: Amount(1),
        destination: None,
        remote: None,
        destination_fee: Amount::ZERO,
        valid_through: 90,
    };
    let spend = SignedIntent {
        approvals: vec![Approval {
            key: public(10),
            signature: signature(10, &intent.bytes().unwrap()),
        }],
        intent,
    };
    let mut incompatible = proof.clone();
    incompatible.snapshots[79] =
        certified_with_commands(&fork, vec![Command::Spend(Box::new(spend))]);
    let mut receiver = Store::create(
        &root.join("conflict-receiver"),
        h.bootstrap.clone(),
        destination_id,
        &public(1),
        pin,
    )
    .unwrap();
    receiver
        .accept_complete_origin_history(proof.clone())
        .unwrap();
    assert!(receiver
        .accept_complete_origin_history(incompatible)
        .is_err());
    assert_eq!(receiver.journal.incident_ids.len(), 1);
    assert!(receiver.safety.check_region(h.region).is_err());
    assert!(receiver.complete_origin_pending_imports().is_err());
    let quarantine_bytes = inventory(&root);
    assert!(receiver.accept_complete_origin_history(proof).is_err());
    assert_eq!(inventory(&root), quarantine_bytes);
    assert_eq!(receiver.chain.height(), 0);
    assert!(receiver.chain.ledger.coins.is_empty());
    assert!(receiver
        .bft_candidate(
            vec![Command::Import {
                snapshot: checkpoint,
                export
            }],
            public(10)
        )
        .is_err());
}
