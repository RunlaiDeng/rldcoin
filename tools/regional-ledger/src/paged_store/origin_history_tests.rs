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
fn complete_origin80_local_import_candidate_cannot_emit_standalone_network_proof() {
    let (h, source, root, _, records, export) =
        source_fixture_with_profile(80, 16, crate::paged_bft::ORIGIN_HISTORY_RULES);
    let destination_id = source.trust.named("proxima").unwrap();
    let proof = CompleteOriginHistory {
        source: h.region,
        destination: destination_id,
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
    let mut destination = Store::create(
        &root.join("network-destination"),
        h.bootstrap.clone(),
        destination_id,
        &public(1),
        source.trust.currency().unwrap(),
    )
    .unwrap();
    destination.accept_complete_origin_history(proof).unwrap();
    let commands = destination.complete_origin_pending_imports().unwrap();
    assert_eq!(commands.len(), 1);
    let before = inventory(&root);
    let head = destination.storage_head().unwrap();
    let state = destination.chain.ledger.root().unwrap();
    destination
        .bft_candidate(commands.clone(), public(10))
        .unwrap();
    let error = crate::bft_network::local_envelope(
        crate::bft_network::Body::Submission(commands),
        &destination,
    )
    .unwrap_err();
    assert_eq!(error, "contact causal dependency absent");
    assert_eq!(destination.storage_head().unwrap(), head);
    assert_eq!(destination.chain.ledger.root().unwrap(), state);
    assert_eq!(inventory(&root), before);
    assert_eq!(destination.chain.height(), 0);
    assert!(destination.chain.ledger.imports.is_empty());
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

#[test]
fn origin_network80_self_contained_submission_and_sequential_finality() {
    use crate::bft_network::{self, Body};
    let (h, source, root, _, records, export) =
        source_fixture_with_profile(80, 16, crate::paged_bft::ORIGIN_NETWORK_RULES);
    let destination_id = source.trust.named("proxima").unwrap();
    let currency = source.trust.currency().unwrap();
    let proof = CompleteOriginHistory {
        source: h.region,
        destination: destination_id,
        export,
        snapshots: records
            .into_iter()
            .map(|r| {
                let Record::Certified(s) = r else {
                    panic!("source certificate")
                };
                *s
            })
            .collect(),
    };
    let mut sender = Store::create(
        &root.join("sender"),
        h.bootstrap.clone(),
        destination_id,
        &public(1),
        currency,
    )
    .unwrap();
    let mut receiver = Store::create(
        &root.join("receiver"),
        h.bootstrap.clone(),
        destination_id,
        &public(1),
        currency,
    )
    .unwrap();
    sender
        .accept_complete_origin_history(proof.clone())
        .unwrap();
    let commands = sender.complete_origin_pending_imports().unwrap();
    let before = inventory(&root);
    let wire = bft_network::local_envelope(Body::Submission(commands.clone()), &sender)
        .unwrap()
        .envelope;
    assert_eq!(wire.format, bft_network::ORIGIN_FORMAT);
    assert_eq!(wire.origins.as_ref().unwrap(), &vec![proof.clone()]);
    assert!(wire.evidence.snapshots.is_empty());
    let envelope = wire.clone().expand().unwrap();
    envelope.verify(&receiver).unwrap();
    assert_eq!(inventory(&root), before);
    for case in 0..5 {
        let mut bad = wire.clone();
        match case {
            0 => bad.origins = None,
            1 => {
                bad.origins.as_mut().unwrap()[0].snapshots.remove(0);
            }
            2 => {
                bad.origins.as_mut().unwrap()[0].snapshots[79]
                    .bft
                    .as_mut()
                    .unwrap()
                    .committed
                    .votes[0]
                    .approval
                    .signature = "00".repeat(64)
            }
            3 => bad.format = bft_network::FORMAT.into(),
            _ => bad.origins.as_mut().unwrap()[0].destination = h.region,
        }
        assert!(bft_network::sync_origin_envelope(&mut receiver, bad).is_err());
        assert_eq!(inventory(&root), before);
    }
    bft_network::sync_origin_envelope(&mut receiver, wire).unwrap();
    assert_eq!(receiver.chain.height(), 0);
    assert!(receiver.chain.ledger.imports.is_empty());
    assert_eq!(
        receiver.complete_origin_pending_imports().unwrap(),
        commands
    );
    let import = certified_with_commands(&sender.paged_replay.as_ref().unwrap().replay, commands);
    let finalized = bft_network::local_envelope(Body::Finalized(Box::new(import.clone())), &sender)
        .unwrap()
        .envelope;
    bft_network::sync_origin_envelope(&mut receiver, finalized).unwrap();
    assert_eq!(receiver.chain.height(), 1);
    assert_eq!(receiver.chain.ledger.imports.len(), 1);
    let recipient = id("output", &(export, 0u32)).unwrap();
    assert_eq!(
        receiver.chain.ledger.coins[&recipient].payment.amount,
        Amount(99)
    );
    assert_eq!(receiver.chain.ledger.coins[&recipient].mature, 3);
    receiver.chain.ledger.audit().unwrap();
    sender.finalize(import).unwrap();
    let mature2 = certified(&sender.paged_replay.as_ref().unwrap().replay);
    sender.finalize(mature2).unwrap();
    let mature3 = certified(&sender.paged_replay.as_ref().unwrap().replay);
    sender.finalize(mature3).unwrap();
    let intent = Intent {
        currency,
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
    let spend = SignedIntent {
        approvals: vec![Approval {
            key: public(11),
            signature: signature(11, &intent.bytes().unwrap()),
        }],
        intent,
    };
    let mut forged = spend.clone();
    forged.approvals[0].signature = "00".repeat(64);
    let before = inventory(&root);
    assert!(bft_network::local_envelope(
        Body::Submission(vec![Command::Spend(Box::new(forged))]),
        &sender
    )
    .is_err());
    assert_eq!(inventory(&root), before);
    let spend = certified_with_commands(
        &sender.paged_replay.as_ref().unwrap().replay,
        vec![Command::Spend(Box::new(spend))],
    );
    let catchup = bft_network::local_envelope(Body::Finalized(Box::new(spend)), &sender)
        .unwrap()
        .envelope;
    bft_network::sync_origin_envelope(&mut receiver, catchup.clone()).unwrap();
    crate::keystore::private_create(
        &root.join("origin-network-final4-wire.json"),
        &serde_json::to_vec(&catchup).unwrap(),
    )
    .unwrap();
    crate::keystore::private_create(
        &root.join("origin-network-bootstrap.json"),
        &serde_json::to_vec(&h.bootstrap).unwrap(),
    )
    .unwrap();
    crate::keystore::private_create(&root.join("origin-network-query.json"),&serde_json::to_vec(&serde_json::json!({"currency":currency,"region":destination_id,"export":export,"authority":public(1)})).unwrap()).unwrap();
    let retry_before = inventory(&root);
    bft_network::sync_origin_envelope(&mut receiver, catchup).unwrap();
    assert_eq!(inventory(&root), retry_before);
    assert_eq!(receiver.chain.height(), 4);
    assert!(!receiver.chain.ledger.coins.contains_key(&recipient));
    assert_eq!(
        conservation(&[source.chain.clone(), receiver.chain.clone()])
            .unwrap()
            .2,
        Amount::ZERO
    );
    let cold_head = receiver.storage_head().unwrap();
    let cold_root = receiver.chain.ledger.root().unwrap();
    drop(receiver);
    let cold = Store::open_pinned(&root.join("receiver"), &public(1), currency, cold_head).unwrap();
    assert_eq!(cold.chain.ledger.root().unwrap(), cold_root);
    assert_eq!(cold.chain.height(), 4);
    cold.chain.ledger.audit().unwrap();
}

#[test]
fn origin_network_two_valid_conflicting_histories_retain_incident_without_credit() {
    use crate::bft_network::{self, Body, WireEnvelope};
    let (h, source, root, _, records, export) =
        source_fixture_with_profile(80, 16, crate::paged_bft::ORIGIN_NETWORK_RULES);
    let destination = source.trust.named("proxima").unwrap();
    let currency = source.trust.currency().unwrap();
    let proof = CompleteOriginHistory {
        source: h.region,
        destination,
        export,
        snapshots: records
            .iter()
            .map(|r| {
                let Record::Certified(s) = r else {
                    panic!("source certificate")
                };
                *s.clone()
            })
            .collect(),
    };
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
        .find(|(_, c)| c.created == 2)
        .unwrap();
    let intent = Intent {
        currency,
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
    let wire = WireEnvelope {
        format: bft_network::ORIGIN_FORMAT.into(),
        currency,
        region: destination,
        evidence: crate::carriage::CarriedEvidence { snapshots: vec![] },
        body: Body::Submission(vec![Command::Import {
            snapshot: proof.snapshots[79].statement.id().unwrap(),
            export,
        }]),
        origins: Some(vec![proof, incompatible]),
    };
    let mut receiver = Store::create(
        &root.join("incident-receiver"),
        h.bootstrap.clone(),
        destination,
        &public(1),
        currency,
    )
    .unwrap();
    assert!(wire.clone().expand().unwrap().verify(&receiver).is_err());
    assert!(bft_network::sync_origin_envelope(&mut receiver, wire.clone()).is_err());
    assert_eq!(receiver.journal.incident_ids.len(), 1);
    assert!(receiver.safety.check_region(h.region).is_err());
    let before_control = inventory(&root);
    let mut timeout = crate::bft::TimeoutVote {
        context: crate::bft::Context::current(&receiver).unwrap(),
        round: 0,
        high: None,
        approval: Approval {
            key: public(2),
            signature: String::new(),
        },
    };
    timeout.approval.signature = signature(2, &timeout.bytes().unwrap());
    assert!(bft_network::local_envelope(
        Body::Signed(Box::new(crate::bft::Message::Timeout(Box::new(timeout)))),
        &receiver,
    )
    .is_err());
    assert_eq!(inventory(&root), before_control);
    assert_eq!(receiver.chain.height(), 0);
    assert!(receiver.chain.ledger.coins.is_empty());
    assert!(receiver.chain.ledger.imports.is_empty());
    crate::keystore::private_create(
        &root.join("origin-network-conflicting-wire.json"),
        &serde_json::to_vec(&wire).unwrap(),
    )
    .unwrap();
    crate::keystore::private_create(
        &root.join("origin-network-conflict-bootstrap.json"),
        &serde_json::to_vec(&h.bootstrap).unwrap(),
    )
    .unwrap();
    crate::keystore::private_create(
        &root.join("origin-network-conflict-query.json"),
        &serde_json::to_vec(
            &serde_json::json!({"currency":currency,"region":destination,"authority":public(1)}),
        )
        .unwrap(),
    )
    .unwrap();
}

#[test]
fn origin_contact80_native_export_complete66_stable_frame_and_receiver_pending_only() {
    origin_contact_named_source("earth");
}

#[test]
fn origin_contact_fresh_live_proposal_chain_fixture() {
    let name =
        std::env::var("RLD_PUBLIC_CONTACT_ORIGIN").unwrap_or_else(|_| "earth-batch-1008".into());
    origin_contact_named_source(&name);
}

fn origin_contact_named_source(origin_name: &str) {
    let (h, source, root, _, records, export) =
        super::export_archive_tests::source_fixture_with_named_origin(
            80,
            16,
            crate::paged_bft::ORIGIN_NETWORK_RULES,
            origin_name,
        );
    let currency = source.trust.currency().unwrap();
    let destination = source.trust.named("proxima").unwrap();
    let mut origin = Store::create(
        &root.join("ordinary-source80"),
        h.bootstrap.clone(),
        h.region,
        &public(1),
        currency,
    )
    .unwrap();
    for batch in records.chunks(crate::history::PAGE_EVENTS) {
        origin.append_paged(batch).unwrap();
    }
    let before = inventory(&root);
    let raw = origin.contact_export(export).unwrap();
    let (frame, proof) = crate::contact::Frame::unpack_origin(&raw).unwrap();
    assert_eq!(frame.source_chain_id, h.region);
    assert_eq!(frame.destination_chain_id, destination);
    assert_eq!(frame.export_id, export);
    assert_eq!(proof.snapshots.len(), 66);
    assert!(serde_json::to_vec(&proof).unwrap().len() <= crate::contact::MAX_PAYLOAD);
    assert_eq!(inventory(&root), before);
    origin
        .finalize(certified(&origin.paged_replay.as_ref().unwrap().replay))
        .unwrap();
    assert_eq!(origin.contact_export(export).unwrap(), raw);
    let mut receiver = Store::create(
        &root.join("ordinary-receiver"),
        h.bootstrap.clone(),
        destination,
        &public(1),
        currency,
    )
    .unwrap();
    let before = inventory(&root);
    assert!(receiver
        .retained_origin_contact_messages()
        .unwrap()
        .is_empty());
    let mut bad = proof.clone();
    bad.snapshots[65].bft.as_mut().unwrap().committed.votes[0]
        .approval
        .signature = "00".repeat(64);
    let altered_message = crate::contact::Frame::origin_frame(&bad)
        .unwrap()
        .message_id;
    assert_ne!(altered_message, frame.message_id);
    assert!(receiver.accept_complete_origin_history(bad).is_err());
    assert_eq!(inventory(&root), before);
    receiver.accept_complete_origin_history(proof).unwrap();
    assert_eq!(
        receiver.retained_origin_contact_messages().unwrap(),
        vec![frame.message_id]
    );
    assert_eq!(receiver.chain.height(), 0);
    assert!(receiver.chain.ledger.coins.is_empty());
    assert_eq!(receiver.complete_origin_pending_imports().unwrap().len(), 1);
    let head = receiver.storage_head().unwrap();
    let before_cold = inventory(&root.join("ordinary-receiver"));
    drop(receiver);
    let cold =
        Store::open_pinned(&root.join("ordinary-receiver"), &public(1), currency, head).unwrap();
    assert_eq!(
        cold.retained_origin_contact_messages().unwrap(),
        vec![frame.message_id]
    );
    assert_eq!(cold.chain.height(), 0);
    assert!(cold.chain.ledger.coins.is_empty());
    drop(cold);
    assert_eq!(inventory(&root.join("ordinary-receiver")), before_cold);
    crate::keystore::private_create(
        &root.join("origin-contact-bootstrap.json"),
        &serde_json::to_vec(&h.bootstrap).unwrap(),
    )
    .unwrap();
    crate::keystore::private_create(&root.join("origin-contact-frame.json"), &raw).unwrap();
    crate::keystore::private_create(&root.join("origin-contact-query.json"),&serde_json::to_vec(&serde_json::json!({"currency":currency,"source":h.region,"destination":destination,"authority":public(1),"export":export})).unwrap()).unwrap();
}

#[test]
fn origin_conflict80_survives_invalid_tail81_without_credit_or_forged_incident() {
    use crate::bft_network::{self, Body, WireEnvelope};
    let (h, source, root, _, records, export) =
        source_fixture_with_profile(80, 16, crate::paged_bft::ORIGIN_NETWORK_RULES);
    let destination = source.trust.named("proxima").unwrap();
    let currency = source.trust.currency().unwrap();
    let proof = CompleteOriginHistory {
        source: h.region,
        destination,
        export,
        snapshots: records
            .iter()
            .map(|r| {
                let Record::Certified(s) = r else {
                    panic!("source certificate")
                };
                *s.clone()
            })
            .collect(),
    };
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
        .find(|(_, c)| c.created == 2)
        .unwrap();
    let intent = Intent {
        currency,
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
    let mut incoming = proof.clone();
    incoming.snapshots[79] = certified_with_commands(&fork, vec![Command::Spend(Box::new(spend))]);
    let conflict = Conflict::from_snapshots(&proof.snapshots[79], &incoming.snapshots[79]).unwrap();
    conflict.verify(&source.trust).unwrap();
    assert!(Conflict::may_conflict(
        &proof.snapshots[79],
        &incoming.snapshots[79]
    ));
    assert!(!Conflict::may_conflict(
        &proof.snapshots[79],
        &proof.snapshots[79]
    ));
    // The later malformed parent witness must not erase the authentic conflict80.
    let mut tail = incoming.snapshots[79].clone();
    tail.statement.height = 81;
    tail.blocks.remove(0);
    incoming.snapshots.push(tail);
    assert!(incoming.shape(destination, &source.trust).is_err());
    let mut forged = incoming.clone();
    forged.snapshots[79].bft.as_mut().unwrap().committed.votes[0]
        .approval
        .signature = "00".repeat(64);
    let make_wire = |incoming: CompleteOriginHistory| WireEnvelope {
        format: bft_network::ORIGIN_FORMAT.into(),
        currency,
        region: destination,
        evidence: crate::carriage::CarriedEvidence { snapshots: vec![] },
        body: Body::Submission(vec![Command::Import {
            snapshot: proof.snapshots[79].statement.id().unwrap(),
            export,
        }]),
        origins: Some(vec![proof.clone(), incoming]),
    };
    // Exercise retained-local comparison and conflict between two arriving histories.
    for mode in [
        "local",
        "network",
        "batch",
        "batch-prefix",
        "network-prefix",
        "observe-prefix",
    ] {
        let network = mode != "local";
        let dir = root.join(format!("bad-tail-{mode}"));
        let mut receiver =
            Store::create(&dir, h.bootstrap.clone(), destination, &public(1), currency).unwrap();
        if !network {
            receiver
                .accept_complete_origin_history(proof.clone())
                .unwrap();
        }
        let value = receiver.chain.ledger.clone();
        let before = inventory(&dir);
        let head = receiver.storage_head().unwrap();
        let decorate = |receiver: &Store, mut wire: WireEnvelope| {
            if mode.ends_with("prefix") {
                wire.evidence
                    .snapshots
                    .push(crate::carriage::CarriedSnapshot {
                        prefix: Some(crate::carriage::Prefix {
                            checkpoint: Hash::ZERO,
                            blocks: 1,
                        }),
                        snapshot: certified(&receiver.paged_replay.as_ref().unwrap().replay),
                    });
            }
            wire
        };
        let receive_batch = |receiver: &mut Store, incoming: CompleteOriginHistory| {
            let mut first = make_wire(incoming.clone());
            first.origins = Some(vec![proof.clone()]);
            let mut second = make_wire(incoming);
            second.origins.as_mut().unwrap().remove(0);
            second = decorate(receiver, second);
            let wires = vec![first, second];
            bft_network::receive_origin_batch(receiver, wires).map(|_| ())
        };
        let rejected = if mode.starts_with("batch") {
            receive_batch(&mut receiver, forged.clone())
        } else if mode == "observe-prefix" {
            receiver.observe_origin_network_wire_conflicts(&decorate(
                &receiver,
                make_wire(forged.clone()),
            ))
        } else if network {
            let wire = decorate(&receiver, make_wire(forged.clone()));
            bft_network::sync_origin_envelope(&mut receiver, wire)
        } else {
            receiver
                .accept_complete_origin_history(forged.clone())
                .map(|_| ())
        };
        assert!(rejected.is_err());
        assert!(receiver.journal.incident_ids.is_empty());
        assert_eq!(receiver.storage_head().unwrap(), head);
        assert_eq!(inventory(&dir), before);
        let rejected = if mode.starts_with("batch") {
            receive_batch(&mut receiver, incoming.clone())
        } else if mode == "observe-prefix" {
            receiver.observe_origin_network_wire_conflicts(&decorate(
                &receiver,
                make_wire(incoming.clone()),
            ))
        } else if network {
            let wire = decorate(&receiver, make_wire(incoming.clone()));
            bft_network::sync_origin_envelope(&mut receiver, wire)
        } else {
            receiver
                .accept_complete_origin_history(incoming.clone())
                .map(|_| ())
        };
        assert!(rejected.is_err());
        assert_eq!(receiver.chain.ledger, value);
        assert_eq!(receiver.chain.height(), 0);
        assert_eq!(
            receiver.journal.incident_ids.len(),
            1,
            "valid conflict hidden by invalid tail81; network={network}"
        );
        assert!(receiver.safety.check_region(h.region).is_err());
        assert!(receiver
            .retained_origin_contact_messages()
            .unwrap()
            .is_empty());
        if network {
            // No origin event was installed, so there is no pending work at all.
            assert!(receiver
                .complete_origin_pending_imports()
                .unwrap()
                .is_empty());
        } else {
            assert!(receiver.complete_origin_pending_imports().is_err());
        }
        assert_eq!(receiver.conflicts[0].id().unwrap(), conflict.id().unwrap());
        let head = receiver.storage_head().unwrap();
        drop(receiver);
        let before = inventory(&dir);
        let cold = Store::open_pinned(&dir, &public(1), currency, head).unwrap();
        assert_eq!(cold.chain.ledger, value);
        assert_eq!(cold.journal.incident_ids.len(), 1);
        assert!(cold.safety.check_region(h.region).is_err());
        assert!(cold.retained_origin_contact_messages().unwrap().is_empty());
        if network {
            assert!(cold.complete_origin_pending_imports().unwrap().is_empty());
        } else {
            assert!(cold.complete_origin_pending_imports().is_err());
        }
        drop(cold);
        assert_eq!(inventory(&dir), before);
    }
}

#[test]
fn origin_contact80_authenticated_local_evidence_does_not_replace_certified_export_prefix() {
    let (h, source, root, _, records, export) =
        source_fixture_with_profile(80, 16, crate::paged_bft::ORIGIN_NETWORK_RULES);
    let mut origin = Store::create(
        &root.join("ordinary-evidence-source80"),
        h.bootstrap.clone(),
        h.region,
        &public(1),
        source.trust.currency().unwrap(),
    )
    .unwrap();
    for batch in records.chunks(crate::history::PAGE_EVENTS) {
        origin.append_paged(batch).unwrap();
    }
    let raw = origin.contact_export(export).unwrap();
    let Record::Certified(tail) = &records[79] else {
        panic!("source certified tail")
    };
    let mut forged = *tail.clone();
    forged.bft.as_mut().unwrap().committed.votes[0]
        .approval
        .signature = "00".repeat(64);
    let before = inventory(&root);
    assert!(origin
        .add_evidence(Evidence {
            snapshots: vec![forged]
        })
        .is_err());
    assert_eq!(inventory(&root), before);
    origin
        .add_evidence(Evidence {
            snapshots: vec![*tail.clone()],
        })
        .unwrap();
    let before = inventory(&root);
    assert_eq!(origin.contact_export(export).unwrap(), raw);
    assert_eq!(inventory(&root), before);
    origin.chain.ledger.audit().unwrap();
}

#[test]
fn origin66_single_receiver_discriminates_conflict_scan_from_full_replay_cost() {
    let (h, source, root, _, records, export) =
        source_fixture_with_profile(66, 16, crate::paged_bft::ORIGIN_NETWORK_RULES);
    let destination = source.trust.named("proxima").unwrap();
    let currency = source.trust.currency().unwrap();
    let proof = CompleteOriginHistory {
        source: h.region,
        destination,
        export,
        snapshots: records
            .into_iter()
            .map(|r| {
                let Record::Certified(s) = r else {
                    panic!("certified source")
                };
                *s
            })
            .collect(),
    };
    let dir = root.join("cost-receiver");
    let mut receiver =
        Store::create(&dir, h.bootstrap.clone(), destination, &public(1), currency).unwrap();
    receiver
        .accept_complete_origin_history(proof.clone())
        .unwrap();
    let head = receiver.storage_head().unwrap();
    let value = receiver.chain.ledger.clone();
    let before = inventory(&dir);
    let started = std::time::Instant::now();
    receiver
        .check_paged_snapshot_conflicts(&proof.snapshots)
        .unwrap();
    let conflict_ns = started.elapsed().as_nanos();
    let started = std::time::Instant::now();
    CompleteOriginHistory::verify_network_set(
        std::slice::from_ref(&proof),
        destination,
        &receiver.trust,
    )
    .unwrap();
    let complete_network_ns = started.elapsed().as_nanos();
    let started = std::time::Instant::now();
    receiver
        .accept_complete_origin_history(proof.clone())
        .unwrap();
    let exact_retry_ns = started.elapsed().as_nanos();
    assert_eq!(receiver.storage_head().unwrap(), head);
    assert_eq!(receiver.chain.ledger, value);
    assert_eq!(inventory(&dir), before);
    drop(receiver);
    let started = std::time::Instant::now();
    let cold = Store::open_pinned(&dir, &public(1), currency, head).unwrap();
    let cold_replay_ns = started.elapsed().as_nanos();
    assert_eq!(cold.chain.ledger, value);
    assert_eq!(cold.chain.height(), 0);
    assert!(cold.journal.incident_ids.is_empty());
    drop(cold);
    assert_eq!(inventory(&dir), before);
    println!("origin66_cost={{\"conflict_ns\":{conflict_ns},\"complete_network_ns\":{complete_network_ns},\"exact_retry_ns\":{exact_retry_ns},\"cold_replay_ns\":{cold_replay_ns}}}");
    // Timings discriminate work; they never authorize evidence or credit.
}

#[test]
fn origin66_genesis_timeout_requires_no_value_dependency_but_import_and_parent_do() {
    control_dependency_fixture(false);
}

#[test]
fn origin_network_local_issuer_retains_complete_native_history_without_self_import() {
    use crate::bft_network::{self, Body};
    let mut h = header();
    h.bootstrap.currency.origin = "earth-local-material".into();
    h.bootstrap.currency.signature = signature(1, &h.bootstrap.currency.bytes().unwrap());
    let admission = &mut h.bootstrap.admissions[0];
    admission.currency = h.bootstrap.currency.id().unwrap();
    admission.region = h.bootstrap.currency.origin.clone();
    admission.rules = crate::paged_bft::ORIGIN_NETWORK_RULES.into();
    admission.value_rules = Some(crate::paged_bft::rules_hash_for(&admission.rules).unwrap());
    admission.signature = signature(1, &admission.bytes().unwrap());
    h.region = admission.id().unwrap();
    let (root, _) = super::body_witness_tests::stream(&h, &replay(&h));
    let currency = h.bootstrap.currency.id().unwrap();
    let mut sender = Store::create(
        &root.join("issuer"),
        h.bootstrap.clone(),
        h.region,
        &public(1),
        currency,
    )
    .unwrap();
    let receiver = Store::create(
        &root.join("cold-receiver"),
        h.bootstrap.clone(),
        h.region,
        &public(1),
        currency,
    )
    .unwrap();
    let receiver_before = inventory(&root.join("cold-receiver"));
    for height in 1..=3 {
        let snapshot = certified(&sender.paged_replay.as_ref().unwrap().replay);
        sender.finalize(snapshot.clone()).unwrap();
        let before = inventory(&root.join("issuer"));
        let (origins, evidence) = sender.origin_network_material().unwrap();
        assert!(origins.is_empty());
        assert_eq!(evidence.snapshots.len(), height);
        let packed =
            bft_network::local_envelope(Body::Finalized(Box::new(snapshot)), &sender).unwrap();
        let complete = packed.envelope.expand().unwrap();
        assert_eq!(complete.evidence.snapshots, evidence.snapshots);
        complete.verify(&receiver).unwrap();
        assert_eq!(inventory(&root.join("issuer")), before);
        assert_eq!(inventory(&root.join("cold-receiver")), receiver_before);
        assert_eq!(receiver.chain.height(), 0);
        assert!(receiver.chain.ledger.coins.is_empty());
        let mut forged = complete.clone();
        forged.evidence.snapshots[0]
            .bft
            .as_mut()
            .unwrap()
            .committed
            .votes[0]
            .approval
            .signature = "00".repeat(64);
        assert!(forged.verify(&receiver).is_err());
        if height > 1 {
            let mut missing = complete;
            missing.evidence.snapshots.remove(0);
            assert!(missing.verify(&receiver).is_err());
        }
        assert_eq!(inventory(&root.join("cold-receiver")), receiver_before);
    }
    let head = sender.storage_head().unwrap();
    drop(sender);
    let cold = Store::open_pinned(&root.join("issuer"), &public(1), currency, head).unwrap();
    assert_eq!(cold.chain.height(), 3);
    let (origins, evidence) = cold.origin_network_material().unwrap();
    assert!(origins.is_empty());
    assert_eq!(evidence.snapshots.len(), 3);
    assert_eq!(evidence.snapshots.last().unwrap().statement.height, 3);
}

#[test]
fn origin66_empty_parent_control_retains_certificates_without_pending_value_dependency() {
    control_dependency_fixture(true);
}

fn control_dependency_fixture(empty_parent: bool) {
    use crate::bft_network::{self, Body};
    let (h, source, root, _, records, export) =
        source_fixture_with_profile(66, 16, crate::paged_bft::ORIGIN_NETWORK_RULES);
    let destination = source.trust.named("proxima").unwrap();
    let currency = source.trust.currency().unwrap();
    let proof = CompleteOriginHistory {
        source: h.region,
        destination,
        export,
        snapshots: records
            .into_iter()
            .map(|r| {
                let Record::Certified(s) = r else {
                    panic!("certified source")
                };
                *s
            })
            .collect(),
    };
    let mut sender = Store::create(
        &root.join("control-sender"),
        h.bootstrap.clone(),
        destination,
        &public(1),
        currency,
    )
    .unwrap();
    sender
        .accept_complete_origin_history(proof.clone())
        .unwrap();
    let receiver = Store::create(
        &root.join("control-receiver"),
        h.bootstrap.clone(),
        destination,
        &public(1),
        currency,
    )
    .unwrap();
    let receiver_head = receiver.storage_head().unwrap();
    drop(receiver);
    let receiver = Store::open_pinned(
        &root.join("control-receiver"),
        &public(1),
        currency,
        receiver_head,
    )
    .unwrap();
    if empty_parent {
        let empty = certified(&sender.paged_replay.as_ref().unwrap().replay);
        sender.finalize(empty).unwrap();
        assert_eq!(sender.chain.ledger, Ledger::default());
    }
    let timeout = |context| {
        let mut vote = crate::bft::TimeoutVote {
            context,
            round: 0,
            high: None,
            approval: Approval {
                key: public(2),
                signature: String::new(),
            },
        };
        vote.approval.signature = signature(2, &vote.bytes().unwrap());
        Body::Signed(Box::new(crate::bft::Message::Timeout(Box::new(vote))))
    };
    let body = timeout(crate::bft::Context::current(&sender).unwrap());
    let (origins, evidence) = sender.origin_network_material().unwrap();
    assert_eq!(evidence.snapshots.is_empty(), !empty_parent);
    let complete = bft_network::Envelope {
        format: bft_network::ORIGIN_FORMAT.into(),
        currency,
        region: destination,
        origins: Some(origins),
        evidence,
        body: body.clone(),
    };
    let before = inventory(&root);
    let started = std::time::Instant::now();
    complete.verify(&receiver).unwrap();
    let complete_ns = started.elapsed().as_nanos();
    let mut minimal = complete.clone();
    minimal.origins = Some(vec![]);
    let started = std::time::Instant::now();
    minimal.verify(&receiver).unwrap();
    let minimal_ns = started.elapsed().as_nanos();
    let started = std::time::Instant::now();
    let local = bft_network::local_envelope(body, &sender).unwrap();
    let local_ns = started.elapsed().as_nanos();
    println!("origin66_control_cost={{\"complete_ns\":{complete_ns},\"minimal_ns\":{minimal_ns},\"local_ns\":{local_ns},\"complete_bytes\":{},\"minimal_bytes\":{},\"local_bytes\":{}}}",
        serde_json::to_vec(&complete.pack().unwrap()).unwrap().len(),
        serde_json::to_vec(&minimal.pack().unwrap()).unwrap().len(),
        serde_json::to_vec(&local.envelope).unwrap().len());
    for case in 0..3 {
        let mut bad = minimal.clone();
        match case {
            0 => {
                let Body::Signed(message) = &mut bad.body else {
                    panic!("signed")
                };
                let crate::bft::Message::Timeout(vote) = message.as_mut() else {
                    panic!("timeout")
                };
                vote.approval.signature = "00".repeat(64);
            }
            1 => {
                let mut context = crate::bft::Context::current(&sender).unwrap();
                context.parent_height += 1;
                bad.body = timeout(context);
            }
            _ => {
                let mut forged = proof.clone();
                forged.snapshots[65].bft.as_mut().unwrap().committed.votes[0]
                    .approval
                    .signature = "00".repeat(64);
                bad.origins = Some(vec![forged]);
            }
        }
        assert!(bad.verify(&receiver).is_err());
    }
    assert_eq!(inventory(&root), before);
    let import = certified_with_commands(
        &sender.paged_replay.as_ref().unwrap().replay,
        sender.complete_origin_pending_imports().unwrap(),
    );
    let mut vote = crate::bft::Vote {
        context: crate::bft::Context::current(&sender).unwrap(),
        round: 0,
        value: import.statement.id().unwrap(),
        phase: crate::bft::Phase::Prepare,
        approval: Approval {
            key: public(2),
            signature: String::new(),
        },
    };
    vote.approval.signature = signature(2, &vote.bytes().unwrap());
    let vote = bft_network::local_envelope(
        Body::Signed(Box::new(crate::bft::Message::Vote(Box::new(vote)))),
        &sender,
    )
    .unwrap()
    .envelope;
    assert!(vote.origins.as_ref().unwrap().is_empty());
    vote.expand().unwrap().verify(&receiver).unwrap();
    assert_eq!(inventory(&root), before);
    let value = bft_network::local_envelope(Body::Finalized(Box::new(import.clone())), &sender)
        .unwrap()
        .envelope;
    assert_eq!(value.origins.as_ref().unwrap(), &vec![proof.clone()]);
    value.clone().expand().unwrap().verify(&receiver).unwrap();
    let mut missing = value.expand().unwrap();
    missing.origins = Some(vec![]);
    assert!(missing.verify(&receiver).is_err());
    sender.finalize(import).unwrap();
    let later = bft_network::local_envelope(
        timeout(crate::bft::Context::current(&sender).unwrap()),
        &sender,
    )
    .unwrap()
    .envelope;
    assert_eq!(later.origins.as_ref().unwrap(), &vec![proof]);
    later.clone().expand().unwrap().verify(&receiver).unwrap();
    let mut missing = later.expand().unwrap();
    missing.origins = Some(vec![]);
    assert!(missing.verify(&receiver).is_err());
    assert_eq!(receiver.storage_head().unwrap(), receiver_head);
    assert_eq!(receiver.chain.height(), 0);
    assert!(receiver.chain.ledger.coins.is_empty());
    assert!(receiver.journal.incident_ids.is_empty());
    assert_eq!(
        serde_json::to_vec(&local.envelope).unwrap(),
        serde_json::to_vec(&minimal.pack().unwrap()).unwrap()
    );
}

#[test]
fn origin66_receive_batch_authenticates_all_before_sync_and_matches_sequential_value() {
    origin_receive_batch_fixture(false);
}

#[test]
fn origin66_nonempty_finality_batch_authenticates_before_sync_and_matches_cold_value() {
    origin_receive_batch_fixture(true);
}

fn origin_receive_batch_fixture(nonempty: bool) {
    use crate::bft_network::{self, Body};
    // Public no-value fixture namespace only. The signed currency validates its
    // normal name bound; this never opens/converts old stores or grants trust.
    let name = std::env::var("RLD_PUBLIC_FINALITY_ORIGIN")
        .unwrap_or_else(|_| "earth-finality-batch".into());
    let (h, source, root, _, records, export) =
        super::export_archive_tests::source_fixture_with_named_origin(
            66,
            16,
            crate::paged_bft::ORIGIN_NETWORK_RULES,
            if nonempty { &name } else { "earth" },
        );
    let destination = source.trust.named("proxima").unwrap();
    let currency = source.trust.currency().unwrap();
    let proof = CompleteOriginHistory {
        source: h.region,
        destination,
        export,
        snapshots: records
            .into_iter()
            .map(|r| {
                let Record::Certified(s) = r else {
                    panic!("source certified")
                };
                *s
            })
            .collect(),
    };
    let mut sender = Store::create(
        &root.join("batch-sender"),
        h.bootstrap.clone(),
        destination,
        &public(1),
        currency,
    )
    .unwrap();
    sender.accept_complete_origin_history(proof).unwrap();
    let import = certified_with_commands(
        &sender.paged_replay.as_ref().unwrap().replay,
        sender.complete_origin_pending_imports().unwrap(),
    );
    if nonempty {
        sender
            .finalize_origin_network_certificate(import.clone())
            .unwrap();
        assert_eq!(sender.chain.height(), 1);
    }
    let wire = bft_network::local_envelope(Body::Finalized(Box::new(import)), &sender)
        .unwrap()
        .envelope;
    let new_receiver = |name: &str| {
        Store::create(
            &root.join(name),
            h.bootstrap.clone(),
            destination,
            &public(1),
            currency,
        )
        .unwrap()
    };
    let mut batch = new_receiver("batch-receiver");
    let mut sequential = new_receiver("sequential-receiver");
    assert_eq!(wire.evidence.snapshots.is_empty(), !nonempty);
    for case in 0..if nonempty { 7 } else { 5 } {
        let mut bad = wire.clone();
        match case {
            0 => {
                let Body::Finalized(snapshot) = &mut bad.body else {
                    panic!("finalized")
                };
                snapshot.bft.as_mut().unwrap().committed.votes[0]
                    .approval
                    .signature = "00".repeat(64);
            }
            1 => {
                bad.origins.as_mut().unwrap()[0].snapshots[65]
                    .bft
                    .as_mut()
                    .unwrap()
                    .committed
                    .votes[0]
                    .approval
                    .signature = "00".repeat(64)
            }
            2 => bad.currency = Hash::ZERO,
            3 => bad.format = bft_network::FORMAT.into(),
            4 => {
                let mut context = crate::bft::Context::current(&sender).unwrap();
                context.parent_height += 1;
                let mut timeout = crate::bft::TimeoutVote {
                    context,
                    round: 0,
                    high: None,
                    approval: Approval {
                        key: public(2),
                        signature: String::new(),
                    },
                };
                timeout.approval.signature = signature(2, &timeout.bytes().unwrap());
                bad.body = Body::Signed(Box::new(crate::bft::Message::Timeout(Box::new(timeout))));
            }
            5 => {
                bad.evidence.snapshots[0]
                    .snapshot
                    .bft
                    .as_mut()
                    .unwrap()
                    .committed
                    .votes[0]
                    .approval
                    .signature = "00".repeat(64)
            }
            _ => {
                bad.evidence.snapshots[0].prefix = Some(crate::carriage::Prefix {
                    checkpoint: Hash::ZERO,
                    blocks: 1,
                })
            }
        }
        let before = inventory(&root.join("batch-receiver"));
        let head = batch.storage_head().unwrap();
        assert!(bft_network::receive_origin_batch(&mut batch, vec![wire.clone(), bad]).is_err());
        assert_eq!(batch.storage_head().unwrap(), head);
        assert_eq!(inventory(&root.join("batch-receiver")), before);
        assert_eq!(batch.chain.height(), 0);
        assert!(batch.chain.ledger.coins.is_empty());
        assert!(batch.journal.incident_ids.is_empty());
    }
    assert!(bft_network::receive_origin_batch(&mut batch, vec![]).is_err());
    assert!(bft_network::receive_origin_batch(&mut batch, vec![wire.clone(); 5]).is_err());
    let rows = bft_network::receive_origin_batch(&mut batch, vec![wire.clone(); 4]).unwrap();
    bft_network::inspect_live_batch(vec![wire.clone(); 4], &sequential).unwrap();
    for _ in 0..4 {
        bft_network::sync_origin_envelope(&mut sequential, wire.clone()).unwrap();
    }
    assert_eq!(rows.len(), 4);
    assert!(rows.windows(2).all(|p| p[0].message_id == p[1].message_id));
    assert_eq!(batch.chain.height(), 1);
    assert_eq!(batch.chain.ledger, sequential.chain.ledger);
    assert_eq!(batch.chain.finalized, sequential.chain.finalized);
    assert_eq!(
        batch.storage_head().unwrap(),
        sequential.storage_head().unwrap()
    );
    let head = batch.storage_head().unwrap();
    let before = inventory(&root.join("batch-receiver"));
    bft_network::receive_origin_batch(&mut batch, vec![wire.clone()]).unwrap();
    assert_eq!(batch.storage_head().unwrap(), head);
    assert_eq!(inventory(&root.join("batch-receiver")), before);
    let value = batch.chain.ledger.clone();
    drop(batch);
    let cold =
        Store::open_pinned(&root.join("batch-receiver"), &public(1), currency, head).unwrap();
    assert_eq!(cold.chain.ledger, value);
    assert_eq!(cold.chain.height(), 1);
    assert!(cold.chain.ledger.coins.values().all(|c| c.mature == 3));
    drop(cold);
    if nonempty {
        for (name, bytes) in [
            ("finality-bootstrap.json", serde_json::to_vec(&h.bootstrap).unwrap()),
            ("finality-wire.json", serde_json::to_vec(&wire).unwrap()),
            ("finality-query.json", serde_json::to_vec(&serde_json::json!({
                "currency":currency,"authority":public(1),"source":h.region,
                "destination":destination,"export":export,"source_signing_custody_qualified":false,
            })).unwrap()),
        ] {
            crate::keystore::private_create(&root.join(name), &bytes).unwrap();
        }
    }
}
