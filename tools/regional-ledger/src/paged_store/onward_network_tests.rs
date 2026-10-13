//! Fresh explicit envelope authority only; no ordinary Runtime or custody qualification.
use super::body_witness_tests::{certified_with_commands, replay};
use super::export_archive_tests::{inventory, source_fixture_with_regions};
use super::*;
use crate::bft::{Context, Message, Proposal, TimeoutVote};
use crate::bft_network::Body;
use crate::bft_onward_network as net;
use crate::tests::{public, signature};
use std::{process::Command as Process, time::Instant};

fn phase(started: &Instant, name: &str) {
    eprintln!(
        "onward_envelope_phase={}",
        serde_json::json!({
            "phase":name,"elapsed_seconds":started.elapsed().as_secs_f64()
        })
    );
}
fn payment(
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
        destination: remote.as_ref().map(|v| v.0),
        remote: remote.as_ref().map(|v| v.1.clone()),
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
fn install(node: &mut Store, commands: Vec<Command>) -> Snapshot {
    let snapshot = certified_with_commands(&node.paged_replay.as_ref().unwrap().replay, commands);
    node.finalize(snapshot.clone()).unwrap();
    snapshot
}
fn envelope(
    proof: &CompleteOnwardNetworkHistory,
    parents: &[Snapshot],
    body: Body,
    currency: Hash,
    region: Hash,
) -> net::Envelope {
    net::Envelope {
        format: net::FORMAT.into(),
        currency,
        region,
        history: Some(proof.clone()),
        evidence: Evidence {
            snapshots: parents.to_vec(),
        },
        body,
    }
}
fn refusal(root: &Path, receiver: &mut Store, name: &str, wire: net::WireEnvelope) -> String {
    let before = inventory(root);
    let head = receiver.storage_head().unwrap();
    let chain = receiver.chain.clone();
    let error = net::inspect(receiver, wire).unwrap_err();
    assert_eq!(receiver.storage_head().unwrap(), head);
    assert_eq!(receiver.chain.ledger, chain.ledger);
    assert_eq!(receiver.chain.finalized, chain.finalized);
    assert_eq!(receiver.chain.height(), chain.height());
    assert!(receiver.journal.incident_ids.is_empty());
    assert_eq!(inventory(root), before);
    eprintln!(
        "onward_envelope_refusal={}",
        serde_json::json!({"case":name,"error":error})
    );
    error
}
#[derive(Serialize, Deserialize)]
struct ColdPins {
    currency: Hash,
    b: Hash,
    c: Hash,
    b_head: Hash,
    c_head: Hash,
    b_state: Hash,
    c_state: Hash,
    c_finality: Hash,
    a80: Hash,
    b4: Hash,
    export: Hash,
    proof: Hash,
}
fn cold_child(root: &Path) {
    let pins: ColdPins =
        serde_json::from_slice(&fs::read(root.join("onward-envelope-cold.json")).unwrap()).unwrap();
    let before = inventory(root);
    let b = Store::open_pinned(
        &root.join("intermediate"),
        &public(1),
        pins.currency,
        pins.b_head,
    )
    .unwrap();
    let c = Store::open_pinned(
        &root.join("destination"),
        &public(1),
        pins.currency,
        pins.c_head,
    )
    .unwrap();
    assert_eq!((b.chain.region, b.chain.height()), (pins.b, 5));
    assert_eq!(
        (c.chain.region, c.chain.height(), c.chain.finalized),
        (pins.c, 2, Some(pins.c_finality))
    );
    assert_eq!(b.chain.ledger.root().unwrap(), pins.b_state);
    assert_eq!(c.chain.ledger.root().unwrap(), pins.c_state);
    let proof = b.complete_onward_network_export(pins.export).unwrap();
    assert_eq!(
        id("onward-envelope-fixture-proof", &proof).unwrap(),
        pins.proof
    );
    assert_eq!(proof.history.snapshots.len(), 4);
    assert_eq!(
        c.chain.ledger.imports,
        BTreeMap::from([(pins.export, pins.b4)])
    );
    let imported = &c.chain.ledger.coins[&id("output", &(pins.export, 0u32)).unwrap()];
    assert_eq!(
        imported.payment,
        Payment {
            owner: public(12),
            amount: Amount(89)
        }
    );
    assert_eq!(imported.mature, 4);
    assert_eq!(imported.dependencies, BTreeSet::from([pins.a80, pins.b4]));
    for anchor in [pins.a80, pins.b4] {
        c.evidence.snapshot(anchor).unwrap();
    }
    assert!(c
        .complete_onward_network_pending_imports()
        .unwrap()
        .is_empty());
    assert_eq!(c.chain.ledger.minted, Amount::ZERO);
    c.chain.ledger.audit().unwrap();
    let mut retained = 0;
    let stream = c.paged.as_ref().unwrap();
    stream
        .visit(stream.storage_head(), |record| {
            if let Record::OnwardNetworkHistory(proof) = record {
                retained += 1;
                assert_eq!(
                    id("onward-envelope-fixture-proof", proof.as_ref()).unwrap(),
                    pins.proof
                );
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(retained, 1);
    assert_eq!(stream.record_count(), 3);
    drop(c);
    drop(b);
    assert_eq!(inventory(root), before);
}

#[test]
#[ignore = "fresh complete A/B ancestry, C parent, actual consensus body and authenticated conflict boundary"]
fn complete_onward_network_authenticates_parent_body_and_conflicts() {
    // Only the parent supplies this fresh retained root; the child performs no construction.
    if let Some(root) = std::env::var_os("RLD_ONWARD_ENVELOPE_COLD_CHILD") {
        let root = PathBuf::from(root);
        assert!(root.is_absolute());
        cold_child(&root);
        return;
    }
    let started = Instant::now();
    phase(&started, "native-ancestry-begin");
    let (h, source, root, _, records, origin_export) = source_fixture_with_regions(
        80,
        16,
        crate::paged_bft::ORIGIN_NETWORK_RULES,
        "earth",
        &[("andromeda", crate::paged_bft::ONWARD_NETWORK_RULES)],
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
                _ => panic!("actual A certificate"),
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
    install(&mut intermediate, vec![]); // Real empty B1 precedes received A history.
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
    install(&mut intermediate, vec![]);
    let b_input = id("output", &(origin_export, 0u32)).unwrap();
    let onward = payment(
        b,
        pin,
        b_input,
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
    let Command::Spend(signed) = &onward else {
        unreachable!()
    };
    let export = signed.intent.id().unwrap();
    let b4_snapshot = install(&mut intermediate, vec![onward]);
    let b4 = b4_snapshot.statement.id().unwrap();
    let first = intermediate.complete_onward_network_export(export).unwrap();
    let b5 = install(&mut intermediate, vec![]);
    let proof = intermediate.complete_onward_network_export(export).unwrap();
    assert_eq!(first, proof);
    assert_eq!(proof.history.origin, origin);
    assert_eq!(proof.history.snapshots.len(), 4);
    assert_eq!(proof.history.snapshots[3].statement.id().unwrap(), b4);
    assert_ne!(export, origin_export);
    assert!(!intermediate.chain.ledger.coins.contains_key(&b_input));
    assert_eq!(
        intermediate.chain.ledger.imports,
        BTreeMap::from([(origin_export, a80)])
    );
    assert_eq!(
        intermediate.chain.ledger.exports[&export].dependencies,
        BTreeSet::from([a80])
    );
    assert_eq!(intermediate.chain.ledger.minted, Amount::ZERO);
    assert_eq!(
        conservation_with_escrow(&[source.chain.clone(), intermediate.chain.clone()])
            .unwrap()
            .3,
        Amount(90)
    );

    let admission = h
        .bootstrap
        .admissions
        .iter()
        .find(|a| a.id().unwrap() == c)
        .unwrap();
    admission.verify(&h.bootstrap.currency).unwrap();
    let mut altered = admission.clone();
    altered.rules = crate::paged_bft::ONWARD_HISTORY_RULES.into();
    altered.value_rules = Some(crate::paged_bft::rules_hash_for(&altered.rules).unwrap());
    assert!(altered.verify(&h.bootstrap.currency).is_err());
    let make_c = |name: &str| {
        Store::create(&root.join(name), h.bootstrap.clone(), c, &public(1), pin).unwrap()
    };
    let mut destination = make_c("destination");
    let c1 = install(&mut destination, vec![]);
    let c1_id = c1.statement.id().unwrap();
    let native_before = destination.chain.ledger.clone();
    assert_eq!(
        destination
            .accept_complete_onward_network_history(proof.clone())
            .unwrap(),
        b4
    );
    assert_eq!(destination.chain.ledger, native_before);
    assert!(
        destination.chain.ledger.coins.is_empty() && destination.chain.ledger.imports.is_empty()
    );
    let pending = vec![Command::Import {
        snapshot: b4,
        export,
    }];
    assert_eq!(
        destination
            .complete_onward_network_pending_imports()
            .unwrap(),
        pending
    );
    let before = inventory(&root);
    destination
        .accept_complete_onward_network_history(proof.clone())
        .unwrap();
    assert_eq!(inventory(&root), before);
    let before = inventory(&root);
    assert!(destination
        .accept_complete_onward_history(proof.history.clone())
        .is_err());
    assert!(intermediate.complete_onward_export(export).is_err());
    assert!(intermediate
        .accept_complete_onward_network_history(proof.clone())
        .is_err());
    assert_eq!(inventory(&root), before);
    phase(&started, "native-ancestry-end");

    phase(&started, "self-contained-body-begin");
    let mut receiver = make_c("fresh-receiver");
    assert_eq!(receiver.chain.height(), 0);
    assert!(receiver.evidence.snapshot(c1_id).is_err());
    let import = certified_with_commands(
        &destination.paged_replay.as_ref().unwrap().replay,
        pending.clone(),
    );
    let c2 = import.statement.id().unwrap();
    let mut prospective = import.clone();
    prospective.bft = None;
    let context = Context::current(&destination).unwrap();
    let keys = context
        .keys(&destination.trust, &destination.evidence)
        .unwrap();
    let leader = crate::bft::leader(&context, 0, &keys).unwrap();
    let seed = (2u8..=5).find(|n| public(*n) == leader).unwrap();
    let mut proposal = Proposal {
        round: 0,
        snapshot: Box::new(prospective),
        timeout: None,
        leader: Approval {
            key: leader,
            signature: String::new(),
        },
    };
    proposal.leader.signature = signature(seed, &proposal.bytes().unwrap());
    proposal
        .verify(&destination.trust, &destination.evidence)
        .unwrap();
    let qc = import.bft.as_ref().unwrap();
    let bodies = vec![
        Body::Submission(pending.clone()),
        Body::Signed(Box::new(Message::Proposal(Box::new(proposal.clone())))),
        Body::Signed(Box::new(Message::Vote(Box::new(
            qc.prepared.votes[0].clone(),
        )))),
        Body::Signed(Box::new(Message::Vote(Box::new(
            qc.committed.votes[0].clone(),
        )))),
        Body::Finalized(Box::new(import.clone())),
    ];
    let before = inventory(&root);
    let head = receiver.storage_head().unwrap();
    let mut identities = BTreeSet::new();
    let mut max_wire = 0;
    let mut max_expanded = 0;
    for body in bodies {
        let expanded = envelope(&proof, std::slice::from_ref(&c1), body, pin, c);
        let expanded_bytes = serde_json::to_vec(&expanded).unwrap().len();
        assert!(expanded_bytes <= MAX_BYTES);
        let expected = expanded.verify(&receiver).unwrap();
        let wire = expanded.pack().unwrap();
        let wire_bytes = serde_json::to_vec(&wire).unwrap();
        assert!(wire_bytes.len() <= crate::contact::MAX_PAYLOAD);
        max_wire = max_wire.max(wire_bytes.len());
        max_expanded = max_expanded.max(expanded_bytes);
        let decoded: net::WireEnvelope = crate::bft_client::decode(&wire_bytes).unwrap();
        assert_eq!(
            serde_json::to_value(decoded.clone().expand().unwrap()).unwrap(),
            serde_json::to_value(&expanded).unwrap()
        );
        let actual = net::inspect(&mut receiver, decoded.clone()).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(net::inspect(&mut receiver, decoded).unwrap(), actual);
        assert!(identities.insert(actual));
    }
    assert_eq!(receiver.storage_head().unwrap(), head);
    assert_eq!(receiver.chain.height(), 0);
    assert!(receiver.chain.ledger.coins.is_empty() && receiver.chain.ledger.imports.is_empty());
    assert_eq!(inventory(&root), before);
    let valid = envelope(
        &proof,
        std::slice::from_ref(&c1),
        Body::Signed(Box::new(Message::Proposal(Box::new(proposal.clone())))),
        pin,
        c,
    )
    .pack()
    .unwrap();
    for case in 0..7 {
        let mut bad = valid.clone();
        let name = match case {
            0 => {
                bad.history = None;
                "missing-foreign-closure"
            }
            1 => {
                bad.history
                    .as_mut()
                    .unwrap()
                    .history
                    .origin
                    .snapshots
                    .remove(0);
                "missing-A-prefix"
            }
            2 => {
                bad.evidence.snapshots.clear();
                "missing-C-parent"
            }
            3 => {
                bad.history.as_mut().unwrap().history.origin.snapshots[79]
                    .bft
                    .as_mut()
                    .unwrap()
                    .committed
                    .votes[0]
                    .approval
                    .signature = "00".repeat(64);
                "bad-A-tail"
            }
            4 => {
                let mut tail = b5.clone();
                tail.bft.as_mut().unwrap().committed.votes[0]
                    .approval
                    .signature = "00".repeat(64);
                bad.history.as_mut().unwrap().history.snapshots.push(tail);
                "bad-B-extra-tail"
            }
            5 => {
                let Body::Signed(message) = &mut bad.body else {
                    unreachable!()
                };
                let Message::Proposal(p) = message.as_mut() else {
                    unreachable!()
                };
                p.leader.signature = "00".repeat(64);
                "bad-body-signature"
            }
            _ => {
                bad.format = crate::bft_network::FORMAT.into();
                "old-format-mismatch"
            }
        };
        refusal(&root, &mut receiver, name, bad);
    }
    let mut bad_c2 = import.clone();
    bad_c2.bft.as_mut().unwrap().committed.votes[0]
        .approval
        .signature = "00".repeat(64);
    let tail = envelope(
        &proof,
        &[c1.clone(), bad_c2],
        Body::Signed(Box::new(Message::Proposal(Box::new(proposal)))),
        pin,
        c,
    )
    .pack()
    .unwrap();
    refusal(&root, &mut receiver, "bad-C-extra-tail", tail);
    phase(&started, "self-contained-body-end");

    phase(&started, "old-fallback-refusals-begin");
    // A valid genesis control body ensures rejection is not merely missing foreign history.
    let genesis = Context::current(&receiver).unwrap();
    let mut timeout = TimeoutVote {
        context: genesis.clone(),
        round: 0,
        high: None,
        approval: Approval {
            key: public(2),
            signature: String::new(),
        },
    };
    timeout.approval.signature = signature(2, &timeout.bytes().unwrap());
    timeout
        .verify(&genesis.keys(&receiver.trust, &receiver.evidence).unwrap())
        .unwrap();
    let old = crate::bft_network::Envelope {
        format: crate::bft_network::FORMAT.into(),
        currency: pin,
        region: c,
        evidence: Evidence::default(),
        body: Body::Signed(Box::new(Message::Timeout(Box::new(timeout.clone())))),
        origins: None,
    };
    let mut legacy_receiver = Store::create(
        &root.join("legacy-network-receiver"),
        h.bootstrap.clone(),
        h.region,
        &public(1),
        pin,
    )
    .unwrap();
    let legacy_context = Context::current(&legacy_receiver).unwrap();
    let mut legacy_timeout = TimeoutVote {
        context: legacy_context,
        round: 0,
        high: None,
        approval: Approval {
            key: public(2),
            signature: String::new(),
        },
    };
    legacy_timeout.approval.signature = signature(2, &legacy_timeout.bytes().unwrap());
    let mut legacy_envelope = crate::bft_network::Envelope {
        format: crate::bft_network::FORMAT.into(),
        currency: pin,
        region: h.region,
        evidence: Evidence::default(),
        origins: None,
        body: Body::Signed(Box::new(Message::Timeout(Box::new(legacy_timeout)))),
    };
    legacy_envelope.verify(&legacy_receiver).unwrap();
    legacy_envelope.evidence = Evidence {
        snapshots: vec![c1.clone()],
    };
    let before = inventory(&root);
    let profile_refusal = "complete onward network requires separately integrated ordinary runtime";
    assert_eq!(
        legacy_envelope.verify(&legacy_receiver).unwrap_err(),
        profile_refusal
    );
    assert_eq!(
        crate::bft_network::sync(&mut legacy_receiver, legacy_envelope.evidence).unwrap_err(),
        profile_refusal
    );
    assert!(old.verify(&receiver).is_err());
    assert!(crate::bft_network::local_envelope(
        Body::Signed(Box::new(Message::Timeout(Box::new(timeout)))),
        &receiver
    )
    .is_err());
    assert!(crate::bft_network::sync(&mut receiver, Evidence::default()).is_err());
    assert!(destination.bft_submit(pending.clone()).is_err());
    let onward_frame = intermediate.contact_export(export).unwrap();
    let (frame, carried) = crate::contact::Frame::unpack_onward(&onward_frame).unwrap();
    assert_eq!(frame.kind, "onward-source-finality");
    assert_eq!(carried, proof);
    assert!(crate::contact::Frame::unpack_origin(&onward_frame).is_err());
    assert!(receiver.contact_apply(b"{}", None).is_err());
    // A complete authentic empty C checkpoint independently passes ordinary
    // evidence validation. The old contact route must reject its new source
    // profile before looking for a value export or writing any event.
    let contact_evidence = Evidence {
        snapshots: vec![c1.clone()],
    };
    VerifiedEvidence::verify(&contact_evidence, &intermediate.trust).unwrap();
    let raw = crate::contact::Frame::pack(&crate::contact::Bundle {
        format: crate::contact::FORMAT.into(),
        currency: pin,
        source: c,
        destination: b,
        snapshot: c1_id,
        export,
        evidence: contact_evidence,
        incidents: vec![],
    })
    .unwrap();
    crate::contact::Frame::unpack(&raw).unwrap();
    assert_eq!(
        intermediate.contact_apply(&raw, None).unwrap_err(),
        "complete onward network requires separately integrated ordinary runtime"
    );
    assert!(crate::bft_client::Client::lock(
        &root.join("absent-caller/head"),
        &root.join("absent-signer"),
        public(2),
        crate::bft_client::FORMAT.into(),
        &receiver
    )
    .is_err());
    assert!(crate::bft_runtime_archive::Client::lock(
        &root.join("absent-runtime"),
        public(2),
        crate::bft_client::FORMAT.into(),
        &receiver
    )
    .is_err());
    assert!(
        !root.join("absent-caller").exists()
            && !root.join("absent-signer").exists()
            && !root.join("absent-runtime").exists()
    );
    assert_eq!(inventory(&root), before);
    phase(&started, "old-fallback-refusals-end");

    phase(&started, "actual-import-and-cold-begin");
    destination.finalize(import.clone()).unwrap();
    let imported = id("output", &(export, 0u32)).unwrap();
    assert_eq!(
        destination.chain.ledger.coins[&imported].payment,
        Payment {
            owner: public(12),
            amount: Amount(89)
        }
    );
    assert_eq!(destination.chain.ledger.coins[&imported].mature, 4);
    assert_eq!(
        destination.chain.ledger.coins[&imported].dependencies,
        BTreeSet::from([a80, b4])
    );
    assert_eq!(
        destination.chain.ledger.imports,
        BTreeMap::from([(export, b4)])
    );
    assert!(destination
        .complete_onward_network_pending_imports()
        .unwrap()
        .is_empty());
    destination.chain.ledger.audit().unwrap();
    let before = inventory(&root);
    assert_eq!(
        destination.bft_candidate(pending, public(10)).unwrap_err(),
        "permanent import tombstone rejects replay"
    );
    assert_eq!(inventory(&root), before);
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
    let pins = ColdPins {
        currency: pin,
        b,
        c,
        b_head: intermediate.storage_head().unwrap(),
        c_head: destination.storage_head().unwrap(),
        b_state: intermediate.chain.ledger.root().unwrap(),
        c_state: destination.chain.ledger.root().unwrap(),
        c_finality: c2,
        a80,
        b4,
        export,
        proof: id("onward-envelope-fixture-proof", &proof).unwrap(),
    };
    drop(destination);
    drop(intermediate);
    crate::keystore::private_create(
        &root.join("onward-envelope-cold.json"),
        &serde_json::to_vec(&pins).unwrap(),
    )
    .unwrap();
    let before = inventory(&root);
    let child=Process::new(std::env::current_exe().unwrap()).args([
        "--exact","storage::paged::onward_network_tests::complete_onward_network_authenticates_parent_body_and_conflicts",
        "--ignored","--nocapture","--test-threads=1",
    ]).env("RLD_ONWARD_ENVELOPE_COLD_CHILD",&root).output().unwrap();
    assert!(
        child.status.success(),
        "{}{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    assert_eq!(inventory(&root), before);
    phase(&started, "actual-import-and-cold-end");

    phase(&started, "genuine-ancestor-conflict-begin");
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
    let fork_payment = payment(
        h.region,
        pin,
        *input,
        10,
        15,
        coin.payment.amount.checked_sub(Amount(1)).unwrap(),
        None,
    );
    let alternate = certified_with_commands(&fork, vec![fork_payment]);
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
    let mut incident_receiver = make_c("incident-receiver");
    incident_receiver
        .accept_complete_onward_network_history(proof.clone())
        .unwrap();
    let mut conflict = valid.clone();
    let history = &mut conflict.history.as_mut().unwrap().history;
    history.origin.snapshots[79] = alternate;
    let mut invalid_later = b5;
    invalid_later.bft.as_mut().unwrap().committed.votes[0]
        .approval
        .signature = "00".repeat(64);
    history.snapshots.push(invalid_later);
    let mut forged = conflict.clone();
    forged.history.as_mut().unwrap().history.origin.snapshots[79]
        .bft
        .as_mut()
        .unwrap()
        .committed
        .votes[0]
        .approval
        .signature = "00".repeat(64);
    refusal(
        &root,
        &mut incident_receiver,
        "forged-conflict-plus-invalid-tail",
        forged,
    );
    // The same authentic ancestor incident also closes an already-empty task query.
    let mut imported_receiver = make_c("imported-incident-receiver");
    imported_receiver.finalize(c1.clone()).unwrap();
    imported_receiver
        .accept_complete_onward_network_history(proof.clone())
        .unwrap();
    imported_receiver.finalize(import).unwrap();
    assert!(imported_receiver
        .complete_onward_network_pending_imports()
        .unwrap()
        .is_empty());
    let imported_state = imported_receiver.chain.ledger.clone();
    let error = net::inspect(&mut imported_receiver, conflict.clone()).unwrap_err();
    assert!(error.contains("conflict retained"), "{error}");
    assert_eq!(imported_receiver.chain.ledger, imported_state);
    let before = inventory(&root);
    assert!(imported_receiver
        .complete_onward_network_pending_imports()
        .is_err());
    assert_eq!(inventory(&root), before);
    let state = incident_receiver.chain.ledger.clone();
    let error = net::inspect(&mut incident_receiver, conflict).unwrap_err();
    assert!(error.contains("conflict retained"), "{error}");
    assert_eq!(incident_receiver.journal.incident_ids.len(), 1);
    assert!(incident_receiver.safety.check_region(h.region).is_err());
    assert_eq!(incident_receiver.chain.height(), 0);
    assert_eq!(incident_receiver.chain.ledger, state);
    let before = inventory(&root);
    assert!(net::inspect(&mut incident_receiver, valid).is_err());
    assert!(incident_receiver
        .accept_complete_onward_network_history(proof)
        .is_err());
    assert!(incident_receiver
        .complete_onward_network_pending_imports()
        .is_err());
    assert_eq!(inventory(&root), before);
    phase(&started, "genuine-ancestor-conflict-end");
    println!(
        "onward_envelope_result={}",
        serde_json::json!({
            "fixture_root":root,"source_height":80,"intermediate_height":5,"selected_export_height":4,
            "recipient_height":2,"uninitialized_inspection_receiver_height":receiver.chain.height(),
            "verified_distinct_bodies":identities.len(),"maximum_wire_bytes":max_wire,"maximum_expanded_bytes":max_expanded,
            "origin_anchor":a80,"intermediate_anchor":b4,"recipient_checkpoint":c2,"totals":totals,
            "cold_child_success":true,"actual_mature_payment_tested":false,
            "ordinary_network_qualified":false,"independent_custody_qualified":false,"mainnet_qualified":false,
            "elapsed_seconds":started.elapsed().as_secs_f64()
        })
    );
}
