//! Fresh no-value public-fixture current-process guards; no old failed inputs.
use super::body_witness_tests::{certified, header, replay, stream};
use super::continuation_tests::inventory;
use super::*;
use crate::tests::public;

fn fresh() -> (PathBuf, Store) {
    let h = header();
    let r = replay(&h);
    let (root, flat) = stream(&h, &r);
    drop(flat);
    let node = Store::create(
        &root.join("node"),
        h.bootstrap.clone(),
        h.region,
        &public(1),
        h.bootstrap.currency.id().unwrap(),
    )
    .unwrap();
    (root, node)
}
fn next(node: &Store) -> Snapshot {
    certified(&node.paged_replay.as_ref().unwrap().replay)
}
#[test]
fn actual_process_projection_mutations_refuse_before_disk_and_valid_append_remains_native() {
    let (root, mut node) = fresh();
    node.finalize(next(&node)).unwrap();
    let next = next(&node);
    let chain = node.chain.clone();
    let evidence = node.evidence.clone();
    let journal = node.journal.clone();
    let trust = node.trust.clone();
    let before = inventory(&root);
    for choice in 0..5 {
        match choice {
            0 => node.chain.ledger.minted = Amount(1),
            1 => node.chain.epoch = Hash([9; 32]),
            2 => {
                node.journal.incident_ids.insert(Hash([9; 32]));
            }
            3 => node.evidence = VerifiedEvidence::default(),
            _ => node.trust.binding = Hash([9; 32]),
        }
        assert!(node
            .append_paged(&[Record::Certified(Box::new(next.clone()))])
            .is_err());
        assert_eq!(inventory(&root), before);
        node.chain = chain.clone();
        node.evidence = evidence.clone();
        node.journal = journal.clone();
        node.trust = trust.clone();
    }
    node.finalize(next).unwrap();
    assert_eq!(node.chain.height(), 2);
    node.chain.ledger.audit().unwrap();
    let current = node.paged_replay.as_ref().unwrap();
    current
        .replay
        .executed
        .require_boundary(
            &current.header.scope(&current.replay.trust).unwrap(),
            2,
            node.storage_head().unwrap(),
        )
        .unwrap();
    let head = node.storage_head().unwrap();
    let state = node.chain.ledger.clone();
    let pin = node.pin;
    drop(node);
    let node = Store::open_pinned(&root.join("node"), &public(1), pin, head).unwrap();
    assert_eq!(node.chain.ledger, state);
    node.paged_replay
        .as_ref()
        .unwrap()
        .stage(
            &node,
            &read_header(&root.join("node")).unwrap(),
            node.paged.as_ref().unwrap(),
        )
        .unwrap();
}
#[test]
fn actual_process_header_mutation_refuses_without_record_publication() {
    let (root, mut node) = fresh();
    node.finalize(next(&node)).unwrap();
    let next = next(&node);
    let mut h = read_header(&root.join("node")).unwrap();
    h.region = Hash([9; 32]);
    fs::write(
        root.join("node").join(HEADER),
        serde_json::to_vec(&h).unwrap(),
    )
    .unwrap();
    let before = inventory(&root);
    assert!(node
        .append_paged(&[Record::Certified(Box::new(next))])
        .is_err());
    assert_eq!(inventory(&root), before);
    assert_eq!(node.chain.height(), 1);
}
#[test]
fn all_original_durable_interruptions_keep_committed_process_state_and_poison_handle() {
    for interrupt in 0..3 {
        let (root, mut node) = fresh();
        node.finalize(next(&node)).unwrap();
        let current_head = node.storage_head().unwrap();
        let state = node.chain.ledger.clone();
        let next = next(&node);
        node.paged.as_mut().unwrap().interrupt_at(interrupt);
        assert!(node
            .append_paged(&[Record::Certified(Box::new(next.clone()))])
            .is_err());
        assert!(!node.healthy);
        assert_eq!(node.chain.ledger, state);
        assert_eq!(node.chain.height(), 1);
        let current = node.paged_replay.as_ref().unwrap();
        assert_eq!(current.head, current_head);
        current
            .replay
            .executed
            .require_boundary(
                &current.header.scope(&current.replay.trust).unwrap(),
                1,
                current_head,
            )
            .unwrap();
        let before = inventory(&root);
        assert!(node
            .append_paged(&[Record::Certified(Box::new(next))])
            .is_err());
        assert_eq!(inventory(&root), before);
        // Retain the fresh failed target; no reopen, repair or fixture recovery.
    }
}

fn fresh_regional_contact() -> (PathBuf, Store, Store, Vec<u8>) {
    let mut h = header();
    let mut admission = h.bootstrap.admissions[0].clone();
    admission.region = "proxima".into();
    admission.signature = crate::tests::signature(1, &admission.bytes().unwrap());
    let destination_region = admission.id().unwrap();
    h.bootstrap.admissions.push(admission);
    let r = replay(&h);
    let (root, flat) = stream(&h, &r);
    drop(flat);
    let pin = h.bootstrap.currency.id().unwrap();
    let mut source = Store::create(
        &root.join("source"),
        h.bootstrap.clone(),
        h.region,
        &public(1),
        pin,
    )
    .unwrap();
    let destination = Store::create(
        &root.join("destination"),
        h.bootstrap.clone(),
        destination_region,
        &public(1),
        pin,
    )
    .unwrap();
    for _ in 0..2 {
        source.finalize(next(&source)).unwrap();
    }
    let input = source
        .chain
        .ledger
        .coins
        .iter()
        .find(|(_, coin)| coin.mature == 3)
        .unwrap();
    let intent = Intent {
        currency: pin,
        region: h.region,
        inputs: vec![*input.0],
        outputs: vec![Payment {
            owner: public(10),
            amount: input.1.payment.amount.checked_sub(Amount(10)).unwrap(),
        }],
        fee: Amount(1),
        destination: Some(destination_region),
        remote: Some(Payment {
            owner: public(20),
            amount: Amount(9),
        }),
        destination_fee: Amount(2),
        valid_through: 24,
    };
    let export = intent.id().unwrap();
    let signed = SignedIntent {
        approvals: vec![Approval {
            key: public(10),
            signature: crate::tests::signature(10, &intent.bytes().unwrap()),
        }],
        intent,
    };
    let snapshot = super::body_witness_tests::certified_with_commands(
        &source.paged_replay.as_ref().unwrap().replay,
        vec![Command::Spend(Box::new(signed))],
    );
    source.finalize(snapshot).unwrap();
    let raw = source.contact_export(export).unwrap();
    (root, source, destination, raw)
}
#[test]
fn ordinary_current_contact_standalone_proof_pending_import_mature_payment_cold() {
    let (root, source, mut destination, raw) = fresh_regional_contact();
    let (_, bundle) = crate::contact::Frame::unpack(&raw).unwrap();
    let before = inventory(&root);
    for choice in 0..3 {
        let mut bad = bundle.clone();
        match choice {
            0 => {
                bad.evidence.snapshots.remove(0);
            }
            1 => bad
                .evidence
                .snapshots
                .last_mut()
                .unwrap()
                .blocks
                .last_mut()
                .unwrap()
                .commands
                .clear(),
            _ => {
                bad.evidence
                    .snapshots
                    .last_mut()
                    .unwrap()
                    .bft
                    .as_mut()
                    .unwrap()
                    .committed
                    .votes[0]
                    .approval
                    .signature = "00".repeat(64)
            }
        }
        assert!(destination
            .contact_apply(&crate::contact::Frame::pack(&bad).unwrap(), None)
            .is_err());
        assert_eq!(inventory(&root), before);
    }
    let status = destination.contact_apply(&raw, None).unwrap();
    assert!(status.evidence_verified && !status.import_accepted);
    assert_eq!(destination.chain.height(), 0);
    assert!(destination.chain.ledger.coins.is_empty());
    let head = destination.storage_head().unwrap();
    let before = inventory(&root);
    destination.contact_apply(&raw, None).unwrap();
    assert_eq!(destination.storage_head().unwrap(), head);
    assert_eq!(inventory(&root), before);
    let certified_import = super::body_witness_tests::certified_with_commands(
        &destination.paged_replay.as_ref().unwrap().replay,
        vec![Command::Import {
            snapshot: bundle.snapshot,
            export: bundle.export,
        }],
    );
    destination.finalize(certified_import).unwrap();
    let status = destination.contact_status(status.message_id).unwrap();
    assert!(status.import_accepted && !status.original_recipient_output_spendable_now);
    assert_eq!(status.recipient_mature_height, Some(3));
    let before = inventory(&root);
    destination.contact_apply(&raw, None).unwrap();
    assert_eq!(inventory(&root), before);
    let recipient = id("output", &(bundle.export, 0u32)).unwrap();
    assert_eq!(
        destination.chain.ledger.coins[&recipient].payment.amount,
        Amount(7)
    );
    let intent = Intent {
        currency: destination.pin,
        region: destination.chain.region,
        inputs: vec![recipient],
        outputs: vec![Payment {
            owner: public(21),
            amount: Amount(6),
        }],
        fee: Amount(1),
        destination: None,
        remote: None,
        destination_fee: Amount::ZERO,
        valid_through: 24,
    };
    let signed = SignedIntent {
        approvals: vec![Approval {
            key: public(20),
            signature: crate::tests::signature(20, &intent.bytes().unwrap()),
        }],
        intent,
    };
    assert!(destination
        .bft_candidate(vec![Command::Spend(Box::new(signed.clone()))], public(10))
        .is_err());
    destination.finalize(next(&destination)).unwrap();
    let payment = super::body_witness_tests::certified_with_commands(
        &destination.paged_replay.as_ref().unwrap().replay,
        vec![Command::Spend(Box::new(signed))],
    );
    destination.finalize(payment).unwrap();
    let status = destination.contact_status(status.message_id).unwrap();
    assert_eq!(status.local_height, 3);
    assert_eq!(status.original_recipient_output_remaining, Amount::ZERO);
    assert!(destination
        .chain
        .ledger
        .imports
        .contains_key(&bundle.export));
    assert_eq!(
        conservation(&[source.chain.clone(), destination.chain.clone()])
            .unwrap()
            .2,
        Amount::ZERO
    );
    let head = destination.storage_head().unwrap();
    let ledger = destination.chain.ledger.clone();
    let pin = destination.pin;
    drop(destination);
    let mut destination =
        Store::open_pinned(&root.join("destination"), &public(1), pin, head).unwrap();
    assert_eq!(destination.chain.ledger, ledger);
    let before = inventory(&root);
    destination.contact_apply(&raw, None).unwrap();
    assert_eq!(inventory(&root), before);
    println!("ordinary-current-contact actual_full_wire=true retry_no_write=true certified_import=true maturity2=true owner7_to6_fee1=true full_cold_import_tombstone=true global_conservation=true");
}
#[test]
fn ordinary_current_contact_exact_retry_refuses_pending_guard_and_safety_projection() {
    let (root, _source, mut destination, raw) = fresh_regional_contact();
    let status = destination.contact_apply(&raw, None).unwrap();
    let before = inventory(&root);
    destination
        .safety
        .regions
        .insert(destination.chain.region, BTreeSet::from([Hash([9; 32])]));
    assert!(destination.contact_apply(&raw, None).is_err());
    assert_eq!(inventory(&root), before);
    destination.safety = Safety::default();
    assert!(
        !destination
            .contact_status(status.message_id)
            .unwrap()
            .import_accepted
    );
    write_guard(&root.join("destination"), Hash([9; 32])).unwrap();
    let before = inventory(&root);
    assert!(destination.contact_apply(&raw, None).is_err());
    assert_eq!(inventory(&root), before);
    assert_eq!(destination.chain.height(), 0);
    // Retain the new pending target and guard unchanged; no reopen or recovery.
}

thread_local! {
    static EXECUTED_RECORDS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}
pub(super) fn note_actual_record_execution() {
    EXECUTED_RECORDS.with(|count| count.set(count.get() + 1));
}
fn take_actual_record_executions() -> u64 {
    EXECUTED_RECORDS.with(|count| count.replace(0))
}
#[test]
fn receipt_read_and_ordinary_candidate_actual_native_history_execution_boundary() {
    let (root, mut node) = fresh();
    for _ in 0..4 {
        node.finalize(next(&node)).unwrap();
    }
    let before = inventory(&root);
    take_actual_record_executions();
    let receipts = node.paged_receipt_history().unwrap();
    let receipt_records = take_actual_record_executions();
    assert_eq!(receipt_records, 0);
    assert_eq!(receipts.len(), 0);
    let candidate = node.bft_candidate(vec![], public(10)).unwrap();
    let candidate_records = take_actual_record_executions();
    assert_eq!(candidate_records, 0);
    assert_eq!(candidate.statement.height, 5);
    assert_eq!(node.chain.height(), 4);
    assert_eq!(inventory(&root), before);
    println!("actual-original-receipt-read Native_records={receipt_records} actual-ordinary-candidate Native_records={candidate_records} no_state_or_bytes_changed=true");
}

#[test]
fn current_receipt_and_candidate_refuse_public_projection_and_pending_incident() {
    let (root, mut node) = fresh();
    node.finalize(next(&node)).unwrap();
    let chain = node.chain.clone();
    let safety = node.safety.clone();
    let before = inventory(&root);
    node.chain.ledger.minted = Amount(1);
    assert!(node.paged_receipt_history().is_err());
    assert!(node.bft_candidate(vec![], public(10)).is_err());
    assert_eq!(inventory(&root), before);
    node.chain = chain;
    node.safety
        .regions
        .insert(node.chain.region, BTreeSet::from([Hash([9; 32])]));
    assert!(node.paged_receipt_history().is_err());
    assert!(node.bft_candidate(vec![], public(10)).is_err());
    assert_eq!(inventory(&root), before);
    node.safety = safety;
    write_guard(&root.join("node"), Hash([9; 32])).unwrap();
    let before = inventory(&root);
    assert!(node.paged_receipt_history().is_err());
    assert!(node.bft_candidate(vec![], public(10)).is_err());
    assert_eq!(inventory(&root), before);
    // Keep the fresh pending target unchanged; no reopening or clearing guard.
}
#[test]
fn current_receipt_and_candidate_refuse_changed_complete_page_bytes() {
    let (root, mut node) = fresh();
    for _ in 0..16 {
        node.finalize(next(&node)).unwrap();
    }
    // Select an actual committed complete page, not a fabricated cache identity.
    let files = inventory(&root);
    let page = files
        .keys()
        .find(|path| {
            path.parent()
                .is_some_and(|p| p.file_name() == Some(std::ffi::OsStr::new("pages")))
        })
        .expect("actual Native page");
    let path = page;
    let mut bytes = fs::read(path).unwrap();
    bytes[0] ^= 1;
    fs::write(path, bytes).unwrap();
    let before = inventory(&root);
    assert!(node.paged_receipt_history().is_err());
    assert!(node.bft_candidate(vec![], public(10)).is_err());
    assert_eq!(inventory(&root), before);
    assert_eq!(node.chain.height(), 16);
    // Retain this new deliberately corrupt target; no reopening or byte repair.
}
