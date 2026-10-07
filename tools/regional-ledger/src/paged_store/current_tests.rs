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
