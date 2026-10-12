//! Fresh signed no-value Native profiles; fixture quorum keys are public inputs.
use super::body_witness_tests::{certified, certified_with_commands};
use super::continuation_tests::inventory;
use super::*;
use crate::tests::{public, signature};

fn header() -> Header {
    let mut header = super::body_witness_tests::header();
    header.format = PACKED_FORMAT.into();
    let admission = &mut header.bootstrap.admissions[0];
    admission.rules = crate::paged_bft::PACKED_RULES.into();
    admission.value_rules = Some(crate::paged_bft::rules_hash_for(&admission.rules).unwrap());
    admission.signature = signature(1, &admission.bytes().unwrap());
    header.region = admission.id().unwrap();
    header
}
fn fresh() -> (PathBuf, Store) {
    let root = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "rld-native-packed-{}",
            crate::contact_runtime::random().unwrap()
        ));
    private_root(&root).unwrap();
    eprintln!("Fresh Native packed fixture: {}", root.display());
    let header = header();
    let pin = header.bootstrap.currency.id().unwrap();
    let node = Store::create(
        &root.join("node"),
        header.bootstrap,
        header.region,
        &public(1),
        pin,
    )
    .unwrap();
    (root, node)
}
fn next(node: &Store, commands: Vec<Command>) -> Snapshot {
    certified_with_commands(&node.paged_replay.as_ref().unwrap().replay, commands)
}
fn signed_payment(
    root: &Path,
    node: &Store,
    owner: u8,
    recipient: u8,
    amount: Amount,
    input: Option<Hash>,
) -> (Vec<Command>, crate::wallet_agent::Agent, Hash) {
    let key = root.join(format!("public-fixture-owner-{owner}.json"));
    crate::keystore::private_create(
        &key,
        &serde_json::to_vec(&serde_json::json!({"secret_key":hex::encode([owner;32])})).unwrap(),
    )
    .unwrap();
    let mut agent = crate::wallet_agent::Agent::create(
        &root.join(format!("owner-{owner}")),
        node,
        public(owner),
    )
    .unwrap();
    let head = agent.journal.head().unwrap();
    let prepared = agent
        .prepare(
            node,
            crate::wallet::Request {
                owner: public(owner),
                participants: vec![],
                inputs: input.map(|id| vec![id]),
                outputs: vec![Payment {
                    owner: public(recipient),
                    amount,
                }],
                remote: None,
                fee: Amount(1),
                valid_for_blocks: 8,
                valid_through: None,
            },
            head,
        )
        .unwrap();
    let signed = agent
        .sign(node, prepared.draft, &key, prepared.review_commitment, head)
        .unwrap();
    (signed.commands, agent, signed.wallet_head)
}

#[test]
fn signed_packed_store_crosses_pack_boundary_with_two_actual_owner_payments_and_full_cold_replay() {
    let started = std::time::Instant::now();
    let (root, mut node) = fresh();
    let mut owners = Vec::new();
    for height in 1..=1025 {
        assert!(
            started.elapsed().as_secs() < 300,
            "Native packed component deadline exhausted"
        );
        let commands = if height == 4 {
            let (commands, agent, head) = signed_payment(&root, &node, 10, 11, Amount(99), None);
            owners.push((agent, head));
            commands
        } else if height == 8 {
            let input = *node
                .chain
                .ledger
                .coins
                .iter()
                .find(|(_, coin)| {
                    coin.payment.owner == public(11)
                        && coin.payment.amount == Amount(99)
                        && coin.mature <= node.chain.height()
                })
                .unwrap()
                .0;
            let (commands, agent, head) =
                signed_payment(&root, &node, 11, 14, Amount(98), Some(input));
            owners.push((agent, head));
            commands
        } else {
            vec![]
        };
        let snapshot = next(&node, commands);
        node.finalize(snapshot).unwrap();
        assert_eq!(node.chain.height(), height);
        assert!(node.evidence.snapshots.len() <= MAX_SNAPSHOTS);
        if height.is_multiple_of(64) {
            eprintln!(
                "Native packed height={height} elapsed={:.3}",
                started.elapsed().as_secs_f64()
            );
        }
    }
    assert_eq!(node.history_layout().unwrap().0, PACKED_FORMAT);
    assert!(
        fs::read_dir(root.join("node/ledger-events/packs"))
            .unwrap()
            .count()
            > 0
    );
    assert_eq!(
        node.chain.ledger.minted,
        Amount(rld_pow::cumulative_emission(1025))
    );
    assert!(node
        .chain
        .ledger
        .coins
        .values()
        .any(|c| c.payment.owner == public(14)
            && c.payment.amount == Amount(98)
            && c.mature <= node.chain.height()));
    for (owner, head) in &owners {
        assert_eq!(owner.journal.head().unwrap(), *head);
    }
    let head = node.storage_head().unwrap();
    let ledger = node.chain.ledger.clone();
    let region = node.chain.region;
    let pin = node.pin;
    let before = inventory(&root);
    drop(node);
    let cold = Store::open_pinned(&root.join("node"), &public(1), pin, head).unwrap();
    assert_eq!(cold.chain.height(), 1025);
    assert_eq!(cold.chain.ledger, ledger);
    assert_eq!(cold.chain.region, region);
    assert_eq!(cold.blocks().unwrap().count(), 1025);
    assert_eq!(cold.storage_head().unwrap(), head);
    assert_eq!(inventory(&root), before);
    assert!(
        started.elapsed().as_secs() < 300,
        "Native packed cold closure exceeded original component deadline"
    );
    drop(cold);
    drop(owners);
    // Retain the complete source-bound scope on both success and failure.
}

#[test]
fn packed_native_replay_rejects_hash_consistent_forged_certificate_and_wrong_signed_dialect() {
    let (root, node) = fresh();
    let h = read_header(&root.join("node")).unwrap();
    let mut bad = certified(&node.paged_replay.as_ref().unwrap().replay);
    bad.bft.as_mut().unwrap().committed.votes[0]
        .approval
        .signature = "00".repeat(64);
    let scope = h.scope(&node.trust).unwrap();
    let pin = node.pin;
    drop(node);
    let target = root.join("bad");
    private_root(&target).unwrap();
    crate::keystore::private_create(&target.join("LOCK"), b"").unwrap();
    private_root(&target.join("incidents")).unwrap();
    crate::keystore::private_create(&target.join("INCIDENT_GUARD"), &Hash::ZERO.0).unwrap();
    crate::keystore::private_create(&target.join(HEADER), &serde_json::to_vec(&h).unwrap())
        .unwrap();
    let mut stream = EventStream::create(&target.join(EVENTS), scope, true).unwrap();
    let old = stream.storage_head();
    stream
        .append_accounted(&[Record::Certified(Box::new(bad))], old, 3, 0)
        .unwrap();
    let head = stream.storage_head();
    stream.visit(head, |_| Ok(())).unwrap();
    drop(stream);
    let before = inventory(&root);
    assert!(Store::open_pinned(&target, &public(1), pin, head).is_err());
    assert_eq!(inventory(&root), before);
    let mut changed = h.clone();
    changed.format = FORMAT.into();
    assert!(changed
        .scope(&Trust::verify(&h.bootstrap, &public(1), pin).unwrap())
        .is_err());
    let mut admission = h.bootstrap.admissions[0].clone();
    admission.value_rules = Some(crate::paged_bft::rules_hash().unwrap());
    admission.signature = signature(1, &admission.bytes().unwrap());
    assert!(admission.verify(&h.bootstrap.currency).is_err());
}

#[test]
fn packed_native_interruption_preserves_previous_executed_state_and_refuses_reuse() {
    for boundary in 0..3 {
        let (root, mut node) = fresh();
        let first = next(&node, vec![]);
        node.finalize(first).unwrap();
        let head = node.storage_head().unwrap();
        let ledger = node.chain.ledger.clone();
        let candidate = next(&node, vec![]);
        node.paged.as_mut().unwrap().interrupt_at(boundary);
        assert!(node.finalize(candidate).is_err());
        assert!(!node.healthy);
        assert_eq!(node.chain.height(), 1);
        assert_eq!(node.chain.ledger, ledger);
        assert_eq!(node.paged_replay.as_ref().unwrap().head, head);
        assert!(root.join("node/ledger-events/live.next").exists());
        let before = inventory(&root);
        assert!(node.storage_head().is_err());
        assert_eq!(inventory(&root), before);
        // Keep all failed stores stopped; no reopen or recovery qualification.
    }
}
