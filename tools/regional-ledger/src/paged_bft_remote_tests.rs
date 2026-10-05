use super::paged_integration::{certify, retain};
use super::retained_native_replay::inventory;
use super::*;
fn target(source: &Harness, package: Bootstrap, region: Hash) -> Harness {
    let root = source.root.join("destination");
    fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let currency = package.currency.id().unwrap();
    let node = Store::create(&root.join("node"), package, region, &public(1), currency).unwrap();
    let seeds = keys();
    let mut agents = vec![];
    for seed in &seeds {
        crate::keystore::private_create(
            &root.join(format!("key-{seed}.json")),
            &serde_json::to_vec(&serde_json::json!({"secret_key":hex::encode([*seed;32])}))
                .unwrap(),
        )
        .unwrap();
        agents.push(
            Agent::create(&root.join(format!("signer-{seed}")), &node, public(*seed)).unwrap(),
        );
    }
    let heads = agents.iter().map(|a| a.head().unwrap()).collect();
    let h = Harness {
        root,
        node,
        agents,
        heads,
        seeds,
        retain: true,
    };
    for n in 0..4 {
        retain(&h.root, n, h.heads[n]);
    }
    h
}
fn emit_refusal(
    phase: &str,
    reason: &str,
    source: &Harness,
    export_included: bool,
    unchanged: bool,
) {
    println!(
        "paged-remote-refusal {}",
        serde_json::json!({"phase":phase,"reason":reason,"source_height":source.node.chain.height(),"active_snapshots":source.node.evidence.snapshots.len(),"signer_records":source.agents.iter().map(Agent::record_count).collect::<Vec<_>>(),"source_export_already_included":export_included,"native_and_private_inventory_unchanged_by_refusal":unchanged,"refund_or_resign_or_recovery":false,"remote_import_or_maturity_qualified":false})
    );
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContactManifest {
    format: String,
    scope: crate::retained_pages::Scope,
    pages: Vec<crate::history::Reference>,
    tail: Vec<crate::storage::PagedRecord>,
    count: u64,
    head: Hash,
}
fn corrupted_contact_copy_refuses(h: &Harness, pin: Hash) {
    let copied = h.root.join("bad-native-contact-copy");
    super::paged_recovery::copy_private(&h.root.join("node"), &copied);
    let path = copied.join("ledger-events/stream.json");
    let mut manifest: ContactManifest = crate::storage::read_json(&path).unwrap();
    assert!(manifest.pages.is_empty());
    let crate::storage::PagedRecord::Contact(frame) = &mut manifest.tail[0] else {
        panic!("first exact retained contact frame");
    };
    let (_, mut bundle) = crate::contact::Frame::unpack(&frame.retained_bytes().unwrap()).unwrap();
    bundle
        .evidence
        .snapshots
        .last_mut()
        .unwrap()
        .bft
        .as_mut()
        .unwrap()
        .committed
        .votes[0]
        .approval
        .signature = "00".repeat(64);
    let raw = crate::contact::Frame::pack(&bundle).unwrap();
    **frame = crate::contact::Frame::unpack(&raw).unwrap().0;
    let mut head = manifest.scope.initial().unwrap();
    for (index, record) in manifest.tail.iter().enumerate() {
        head = crate::retained_pages::next_head(head, index as u64, record).unwrap();
    }
    manifest.head = head;
    fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let before = inventory(&h.root);
    let reason = Store::open_pinned(&copied, &public(1), pin, head)
        .err()
        .expect("hash-consistent contact corruption cannot authorize cold state");
    assert!(
        reason.contains("signature"),
        "actual native rejection: {reason}"
    );
    assert_eq!(inventory(&h.root), before);
    println!("paged-contact hash_consistent_cold_bad_signature_refused=true copied_keys=false unchanged=true");
}
#[test]
fn paged_source_export_after65_requires_complete_remote_contact_and_recipient_maturity() {
    remote_cycle(65, true);
}
#[test]
fn paged_short_contact_requires_native_record_import_maturity_and_cold() {
    remote_cycle(3, false);
}
fn remote_cycle(prefix_height: u64, expect_dependency_bound: bool) {
    let started = std::time::Instant::now();
    let mut source = Harness::with_rules(crate::paged_bft::RULES);
    source.retain = true;
    let package = source.node.journal.bootstrap.clone();
    let destination = package.admissions[1].id().unwrap();
    for n in 0..4 {
        retain(&source.root, n, source.heads[n]);
    }
    for height in 1..=prefix_height {
        let snapshot = certify(&mut source, vec![]);
        source.node.finalize(snapshot).unwrap();
        if height % 16 == 0 || height == 65 {
            println!(
                "paged-remote complete_source_height={height} active={} elapsed={:.3}",
                source.node.evidence.snapshots.len(),
                started.elapsed().as_secs_f64()
            );
        }
    }
    assert_eq!(
        source.node.evidence.snapshots.len(),
        prefix_height.min(64) as usize
    );
    let mut owner = crate::wallet_agent::Agent::create(
        &source.root.join("export-owner"),
        &source.node,
        public(10),
    )
    .unwrap();
    let old = owner.journal.head().unwrap();
    retain(&source.root, 4, old);
    crate::keystore::private_create(
        &source.root.join("owner-key.json"),
        &serde_json::to_vec(&serde_json::json!({"secret_key":hex::encode([10;32])})).unwrap(),
    )
    .unwrap();
    let prepared = owner
        .prepare(
            &source.node,
            crate::wallet::Request {
                owner: public(10),
                participants: vec![],
                inputs: None,
                outputs: vec![],
                remote: Some(crate::wallet::Remote {
                    destination,
                    recipient: Payment {
                        owner: public(11),
                        amount: Amount(100),
                    },
                    destination_fee: Amount(1),
                }),
                fee: Amount(1),
                valid_for_blocks: 8,
                valid_through: None,
            },
            old,
        )
        .unwrap();
    let signed = owner
        .sign(
            &source.node,
            prepared.draft,
            &source.root.join("owner-key.json"),
            prepared.review_commitment,
            old,
        )
        .unwrap();
    let wallet_head = signed.wallet_head;
    retain(&source.root, 4, wallet_head);
    let export = signed
        .commands
        .iter()
        .find_map(|c| {
            if let Command::Spend(s) = c {
                s.intent.destination.map(|_| s.intent.id().unwrap())
            } else {
                None
            }
        })
        .unwrap();
    let snapshot = certify(&mut source, signed.commands);
    source.node.finalize(snapshot).unwrap();
    assert_eq!(source.node.chain.height(), prefix_height + 1);
    assert!(source.node.chain.ledger.exports.contains_key(&export));
    owner.view(&source.node, wallet_head).unwrap();
    let before = inventory(&source.root);
    let native = source.node.storage_head().unwrap();
    let ledger = source.node.chain.ledger.clone();
    let raw = match source.node.contact_export(export) {
        Ok(raw) => raw,
        Err(reason) => {
            let unchanged = inventory(&source.root) == before
                && source.node.storage_head().unwrap() == native
                && source.node.chain.ledger == ledger;
            assert!(unchanged);
            emit_refusal("native-contact-export", &reason, &source, true, unchanged);
            if expect_dependency_bound {
                assert_eq!(reason, "contact dependency bound");
                return;
            }
            panic!("post-boundary remote contact capability refused: {reason}");
        }
    };
    assert!(
        !expect_dependency_bound,
        "dependency-bound regression changed; requalify complete remote authority"
    );
    let (_, bundle) = crate::contact::Frame::unpack(&raw).unwrap();
    assert_eq!(bundle.export, export);
    let mut target = target(&source, package, destination);
    let before = inventory(&target.root);
    let status = match target.node.contact_apply(&raw, None) {
        Ok(status) => status,
        Err(reason) => {
            let unchanged = inventory(&target.root) == before;
            emit_refusal(
                "destination-native-contact-accept",
                &reason,
                &source,
                true,
                unchanged,
            );
            panic!("destination contact capability refused: {reason}");
        }
    };
    assert!(status.evidence_verified && !status.import_accepted);
    let before = inventory(&target.root);
    let head = target.node.storage_head().unwrap();
    let ledger = target.node.chain.ledger.clone();
    let retry = target.node.contact_apply(&raw, None).unwrap();
    assert!(retry.evidence_verified && !retry.import_accepted);
    assert_eq!(target.node.storage_head().unwrap(), head);
    assert_eq!(inventory(&target.root), before);
    let mut bad = bundle.clone();
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
        .signature = "00".repeat(64);
    let bad = crate::contact::Frame::pack(&bad).unwrap();
    assert!(target.node.contact_apply(&bad, None).is_err());
    let mut missing = bundle.clone();
    missing.evidence.snapshots.remove(0);
    let missing = crate::contact::Frame::pack(&missing).unwrap();
    assert!(target.node.contact_apply(&missing, None).is_err());
    let mut wrong = bundle.clone();
    wrong.destination = target.node.journal.bootstrap.admissions[2].id().unwrap();
    let wrong = crate::contact::Frame::pack(&wrong).unwrap();
    assert!(target.node.contact_apply(&wrong, None).is_err());
    assert_eq!(target.node.storage_head().unwrap(), head);
    assert_eq!(target.node.chain.ledger, ledger);
    assert_eq!(inventory(&target.root), before);
    println!("paged-contact exact_retry_no_append=true later_bad_envelope_missing_prefix_wrong_route_refused=true pending_has_no_credit=true unchanged=true");
    let snapshot = certify(
        &mut target,
        vec![Command::Import {
            snapshot: bundle.snapshot,
            export,
        }],
    );
    target.node.finalize(snapshot).unwrap();
    let expectation = crate::wallet::ReceiptExpectation {
        currency: source.node.trust.currency().unwrap(),
        source: source.node.chain.region,
        destination,
        export,
        recipient: public(11),
        net_amount: Amount(99),
    };
    assert!(
        !crate::wallet::receipt(&target.node, expectation.clone())
            .unwrap()
            .original_output_spendable_now
    );
    assert!(
        !target
            .node
            .contact_status(status.message_id)
            .unwrap()
            .original_recipient_output_spendable_now
    );
    for _ in 0..target.node.trust.currency.maturity {
        let snapshot = certify(&mut target, vec![]);
        target.node.finalize(snapshot).unwrap();
    }
    assert!(
        crate::wallet::receipt(&target.node, expectation.clone())
            .unwrap()
            .original_output_spendable_now
    );
    assert!(
        target
            .node
            .contact_status(status.message_id)
            .unwrap()
            .original_recipient_output_spendable_now
    );
    corrupted_contact_copy_refuses(&target, source.node.trust.currency().unwrap());
    let source_root = source.root.clone();
    let target_root = target.root.clone();
    let pin = source.node.trust.currency().unwrap();
    let source_head = source.node.storage_head().unwrap();
    let target_head = target.node.storage_head().unwrap();
    let source_heads = source.heads.clone();
    let target_heads = target.heads.clone();
    let seeds = source.seeds.clone();
    drop(owner);
    drop(source);
    drop(target);
    let before = inventory(&source_root);
    let source =
        Store::open_pinned(&source_root.join("node"), &public(1), pin, source_head).unwrap();
    let target =
        Store::open_pinned(&target_root.join("node"), &public(1), pin, target_head).unwrap();
    for (root, node, heads) in [
        (&source_root, &source, &source_heads),
        (&target_root, &target, &target_heads),
    ] {
        for (n, seed) in seeds.iter().enumerate() {
            let agent = Agent::open(&root.join(format!("signer-{seed}")), node).unwrap();
            assert_eq!(agent.head().unwrap(), heads[n]);
            assert_eq!(
                fs::read(root.join(format!("caller-{n}.head"))).unwrap(),
                heads[n].0
            );
        }
    }
    let owner =
        crate::wallet_agent::Agent::open(&source_root.join("export-owner"), &source).unwrap();
    owner.view(&source, wallet_head).unwrap();
    assert_eq!(
        fs::read(source_root.join("caller-4.head")).unwrap(),
        wallet_head.0
    );
    assert!(
        crate::wallet::receipt(&target, expectation)
            .unwrap()
            .original_output_spendable_now
    );
    assert_eq!(inventory(&source_root), before);
    assert!(
        target
            .contact_status(status.message_id)
            .unwrap()
            .original_recipient_output_spendable_now
    );
    println!("paged-remote-complete source_height={} recipient_mature99=true full_native_signer_wallet_contact_cold=true no_network_or_independent_qualification=true elapsed={:.3}",prefix_height+1,started.elapsed().as_secs_f64());
}
