use super::paged_integration::{certify, retain};
use super::retained_native_replay::inventory;
use super::*;
use std::process::Command as Process;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodePin {
    relative: String,
    native: Hash,
    signers: Vec<Hash>,
    wallet: Hash,
    contact: Hash,
    expectation: crate::wallet::ReceiptExpectation,
    remaining: Amount,
    height: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pins {
    currency: Hash,
    nodes: Vec<NodePin>,
}
fn fail(phase: &str, reason: &str, h: &Harness, unchanged: bool) -> ! {
    println!(
        "paged-cycle-refusal {}",
        serde_json::json!({
            "phase":phase,"reason":reason,"native_height":h.node.chain.height(),
            "active_snapshots":h.node.evidence.snapshots.len(),
            "native_export_count":h.node.chain.ledger.exports.len(),
            "native_import_count":h.node.chain.ledger.imports.len(),
            "native_private_inventory_unchanged_by_refusal":unchanged,
            "refund_resign_recovery":false,"three_region_cycle_qualified":false
        })
    );
    panic!("native paged cycle first refusal: {phase}: {reason}");
}
fn certify_next(h: &mut Harness, commands: Vec<crate::Command>) {
    let snapshot = certify(h, commands);
    h.node.finalize(snapshot).unwrap();
    h.node.chain.ledger.audit().unwrap();
}
fn accounting(nodes: [&Harness; 3], pending: u128) {
    let chains = nodes
        .iter()
        .map(|h| h.node.chain.clone())
        .collect::<Vec<_>>();
    let (issued, liquid, escrow, actual) = conservation_with_escrow(&chains).unwrap();
    assert_eq!(escrow, Amount::ZERO);
    assert_eq!(actual, Amount(pending));
    assert_eq!(issued, add(liquid, actual).unwrap());
}
fn export(
    h: &mut Harness,
    owner: u8,
    destination: Hash,
    recipient: u8,
    gross: u128,
    input: Option<Hash>,
) -> (Hash, Hash) {
    let mut agent =
        crate::wallet_agent::Agent::create(&h.root.join("cycle-owner"), &h.node, public(owner))
            .unwrap();
    let old = agent.journal.head().unwrap();
    retain(&h.root, 4, old);
    let key = h.root.join("cycle-owner-key.json");
    crate::keystore::private_create(
        &key,
        &serde_json::to_vec(&serde_json::json!({"secret_key":hex::encode([owner;32])})).unwrap(),
    )
    .unwrap();
    let before = inventory(&h.root);
    let prepared = agent
        .prepare(
            &h.node,
            crate::wallet::Request {
                owner: public(owner),
                participants: vec![],
                inputs: input.map(|i| vec![i]),
                outputs: vec![],
                remote: Some(crate::wallet::Remote {
                    destination,
                    recipient: Payment {
                        owner: public(recipient),
                        amount: Amount(gross),
                    },
                    destination_fee: Amount(1),
                }),
                fee: Amount(1),
                valid_for_blocks: 8,
                valid_through: None,
            },
            old,
        )
        .unwrap_or_else(|reason| {
            fail(
                "native-owner-review",
                &reason,
                h,
                inventory(&h.root) == before,
            )
        });
    if let Some(input) = input {
        assert_eq!(prepared.draft.intent.inputs, vec![input]);
        assert_eq!(prepared.draft.change, Amount::ZERO);
    }
    let spent = prepared.draft.intent.inputs.clone();
    let before = inventory(&h.root);
    let signed = agent
        .sign(
            &h.node,
            prepared.draft,
            &key,
            prepared.review_commitment,
            old,
        )
        .unwrap_or_else(|reason| {
            fail(
                "native-owner-sign",
                &reason,
                h,
                inventory(&h.root) == before,
            )
        });
    retain(&h.root, 4, signed.wallet_head);
    let head = signed.wallet_head;
    let export = signed
        .commands
        .iter()
        .find_map(|command| match command {
            crate::Command::Spend(spend) if spend.intent.destination.is_some() => {
                Some(spend.intent.id().unwrap())
            }
            _ => None,
        })
        .unwrap();
    certify_next(h, signed.commands);
    for input in spent {
        assert!(!h.node.chain.ledger.coins.contains_key(&input));
    }
    assert_eq!(
        h.node.chain.ledger.exports[&export].recipient.amount,
        Amount(gross)
    );
    agent.view(&h.node, head).unwrap();
    (export, head)
}
fn carry(
    source: &Harness,
    destination: &mut Harness,
    export: Hash,
) -> (Hash, crate::wallet::ReceiptExpectation) {
    let before = inventory(&source.root);
    let native = source.node.storage_head().unwrap();
    let ledger = source.node.chain.ledger.clone();
    let raw = source.node.contact_export(export).unwrap_or_else(|reason| {
        fail(
            "native-complete-export-proof",
            &reason,
            source,
            inventory(&source.root) == before
                && source.node.storage_head().unwrap() == native
                && source.node.chain.ledger == ledger,
        )
    });
    let (_, bundle) = crate::contact::Frame::unpack(&raw).unwrap();
    let actual = &source.node.chain.ledger.exports[&export];
    let expectation = crate::wallet::ReceiptExpectation {
        currency: source.node.trust.currency().unwrap(),
        source: source.node.chain.region,
        destination: destination.node.chain.region,
        export,
        recipient: actual.recipient.owner.clone(),
        net_amount: actual
            .recipient
            .amount
            .checked_sub(actual.destination_fee)
            .unwrap(),
    };
    let before = inventory(&destination.root);
    let native = destination.node.storage_head().unwrap();
    let ledger = destination.node.chain.ledger.clone();
    let status = destination
        .node
        .contact_apply(&raw, None)
        .unwrap_or_else(|reason| {
            fail(
                "native-complete-contact-accept",
                &reason,
                destination,
                inventory(&destination.root) == before
                    && destination.node.storage_head().unwrap() == native
                    && destination.node.chain.ledger == ledger,
            )
        });
    assert!(status.evidence_verified && !status.import_accepted);
    assert!(!status.original_recipient_output_spendable_now);
    let ident = status.message_id;
    certify_next(
        destination,
        vec![crate::Command::Import {
            snapshot: bundle.snapshot,
            export,
        }],
    );
    let status = destination.node.contact_status(ident).unwrap();
    assert!(status.import_accepted && !status.original_recipient_output_spendable_now);
    for _ in 0..destination.node.trust.currency.maturity {
        certify_next(destination, vec![]);
    }
    assert!(
        crate::wallet::receipt(&destination.node, expectation.clone())
            .unwrap()
            .original_output_spendable_now
    );
    let head = destination.node.storage_head().unwrap();
    let before = inventory(&destination.root);
    let status = destination.node.contact_apply(&raw, None).unwrap();
    assert!(status.import_accepted && status.original_recipient_output_spendable_now);
    assert_eq!(destination.node.storage_head().unwrap(), head);
    assert_eq!(inventory(&destination.root), before);
    // A duplicate local import must fail before signing/debit, despite a valid
    // retained contact frame and permanent original export.
    assert!(destination
        .node
        .bft_candidate(
            vec![crate::Command::Import {
                snapshot: bundle.snapshot,
                export,
            }],
            public(10)
        )
        .is_err());
    assert_eq!(inventory(&destination.root), before);
    println!("paged-cycle-hop proof_checkpoints={} payload_frame_bytes={} destination_height={} recipient_net={} imported_mature=true duplicate_import_refused=true original_export_retained=true",bundle.evidence.snapshots.len(),raw.len(),destination.node.chain.height(),expectation.net_amount.0);
    (ident, expectation)
}
#[test]
#[ignore = "bounded parent explicitly launches this fresh pinned read-only process"]
fn paged_three_region_cycle_cold_child() {
    let root = PathBuf::from(
        std::env::var_os("RLD_PAGED_CYCLE_ROOT").expect("parent private fixture path"),
    );
    let pins: Pins = crate::storage::read_json(&root.join("cycle-pins.json")).unwrap();
    assert_eq!(pins.nodes.len(), 3);
    let before = inventory(&root);
    let mut chains = vec![];
    for (n, pin) in pins.nodes.iter().enumerate() {
        assert_eq!(
            pin.relative,
            [".", "destination", "destination/destination"][n]
        );
        let dir = root.join(&pin.relative);
        assert_eq!(
            fs::read(dir.join("caller-native.head")).unwrap(),
            pin.native.0
        );
        let node =
            Store::open_pinned(&dir.join("node"), &public(1), pins.currency, pin.native).unwrap();
        assert_eq!(node.chain.height(), pin.height);
        for (i, seed) in keys().iter().enumerate() {
            let agent = Agent::open(&dir.join(format!("signer-{seed}")), &node).unwrap();
            assert_eq!(agent.head().unwrap(), pin.signers[i]);
            assert_eq!(
                fs::read(dir.join(format!("caller-{i}.head"))).unwrap(),
                pin.signers[i].0
            );
        }
        let wallet = crate::wallet_agent::Agent::open(&dir.join("cycle-owner"), &node).unwrap();
        wallet.view(&node, pin.wallet).unwrap();
        assert_eq!(fs::read(dir.join("caller-4.head")).unwrap(), pin.wallet.0);
        let status = node.contact_status(pin.contact).unwrap();
        assert!(status.import_accepted && status.recipient_mature_height.unwrap() <= pin.height);
        assert_eq!(status.original_recipient_output_remaining, pin.remaining);
        let receipt = crate::wallet::receipt(&node, pin.expectation.clone()).unwrap();
        assert_eq!(
            receipt.original_output_spendable_now,
            !pin.remaining.is_zero()
        );
        chains.push(node.chain.clone());
    }
    let (_, _, escrow, pending) = conservation_with_escrow(&chains).unwrap();
    assert_eq!(escrow, Amount::ZERO);
    assert_eq!(pending, Amount::ZERO);
    assert_eq!(inventory(&root), before);
    println!("paged-cycle-cold three_native_twelve_signers_three_wallets_from_genesis=true private_inventory_unchanged=true independently_fresh=false");
}
#[test]
fn paged_contact_causal_order_counter_uses_native_imported_owner_input() {
    let mut earth = Harness::with_rules(crate::paged_bft::RULES);
    earth.retain = true;
    for n in 0..4 {
        retain(&earth.root, n, earth.heads[n]);
    }
    let package = earth.node.journal.bootstrap.clone();
    let mut proxima =
        super::paged_remote::target(&earth, package.clone(), package.admissions[1].id().unwrap());
    for _ in 0..3 {
        certify_next(&mut earth, vec![]);
    }
    let (first, _) = export(&mut earth, 10, proxima.node.chain.region, 11, 100, None);
    carry(&earth, &mut proxima, first);
    let (onward, _) = export(
        &mut proxima,
        11,
        package.admissions[2].id().unwrap(),
        12,
        98,
        Some(id("output", &(first, 0u32)).unwrap()),
    );
    // Exact public view bytes are retained; only proof carriage order changes.
    let old = proxima.node.journal.evidence.clone();
    let reason = VerifiedEvidence::verify(&old, &proxima.node.trust)
        .err()
        .expect("height order must expose the actual cross-region causal counter");
    assert_eq!(reason, "missing verified source checkpoint");
    let before = inventory(&earth.root);
    let raw = proxima.node.contact_export(onward).unwrap();
    let (_, bundle) = crate::contact::Frame::unpack(&raw).unwrap();
    let checked = VerifiedEvidence::verify(&bundle.evidence, &proxima.node.trust).unwrap();
    assert_eq!(
        checked.export(bundle.snapshot, onward).unwrap(),
        &proxima.node.chain.ledger.exports[&onward]
    );
    let mut original = old
        .snapshots
        .iter()
        .map(|s| serde_json::to_vec(s).unwrap())
        .collect::<Vec<_>>();
    let mut carried = bundle
        .evidence
        .snapshots
        .iter()
        .map(|s| serde_json::to_vec(s).unwrap())
        .collect::<Vec<_>>();
    original.sort();
    carried.sort();
    assert_eq!(original, carried);
    assert_eq!(inventory(&earth.root), before);
    println!("paged-causal-counter old_height_order_native_refused=true new_complete_original_multiset_native_verified=true checkpoints8=true native_owner_import99_spent_onward98=true export_refusal_never_refunds=true unchanged=true");
}
#[test]
fn paged_three_region_actual_owner_onward_return_with_fresh_process_cold() {
    let started = std::time::Instant::now();
    let mut earth = Harness::with_rules(crate::paged_bft::RULES);
    earth.retain = true;
    for n in 0..4 {
        retain(&earth.root, n, earth.heads[n]);
    }
    let package = earth.node.journal.bootstrap.clone();
    let mut proxima =
        super::paged_remote::target(&earth, package.clone(), package.admissions[1].id().unwrap());
    let mut andromeda = super::paged_remote::target(
        &proxima,
        package.clone(),
        package.admissions[2].id().unwrap(),
    );
    let regions = [
        earth.node.chain.region,
        proxima.node.chain.region,
        andromeda.node.chain.region,
    ];
    for _ in 0..3 {
        certify_next(&mut earth, vec![]);
    }
    accounting([&earth, &proxima, &andromeda], 0);
    let (first, ewallet) = export(&mut earth, 10, regions[1], 11, 100, None);
    accounting([&earth, &proxima, &andromeda], 100);
    let (pcontact, preceipt) = carry(&earth, &mut proxima, first);
    accounting([&earth, &proxima, &andromeda], 0);
    let (second, pwallet) = export(
        &mut proxima,
        11,
        regions[2],
        12,
        98,
        Some(id("output", &(first, 0u32)).unwrap()),
    );
    accounting([&earth, &proxima, &andromeda], 98);
    let (acontact, areceipt) = carry(&proxima, &mut andromeda, second);
    accounting([&earth, &proxima, &andromeda], 0);
    let (third, awallet) = export(
        &mut andromeda,
        12,
        regions[0],
        10,
        96,
        Some(id("output", &(second, 0u32)).unwrap()),
    );
    accounting([&earth, &proxima, &andromeda], 96);
    let (econtact, ereceipt) = carry(&andromeda, &mut earth, third);
    accounting([&earth, &proxima, &andromeda], 0);
    let mut nodes = vec![];
    for (n, (h, wallet, contact, expectation, remaining)) in [
        (&earth, ewallet, econtact, ereceipt, Amount(95)),
        (&proxima, pwallet, pcontact, preceipt, Amount::ZERO),
        (&andromeda, awallet, acontact, areceipt, Amount::ZERO),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(h.node.chain.ledger.exports.len(), 1);
        assert_eq!(h.node.chain.ledger.imports.len(), 1);
        let native = h.node.storage_head().unwrap();
        crate::keystore::private_create(&h.root.join("caller-native.head"), &native.0).unwrap();
        nodes.push(NodePin {
            relative: [".", "destination", "destination/destination"][n].into(),
            native,
            signers: h.heads.clone(),
            wallet,
            contact,
            expectation,
            remaining,
            height: h.node.chain.height(),
        });
    }
    let root = earth.root.clone();
    let pins = Pins {
        currency: earth.node.trust.currency().unwrap(),
        nodes,
    };
    crate::keystore::private_create(
        &root.join("cycle-pins.json"),
        &serde_json::to_vec(&pins).unwrap(),
    )
    .unwrap();
    assert_eq!(
        pins.nodes.iter().map(|n| n.height).collect::<Vec<_>>(),
        vec![7, 4, 4]
    );
    drop(earth);
    drop(proxima);
    drop(andromeda);
    let before = inventory(&root);
    let child = Process::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tests::regional_bft::paged_cycle::paged_three_region_cycle_cold_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("RLD_PAGED_CYCLE_ROOT", &root)
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "{}{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    println!("{}", String::from_utf8_lossy(&child.stdout));
    assert_eq!(inventory(&root), before);
    println!("paged-cycle-complete heights7_4_4=true native_owner_net99_97_95=true exact_imported_inputs_spent=true global_issued_liquid_zero_pending=true separate_caller_heads=true original_exports_tombstones_retained=true fresh_process_cold=true unchanged=true elapsed={:.3}", started.elapsed().as_secs_f64());
}
