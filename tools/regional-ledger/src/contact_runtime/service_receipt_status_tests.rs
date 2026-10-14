//! A real custody receipt can coexist with unavailable Native progress telemetry.
//! This component performs no network service or ledger acceptance.
use super::*;
use crate::contact::Frame;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::collections::BTreeMap;
use std::time::SystemTime;

fn inventory(root: &Path) -> BTreeMap<PathBuf, (Vec<u8>, SystemTime)> {
    fn visit(root: &Path, output: &mut BTreeMap<PathBuf, (Vec<u8>, SystemTime)>) {
        for entry in fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            assert!(!metadata.file_type().is_symlink());
            if metadata.is_dir() {
                visit(&path, output);
            } else {
                assert!(metadata.is_file());
                output.insert(
                    path.clone(),
                    (fs::read(path).unwrap(), metadata.modified().unwrap()),
                );
            }
        }
    }
    let mut output = BTreeMap::new();
    visit(root, &mut output);
    output
}

fn within(deadline: f64) {
    assert!(
        monotonic().unwrap() < deadline,
        "original receipt-status component deadline exhausted"
    );
}

#[test]
#[ignore = "fresh signed custody and Native lock observation component"]
fn durable_receipt_remains_authenticated_when_native_progress_is_unknown() {
    let started = monotonic().unwrap();
    let deadline = started + 10.0;
    let root = directory(
        &fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("rld-receipt-status-{}", random().unwrap())),
    )
    .unwrap();
    println!(
        "\nonward_receipt_status_counter_scope={}",
        json!({
            "root":root,"pid":std::process::id(),"started":started,"deadline":deadline,
            "fixture_only":true
        })
    );
    // The genesis uses public test signing keys; Mesh identities are fresh private
    // no-value fixture material.
    let mut genesis = crate::tests::bootstrap();
    genesis.currency.origin = format!("receipt-status-{}", &random().unwrap()[..16]);
    genesis.currency.cap = crate::Amount::TOTAL_SUPPLY;
    genesis.currency.block_reward = rld_pow::subsidy(1).unwrap();
    genesis.currency.signature = crate::tests::signature(1, &genesis.currency.bytes().unwrap());
    let currency = genesis.currency.id().unwrap();
    for (i, admission) in genesis.admissions.iter_mut().enumerate() {
        if i == 0 {
            admission.region = genesis.currency.origin.clone();
        }
        admission.currency = currency;
        admission.signature = crate::tests::signature(1, &admission.bytes().unwrap());
    }
    let authority = genesis.currency.authority.clone();
    let region = genesis.admissions[0].id().unwrap();
    let native =
        Store::create(&root.join("ledger"), genesis, region, &authority, currency).unwrap();
    let head = native.storage_head().unwrap();
    assert!(!head.is_zero());
    let value = native.chain.ledger.root().unwrap();
    assert_eq!(native.chain.height(), 0);
    assert_eq!(native.chain.ledger.minted, crate::Amount::ZERO);
    let network = currency.to_hex();
    let mut ids = Vec::new();
    for n in 0..2 {
        let identity = initialize(
            &root.join(format!("mesh-{n}")),
            &network,
            &region.to_hex(),
            "public-no-value-receipt-status",
        )
        .unwrap();
        ids.push(identity["node_id"].as_str().unwrap().to_owned());
    }
    assert_ne!(ids[0], ids[1]);
    let configs: Vec<_> = (0..2)
        .map(|n| {
            json!({
                "format":MESH,"network":network,"state":root.join(format!("mesh-{n}")),
                "contacts":[{"peer":ids[1-n],"inbox":root.join(format!("spool-{}-{n}",1-n)),
                    "outbox":root.join(format!("spool-{n}-{}",1-n))}]
            })
        })
        .collect();
    // Establish the two real signed advertisements before any nonmutation baseline.
    for (sender, receiver) in [(0, 1), (1, 0)] {
        let bundle = Node::open(&configs[sender])
            .unwrap()
            .prepare(&ids[receiver])
            .unwrap();
        Node::open(&configs[receiver])
            .unwrap()
            .receive(&bundle, &ids[sender])
            .unwrap();
    }
    assert_eq!(
        Node::open(&configs[0]).unwrap().observation()["retained_receipts"],
        0
    );
    within(deadline);
    // Reuse the ordinary mesh fixture's hash-bound frame shape. The real source
    // identity signs the complete packet and route; this is not a Native payment.
    let payload = bytes(
        &json!({"format":crate::bft_network::FORMAT,"currency":currency,
        "region":region,"evidence":{"snapshots":[]},"body":{"Submission":[]}}),
    )
    .unwrap();
    let payload_hash = Hash(Sha256::digest(&payload).into());
    let mut frame = Frame {
        format: crate::contact::FRAME_FORMAT.into(),
        kind: "regional-bft".into(),
        source_chain_id: region,
        destination_chain_id: region,
        export_id: payload_hash,
        payload_sha256: payload_hash,
        payload_b64: STANDARD.encode(payload),
        message_id: Hash::ZERO,
    };
    frame.message_id = frame.message().unwrap();
    let raw = frame.retained_bytes().unwrap();
    let packet = Node::open(&configs[0])
        .unwrap()
        .enqueue(&raw, &ids[1])
        .unwrap();
    let outgoing = Node::open(&configs[0]).unwrap().prepare(&ids[1]).unwrap();
    let transits = outgoing["body"]["transits"].as_array().unwrap();
    assert_eq!(transits.len(), 1);
    let transit = &transits[0];
    assert_eq!(digest(&transit["packet"]).unwrap(), packet);
    assert_eq!(transit["packet"]["body"]["destination"], ids[1]);
    assert_eq!(
        transit["routing"]["body"]["frame_id"],
        frame.message_id.to_hex()
    );
    assert_eq!(
        Node::open(&configs[1])
            .unwrap()
            .receive(&outgoing, &ids[0])
            .unwrap(),
        vec![packet.clone()]
    );
    let reply = Node::open(&configs[1]).unwrap().prepare(&ids[0]).unwrap();
    let receipts = reply["body"]["receipts"].as_array().unwrap();
    assert_eq!(receipts.len(), 1);
    let receipt = &receipts[0];
    let checked = schema(receipt, &network, "receipt").unwrap();
    assert_eq!(checked["body"]["network"], network);
    assert_eq!(checked["body"]["node_id"], ids[1]);
    assert_eq!(checked["body"]["packet_id"], packet);
    assert_eq!(checked["body"]["frame_id"], frame.message_id.to_hex());
    assert_eq!(checked["body"]["routing"], transit["routing"]);
    assert_eq!(
        checked["body"]["outcome"],
        "EVIDENCE_STORED_NOT_LEDGER_ACCEPTED"
    );
    assert!(Node::open(&configs[0])
        .unwrap()
        .receive(&reply, &ids[1])
        .unwrap()
        .is_empty());
    let observed = Node::open(&configs[0]).unwrap().observation();
    assert_eq!(observed["retained_messages"], 1);
    assert_eq!(observed["retained_receipts"], 1);
    assert_eq!(observed["archive_entries"], 0);
    let before = inventory(&root);
    within(deadline);
    // The held Native Store supplies the actual OS lock refusal. No synthetic
    // status success or receipt value is substituted for unavailable telemetry.
    let options = Options {
        ledger: root.join("ledger"),
        authority: authority.clone(),
        currency,
        mesh_config: None,
        bft_config: None,
        listen: "127.0.0.1:0".parse().unwrap(),
        miner: None,
        interval: 1.0,
        insecure_tcp: false,
    };
    let (mut runtime, mut cursor, mut seen) = (None, None, Vec::new());
    let failure =
        tick_ledger(&options, &configs[0], &mut runtime, &mut cursor, &mut seen).unwrap_err();
    assert!(lock_contention(&failure));
    assert_eq!(failure, std::fs::TryLockError::WouldBlock.to_string());
    let unknown = unknown_progress(currency, region);
    assert_eq!(unknown["progress_observation_available"], false);
    for field in ["local_height", "height", "round", "mesh", "ledger_changed"] {
        assert!(unknown.get(field).is_none());
    }
    assert!(runtime.is_none() && cursor.is_none() && seen.is_empty());
    // Force complete transit authentication again, with no process witness hit.
    crate::contact_witness::execute(&bytes(&json!("Clear")).unwrap(), &[]).unwrap();
    assert_eq!(Node::open(&configs[0]).unwrap().observation(), observed);
    assert_eq!(
        Node::open(&configs[1]).unwrap().received_frames().unwrap(),
        vec![(packet.clone(), raw)]
    );
    assert!(
        before == inventory(&root),
        "authenticated checks changed retained bytes or mtimes"
    );
    assert_eq!(native.storage_head().unwrap(), head);
    assert_eq!(native.chain.ledger.root().unwrap(), value);
    assert_eq!(native.chain.height(), 0);
    assert_eq!(native.chain.ledger.minted, crate::Amount::ZERO);
    drop(native);
    within(deadline);
    let cold = Store::open_pinned_inspection(&options.ledger, &authority, currency, head).unwrap();
    assert_eq!(cold.storage_head().unwrap(), head);
    assert_eq!(cold.chain.ledger.root().unwrap(), value);
    assert_eq!(cold.chain.height(), 0);
    assert_eq!(cold.chain.ledger.minted, crate::Amount::ZERO);
    drop(cold);
    assert!(
        before == inventory(&root),
        "same-process Native replay changed retained inventory"
    );
    // Re-sign only the exchange with the real destination identity, preserving
    // its valid outer signature while the exact inner receipt signature is bad.
    let mut corrupt_body = reply["body"].clone();
    corrupt_body["receipts"][0]["signature"] = json!("00".repeat(64));
    assert!(schema(&corrupt_body["receipts"][0], &network, "receipt").is_err());
    let corrupt = Node::open(&configs[1])
        .unwrap()
        .sign("exchange", corrupt_body)
        .unwrap();
    let refusal = Node::open(&configs[0])
        .unwrap()
        .receive(&corrupt, &ids[1])
        .unwrap_err();
    assert!(!refusal.is_empty());
    assert!(
        before == inventory(&root),
        "rejected receipt changed retained bytes or mtimes"
    );
    crate::contact_witness::execute(&bytes(&json!("Clear")).unwrap(), &[]).unwrap();
    assert_eq!(Node::open(&configs[0]).unwrap().observation(), observed);
    assert!(
        before == inventory(&root),
        "reopen after refusal changed retained inventory"
    );
    within(deadline);
    let ended = monotonic().unwrap();
    assert!(ended < deadline);
    println!(
        "\nonward_receipt_status_counter_result={}",
        json!({
            "root":root,"pid":std::process::id(),"started":started,"deadline":deadline,
            "ended":ended,"elapsed_seconds":ended-started,"passed":true,
            "real_signed_packet_and_destination_receipt":true,"receipt_zero_baseline":true,
            "exact_receipt_binding":true,"actual_native_lock_refusal":true,
            "unknown_progress_omits_receipt_observation":true,
            "authenticated_receipt_during_unknown_progress":true,
            "read_only_checks_preserved_bytes_and_mtimes":true,"native_head_and_zero_value_unchanged":true,
            "same_process_full_reopen":true,"corrupt_receipt_refused":true,
            "corruption_refusal_preserved_inventory":true,
            "fresh_process_cold":false,"network_qualified":false,"routing_qualified":false,
            "payment_qualified":false,"bft_liveness_qualified":false,"old_routing_cause_established":false,
            "mainnet":false,"native_height":0,"native_head":head,"source_receipts_before":0,"source_receipts_after":1,
            "source_node_id":ids[0],"destination_node_id":ids[1],"packet_id":packet,
            "frame_id":frame.message_id,"receipt_sha256":digest(receipt).unwrap(),
            "inventory_files":before.len(),"unknown_progress":unknown,
            "native_lock_error":failure,"corrupt_receipt_error":refusal
        })
    );
    // Preserve this scope on both success and failure for the external seal.
}
