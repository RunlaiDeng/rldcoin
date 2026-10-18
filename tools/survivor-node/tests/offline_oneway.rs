//! Public NO-VALUE, two fresh ordinary stores and only a forward file contact.
//! Retained private fixture state is never published or reused as monetary state.
use rld_survivor_node::{
    kernel::genesis_id,
    network::Network,
    store::{Limits, Store},
};
use serde_json::{json, Value};
use std::{
    fs,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[test]
fn one_way_offline_contact_synchronizes_one_missing_block_without_return_frames() {
    one_way(1, Duration::from_secs(10), false);
}

#[test]
fn one_way_complete_prefix_crosses_batches_and_sender_restart() {
    one_way(33, Duration::from_secs(60), true);
}

fn one_way(block_count: usize, budget: Duration, restart: bool) {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/survivor-v1/vectors.json"
    ))
    .unwrap();
    let genesis = hex::decode(vectors["genesis"]["manifest_hex"].as_str().unwrap()).unwrap();
    let chain = genesis_id(&genesis);
    let root = std::env::temp_dir().join(format!(
        "rld-survivor-offline-oneway-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut source = Store::open(&root.join("source"), &genesis, chain, Limits::default()).unwrap();
    let mut receiver =
        Store::open(&root.join("receiver"), &genesis, chain, Limits::default()).unwrap();
    let blocks: Vec<_> = vectors["main_branch"].as_array().unwrap()[..block_count]
        .iter()
        .map(|b| hex::decode(b["block_hex"].as_str().unwrap()).unwrap())
        .collect();
    // Respect the native grouped-admission limit while building the separate
    // longer-than-one-offer fixture. No consensus or carriage limit is raised.
    for (index, batch) in blocks.chunks(16).enumerate() {
        let mut operation = [1; 32];
        operation[31] = index as u8 + 1;
        source
            .accept_history(operation, batch, 2_000_000_000)
            .unwrap();
    }
    assert_eq!(source.ledger().tip().height(), block_count as u128);
    assert_eq!(receiver.ledger().tip().height(), 0);

    let first_source = Network::open(&root.join("source/contact"), chain, None).unwrap();
    let first_receiver = Network::open(&root.join("receiver/contact"), chain, None).unwrap();
    let source_key = first_source.status()["identity"]
        .as_str()
        .unwrap()
        .to_owned();
    let receiver_key = first_receiver.status()["identity"]
        .as_str()
        .unwrap()
        .to_owned();
    drop(first_source);
    drop(first_receiver);
    let config = |peer: &str| {
        serde_json::to_vec(&json!({
            "listen":"127.0.0.1:0",
            "neighbors":[],
            "offline_peers":[peer]
        }))
        .unwrap()
    };
    let mut source_network = Network::open(
        &root.join("source/contact"),
        chain,
        Some(&config(&receiver_key)),
    )
    .unwrap();
    let mut receiver_network = Network::open(
        &root.join("receiver/contact"),
        chain,
        Some(&config(&source_key)),
    )
    .unwrap();
    let source_key = hex::decode(source_key).unwrap().try_into().unwrap();
    let receiver_key = hex::decode(receiver_key).unwrap().try_into().unwrap();
    let started = Instant::now();
    let deadline = started + budget;
    let mut rounds = 0;
    let mut delivered_frames = 0;
    let mut retained_return_receipts = 0;
    let mut restarted = false;
    while rounds < if restart { 120 } else { 20 } && Instant::now() < deadline {
        source_network.tick(&mut source, 2_000_000_000).unwrap();
        receiver_network.tick(&mut receiver, 2_000_000_000).unwrap();
        for frame in source_network.offline_export(receiver_key).unwrap() {
            delivered_frames += 1;
            // The signed result remains at the receiver. No receipt, request,
            // advertisement or other frame is carried in the reverse direction.
            if receiver_network
                .offline_import(source_key, &frame)
                .unwrap()
                .is_some()
            {
                retained_return_receipts += 1;
            }
        }
        receiver_network.tick(&mut receiver, 2_000_000_000).unwrap();
        rounds += 1;
        if restart && !restarted && receiver.ledger().tip().height() > 0 {
            // Recreate only the ordinary adapter. Exact unreceipted packets and
            // progress survive in its independent custody database.
            let identity = source_network.status()["identity"].clone();
            drop(source_network);
            source_network = Network::open(
                &root.join("source/contact"),
                chain,
                Some(&config(&hex::encode(receiver_key))),
            )
            .unwrap();
            assert_eq!(source_network.status()["identity"], identity);
            restarted = true;
        }
        if receiver.ledger().tip().id() == source.ledger().tip().id() {
            break;
        }
        std::thread::sleep(Duration::from_millis(210));
    }
    let source_tip = source.ledger().tip().id();
    let receiver_tip = receiver.ledger().tip().id();
    assert!(delivered_frames > 0 && retained_return_receipts > 0);
    assert!(!restart || restarted);
    assert!(Instant::now() < deadline, "one-way native prefix budget");
    assert_eq!(receiver.ledger().coins(), source.ledger().coins());
    let retained =
        rusqlite::Connection::open(root.join("source/contact/custody/carriage.sqlite3")).unwrap();
    let counts: (i64, i64, i64) = retained
        .query_row(
            "SELECT (SELECT count(*) FROM receipts),(SELECT count(*) FROM hop_receipts),(SELECT count(*) FROM packets WHERE kind=3 AND done=0)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(counts, (0, 0, block_count as i64));
    drop(retained);
    let issued = source.ledger().issued();
    drop(source_network);
    drop(receiver_network);
    drop(source);
    drop(receiver);
    assert_eq!(
        receiver_tip, source_tip,
        "one-way offline contact must carry complete missing history without a return frame"
    );
    let cold = Store::open(&root.join("receiver"), &genesis, chain, Limits::default()).unwrap();
    assert_eq!(cold.ledger().tip().id(), source_tip);
    assert_eq!(cold.ledger().tip().height(), block_count as u128);
    assert_eq!(cold.ledger().issued(), issued);
    assert_eq!(
        cold.ledger()
            .coins()
            .values()
            .map(|c| c.amount)
            .sum::<u128>(),
        issued
    );
}
