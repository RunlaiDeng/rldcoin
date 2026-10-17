//! Bounded history installation is one durable selected transition, not trusted
//! snapshots or a replacement for full genesis-rooted kernel execution.
use rld_survivor_node::{
    kernel::{genesis_id, Ledger},
    store::{Limits, Store},
};
use serde_json::Value;
fn fixture() -> (Vec<u8>, Vec<Vec<u8>>) {
    let v: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/survivor-v1/vectors.json"
    ))
    .unwrap();
    (
        hex::decode(v["genesis"]["manifest_hex"].as_str().unwrap()).unwrap(),
        v["main_branch"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| hex::decode(x["block_hex"].as_str().unwrap()).unwrap())
            .collect(),
    )
}
#[test]
fn complete_groups_match_sequential_kernel_and_retain_exact_retry_and_notifications() {
    let (g, blocks) = fixture();
    let pin = genesis_id(&g);
    let root = std::env::temp_dir().join(format!(
        "rld-survivor-history-groups-{}",
        std::process::id()
    ));
    let mut s = Store::open(&root, &g, pin, Limits::default()).unwrap();
    let mut expected = Ledger::from_genesis(&g, pin, Limits::default().coins).unwrap();
    let mut ids = Vec::new();
    for (i, group) in blocks.chunks(32).enumerate() {
        let op = [i as u8 + 1; 32];
        let outcome = s.accept_history(op, group, 2_000_000_000).unwrap();
        for b in group {
            expected.execute(b).unwrap();
        }
        assert_eq!(s.ledger().tip(), expected.tip());
        assert_eq!(s.ledger().coins(), expected.coins());
        assert_eq!(s.revision(), i as u128 + 1);
        let events = s.changes_since(i as u128).unwrap();
        assert_eq!(
            events["changes"][0]["attached"].as_array().unwrap().len(),
            group.len()
        );
        ids.push((op, group.to_vec(), outcome));
    }
    for (op, group, outcome) in &ids {
        assert_eq!(
            s.accept_history(*op, group, 2_000_000_000).unwrap(),
            *outcome
        );
        assert_eq!(
            s.accept(*op, group.last().unwrap(), 2_000_000_000)
                .unwrap_err(),
            "OPERATION_ID_CONFLICT"
        );
        if group.len() > 1 {
            let mut altered = group.clone();
            altered[0][268] ^= 1;
            assert_eq!(
                s.accept_history(*op, &altered, 2_000_000_000).unwrap_err(),
                "OPERATION_ID_CONFLICT"
            );
            assert_eq!(
                s.accept_history(*op, &group[1..], 2_000_000_000)
                    .unwrap_err(),
                "OPERATION_ID_CONFLICT"
            );
        }
    }
    drop(s);
    let mut s = Store::open(&root, &g, pin, Limits::default()).unwrap();
    assert_eq!(s.ledger().tip(), expected.tip());
    assert_eq!(s.ledger().coins(), expected.coins());
    let v: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/survivor-v1/vectors.json"
    ))
    .unwrap();
    let previous = s.revision();
    for (i, b) in v["alternative_branch"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        s.accept(
            [200 + i as u8; 32],
            &hex::decode(b["block_hex"].as_str().unwrap()).unwrap(),
            2_000_000_000,
        )
        .unwrap();
    }
    assert_eq!(
        hex::encode(s.ledger().tip().id()),
        v["selection"]["greater_work_winner"]
    );
    assert!(s.changes_since(previous).unwrap()["changes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| !x["detached"].as_array().unwrap().is_empty()));
    let tip = s.ledger().tip().clone();
    let coins = s.ledger().coins().clone();
    drop(s);
    let s = Store::open(&root, &g, pin, Limits::default()).unwrap();
    assert_eq!(s.ledger().tip(), &tip);
    assert_eq!(s.ledger().coins(), &coins);
}

#[test]
fn previous_store_format_refuses_without_creating_a_group_index() {
    let (g, _) = fixture();
    let pin = genesis_id(&g);
    let root = std::env::temp_dir().join(format!(
        "rld-survivor-history-old-format-{}",
        std::process::id()
    ));
    drop(Store::open(&root, &g, pin, Limits::default()).unwrap());
    let path = root.join("ledger.sqlite3");
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute("DROP TABLE history_batches", []).unwrap();
    db.execute("UPDATE binding SET format='RLD-SURVIVOR-STORE-3'", [])
        .unwrap();
    drop(db);
    let before = std::fs::read(&path).unwrap();
    assert!(Store::open(&root, &g, pin, Limits::default()).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn native_command_exact_group_retry_survives_restart() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let (mut g, _) = fixture();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    g[45..53].copy_from_slice(&(now - 100).to_be_bytes());
    getrandom::getrandom(&mut g[13..45]).unwrap();
    let pin = genesis_id(&g);
    let mut ledger = Ledger::from_genesis(&g, pin, Limits::default().coins).unwrap();
    let miner = ed25519_dalek::SigningKey::from_bytes(&[11; 32])
        .verifying_key()
        .to_bytes();
    let mut blocks = Vec::new();
    for h in 1..=3 {
        let mut job = ledger
            .mining_job(miner, vec![], now - 100 + h, now)
            .unwrap();
        let b = job.attempt(1_000_000).unwrap();
        ledger.execute(&b).unwrap();
        blocks.push(b);
    }
    let root = std::env::temp_dir().join(format!(
        "rld-survivor-history-command-{}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    let genesis = root.join("genesis.bin");
    std::fs::write(&genesis, &g).unwrap();
    let request = serde_json::json!({"method":"accept_history","operation_id":hex::encode([42;32]),"blocks":blocks[..3].iter().map(hex::encode).collect::<Vec<_>>()});
    for _ in 0..2 {
        let mut child = Command::new(env!("CARGO_BIN_EXE_rld-survivor-node"))
            .arg("serve")
            .arg(root.join("node"))
            .arg(&genesis)
            .arg(hex::encode(pin))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        writeln!(child.stdin.take().unwrap(), "{request}").unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let response: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert!(response["diagnostic"].is_null(), "{response}");
        assert_eq!(response["revision"], "1");
    }
    let store = Store::open(&root.join("node"), &g, pin, Limits::default()).unwrap();
    assert_eq!(store.ledger().tip().height(), 3);
    assert_eq!(store.revision(), 1);
}
#[test]
fn invalid_tail_missing_member_and_altered_member_order_cannot_select_partial_history() {
    let (g, blocks) = fixture();
    let pin = genesis_id(&g);
    let root = std::env::temp_dir().join(format!(
        "rld-survivor-history-negative-{}",
        std::process::id()
    ));
    let mut s = Store::open(&root, &g, pin, Limits::default()).unwrap();
    let mut bad = blocks[..3].to_vec();
    bad[2][220] ^= 1;
    assert!(s.accept_history([1; 32], &bad, 2_000_000_000).is_err());
    assert_eq!(s.ledger().tip().height(), 0);
    assert!(s.operation([1; 32]).unwrap().is_none());
    assert!(s
        .accept_history(
            [2; 32],
            &[blocks[0].clone(), blocks[2].clone()],
            2_000_000_000
        )
        .is_err());
    assert_eq!(s.revision(), 0);
    s.accept_history([3; 32], &blocks[..3], 2_000_000_000)
        .unwrap();
    drop(s);
    let db = rusqlite::Connection::open(root.join("ledger.sqlite3")).unwrap();
    let mut members: Vec<u8> = db
        .query_row("SELECT members FROM history_batches", [], |r| r.get(0))
        .unwrap();
    for i in 0..32 {
        members.swap(2 + i, 34 + i);
    }
    db.execute("UPDATE history_batches SET members=?1", [members])
        .unwrap();
    drop(db);
    assert!(Store::open(&root, &g, pin, Limits::default()).is_err());
}

#[test]
fn ordinary_admitted_file_reception_uses_complete_durable_history_group() {
    use ed25519_dalek::SigningKey;
    use rld_survivor_node::{
        carriage::{Budget, Carriage},
        contact::peer_id,
        network::Network,
    };
    let (g, blocks) = fixture();
    let pin = genesis_id(&g);
    let root = std::env::temp_dir().join(format!(
        "rld-survivor-history-contact-{}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    let mut store = Store::open(&root.join("node"), &g, pin, Limits::default()).unwrap();
    let net = Network::open(&root.join("contact"), pin, None).unwrap();
    let destination = hex::decode(net.status()["identity"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    drop(net);
    // Explicit public NO-VALUE contact fixture seed; never monetary custody.
    let key = SigningKey::from_bytes(&[11; 32]);
    let source = key.verifying_key().to_bytes();
    let config=serde_json::to_vec(&serde_json::json!({"listen":"127.0.0.1:0","neighbors":[],"offline_peers":[hex::encode(source)]})).unwrap();
    let mut net = Network::open(&root.join("contact"), pin, Some(&config)).unwrap();
    let mut out = Carriage::open(&root.join("outgoing"), pin, source, Budget::default()).unwrap();
    for block in &blocks[..3] {
        let packet = out.originate(&key, peer_id(destination), 3, block).unwrap();
        let frame = out.prepare_offline(&key, destination, &packet).unwrap();
        let receipt = net.offline_import(source, frame.raw()).unwrap().unwrap();
        out.offline_receipt(&receipt, destination).unwrap();
    }
    assert_eq!(store.ledger().tip().height(), 0); // Custody alone grants no money.
    net.tick(&mut store, 2_000_000_000).unwrap();
    assert_eq!(store.ledger().tip().height(), 3);
    assert_eq!(store.revision(), 1);
    assert_eq!(
        store.changes_since(0).unwrap()["changes"][0]["attached"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    drop(net);
    drop(store);
    let store = Store::open(&root.join("node"), &g, pin, Limits::default()).unwrap();
    assert_eq!(store.ledger().tip().height(), 3);
    assert_eq!(store.revision(), 1);
}
