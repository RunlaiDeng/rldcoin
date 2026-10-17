//! Two ordinary contact lifecycles with separate stores and real pinned TLS.
//! Same-controller ground evidence only; no independent-host/physical claim.
use rld_survivor_node::{
    kernel::genesis_id,
    network::Network,
    store::{Limits, Store},
};
use serde_json::{json, Value};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
#[test]
fn ordinary_sync_then_one_survivor_extends_the_same_history() {
    let v: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/survivor-v1/vectors.json"
    ))
    .unwrap();
    let mut g = hex::decode(v["genesis"]["manifest_hex"].as_str().unwrap()).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    g[45..53].copy_from_slice(&(now - 86400).to_be_bytes());
    let mut nonce = [0; 32];
    getrandom::getrandom(&mut nonce).unwrap();
    g[13..45].copy_from_slice(&nonce);
    let chain = genesis_id(&g);
    let root = std::env::temp_dir().join(format!("rld-survivor-network-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let mut a = Store::open(&root.join("a"), &g, chain, Limits::default()).unwrap();
    let mut b = Store::open(&root.join("b"), &g, chain, Limits::default()).unwrap();
    let miner = hex::decode(v["wallet_public_keys"][0].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    for i in 1u128..=12 {
        let mut job = a
            .ledger()
            .mining_job(miner, vec![], now + i as u64, now)
            .unwrap();
        let raw = job.attempt(100000).unwrap();
        let mut op = [0; 32];
        op[16..].copy_from_slice(&i.to_be_bytes());
        a.accept(op, &raw, now).unwrap();
    }
    let na = Network::open(&root.join("na"), chain, None).unwrap();
    let nb = Network::open(&root.join("nb"), chain, None).unwrap();
    let sa = na.status();
    let sb = nb.status();
    drop(na);
    drop(nb);
    let config = |own: &Value, peer: &Value| {
        serde_json::to_vec(&json!({"listen":own["listen"],"neighbors":[{"key":peer["identity"],"endpoint":peer["listen"],"certificate_sha256":peer["certificate_sha256"]}]})).unwrap()
    };
    let mut na = Network::open(&root.join("na"), chain, Some(&config(&sa, &sb))).unwrap();
    let mut nb = Network::open(&root.join("nb"), chain, Some(&config(&sb, &sa))).unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    while b.ledger().tip().id() != a.ledger().tip().id() {
        assert!(
            Instant::now() < deadline,
            "sync budget: A {} B {} A-net {} B-net {}",
            a.ledger().tip().height(),
            b.ledger().tip().height(),
            na.status(),
            nb.status()
        );
        na.tick(&mut a, now).unwrap();
        nb.tick(&mut b, now).unwrap();
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(a.ledger().coins(), b.ledger().coins());
    let tip = b.ledger().tip().id();
    drop(na);
    drop(a);
    let miner = hex::decode(v["wallet_public_keys"][1].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let mut job = b.ledger().mining_job(miner, vec![], now + 13, now).unwrap();
    let raw = job.attempt(100000).unwrap();
    b.accept([99; 32], &raw, now).unwrap();
    assert_ne!(b.ledger().tip().id(), tip);
    assert_eq!(b.ledger().tip().height(), 13);
    drop(nb);
    drop(b);
    let b = Store::open(&root.join("b"), &g, chain, Limits::default()).unwrap();
    assert_eq!(b.ledger().tip().height(), 13);
}
