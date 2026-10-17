//! Private fresh temporary stores; only published NO-VALUE fixture bytes are used.
use rld_survivor_node::{
    kernel::genesis_id,
    store::{Limits, Store},
};
use serde_json::Value;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn fixture() -> (Value, Vec<u8>, PathBuf) {
    let v: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/survivor-v1/vectors.json"
    ))
    .unwrap();
    let g = hex::decode(v["genesis"]["manifest_hex"].as_str().unwrap()).unwrap();
    let root = std::env::temp_dir().join(format!(
        "rld-survivor-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    (v, g, root)
}
fn b(v: &Value) -> Vec<u8> {
    hex::decode(v["block_hex"].as_str().unwrap()).unwrap()
}
fn op(n: u128) -> [u8; 32] {
    let mut x = [0; 32];
    x[16..].copy_from_slice(&n.to_be_bytes());
    x
}
#[test]
fn durable_extension_exact_retry_reorg_and_cold_replay() {
    let (v, g, path) = fixture();
    let pin = genesis_id(&g);
    let mut s = Store::open(&path, &g, pin, Limits::default()).unwrap();
    let now = 2_000_000_000;
    assert!(Store::open(&path, &g, pin, Limits::default()).is_err());
    for (i, x) in v["main_branch"].as_array().unwrap().iter().enumerate() {
        let raw = b(x);
        let result = s.accept(op(i as u128 + 1), &raw, now).unwrap();
        assert!(result.selected);
        assert_eq!(s.accept(op(i as u128 + 1), &raw, now).unwrap(), result);
    }
    assert!(s
        .accept(op(1), &b(&v["main_branch"][1]), now)
        .unwrap_err()
        .contains("OPERATION_ID_CONFLICT"));
    let main = s.ledger().tip().clone();
    let maincoins = s.ledger().coins().clone();
    drop(s);
    let mut s = Store::open(&path, &g, pin, Limits::default()).unwrap();
    assert_eq!(s.ledger().tip(), &main);
    assert_eq!(s.ledger().coins(), &maincoins);
    for (i, x) in v["alternative_branch"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        s.accept(op(i as u128 + 1000), &b(x), now).unwrap();
    }
    assert_eq!(
        hex::encode(s.ledger().tip().id()),
        v["selection"]["greater_work_winner"]
    );
    let tip = s.ledger().tip().clone();
    let revision = s.revision();
    let coins = s.ledger().coins().clone();
    drop(s);
    let mut s = Store::open(&path, &g, pin, Limits::default()).unwrap();
    assert_eq!(s.ledger().tip(), &tip);
    assert_eq!(s.revision(), revision);
    assert_eq!(s.ledger().coins(), &coins);
    s.clock(now).unwrap();
    assert!(s.clock(now - 1).is_err());
    assert_eq!(s.ledger().tip(), &tip);
}
#[test]
fn interrupted_intent_recovers_only_prior_and_exact_retry() {
    let (v, g, path) = fixture();
    let pin = genesis_id(&g);
    let mut s = Store::open(&path, &g, pin, Limits::default()).unwrap();
    let raw = b(&v["main_branch"][0]);
    s.accept(op(1), &raw, 2_000_000_000).unwrap();
    drop(s);
    // Reconstruct the exact durable INTENT boundary, not a claimed process/power cut.
    let db = rusqlite::Connection::open(path.join("ledger.sqlite3")).unwrap();
    db.execute("UPDATE operations SET committed=0", []).unwrap();
    db.execute(
        "UPDATE binding SET tip=?1,revision=?2",
        rusqlite::params![pin.as_slice(), 0u128.to_be_bytes().as_slice()],
    )
    .unwrap();
    drop(db);
    let mut s = Store::open(&path, &g, pin, Limits::default()).unwrap();
    assert_eq!(s.ledger().tip().height(), 0);
    assert!(s.operation(op(1)).unwrap().is_none());
    let o = s.accept(op(1), &raw, 2_000_000_000).unwrap();
    assert!(o.selected);
    assert_eq!(s.ledger().tip().height(), 1);
}
#[test]
fn wrong_pin_restore_marker_tamper_and_invalid_tail_refuse() {
    let (v, g, path) = fixture();
    let pin = genesis_id(&g);
    let mut s = Store::open(&path, &g, pin, Limits::default()).unwrap();
    let raw = b(&v["main_branch"][0]);
    let mut bad = raw.clone();
    bad[230] ^= 1;
    assert!(s.accept(op(1), &bad, 2_000_000_000).is_err());
    assert_eq!(s.revision(), 0);
    s.accept(op(1), &raw, 2_000_000_000).unwrap();
    drop(s);
    assert!(Store::open(&path, &g, [0; 32], Limits::default()).is_err());
    std::fs::write(path.join("RESTORING"), b"incomplete").unwrap();
    assert!(Store::open(&path, &g, pin, Limits::default()).is_err());
    let (v, g, path) = fixture();
    let pin = genesis_id(&g);
    let mut s = Store::open(&path, &g, pin, Limits::default()).unwrap();
    s.accept(op(1), &b(&v["main_branch"][0]), 2_000_000_000)
        .unwrap();
    drop(s);
    let db = rusqlite::Connection::open(path.join("ledger.sqlite3")).unwrap();
    db.execute("UPDATE blocks SET raw=zeroblob(length(raw))", [])
        .unwrap();
    drop(db);
    assert!(Store::open(&path, &g, pin, Limits::default()).is_err());
}
