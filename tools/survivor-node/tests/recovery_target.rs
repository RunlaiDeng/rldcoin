//! Actual nonce search on a harder inherited target followed by single-node
//! recovery; timestamp setup is finite ground evidence, not a guaranteed deadline.
use rld_survivor_node::{
    kernel::genesis_id,
    store::{Limits, Store},
};
use serde_json::Value;
#[test]
fn survivor_recovery_reduces_actual_target_without_resetting_base_or_history() {
    let v: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/survivor-v1/vectors.json"
    ))
    .unwrap();
    let mut g = hex::decode(v["genesis"]["manifest_hex"].as_str().unwrap()).unwrap();
    getrandom::getrandom(&mut g[13..45]).unwrap();
    let pin = genesis_id(&g);
    let start = u64::from_be_bytes(g[45..53].try_into().unwrap());
    let now = start + 100_000;
    let root = std::env::temp_dir().join(format!("rld-survivor-target-{}", std::process::id()));
    let mut s = Store::open(&root, &g, pin, Limits::default()).unwrap();
    let miner = hex::decode(v["wallet_public_keys"][0].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    for h in 1u128..=145 {
        let mut job = s
            .ledger()
            .mining_job(miner, vec![], start + h as u64, now)
            .unwrap();
        let raw = job
            .attempt(1_000_000)
            .expect("finite fixture search budget");
        let mut op = [0; 32];
        op[16..].copy_from_slice(&h.to_be_bytes());
        s.accept(op, &raw, now).unwrap();
    }
    let prior = s.get_block(s.ledger().tip().id()).unwrap();
    assert!(prior[92..124] < g[53..85]);
    let tip = s.ledger().tip().clone();
    drop(s);
    let mut s = Store::open(&root, &g, pin, Limits::default()).unwrap();
    assert_eq!(s.ledger().tip(), &tip);
    let mut job = s.ledger().mining_job(miner, vec![], now, now).unwrap();
    let raw = job.attempt(1_000_000).unwrap();
    assert_eq!(&raw[36..68], tip.id());
    assert_eq!(&raw[92..124], &prior[92..124]);
    assert_eq!(&raw[124..156], &g[53..85]);
    s.accept([200; 32], &raw, now).unwrap();
    let before = u128::from_be_bytes(tip.work_bytes()[32..].try_into().unwrap());
    let after = u128::from_be_bytes(s.ledger().tip().work_bytes()[32..].try_into().unwrap());
    assert_eq!(after - before, 256);
    let mut job = s
        .ledger()
        .mining_job(miner, vec![], now + 1, now + 1)
        .unwrap();
    let next = job.attempt(1_000_000).unwrap();
    assert_eq!(&next[92..124], &prior[92..124]);
    assert_eq!(&next[124..156], &prior[92..124]);
    s.accept([201; 32], &next, now + 1).unwrap();
    assert_eq!(s.ledger().tip().height(), 147);
}
