//! Bounded pool policy over published NO-VALUE transactions.
use rld_survivor_node::{
    kernel::genesis_id,
    store::{Limits, Store},
};
use serde_json::Value;
#[test]
fn pool_checks_signatures_waits_for_parent_and_never_spends_on_submission() {
    let v: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/survivor-v1/vectors.json"
    ))
    .unwrap();
    let g = hex::decode(v["genesis"]["manifest_hex"].as_str().unwrap()).unwrap();
    let pin = genesis_id(&g);
    let path = std::env::temp_dir().join(format!("rld-survivor-pool-{}", std::process::id()));
    let mut s = Store::open(&path, &g, pin, Limits::default()).unwrap();
    let now = 2_000_000_000;
    let p = hex::decode(v["payment"]["transaction_hex"].as_str().unwrap()).unwrap();
    let onward = hex::decode(v["onward"]["transaction_hex"].as_str().unwrap()).unwrap();
    let before = s.ledger().tip().clone();
    s.submit_transaction([1; 32], &p, now).unwrap();
    s.submit_transaction([2; 32], &onward, now).unwrap();
    assert_eq!(s.ledger().tip(), &before);
    assert!(s.template_transactions().unwrap().is_empty());
    assert!(s.submit_transaction([1; 32], &onward, now).is_err());
    let mut bad = p.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(s.submit_transaction([3; 32], &bad, now).is_err());
    for (i, b) in v["main_branch"].as_array().unwrap()[..100]
        .iter()
        .enumerate()
    {
        let mut id = [0; 32];
        id[16..].copy_from_slice(&(i as u128 + 1).to_be_bytes());
        s.accept(
            id,
            &hex::decode(b["block_hex"].as_str().unwrap()).unwrap(),
            now,
        )
        .unwrap();
    }
    assert_eq!(s.template_transactions().unwrap(), vec![p]);
    s.accept(
        [4; 32],
        &hex::decode(v["main_branch"][100]["block_hex"].as_str().unwrap()).unwrap(),
        now,
    )
    .unwrap();
    assert_eq!(s.template_transactions().unwrap(), vec![onward]);
    drop(s);
    let s = Store::open(&path, &g, pin, Limits::default()).unwrap();
    assert_eq!(s.template_transactions().unwrap().len(), 1);
}
