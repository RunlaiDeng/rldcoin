//! Public no-value vectors exercise losing descendants, reservations and replay.
use ed25519_dalek::SigningKey;
use rld_survivor_node::{
    kernel::genesis_id,
    store::{Limits, Store},
};
use serde_json::Value;
fn op(n: u128) -> [u8; 32] {
    let mut b = [0; 32];
    b[16..].copy_from_slice(&n.to_be_bytes());
    b
}
fn raw(v: &Value) -> Vec<u8> {
    hex::decode(v["block_hex"].as_str().unwrap()).unwrap()
}
#[test]
fn detached_payment_and_rewards_are_visible_and_original_bytes_reoffered() {
    let v: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/survivor-v1/vectors.json"
    ))
    .unwrap();
    let g = hex::decode(v["genesis"]["manifest_hex"].as_str().unwrap()).unwrap();
    let pin = genesis_id(&g);
    let root =
        std::env::temp_dir().join(format!("rld-survivor-observations-{}", std::process::id()));
    let mut s = Store::open(&root, &g, pin, Limits::default()).unwrap();
    let now = 2_000_000_000;
    for (i, b) in v["main_branch"].as_array().unwrap()[..100]
        .iter()
        .enumerate()
    {
        s.accept(op(i as u128 + 1), &raw(b), now).unwrap();
    }
    let x = hex::decode(v["payment"]["transaction_hex"].as_str().unwrap()).unwrap();
    let key = SigningKey::from_bytes(
        &hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let digest = s.review_transfer(op(999), &x[..x.len() - 64], now).unwrap();
    s.sign_review(op(999), digest, &key, now).unwrap();
    for (i, b) in v["main_branch"].as_array().unwrap()[100..]
        .iter()
        .enumerate()
    {
        s.accept(op(i as u128 + 101), &raw(b), now).unwrap();
    }
    assert_eq!(
        s.payment_operation(op(999)).unwrap().unwrap()["ledger"],
        "INCLUDED"
    );
    let rev = s.revision();
    for (i, b) in v["alternative_branch"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        s.accept(op(i as u128 + 2000), &raw(b), now).unwrap();
    }
    let change = s.changes_since(rev).unwrap();
    assert!(change["changes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| !c["detached"].as_array().unwrap().is_empty()));
    let observed = s.payment_operation(op(999)).unwrap().unwrap();
    assert_eq!(observed["ledger"], "DETACHED");
    assert!(observed["inclusion"].is_null());
    s.reoffer_pending().unwrap();
    let id = hex::decode(observed["transaction_id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(s.get_transaction(id).unwrap(), x);
    assert_eq!(
        s.ledger().coins().values().map(|c| c.amount).sum::<u128>(),
        s.ledger().issued()
    );
    let last = s.revision();
    drop(s);
    let s = Store::open(&root, &g, pin, Limits::default()).unwrap();
    assert_eq!(s.revision(), last);
    assert_eq!(
        s.payment_operation(op(999)).unwrap().unwrap()["ledger"],
        "DETACHED"
    );
    assert_eq!(s.changes_since(rev).unwrap(), change);
}
