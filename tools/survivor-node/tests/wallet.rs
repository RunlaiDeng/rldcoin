//! RFC8032 public NO-VALUE fixture keys. Never use them for assets.
use ed25519_dalek::SigningKey;
use rld_survivor_node::{
    kernel::genesis_id,
    keyfile,
    store::{Limits, Store},
};
use serde_json::Value;
fn key() -> SigningKey {
    SigningKey::from_bytes(
        &hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap()
            .try_into()
            .unwrap(),
    )
}
fn op(n: u128) -> [u8; 32] {
    let mut x = [0; 32];
    x[16..].copy_from_slice(&n.to_be_bytes());
    x
}
#[test]
fn encrypted_key_authenticates_exact_header_password_chain_and_nonce() {
    let key = key();
    let chain = [1; 32];
    let a = keyfile::encrypt(&key, chain, b"public no-value test password").unwrap();
    let b = keyfile::encrypt(&key, chain, b"public no-value test password").unwrap();
    assert_eq!(a.len(), 187);
    assert_ne!(a, b);
    assert_eq!(
        keyfile::decrypt(&a, chain, b"public no-value test password")
            .unwrap()
            .verifying_key(),
        key.verifying_key()
    );
    assert!(keyfile::decrypt(&a, chain, b"wrong").is_err());
    assert!(keyfile::decrypt(&a, [2; 32], b"public no-value test password").is_err());
    for n in [0, 10, 15, 73, 100, 186] {
        let mut x = a.clone();
        x[n] ^= 1;
        assert!(keyfile::decrypt(&x, chain, b"public no-value test password").is_err());
    }
    assert!(keyfile::encrypt(&key, chain, b"").is_err());
    assert!(keyfile::encrypt(&key, chain, &[0xff]).is_err());
}
#[test]
fn review_reserved_before_sign_exact_retry_and_restart() {
    let v: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/survivor-v1/vectors.json"
    ))
    .unwrap();
    let g = hex::decode(v["genesis"]["manifest_hex"].as_str().unwrap()).unwrap();
    let pin = genesis_id(&g);
    let path = std::env::temp_dir().join(format!("rld-survivor-wallet-{}", std::process::id()));
    let mut s = Store::open(&path, &g, pin, Limits::default()).unwrap();
    let now = 2_000_000_000;
    for (i, x) in v["main_branch"].as_array().unwrap()[..100]
        .iter()
        .enumerate()
    {
        s.accept(
            op(i as u128 + 1),
            &hex::decode(x["block_hex"].as_str().unwrap()).unwrap(),
            now,
        )
        .unwrap();
    }
    let key = key();
    let owner = key.verifying_key().to_bytes();
    let payment = hex::decode(v["payment"]["transaction_hex"].as_str().unwrap()).unwrap();
    let u = &payment[..payment.len() - 64];
    let id = op(1001);
    let before = s.wallet_state(owner).unwrap();
    let digest = s.review_transfer(id, u, now).unwrap();
    let reserved = s.wallet_state(owner).unwrap();
    assert!(reserved.reserved > 0);
    assert_eq!(before.unspent, reserved.unspent);
    assert!(reserved.available < before.available);
    assert!(s.signed_operation(id).unwrap().is_none());
    assert!(s.review_transfer(op(1002), u, now).is_err());
    assert!(s.sign_review(id, [0; 32], &key, now).is_err());
    drop(s);
    let mut s = Store::open(&path, &g, pin, Limits::default()).unwrap();
    assert_eq!(reserved, s.wallet_state(owner).unwrap());
    assert!(s.signed_operation(id).unwrap().is_none());
    let x = s.sign_review(id, digest, &key, now).unwrap();
    assert_eq!(x, payment);
    assert_eq!(s.sign_review(id, digest, &key, now).unwrap(), x);
    drop(s);
    let mut s = Store::open(&path, &g, pin, Limits::default()).unwrap();
    assert_eq!(s.signed_operation(id).unwrap(), Some(x));
    assert!(s
        .accept(
            id,
            &hex::decode(v["main_branch"][100]["block_hex"].as_str().unwrap()).unwrap(),
            now
        )
        .is_err());
    assert!(s.waive_reservation(id, false).is_err());
    s.waive_reservation(id, true).unwrap();
    assert_eq!(s.wallet_state(owner).unwrap().reserved, 0);
}
