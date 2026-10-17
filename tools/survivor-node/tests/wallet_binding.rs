//! Public NO-VALUE fixture keys exercise exact caller review binding under hot
//! journal corruption. No altered intent or unchecked recovery may release X.
use ed25519_dalek::SigningKey;
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
fn fixture() -> (Store, Vec<u8>, SigningKey, Value, PathBuf) {
    let v: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/survivor-v1/vectors.json"
    ))
    .unwrap();
    let g = hex::decode(v["genesis"]["manifest_hex"].as_str().unwrap()).unwrap();
    let root = std::env::temp_dir().join(format!(
        "rld-survivor-wallet-binding-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut s = Store::open(&root, &g, genesis_id(&g), Limits::default()).unwrap();
    let blocks: Vec<_> = v["main_branch"].as_array().unwrap()[..100]
        .iter()
        .map(|b| hex::decode(b["block_hex"].as_str().unwrap()).unwrap())
        .collect();
    for (i, group) in blocks.chunks(32).enumerate() {
        s.accept_history([i as u8 + 1; 32], group, 2_000_000_000)
            .unwrap();
    }
    let x = hex::decode(v["payment"]["transaction_hex"].as_str().unwrap()).unwrap();
    let key = SigningKey::from_bytes(
        &hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap()
            .try_into()
            .unwrap(),
    );
    (s, x, key, v, root)
}
#[test]
fn changed_recipient_cannot_reuse_the_original_caller_review_digest() {
    let (mut s, x, key, v, root) = fixture();
    let u = &x[..x.len() - 64];
    let digest = s.review_transfer([90; 32], u, 2_000_000_000).unwrap();
    let mut changed = u.to_vec();
    changed[104..136]
        .copy_from_slice(&hex::decode(v["wallet_public_keys"][2].as_str().unwrap()).unwrap());
    let db = rusqlite::Connection::open(root.join("ledger.sqlite3")).unwrap();
    db.execute(
        "UPDATE wallet SET unsigned=?1 WHERE id=?2",
        rusqlite::params![changed, [90u8; 32].as_slice()],
    )
    .unwrap();
    drop(db);
    assert!(s
        .sign_review([90; 32], digest, &key, 2_000_000_000)
        .is_err());
    let db = rusqlite::Connection::open(root.join("ledger.sqlite3")).unwrap();
    assert!(db
        .query_row(
            "SELECT signed IS NULL FROM wallet WHERE id=?1",
            [[90u8; 32].as_slice()],
            |r| r.get::<_, bool>(0)
        )
        .unwrap());
    assert!(!s.storage_ready());
}
#[test]
fn recovery_rejects_altered_signature_or_another_valid_signed_intent() {
    for other in [false, true] {
        let (mut s, x, key, v, root) = fixture();
        let u = &x[..x.len() - 64];
        let digest = s.review_transfer([91; 32], u, 2_000_000_000).unwrap();
        let mut signed = s
            .sign_review([91; 32], digest, &key, 2_000_000_000)
            .unwrap();
        if other {
            signed = hex::decode(v["onward"]["transaction_hex"].as_str().unwrap()).unwrap();
        } else {
            let last = signed.len() - 1;
            signed[last] ^= 1;
        }
        let db = rusqlite::Connection::open(root.join("ledger.sqlite3")).unwrap();
        db.execute(
            "UPDATE wallet SET signed=?1 WHERE id=?2",
            rusqlite::params![signed, [91u8; 32].as_slice()],
        )
        .unwrap();
        drop(db);
        assert!(s.signed_operation([91; 32]).is_err());
        assert!(s.payment_operation([91; 32]).is_err());
        assert!(!s.storage_ready());
    }
}

#[test]
fn signing_cannot_release_bytes_when_the_exact_journal_update_did_not_happen() {
    let (mut s, x, key, _, root) = fixture();
    let u = &x[..x.len() - 64];
    let digest = s.review_transfer([92; 32], u, 2_000_000_000).unwrap();
    let db = rusqlite::Connection::open(root.join("ledger.sqlite3")).unwrap();
    db.execute_batch("CREATE TRIGGER refuse_signature BEFORE UPDATE OF signed ON wallet BEGIN SELECT RAISE(IGNORE); END;").unwrap();
    drop(db);
    assert!(s
        .sign_review([92; 32], digest, &key, 2_000_000_000)
        .is_err());
    let db = rusqlite::Connection::open(root.join("ledger.sqlite3")).unwrap();
    assert!(db
        .query_row(
            "SELECT signed IS NULL FROM wallet WHERE id=?1",
            [[92u8; 32].as_slice()],
            |r| r.get::<_, bool>(0)
        )
        .unwrap());
    assert!(!s.storage_ready());
}

#[test]
fn wrong_caller_digest_does_not_poison_an_intact_review() {
    let (mut s, x, key, _, _) = fixture();
    let u = &x[..x.len() - 64];
    let digest = s.review_transfer([93; 32], u, 2_000_000_000).unwrap();
    let mut wrong = digest;
    wrong[0] ^= 1;
    assert!(s
        .sign_review([93; 32], wrong, &key, 2_000_000_000)
        .unwrap_err()
        .starts_with("INVALID_CRYPTO"));
    assert!(s.storage_ready());
    assert!(s.signed_operation([93; 32]).unwrap().is_none());
    assert_eq!(
        s.sign_review([93; 32], digest, &key, 2_000_000_000)
            .unwrap(),
        x
    );
}

#[test]
fn signing_rechecks_the_exact_bytes_retained_by_the_committed_update() {
    let (mut s, x, key, _, root) = fixture();
    let digest = s
        .review_transfer([94; 32], &x[..x.len() - 64], 2_000_000_000)
        .unwrap();
    let db = rusqlite::Connection::open(root.join("ledger.sqlite3")).unwrap();
    db.execute_batch("CREATE TRIGGER damage_signature AFTER UPDATE OF signed ON wallet BEGIN UPDATE wallet SET signed=zeroblob(length(NEW.signed)) WHERE id=NEW.id; END;").unwrap();
    drop(db);
    assert!(s
        .sign_review([94; 32], digest, &key, 2_000_000_000)
        .is_err());
    assert!(!s.storage_ready());
}
