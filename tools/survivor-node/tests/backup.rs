//! Encrypted no-value backup, exact intent recovery and explicit stale-state refusal.
use ed25519_dalek::SigningKey;
use rld_survivor_node::{
    backup,
    kernel::genesis_id,
    network::Network,
    store::{Limits, Store},
};
use serde_json::Value;
#[test]
fn complete_snapshot_pending_intent_freshness_and_authenticated_restore() {
    let v: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/survivor-v1/vectors.json"
    ))
    .unwrap();
    let g = hex::decode(v["genesis"]["manifest_hex"].as_str().unwrap()).unwrap();
    let pin = genesis_id(&g);
    let root = std::env::temp_dir().join(format!("rld-survivor-backup-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let mut s = Store::open(&root.join("live"), &g, pin, Limits::default()).unwrap();
    for (i, b) in v["main_branch"].as_array().unwrap()[..100]
        .iter()
        .enumerate()
    {
        let mut op = [0; 32];
        op[16..].copy_from_slice(&(i as u128 + 1).to_be_bytes());
        s.accept(
            op,
            &hex::decode(b["block_hex"].as_str().unwrap()).unwrap(),
            2_000_000_000,
        )
        .unwrap();
    }
    let n = Network::open(&root.join("live/contact"), pin, None).unwrap();
    let x = hex::decode(v["payment"]["transaction_hex"].as_str().unwrap()).unwrap();
    let review = s
        .review_transfer([199; 32], &x[..x.len() - 64], 2_000_000_000)
        .unwrap();
    let password = b"public no-value backup test passphrase";
    let image = root.join("image");
    let head = backup::create(&s, &n, &image, password, &[]).unwrap();
    assert_eq!(head, backup::state_head(&s, &n).unwrap());
    let restored = root.join("restored");
    backup::restore(&image, &restored, &g, pin, password, None).unwrap();
    let mut r = Store::open(&restored, &g, pin, Limits::default()).unwrap();
    assert_eq!(r.freshness().unwrap(), "FRESHNESS_UNKNOWN");
    assert_eq!(r.ledger().tip(), s.ledger().tip());
    assert!(r.signed_operation([199; 32]).unwrap().is_none());
    let key = SigningKey::from_bytes(
        &hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert!(r
        .sign_review([199; 32], review, &key, 2_000_000_000)
        .unwrap_err()
        .starts_with("FRESHNESS_UNKNOWN"));
    assert!(r
        .acknowledge_restore_risk(r.intent_head().unwrap(), false)
        .is_err());
    assert!(r.acknowledge_restore_risk([0; 32], true).is_err());
    r.acknowledge_restore_risk(r.intent_head().unwrap(), true)
        .unwrap();
    assert_eq!(
        r.sign_review([199; 32], review, &key, 2_000_000_000)
            .unwrap(),
        x
    );
    drop(r);
    let r = Store::open(&restored, &g, pin, Limits::default()).unwrap();
    assert_eq!(r.signed_operation([199; 32]).unwrap(), Some(x));
    let known = root.join("known");
    backup::restore(&image, &known, &g, pin, password, Some(head)).unwrap();
    let known = Store::open(&known, &g, pin, Limits::default()).unwrap();
    assert_eq!(known.freshness().unwrap(), "MATCHES_PROVIDED_HEAD");
    let stale = root.join("stale");
    assert!(backup::restore(&image, &stale, &g, pin, password, Some([0; 32])).is_err());
    assert!(stale.join("RESTORING").exists());
    assert!(Store::open(&stale, &g, pin, Limits::default()).is_err());
    assert!(backup::restore(&image, &restored, &g, pin, password, None).is_err());
    let mut corrupt = std::fs::read(image.join("3.sealed")).unwrap();
    corrupt[150] ^= 1;
    std::fs::write(image.join("3.sealed"), corrupt).unwrap();
    let damaged = root.join("damaged");
    assert!(backup::restore(&image, &damaged, &g, pin, password, None).is_err());
    assert!(damaged.join("RESTORING").exists());
}
