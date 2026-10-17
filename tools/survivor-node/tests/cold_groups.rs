//! Public NO-VALUE batches. Faster cold notification reconstruction must retain
//! every original native block and complete change-set authentication check.
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
fn fixture() -> (Vec<u8>, PathBuf) {
    let v: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/survivor-v1/vectors.json"
    ))
    .unwrap();
    let g = hex::decode(v["genesis"]["manifest_hex"].as_str().unwrap()).unwrap();
    let root = std::env::temp_dir().join(format!(
        "rld-survivor-cold-groups-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut s = Store::open(&root, &g, genesis_id(&g), Limits::default()).unwrap();
    let blocks: Vec<_> = v["main_branch"].as_array().unwrap()[..64]
        .iter()
        .map(|b| hex::decode(b["block_hex"].as_str().unwrap()).unwrap())
        .collect();
    s.accept_history([1; 32], &blocks[..32], 2_000_000_000)
        .unwrap();
    s.accept_history([2; 32], &blocks[32..], 2_000_000_000)
        .unwrap();
    (g, root)
}
#[test]
fn cold_groups_reconstruct_the_complete_original_notifications() {
    let (g, root) = fixture();
    let pin = genesis_id(&g);
    let s = Store::open(&root, &g, pin, Limits::default()).unwrap();
    let events = s.changes_since(0).unwrap();
    let tip = s.ledger().tip().clone();
    let coins = s.ledger().coins().clone();
    assert_eq!(events["changes"].as_array().unwrap().len(), 2);
    for e in events["changes"].as_array().unwrap() {
        assert_eq!(e["attached"].as_array().unwrap().len(), 32);
        assert!(e["detached"].as_array().unwrap().is_empty());
    }
    drop(s);
    let s = Store::open(&root, &g, pin, Limits::default()).unwrap();
    assert_eq!(s.changes_since(0).unwrap(), events);
    assert_eq!(s.ledger().tip(), &tip);
    assert_eq!(s.ledger().coins(), &coins);
}
#[test]
fn changed_attached_detached_reward_or_output_set_never_passes_cold_replay() {
    for case in 0..4 {
        let (g, root) = fixture();
        let db = rusqlite::Connection::open(root.join("ledger.sqlite3")).unwrap();
        let raw: String = db
            .query_row(
                "SELECT body FROM changes WHERE revision=?1",
                [2u128.to_be_bytes().as_slice()],
                |r| r.get(0),
            )
            .unwrap();
        let mut event: Value = serde_json::from_str(&raw).unwrap();
        match case {
            0 => {
                event["attached"].as_array_mut().unwrap().swap(0, 1);
            }
            1 => {
                event["detached"] = serde_json::json!([event["attached"][0].clone()]);
            }
            2 => {
                event["attached"][0]["reward"]["amount"] = Value::String("1".into());
            }
            _ => {
                event["changed_outputs"]
                    .as_array_mut()
                    .unwrap()
                    .pop()
                    .unwrap();
            }
        }
        db.execute(
            "UPDATE changes SET body=?1 WHERE revision=?2",
            rusqlite::params![event.to_string(), 2u128.to_be_bytes().as_slice()],
        )
        .unwrap();
        drop(db);
        assert!(
            Store::open(&root, &g, genesis_id(&g), Limits::default()).is_err(),
            "case {case}"
        );
    }
}
#[test]
fn a_corrupt_non_tail_member_still_requires_full_native_execution() {
    let (g, root) = fixture();
    let db = rusqlite::Connection::open(root.join("ledger.sqlite3")).unwrap();
    let (id, mut raw): (Vec<u8>, Vec<u8>) = db
        .query_row(
            "SELECT id,raw FROM blocks WHERE substr(raw,69,16)=?1",
            [33u128.to_be_bytes().as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let last = raw.len() - 1;
    raw[last] ^= 1;
    db.execute(
        "UPDATE blocks SET raw=?1 WHERE id=?2",
        rusqlite::params![raw, id],
    )
    .unwrap();
    drop(db);
    assert!(Store::open(&root, &g, genesis_id(&g), Limits::default()).is_err());
}
