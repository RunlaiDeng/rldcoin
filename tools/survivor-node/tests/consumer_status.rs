//! Public NO-VALUE selected history exercises consumer status and corruption
//! refusal. A query must never first-sign or change selected monetary state.
use rld_survivor_node::{
    kernel::{genesis_id, Ledger},
    store::{Limits, Store},
};
use serde_json::Value;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn fixture(height: usize) -> (Store, Value, PathBuf) {
    let v: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/survivor-v1/vectors.json"
    ))
    .unwrap();
    let g = hex::decode(v["genesis"]["manifest_hex"].as_str().unwrap()).unwrap();
    let root = std::env::temp_dir().join(format!(
        "rld-survivor-consumer-status-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut s = Store::open(&root, &g, genesis_id(&g), Limits::default()).unwrap();
    let blocks: Vec<_> = v["main_branch"].as_array().unwrap()[..height]
        .iter()
        .map(|b| hex::decode(b["block_hex"].as_str().unwrap()).unwrap())
        .collect();
    for (i, group) in blocks.chunks(32).enumerate() {
        s.accept_history([i as u8 + 1; 32], group, 2_000_000_000)
            .unwrap();
    }
    (s, v, root)
}
fn transaction(v: &Value, name: &str) -> Vec<u8> {
    hex::decode(v[name]["transaction_hex"].as_str().unwrap()).unwrap()
}
#[test]
fn transfer_outputs_report_current_local_reservation_and_explicit_waiver() {
    let (mut s, v, _) = fixture(101);
    let payment = transaction(&v, "payment");
    let onward = transaction(&v, "onward");
    let owner = hex::decode(v["wallet_public_keys"][1].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let revision = s.revision();
    assert_eq!(
        s.transfer_observation(&payment).unwrap()["outputs"][0]["reserved"],
        false
    );
    s.review_transfer([77; 32], &onward[..onward.len() - 64], 2_000_000_000)
        .unwrap();
    assert_eq!(s.wallet_state(owner).unwrap().reserved, 100);
    let observed = s.transfer_observation(&payment).unwrap();
    assert_eq!(observed["outputs"][0]["reserved"], true);
    assert_eq!(observed["outputs"][0]["eligible_next_height"], true);
    assert_eq!(observed["outputs"][0]["maturity_height"], "101");
    s.waive_reservation([77; 32], true).unwrap();
    assert_eq!(
        s.transfer_observation(&payment).unwrap()["outputs"][0]["reserved"],
        false
    );
    assert_eq!(s.wallet_state(owner).unwrap().available, 100);
    assert_eq!(s.revision(), revision);
}
#[test]
fn spent_output_retains_known_selected_maturity_and_is_ineligible() {
    let (s, v, _) = fixture(102);
    let observed = s.transfer_observation(&transaction(&v, "payment")).unwrap();
    assert_eq!(observed["ledger"], "INCLUDED");
    assert_eq!(observed["outputs"][0]["state"], "SPENT");
    assert_eq!(observed["outputs"][0]["maturity_height"], "101");
    assert_eq!(observed["outputs"][0]["eligible_next_height"], false);
    assert_eq!(observed["outputs"][0]["reserved"], false);
}
#[test]
fn reviewed_intent_observes_external_inclusion_without_first_signing() {
    let (mut s, v, root) = fixture(101);
    let onward = transaction(&v, "onward");
    let digest = s
        .review_transfer([78; 32], &onward[..onward.len() - 64], 2_000_000_000)
        .unwrap();
    let next = hex::decode(v["main_branch"][101]["block_hex"].as_str().unwrap()).unwrap();
    s.accept([79; 32], &next, 2_000_000_000).unwrap();
    let revision = s.revision();
    let tip = s.ledger().tip().clone();
    let observed = s.payment_operation([78; 32]).unwrap().unwrap();
    assert_eq!(observed["ledger"], "INCLUDED");
    assert_eq!(observed["local_intent"], "REVIEWED");
    assert_eq!(observed["review_digest"], hex::encode(digest));
    assert!(s.signed_operation([78; 32]).unwrap().is_none());
    assert_eq!(s.revision(), revision);
    assert_eq!(s.ledger().tip(), &tip);
    drop(s);
    let g = hex::decode(v["genesis"]["manifest_hex"].as_str().unwrap()).unwrap();
    let s = Store::open(&root, &g, genesis_id(&g), Limits::default()).unwrap();
    assert_eq!(
        s.payment_operation([78; 32]).unwrap().unwrap()["ledger"],
        "INCLUDED"
    );
    assert!(s.signed_operation([78; 32]).unwrap().is_none());
}
#[test]
fn hot_body_corruption_refuses_objects_and_suspends_monetary_mutation() {
    let (mut s, v, root) = fixture(101);
    let tip = s.ledger().tip().clone();
    let mut raw = s.get_block(tip.id()).unwrap();
    let last = raw.len() - 1;
    raw[last] ^= 1;
    let db = rusqlite::Connection::open(root.join("ledger.sqlite3")).unwrap();
    db.execute(
        "UPDATE blocks SET raw=?1 WHERE id=?2",
        rusqlite::params![raw, tip.id().as_slice()],
    )
    .unwrap();
    drop(db);
    assert!(s.get_block(tip.id()).is_err());
    let next = hex::decode(v["main_branch"][101]["block_hex"].as_str().unwrap()).unwrap();
    assert!(s
        .accept([80; 32], &next, 2_000_000_000)
        .unwrap_err()
        .starts_with("RESOURCE_WAIT"));
    assert_eq!(s.ledger().tip(), &tip);
    assert!(s.transfer_observation(&transaction(&v, "payment")).is_err());
}
#[test]
fn missing_object_request_does_not_suspend_healthy_progress() {
    let (mut s, v, _) = fixture(101);
    assert!(s
        .get_block([253; 32])
        .unwrap_err()
        .starts_with("MISSING_HISTORY"));
    let next = hex::decode(v["main_branch"][101]["block_hex"].as_str().unwrap()).unwrap();
    s.accept([81; 32], &next, 2_000_000_000).unwrap();
    assert_eq!(s.ledger().tip().height(), 102);
}

#[test]
fn missing_known_selected_tip_suspends_monetary_mutation() {
    let (mut s, v, root) = fixture(101);
    let tip = s.ledger().tip().clone();
    let db = rusqlite::Connection::open(root.join("ledger.sqlite3")).unwrap();
    db.execute("DELETE FROM blocks WHERE id=?1", [tip.id().as_slice()])
        .unwrap();
    drop(db);
    assert!(s
        .get_block(tip.id())
        .unwrap_err()
        .starts_with("MISSING_HISTORY"));
    assert!(!s.storage_ready());
    let next = hex::decode(v["main_branch"][101]["block_hex"].as_str().unwrap()).unwrap();
    assert!(s
        .accept([82; 32], &next, 2_000_000_000)
        .unwrap_err()
        .starts_with("RESOURCE_WAIT"));
    assert_eq!(s.ledger().tip(), &tip);
}

#[test]
fn a_restored_selected_output_restores_its_unwaived_reservation() {
    let (mut s, v, _) = fixture(101);
    let payment = transaction(&v, "payment");
    let onward = transaction(&v, "onward");
    let owner = hex::decode(v["wallet_public_keys"][1].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    s.review_transfer([77; 32], &onward[..onward.len() - 64], 2_000_000_000)
        .unwrap();
    let miner = hex::decode(v["wallet_public_keys"][0].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let g = hex::decode(v["genesis"]["manifest_hex"].as_str().unwrap()).unwrap();
    let mut fork = Ledger::from_genesis(&g, genesis_id(&g), Limits::default().coins).unwrap();
    for b in &v["main_branch"].as_array().unwrap()[..100] {
        fork.execute(&hex::decode(b["block_hex"].as_str().unwrap()).unwrap())
            .unwrap();
    }
    // This branch removes the payment without consuming its common-ancestor
    // input. The separate public conflicting branch correctly forbids reoffer.
    for i in 0..3 {
        let mut job = fork
            .mining_job(miner, vec![], fork.tip().timestamp() + 600, 2_000_000_000)
            .unwrap();
        let b = job.attempt(1_000_000).unwrap();
        fork.execute(&b).unwrap();
        s.accept([100 + i; 32], &b, 2_000_000_000).unwrap();
    }
    assert_eq!(
        s.transfer_observation(&payment).unwrap()["ledger"],
        "DETACHED"
    );
    assert_eq!(s.wallet_state(owner).unwrap().reserved, 0);
    let mut job = s
        .ledger()
        .mining_job(
            miner,
            vec![payment.clone()],
            s.ledger().tip().timestamp() + 1,
            2_000_000_000,
        )
        .unwrap();
    let b = job.attempt(1_000_000).unwrap();
    s.accept([83; 32], &b, 2_000_000_000).unwrap();
    let observed = s.transfer_observation(&payment).unwrap();
    assert_eq!(observed["ledger"], "INCLUDED");
    assert_eq!(observed["outputs"][0]["reserved"], true);
    assert_eq!(
        observed["outputs"][0]["maturity_height"],
        s.ledger().tip().height().to_string()
    );
    assert_eq!(s.wallet_state(owner).unwrap().reserved, 100);
    assert!(s.signed_operation([77; 32]).unwrap().is_none());
}
