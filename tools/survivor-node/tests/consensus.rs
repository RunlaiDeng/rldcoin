//! Public NO-VALUE specification fixtures, never generated production custody.
use rld_survivor_node::kernel::{genesis_id, issuance, Ledger};
use serde_json::Value;
fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../docs/protocol/survivor-v1/vectors.json"
    ))
    .unwrap()
}
fn raw(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(v[k].as_str().unwrap()).unwrap()
}
fn fresh(v: &Value, capacity: usize) -> Ledger {
    let g = raw(&v["genesis"], "manifest_hex");
    Ledger::from_genesis(&g, genesis_id(&g), capacity).unwrap()
}
fn step(l: &mut Ledger, b: &Value) {
    l.execute(&raw(b, "block_hex")).unwrap();
    assert_eq!(hex::encode(l.tip().id()), b["block_id"].as_str().unwrap());
    assert_eq!(
        hex::encode(l.tip().root()),
        b["state_root"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(l.tip().work_bytes()),
        b["cumulative_work_hex"].as_str().unwrap()
    );
    assert_eq!(l.issued().to_string(), b["issued"].as_str().unwrap());
}
#[test]
fn all_branches_roots_work_issuance_and_reorg() {
    let v = vectors();
    let mut main = fresh(&v, 1000);
    let mut fork = None;
    for b in v["main_branch"].as_array().unwrap() {
        step(&mut main, b);
        if main.tip().height() == 100 {
            fork = Some(main.clone());
        }
    }
    let mut alt = fork.unwrap();
    for b in v["alternative_branch"].as_array().unwrap() {
        step(&mut alt, b);
    }
    assert!(alt.tip().preferred_to(main.tip()));
    assert_eq!(
        hex::encode(alt.tip().id()),
        v["selection"]["greater_work_winner"]
    );
    let mut recovery = fresh(&v, 1000);
    for b in v["recovery_branch_from_genesis"].as_array().unwrap() {
        step(&mut recovery, b);
    }
    for b in v["issuance"].as_array().unwrap() {
        let (sub, issued) = issuance(b["height"].as_str().unwrap().parse().unwrap());
        assert_eq!(sub.to_string(), b["subsidy"]);
        assert_eq!(issued.to_string(), b["issued"]);
    }
    assert_eq!(
        main.coins().values().map(|c| c.amount).sum::<u128>(),
        main.issued()
    );
}
#[test]
fn malformed_block_is_atomic_and_clock_is_not_intrinsic_validity() {
    let v = vectors();
    let mut l = fresh(&v, 1000);
    let block = raw(&v["main_branch"][0], "block_hex");
    for i in 0..block.len() {
        let mut changed = block.clone();
        changed[i] ^= 1;
        let before = l.tip().clone();
        let coins = l.coins().clone();
        assert!(l.execute(&changed).is_err(), "offset {i}");
        assert_eq!(*l.tip(), before);
        assert_eq!(*l.coins(), coins);
    }
    for n in 0..block.len() {
        assert!(l.execute(&block[..n]).is_err());
    }
    let mut trailing = block.clone();
    trailing.push(0);
    assert!(l.execute(&trailing).is_err());
    l.execute(&block).unwrap();
    let t = l.tip().timestamp();
    assert!(!l.tip().eligible(t - 7201));
    assert!(l.tip().eligible(t - 7200));
}
#[test]
fn genesis_pin_monetary_refusal_and_resource_atomicity() {
    let v = vectors();
    let g = raw(&v["genesis"], "manifest_hex");
    assert!(Ledger::from_genesis(&g, [0; 32], 10).is_err());
    let mut monetary = g.clone();
    monetary[12] = 1;
    assert!(Ledger::from_genesis(&monetary, genesis_id(&monetary), 10).is_err());
    let mut l = fresh(&v, 1);
    step(&mut l, &v["main_branch"][0]);
    let before = l.tip().clone();
    assert!(l
        .execute(&raw(&v["main_branch"][1], "block_hex"))
        .unwrap_err()
        .contains("RESOURCE_WAIT"));
    assert_eq!(*l.tip(), before);
}
#[test]
fn signed_payment_maturity_onward_and_bad_signatures() {
    let v = vectors();
    let mut l = fresh(&v, 1000);
    let p = raw(&v["payment"], "transaction_hex");
    for b in &v["main_branch"].as_array().unwrap()[..99] {
        step(&mut l, b);
    }
    assert!(l.validate_transfer(&p).unwrap_err().contains("MATURITY"));
    step(&mut l, &v["main_branch"][99]);
    assert!(l.validate_transfer(&p).is_ok());
    for n in v["negative_transfers"].as_array().unwrap() {
        assert!(
            l.validate_transfer(&raw(n, "transaction_hex")).is_err(),
            "{}",
            n["name"]
        );
    }
    step(&mut l, &v["main_branch"][100]);
    assert!(l.validate_transfer(&p).is_err());
    assert!(l
        .validate_transfer(&raw(&v["onward"], "transaction_hex"))
        .is_ok());
    step(&mut l, &v["main_branch"][101]);
}
#[test]
fn mining_uses_normal_validator_and_finite_jobs() {
    let v = vectors();
    let mut l = fresh(&v, 1000);
    let miner = hex::decode(v["wallet_public_keys"][0].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let time = l.tip().timestamp() + 600;
    let mut job = l.mining_job(miner, vec![], time, time).unwrap();
    assert!(job.attempt(0).is_none());
    let raw = job.attempt(100000).expect("public finite mining budget");
    l.execute(&raw).unwrap();
    assert_eq!(l.tip().height(), 1);
    assert_eq!(
        raw,
        hex::decode(v["main_branch"][0]["block_hex"].as_str().unwrap()).unwrap()
    );
}
