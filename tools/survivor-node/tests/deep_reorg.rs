//! Native deep-reorganization fixture with public NO-VALUE keys and logical
//! historical timestamps. Not independent custody or physical-route qualification.
use ed25519_dalek::SigningKey;
use rld_survivor_node::{
    kernel::{genesis_id, Hash, Ledger},
    store::{Limits, Store},
};
use sha2::{Digest, Sha256};
use std::time::Instant;
const NOW: u64 = 2_000_000_000;
const START: u64 = 1_000_000;
fn op(branch: u8, height: u128) -> Hash {
    Sha256::digest(
        [
            b"PUBLIC NO-VALUE DEEP FORK OP".as_slice(),
            &[branch],
            &height.to_be_bytes(),
        ]
        .concat(),
    )
    .into()
}
fn txid(raw: &[u8]) -> Hash {
    Sha256::digest([b"RLD-SURVIVOR-1/TXID\0".as_slice(), &raw[..raw.len() - 64]].concat()).into()
}
fn block(ledger: &Ledger, miner: Hash, txs: Vec<Vec<u8>>, height: u128) -> Vec<u8> {
    let mut job = ledger
        .mining_job(miner, txs, START + height as u64 * 600, NOW)
        .unwrap();
    job.attempt(1_000_000).expect("finite actual nonce budget")
}
fn output(raw: &[u8]) -> Vec<u8> {
    let mut point = txid(raw).to_vec();
    point.extend(0u16.to_be_bytes());
    point
}
fn reward(raw: &[u8]) -> Vec<u8> {
    let id: Hash = Sha256::digest(
        [
            b"RLD-SURVIVOR-1/REWARD\0".as_slice(),
            &raw[4..84],
            &raw[156..220],
        ]
        .concat(),
    )
    .into();
    let mut point = id.to_vec();
    point.extend(0u16.to_be_bytes());
    point
}
fn pay(store: &mut Store, key: &SigningKey, to: Hash, operation: Hash, input: &[u8]) -> Vec<u8> {
    let coin = store
        .ledger()
        .coins()
        .get(input)
        .expect("explicit fixture input absent");
    assert_eq!(coin.owner, key.verifying_key().to_bytes());
    assert!(coin.maturity <= store.ledger().tip().height() + 1 && coin.amount > 1);
    let mut u = 1u16.to_be_bytes().to_vec();
    u.extend(store.ledger().chain_id());
    u.extend(coin.owner);
    u.extend(1u16.to_be_bytes());
    u.extend(input);
    u.extend(1u16.to_be_bytes());
    u.extend(to);
    u.extend((coin.amount - 1).to_be_bytes());
    u.extend(1u128.to_be_bytes());
    u.extend(u128::MAX.to_be_bytes());
    let digest = store.review_transfer(operation, &u, NOW).unwrap();
    store.sign_review(operation, digest, key, NOW).unwrap()
}
fn detached(store: &Store) {
    for operation in [op(11, 165), op(12, 166)] {
        let state = store.payment_operation(operation).unwrap().unwrap();
        assert_eq!(state["ledger"], "DETACHED");
        assert_eq!(state["readiness"], "WAITING_FOR_HISTORY");
        assert_eq!(state["local_intent"], "SIGNED");
        assert_eq!(state["signature_source"], "LOCAL_WALLET");
        assert!(state["inclusion"].is_null());
        for output in state["outputs"].as_array().unwrap() {
            assert_eq!(output["state"], "ABSENT");
            assert_ne!(output["eligible_next_height"], true);
            assert_eq!(output["reserved"], false);
        }
    }
}
#[test]
fn deep_reorg_preserves_original_intents_and_allows_explicit_winning_payments() {
    let started = Instant::now();
    let check = || {
        assert!(
            started.elapsed().as_secs_f64() <= 180.0,
            "original whole180 budget"
        )
    };
    let root = std::env::temp_dir().join(format!("rld-survivor-deep-reorg-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let mut genesis = b"RLDSGEN1".to_vec();
    genesis.extend(1u16.to_be_bytes());
    genesis.extend(1u16.to_be_bytes());
    genesis.push(0);
    let mut nonce = [0; 32];
    getrandom::getrandom(&mut nonce).unwrap();
    genesis.extend(nonce);
    genesis.extend(START.to_be_bytes());
    genesis.push(0);
    genesis.extend([255; 31]);
    std::fs::write(root.join("genesis.bin"), &genesis).unwrap();
    let pin = genesis_id(&genesis);
    let a = SigningKey::from_bytes(&[51; 32]);
    let b = SigningKey::from_bytes(&[52; 32]);
    let c = SigningKey::from_bytes(&[53; 32]);
    let d = SigningKey::from_bytes(&[54; 32]);
    let pa = a.verifying_key().to_bytes();
    let pb = b.verifying_key().to_bytes();
    let pc = c.verifying_key().to_bytes();
    let pd = d.verifying_key().to_bytes();
    let mut store = Store::open(&root.join("node"), &genesis, pin, Limits::default()).unwrap();
    let mut common = None;
    let mut old_reward: Option<Vec<u8>> = None;
    let mut first = None;
    let mut second = None;
    for height in 1u128..=240 {
        check();
        let mut txs = Vec::new();
        if height == 165 {
            let x = pay(
                &mut store,
                &a,
                pb,
                op(11, height),
                old_reward.as_ref().unwrap(),
            );
            first = Some(x.clone());
            txs.push(x);
        }
        if height == 166 {
            let x = pay(
                &mut store,
                &b,
                pc,
                op(12, height),
                &output(first.as_ref().unwrap()),
            );
            second = Some(x.clone());
            txs.push(x);
        }
        let raw = block(store.ledger(), pa, txs, height);
        store.accept(op(1, height), &raw, NOW).unwrap();
        if height == 65 {
            old_reward = Some(reward(&raw));
        }
        if height == 64 {
            common = Some(store.ledger().clone());
        }
    }
    let first = first.unwrap();
    let second = second.unwrap();
    for operation in [op(11, 165), op(12, 166)] {
        assert_eq!(
            store.payment_operation(operation).unwrap().unwrap()["ledger"],
            "INCLUDED"
        );
    }
    assert!(store.wallet_state(pc).unwrap().available > 0);
    let before = store.revision();

    let mut fork = common.unwrap();
    let raw65 = block(&fork, pd, vec![], 65);
    let mut ahead = fork.clone();
    ahead.execute(&raw65).unwrap();
    let raw66 = block(&ahead, pd, vec![], 66);
    let original_tip = store.ledger().tip().clone();
    let original_coins = store.ledger().coins().clone();
    let missing = store.accept(op(2, 66), &raw66, NOW).unwrap_err();
    assert!(missing.starts_with("MISSING_HISTORY"));
    assert_eq!(store.ledger().tip(), &original_tip);
    assert_eq!(store.ledger().coins(), &original_coins);
    assert_eq!(store.revision(), before);
    assert!(store.operation(op(2, 66)).unwrap().is_none());
    assert!(store.storage_ready());
    for height in 65u128..=251 {
        check();
        let raw = if height == 65 {
            raw65.clone()
        } else if height == 66 {
            raw66.clone()
        } else {
            block(&fork, pd, vec![], height)
        };
        fork.execute(&raw).unwrap();
        store.accept(op(2, height), &raw, NOW).unwrap();
    }
    check();
    assert_eq!(store.ledger().tip(), fork.tip());
    assert_eq!(store.ledger().coins(), fork.coins());
    let changes = store.changes_since(before).unwrap();
    let depth = changes["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["detached"].as_array().unwrap().len())
        .max()
        .unwrap();
    assert!(depth > 144);
    detached(&store);
    assert_eq!(store.wallet_state(pc).unwrap().available, 0);
    store.reoffer_pending().unwrap();
    assert_eq!(
        store.signed_operation(op(11, 165)).unwrap(),
        Some(first.clone())
    );
    assert_eq!(
        store.signed_operation(op(12, 166)).unwrap(),
        Some(second.clone())
    );
    for raw in [&first, &second] {
        assert_eq!(store.get_transaction(txid(raw)).unwrap(), *raw);
    }
    // A missing old input cannot be silently replaced using another current coin.
    let refused = store
        .review_transfer(op(21, 252), &first[..first.len() - 64], NOW)
        .unwrap_err();
    assert!(refused.contains("WAITING_FOR_INPUT"));
    assert!(store.storage_ready());
    assert!(store.signed_operation(op(21, 252)).unwrap().is_none());
    assert!(store.template_transactions().unwrap().is_empty());

    let win_first = pay(&mut store, &d, pc, op(13, 252), &reward(&raw65));
    store
        .submit_transaction(op(14, 252), &win_first, NOW)
        .unwrap();
    let template = store.template_transactions().unwrap();
    assert_eq!(template, vec![win_first.clone()]);
    let raw = block(store.ledger(), pd, template, 252);
    store.accept(op(3, 252), &raw, NOW).unwrap();
    let win_second = pay(&mut store, &c, pb, op(15, 253), &output(&win_first));
    store
        .submit_transaction(op(16, 253), &win_second, NOW)
        .unwrap();
    let template = store.template_transactions().unwrap();
    assert_eq!(template, vec![win_second.clone()]);
    let raw = block(store.ledger(), pd, template, 253);
    store.accept(op(3, 253), &raw, NOW).unwrap();
    detached(&store);
    assert!(store.wallet_state(pb).unwrap().available > 0);
    assert_eq!(store.wallet_state(pc).unwrap().available, 0);
    check();
    let tip = store.ledger().tip().clone();
    let revision = store.revision();
    let issued = store.ledger().issued();

    drop(store);
    check();
    let store = Store::open(&root.join("node"), &genesis, pin, Limits::default()).unwrap();
    check();
    assert_eq!(store.ledger().tip(), &tip);
    assert_eq!(store.revision(), revision);
    assert_eq!(store.ledger().issued(), issued);
    assert_eq!(
        store
            .ledger()
            .coins()
            .values()
            .map(|coin| coin.amount)
            .sum::<u128>(),
        issued
    );
    assert_eq!(store.wallet_state(pc).unwrap().available, 0);
    assert!(store.wallet_state(pb).unwrap().available > 0);
    for (operation, exact) in [
        (op(11, 165), first),
        (op(12, 166), second),
        (op(13, 252), win_first),
        (op(15, 253), win_second),
    ] {
        assert_eq!(store.signed_operation(operation).unwrap(), Some(exact));
    }
    detached(&store);
    for operation in [op(13, 252), op(15, 253)] {
        assert_eq!(
            store.payment_operation(operation).unwrap().unwrap()["ledger"],
            "INCLUDED"
        );
    }

    check();
}
