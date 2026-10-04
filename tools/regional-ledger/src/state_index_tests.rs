use super::*;

fn key(n: u32) -> Hash {
    let mut bytes = [0; 32];
    bytes[28..].copy_from_slice(&n.to_be_bytes());
    Hash(bytes)
}
fn ledger(count: usize) -> Ledger {
    let mut value = Ledger::default();
    for n in 0..count {
        value.coins.insert(
            key(n as u32 * 2 + 2),
            Coin {
                payment: Payment {
                    owner: hex::encode([10; 32]),
                    amount: Amount(1),
                },
                created: 1,
                mature: 3,
                channel_dependencies: BTreeSet::new(),
                dependencies: BTreeSet::new(),
            },
        );
    }
    value.minted = Amount(count as u128);
    value
}
fn checked(w: &mut Option<StateIndex>, value: &Ledger) -> Cost {
    let (incremental, _, cost) = calculate(w, value, None).unwrap();
    assert_eq!(
        incremental,
        Commitment::from_ledger_uncached(value).unwrap()
    );
    assert_eq!(incremental.hash().unwrap(), value.root().unwrap());
    assert!(cost.retained_bytes <= MAX_BYTES);
    cost
}

#[test]
fn exact_unchanged_records_reuse_hashes_but_changed_leaf_rehashes_its_path() {
    let mut value = ledger(MAX_COINS);
    let mut w = None;
    let cold = checked(&mut w, &value);
    assert_eq!(cold.leaf_hashes, MAX_COINS);
    assert_eq!(cold.branch_hashes, MAX_COINS - 1);
    let warm = checked(&mut w, &value);
    assert_eq!((warm.leaf_hashes, warm.branch_hashes), (0, 0));
    assert_eq!(
        (warm.reused_leaves, warm.reused_branches),
        (MAX_COINS, MAX_COINS - 1)
    );
    value.coins.get_mut(&key(4000)).unwrap().mature += 1;
    let changed = checked(&mut w, &value);
    assert_eq!(changed.leaf_hashes, 1);
    assert_eq!(changed.branch_hashes, 12);
    assert_eq!(changed.reused_leaves, MAX_COINS - 1);
    println!(
        "{}",
        serde_json::json!({
            "format":"RLD-NATIVE-INCREMENTAL-INDEX-COST-V1",
            "synthetic_map_shape_only":true,"native_implementation":implementation().unwrap(),
            "entries":MAX_COINS,"cold":cold,"unchanged":warm,"changed_one_record":changed,
            "cold_commitments_exact":true,"proof_and_index_bounds_unchanged":true,
            "disk_index_or_long_history_qualified":false
        })
    );
}

#[test]
fn insert_delete_reorder_and_odd_padding_match_independent_full_reconstruction() {
    // Inserts/deletes may shift every position. This retains the exact V1 tree,
    // and deliberately makes no logarithmic-work claim for such changes.
    let mut w = None;
    let mut value = ledger(17);
    checked(&mut w, &value);
    for n in [2, 10, 34, 4, 22] {
        value.coins.remove(&key(n));
        value.minted.0 -= 1;
        checked(&mut w, &value);
    }
    for n in [1, 5, 100, 3, 200] {
        value.coins.insert(key(n), ledger(1).coins[&key(2)].clone());
        value.minted.0 += 1;
        checked(&mut w, &value);
    }
    value.coins.clear();
    value.minted = Amount::ZERO;
    checked(&mut w, &value);
    let repeated = checked(&mut w, &value);
    assert_eq!((repeated.leaf_hashes, repeated.branch_hashes), (0, 0));
}

#[test]
fn exact_record_fields_collections_and_counters_never_reuse_another_value() {
    let mut value = ledger(3);
    let mut w = None;
    checked(&mut w, &value);
    for mode in 0..6 {
        let coin = value.coins.get_mut(&key(2)).unwrap();
        match mode {
            0 => coin.payment.owner = hex::encode([11; 32]),
            1 => coin.created += 1,
            2 => coin.mature += 1,
            3 => {
                coin.dependencies.insert(key(99));
            }
            4 => {
                coin.payment.amount.0 += 1;
                value.minted.0 += 1;
            }
            _ => {
                coin.payment.amount.0 += 1;
                value.received.0 += 1;
            }
        }
        assert_eq!(checked(&mut w, &value).leaf_hashes, 1);
    }
    value.exports.insert(
        key(2),
        Export {
            id: key(2),
            source: key(50),
            destination: key(60),
            recipient: Payment {
                owner: hex::encode([12; 32]),
                amount: Amount(7),
            },
            destination_fee: Amount(2),
            height: 5,
            channel_dependencies: BTreeSet::new(),
            dependencies: BTreeSet::from([key(99)]),
        },
    );
    value.minted.0 += 7;
    value.imports.insert(key(2), key(80));
    assert_eq!(checked(&mut w, &value).leaf_hashes, 2);
    value.imports.insert(key(2), key(81));
    assert_eq!(checked(&mut w, &value).leaf_hashes, 1);
    value.exports.get_mut(&key(2)).unwrap().destination_fee.0 += 1;
    assert_eq!(checked(&mut w, &value).leaf_hashes, 1);
    // Counters are rebuilt from the current audited ledger, never cached.
    value.minted.0 -= 1;
    value.received.0 += 1;
    assert_eq!(checked(&mut w, &value).leaf_hashes, 0);
}

#[test]
fn failed_audit_and_capacity_leave_previous_witness_and_commitment_intact() {
    let value = ledger(8);
    let mut w = None;
    let original = calculate(&mut w, &value, None).unwrap().0;
    let mut bad = value.clone();
    bad.coins.get_mut(&key(2)).unwrap().payment.amount.0 += 1;
    assert!(calculate(&mut w, &bad, None).is_err());
    assert_eq!(calculate(&mut w, &value, None).unwrap().0, original);
    assert!(calculate(&mut w, &ledger(MAX_COINS + 1), None).is_err());
    assert_eq!(checked(&mut w, &value).leaf_hashes, 0);
}

#[test]
fn optional_retention_exhaustion_falls_back_without_losing_records_or_changing_roots() {
    let mut value = ledger(MAX_COINS);
    for coin in value.coins.values_mut() {
        coin.payment.owner = "x".repeat(2048);
    }
    // Synthetic hashing input only. Native execution still validates public
    // keys; this test does not grant these records issuance or owner authority.
    let mut w = None;
    let (state, _, cost) = calculate(&mut w, &value, None).unwrap();
    assert!(!cost.witness_retained);
    assert!(cost.uncached_fallback && cost.leaf_hashes >= MAX_COINS);
    assert!(w.is_none());
    assert_eq!(state, Commitment::from_ledger_uncached(&value).unwrap());
    assert!(checked(&mut w, &ledger(8)).witness_retained);
}

#[test]
fn warm_selected_proofs_match_cold_tree_and_do_not_hide_spent_or_permanent_records() {
    let mut value = ledger(5);
    let mut w = None;
    checked(&mut w, &value);
    for n in 0..14 {
        let (state, prepared, cost) = calculate(&mut w, &value, Some(Collection::Coins)).unwrap();
        let prepared = prepared.unwrap();
        let full = cold_prepared(&value, Collection::Coins).unwrap();
        assert_eq!(prepared.values, full.values);
        assert_eq!(prepared.levels, full.levels);
        assert_eq!((cost.leaf_hashes, cost.branch_hashes), (0, 0));
        let p = proof::Proof::from_ledger(&value, Collection::Coins, key(n)).unwrap();
        assert_eq!(
            p.verify(state.hash().unwrap(), Collection::Coins, key(n))
                .unwrap(),
            value.coins.get(&key(n)).cloned().map(Value::Coins)
        );
    }
    let old = proof::Proof::from_ledger(&value, Collection::Coins, key(2)).unwrap();
    value.coins.remove(&key(2));
    value.minted.0 -= 1;
    value.imports.insert(key(2), key(90));
    let state = calculate(&mut w, &value, None).unwrap().0.hash().unwrap();
    assert!(old.verify(state, Collection::Coins, key(2)).is_err());
    assert_eq!(
        proof::Proof::from_ledger(&value, Collection::Coins, key(2))
            .unwrap()
            .verify(state, Collection::Coins, key(2))
            .unwrap(),
        None
    );
    assert_eq!(
        proof::Proof::from_ledger(&value, Collection::Imports, key(2))
            .unwrap()
            .verify(state, Collection::Imports, key(2))
            .unwrap(),
        Some(Value::Imports(key(90)))
    );
    w = None;
    assert_eq!(
        calculate(&mut w, &value, None).unwrap().0.hash().unwrap(),
        state
    );
}
