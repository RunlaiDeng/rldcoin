use super::*;
use crate::state_proof::{Collection as C, Proof, Value, Witness};

fn key(n: u32) -> Hash {
    let mut bytes = [0; 32];
    bytes[28..].copy_from_slice(&n.to_be_bytes());
    Hash(bytes)
}
fn sample(count: usize) -> Ledger {
    // Synthetic map-shape/resource data, never a signed issuance qualification.
    let mut ledger = Ledger::default();
    for n in 0..count {
        ledger.coins.insert(
            key((n as u32 + 1) * 2),
            Coin {
                payment: Payment {
                    owner: public(10),
                    amount: Amount(1),
                },
                created: 1,
                mature: 3,
                dependencies: BTreeSet::new(),
            },
        );
    }
    ledger.minted = Amount(count as u128);
    ledger
}
#[test]
fn exact_members_and_adjacent_absence_cover_empty_single_odd_and_even_indexes() {
    for count in [0, 1, 2, 3, 5, 8, 17] {
        let ledger = sample(count);
        let root = ledger.root().unwrap();
        for n in 0..=(count as u32 + 1) * 2 {
            let proof = Proof::from_ledger(&ledger, C::Coins, key(n)).unwrap();
            let wire = serde_json::to_vec(&proof).unwrap();
            let cold: Proof = serde_json::from_slice(&wire).unwrap();
            assert_eq!(
                cold.verify(root, C::Coins, key(n)).unwrap(),
                ledger.coins.get(&key(n)).cloned().map(Value::Coins)
            );
            assert_eq!(cold, proof);
        }
    }
}
#[test]
fn roots_bind_all_collections_counters_records_and_exact_query() {
    let mut ledger = sample(3);
    let export = Export {
        id: key(20),
        source: key(50),
        destination: key(60),
        recipient: Payment {
            owner: public(11),
            amount: Amount(7),
        },
        destination_fee: Amount(2),
        height: 5,
        dependencies: BTreeSet::from([key(80)]),
    };
    ledger.exports.insert(key(20), export.clone());
    ledger.imports.insert(key(40), key(90));
    ledger.minted = Amount(10);
    let root = ledger.root().unwrap();
    let proof = Proof::from_ledger(&ledger, C::Exports, key(20)).unwrap();
    assert_eq!(
        proof.verify(root, C::Exports, key(20)).unwrap(),
        Some(Value::Exports(export))
    );
    assert!(proof.verify(root, C::Coins, key(20)).is_err());
    assert!(proof.verify(root, C::Exports, key(21)).is_err());
    assert!(proof.verify(Hash::ZERO, C::Exports, key(20)).is_err());
    for mode in 0..7 {
        let mut changed = proof.clone();
        match mode {
            0 => changed.state.coins.tree = Hash::ZERO,
            1 => changed.state.exports.entries += 1,
            2 => changed.state.imports.tree = Hash::ZERO,
            3 => changed.state.minted.0 += 1,
            4 => changed.state.received.0 += 1,
            5 => changed.state.format = "RLD-REGIONAL-STATE-COMMITMENT-V0".into(),
            _ => {
                if let Witness::Present { member } = &mut changed.witness {
                    if let Value::Exports(value) = &mut member.value {
                        value.destination_fee.0 += 1;
                    }
                }
            }
        }
        assert!(changed.verify(root, C::Exports, key(20)).is_err());
    }
    let imported = Proof::from_ledger(&ledger, C::Imports, key(40)).unwrap();
    assert_eq!(
        imported.verify(root, C::Imports, key(40)).unwrap(),
        Some(Value::Imports(key(90)))
    );
}
#[test]
fn altered_paths_positions_values_padding_and_unbounded_inputs_refuse() {
    let ledger = sample(5);
    let root = ledger.root().unwrap();
    let original = Proof::from_ledger(&ledger, C::Coins, key(10)).unwrap();
    for mode in 0..7 {
        let mut proof = original.clone();
        if let Witness::Present { member } = &mut proof.witness {
            match mode {
                0 => member.siblings[0] = Hash::ZERO,
                1 => member.siblings.pop().map(|_| ()).unwrap(),
                2 => member.siblings.push(Hash::ZERO),
                3 => member.index = u64::MAX,
                4 => member.index -= 1,
                5 => member.value = Value::Imports(Hash::ZERO),
                _ => {
                    if let Value::Coins(c) = &mut member.value {
                        c.payment.amount.0 += 1;
                    }
                }
            }
        }
        assert!(proof.verify(root, C::Coins, key(10)).is_err());
    }
    let mut proof = original.clone();
    proof.state.coins.entries = u64::MAX;
    assert!(proof.state.hash().is_err());
    let mut proof = original;
    if let Witness::Present { member } = &mut proof.witness {
        member.siblings = vec![Hash::ZERO; 2000];
    }
    assert!(proof
        .verify(root, C::Coins, key(10))
        .unwrap_err()
        .contains("byte bound"));
    assert!(Proof::from_ledger(&sample(MAX_COINS + 1), C::Coins, key(2)).is_err());
    assert!(serde_json::from_str::<Proof>(r#"{"extra":true}"#).is_err());
}
#[test]
fn missing_nonadjacent_and_equal_key_absence_never_hide_an_existing_record() {
    let ledger = sample(5);
    let root = ledger.root().unwrap();
    let original = Proof::from_ledger(&ledger, C::Coins, key(5)).unwrap();
    let member = |n| match Proof::from_ledger(&ledger, C::Coins, key(n))
        .unwrap()
        .witness
    {
        Witness::Present { member } => member,
        _ => panic!("member expected"),
    };
    for witness in [
        Witness::Absent {
            lower: None,
            upper: None,
        },
        Witness::Absent {
            lower: Some(member(2)),
            upper: Some(member(6)),
        },
        Witness::Absent {
            lower: None,
            upper: Some(member(6)),
        },
        Witness::Absent {
            lower: Some(member(4)),
            upper: None,
        },
    ] {
        let mut proof = original.clone();
        proof.witness = witness;
        assert!(proof.verify(root, C::Coins, key(5)).is_err());
    }
    let mut proof = original;
    proof.key = key(4);
    assert!(proof.verify(root, C::Coins, key(4)).is_err());
}
#[test]
fn full_capacity_proof_cost_is_bounded_without_discarding_permanent_indexes() {
    let ledger = sample(MAX_COINS);
    let proof = Proof::from_ledger(&ledger, C::Coins, key(4097)).unwrap();
    proof
        .verify(ledger.root().unwrap(), C::Coins, key(4097))
        .unwrap();
    if let Witness::Absent {
        lower: Some(a),
        upper: Some(b),
    } = &proof.witness
    {
        assert_eq!(a.siblings.len(), 12);
        assert_eq!(b.siblings.len(), 12);
    } else {
        panic!("two exact adjacent witnesses expected");
    }
    let bytes = serde_json::to_vec(&proof).unwrap().len();
    assert!(bytes < 4096);
    println!(
        "{}",
        serde_json::json!({"format":"RLD-NATIVE-STATE-PROOF-CAPACITY-SAMPLE-V1",
        "synthetic_map_shape_only":true,"native_implementation":implementation().unwrap(),
        "entries":MAX_COINS,"absence_proof_bytes":bytes,"sibling_hashes":24,
        "state_bytes":serde_json::to_vec(&ledger).unwrap().len(),
        "native_long_history_qualified":false,"permanent_index_bound_unchanged":true})
    );
}
#[test]
fn native_signed_export_and_spent_import_proofs_require_exact_replayed_checkpoints() {
    let mut f = Fixture::new();
    let initial = f.earth.finalized.unwrap();
    let (source, export) = f.imported();
    for chain in [&f.earth, &f.proxima] {
        assert_eq!(
            chain.ledger.root().unwrap(),
            crate::state_proof::Commitment::from_ledger_uncached(&chain.ledger)
                .unwrap()
                .hash()
                .unwrap()
        );
    }
    let proof = f
        .evidence
        .prove_state(source, C::Exports, export, &f.trust)
        .unwrap();
    assert_eq!(
        f.evidence
            .check_state_proof(source, C::Exports, export, &proof, &f.trust)
            .unwrap(),
        Some(Value::Exports(
            f.evidence.export(source, export).unwrap().clone()
        ))
    );
    assert!(f
        .evidence
        .check_state_proof(initial, C::Exports, export, &proof, &f.trust)
        .is_err());
    assert!(VerifiedEvidence::default()
        .check_state_proof(source, C::Exports, export, &proof, &f.trust)
        .is_err());
    for _ in 0..2 {
        advance(&mut f.proxima, &f.trust, &f.evidence, vec![]);
    }
    let before = finalize(&mut f.proxima, &f.trust, &mut f.evidence);
    let input = coins(&f.proxima, 11)[0];
    let old = f
        .evidence
        .prove_state(before, C::Coins, input, &f.trust)
        .unwrap();
    let signed = intent(
        &f.proxima,
        &f.trust,
        vec![input],
        vec![Payment {
            owner: public(12),
            amount: Amount(78),
        }],
        None,
        None,
        0,
        0,
        &[11],
    );
    advance(
        &mut f.proxima,
        &f.trust,
        &f.evidence,
        vec![Command::Spend(Box::new(signed))],
    );
    let after = finalize(&mut f.proxima, &f.trust, &mut f.evidence);
    assert_eq!(
        f.proxima.ledger.root().unwrap(),
        crate::state_proof::Commitment::from_ledger_uncached(&f.proxima.ledger)
            .unwrap()
            .hash()
            .unwrap()
    );
    let receipt = f
        .evidence
        .prove_state(after, C::Imports, export, &f.trust)
        .unwrap();
    let spent = f
        .evidence
        .prove_state(after, C::Coins, input, &f.trust)
        .unwrap();
    assert!(f
        .evidence
        .check_state_proof(after, C::Coins, input, &old, &f.trust)
        .is_err());
    let carried = Evidence {
        snapshots: [initial, source, before, after]
            .into_iter()
            .map(|sid| f.evidence.snapshot(sid).unwrap().clone())
            .collect(),
    };
    let cold = VerifiedEvidence::verify(&carried, &f.trust).unwrap();
    assert_eq!(
        cold.check_state_proof(after, C::Imports, export, &receipt, &f.trust)
            .unwrap(),
        Some(Value::Imports(source))
    );
    assert_eq!(
        cold.check_state_proof(after, C::Coins, input, &spent, &f.trust)
            .unwrap(),
        None
    );
    assert_eq!(cold.snapshots[&after].1, f.proxima.ledger);
    f.audit();
    // Even fixture validators signing a fabricated state cannot replace native
    // execution with a sender-provided root or balance.
    let mut forged = carried;
    forged.snapshots[3].statement.state = Hash::ZERO;
    let bytes = forged.snapshots[3].statement.bytes().unwrap();
    for (approval, seed) in forged.snapshots[3].approvals.iter_mut().zip(keys()) {
        approval.signature = signature(seed, &bytes);
    }
    assert!(VerifiedEvidence::verify(&forged, &f.trust).is_err());
}
