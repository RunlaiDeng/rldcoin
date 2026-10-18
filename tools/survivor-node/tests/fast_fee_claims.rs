//! PUBLIC NO-VALUE signatures and prospective numerical terms only. This test
//! creates no native escrow, channel, independent retainer or monetary network.
use ed25519_dalek::{Signer, SigningKey};
use rld_survivor_node::fast_fee_claims::{Contract, FeeFloors};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../docs/protocol/fast-miner-fee-claims-v1-vectors.json"
    ))
    .unwrap()
}
fn bytes(value: &Value, field: &str) -> Vec<u8> {
    hex::decode(value[field].as_str().unwrap()).unwrap()
}
fn signed(context: &[u8], q: u64, balances: [u128; 2], slots: [u64; 2]) -> Vec<u8> {
    // Public fixture seeds, never production keys or native signing custody.
    let keys = [
        SigningKey::from_bytes(&[101; 32]),
        SigningKey::from_bytes(&[102; 32]),
    ];
    let mut raw = context[..68].to_vec();
    raw.extend(q.to_be_bytes());
    for amount in balances {
        raw.extend(amount.to_be_bytes());
    }
    for n in slots {
        raw.extend(n.to_be_bytes());
    }
    assert_eq!(raw.len(), 124);
    let mut h = Sha256::new();
    h.update(b"RLD-FAST-FEE-CLAIM-1/CONTEXT\0");
    h.update(context);
    let mut message = b"RLD-FAST-FEE-CLAIM-1/STATE\0".to_vec();
    message.extend(h.finalize());
    message.extend(&raw);
    for key in keys {
        raw.extend(key.sign(&message).to_bytes());
    }
    raw
}

#[test]
fn canonical_public_certificates_bind_every_term_and_both_ordered_owners() {
    let v = vectors();
    let context = bytes(&v, "context_hex");
    assert_eq!(context.len(), 228);
    let contract = Contract::decode(&context).unwrap();
    assert_eq!(contract.bytes(), context);
    assert_eq!(hex::encode(contract.commitment()), v["context_commitment"]);
    for case in v["cases"].as_array().unwrap() {
        let raw = bytes(case, "certificate_hex");
        assert_eq!(raw.len(), 252);
        assert_eq!(raw[..124], bytes(case, "unsigned_hex"));
        let claim = contract.verify(&raw).unwrap();
        assert_eq!(claim.sequence, case["sequence"].as_u64().unwrap());
        for i in 0..2 {
            assert_eq!(claim.balances[i].to_string(), case["balances"][i]);
            assert_eq!(claim.slots[i], case["slots"][i].as_u64().unwrap());
        }
    }
    // Terms are part of the signature domain, not merely a caller's repeated ID.
    let original = bytes(&v["cases"][2], "certificate_hex");
    for offset in [4, 36, 164, 180, 188, 204, 212] {
        let mut other = context.clone();
        other[offset + 7] ^= 1;
        if let Ok(contract) = Contract::decode(&other) {
            assert!(contract.verify(&original).is_err());
        }
    }
    let mut other = context.clone();
    other[132..164].copy_from_slice(
        &SigningKey::from_bytes(&[104; 32])
            .verifying_key()
            .to_bytes(),
    );
    assert!(Contract::decode(&other).unwrap().verify(&original).is_err());
    let mut reversed = context.clone();
    reversed[68..100].copy_from_slice(&context[100..132]);
    reversed[100..132].copy_from_slice(&context[68..100]);
    assert!(Contract::decode(&reversed)
        .unwrap()
        .verify(&original)
        .is_err());
}

#[test]
fn higher_principal_sequence_cannot_erase_a_retained_lower_sequence_fee_claim() {
    let v = vectors();
    let context = bytes(&v, "context_hex");
    let mut floors = FeeFloors::new(Contract::decode(&context).unwrap());
    for case in v["cases"].as_array().unwrap() {
        floors.observe(&bytes(case, "certificate_hex")).unwrap();
    }
    // Both parties really signed the higher sequence with zero counters. A
    // latest-state-only fee design loses5; this independent floor does not.
    let erasing = Contract::decode(&context)
        .unwrap()
        .verify(&bytes(&v["cases"][3], "certificate_hex"))
        .unwrap();
    assert_eq!((erasing.sequence, erasing.slots), (100, [0, 0]));
    assert_eq!(floors.slots(), [1, 1]);
    assert_eq!(floors.accounting().fee_ranges, [2, 3]);
    let mut reconstructed = FeeFloors::new(Contract::decode(&context).unwrap());
    for proof in floors.proofs().into_iter().flatten() {
        reconstructed.observe(proof).unwrap();
    }
    assert_eq!(reconstructed.slots(), floors.slots());
    assert_eq!(reconstructed.accounting(), floors.accounting());
}

#[test]
fn exhaustive_small_range_orders_duplicates_and_exhaustion_preserve_exact_backing() {
    let v = vectors();
    let context = bytes(&v, "context_hex");
    let mut claims = Vec::new();
    for a in 0..=6 {
        for b in 0..=5 {
            claims.push(signed(&context, a + b, [600, 400], [a, b]));
        }
    }
    for reverse in [false, true] {
        let mut floors = FeeFloors::new(Contract::decode(&context).unwrap());
        let mut order: Vec<_> = claims.iter().collect();
        if reverse {
            order.reverse();
        }
        for raw in order {
            let old = floors.slots();
            floors.observe(raw).unwrap();
            let next = floors.slots();
            assert!(next[0] >= old[0] && next[1] >= old[1]);
            let accounting = floors.accounting();
            for i in 0..2 {
                assert_eq!(
                    accounting.fee_ranges[i] + accounting.unused[i],
                    accounting.reserved[i]
                );
            }
            assert_eq!(
                accounting.principal + accounting.reserved.iter().sum::<u128>(),
                1027
            );
            let retained: Vec<_> = floors
                .proofs()
                .iter()
                .map(|x| x.map(<[u8]>::to_vec))
                .collect();
            floors.observe(raw).unwrap();
            assert_eq!(floors.slots(), next);
            assert_eq!(
                floors
                    .proofs()
                    .iter()
                    .map(|x| x.map(<[u8]>::to_vec))
                    .collect::<Vec<_>>(),
                retained
            );
        }
        assert_eq!(floors.slots(), [6, 5]);
        assert_eq!(floors.accounting().fee_ranges, [12, 15]);
        assert_eq!(floors.accounting().unused, [0, 0]);
    }
}

#[test]
fn malformed_or_even_jointly_signed_overbound_claims_do_not_change_any_floor() {
    let v = vectors();
    let context = bytes(&v, "context_hex");
    let valid = bytes(&v["cases"][2], "certificate_hex");
    let mut floors = FeeFloors::new(Contract::decode(&context).unwrap());
    floors.observe(&valid).unwrap();
    let mut bad = vec![
        vec![],
        valid[..251].to_vec(),
        [valid.clone(), vec![0]].concat(),
        signed(&context, 9, [600, 400], [7, 0]),
        signed(&context, 9, [600, 400], [0, 6]),
        signed(&context, 9, [601, 400], [1, 1]),
        signed(&context, 9, [u128::MAX, u128::MAX], [1, 1]),
    ];
    for offset in [0, 3, 4, 36, 124, 188, 251] {
        let mut raw = valid.clone();
        raw[offset] ^= 1;
        bad.push(raw);
    }
    let mut swapped = valid.clone();
    swapped[124..188].copy_from_slice(&valid[188..252]);
    swapped[188..252].copy_from_slice(&valid[124..188]);
    bad.push(swapped);
    for raw in bad {
        let old = floors.accounting();
        let proofs = floors.proofs().map(|p| p.map(<[u8]>::to_vec));
        assert!(floors.observe(&raw).is_err());
        assert_eq!(floors.accounting(), old);
        assert_eq!(floors.proofs().map(|p| p.map(<[u8]>::to_vec)), proofs);
    }
}

#[test]
fn terms_refuse_zero_overflow_cap_unknown_size_and_weak_keys() {
    let v = vectors();
    let context = bytes(&v, "context_hex");
    let mut bad = vec![
        vec![],
        context[..227].to_vec(),
        [context.clone(), vec![0]].concat(),
    ];
    for (offset, size) in [
        (164, 16),
        (180, 8),
        (188, 16),
        (204, 8),
        (212, 16),
        (68, 32),
        (132, 32),
    ] {
        let mut raw = context.clone();
        raw[offset..offset + size].fill(0);
        bad.push(raw);
    }
    let mut overflow = context.clone();
    overflow[180..188].fill(255);
    overflow[188..204]
        .copy_from_slice(&100_000_000_000_000_000_000_000_000_000_000_000u128.to_be_bytes());
    assert!(Contract::decode(&overflow)
        .err()
        .unwrap()
        .contains("overflow"));
    bad.push(overflow);
    let mut cap = context.clone();
    cap[164..180]
        .copy_from_slice(&100_000_000_000_000_000_000_000_000_000_000_000u128.to_be_bytes());
    bad.push(cap);
    let mut same = context.clone();
    same[100..132].copy_from_slice(&context[68..100]);
    bad.push(same);
    let mut version = context.clone();
    version[3] = 2;
    bad.push(version);
    for raw in bad {
        assert!(Contract::decode(&raw).is_err());
    }
}

#[test]
fn withholding_a_highest_claim_is_an_explicit_unresolved_monitoring_dependency() {
    let v = vectors();
    let context = bytes(&v, "context_hex");
    let old = bytes(&v["cases"][0], "certificate_hex");
    let new = bytes(&v["cases"][1], "certificate_hex");
    // Same public funding/old-close view, different off-chain histories. Neither
    // a local parser nor a signature check can invent a withheld higher claim.
    let mut no_retainer = FeeFloors::new(Contract::decode(&context).unwrap());
    no_retainer.observe(&old).unwrap();
    assert_eq!(no_retainer.accounting().fee_ranges, [0, 0]);
    let mut timely_retainer = FeeFloors::new(Contract::decode(&context).unwrap());
    timely_retainer.observe(&old).unwrap();
    timely_retainer.observe(&new).unwrap();
    assert_eq!(timely_retainer.accounting().fee_ranges, [2, 0]);
    // Full-budget prepayment covers both possibilities but cannot establish the
    // exact completed-payment aggregate, which is0 or2 under the same old view.
    assert_eq!(
        no_retainer.accounting().reserved,
        timely_retainer.accounting().reserved
    );
    assert_ne!(
        no_retainer.accounting().fee_ranges,
        timely_retainer.accounting().fee_ranges
    );
}
