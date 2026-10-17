//! Public NO-VALUE fixture signatures distinguish local pool preference from
//! selected-history validity. Pool policy never rejects an otherwise valid block.
use ed25519_dalek::{Signer, SigningKey};
use rld_survivor_node::{
    kernel::genesis_id,
    store::{Limits, Store},
};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[test]
fn conflicting_pool_intents_have_one_ready_winner_and_preserve_block_validity() {
    let v: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/survivor-v1/vectors.json"
    ))
    .unwrap();
    let g = hex::decode(v["genesis"]["manifest_hex"].as_str().unwrap()).unwrap();
    let root =
        std::env::temp_dir().join(format!("rld-survivor-pool-policy-{}", std::process::id()));
    let mut s = Store::open(&root, &g, genesis_id(&g), Limits::default()).unwrap();
    let blocks: Vec<_> = v["main_branch"].as_array().unwrap()[..100]
        .iter()
        .map(|b| hex::decode(b["block_hex"].as_str().unwrap()).unwrap())
        .collect();
    for (i, group) in blocks.chunks(32).enumerate() {
        s.accept_history([i as u8 + 1; 32], group, 2_000_000_000)
            .unwrap();
    }
    let original = hex::decode(v["payment"]["transaction_hex"].as_str().unwrap()).unwrap();
    let mut u = original[..original.len() - 64].to_vec();
    let fee_at = u.len() - 32;
    let last_amount = fee_at - 16;
    let fee = u128::from_be_bytes(u[fee_at..fee_at + 16].try_into().unwrap());
    let amount = u128::from_be_bytes(u[last_amount..fee_at].try_into().unwrap());
    u[fee_at..fee_at + 16].copy_from_slice(&(fee + 1).to_be_bytes());
    u[last_amount..fee_at].copy_from_slice(&(amount - 1).to_be_bytes());
    let key = SigningKey::from_bytes(
        &hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let sign = |u: &[u8]| {
        let mut x = u.to_vec();
        x.extend(
            key.sign(&[b"RLD-SURVIVOR-1/TRANSFER\0".as_slice(), u].concat())
                .to_bytes(),
        );
        x
    };
    let a = sign(&u);
    u[104..136]
        .copy_from_slice(&hex::decode(v["wallet_public_keys"][2].as_str().unwrap()).unwrap());
    let b = sign(&u);
    let id = |x: &[u8]| -> [u8; 32] {
        Sha256::digest([b"RLD-SURVIVOR-1/TXID\0".as_slice(), &x[..x.len() - 64]].concat()).into()
    };
    let winner = if id(&a) < id(&b) { &a } else { &b };
    for (i, x) in [&original, &b, &a].iter().enumerate() {
        s.submit_transaction([80 + i as u8; 32], x, 2_000_000_000)
            .unwrap();
    }
    let tip = s.ledger().tip().clone();
    let revision = s.revision();
    for x in [&original, &a, &b] {
        let observed = s.transfer_observation(x).unwrap();
        if x == winner {
            assert_eq!(observed["readiness"], "READY");
            assert!(observed["conflict_source"].is_null());
        } else {
            assert_eq!(observed["readiness"], "CONFLICTED");
            assert_eq!(observed["conflict_source"], "LOCAL_POOL");
        }
    }
    assert_eq!(s.ledger().tip(), &tip);
    assert_eq!(s.revision(), revision);
    assert_eq!(s.template_transactions().unwrap(), vec![winner.clone()]);
    drop(s);
    let mut s = Store::open(&root, &g, genesis_id(&g), Limits::default()).unwrap();
    assert_eq!(s.template_transactions().unwrap(), vec![winner.clone()]);
    // More total fee does not imply a higher exact fee/byte ratio. A compact
    // three-fee intent outranks an eight-output four-fee intent on the same input.
    let original_u = &original[..original.len() - 64];
    let total = original_u[104..fee_at]
        .as_chunks::<48>()
        .0
        .iter()
        .map(|o| u128::from_be_bytes(o[32..48].try_into().unwrap()))
        .sum::<u128>()
        + fee;
    let shape = |count: u16, new_fee: u128| {
        let mut u = original_u[..102].to_vec();
        u.extend(count.to_be_bytes());
        for i in 0..count {
            u.extend(key.verifying_key().to_bytes());
            let value = if i + 1 == count {
                total - new_fee - u128::from(count - 1)
            } else {
                1
            };
            u.extend(value.to_be_bytes());
        }
        u.extend(new_fee.to_be_bytes());
        u.extend(&original_u[fee_at + 16..]);
        sign(&u)
    };
    let compact = shape(1, 3);
    let expanded = shape(8, 4);
    s.submit_transaction([91; 32], &expanded, 2_000_000_000)
        .unwrap();
    s.submit_transaction([92; 32], &compact, 2_000_000_000)
        .unwrap();
    assert_eq!(s.template_transactions().unwrap(), vec![compact.clone()]);
    assert_eq!(
        s.transfer_observation(&compact).unwrap()["readiness"],
        "READY"
    );
    assert_eq!(
        s.transfer_observation(&expanded).unwrap()["conflict_source"],
        "LOCAL_POOL"
    );
    // The public branch includes the lower local fee. Consensus must still
    // execute it, after which competing intents have a selected-history conflict.
    let next = hex::decode(v["main_branch"][100]["block_hex"].as_str().unwrap()).unwrap();
    s.accept([90; 32], &next, 2_000_000_000).unwrap();
    assert_eq!(
        s.transfer_observation(&original).unwrap()["ledger"],
        "INCLUDED"
    );
    for x in [&a, &b, &compact, &expanded] {
        let observed = s.transfer_observation(x).unwrap();
        assert_eq!(observed["readiness"], "CONFLICTED");
        assert_eq!(observed["conflict_source"], "SELECTED_HISTORY");
    }
}

#[test]
fn altered_retained_pool_identity_refuses_without_selecting_or_spending() {
    let v: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/survivor-v1/vectors.json"
    ))
    .unwrap();
    let g = hex::decode(v["genesis"]["manifest_hex"].as_str().unwrap()).unwrap();
    let root = std::env::temp_dir().join(format!("rld-survivor-pool-index-{}", std::process::id()));
    let mut s = Store::open(&root, &g, genesis_id(&g), Limits::default()).unwrap();
    let x = hex::decode(v["payment"]["transaction_hex"].as_str().unwrap()).unwrap();
    s.submit_transaction([1; 32], &x, 2_000_000_000).unwrap();
    let before = s.ledger().tip().clone();
    let db = rusqlite::Connection::open(root.join("ledger.sqlite3")).unwrap();
    db.execute("UPDATE pool SET id=?1", [[255u8; 32].as_slice()])
        .unwrap();
    drop(db);
    assert!(s
        .template_transactions()
        .unwrap_err()
        .starts_with("INVALID_CRYPTO"));
    assert!(!s.storage_ready());
    assert_eq!(s.ledger().tip(), &before);
    assert_eq!(s.revision(), 0);
}
