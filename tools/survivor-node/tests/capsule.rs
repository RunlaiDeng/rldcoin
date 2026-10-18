//! Published NO-VALUE byte fixtures; no generated custody is distributed.
use rld_survivor_node::{
    capsule,
    kernel::genesis_id,
    store::{Limits, Store},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

fn root() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "rld-capsule-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&path).unwrap();
    path
}
fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../docs/protocol/payment-capsule-v1-vectors.json"
    ))
    .unwrap()
}
fn consensus() -> Value {
    serde_json::from_str(include_str!(
        "../../../docs/protocol/survivor-v1/vectors.json"
    ))
    .unwrap()
}
fn raw(value: &Value, field: &str) -> Vec<u8> {
    hex::decode(value[field].as_str().unwrap()).unwrap()
}
fn seal(bytes: &mut [u8]) {
    let n = bytes.len() - 32;
    let mut digest = Sha256::new();
    digest.update(b"RLD-SURVIVOR-CAPSULE-1/CONTENT\0");
    digest.update(&bytes[..n]);
    bytes[n..].copy_from_slice(&digest.finalize());
}

#[test]
fn public_wire_vectors_replay_and_bind_exact_intent_without_inventing_input_value() {
    let wire = vectors();
    let v = consensus();
    let genesis = raw(&v["genesis"], "manifest_hex");
    let pin = genesis_id(&genesis);
    let intent = raw(&v["payment"], "transaction_hex");
    assert_eq!(
        Sha256::digest(include_bytes!(
            "../../../docs/protocol/survivor-v1/vectors.json"
        ))
        .to_vec(),
        hex::decode(wire["source_vectors_sha256"].as_str().unwrap()).unwrap()
    );
    for case in wire["cases"].as_array().unwrap() {
        let root = root();
        let file = root.join("public.capsule");
        fs::write(&file, raw(case, "capsule_hex")).unwrap();
        let checked =
            capsule::verify(&file, &genesis, pin, Limits::default(), Some(&intent)).unwrap();
        assert_eq!(hex::encode(checked.id()), case["capsule_id"]);
        assert_eq!(checked.intent(), intent);
        assert_eq!(checked.observation(None)["local_ledger_acceptance"], false);
        assert!(checked.observation(None)["clock_eligible"].is_null());
        let mut recipient =
            Store::open(&root.join("recipient"), &genesis, pin, Limits::default()).unwrap();
        let result = capsule::import(&mut recipient, &file, Some(&intent), 2_000_000_000).unwrap();
        assert_eq!(
            recipient.ledger().tip().height(),
            case["block_count"].as_u64().unwrap() as u128
        );
        if case["block_count"] == 0 {
            assert_eq!(result["transaction"]["ledger"], "WAITING_FOR_HISTORY");
            assert_eq!(recipient.ledger().issued(), 0);
            assert!(recipient.ledger().coins().is_empty());
        } else {
            assert_eq!(result["transaction"]["ledger"], "INCLUDED");
            assert_eq!(result["transaction_hex"], hex::encode(&intent));
        }
        let selected = recipient.ledger().tip().id();
        let revision = recipient.revision();
        capsule::import(&mut recipient, &file, Some(&intent), 2_000_000_000).unwrap();
        assert_eq!(recipient.ledger().tip().id(), selected);
        assert_eq!(recipient.revision(), revision);
        drop(recipient);
        let cold = Store::open(&root.join("recipient"), &genesis, pin, Limits::default()).unwrap();
        assert_eq!(cold.ledger().tip().id(), selected);
        assert_eq!(cold.revision(), revision);
        assert_eq!(
            cold.ledger()
                .coins()
                .values()
                .map(|c| c.amount)
                .sum::<u128>(),
            cold.ledger().issued()
        );
    }
}

#[test]
fn complete_initial_refusal_preserves_native_head_revision_money_and_pool() {
    let wire = vectors();
    let v = consensus();
    let genesis = raw(&v["genesis"], "manifest_hex");
    let pin = genesis_id(&genesis);
    let original = raw(&wire["cases"][1], "capsule_hex");
    let intent = raw(&v["payment"], "transaction_hex");
    let root = root();
    let file = root.join("input.capsule");
    let mut recipient =
        Store::open(&root.join("recipient"), &genesis, pin, Limits::default()).unwrap();
    let mut negatives = Vec::new();
    for size in [0, 95, 96, original.len() - 1] {
        negatives.push((format!("truncated-{size}"), original[..size].to_vec()));
    }
    for offset in [0, 9, 11, 12, 64, 96 + intent.len(), original.len() - 1] {
        let mut altered = original.clone();
        altered[offset] ^= 1;
        if offset != original.len() - 1 {
            seal(&mut altered);
        }
        negatives.push((format!("field-{offset}"), altered));
    }
    for (offset, bytes) in [(44, u64::MAX.to_be_bytes()), (56, u64::MAX.to_be_bytes())] {
        let mut altered = original.clone();
        altered[offset..offset + 8].copy_from_slice(&bytes);
        seal(&mut altered);
        negatives.push((format!("overflow-{offset}"), altered));
    }
    let mut bad_signature = original.clone();
    bad_signature[96 + intent.len() - 1] ^= 1;
    seal(&mut bad_signature);
    negatives.push(("changed-signature".into(), bad_signature));
    let mut invalid_native_tail = original.clone();
    let last = invalid_native_tail.len() - 33;
    invalid_native_tail[last] ^= 1;
    seal(&mut invalid_native_tail);
    negatives.push((
        "native-invalid-recomputed-wrapper".into(),
        invalid_native_tail,
    ));
    let mut appended = original.clone();
    appended.push(0);
    negatives.push(("trailing".into(), appended));
    for (name, bytes) in negatives {
        fs::write(&file, bytes).unwrap();
        let failure = capsule::import(&mut recipient, &file, Some(&intent), 2_000_000_000);
        assert!(failure.is_err(), "{name}: {failure:?}");
        assert_eq!(recipient.ledger().tip().id(), pin, "{name}");
        assert_eq!(recipient.revision(), 0, "{name}");
        assert_eq!(recipient.ledger().issued(), 0, "{name}");
        assert!(recipient.ledger().coins().is_empty(), "{name}");
        assert!(
            recipient.template_transactions().unwrap().is_empty(),
            "{name}"
        );
        assert!(recipient.storage_ready(), "{name}");
    }
    fs::write(&file, &original).unwrap();
    assert!(capsule::verify(&file, &genesis, [0; 32], Limits::default(), None).is_err());
    assert!(capsule::import(
        &mut recipient,
        &file,
        Some(b"changed expected intent"),
        2_000_000_000
    )
    .is_err());
    let small = Limits {
        database_bytes: original.len() as u64 - 1,
        ..Limits::default()
    };
    assert!(capsule::verify(&file, &genesis, pin, small, None)
        .err()
        .unwrap()
        .starts_with("RESOURCE_WAIT"));
    assert_eq!(recipient.ledger().tip().id(), pin);
}

#[test]
fn export_and_refresh_preserve_owner_bytes_while_evidence_changes() {
    let v = consensus();
    let wire = vectors();
    let genesis = raw(&v["genesis"], "manifest_hex");
    let pin = genesis_id(&genesis);
    let intent = raw(&v["payment"], "transaction_hex");
    let root = root();
    let mut source = Store::open(&root.join("source"), &genesis, pin, Limits::default()).unwrap();
    let old = root.join("old.capsule");
    capsule::export(&source, &intent, &old).unwrap();
    assert_eq!(
        fs::read(&old).unwrap(),
        raw(&wire["cases"][0], "capsule_hex")
    );
    let blocks: Vec<_> = v["main_branch"].as_array().unwrap()[..102]
        .iter()
        .map(|b| raw(b, "block_hex"))
        .collect();
    for (i, batch) in blocks.chunks(32).enumerate() {
        let mut id = [21; 32];
        id[31] = i as u8;
        source.accept_history(id, batch, 2_000_000_000).unwrap();
    }
    let new = root.join("new.capsule");
    capsule::refresh(&source, &old, &new).unwrap();
    assert_eq!(
        fs::read(&new).unwrap(),
        raw(&wire["cases"][1], "capsule_hex")
    );
    let old_checked =
        capsule::verify(&old, &genesis, pin, Limits::default(), Some(&intent)).unwrap();
    let new_checked = capsule::verify(
        &new,
        &genesis,
        pin,
        Limits::default(),
        Some(old_checked.intent()),
    )
    .unwrap();
    assert_eq!(old_checked.intent(), new_checked.intent());
    assert_ne!(old_checked.id(), new_checked.id());
    let retained = fs::read(&new).unwrap();
    assert!(capsule::export(&source, &intent, &new).is_err());
    assert_eq!(fs::read(&new).unwrap(), retained);
    // Refresh to genesis removes backing evidence, never fabricates the input.
    let empty = Store::open(&root.join("empty"), &genesis, pin, Limits::default()).unwrap();
    let unsupported = root.join("missing-input.capsule");
    capsule::refresh(&empty, &new, &unsupported).unwrap();
    assert_eq!(
        fs::read(unsupported).unwrap(),
        raw(&wire["cases"][0], "capsule_hex")
    );
}

#[test]
fn imported_evidence_cannot_replace_stronger_work_or_bypass_local_clock() {
    let v = consensus();
    let wire = vectors();
    let genesis = raw(&v["genesis"], "manifest_hex");
    let pin = genesis_id(&genesis);
    let intent = raw(&v["payment"], "transaction_hex");
    let root = root();
    let file = root.join("weaker.capsule");
    fs::write(&file, raw(&wire["cases"][1], "capsule_hex")).unwrap();
    let mut recipient =
        Store::open(&root.join("recipient"), &genesis, pin, Limits::default()).unwrap();
    let blocks: Vec<_> = v["main_branch"]
        .as_array()
        .unwrap()
        .iter()
        .take(100)
        .chain(v["alternative_branch"].as_array().unwrap())
        .map(|block| raw(block, "block_hex"))
        .collect();
    for (index, batch) in blocks.chunks(32).enumerate() {
        let mut operation = [44; 32];
        operation[31] = index as u8;
        recipient
            .accept_history(operation, batch, 2_000_000_000)
            .unwrap();
    }
    let selected = recipient.ledger().tip().clone();
    let revision = recipient.revision();
    let issued = recipient.ledger().issued();
    let result = capsule::import(&mut recipient, &file, Some(&intent), 2_000_000_000).unwrap();
    assert_eq!(result["selected_tip"], hex::encode(selected.id()));
    assert_ne!(result["selected_tip"], result["carried_tip"]);
    assert_eq!(recipient.revision(), revision);
    assert_eq!(recipient.ledger().tip().root(), selected.root());
    assert_eq!(recipient.ledger().issued(), issued);
    drop(recipient);
    let cold = Store::open(&root.join("recipient"), &genesis, pin, Limits::default()).unwrap();
    assert_eq!(cold.ledger().tip().id(), selected.id());
    assert_eq!(cold.ledger().tip().root(), selected.root());
    assert_eq!(cold.revision(), revision);
    let mut clock_wait =
        Store::open(&root.join("clock-wait"), &genesis, pin, Limits::default()).unwrap();
    assert!(capsule::import(&mut clock_wait, &file, Some(&intent), 0)
        .unwrap_err()
        .starts_with("CLOCK_WAIT"));
    assert_eq!(clock_wait.ledger().tip().id(), pin);
    assert_eq!(clock_wait.revision(), 0);
    assert!(clock_wait.ledger().coins().is_empty());
}
