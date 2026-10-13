//! Fixed public no-value signing seeds exercise the actual transport verifier.
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use std::{process::Command, time::Instant};

fn sign(kind: &str, body: Value) -> Value {
    let key = SigningKey::from_bytes(&[7; 32]);
    let mut message = format!("RLD-CONTACT-MESH-V3\0{kind}\0").into_bytes();
    message.extend(wallet_client::canonical(&body).unwrap());
    json!({"body":body,"public_key":hex::encode(key.verifying_key().as_bytes()),
        "signature":hex::encode(key.sign(&message).to_bytes())})
}
fn sample(nonce: usize) -> Vec<u8> {
    let network = "11".repeat(32);
    let public = SigningKey::from_bytes(&[7; 32]).verifying_key();
    let mut identity = Sha256::new();
    identity.update(b"RLD-CONTACT-MESH-V3\0node\0");
    identity.update(public.as_bytes());
    let node = hex::encode(identity.finalize());
    let region = crate::Hash::from_hex(&"22".repeat(32)).unwrap();
    let payload = wallet_client::canonical(&json!({"format":"RLD-REGIONAL-BFT-NETWORK-V2",
        "currency":network,"region":region,"evidence":{"snapshots":[]},"body":{"Submission":[]}}))
    .unwrap();
    let hash = crate::Hash(Sha256::digest(&payload).into());
    let mut frame = crate::contact::Frame {
        format: crate::contact::FRAME_FORMAT.into(),
        kind: "regional-bft".into(),
        source_chain_id: region,
        destination_chain_id: region,
        export_id: hash,
        payload_sha256: hash,
        payload_b64: STANDARD.encode(payload),
        message_id: crate::Hash::ZERO,
    };
    frame.message_id = frame.message().unwrap();
    let packet = sign(
        "packet",
        json!({"format":"RLD-CONTACT-MESH-V3","network":network,"node_id":node,
        "destination":"33".repeat(32),"nonce":format!("{nonce:064x}"),"hop_limit":16,"frame":STANDARD.encode(frame.retained_bytes().unwrap())}),
    );
    let id = hex::encode(Sha256::digest(wallet_client::canonical(&packet).unwrap()));
    let route = sign(
        "receipt-route",
        json!({"format":"RLD-CONTACT-MESH-V3","network":network,"node_id":node,
        "packet_id":id,"destination":"33".repeat(32),"frame_id":frame.message_id}),
    );
    wallet_client::canonical(&json!({"packet":packet,"routing":route,"hops":[]})).unwrap()
}
fn scope() -> Value {
    json!({"mesh":"RLD-CONTACT-MESH-V3","network":"11".repeat(32),"recipient":null,"sender":null,"hops":16,
        "frame":crate::contact::MAX_FRAME,"payload":crate::contact::MAX_PAYLOAD,
        "frame_format":crate::contact::FRAME_FORMAT,"frame_domain":hex::encode(format!("{}\0",crate::contact::FRAME_FORMAT)),
        "kinds":["destination-receipt","destination-sync","finalized-import","onward-source-finality","regional-bft","source-finality","source-sync"],
        "provider":{"format":"RLD-NATIVE-CONTACT-CRYPTO-V1","implementation":crate::implementation().unwrap(),
            "path":"rust-contact-runtime-in-process","instance":0}})
}
fn call(mode: &str, raw: &[u8], scope: Value) -> Result<Value> {
    execute(
        &wallet_client::canonical(
            &json!({mode:{"scope":scope,"retention":512,"size_bytes":raw.len(),
        "sha256":hex::encode(Sha256::digest(raw))}}),
        )?,
        raw,
    )
}
#[test]
fn hot_verified_transit_survives_a_cold_signed_archive_scan() {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "contact_witness::tests::hot_verified_transit_scan_child",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("RLD_WITNESS_SCAN_CHILD", "1")
        .output()
        .unwrap();
    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    assert!(
        output.status.success(),
        "fresh isolated signed witness scan failed"
    );
}
#[test]
fn hot_verified_transit_scan_child() {
    if std::env::var("RLD_WITNESS_SCAN_CHILD").as_deref() != Ok("1") {
        return;
    }
    let started = Instant::now();
    execute(br#"{"Clear":null}"#, &[]).unwrap();
    let hot = sample(0);
    let domain = scope();
    assert_eq!(call("Probe", &hot, domain.clone()).unwrap()["found"], false);
    assert_eq!(call("Check", &hot, domain.clone()).unwrap()["found"], true);
    assert_eq!(call("Probe", &hot, domain.clone()).unwrap()["found"], true);
    for n in 1..=512 {
        let cold = sample(n);
        assert_eq!(
            call("Probe", &cold, domain.clone()).unwrap()["found"],
            false
        );
        call("Check", &cold, domain.clone()).unwrap();
        assert!(
            started.elapsed().as_secs_f64() < 30.0,
            "signed scan original component deadline exhausted"
        );
    }
    let count = execute(br#"{"Inspect":null}"#, &[]).unwrap()["entries"]
        .as_u64()
        .unwrap();
    assert_eq!(count, 512);
    let retained = call("Probe", &hot, domain.clone()).unwrap();
    println!(
        "signed scan: cold_inputs=512 retained_entries={count} hot_found={} seconds={}",
        retained["found"],
        started.elapsed().as_secs_f64()
    );
    assert_eq!(retained["ledger_authority"], false);
    assert_eq!(retained["custody_acknowledgment"], false);
    assert_eq!(
        retained["found"], true,
        "one-touch archive scan displaced a reused exact hot transit"
    );
    let mut changed: Value = serde_json::from_slice(&hot).unwrap();
    changed["packet"]["signature"] = json!("00".repeat(64));
    let changed = wallet_client::canonical(&changed).unwrap();
    assert_eq!(
        call("Probe", &changed, domain.clone()).unwrap()["found"],
        false
    );
    assert!(call("Check", &changed, domain.clone()).is_err());
    for (key, value) in [
        ("network", json!("44".repeat(32))),
        ("recipient", json!("33".repeat(32))),
        ("frame", json!(1)),
    ] {
        let mut other = domain.clone();
        other[key] = value;
        assert_eq!(call("Probe", &hot, other.clone()).unwrap()["found"], false);
        assert!(call("Check", &hot, other).is_err());
    }
    let mut other = domain.clone();
    other["provider"]["instance"] = json!(1);
    assert_eq!(call("Probe", &hot, other).unwrap()["found"], false);
    let scope_raw = wallet_client::canonical(&domain).unwrap();
    let mut fast = PROBE_CODEC.to_vec();
    fast.extend(512u16.to_be_bytes());
    fast.extend((scope_raw.len() as u32).to_be_bytes());
    fast.extend((hot.len() as u64).to_be_bytes());
    fast.extend(Sha256::digest(&hot));
    fast.extend(scope_raw);
    assert_eq!(probe_bytes(&fast, &hot).unwrap()["found"], true);
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "contact_witness::tests::signed_witness_cold_process_child",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("RLD_WITNESS_RESTART_CHILD", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "new-process witness started warm: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    execute(br#"{"Clear":null}"#, &[]).unwrap();
    assert_eq!(probe_bytes(&fast, &hot).unwrap()["found"], false);
    assert_eq!(call("Probe", &hot, domain.clone()).unwrap()["found"], false);
    call("Check", &hot, domain.clone()).unwrap();
    assert_eq!(call("Probe", &hot, domain).unwrap()["found"], true);
    execute(br#"{"Clear":null}"#, &[]).unwrap();
    for n in 0..=512 {
        let raw = sample(n);
        call("Check", &raw, scope()).unwrap();
        assert_eq!(call("Probe", &raw, scope()).unwrap()["found"], true);
    }
    assert_eq!(
        execute(br#"{"Inspect":null}"#, &[]).unwrap()["entries"],
        512
    );
    assert!(
        store()
            .lock()
            .unwrap()
            .entries
            .iter()
            .filter(|entry| entry.reused)
            .count()
            <= 256
    );
    assert_eq!(
        call("Probe", &hot, scope()).unwrap()["found"],
        false,
        "a superseded protected transit became permanently pinned"
    );
    assert!(
        started.elapsed().as_secs_f64() < 30.0,
        "signed witness closure original deadline exhausted"
    );
}

#[test]
fn signed_witness_cold_process_child() {
    if std::env::var("RLD_WITNESS_RESTART_CHILD").as_deref() != Ok("1") {
        return;
    }
    assert_eq!(execute(br#"{"Inspect":null}"#, &[]).unwrap()["entries"], 0);
    assert_eq!(call("Probe", &sample(0), scope()).unwrap()["found"], false);
}

fn prepared_control(raw: &[u8], domain: Value, retention: usize, mode: &str) -> Vec<u8> {
    wallet_client::canonical(&json!({mode:{"scope":domain,"retention":retention,
        "size_bytes":raw.len(),"sha256":hex::encode(Sha256::digest(raw))}}))
    .unwrap()
}
fn prepared_call(raw: &[u8], domain: Value, retention: usize) -> Result<Value> {
    match prepare_probe(&prepared_control(raw, domain, retention, "Probe"), raw)? {
        PreparedProbe::Hit(value) => Ok(value),
        PreparedProbe::Miss(pending) => pending.check(),
    }
}
fn original_pair(raw: &[u8], domain: Value, retention: usize) -> Result<Value> {
    let probe = execute(
        &prepared_control(raw, domain.clone(), retention, "Probe"),
        raw,
    )?;
    if probe["found"] == true {
        Ok(probe)
    } else {
        execute(&prepared_control(raw, domain, retention, "Check"), raw)
    }
}
fn counts() -> (usize, usize) {
    (
        INPUT_PREFLIGHTS.with(|n| n.replace(0)),
        FULL_CHECKS.with(|n| n.replace(0)),
    )
}
#[test]
fn prepared_probe_preserves_complete_authentication() {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "contact_witness::tests::prepared_probe_component_child",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("RLD_PREPARED_WITNESS_CHILD", "1")
        .output()
        .unwrap();
    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    assert!(
        output.status.success(),
        "isolated prepared input component failed"
    );
}
#[test]
fn prepared_probe_component_child() {
    if std::env::var("RLD_PREPARED_WITNESS_CHILD").as_deref() != Ok("1") {
        return;
    }
    let started = Instant::now();
    let clear = || {
        execute(br#"{"Clear":null}"#, &[]).unwrap();
        counts();
    };
    clear();
    let raw = sample(1024);
    let domain = scope();
    let original = original_pair(&raw, domain.clone(), 512).unwrap();
    assert_eq!(counts(), (2, 1));
    clear();
    let actual = prepared_call(&raw, domain.clone(), 512).unwrap();
    assert_eq!(counts(), (1, 1));
    assert_eq!(actual, original);
    assert_eq!(actual["ledger_authority"], false);
    assert_eq!(actual["custody_acknowledgment"], false);
    let hot = prepared_call(&raw, domain.clone(), 512).unwrap();
    assert_eq!(counts(), (1, 0));
    assert_eq!(hot, original_pair(&raw, domain.clone(), 512).unwrap());
    assert_eq!(counts(), (1, 0));
    assert_eq!(
        execute(&prepared_control(&raw, domain.clone(), 512, "Check"), &raw).unwrap(),
        original
    );
    assert_eq!(
        counts(),
        (1, 1),
        "public Check must verify even a warm witness"
    );
    clear();
    let typed: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(
        crate::contact_runtime::transit(&typed, &"11".repeat(32), Value::Null, Value::Null)
            .unwrap(),
        original["verification"]
    );
    assert_eq!(
        counts(),
        (1, 1),
        "actual runtime cold path repeated input preflight"
    );
    assert_eq!(
        crate::contact_runtime::transit(&typed, &"11".repeat(32), Value::Null, Value::Null)
            .unwrap(),
        json!({"visited":original["visited"],"ledger_authority":false,"custody_acknowledgment":false})
    );
    assert_eq!(
        counts(),
        (1, 0),
        "actual runtime hot path repeated full verification"
    );
    // A miss alone cannot insert a witness; eviction/clear cannot authenticate it.
    clear();
    let PreparedProbe::Miss(pending) =
        prepare_probe(&prepared_control(&raw, domain.clone(), 512, "Probe"), &raw).unwrap()
    else {
        panic!("cold hit")
    };
    assert_eq!(execute(br#"{"Inspect":null}"#, &[]).unwrap()["entries"], 0);
    execute(br#"{"Clear":null}"#, &[]).unwrap();
    assert_eq!(pending.check().unwrap(), original);
    assert_eq!(counts(), (1, 1));
    clear();
    drop(prepare_probe(&prepared_control(&raw, domain.clone(), 512, "Probe"), &raw).unwrap());
    assert_eq!(execute(br#"{"Inspect":null}"#, &[]).unwrap()["entries"], 0);

    let mut bad_signature: Value = serde_json::from_slice(&raw).unwrap();
    bad_signature["packet"]["signature"] = json!("00".repeat(64));
    let mut bad_route: Value = serde_json::from_slice(&raw).unwrap();
    bad_route["routing"]["signature"] = json!("00".repeat(64));
    let mut whitespace = raw.clone();
    whitespace.push(b' ');
    let changed_raw = [
        wallet_client::canonical(&bad_signature).unwrap(),
        wallet_client::canonical(&bad_route).unwrap(),
        whitespace,
    ];
    for candidate in &changed_raw {
        clear();
        let reference = original_pair(candidate, domain.clone(), 512).unwrap_err();
        clear();
        assert_eq!(
            prepared_call(candidate, domain.clone(), 512).unwrap_err(),
            reference
        );
        assert_eq!(execute(br#"{"Inspect":null}"#, &[]).unwrap()["entries"], 0);
        // Warm exact original first: altered bytes may neither hit nor poison it.
        clear();
        let valid = prepared_call(&raw, domain.clone(), 512).unwrap();
        let PreparedProbe::Miss(pending) = prepare_probe(
            &prepared_control(candidate, domain.clone(), 512, "Probe"),
            candidate,
        )
        .unwrap() else {
            panic!("changed raw reused original authentication")
        };
        assert_eq!(pending.check().unwrap_err(), reference);
        let PreparedProbe::Hit(retained) =
            prepare_probe(&prepared_control(&raw, domain.clone(), 512, "Probe"), &raw).unwrap()
        else {
            panic!("invalid input displaced the valid original")
        };
        assert_eq!(retained["visited"], valid["visited"]);
    }
    for (field, value) in [
        ("network", json!("44".repeat(32))),
        ("recipient", json!("33".repeat(32))),
        ("frame", json!(1)),
        ("hops", json!(17)),
    ] {
        let mut changed = domain.clone();
        changed[field] = value;
        clear();
        let reference = original_pair(&raw, changed.clone(), 512).unwrap_err();
        clear();
        assert_eq!(prepared_call(&raw, changed, 512).unwrap_err(), reference);
    }
    for retention in [0, 513] {
        clear();
        let reference = original_pair(&raw, domain.clone(), retention);
        clear();
        assert_eq!(prepared_call(&raw, domain.clone(), retention), reference);
        assert_eq!(execute(br#"{"Inspect":null}"#, &[]).unwrap()["entries"], 0);
    }
    clear();
    prepared_call(&raw, domain.clone(), 512).unwrap();
    let mut different_provider = domain.clone();
    different_provider["provider"]["instance"] = json!(1);
    counts();
    prepared_call(&raw, different_provider, 512).unwrap();
    assert_eq!(
        counts(),
        (1, 1),
        "another validation scope cannot reuse the warm witness"
    );
    // Invalid control/claimed bytes refuse before a token or warm result exists.
    let mut wrong: Value =
        serde_json::from_slice(&prepared_control(&raw, domain.clone(), 512, "Probe")).unwrap();
    wrong["Probe"]["sha256"] = json!("00".repeat(32));
    let wrong = wallet_client::canonical(&wrong).unwrap();
    assert!(prepare_probe(&wrong, &raw).is_err());
    let mut noncanonical = prepared_control(&raw, domain.clone(), 512, "Probe");
    noncanonical.push(b' ');
    assert!(prepare_probe(&noncanonical, &raw).is_err());
    for mode in ["Check", "Inspect", "Clear"] {
        let control = if mode == "Check" {
            prepared_control(&raw, domain.clone(), 512, mode)
        } else {
            wallet_client::canonical(&json!({mode:null})).unwrap()
        };
        assert!(prepare_probe(&control, &raw).is_err());
    }
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "contact_witness::tests::signed_witness_cold_process_child",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("RLD_WITNESS_RESTART_CHILD", "1")
        .output()
        .unwrap();
    assert!(child.status.success(), "fresh process became warm");

    // Paired wall observations have no regional-performance acceptance threshold.
    // Retention zero forces every full original native check, without cache clears.
    let samples = (2048..2064).map(sample).collect::<Vec<_>>();
    let mut original_seconds = 0.0;
    let mut prepared_seconds = 0.0;
    for (index, sample) in samples.iter().enumerate() {
        let reference = |seconds: &mut f64| {
            counts();
            let at = Instant::now();
            let value = original_pair(sample, domain.clone(), 0).unwrap();
            *seconds += at.elapsed().as_secs_f64();
            assert_eq!(counts(), (2, 1));
            value
        };
        let candidate = |seconds: &mut f64| {
            counts();
            let at = Instant::now();
            let value = prepared_call(sample, domain.clone(), 0).unwrap();
            *seconds += at.elapsed().as_secs_f64();
            assert_eq!(counts(), (1, 1));
            value
        };
        let (a, b) = if index % 2 == 0 {
            (
                reference(&mut original_seconds),
                candidate(&mut prepared_seconds),
            )
        } else {
            let b = candidate(&mut prepared_seconds);
            (reference(&mut original_seconds), b)
        };
        assert_eq!(a, b);
        assert!(
            started.elapsed().as_secs_f64() < 30.0,
            "original prepared component deadline"
        );
    }
    println!(
        "Prepared witness component: {}",
        json!({"samples":16,"original_preflights_each":2,"prepared_preflights_each":1,"full_checks_each":1,"original_seconds":original_seconds,"prepared_seconds":prepared_seconds,"complete_results_equal":true,"cold_process_verified":true,"ledger_authority":false,"regional_latency_qualification":false,"seconds":started.elapsed().as_secs_f64()})
    );
    clear();
}
