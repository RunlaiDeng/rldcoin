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
        "kinds":["destination-receipt","destination-sync","finalized-import","regional-bft","source-finality","source-sync"],
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
