//! Fixed public no-value transport inputs; no Native authority or disk fixture.
use super::{start_work_trace, take_work_trace};
use crate::{contact::Frame, contact_witness, wallet_client, wallet_http, Hash};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{process::Command, time::Instant};

fn network() -> String {
    "11".repeat(32)
}
fn identity(seed: u8) -> String {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let mut hash = Sha256::new();
    hash.update(b"RLD-CONTACT-MESH-V3\0node\0");
    hash.update(key.verifying_key().as_bytes());
    hex::encode(hash.finalize())
}
fn sign(kind: &str, body: Value) -> Value {
    // This deliberately public fixture seed never signs ledger value.
    let key = SigningKey::from_bytes(&[7; 32]);
    let mut message = format!("RLD-CONTACT-MESH-V3\0{kind}\0").into_bytes();
    message.extend(wallet_client::canonical(&body).unwrap());
    json!({"body":body,"public_key":hex::encode(key.verifying_key().as_bytes()),
        "signature":hex::encode(key.sign(&message).to_bytes())})
}
fn payload() -> Vec<u8> {
    wallet_client::canonical(&json!({"format":"RLD-REGIONAL-BFT-NETWORK-V2",
        "currency":network(),"region":"22".repeat(32),
        "evidence":{"snapshots":[]},"body":{"Submission":[]}}))
    .unwrap()
}
fn frame(payload: &[u8]) -> Frame {
    let region = Hash::from_hex(&"22".repeat(32)).unwrap();
    let digest = Hash(Sha256::digest(payload).into());
    let mut frame = Frame {
        format: crate::contact::FRAME_FORMAT.into(),
        kind: "regional-bft".into(),
        source_chain_id: region,
        destination_chain_id: region,
        export_id: digest,
        payload_sha256: digest,
        payload_b64: STANDARD.encode(payload),
        message_id: Hash::ZERO,
    };
    frame.message_id = frame.message().unwrap();
    frame
}
fn signed_transit(frame: &Frame) -> Value {
    signed_transit_in_network(frame, &network())
}
fn signed_transit_in_network(frame: &Frame, network: &str) -> Value {
    let source = identity(7);
    let destination = identity(8);
    let packet = sign(
        "packet",
        json!({"format":"RLD-CONTACT-MESH-V3",
        "network":network,"node_id":source,"destination":destination,
        "nonce":"01".repeat(32),"hop_limit":16,
        "frame":STANDARD.encode(frame.retained_bytes().unwrap())}),
    );
    let id = hex::encode(Sha256::digest(wallet_client::canonical(&packet).unwrap()));
    let route = sign(
        "receipt-route",
        json!({"format":"RLD-CONTACT-MESH-V3",
        "network":network,"node_id":source,"packet_id":id,
        "destination":destination,"frame_id":frame.message_id}),
    );
    let hop = sign(
        "hop",
        json!({"format":"RLD-CONTACT-MESH-V3",
        "network":network,"node_id":source,"packet_id":id,
        "previous":id,"to":destination}),
    );
    json!({"packet":packet,"routing":route,"hops":[hop]})
}
fn checked(value: &Value) -> crate::Result<Value> {
    crate::contact_runtime::transit(value, &network(), json!(identity(8)), json!(identity(7)))
}
fn expected(value: &Value, frame: &Frame) -> Value {
    json!({"format":"RLD-NATIVE-CONTACT-TRANSIT-V1","mode":"transit",
        "network":network(),"body":value["packet"]["body"],"frame":frame,
        "visited":[identity(7),identity(8)],"transport_authenticated":true,
        "ledger_authority":false,"custody_acknowledgment":false})
}
fn clear() {
    contact_witness::execute(br#"{"Clear":null}"#, &[]).unwrap();
}
fn entries() -> u64 {
    contact_witness::execute(br#"{"Inspect":null}"#, &[]).unwrap()["entries"]
        .as_u64()
        .unwrap()
}
fn calls(work: &[Value], phase: &str) -> u64 {
    work.iter()
        .filter(|entry| entry["phase"] == phase)
        .map(|entry| entry["calls"].as_u64().unwrap())
        .sum()
}

#[test]
#[ignore = "one fresh serial component observation; controller retains baseline failure"]
fn regional_payload_decodes_once_after_cold_full_transit_check() {
    let started = Instant::now();
    let payload = payload();
    let frame = frame(&payload);
    let transit = signed_transit(&frame);
    let original = wallet_client::canonical(&transit).unwrap();
    let expected = wallet_client::canonical(&expected(&transit, &frame)).unwrap();
    clear();
    assert_eq!(entries(), 0);
    start_work_trace();
    wallet_http::decode_cost::begin(&payload).unwrap();
    let result = checked(&transit);
    let payload_decodes = wallet_http::decode_cost::take();
    let work = take_work_trace();
    let full_checks = calls(&work, "transit-full-check");
    let witness_hits = calls(&work, "transit-witness-hit");
    let misses = calls(&work, "transit-witness-miss-probe");
    let elapsed_seconds = started.elapsed().as_secs_f64();
    // Emit before the final expected-one assertion: the original source is red.
    println!(
        "\nregional-payload-decode-observation {}",
        json!({
        "payload_decodes":payload_decodes,"full_checks":full_checks,
        "witness_hits":witness_hits,"witness_misses":misses,
        "verification":result.as_ref().ok(),"error":result.as_ref().err(),
        "payload_sha256":hex::encode(Sha256::digest(&payload)),
        "transit_sha256":hex::encode(Sha256::digest(&original)),
        "elapsed_seconds":elapsed_seconds,"component_bound_seconds":30,
        "fixture_only":true,"native_verified":false,"ledger_authority":false,
        "custody_acknowledgment":false,"latency_percentiles_qualified":false})
    );
    let verified = result.unwrap();
    assert_eq!(wallet_client::canonical(&verified).unwrap(), expected);
    assert_eq!(wallet_client::canonical(&transit).unwrap(), original);
    assert_eq!((full_checks, witness_hits, misses), (1, 0, 1));
    assert_eq!(entries(), 1);
    assert!(
        elapsed_seconds < 30.0,
        "original component deadline exhausted"
    );
    assert_eq!(
        payload_decodes, 1,
        "same exact regional payload was decoded repeatedly"
    );
}

#[test]
fn regional_payload_refusal_guards_preserve_complete_authentication() {
    // Isolate global witness Clear from concurrently running library tests.
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "contact_runtime::service::regional_payload_decode_tests::regional_payload_refusal_guards_child",
            "--exact", "--nocapture", "--test-threads=1",
        ])
        .env("RLD_REGIONAL_PAYLOAD_GUARD_CHILD", "1")
        .output().unwrap();
    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    assert!(
        output.status.success(),
        "isolated regional payload refusal guard failed"
    );
}

#[test]
fn regional_payload_refusal_guards_child() {
    if std::env::var("RLD_REGIONAL_PAYLOAD_GUARD_CHILD").as_deref() != Ok("1") {
        return;
    }
    let started = Instant::now();
    let payload = payload();
    let valid_frame = frame(&payload);
    let valid = signed_transit(&valid_frame);
    let original = wallet_client::canonical(&valid).unwrap();
    clear();
    assert_eq!(entries(), 0);
    let verified = checked(&valid).unwrap();
    assert_eq!(
        wallet_client::canonical(&verified).unwrap(),
        wallet_client::canonical(&expected(&valid, &valid_frame)).unwrap()
    );
    assert_eq!(entries(), 1);
    let mut refused = Vec::new();
    let mut refuse = |name: &str, frame: &Frame, required: &str| {
        // Re-sign all outer carriage, so each case reaches the intended inner guard.
        let input = signed_transit(frame);
        let before = wallet_client::canonical(&input).unwrap();
        let error = checked(&input).expect_err("malformed regional payload was authenticated");
        assert!(
            error.contains(required),
            "{name} failed at a different boundary: {error}"
        );
        assert_eq!(wallet_client::canonical(&input).unwrap(), before);
        assert_eq!(
            entries(),
            1,
            "failed input inserted an authenticated witness"
        );
        assert!(
            started.elapsed().as_secs_f64() < 30.0,
            "original guard deadline exhausted"
        );
        refused.push(name.to_owned());
    };
    let mut wrong_currency: Value = serde_json::from_slice(&payload).unwrap();
    wrong_currency["currency"] = json!("44".repeat(32));
    let wrong_payload = wallet_client::canonical(&wrong_currency).unwrap();
    let wrong_frame = frame(&wrong_payload);
    let (_, inspected) = crate::contact_frame::inspect_bytes(
        &wrong_frame.retained_bytes().unwrap(),
        None,
        None,
        crate::contact::MAX_PAYLOAD,
        crate::contact::MAX_FRAME,
    )
    .unwrap();
    assert_eq!(
        inspected, wrong_payload,
        "unbound frame inspection changed its original domain semantics"
    );
    refuse(
        "wrong_currency",
        &wrong_frame,
        "consensus carriage differs from mesh currency",
    );
    let mut duplicate = payload[..payload.len() - 1].to_vec();
    duplicate.extend(format!(",\"currency\":\"{}\"}}", network()).as_bytes());
    refuse(
        "duplicate_payload_field",
        &frame(&duplicate),
        "duplicate JSON field",
    );
    let text = String::from_utf8(payload.clone()).unwrap();
    let nested_duplicate = text.replace(
        "\"evidence\":{\"snapshots\":[]}",
        "\"evidence\":{\"snapshots\":[],\"snapshots\":[]}",
    );
    assert_ne!(text, nested_duplicate);
    refuse(
        "nested_duplicate_payload_field",
        &frame(nested_duplicate.as_bytes()),
        "duplicate JSON field",
    );
    let mut malformed: Value = serde_json::from_slice(&payload).unwrap();
    malformed.as_object_mut().unwrap().remove("evidence");
    refuse(
        "malformed_regional_shape",
        &frame(&wallet_client::canonical(&malformed).unwrap()),
        "regional consensus carriage binding mismatch",
    );
    let mut origin: Value = serde_json::from_slice(&payload).unwrap();
    origin["format"] = json!("RLD-REGIONAL-BFT-ORIGIN-NETWORK-V3");
    origin["origins"] = json!([null, null, null, null, null]);
    refuse(
        "origin_reference_count",
        &frame(&wallet_client::canonical(&origin).unwrap()),
        "regional consensus carriage binding mismatch",
    );
    let mut bad_hash = valid_frame.clone();
    bad_hash.payload_sha256 = Hash::ZERO;
    bad_hash.message_id = bad_hash.message().unwrap();
    refuse("altered_payload_hash", &bad_hash, "payload changed");
    let mut bad_frame = valid_frame.clone();
    bad_frame.message_id = Hash::ZERO;
    refuse("altered_frame_identity", &bad_frame, "message ID changed");
    // Use a letter-containing domain so this is a real case-sensitivity guard.
    let mut uppercase: Value = serde_json::from_slice(&payload).unwrap();
    uppercase["currency"] = json!("AA".repeat(32));
    let uppercase_frame = frame(&wallet_client::canonical(&uppercase).unwrap());
    let lower_network = "aa".repeat(32);
    let uppercase_input = signed_transit_in_network(&uppercase_frame, &lower_network);
    let error = crate::contact_runtime::transit(
        &uppercase_input,
        &lower_network,
        json!(identity(8)),
        json!(identity(7)),
    )
    .expect_err("uppercase currency accepted");
    assert!(
        error == "invalid consensus currency",
        "uppercase currency failed elsewhere: {error}"
    );
    assert_eq!(entries(), 1);
    refused.push("uppercase_currency".to_owned());
    let error = crate::contact_frame::inspect_bytes(
        &valid_frame.retained_bytes().unwrap(),
        None,
        None,
        payload.len() - 1,
        crate::contact::MAX_FRAME,
    )
    .expect_err("payload accepted above caller bound");
    assert!(
        error.contains("payload changed"),
        "payload bound failed elsewhere: {error}"
    );
    refused.push("caller_payload_bound".to_owned());
    origin["origins"] = json!([]);
    let origin_frame = frame(&wallet_client::canonical(&origin).unwrap());
    let origin_input = signed_transit(&origin_frame);
    assert_eq!(
        wallet_client::canonical(&checked(&origin_input).unwrap()).unwrap(),
        wallet_client::canonical(&expected(&origin_input, &origin_frame)).unwrap()
    );
    let mut opaque = frame(b"\xffopaque non-JSON carriage\0");
    opaque.kind = "source-sync".into();
    opaque.destination_chain_id = Hash::from_hex(&"33".repeat(32)).unwrap();
    opaque.export_id = Hash::from_hex(&"44".repeat(32)).unwrap();
    opaque.message_id = opaque.message().unwrap();
    let opaque_input = signed_transit(&opaque);
    assert_eq!(
        wallet_client::canonical(&checked(&opaque_input).unwrap()).unwrap(),
        wallet_client::canonical(&expected(&opaque_input, &opaque)).unwrap()
    );
    assert_eq!(entries(), 3);
    assert!(
        started.elapsed().as_secs_f64() < 30.0,
        "original guard deadline exhausted"
    );
    assert_eq!(wallet_client::canonical(&valid).unwrap(), original);
    println!(
        "\nregional-payload-refusal-observation {}",
        json!({"refused":refused,
        "accepted":["standard_v2", "origin_v3_empty_origins", "nonregional_opaque_non_json"],
        "retained_authenticated_witnesses":entries(),"elapsed_seconds":started.elapsed().as_secs_f64(),
        "component_bound_seconds":30,"fixture_only":true,"native_verified":false,
        "ledger_authority":false,"custody_acknowledgment":false})
    );
}
