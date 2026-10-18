//! Public NO-VALUE bytes. Repeated intrinsic checks cannot waive changed crypto,
//! transport authentication, chain binding or parent-dependent value execution.
use ed25519_dalek::SigningKey;
use rld_survivor_node::{
    contact::{block_syntax, peer_id, Frame, Packet},
    kernel::{block_id, genesis_id, Hash, Ledger},
};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn fixtures() -> (Value, Hash) {
    let v: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/survivor-v1/vectors.json"
    ))
    .unwrap();
    let g = hex::decode(v["genesis"]["manifest_hex"].as_str().unwrap()).unwrap();
    let pin = genesis_id(&g);
    (v, pin)
}
fn payment(v: &Value) -> Vec<u8> {
    hex::decode(v["main_branch"][100]["block_hex"].as_str().unwrap()).unwrap()
}
fn mine_header(raw: &mut [u8]) {
    let target = raw[124..156].to_vec();
    for nonce in 0u128..1_000_000 {
        raw[252..268].copy_from_slice(&nonce.to_be_bytes());
        if block_id(raw).unwrap().as_slice() <= target.as_slice() {
            return;
        }
    }
    panic!("finite public-fixture header search");
}

#[test]
fn repeated_block_checks_refuse_changed_chain_and_remined_bad_signature() {
    let (v, pin) = fixtures();
    let good = payment(&v);
    block_syntax(&good, pin).unwrap();
    block_syntax(&good, pin).unwrap();
    let mut wrong_chain = pin;
    wrong_chain[0] ^= 1;
    assert!(block_syntax(&good, wrong_chain).is_err());
    let mut bad = good.clone();
    *bad.last_mut().unwrap() ^= 0x80;
    let root = Sha256::digest([b"RLD-SURVIVOR-1/TRANSACTIONS\0".as_slice(), &bad[268..]].concat());
    bad[188..220].copy_from_slice(&root);
    mine_header(&mut bad);
    for _ in 0..3 {
        assert!(block_syntax(&bad, pin).is_err());
        block_syntax(&good, pin).unwrap();
    }
    std::thread::spawn(move || assert!(block_syntax(&bad, pin).is_err()))
        .join()
        .unwrap();
}

#[test]
fn intrinsically_valid_repeated_body_never_installs_a_false_state_root() {
    let (v, pin) = fixtures();
    let g = hex::decode(v["genesis"]["manifest_hex"].as_str().unwrap()).unwrap();
    let mut ledger = Ledger::from_genesis(&g, pin, 1_000_000).unwrap();
    for block in &v["main_branch"].as_array().unwrap()[..100] {
        ledger
            .execute(&hex::decode(block["block_hex"].as_str().unwrap()).unwrap())
            .unwrap();
    }
    let prior = ledger.tip().clone();
    let coins = ledger.coins().clone();
    let mut false_root = payment(&v);
    false_root[220] ^= 1;
    mine_header(&mut false_root);
    for _ in 0..3 {
        block_syntax(&false_root, pin).unwrap();
        assert!(ledger.execute(&false_root).is_err());
        assert_eq!(ledger.tip(), &prior);
        assert_eq!(ledger.coins(), &coins);
    }
    ledger.execute(&payment(&v)).unwrap();
    assert_eq!(ledger.tip().height(), 101);
}

#[test]
fn repeated_payload_still_authenticates_each_packet_frame_and_challenge() {
    let (v, pin) = fixtures();
    let raw = payment(&v);
    block_syntax(&raw, pin).unwrap();
    // Deliberately public NO-VALUE transport fixture keys.
    let a = SigningKey::from_bytes(&[11; 32]);
    let b = SigningKey::from_bytes(&[12; 32]);
    let pa = a.verifying_key().to_bytes();
    let pb = b.verifying_key().to_bytes();
    for sequence in 1..=3 {
        let packet = Packet::sign(pin, &a, peer_id(pb), sequence, 3, &raw).unwrap();
        let mut bad_packet = packet.raw().to_vec();
        *bad_packet.last_mut().unwrap() ^= 0x80;
        assert!(Packet::decode(&bad_packet, pin).is_err());
        let frame = Frame::delivery(pin, &a, peer_id(pb), [3; 32], [4; 32], &packet).unwrap();
        frame
            .authenticate_delivery(pa, peer_id(pb), [3; 32], false)
            .unwrap();
        assert!(frame
            .authenticate_delivery(pa, peer_id(pb), [5; 32], false)
            .is_err());
        let mut bad_frame = frame.raw().to_vec();
        *bad_frame.last_mut().unwrap() ^= 0x80;
        assert!(Frame::decode(&bad_frame, pin).is_err());
    }
}
