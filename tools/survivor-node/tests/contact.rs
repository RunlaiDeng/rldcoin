//! Exact public NO-VALUE O07/O08 fixture bytes and negative binding cases.
use rld_survivor_node::contact::{peer_id, Frame, Packet};
use serde_json::Value;
fn fixture() -> (Value, [u8; 32]) {
    let v: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/survivor-v1/vectors.json"
    ))
    .unwrap();
    let chain = hex::decode(v["genesis"]["chain_id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    (v, chain)
}
fn raw(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(v["contact"][k].as_str().unwrap()).unwrap()
}
#[test]
fn exact_packet_frames_return_receipt_and_session_replay() {
    let (v, c) = fixture();
    let p = Packet::decode(&raw(&v, "packet_hex"), c).unwrap();
    assert_eq!(hex::encode(p.id()), v["contact"]["packet_id"]);
    let challenge = Frame::decode(&raw(&v, "challenge_frame_hex"), c).unwrap();
    let delivery = Frame::decode(&raw(&v, "delivery_frame_hex"), c).unwrap();
    let receipt = Frame::decode(&raw(&v, "destination_receipt_frame_hex"), c).unwrap();
    let returned = Packet::decode(&raw(&v, "return_receipt_packet_hex"), c).unwrap();
    assert_eq!(returned.kind(), 9);
    assert!(receipt.discharges(&p));
    assert_eq!(
        receipt
            .authenticate_receipt(&delivery, receipt.sender())
            .unwrap(),
        1
    );
    assert!(delivery
        .authenticate_delivery(
            delivery.sender(),
            delivery.receiver(),
            challenge.challenge_nonce(),
            false
        )
        .is_ok());
    assert!(delivery
        .authenticate_delivery(delivery.sender(), delivery.receiver(), [0; 32], false)
        .is_err());
    assert!(delivery
        .authenticate_delivery(delivery.sender(), delivery.receiver(), [0; 32], true)
        .is_err());
    assert!(receipt
        .authenticate_receipt(&delivery, delivery.sender())
        .is_err());
    assert_eq!(peer_id(receipt.sender()), p.destination());
}
#[test]
fn altered_truncated_oversized_packet_and_frames_never_authenticate() {
    let (v, c) = fixture();
    let p = raw(&v, "packet_hex");
    for i in 0..p.len() {
        let mut b = p.clone();
        b[i] ^= 1;
        assert!(Packet::decode(&b, c).is_err(), "packet {i}");
    }
    for key in [
        "challenge_frame_hex",
        "delivery_frame_hex",
        "destination_receipt_frame_hex",
    ] {
        let f = raw(&v, key);
        for i in 0..f.len() {
            let mut b = f.clone();
            b[i] ^= 1;
            assert!(Frame::decode(&b, c).is_err(), "{key} {i}");
        }
        assert!(Frame::decode(&f[..f.len() - 1], c).is_err());
    }
    assert!(Packet::decode(&p, [0; 32]).is_err());
    assert!(Packet::decode(&vec![0; 1_048_348], c).is_err());
}
