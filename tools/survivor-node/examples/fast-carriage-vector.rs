//! PUBLIC NO-VALUE deterministic codec material only. No generated operator
//! identity, wallet, policy or private state is emitted. Frames are assembled
//! independently of the transport codec encoder.
use ed25519_dalek::{Signer, SigningKey};
use rld_survivor_node::kernel::{fast, Hash};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
fn tag(s: &str) -> Vec<u8> {
    [b"RLD-FAST-PEER-1/".as_slice(), s.as_bytes(), &[0]].concat()
}
fn hash(s: &str, raw: &[u8]) -> Hash {
    Sha256::digest([tag(s), raw.to_vec()].concat()).into()
}
fn main() {
    let v: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/native-fast-escrow-v1-vectors.json"
    ))
    .unwrap();
    let genesis = hex::decode(v["genesis_hex"].as_str().unwrap()).unwrap();
    let chain = fast::genesis_id(&genesis);
    let observed = u64::from_be_bytes(genesis[45..53].try_into().unwrap()) + 1800;
    let mut ledger = fast::Ledger::from_genesis(&genesis, chain, 100000).unwrap();
    let key = SigningKey::from_bytes(&[181; 32]);
    let destination = SigningKey::from_bytes(&[182; 32])
        .verifying_key()
        .to_bytes();
    let mut blocks = vec![];
    for _ in 0..2 {
        let mut job = ledger
            .mining_job(
                key.verifying_key().to_bytes(),
                vec![],
                ledger.tip().timestamp() + 600,
                observed,
            )
            .unwrap();
        let mut found = None;
        for _ in 0..1024 {
            if let (Some(raw), _) = job.search(4096) {
                found = Some(raw);
                break;
            }
        }
        let raw = found.unwrap();
        ledger.execute(&raw, observed).unwrap();
        blocks.push(raw);
    }
    let mut frame = b"RLDFBLK1".to_vec();
    frame.extend([0, 1, 0, 1]);
    frame.extend(chain);
    frame.extend(1u64.to_be_bytes());
    frame.extend(2u16.to_be_bytes());
    for raw in &blocks {
        frame.extend((raw.len() as u32).to_be_bytes());
        frame.extend(raw);
    }
    let mut packet = vec![0, 1, 0, 1];
    packet.extend(chain);
    packet.extend(key.verifying_key().to_bytes());
    packet.extend(destination);
    packet.push(9);
    let message = hash("MESSAGE", &[packet.as_slice(), &frame].concat());
    packet.extend(message);
    packet.extend((frame.len() as u32).to_be_bytes());
    packet.extend(&frame);
    let signature = key.sign(&[tag("PACKET"), packet.clone()].concat());
    packet.extend(signature.to_bytes());
    println!("{}",serde_json::to_string_pretty(&json!({"format":"RLD-FAST-BLOCK-BATCH-1-PUBLIC-VECTOR","classification":"PUBLIC_NO_VALUE_ONLY","scope":"Independent data framing/signatures plus two native empty PoW blocks. Not an adopted network, monetary custody, performance or full-service qualification.","public_sender_seed_hex":hex::encode([181;32]),"public_destination_seed_hex":hex::encode([182;32]),"genesis_hex":hex::encode(genesis),"chain_hex":hex::encode(chain),"observed_time":observed.to_string(),"first_source_record":"1","blocks_hex":blocks.iter().map(hex::encode).collect::<Vec<_>>(),"batch_hex":hex::encode(frame),"packet_hex":hex::encode(&packet),"packet_id_hex":hex::encode(hash("PACKET-ID",&packet))})).unwrap());
}
