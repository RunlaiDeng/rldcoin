//! Ordinary lifecycle file carriage; finite ground delay and independently pinned peers.
use rld_survivor_node::{
    kernel::genesis_id,
    network::Network,
    store::{Limits, Store},
};
use serde_json::{json, Value};
use std::time::{Duration, Instant};
#[test]
fn admitted_file_adapter_syncs_complete_history_without_a_tcp_neighbor() {
    let v: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/survivor-v1/vectors.json"
    ))
    .unwrap();
    let g = hex::decode(v["genesis"]["manifest_hex"].as_str().unwrap()).unwrap();
    let pin = genesis_id(&g);
    let root = std::env::temp_dir().join(format!("rld-survivor-offline-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let mut a = Store::open(&root.join("a"), &g, pin, Limits::default()).unwrap();
    let mut b = Store::open(&root.join("b"), &g, pin, Limits::default()).unwrap();
    for (i, x) in v["main_branch"].as_array().unwrap()[..3].iter().enumerate() {
        a.accept(
            [i as u8 + 1; 32],
            &hex::decode(x["block_hex"].as_str().unwrap()).unwrap(),
            2_000_000_000,
        )
        .unwrap();
    }
    let na = Network::open(&root.join("a/contact"), pin, None).unwrap();
    let nb = Network::open(&root.join("b/contact"), pin, None).unwrap();
    let ka = na.status()["identity"].as_str().unwrap().to_string();
    let kb = nb.status()["identity"].as_str().unwrap().to_string();
    drop(na);
    drop(nb);
    let cfg = |peer: &str| {
        serde_json::to_vec(&json!({"listen":"127.0.0.1:0","neighbors":[],"offline_peers":[peer]}))
            .unwrap()
    };
    // An expired ground certificate must not disable independently admitted files.
    let mut parameters = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    parameters.not_before = rcgen::date_time_ymd(2000, 1, 1);
    parameters.not_after = rcgen::date_time_ymd(2001, 1, 1);
    parameters.distinguished_name = rcgen::DistinguishedName::new();
    parameters
        .distinguished_name
        .push(rcgen::DnType::CommonName, ka.clone());
    parameters
        .distinguished_name
        .push(rcgen::DnType::OrganizationalUnitName, hex::encode(pin));
    parameters.is_ca = rcgen::IsCa::ExplicitNoCa;
    let tlskey = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let cert = parameters.self_signed(&tlskey).unwrap();
    let mut material = (cert.der().len() as u32).to_be_bytes().to_vec();
    material.extend(cert.der().iter());
    material.extend(tlskey.serialize_der());
    std::fs::write(root.join("a/contact/tls.secret"), material).unwrap();
    let mut na = Network::open(&root.join("a/contact"), pin, Some(&cfg(&kb))).unwrap();
    let mut nb = Network::open(&root.join("b/contact"), pin, Some(&cfg(&ka))).unwrap();
    let ka = hex::decode(ka).unwrap().try_into().unwrap();
    let kb = hex::decode(kb).unwrap().try_into().unwrap();
    assert!(na.offline_export([0; 32]).is_err());
    let deadline = Instant::now() + Duration::from_secs(60);
    while b.ledger().tip().id() != a.ledger().tip().id() {
        assert!(Instant::now() < deadline, "offline sync deadline");
        na.tick(&mut a, 2_000_000_000).unwrap();
        nb.tick(&mut b, 2_000_000_000).unwrap();
        for frame in na.offline_export(kb).unwrap() {
            let file = root.join("forward.frame");
            std::fs::write(&file, frame).unwrap();
            if let Some(r) = nb
                .offline_import(ka, &std::fs::read(file).unwrap())
                .unwrap()
            {
                na.offline_import(kb, &r).unwrap();
            }
        }
        for frame in nb.offline_export(ka).unwrap() {
            if let Some(r) = na.offline_import(kb, &frame).unwrap() {
                nb.offline_import(ka, &r).unwrap();
            }
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    assert_eq!(a.ledger().coins(), b.ledger().coins());
    drop(nb);
    drop(b);
    let b = Store::open(&root.join("b"), &g, pin, Limits::default()).unwrap();
    assert_eq!(b.ledger().tip().height(), 3);
}
