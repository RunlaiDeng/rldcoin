//! Same-host TLS ground fixture. Public NO-VALUE contact keys, fresh private TLS
//! materials retained only in process memory; not physical-route qualification.
use ed25519_dalek::SigningKey;
use rld_survivor_node::{
    carriage::{Budget, Carriage},
    contact::peer_id,
    tls::{self, Material, Neighbor},
};
use std::{
    net::TcpListener,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
fn run(wrong_pin: bool) {
    let chain = [9; 32];
    let a = SigningKey::from_bytes(&[11; 32]);
    let b = SigningKey::from_bytes(&[12; 32]);
    let ka = a.verifying_key().to_bytes();
    let kb = b.verifying_key().to_bytes();
    let (c, k) = Material::generate(chain, ka).unwrap();
    let ma = Material::from_der(c, k, chain, ka).unwrap();
    let (c, k) = Material::generate(chain, kb).unwrap();
    let mb = Material::from_der(c, k, chain, kb).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = listener.local_addr().unwrap();
    let pa = Neighbor {
        key: ka,
        endpoint,
        certificate_sha256: ma.fingerprint(),
    };
    let pb = Neighbor {
        key: kb,
        endpoint,
        certificate_sha256: if wrong_pin { [0; 32] } else { mb.fingerprint() },
    };
    let config = tls::server(&mb, chain, vec![pa.clone()]).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let parent = std::env::temp_dir().join(format!(
        "rld-survivor-tls-{}-{wrong_pin}",
        std::process::id()
    ));
    std::fs::create_dir(&parent).unwrap();
    let inbound = parent.join("in");
    let worker = std::thread::spawn(move || {
        let mut custody = Carriage::open(&inbound, chain, kb, Budget::default()).unwrap();
        let socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(e) => panic!("accept: {e}"),
            }
        };
        tls::accept(
            socket,
            config,
            chain,
            &b,
            &[pa],
            |raw, sender, challenge| {
                seen.fetch_add(1, Ordering::Relaxed);
                custody.receive(raw, sender, challenge, false, &b)
            },
        )
    });
    let mut out = Carriage::open(&parent.join("out"), chain, ka, Budget::default()).unwrap();
    let packet = out.originate(&a, peer_id(kb), 4, &[0; 96]).unwrap();
    let result = tls::deliver(&ma, chain, &a, &pb, &packet);
    let accepted = worker.join().unwrap();
    if wrong_pin {
        assert!(result.is_err());
        assert!(accepted.is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    } else {
        let receipt = result.unwrap().unwrap();
        assert!(receipt.discharges(&packet));
        out.retain_destination_receipt(&packet, &receipt).unwrap();
        accepted.unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }
}
#[test]
fn exact_tls13_mutual_pins_application_challenge_and_durable_custody() {
    run(false)
}
#[test]
fn wrong_tls_pin_never_reaches_custody() {
    run(true)
}
