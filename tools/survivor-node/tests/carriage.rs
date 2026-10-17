//! PUBLIC NO-VALUE contact fixtures. Keys are deterministic public examples only.
use ed25519_dalek::SigningKey;
use rld_survivor_node::{
    carriage::{Budget, Carriage},
    contact::{peer_id, Frame},
};
use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "rld-survivor-carriage-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}
fn identity(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
fn head() -> Vec<u8> {
    vec![0; 96]
}
#[test]
fn directed_offline_hops_asymmetric_receipt_and_restart() {
    let chain = [7; 32];
    let a = identity(1);
    let b = identity(2);
    let c = identity(3);
    let d = identity(4);
    let ka = a.verifying_key().to_bytes();
    let kb = b.verifying_key().to_bytes();
    let kc = c.verifying_key().to_bytes();
    let kd = d.verifying_key().to_bytes();
    let ra = root();
    let rb = root();
    let rc = root();
    let rd = root();
    let mut sa = Carriage::open(&ra, chain, ka, Budget::default()).unwrap();
    let mut sb = Carriage::open(&rb, chain, kb, Budget::default()).unwrap();
    let mut sc = Carriage::open(&rc, chain, kc, Budget::default()).unwrap();
    let mut sd = Carriage::open(&rd, chain, kd, Budget::default()).unwrap();
    let p = sa.originate(&a, peer_id(kc), 4, &head()).unwrap();
    let delivery = Frame::delivery(chain, &a, peer_id(kb), [0; 32], [1; 32], &p).unwrap();
    let hop = sb
        .receive(delivery.raw(), ka, [0; 32], true, &b)
        .unwrap()
        .unwrap();
    assert_eq!(hop.authenticate_receipt(&delivery, kb).unwrap(), 0);
    assert!(!hop.discharges(&p));
    assert!(sa.retain_destination_receipt(&p, &hop).is_err());
    let (_, batch) = sb.prepare(&[ka, kc], &BTreeSet::new()).unwrap().unwrap();
    let (_, batch2) = sb.prepare(&[ka, kc], &BTreeSet::new()).unwrap().unwrap();
    assert!(batch.iter().chain(batch2.iter()).any(|x| x.id() == p.id()));
    let to_c = Frame::delivery(chain, &b, peer_id(kc), [0; 32], [2; 32], &p).unwrap();
    let receipt = sc
        .receive(to_c.raw(), kb, [0; 32], true, &c)
        .unwrap()
        .unwrap();
    assert!(receipt.discharges(&p));
    sb.retain_destination_receipt(&p, &receipt).unwrap();
    let back = sc.originate(&c, peer_id(ka), 9, receipt.raw()).unwrap();
    let to_d = Frame::delivery(chain, &c, peer_id(kd), [0; 32], [3; 32], &back).unwrap();
    assert!(sd
        .receive(to_d.raw(), kc, [0; 32], true, &d)
        .unwrap()
        .is_none());
    assert!(sd.packet(p.id()).unwrap().is_none());
    assert!(sd.packet(back.id()).unwrap().is_some());
    let to_a = Frame::delivery(chain, &d, peer_id(ka), [0; 32], [4; 32], &back).unwrap();
    assert!(sa
        .receive(to_a.raw(), kd, [0; 32], true, &a)
        .unwrap()
        .is_none());
    assert!(sa
        .prepare(&[kb], &BTreeSet::new())
        .unwrap()
        .unwrap()
        .1
        .is_empty());
    drop(sa);
    drop(sb);
    let mut sa = Carriage::open(&ra, chain, ka, Budget::default()).unwrap();
    assert!(sa.packet(p.id()).unwrap().is_some());
    assert!(sa
        .prepare(&[kb], &BTreeSet::new())
        .unwrap()
        .unwrap()
        .1
        .is_empty());
    let sb = Carriage::open(&rb, chain, kb, Budget::default()).unwrap();
    assert_eq!(sb.packet(p.id()).unwrap().unwrap().raw(), p.raw());
}
#[test]
fn custody_capacity_duplicate_and_session_refusal() {
    let chain = [8; 32];
    let a = identity(5);
    let b = identity(6);
    let ka = a.verifying_key().to_bytes();
    let kb = b.verifying_key().to_bytes();
    let mut sa = Carriage::open(&root(), chain, ka, Budget::default()).unwrap();
    let mut sb = Carriage::open(
        &root(),
        chain,
        kb,
        Budget {
            packets: 1,
            ..Budget::default()
        },
    )
    .unwrap();
    let p = sa.originate(&a, peer_id(kb), 4, &head()).unwrap();
    let f = Frame::delivery(chain, &a, peer_id(kb), [0; 32], [1; 32], &p).unwrap();
    assert!(sb.receive(f.raw(), ka, [0; 32], false, &b).is_err());
    let receipt = sb.receive(f.raw(), ka, [0; 32], true, &b).unwrap().unwrap();
    assert!(receipt.discharges(&p));
    assert!(sb
        .receive(f.raw(), ka, [0; 32], true, &b)
        .unwrap()
        .unwrap()
        .discharges(&p));
    let q = sa.originate(&a, peer_id(kb), 4, &head()).unwrap();
    let f = Frame::delivery(chain, &a, peer_id(kb), [0; 32], [2; 32], &q).unwrap();
    let refused = sb.receive(f.raw(), ka, [0; 32], true, &b).unwrap().unwrap();
    assert_eq!(refused.authenticate_receipt(&f, kb).unwrap(), 2);
    assert!(sb.packet(q.id()).unwrap().is_none());
    assert!(sb.packet(p.id()).unwrap().is_some());
}

#[test]
fn offline_delivery_restart_and_completion_collection_preserve_live_obligations() {
    let chain = [19; 32];
    let a = identity(21);
    let b = identity(22);
    let ka = a.verifying_key().to_bytes();
    let kb = b.verifying_key().to_bytes();
    let ra = root();
    let rb = root();
    let mut sa = Carriage::open(&ra, chain, ka, Budget::default()).unwrap();
    let mut sb = Carriage::open(&rb, chain, kb, Budget::default()).unwrap();
    let live = sa.originate(&a, peer_id(kb), 4, &head()).unwrap();
    let f = sa.prepare_offline(&a, kb, &live).unwrap();
    let original = f.raw().to_vec();
    drop(sa);
    let mut sa = Carriage::open(&ra, chain, ka, Budget::default()).unwrap();
    assert_eq!(sa.prepare_offline(&a, kb, &live).unwrap().raw(), original);
    let mut first = None;
    for _ in 0..258 {
        let p = sa.originate(&a, peer_id(kb), 4, &head()).unwrap();
        if first.is_none() {
            first = Some(p.id());
        }
        let f = sa.prepare_offline(&a, kb, &p).unwrap();
        let r = sb.receive(f.raw(), ka, [0; 32], true, &b).unwrap().unwrap();
        sa.offline_receipt(r.raw(), kb).unwrap();
        sa.processed(p.id()).unwrap();
        sb.processed(p.id()).unwrap();
    }
    sa.compact_completed().unwrap();
    assert!(sa.packet(first.unwrap()).unwrap().is_none());
    assert!(sa.packet(live.id()).unwrap().is_some());
    // A forged nonce cannot discharge even an authentic exact-packet receipt.
    let other = Frame::delivery(chain, &a, peer_id(kb), [0; 32], [9; 32], &live).unwrap();
    let r = sb
        .receive(other.raw(), ka, [0; 32], true, &b)
        .unwrap()
        .unwrap();
    assert!(sa.offline_receipt(r.raw(), kb).is_err());
    drop(sa);
    let sa = Carriage::open(&ra, chain, ka, Budget::default()).unwrap();
    assert!(sa.packet(live.id()).unwrap().is_some());
}
#[test]
fn repeated_outstanding_offer_preserves_one_exact_origin_packet() {
    let a = identity(23);
    let b = identity(24);
    let chain = [29; 32];
    let mut s = Carriage::open(
        &root(),
        chain,
        a.verifying_key().to_bytes(),
        Budget::default(),
    )
    .unwrap();
    let first = s
        .originate_unique(&a, peer_id(b.verifying_key().to_bytes()), 4, &head())
        .unwrap();
    for _ in 0..128 {
        assert_eq!(
            s.originate_unique(&a, peer_id(b.verifying_key().to_bytes()), 4, &head())
                .unwrap()
                .raw(),
            first.raw()
        );
    }
    let other = s
        .originate_unique(&a, peer_id(b.verifying_key().to_bytes()), 4, &[1; 96])
        .unwrap();
    assert_ne!(other.id(), first.id());
}
