//! Public NO-VALUE contact fixtures. Warm re-emission must bind the exact
//! retained packet and offline roles, even when substituted signatures are valid.
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
use ed25519_dalek::{Signer, SigningKey};
use rld_survivor_node::{
    carriage::{Budget, Carriage},
    contact::{peer_id, Frame, Packet},
    kernel::Hash,
};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256, Sha512};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
fn root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "rld-survivor-offline-binding-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}
fn snapshot(db: &Connection) -> (i64, i64, i64, i64, Vec<u8>) {
    db.query_row(
        "SELECT (SELECT count(*) FROM packets),(SELECT count(*) FROM offline_out),(SELECT count(*) FROM receipts),(SELECT count(*) FROM hop_receipts),sequence FROM identity WHERE one=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
    )
    .unwrap()
}

// Test-only alternate nonce for a published fixture seed. Two fully valid
// signatures on identical unsigned bytes distinguish exact custody from ID-only
// comparison. This is never an operator signing implementation.
fn alternate_signature(packet: &Packet, chain: Hash, seed: [u8; 32]) -> Packet {
    let expanded = Sha512::digest(seed);
    let mut clamped: [u8; 32] = expanded[..32].try_into().unwrap();
    clamped[0] &= 248;
    clamped[31] &= 63;
    clamped[31] |= 64;
    let secret = Scalar::from_bytes_mod_order(clamped);
    let nonce = Scalar::from(17u64);
    let r = (ED25519_BASEPOINT_POINT * nonce).compress().to_bytes();
    let unsigned = &packet.raw()[..packet.raw().len() - 64];
    let message = [b"RLD-SURVIVOR-1/PACKET-SIGN\0".as_slice(), unsigned].concat();
    let challenge: [u8; 64] =
        Sha512::digest([r.as_slice(), packet.origin().as_slice(), &message].concat()).into();
    let s = nonce + Scalar::from_bytes_mod_order_wide(&challenge) * secret;
    let raw = [unsigned, r.as_slice(), s.to_bytes().as_slice()].concat();
    let alternate = Packet::decode(&raw, chain).unwrap();
    assert_eq!(alternate.id(), packet.id());
    assert_ne!(alternate.raw(), packet.raw());
    alternate
}

#[test]
fn retained_offline_delivery_rechecks_exact_bytes_roles_and_session() {
    for case in 0..7 {
        let mut chain = [0; 32];
        getrandom::getrandom(&mut chain).unwrap();
        let a = SigningKey::from_bytes(&[91; 32]);
        let b = SigningKey::from_bytes(&[92; 32]);
        let c = SigningKey::from_bytes(&[93; 32]);
        let ka = a.verifying_key().to_bytes();
        let kb = b.verifying_key().to_bytes();
        let path = root();
        let mut carriage = Carriage::open(&path, chain, ka, Budget::default()).unwrap();
        let packet = carriage.originate(&a, peer_id(kb), 4, &[0; 96]).unwrap();
        let other = carriage.originate(&a, peer_id(kb), 4, &[1; 96]).unwrap();
        let original = carriage.prepare_offline(&a, kb, &packet).unwrap();
        let db = Connection::open(path.join("carriage.sqlite3")).unwrap();
        let before_retry = snapshot(&db);
        assert_eq!(
            carriage.prepare_offline(&a, kb, &packet).unwrap().raw(),
            original.raw()
        );
        assert_eq!(snapshot(&db), before_retry);
        let replacement = match case {
            0 => carriage.prepare_offline(&a, kb, &other).unwrap(),
            1 => Frame::delivery(
                chain,
                &a,
                peer_id(c.verifying_key().to_bytes()),
                [0; 32],
                [4; 32],
                &packet,
            )
            .unwrap(),
            2 => Frame::challenge(chain, &a, peer_id(kb), [5; 32]).unwrap(),
            3 => Frame::delivery(chain, &c, peer_id(kb), [0; 32], [4; 32], &packet).unwrap(),
            4 => Frame::delivery(chain, &a, peer_id(kb), [5; 32], [4; 32], &packet).unwrap(),
            5 => {
                let alternate = alternate_signature(&packet, chain, [91; 32]);
                Frame::delivery(chain, &a, peer_id(kb), [0; 32], [4; 32], &alternate).unwrap()
            }
            _ => {
                let mut raw = original.raw().to_vec();
                raw[141..173].fill(0);
                let end = raw.len() - 64;
                let signature =
                    a.sign(&[b"RLD-SURVIVOR-1/DELIVER\0".as_slice(), &raw[13..end]].concat());
                raw[end..].copy_from_slice(&signature.to_bytes());
                Frame::decode(&raw, chain).unwrap()
            }
        };
        Frame::decode(replacement.raw(), chain).unwrap();
        assert_eq!(
            db.execute(
                "UPDATE offline_out SET raw=?1 WHERE peer=?2 AND packet=?3",
                params![replacement.raw(), kb.as_slice(), packet.id().as_slice()],
            )
            .unwrap(),
            1
        );
        let before = snapshot(&db);
        let database_before = Sha256::digest(fs::read(path.join("carriage.sqlite3")).unwrap());
        assert!(carriage.prepare_offline(&a, kb, &packet).is_err(), "{case}");
        let retained: Vec<u8> = db
            .query_row(
                "SELECT raw FROM offline_out WHERE peer=?1 AND packet=?2",
                params![kb.as_slice(), packet.id().as_slice()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(retained, replacement.raw());
        assert_eq!(snapshot(&db), before);
        assert_eq!(
            Sha256::digest(fs::read(path.join("carriage.sqlite3")).unwrap()),
            database_before
        );
        drop(db);
        drop(carriage);
        assert!(Carriage::open(&path, chain, ka, Budget::default()).is_err());
    }
}

#[test]
fn warm_packet_index_substitution_cannot_answer_or_reacknowledge() {
    for case in 0..4 {
        let mut chain = [0; 32];
        getrandom::getrandom(&mut chain).unwrap();
        let a = SigningKey::from_bytes(&[91; 32]);
        let b = SigningKey::from_bytes(&[92; 32]);
        let ka = a.verifying_key().to_bytes();
        let kb = b.verifying_key().to_bytes();
        let path = root();
        let mut carriage = Carriage::open(&path, chain, ka, Budget::default()).unwrap();
        let packet = carriage.originate(&a, peer_id(kb), 4, &[0; 96]).unwrap();
        let other = carriage.originate(&a, peer_id(kb), 4, &[1; 96]).unwrap();
        assert_eq!(
            carriage.packet(packet.id()).unwrap().unwrap().raw(),
            packet.raw()
        );
        let db = Connection::open(path.join("carriage.sqlite3")).unwrap();
        let changed = match case {
            0 => db.execute(
                "UPDATE packets SET raw=?1 WHERE id=?2",
                params![other.raw(), packet.id().as_slice()],
            ),
            1 => db.execute(
                "UPDATE packets SET origin=?1 WHERE id=?2",
                params![kb.as_slice(), packet.id().as_slice()],
            ),
            2 => db.execute(
                "UPDATE packets SET sequence=?1 WHERE id=?2",
                params![99u128.to_be_bytes().as_slice(), packet.id().as_slice()],
            ),
            _ => db.execute(
                "UPDATE packets SET kind=3 WHERE id=?1",
                [packet.id().as_slice()],
            ),
        }
        .unwrap();
        assert_eq!(changed, 1);
        let before = snapshot(&db);
        let database_before = Sha256::digest(fs::read(path.join("carriage.sqlite3")).unwrap());
        assert!(carriage.packet(packet.id()).is_err(), "{case}");
        let duplicate =
            Frame::delivery(chain, &b, peer_id(ka), [11; 32], [12; 32], &packet).unwrap();
        assert!(carriage
            .receive(duplicate.raw(), kb, [11; 32], false, &a)
            .is_err());
        assert_eq!(snapshot(&db), before);
        assert_eq!(
            Sha256::digest(fs::read(path.join("carriage.sqlite3")).unwrap()),
            database_before
        );
        drop(db);
        drop(carriage);
        assert!(Carriage::open(&path, chain, ka, Budget::default()).is_err());
    }
}

#[test]
fn retained_offline_receipt_rechecks_exact_delivery_before_custody_changes() {
    let mut failures = Vec::new();
    for case in [
        "wrong_receiver",
        "wrong_sender",
        "interactive_challenge",
        "zero_nonce",
        "same_id_other_signature",
        "other_packet",
    ] {
        // Deliberately public, NO-VALUE fixture seeds; never operator custody.
        let chain = [94; 32];
        let a = SigningKey::from_bytes(&[91; 32]);
        let b = SigningKey::from_bytes(&[92; 32]);
        let c = SigningKey::from_bytes(&[93; 32]);
        let ka = a.verifying_key().to_bytes();
        let kb = b.verifying_key().to_bytes();
        let path = root();
        let mut carriage = Carriage::open(&path, chain, ka, Budget::default()).unwrap();
        let packet = carriage.originate(&a, peer_id(kb), 4, &[0; 96]).unwrap();
        let other = carriage.originate(&a, peer_id(kb), 4, &[1; 96]).unwrap();
        let control = carriage.originate(&a, peer_id(kb), 4, &[2; 96]).unwrap();
        let original = carriage.prepare_offline(&a, kb, &packet).unwrap();
        let control_delivery = carriage.prepare_offline(&a, kb, &control).unwrap();
        let control_receipt = Frame::receipt(chain, &b, &control_delivery, 1).unwrap();
        carriage.offline_receipt(control_receipt.raw(), kb).unwrap();
        let db = Connection::open(path.join("carriage.sqlite3")).unwrap();
        assert_eq!(snapshot(&db).2, 1, "{case}: authentic destination control");
        assert_eq!(snapshot(&db).3, 1, "{case}: authentic hop control");

        let replacement = match case {
            "wrong_receiver" => Frame::delivery(
                chain,
                &a,
                peer_id(c.verifying_key().to_bytes()),
                [0; 32],
                [4; 32],
                &packet,
            )
            .unwrap(),
            "wrong_sender" => {
                Frame::delivery(chain, &c, peer_id(kb), [0; 32], [4; 32], &packet).unwrap()
            }
            "interactive_challenge" => {
                Frame::delivery(chain, &a, peer_id(kb), [5; 32], [4; 32], &packet).unwrap()
            }
            "zero_nonce" => {
                let mut raw = original.raw().to_vec();
                raw[141..173].fill(0);
                let end = raw.len() - 64;
                let signature =
                    a.sign(&[b"RLD-SURVIVOR-1/DELIVER\0".as_slice(), &raw[13..end]].concat());
                raw[end..].copy_from_slice(&signature.to_bytes());
                Frame::decode(&raw, chain).unwrap()
            }
            "same_id_other_signature" => {
                let alternate = alternate_signature(&packet, chain, [91; 32]);
                Frame::delivery(chain, &a, peer_id(kb), [0; 32], [4; 32], &alternate).unwrap()
            }
            "other_packet" => {
                Frame::delivery(chain, &a, peer_id(kb), [0; 32], [4; 32], &other).unwrap()
            }
            _ => unreachable!(),
        };
        // Every edited delivery and receipt has a valid real signature. Only
        // the independent durable row/role/exact-byte binding is incorrect.
        Frame::decode(replacement.raw(), chain).unwrap();
        let receipt = if matches!(case, "interactive_challenge" | "other_packet") {
            Frame::receipt(chain, &b, &original, 1).unwrap()
        } else {
            Frame::receipt(chain, &b, &replacement, 1).unwrap()
        };
        Frame::decode(receipt.raw(), chain).unwrap();
        assert_eq!(
            db.execute(
                "UPDATE offline_out SET raw=?1 WHERE peer=?2 AND packet=?3",
                params![replacement.raw(), kb.as_slice(), packet.id().as_slice()],
            )
            .unwrap(),
            1
        );
        let before = snapshot(&db);
        let database_before = fs::read(path.join("carriage.sqlite3")).unwrap();
        if carriage.offline_receipt(receipt.raw(), kb).is_ok() {
            failures.push(format!("{case}: accepted substituted retained delivery"));
        }
        if snapshot(&db) != before {
            failures.push(format!("{case}: changed custody counts or sequence"));
        }
        if fs::read(path.join("carriage.sqlite3")).unwrap() != database_before {
            failures.push(format!("{case}: changed retained SQLite bytes"));
        }
        drop(db);
        drop(carriage);
        if Carriage::open(&path, chain, ka, Budget::default()).is_ok() {
            failures.push(format!(
                "{case}: cold startup accepted substituted delivery"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
