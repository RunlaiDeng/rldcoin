//! PUBLIC NO-VALUE deterministic contact keys. Actual native custody APIs only;
//! no copied node/value/private-key state, modeled signature or receipt authority.
use ed25519_dalek::SigningKey;
use rld_survivor_node::{
    carriage::{Budget, Carriage},
    contact::{peer_id, Frame, Packet},
};
use rusqlite::OptionalExtension;

#[test]
fn return_wrapper_cannot_bypass_known_origin_sequence_conflict() {
    let root = std::env::temp_dir().join(format!(
        "rld-return-sequence-counter-{}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    let chain = [41; 32];
    let a = SigningKey::from_bytes(&[81; 32]);
    let b = SigningKey::from_bytes(&[82; 32]);
    let c = SigningKey::from_bytes(&[83; 32]);
    let ka = a.verifying_key().to_bytes();
    let kb = b.verifying_key().to_bytes();
    let kc = c.verifying_key().to_bytes();
    let b_root = root.join("b");
    let c_root = root.join("c");
    let mut sb = Carriage::open(&b_root, chain, kb, Budget::default()).unwrap();
    let mut sc = Carriage::open(&c_root, chain, kc, Budget::default()).unwrap();
    let original = sb.originate(&b, peer_id(kc), 4, &[0; 96]).unwrap();
    let delivery = Frame::delivery(chain, &b, peer_id(kc), [0; 32], [1; 32], &original).unwrap();
    let receipt = sc
        .receive(delivery.raw(), kb, [0; 32], true, &c)
        .unwrap()
        .unwrap();
    assert!(receipt.discharges(&original));
    let first = Packet::sign(chain, &a, peer_id(kb), 1, 4, &[0; 96]).unwrap();
    let first_frame = Frame::delivery(chain, &a, peer_id(kb), [0; 32], [2; 32], &first).unwrap();
    assert!(sb
        .receive(first_frame.raw(), ka, [0; 32], true, &b)
        .unwrap()
        .is_some());
    let higher = Packet::sign(chain, &a, peer_id(kb), 3, 4, &[0; 96]).unwrap();
    let high_frame = Frame::delivery(chain, &a, peer_id(kb), [0; 32], [5; 32], &higher).unwrap();
    sb.receive(high_frame.raw(), ka, [0; 32], true, &b).unwrap();
    let conflict = Packet::sign(chain, &a, peer_id(kb), 1, 9, receipt.raw()).unwrap();
    let bad = Frame::delivery(chain, &a, peer_id(kb), [0; 32], [3; 32], &conflict).unwrap();
    let result = sb.receive(bad.raw(), ka, [0; 32], true, &b);
    let db = rusqlite::Connection::open_with_flags(
        b_root.join("carriage.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let rows: i64 = db
        .query_row("SELECT count(*) FROM equivocation", [], |r| r.get(0))
        .unwrap();
    let stored: Option<Vec<u8>> = db
        .query_row(
            "SELECT raw FROM receipts WHERE packet=?1",
            [original.id().as_slice()],
            |r| r.get(0),
        )
        .optional()
        .unwrap();
    drop(db);
    let discharged = stored
        .map(|raw| Frame::decode(&raw, chain).unwrap().discharges(&original))
        .unwrap_or(false);
    eprintln!(
        "receive_error={:?}, recorded_equivocations={rows}, original_discharged={discharged}",
        result.as_ref().err()
    );
    assert!(
        result.is_err(),
        "Known origin/sequence conflict entered the RETURN_RECEIPT handler"
    );
    assert_eq!(rows, 1);
    assert!(!discharged);
    assert_eq!(sb.packet(first.id()).unwrap().unwrap().raw(), first.raw());
    assert!(sb.packet(conflict.id()).unwrap().is_none());
    let valid = Packet::sign(chain, &a, peer_id(kb), 2, 9, receipt.raw()).unwrap();
    let frame = Frame::delivery(chain, &a, peer_id(kb), [0; 32], [4; 32], &valid).unwrap();
    assert!(sb
        .receive(frame.raw(), ka, [0; 32], true, &b)
        .unwrap()
        .is_none());
    assert!(sb
        .receive(frame.raw(), ka, [0; 32], true, &b)
        .unwrap()
        .is_none());
    let db = rusqlite::Connection::open_with_flags(
        b_root.join("carriage.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let stored: Vec<u8> = db
        .query_row(
            "SELECT raw FROM receipts WHERE packet=?1",
            [original.id().as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert!(Frame::decode(&stored, chain).unwrap().discharges(&original));
    drop(db);
    drop(sb);
    let mut sb = Carriage::open(&b_root, chain, kb, Budget::default()).unwrap();
    assert!(sb.receive(bad.raw(), ka, [0; 32], true, &b).is_err());
    assert!(sb
        .receive(frame.raw(), ka, [0; 32], true, &b)
        .unwrap()
        .is_none());
}
