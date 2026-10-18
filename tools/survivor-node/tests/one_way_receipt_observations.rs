//! Public NO-VALUE keys. Receiver custody creates its own receipt independently
//! of reverse delivery or the sender receiving a receipt.
use ed25519_dalek::SigningKey;
use rld_survivor_node::{
    carriage::{Budget, Carriage},
    contact::{peer_id, Frame},
};

#[test]
fn forward_only_delivery_retains_a_self_signed_receipt_only_at_receiver() {
    let root = std::env::temp_dir().join(format!("rld-local-receipt-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let chain = [81; 32];
    let a = SigningKey::from_bytes(&[91; 32]);
    let b = SigningKey::from_bytes(&[92; 32]);
    let ka = a.verifying_key().to_bytes();
    let kb = b.verifying_key().to_bytes();
    let mut source = Carriage::open(&root.join("source"), chain, ka, Budget::default()).unwrap();
    let mut receiver =
        Carriage::open(&root.join("receiver"), chain, kb, Budget::default()).unwrap();
    let packet = source.originate(&a, peer_id(kb), 4, &[0; 96]).unwrap();
    let frame = Frame::delivery(chain, &a, peer_id(kb), [0; 32], [1; 32], &packet).unwrap();
    let receipt = receiver
        .receive(frame.raw(), ka, [0; 32], true, &b)
        .unwrap()
        .unwrap();
    assert_eq!(receipt.sender(), kb);
    assert!(receipt.discharges(&packet));
    for (name, expected) in [("source", 0), ("receiver", 1)] {
        let db = rusqlite::Connection::open_with_flags(
            root.join(name).join("carriage.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let (destination, hop): (i64, i64) = db
            .query_row(
                "SELECT (SELECT count(*) FROM receipts),(SELECT count(*) FROM hop_receipts)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((destination, hop), (expected, 0));
        if name == "receiver" {
            let retained: Vec<u8> = db
                .query_row("SELECT raw FROM receipts", [], |row| row.get(0))
                .unwrap();
            assert_eq!(retained, receipt.raw());
            assert!(Frame::decode(&retained, chain).unwrap().discharges(&packet));
        }
    }
}
