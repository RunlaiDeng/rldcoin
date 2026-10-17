//! Public RFC8032 NO-VALUE fixtures. Journal metadata indexes must never grant
//! review or signing authority outside an actually selected native context.
use ed25519_dalek::{Signer, SigningKey};
use rld_survivor_node::{
    kernel::{genesis_id, Hash},
    store::{Limits, Store},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
const NOW: u64 = 2_000_000_000;
const INTENT: Hash = [90; 32];
struct Fixture {
    root: PathBuf,
    genesis: Vec<u8>,
    blocks: Vec<Vec<u8>>,
    payment: Vec<u8>,
    onward: Vec<u8>,
    key: SigningKey,
}
impl Fixture {
    fn new() -> (Self, Store) {
        let v: Value = serde_json::from_str(include_str!(
            "../../../docs/protocol/survivor-v1/vectors.json"
        ))
        .unwrap();
        let genesis = hex::decode(v["genesis"]["manifest_hex"].as_str().unwrap()).unwrap();
        let root = std::env::temp_dir().join(format!(
            "rld-survivor-wallet-history-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut s = Store::open(&root, &genesis, genesis_id(&genesis), Limits::default()).unwrap();
        let blocks: Vec<_> = v["main_branch"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| hex::decode(b["block_hex"].as_str().unwrap()).unwrap())
            .collect();
        for (i, group) in blocks[..100].chunks(32).enumerate() {
            s.accept_history([i as u8 + 1; 32], group, NOW).unwrap();
        }
        let payment = hex::decode(v["payment"]["transaction_hex"].as_str().unwrap()).unwrap();
        let onward = hex::decode(v["onward"]["transaction_hex"].as_str().unwrap()).unwrap();
        let key = SigningKey::from_bytes(
            &hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap()
                .try_into()
                .unwrap(),
        );
        (
            Self {
                root,
                genesis,
                blocks,
                payment,
                onward,
                key,
            },
            s,
        )
    }
    fn open(&self) -> Result<Store, String> {
        Store::open(
            &self.root,
            &self.genesis,
            genesis_id(&self.genesis),
            Limits::default(),
        )
    }
    fn unsigned(&self) -> &[u8] {
        &self.payment[..self.payment.len() - 64]
    }
    fn sign(&self, s: &mut Store) {
        let d = s.review_transfer(INTENT, self.unsigned(), NOW).unwrap();
        assert_eq!(
            s.sign_review(INTENT, d, &self.key, NOW).unwrap(),
            self.payment
        );
    }
    fn rewrite_context(&self, tip: Hash, revision: u128) {
        self.rewrite_review(self.unsigned(), tip, revision);
    }
    fn rewrite_review(&self, unsigned: &[u8], tip: Hash, revision: u128) {
        let digest: Hash = Sha256::digest(
            [
                b"RLD-SURVIVOR-1/REVIEW\0".as_slice(),
                genesis_id(&self.genesis).as_slice(),
                INTENT.as_slice(),
                tip.as_slice(),
                revision.to_be_bytes().as_slice(),
                unsigned,
            ]
            .concat(),
        )
        .into();
        let db = rusqlite::Connection::open(self.root.join("ledger.sqlite3")).unwrap();
        db.execute(
            "UPDATE wallet SET reviewed_tip=?1,reviewed_revision=?2,digest=?3 WHERE id=?4",
            rusqlite::params![
                tip.as_slice(),
                revision.to_be_bytes().as_slice(),
                digest.as_slice(),
                INTENT.as_slice()
            ],
        )
        .unwrap();
        db.execute(
            "UPDATE wallet SET unsigned=?1 WHERE id=?2",
            rusqlite::params![unsigned, INTENT.as_slice()],
        )
        .unwrap();
    }
    fn empty(&self, s: &mut Store, count: usize) -> Vec<Hash> {
        let mut candidate = s.ledger().clone();
        let mut blocks = Vec::new();
        let mut tips = Vec::new();
        for _ in 0..count {
            let now = candidate.tip().timestamp() + 600;
            let mut job = candidate
                .mining_job(self.key.verifying_key().to_bytes(), vec![], now, NOW)
                .unwrap();
            let b = job.attempt(1_000_000).unwrap();
            candidate.execute(&b).unwrap();
            tips.push(candidate.tip().id());
            blocks.push(b);
        }
        let mut operation = [11; 32];
        operation[16..].copy_from_slice(&candidate.tip().height().to_be_bytes());
        s.accept_history(operation, &blocks, NOW).unwrap();
        tips
    }
}

#[test]
fn a_rehashed_review_cannot_claim_a_different_existing_revision() {
    let (f, mut s) = Fixture::new();
    f.sign(&mut s);
    let tip = s.ledger().tip().id();
    assert_eq!(s.revision(), 4);
    s.accept([5; 32], &f.blocks[100], NOW).unwrap();
    assert_eq!(s.revision(), 5);
    drop(s);
    f.rewrite_context(tip, 5);
    eprintln!("NO-VALUE corruption fixture: {}", f.root.display());
    assert!(
        f.open().is_err(),
        "review tip was never selected at revision 5"
    );
}

#[test]
fn historical_review_and_later_signature_survive_onward_history() {
    let (f, mut s) = Fixture::new();
    let digest = s.review_transfer(INTENT, f.unsigned(), NOW).unwrap();
    f.empty(&mut s, 2);
    assert_eq!(
        s.sign_review(INTENT, digest, &f.key, NOW).unwrap(),
        f.payment
    );
    drop(s);
    let mut s = f.open().unwrap();
    assert_eq!(s.signed_operation(INTENT).unwrap(), Some(f.payment.clone()));
    // Include the payment and spend its output. The historical journal must
    // still validate in its original contexts, never against today's inputs.
    let time = s.ledger().tip().timestamp() + 600;
    let mut job = s
        .ledger()
        .mining_job(
            f.key.verifying_key().to_bytes(),
            vec![f.payment.clone()],
            time,
            NOW,
        )
        .unwrap();
    s.accept([12; 32], &job.attempt(1_000_000).unwrap(), NOW)
        .unwrap();
    let mut job = s
        .ledger()
        .mining_job(
            f.key.verifying_key().to_bytes(),
            vec![f.onward.clone()],
            time + 600,
            NOW,
        )
        .unwrap();
    s.accept([13; 32], &job.attempt(1_000_000).unwrap(), NOW)
        .unwrap();
    let tip = s.ledger().tip().clone();
    drop(s);
    let s = f.open().unwrap();
    assert_eq!(s.ledger().tip(), &tip);
    assert_eq!(s.signed_operation(INTENT).unwrap(), Some(f.payment));
}

#[test]
fn never_selected_and_pre_review_signing_contexts_refuse() {
    for case in 0..3 {
        let (f, mut s) = Fixture::new();
        let early = s.ledger().tip().id();
        let tips = f.empty(&mut s, 2);
        f.sign(&mut s);
        drop(s);
        let signing = match case {
            0 => early,
            1 => tips[0],
            _ => [211; 32],
        };
        let db = rusqlite::Connection::open(f.root.join("ledger.sqlite3")).unwrap();
        db.execute(
            "UPDATE wallet SET signing_tip=?1 WHERE id=?2",
            rusqlite::params![signing.as_slice(), INTENT.as_slice()],
        )
        .unwrap();
        drop(db);
        assert!(f.open().is_err(), "case {case}");
    }
}

#[test]
fn incomplete_unknown_and_intermediate_review_contexts_refuse() {
    for case in 0..4 {
        let (f, mut s) = Fixture::new();
        f.sign(&mut s);
        let tip = s.ledger().tip().id();
        let tips = f.empty(&mut s, 2);
        drop(s);
        match case {
            0 => f.rewrite_context(tip, 999),
            1 => f.rewrite_context(tips[0], 5),
            _ => {
                let db = rusqlite::Connection::open(f.root.join("ledger.sqlite3")).unwrap();
                let sql = if case == 2 {
                    "UPDATE wallet SET signed=NULL"
                } else {
                    "UPDATE wallet SET signing_tip=NULL"
                };
                db.execute(sql, []).unwrap();
            }
        }
        assert!(f.open().is_err(), "case {case}");
    }
}

#[test]
fn matching_context_still_checks_owner_value_maturity_expiry_and_signature() {
    for case in 0..5 {
        let (f, mut s) = Fixture::new();
        f.sign(&mut s);
        let tip = s.ledger().tip().id();
        let revision = s.revision();
        let mut unsigned = f.unsigned().to_vec();
        let wrong_key = SigningKey::from_bytes(&[67; 32]);
        match case {
            0 => unsigned[34..66].copy_from_slice(&wrong_key.verifying_key().to_bytes()),
            1 => unsigned[136..152].copy_from_slice(&1u128.to_be_bytes()),
            2 => {
                let (immature, coin) = s
                    .ledger()
                    .coins()
                    .iter()
                    .find(|(_, c)| c.maturity == 102)
                    .unwrap();
                assert_eq!(coin.owner, f.key.verifying_key().to_bytes());
                unsigned[68..102].copy_from_slice(immature);
            }
            3 => {
                let end = unsigned.len();
                unsigned[end - 16..].copy_from_slice(&100u128.to_be_bytes());
            }
            _ => {}
        }
        drop(s);
        f.rewrite_review(&unsigned, tip, revision);
        let key = if case == 0 { &wrong_key } else { &f.key };
        let mut signed = unsigned.clone();
        signed.extend(
            key.sign(&[b"RLD-SURVIVOR-1/TRANSFER\0".as_slice(), &unsigned].concat())
                .to_bytes(),
        );
        if case == 4 {
            let end = signed.len();
            signed[end - 1] ^= 1;
        }
        let db = rusqlite::Connection::open(f.root.join("ledger.sqlite3")).unwrap();
        db.execute(
            "UPDATE wallet SET signed=?1 WHERE id=?2",
            rusqlite::params![signed, INTENT.as_slice()],
        )
        .unwrap();
        drop(db);
        assert!(f.open().is_err(), "case {case}");
    }
}
