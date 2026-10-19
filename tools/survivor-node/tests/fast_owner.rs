//! PUBLIC NO-VALUE keys and new actual native funding in every fixture.
//! Two distinct signing keys/journals do not establish independent operators.
#[allow(dead_code)]
#[path = "support/fast_funding.rs"]
mod support;
use rld_survivor_node::{
    fast_owner::Journal,
    fast_payment::{Invoice, Payment},
    fast_retainer::{self, Creation, Current},
    kernel::Hash,
    keyfile,
};
use std::{
    cell::Cell,
    fs,
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use support::*;
const LIMIT: usize = 1024 * 1024;
const PASSWORD: &[u8] = b"public no-value owner passphrase";
fn directory(f: &Fixture, label: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "rld-fast-owner-{}-{}-{label}",
        std::process::id(),
        hex::encode(f.ledger.chain_id())
    ));
    fs::create_dir(&p).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
    }
    p
}
fn current(f: &Fixture) -> Current<'_> {
    Current {
        ledger: &f.ledger,
        expected_tip: f.ledger.tip().id(),
        now: f.now,
    }
}
fn creation(f: &Fixture, path: &Path, owner: u8, limit: usize) -> Journal {
    Journal::create(
        path,
        Creation {
            genesis: &f.genesis,
            chain: f.ledger.chain_id(),
            history: &f.history,
            delegation: &delegation(f),
            current: current(f),
            limit,
        },
        owner,
    )
    .unwrap()
}
fn invoice<'a>(f: &Fixture, raw: &'a [u8]) -> (&'a [u8], Invoice) {
    let body = &raw[..raw.len() - 256];
    (
        body,
        Invoice::verify(&f.ledger.funding_origin(f.channel).unwrap(), body).unwrap(),
    )
}
fn acknowledgment(f: &Fixture, retainer: &mut fast_retainer::Journal, raw: &[u8]) -> Vec<u8> {
    let review = retainer.prepare(raw, retainer.head(), current(f)).unwrap();
    retainer
        .acknowledge(review.head, review.digest, current(f), || {
            Ok(f.retainer.clone())
        })
        .unwrap()
        .1
}
fn recovery_process(
    path: &Path,
    mode: &str,
    chain: Hash,
    prior: Hash,
    id: Hash,
    label: &str,
) -> serde_json::Value {
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + Duration::from_secs(180);
    let root = path.parent().unwrap();
    let private = |name: &str| {
        let mut o = fs::OpenOptions::new();
        o.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        o.open(root.join(format!("{label}.{name}"))).unwrap()
    };
    struct Guard(Option<std::process::Child>);
    impl Drop for Guard {
        fn drop(&mut self) {
            if let Some(c) = self.0.as_mut() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }
    let mut child = Guard(Some(
        std::process::Command::new(env!("CARGO_BIN_EXE_rld-fast-owner-recover"))
            .arg(mode)
            .arg(path)
            .arg(hex::encode(chain))
            .arg(hex::encode(prior))
            .arg(hex::encode(id))
            .stdout(private("stdout.json"))
            .stderr(private("stderr.log"))
            .spawn()
            .unwrap(),
    ));
    let pid = child.0.as_ref().unwrap().id();
    let status = loop {
        if let Some(s) = child.0.as_mut().unwrap().try_wait().unwrap() {
            break s;
        }
        assert!(Instant::now() < deadline, "original180 owner recovery");
        std::thread::sleep(Duration::from_millis(10));
    };
    child.0.take();
    fs::write(root.join(format!("{label}.terminal.json")),serde_json::json!({"pid":pid,"exit_code":status.code(),"success":status.success(),"forced_stop":false}).to_string()).unwrap();
    assert!(
        status.success(),
        "{}",
        fs::read_to_string(root.join(format!("{label}.stderr.log"))).unwrap()
    );
    let v: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join(format!("{label}.stdout.json"))).unwrap())
            .unwrap();
    assert_eq!(v["key_loaded"], false);
    assert_eq!(v["fast_completion_authorized"], false);
    assert_eq!(v["backing_currentness_known"], false);
    v
}
#[test]
fn both_owners_durable_partial_recovery_receipt_custody_and_onward_payment() {
    let f = fixture();
    let dir = directory(&f, "roundtrip");
    let chain = f.ledger.chain_id();
    let ap = dir.join("owner-a");
    let bp = dir.join("owner-b");
    let mut a = creation(&f, &ap, 0, LIMIT);
    let mut b = creation(&f, &bp, 1, LIMIT);
    assert!(Journal::open(&ap, chain, a.head(), f.now, LIMIT).is_err());
    let origin = f.ledger.funding_origin(f.channel).unwrap();
    let inv = Invoice::propose(&origin, None, 0, 70, [1; 32]).unwrap();
    let body = inv.bytes();
    let a_initial = a.head();
    let ar = a.prepare(body, a_initial, current(&f)).unwrap();
    let br = b.prepare(body, b.head(), current(&f)).unwrap();
    assert_eq!(ar.payer, f.owners[0].verifying_key().to_bytes());
    assert_eq!(ar.recipient, f.owners[1].verifying_key().to_bytes());
    assert_eq!((ar.amount, ar.fee, ar.sequence), (70, 2, 1));
    drop(a);
    let recovery = Journal::recover(&ap, chain, a_initial, inv.id(), f.now, LIMIT).unwrap();
    assert_eq!(recovery.invoice, body);
    assert!(recovery.partial.is_none());
    let v = recovery_process(&ap, "partial", chain, a_initial, inv.id(), "prepared");
    assert_eq!(v["state"], "PREPARED_NO_SIGNATURE");
    a = Journal::open(&ap, chain, ar.head, f.now, LIMIT).unwrap();
    let encrypted = keyfile::encrypt(&f.owners[0], chain, PASSWORD).unwrap();
    let (ah, pa) = a
        .sign(ar.head, ar.digest, current(&f), || {
            keyfile::decrypt(&encrypted, chain, PASSWORD)
        })
        .unwrap();
    inv.verify_partial(&origin, &pa).unwrap();
    assert_eq!(a.latest_sequence(), 0);
    drop(a);
    let recovered = Journal::recover(&ap, chain, ar.head, inv.id(), f.now, LIMIT).unwrap();
    assert_eq!(recovered.partial, Some(pa.clone()));
    assert!(Journal::recover(&ap, chain, [0; 32], inv.id(), f.now, LIMIT).is_err());
    assert!(Journal::recover(&ap, chain, ar.head, [0; 32], f.now, LIMIT).is_err());
    let v = recovery_process(&ap, "partial", chain, ar.head, inv.id(), "signed");
    assert_eq!(v["partial_hex"], hex::encode(&pa));
    a = Journal::open(&ap, chain, ah, f.now, LIMIT).unwrap();
    assert_eq!(
        a.retained_pending(ah, inv.id()).unwrap().partial,
        Some(pa.clone())
    );
    let called = Cell::new(false);
    let repeat = a.review(ah, current(&f)).unwrap();
    assert!(a
        .sign(ah, repeat.digest, current(&f), || {
            called.set(true);
            Ok(f.owners[0].clone())
        })
        .is_err());
    assert!(!called.get());
    let encrypted = keyfile::encrypt(&f.owners[1], chain, PASSWORD).unwrap();
    let (_, pb) = b
        .sign(br.head, br.digest, current(&f), || {
            keyfile::decrypt(&encrypted, chain, PASSWORD)
        })
        .unwrap();
    let first = Payment::combine(&origin, body, &pa, &pb).unwrap();
    let raw = payment(&f, None, 0, 70, 1);
    assert_eq!(first.bytes(), raw);
    let mut r = fast_retainer::Journal::create(
        &dir.join("retainer"),
        Creation {
            genesis: &f.genesis,
            chain,
            history: &f.history,
            delegation: &delegation(&f),
            current: current(&f),
            limit: LIMIT,
        },
    )
    .unwrap();
    assert!(a
        .retain_complete(a.head(), first.bytes(), &[0; 340], f.now)
        .is_err());
    assert_eq!(a.latest_sequence(), 0);
    let ack = acknowledgment(&f, &mut r, first.bytes());
    let before_complete = a.head();
    let a_head = a
        .retain_complete(before_complete, first.bytes(), &ack, f.now)
        .unwrap();
    let b_head = b
        .retain_complete(b.head(), first.bytes(), &ack, f.now)
        .unwrap();
    drop(a);
    drop(b);
    let (h, p, q) =
        Journal::recover_complete(&ap, chain, before_complete, first.id(), f.now, LIMIT).unwrap();
    assert_eq!((h, p, q), (a_head, raw, ack.clone()));
    let v = recovery_process(
        &ap,
        "complete",
        chain,
        before_complete,
        first.id(),
        "complete",
    );
    assert_eq!(v["acknowledgment_hex"], hex::encode(&ack));
    a = Journal::open(&ap, chain, a_head, f.now, LIMIT).unwrap();
    b = Journal::open(&bp, chain, b_head, f.now, LIMIT).unwrap();
    assert_eq!((a.latest_sequence(), b.latest_sequence()), (1, 1));
    let inv2 = Invoice::propose(&origin, Some(&first), 1, 25, [2; 32]).unwrap();
    let body2 = inv2.bytes();
    let ar = a.prepare(body2, a.head(), current(&f)).unwrap();
    let br = b.prepare(body2, b.head(), current(&f)).unwrap();
    assert_eq!(
        a.retained_complete(ar.head).unwrap(),
        Some((first.bytes().to_vec(), ack.clone()))
    );
    assert_eq!(
        (ar.payer, ar.recipient, ar.amount, ar.fee),
        (
            f.owners[1].verifying_key().to_bytes(),
            f.owners[0].verifying_key().to_bytes(),
            25,
            3
        )
    );
    let pa = a
        .sign(ar.head, ar.digest, current(&f), || Ok(f.owners[0].clone()))
        .unwrap()
        .1;
    let pb = b
        .sign(br.head, br.digest, current(&f), || Ok(f.owners[1].clone()))
        .unwrap()
        .1;
    let second = Payment::combine(&origin, body2, &pa, &pb).unwrap();
    let ack2 = acknowledgment(&f, &mut r, second.bytes());
    a.retain_complete(a.head(), second.bytes(), &ack2, f.now)
        .unwrap();
    b.retain_complete(b.head(), second.bytes(), &ack2, f.now)
        .unwrap();
    assert_eq!(
        (
            a.latest_sequence(),
            b.latest_sequence(),
            r.latest_sequence()
        ),
        (2, 2, 2)
    );
    assert_eq!(
        origin
            .verify_certificate(second.after_certificate())
            .unwrap()
            .balances,
        [555, 445]
    );
    let ah = a.head();
    let bh = b.head();
    drop(a);
    drop(b);
    drop(r);
    assert_eq!(
        Journal::open(&ap, chain, ah, f.now, LIMIT)
            .unwrap()
            .latest_sequence(),
        2
    );
    assert_eq!(
        Journal::open(&bp, chain, bh, f.now, LIMIT)
            .unwrap()
            .latest_sequence(),
        2
    );
}
#[test]
fn pending_slot_cannot_be_replaced_or_advanced_by_timeout_or_foreign_receipt() {
    let f = fixture();
    let dir = directory(&f, "pending");
    let mut a = creation(&f, &dir.join("a"), 0, LIMIT);
    let raw = payment(&f, None, 0, 70, 1);
    let (body, _) = invoice(&f, &raw);
    let r = a.prepare(body, a.head(), current(&f)).unwrap();
    let same = a.prepare(body, r.head, current(&f)).unwrap();
    assert_eq!(same.digest, r.digest);
    let fork = payment(&f, None, 0, 71, 2);
    let (forkbody, _) = invoice(&f, &fork);
    assert!(a
        .prepare(forkbody, a.head(), current(&f))
        .unwrap_err_text()
        .contains("CONFLICT"));
    let p = Payment::verify(&f.ledger.funding_origin(f.channel).unwrap(), &raw).unwrap();
    let onward = payment(&f, Some(&p), 1, 5, 3);
    let (next, _) = invoice(&f, &onward);
    assert!(a.prepare(next, a.head(), current(&f)).is_err());
    let called = Cell::new(false);
    assert!(a
        .sign(r.head, [0; 32], current(&f), || {
            called.set(true);
            Ok(f.owners[0].clone())
        })
        .is_err());
    assert!(!called.get());
    let h = a.head();
    drop(a);
    let mut a = Journal::open(&dir.join("a"), f.ledger.chain_id(), h, f.now + 8000, LIMIT).unwrap();
    assert!(a
        .prepare(
            forkbody,
            h,
            Current {
                ledger: &f.ledger,
                expected_tip: f.ledger.tip().id(),
                now: f.now + 8000
            }
        )
        .is_err());
    assert_eq!(a.head(), h);
    assert_eq!(a.latest_sequence(), 0);
}
trait ErrorText<T> {
    fn unwrap_err_text(self) -> String;
}
impl<T> ErrorText<T> for Result<T, String> {
    fn unwrap_err_text(self) -> String {
        match self {
            Err(e) => e,
            Ok(_) => panic!("expected refusal"),
        }
    }
}
#[test]
fn head_review_native_scope_and_clock_are_checked_before_key_loading() {
    let f = fixture();
    let dir = directory(&f, "preflight");
    let mut a = creation(&f, &dir.join("a"), 0, LIMIT);
    let raw = payment(&f, None, 0, 70, 1);
    let (body, _) = invoice(&f, &raw);
    let initial = a.head();
    let r = a.prepare(body, initial, current(&f)).unwrap();
    let called = Cell::new(false);
    let loader = || {
        called.set(true);
        Ok(f.owners[0].clone())
    };
    assert!(a.sign(initial, r.digest, current(&f), loader).is_err());
    assert!(!called.get());
    assert!(a.sign(r.head, [0; 32], current(&f), loader).is_err());
    assert!(!called.get());
    assert!(a
        .sign(
            r.head,
            r.digest,
            Current {
                ledger: &f.ledger,
                expected_tip: [0; 32],
                now: f.now
            },
            loader
        )
        .is_err());
    assert!(!called.get());
    assert!(a
        .sign(
            r.head,
            r.digest,
            Current {
                ledger: &f.before,
                expected_tip: f.before.tip().id(),
                now: f.now
            },
            loader
        )
        .is_err());
    assert!(!called.get());
    let close = closed(&f);
    assert!(a
        .sign(
            r.head,
            r.digest,
            Current {
                ledger: &close,
                expected_tip: close.tip().id(),
                now: f.now + 601
            },
            loader
        )
        .is_err());
    assert!(!called.get());
    assert!(a
        .sign(
            r.head,
            r.digest,
            Current {
                ledger: &f.ledger,
                expected_tip: f.ledger.tip().id(),
                now: f.now - 1
            },
            loader
        )
        .is_err());
    assert!(!called.get());
    let mut changed = f.ledger.clone();
    mine(
        &mut changed,
        f.miner.verifying_key().to_bytes(),
        vec![],
        f.now + 601,
    );
    let now = f.now + 601;
    assert!(a
        .sign(
            r.head,
            r.digest,
            Current {
                ledger: &changed,
                expected_tip: changed.tip().id(),
                now
            },
            loader
        )
        .is_err());
    assert!(!called.get());
    let rr = a
        .review(
            r.head,
            Current {
                ledger: &changed,
                expected_tip: changed.tip().id(),
                now,
            },
        )
        .unwrap();
    assert_ne!(rr.digest, r.digest);
    assert!(a
        .sign(
            rr.head,
            rr.digest,
            Current {
                ledger: &changed,
                expected_tip: changed.tip().id(),
                now
            },
            || Ok(f.owners[1].clone())
        )
        .is_err());
    assert_eq!(a.head(), r.head);
    a.sign(
        rr.head,
        rr.digest,
        Current {
            ledger: &changed,
            expected_tip: changed.tip().id(),
            now,
        },
        loader,
    )
    .unwrap();
    assert!(called.get());
}
#[test]
fn invoice_validation_rejects_changed_terms_unfunded_amount_and_signature_relabeling() {
    let f = fixture();
    let raw = payment(&f, None, 0, 70, 1);
    let (body, inv) = invoice(&f, &raw);
    let origin = f.ledger.funding_origin(f.channel).unwrap();
    for index in [
        0, 4, 36, 68, 132, 164, 165, 181, 197, 199, 267, 275, 291, 307,
    ] {
        let mut bad = body.to_vec();
        bad[index] ^= 0x80;
        assert!(
            Invoice::verify(&origin, &bad).is_err(),
            "changed byte{index}"
        );
    }
    let partial = [vec![0], raw[323..387].to_vec(), raw[451..515].to_vec()].concat();
    inv.verify_partial(&origin, &partial).unwrap();
    let mut new_id = body.to_vec();
    new_id[100] ^= 0x80;
    let new_id = Invoice::verify(&origin, &new_id).unwrap();
    assert!(new_id.verify_partial(&origin, &partial).is_err());
    assert!(Invoice::propose(&origin, None, 0, 0, [1; 32]).is_err());
    assert!(Invoice::propose(&origin, None, 0, 601, [1; 32]).is_err());
    assert!(Invoice::propose(&origin, None, 2, 1, [1; 32]).is_err());
    assert!(Invoice::propose(&origin, None, 0, 1, [0; 32]).is_err());
    let mut bad = partial.clone();
    bad[0] = 1;
    assert!(inv.verify_partial(&origin, &bad).is_err());
    let other = payment(&f, None, 0, 71, 2);
    let (_, other) = invoice(&f, &other);
    assert!(other.verify_partial(&origin, &partial).is_err());
    let mut too_much = body.to_vec();
    too_much[165..181].copy_from_slice(&601u128.to_be_bytes());
    assert!(Invoice::verify(&origin, &too_much).is_err());
}
#[test]
fn capacity_reserves_signature_and_complete_proof_before_preparing() {
    let f = fixture();
    let dir = directory(&f, "capacity");
    let path = dir.join("a");
    let header_size = 443 + f.history.len();
    let mut a = creation(&f, &path, 0, header_size + 1500);
    let raw = payment(&f, None, 0, 70, 1);
    let (body, _) = invoice(&f, &raw);
    let initial = a.head();
    assert!(a
        .prepare(body, initial, current(&f))
        .unwrap_err_text()
        .contains("full lifecycle"));
    assert_eq!(a.head(), initial);
    assert_eq!(fs::metadata(&path).unwrap().len() as usize, header_size);
    drop(a);
    let a = Journal::open(
        &path,
        f.ledger.chain_id(),
        initial,
        f.now,
        header_size + 1500,
    )
    .unwrap();
    assert_eq!(a.latest_sequence(), 0);
}
#[test]
fn changed_prefix_and_rollback_refuse_without_releasing_another_signature() {
    let f = fixture();
    let dir = directory(&f, "corrupt");
    let path = dir.join("a");
    let mut a = creation(&f, &path, 0, LIMIT);
    let header = fs::read(&path).unwrap();
    let old = a.head();
    let raw = payment(&f, None, 0, 70, 1);
    let (body, _) = invoice(&f, &raw);
    let r = a.prepare(body, old, current(&f)).unwrap();
    let called = Cell::new(false);
    let loader = || {
        called.set(true);
        Ok(f.owners[0].clone())
    };
    let mut changed = fs::OpenOptions::new().write(true).open(&path).unwrap();
    changed.seek(SeekFrom::End(-1)).unwrap();
    let original = fs::read(&path).unwrap();
    changed
        .write_all(&[original[original.len() - 1] ^ 1])
        .unwrap();
    changed.sync_all().unwrap();
    assert!(a.sign(r.head, r.digest, current(&f), loader).is_err());
    assert!(!called.get());
    drop(a);
    assert!(Journal::open(&path, f.ledger.chain_id(), r.head, f.now, LIMIT).is_err());
    let rollback = dir.join("rollback");
    fs::write(&rollback, &header).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&rollback, fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(Journal::open(&rollback, f.ledger.chain_id(), r.head, f.now, LIMIT).is_err());
}
#[cfg(unix)]
#[test]
fn replaced_path_and_shared_permissions_refuse_before_keys() {
    use std::os::unix::fs::PermissionsExt;
    let f = fixture();
    let dir = directory(&f, "identity");
    let path = dir.join("a");
    let mut a = creation(&f, &path, 0, LIMIT);
    let raw = payment(&f, None, 0, 70, 1);
    let (body, _) = invoice(&f, &raw);
    let r = a.prepare(body, a.head(), current(&f)).unwrap();
    let bytes = fs::read(&path).unwrap();
    fs::rename(&path, dir.join("retained-original")).unwrap();
    fs::write(&path, &bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let called = Cell::new(false);
    assert!(a
        .sign(r.head, r.digest, current(&f), || {
            called.set(true);
            Ok(f.owners[0].clone())
        })
        .is_err());
    assert!(!called.get());
    drop(a);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Journal::open(&path, f.ledger.chain_id(), r.head, f.now, LIMIT).is_err());
}

#[test]
fn full_receipt_and_ack_cannot_replace_this_owners_missing_partial() {
    let f = fixture();
    let dir = directory(&f, "complete-binding");
    let path = dir.join("a");
    let mut a = creation(&f, &path, 0, LIMIT);
    let raw = payment(&f, None, 0, 70, 1);
    let (body, _) = invoice(&f, &raw);
    let r = a.prepare(body, a.head(), current(&f)).unwrap();
    let mut retainer = fast_retainer::Journal::create(
        &dir.join("retainer"),
        Creation {
            genesis: &f.genesis,
            chain: f.ledger.chain_id(),
            history: &f.history,
            delegation: &delegation(&f),
            current: current(&f),
            limit: LIMIT,
        },
    )
    .unwrap();
    let ack = acknowledgment(&f, &mut retainer, &raw);
    assert!(a
        .retain_complete(r.head, &raw, &ack, f.now)
        .unwrap_err_text()
        .contains("exact retained signature"));
    assert_eq!(a.latest_sequence(), 0);
    a.sign(r.head, r.digest, current(&f), || Ok(f.owners[0].clone()))
        .unwrap();
    let before = a.head();
    let closed = closed(&f);
    a.retain_complete(before, &raw, &ack, f.now + 601).unwrap();
    // Historical proof remains useful even when current backing has closed.
    let first = Payment::verify(&f.ledger.funding_origin(f.channel).unwrap(), &raw).unwrap();
    let next = Invoice::propose(
        &f.ledger.funding_origin(f.channel).unwrap(),
        Some(&first),
        1,
        25,
        [2; 32],
    )
    .unwrap();
    assert!(a
        .prepare(
            next.bytes(),
            a.head(),
            Current {
                ledger: &closed,
                expected_tip: closed.tip().id(),
                now: f.now + 601
            }
        )
        .is_err());
    let head = a.head();
    drop(a);
    assert_eq!(
        Journal::open(&path, f.ledger.chain_id(), head, f.now + 601, LIMIT)
            .unwrap()
            .latest_sequence(),
        1
    );
}
#[test]
fn cold_replay_authenticates_signatures_after_record_hash_is_recomputed() {
    use sha2::{Digest, Sha256};
    let f = fixture();
    let dir = directory(&f, "cold-signature");
    let path = dir.join("a");
    let mut a = creation(&f, &path, 0, LIMIT);
    let raw = payment(&f, None, 0, 70, 1);
    let (body, _) = invoice(&f, &raw);
    let r = a.prepare(body, a.head(), current(&f)).unwrap();
    let offset = fs::metadata(&path).unwrap().len() as usize;
    a.sign(r.head, r.digest, current(&f), || Ok(f.owners[0].clone()))
        .unwrap();
    drop(a);
    let mut bytes = fs::read(&path).unwrap();
    let end = bytes.len() - 32;
    bytes[end - 1] ^= 1;
    let forged: Hash = Sha256::digest(
        [
            b"RLD-FAST-OWNER-1/RECORD\0".as_slice(),
            &bytes[offset + 4..end],
        ]
        .concat(),
    )
    .into();
    bytes[end..].copy_from_slice(&forged);
    fs::write(&path, &bytes).unwrap();
    assert!(Journal::open(&path, f.ledger.chain_id(), forged, f.now, LIMIT).is_err());
    assert_eq!(fs::read(&path).unwrap(), bytes);
    let truncated = dir.join("truncated");
    fs::write(&truncated, &bytes[..bytes.len() - 7]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&truncated, fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(Journal::open(&truncated, f.ledger.chain_id(), forged, f.now, LIMIT).is_err());
    assert_eq!(fs::read(&truncated).unwrap(), bytes[..bytes.len() - 7]);
}

// The parent invokes this exact test in an isolated process. Normal invocation
// returns without creating state; environment variables carry paths/modes only.
#[test]
fn owner_process_boundary_child() {
    let Ok(root) = std::env::var("RLD_FAST_OWNER_BOUNDARY_ROOT") else {
        return;
    };
    let phase = std::env::var("RLD_FAST_OWNER_BOUNDARY_PHASE").unwrap();
    let root = Path::new(&root);
    let f = fixture();
    let path = root.join("owner");
    let mut j = creation(&f, &path, 0, LIMIT);
    let initial = j.head();
    let inv = Invoice::propose(
        &f.ledger.funding_origin(f.channel).unwrap(),
        None,
        0,
        70,
        [1; 32],
    )
    .unwrap();
    let r = j.prepare(inv.bytes(), initial, current(&f)).unwrap();
    let (prior, partial) = if phase == "signed" {
        let encrypted = keyfile::encrypt(&f.owners[0], f.ledger.chain_id(), PASSWORD).unwrap();
        let (_, partial) = j
            .sign(r.head, r.digest, current(&f), || {
                keyfile::decrypt(&encrypted, f.ledger.chain_id(), PASSWORD)
            })
            .unwrap();
        (r.head, Some(partial))
    } else {
        assert_eq!(phase, "prepared");
        (initial, None)
    };
    let marker = root.join("ready.json");
    let mut ready = fs::OpenOptions::new();
    ready.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        ready.mode(0o600);
    }
    let mut ready = ready.open(marker).unwrap();
    ready.write_all(serde_json::json!({"chain":hex::encode(f.ledger.chain_id()),"prior":hex::encode(prior),"head":hex::encode(j.head()),"invoice_id":hex::encode(inv.id()),"invoice_hex":hex::encode(inv.bytes()),"partial_hex":partial.map(hex::encode)}).to_string().as_bytes()).unwrap();
    ready.sync_all().unwrap();
    fs::File::open(root).unwrap().sync_all().unwrap();
    let until = std::time::Instant::now() + std::time::Duration::from_secs(180);
    while std::time::Instant::now() < until {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    panic!("original180 child awaited parent kill");
}
#[cfg(unix)]
#[test]
fn process_sigkill_after_prepare_and_signed_release_recovers_exact_evidence() {
    use std::time::{Duration, Instant};
    for phase in ["prepared", "signed"] {
        let mut entropy = [0; 16];
        getrandom::getrandom(&mut entropy).unwrap();
        let root = std::env::temp_dir().join(format!(
            "rld-fast-owner-kill-{}-{}-{phase}",
            std::process::id(),
            hex::encode(entropy)
        ));
        fs::create_dir(&root).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let private = |name: &str| {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(root.join(name))
                .unwrap()
        };
        struct Guard(Option<std::process::Child>);
        impl Drop for Guard {
            fn drop(&mut self) {
                if let Some(c) = self.0.as_mut() {
                    let _ = c.kill();
                    let _ = c.wait();
                }
            }
        }
        let mut child = Guard(Some(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "owner_process_boundary_child", "--nocapture"])
                .env("RLD_FAST_OWNER_BOUNDARY_ROOT", &root)
                .env("RLD_FAST_OWNER_BOUNDARY_PHASE", phase)
                .stdout(private("child.stdout.log"))
                .stderr(private("child.stderr.log"))
                .spawn()
                .unwrap(),
        ));
        let pid = child.0.as_ref().unwrap().id();
        let deadline = Instant::now() + Duration::from_secs(180);
        let marker = root.join("ready.json");
        let evidence: serde_json::Value = loop {
            assert!(
                child.0.as_mut().unwrap().try_wait().unwrap().is_none(),
                "child exited before boundary"
            );
            if let Ok(bytes) = fs::read(&marker) {
                if let Ok(v) = serde_json::from_slice(&bytes) {
                    break v;
                }
            }
            assert!(
                Instant::now() < deadline,
                "original180 owner kill controller"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        child.0.as_mut().unwrap().kill().unwrap();
        let status = child.0.as_mut().unwrap().wait().unwrap();
        child.0.take();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(9));
        fs::write(root.join("terminal.json"),serde_json::json!({"pid":pid,"signal":status.signal(),"phase":phase,"controller_requested_kill":true}).to_string()).unwrap();
        let h = |name: &str| -> Hash {
            hex::decode(evidence[name].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        };
        let recovered = recovery_process(
            &root.join("owner"),
            "partial",
            h("chain"),
            h("prior"),
            h("invoice_id"),
            "recovered",
        );
        assert_eq!(recovered["journal_head"], evidence["head"]);
        assert_eq!(recovered["invoice_hex"], evidence["invoice_hex"]);
        assert_eq!(recovered["partial_hex"], evidence["partial_hex"]);
        assert_eq!(
            recovered["state"],
            if phase == "signed" {
                "ALREADY_SIGNED"
            } else {
                "PREPARED_NO_SIGNATURE"
            }
        );
    }
}
