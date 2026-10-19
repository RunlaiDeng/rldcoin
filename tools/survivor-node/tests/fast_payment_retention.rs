//! PUBLIC NO-VALUE identities; fresh native funding, full receipt evidence and
//! real encrypted delegated-key use. No independent custody/monitoring claim.
#[path = "support/fast_funding.rs"]
mod support;
use ed25519_dalek::{Signature, VerifyingKey};
use rld_survivor_node::{
    fast_payment::{review_digest, Acknowledgment, Delegation, Payment},
    fast_retainer::{Creation, Current, Journal},
    kernel::Hash,
    keyfile,
};
use sha2::{Digest, Sha256};
use std::{
    cell::Cell,
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use support::*;
const LIMIT: usize = 1024 * 1024;
const PASSWORD: &[u8] = b"public no-value retainer passphrase";
struct Child(Option<std::process::Child>);
impl Drop for Child {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
fn recovery_process(
    path: &Path,
    chain: Hash,
    prior: Hash,
    receipt: Hash,
    label: &str,
) -> serde_json::Value {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
    let parent = path.parent().unwrap();
    let output = parent.join(format!("{label}.stdout.json"));
    let error = parent.join(format!("{label}.stderr.log"));
    let private = |path: &Path| {
        let mut o = std::fs::OpenOptions::new();
        o.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        o.open(path).unwrap()
    };
    let process = std::process::Command::new(env!("CARGO_BIN_EXE_rld-fast-retainer-recover"))
        .arg(path)
        .arg(hex::encode(chain))
        .arg(hex::encode(prior))
        .arg(hex::encode(receipt))
        .stdout(private(&output))
        .stderr(private(&error))
        .spawn()
        .unwrap();
    let pid = process.id();
    let mut process = Child(Some(process));
    let status = loop {
        if let Some(status) = process.0.as_mut().unwrap().try_wait().unwrap() {
            break status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "original180 keyless recovery process"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    process.0.take();
    std::fs::write(parent.join(format!("{label}.terminal.json")),serde_json::json!({"pid":pid,"success":status.success(),"exit_code":status.code(),"forced_stop":false}).to_string()).unwrap();
    assert!(
        status.success(),
        "{}",
        std::fs::read_to_string(error).unwrap()
    );
    serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap()
}
fn directory(f: &Fixture, label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "rld-fast-retention-{}-{}-{label}",
        std::process::id(),
        hex::encode(f.ledger.chain_id())
    ));
    std::fs::create_dir(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    path
}
fn current(f: &Fixture) -> Current<'_> {
    Current {
        ledger: &f.ledger,
        expected_tip: f.ledger.tip().id(),
        now: f.now + 1,
    }
}
fn create(f: &Fixture, path: &Path) -> Journal {
    Journal::create(
        path,
        Creation {
            genesis: &f.genesis,
            chain: f.ledger.chain_id(),
            history: &f.history,
            delegation: &delegation(f),
            current: current(f),
            limit: LIMIT,
        },
    )
    .unwrap()
}
fn acknowledge(j: &mut Journal, f: &Fixture, receipt: &[u8]) -> (Hash, Hash, Vec<u8>) {
    let review = j.prepare(receipt, j.head(), current(f)).unwrap();
    let encrypted = keyfile::encrypt(&f.retainer, f.ledger.chain_id(), PASSWORD).unwrap();
    let (head, ack) = j
        .acknowledge(review.head, review.digest, current(f), || {
            keyfile::decrypt(&encrypted, f.ledger.chain_id(), PASSWORD)
        })
        .unwrap();
    (review.head, head, ack)
}
#[test]
fn public_codec_signatures_and_lengths_match_without_implying_native_funding() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/fast-payment-retention-v1-vectors.json"
    ))
    .unwrap();
    let bytes = |key: &str| hex::decode(v[key].as_str().unwrap()).unwrap();
    let ctx = bytes("context_hex");
    for (i, case) in v["cases"].as_array().unwrap().iter().enumerate() {
        let raw = hex::decode(case["receipt_hex"].as_str().unwrap()).unwrap();
        let n = raw.len() - 256;
        assert_eq!(raw.len(), if i == 0 { 579 } else { 831 });
        assert_eq!(hex::encode(&raw[..n]), case["invoice_body_hex"]);
        let cert = [raw[n - 124..n].to_vec(), raw[n..n + 128].to_vec()].concat();
        rld_survivor_node::fast_fee_claims::Contract::decode(&ctx)
            .unwrap()
            .verify(&cert)
            .unwrap();
        for owner in 0..2 {
            let key: Hash = ctx[68 + owner * 32..100 + owner * 32].try_into().unwrap();
            VerifyingKey::from_bytes(&key)
                .unwrap()
                .verify_strict(
                    &[tag("INVOICE"), raw[..n].to_vec()].concat(),
                    &Signature::from_slice(&raw[n + 128 + owner * 64..n + 192 + owner * 64])
                        .unwrap(),
                )
                .unwrap();
        }
        let id: Hash = Sha256::digest([tag("RECEIPT"), raw].concat()).into();
        assert_eq!(hex::encode(id), case["receipt_id"]);
    }
    let delegation = bytes("delegation_hex");
    assert_eq!(delegation.len(), 245);
    let miner: Hash = delegation[100..132].try_into().unwrap();
    VerifyingKey::from_bytes(&miner)
        .unwrap()
        .verify_strict(
            &[tag("DELEGATION"), delegation[..181].to_vec()].concat(),
            &Signature::from_slice(&delegation[181..]).unwrap(),
        )
        .unwrap();
    let ack = bytes("ack_hex");
    assert_eq!(ack.len(), 340);
    let key: Hash = delegation[132..164].try_into().unwrap();
    VerifyingKey::from_bytes(&key)
        .unwrap()
        .verify_strict(
            &[tag("ACK"), ack[..276].to_vec()].concat(),
            &Signature::from_slice(&ack[276..]).unwrap(),
        )
        .unwrap();
}
#[test]
fn funded_invoice_and_onward_payment_bind_fee_state_invoice_and_ordered_partials() {
    let f = fixture();
    let origin = f.ledger.funding_origin(f.channel).unwrap();
    let raw = payment(&f, None, 0, 70, 51);
    let first = Payment::verify(&origin, &raw).unwrap();
    assert_eq!((first.sequence(), first.fee()), (1, 2));
    let n = raw.len() - 256;
    let a = [
        vec![0],
        raw[n..n + 64].to_vec(),
        raw[n + 128..n + 192].to_vec(),
    ]
    .concat();
    let b = [
        vec![1],
        raw[n + 64..n + 128].to_vec(),
        raw[n + 192..].to_vec(),
    ]
    .concat();
    assert_eq!(
        Payment::combine(&origin, &raw[..n], &a, &b)
            .unwrap()
            .bytes(),
        raw
    );
    assert!(Payment::combine(&origin, &raw[..n], &b, &a).is_err());
    assert!(Payment::combine(&origin, &raw[..n], &a, &a).is_err());
    let second = Payment::verify(&origin, &payment(&f, Some(&first), 1, 25, 52)).unwrap();
    assert_eq!((second.sequence(), second.fee()), (2, 3));
    let state = origin
        .verify_certificate(second.after_certificate())
        .unwrap();
    assert_eq!(state.balances, [555, 445]);
    assert_eq!(state.slots, [1, 1]);
    for offset in [
        0,
        3,
        4,
        36,
        68,
        100,
        132,
        164,
        165,
        181,
        197,
        323,
        raw.len() - 1,
    ] {
        let mut bad = raw.clone();
        bad[offset] ^= 1;
        assert!(Payment::verify(&origin, &bad).is_err());
    }
    for offset in [165, 181] {
        let mut bad = raw.clone();
        bad[offset + 15] ^= 1;
        resign(&f, &mut bad);
        assert!(Payment::verify(&origin, &bad).is_err());
    }
    let mut jump = raw.clone();
    jump[199 + 75] = 2;
    jump[199 + 115] = 2;
    resign(&f, &mut jump);
    assert!(Payment::verify(&origin, &jump).is_err());
    let d = delegation(&f);
    Delegation::verify(&origin, &d).unwrap();
    for offset in [36, 68, 100, 164, 180, 244] {
        let mut bad = d.clone();
        bad[offset] ^= 1;
        assert!(Delegation::verify(&origin, &bad).is_err());
    }
    for forbidden in origin.owners().into_iter().chain([origin.miner()]) {
        assert!(Delegation::unsigned(&origin, forbidden).is_err());
    }
}
#[test]
fn durable_prepare_sign_ack_cold_and_keyless_recovery_preserve_exact_onward_state() {
    let f = fixture();
    let path = directory(&f, "roundtrip").join("journal");
    let origin = f.ledger.funding_origin(f.channel).unwrap();
    let raw1 = payment(&f, None, 0, 70, 61);
    let first = Payment::verify(&origin, &raw1).unwrap();
    let mut j = create(&f, &path);
    let initial = j.head();
    let review = j.prepare(&raw1, initial, current(&f)).unwrap();
    let prepared = review.head;
    assert_eq!(j.latest_sequence(), 0);
    drop(j);
    let pending = Journal::recover(
        &path,
        f.ledger.chain_id(),
        initial,
        first.id(),
        f.now + 1,
        LIMIT,
    )
    .unwrap();
    assert!(pending.acknowledgment.is_none());
    assert_eq!(pending.head, prepared);
    let native = recovery_process(
        &path,
        f.ledger.chain_id(),
        initial,
        first.id(),
        "pending-recovery",
    );
    assert_eq!(native["state"], "PREPARED_NO_ACK");
    assert!(native["acknowledgment_hex"].is_null());
    assert_eq!(native["key_loaded"], false);
    let mut j = Journal::open(&path, f.ledger.chain_id(), prepared, f.now + 1, LIMIT).unwrap();
    let loads = Cell::new(0);
    assert!(j
        .acknowledge(prepared, [0; 32], current(&f), || {
            loads.set(loads.get() + 1);
            Ok(f.retainer.clone())
        })
        .is_err());
    assert_eq!(loads.get(), 0);
    let closing = closed(&f);
    assert!(j
        .acknowledge(
            prepared,
            review.digest,
            Current {
                ledger: &closing,
                expected_tip: closing.tip().id(),
                now: f.now + 1
            },
            || {
                loads.set(loads.get() + 1);
                Ok(f.retainer.clone())
            }
        )
        .is_err());
    assert!(j
        .acknowledge(
            prepared,
            review.digest,
            Current {
                ledger: &f.before,
                expected_tip: f.before.tip().id(),
                now: f.now + 1
            },
            || {
                loads.set(loads.get() + 1);
                Ok(f.retainer.clone())
            }
        )
        .is_err());
    assert_eq!(loads.get(), 0);
    let encrypted = keyfile::encrypt(&f.retainer, f.ledger.chain_id(), PASSWORD).unwrap();
    let (signed, ack1) = j
        .acknowledge(prepared, review.digest, current(&f), || {
            keyfile::decrypt(&encrypted, f.ledger.chain_id(), PASSWORD)
        })
        .unwrap();
    Acknowledgment::verify(
        &origin,
        &Delegation::verify(&origin, &delegation(&f)).unwrap(),
        &first,
        &ack1,
    )
    .unwrap();
    assert_eq!(j.retained_ack(signed, first.id()).unwrap(), ack1);
    assert_eq!(j.latest_certificate().unwrap(), first.after_certificate());
    drop(j);
    let recovered = Journal::recover(
        &path,
        f.ledger.chain_id(),
        prepared,
        first.id(),
        f.now + 1,
        LIMIT,
    )
    .unwrap();
    assert_eq!(recovered.head, signed);
    assert_eq!(recovered.acknowledgment.unwrap(), ack1);
    let native = recovery_process(
        &path,
        f.ledger.chain_id(),
        prepared,
        first.id(),
        "signed-recovery",
    );
    assert_eq!(native["state"], "ALREADY_SIGNED");
    assert_eq!(native["acknowledgment_hex"], hex::encode(&ack1));
    assert_eq!(native["fast_completion_authorized"], false);
    assert_eq!(native["backing_currentness_known"], false);
    assert!(Journal::open(&path, f.ledger.chain_id(), initial, f.now + 1, LIMIT).is_err());
    let mut j = Journal::open(&path, f.ledger.chain_id(), signed, f.now + 1, LIMIT).unwrap();
    let raw2 = payment(&f, Some(&first), 1, 25, 62);
    let second = Payment::verify(&origin, &raw2).unwrap();
    let (p2, h2, ack2) = acknowledge(&mut j, &f, &raw2);
    assert_eq!(j.latest_sequence(), 2);
    drop(j);
    let saved = Journal::recover(
        &path,
        f.ledger.chain_id(),
        p2,
        second.id(),
        f.now + 1,
        LIMIT,
    )
    .unwrap();
    assert_eq!(saved.head, h2);
    assert_eq!(saved.acknowledgment.unwrap(), ack2);
    let j = Journal::open(&path, f.ledger.chain_id(), h2, f.now + 1, LIMIT).unwrap();
    assert_eq!(
        origin
            .verify_certificate(j.latest_certificate().unwrap())
            .unwrap()
            .balances,
        [555, 445]
    );
}
#[test]
fn pending_fork_wrong_prior_and_capacity_refuse_without_erasing_custody() {
    let f = fixture();
    let path = directory(&f, "refusal").join("journal");
    let raw1 = payment(&f, None, 0, 70, 71);
    let origin = f.ledger.funding_origin(f.channel).unwrap();
    let first = Payment::verify(&origin, &raw1).unwrap();
    let mut j = create(&f, &path);
    let initial = j.head();
    let header = std::fs::metadata(&path).unwrap().len() as usize;
    drop(j);
    let limit = header + 1107 - 1;
    let mut small = Journal::open(&path, f.ledger.chain_id(), initial, f.now + 1, limit).unwrap();
    assert!(small.prepare(&raw1, initial, current(&f)).is_err());
    assert_eq!(small.head(), initial);
    assert_eq!(std::fs::metadata(&path).unwrap().len() as usize, header);
    drop(small);
    j = Journal::open(&path, f.ledger.chain_id(), initial, f.now + 1, LIMIT).unwrap();
    let r = j.prepare(&raw1, initial, current(&f)).unwrap();
    let other = payment(&f, None, 0, 71, 72);
    assert!(j.prepare(&other, r.head, current(&f)).is_err());
    assert_eq!(j.head(), r.head);
    let after = payment(&f, Some(&first), 1, 25, 73);
    assert!(j.prepare(&after, r.head, current(&f)).is_err());
    assert_eq!(j.prepare(&raw1, r.head, current(&f)).unwrap().head, r.head);
    assert!(j
        .review(
            r.head,
            Current {
                ledger: &f.ledger,
                expected_tip: [0; 32],
                now: f.now + 1
            }
        )
        .is_err());
    assert!(j
        .review(
            r.head,
            Current {
                ledger: &f.ledger,
                expected_tip: f.ledger.tip().id(),
                now: f.now + 7201
            }
        )
        .is_err());
    let expected = review_digest(
        f.ledger.tip().id(),
        r.head,
        first.id(),
        Delegation::verify(&origin, &delegation(&f)).unwrap().id(),
    );
    assert_eq!(r.digest, expected);
    let mut advanced = f.ledger.clone();
    mine(
        &mut advanced,
        f.miner.verifying_key().to_bytes(),
        vec![],
        f.now,
    );
    let loads = Cell::new(0);
    assert!(j
        .acknowledge(
            r.head,
            r.digest,
            Current {
                ledger: &advanced,
                expected_tip: advanced.tip().id(),
                now: f.now + 1
            },
            || {
                loads.set(1);
                Ok(f.retainer.clone())
            }
        )
        .is_err());
    assert_eq!(loads.get(), 0);
    let newer = j
        .review(
            r.head,
            Current {
                ledger: &advanced,
                expected_tip: advanced.tip().id(),
                now: f.now + 1,
            },
        )
        .unwrap();
    assert_ne!(newer.digest, r.digest);
    assert_eq!(newer.head, r.head);
}
#[test]
fn prefix_corruption_and_current_head_rollback_refuse_before_key_loading() {
    let f = fixture();
    let path = directory(&f, "corruption").join("journal");
    let raw = payment(&f, None, 0, 70, 81);
    let mut j = create(&f, &path);
    let r = j.prepare(&raw, j.head(), current(&f)).unwrap();
    let original = std::fs::read(&path).unwrap();
    let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.seek(SeekFrom::End(-1)).unwrap();
    file.write_all(&[original[original.len() - 1] ^ 1]).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let loads = Cell::new(0);
    assert!(j
        .acknowledge(r.head, r.digest, current(&f), || {
            loads.set(1);
            Ok(f.retainer.clone())
        })
        .is_err());
    assert_eq!(loads.get(), 0);
    drop(j);
    assert!(Journal::open(&path, f.ledger.chain_id(), r.head, f.now + 1, LIMIT).is_err());
    let f = fixture();
    let path = directory(&f, "rollback").join("journal");
    let origin = f.ledger.funding_origin(f.channel).unwrap();
    let raw1 = payment(&f, None, 0, 70, 82);
    let first = Payment::verify(&origin, &raw1).unwrap();
    let mut j = create(&f, &path);
    let (_, head1, _) = acknowledge(&mut j, &f, &raw1);
    let older = std::fs::read(&path).unwrap();
    let raw2 = payment(&f, Some(&first), 1, 25, 83);
    let (prepared2, head2, _) = acknowledge(&mut j, &f, &raw2);
    assert_ne!(head1, head2);
    drop(j);
    // Deliberately restore a fresh test journal's old bytes while retaining its
    // true newer caller head; never reopen an old failed qualification fixture.
    std::fs::write(&path, older).unwrap();
    assert!(Journal::open(&path, f.ledger.chain_id(), head2, f.now + 1, LIMIT).is_err());
    let second = Payment::verify(&origin, &raw2).unwrap();
    assert!(Journal::recover(
        &path,
        f.ledger.chain_id(),
        prepared2,
        second.id(),
        f.now + 1,
        LIMIT
    )
    .is_err());
}

#[test]
fn retained_invoice_evidence_funds_native_exit_and_actual_mature_miner_fee_spend() {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
    let mut f = fixture();
    let a = f.owners[0].verifying_key().to_bytes();
    let d = f.retainer.verifying_key().to_bytes();
    let m = f.miner.verifying_key().to_bytes();
    let (input, coin) = f
        .ledger
        .coins()
        .iter()
        .find(|(_, c)| c.owner == a && c.maturity <= 103 && c.amount > 10000)
        .unwrap();
    // Explicit ordinary test liquidity for the independent claim submitter,
    // distinct from every protocol payment fee owed to the funding miner.
    let (fund_retainer, funding_id) = ordinary(
        f.ledger.chain_id(),
        &f.owners[0],
        input,
        &[(d, 100), (a, coin.amount - 101)],
    );
    let future = f.now + 2_000_000;
    mine_until(&mut f.ledger, a, vec![fund_retainer], f.now, deadline);
    let path = directory(&f, "native-exit").join("journal");
    let origin = f.ledger.funding_origin(f.channel).unwrap();
    let first = Payment::verify(&origin, &payment(&f, None, 0, 70, 91)).unwrap();
    let second = Payment::verify(&origin, &payment(&f, Some(&first), 1, 25, 92)).unwrap();
    let mut j = create(&f, &path);
    acknowledge(&mut j, &f, first.bytes());
    let (_, last_head, _) = acknowledge(&mut j, &f, second.bytes());
    let proof = j.latest_certificate().unwrap().to_vec();
    assert_eq!(proof, second.after_certificate());
    let close = action(&f, 2, &f.owners[0], (&out(f.channel, 0), 1386), &[], 93);
    let closeid = rld_survivor_node::kernel::fast::operation_id(&close);
    mine_until(&mut f.ledger, a, vec![close], future, deadline);
    let close_height = f.ledger.tip().height();
    let claim = action(&f, 4, &f.retainer, (&out(funding_id, 0), 99), &proof, 94);
    mine_until(&mut f.ledger, a, vec![claim], future, deadline);
    let principal = action(&f, 3, &f.owners[1], (&out(f.channel, 1), 1583), &proof, 95);
    mine_until(&mut f.ledger, a, vec![principal], future, deadline);
    while f.ledger.tip().height() < close_height + 2016 {
        mine_until(&mut f.ledger, a, vec![], future, deadline);
    }
    let settle = action(&f, 5, &f.owners[0], (&out(closeid, 0), 1385), &[], 96);
    let sid = rld_survivor_node::kernel::fast::operation_id(&settle);
    mine_until(&mut f.ledger, a, vec![settle], future, deadline);
    let h = f.ledger.tip().height();
    assert_eq!(f.ledger.coins()[&out(sid, 1)].amount, 555);
    assert_eq!(f.ledger.coins()[&out(sid, 2)].amount, 445);
    let fee = &f.ledger.coins()[&out(sid, 5)];
    assert_eq!((fee.owner, fee.amount, fee.maturity), (m, 5, h + 100));
    let (spend, spent_id) = ordinary(f.ledger.chain_id(), &f.miner, &out(sid, 5), &[(a, 4)]);
    assert!(f
        .ledger
        .mining_job(
            a,
            vec![spend.clone()],
            f.ledger.tip().timestamp() + 600,
            future
        )
        .is_err());
    while f.ledger.tip().height() < h + 99 {
        mine_until(&mut f.ledger, a, vec![], future, deadline);
    }
    mine_until(&mut f.ledger, a, vec![spend], future, deadline);
    assert_eq!(f.ledger.coins()[&out(spent_id, 0)].amount, 4);
    assert_eq!(
        f.ledger.coins().values().map(|c| c.amount).sum::<u128>(),
        f.ledger.issued()
    );
    let now = f.ledger.tip().timestamp();
    assert!(j
        .prepare(
            second.bytes(),
            last_head,
            Current {
                ledger: &f.ledger,
                expected_tip: f.ledger.tip().id(),
                now
            }
        )
        .err()
        .unwrap()
        .contains("backing absent"));
    assert_eq!(j.retained_ack(last_head, second.id()).unwrap().len(), 340);
    eprintln!(
        "retainer -> native fee lifecycle uses LOGICAL dispute timestamps; elapsed={:?}",
        std::time::Duration::from_secs(180)
            - deadline.saturating_duration_since(std::time::Instant::now())
    );
}

#[cfg(unix)]
#[test]
fn identical_path_replacement_is_detected_before_delegated_key_loading() {
    let f = fixture();
    let path = directory(&f, "replacement").join("journal");
    let raw = payment(&f, None, 0, 70, 97);
    let mut j = create(&f, &path);
    let r = j.prepare(&raw, j.head(), current(&f)).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    std::fs::rename(&path, path.with_extension("retained-original")).unwrap();
    std::fs::write(&path, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let loads = Cell::new(0);
    assert!(j
        .acknowledge(r.head, r.digest, current(&f), || {
            loads.set(1);
            Ok(f.retainer.clone())
        })
        .is_err());
    assert_eq!(loads.get(), 0);
}
