use super::*;
use crate::stream_replay::{Cursor, Record};
use std::io::Write;

fn block(
    cursor: &mut Cursor,
    commands: Vec<Command>,
    trust: &Trust,
    evidence: &VerifiedEvidence,
) -> Block {
    let mut b = cursor
        .template(commands, public(10), trust, evidence)
        .unwrap();
    mine(&mut b).unwrap();
    cursor.accept(&b, trust, evidence).unwrap();
    b
}
fn owner_command(
    cursor: &Cursor,
    input: Hash,
    amount: Amount,
    from: u8,
    to: u8,
    trust: &Trust,
) -> Command {
    let intent = Intent {
        currency: trust.currency().unwrap(),
        region: trust.named("earth").unwrap(),
        inputs: vec![input],
        outputs: vec![Payment {
            owner: public(to),
            amount,
        }],
        destination: None,
        remote: None,
        fee: Amount::ZERO,
        destination_fee: Amount::ZERO,
        valid_through: cursor.head().unwrap().observation.height + 1,
    };
    let approval = Approval {
        key: public(from),
        signature: signature(from, &intent.bytes().unwrap()),
    };
    Command::Spend(Box::new(SignedIntent {
        intent,
        approvals: vec![approval],
    }))
}
#[test]
fn common_kernel_matches_full_chain_and_keeps_legacy_history_refusal() {
    let f = Fixture::new();
    let mut legacy = Chain::new(f.earth.region, &f.trust).unwrap();
    let mut cursor = Cursor::new(f.earth.region, &f.trust).unwrap();
    for _ in 0..MAX_BLOCKS {
        let mut b = legacy
            .template(vec![], public(10), &f.trust, &f.evidence)
            .unwrap();
        mine(&mut b).unwrap();
        cursor.accept(&b, &f.trust, &f.evidence).unwrap();
        legacy.accept(b, &f.trust, &f.evidence).unwrap();
        assert_eq!(cursor.ledger(), &legacy.ledger);
        assert_eq!(
            cursor.head().unwrap().observation.tip,
            legacy.tip().unwrap()
        );
    }
    assert_eq!(cursor.retained_observations(), MAX_BLOCKS);
    assert!(legacy
        .template(vec![], public(10), &f.trust, &f.evidence)
        .unwrap_err()
        .contains("history bound"));
    let next = block(&mut cursor, vec![], &f.trust, &f.evidence);
    assert_eq!(next.header.height, MAX_BLOCKS as u64 + 1);
    assert_eq!(cursor.retained_observations(), MAX_BLOCKS);
}
#[test]
fn invalid_tail_never_moves_value_history_or_anchor() {
    let f = Fixture::new();
    let mut cursor = Cursor::new(f.earth.region, &f.trust).unwrap();
    for b in &f.earth.blocks {
        cursor.accept(b, &f.trust, &f.evidence).unwrap();
    }
    let sid = f.earth.finalized.unwrap();
    cursor.install(sid, &f.trust, &f.evidence).unwrap();
    let before = cursor.head().unwrap();
    let ledger = cursor.ledger().clone();
    let mut valid = cursor
        .template(vec![], public(10), &f.trust, &f.evidence)
        .unwrap();
    mine(&mut valid).unwrap();
    for mode in 0..6 {
        let mut b = valid.clone();
        match mode {
            0 => b.header.parent = Hash::ZERO,
            1 => b.header.height += 1,
            2 => b.header.region = f.proxima.region,
            3 => b.header.state = Hash::ZERO,
            4 => b.header.anchor = None,
            _ => b.header.anchor = Some(Hash::ZERO),
        }
        mine(&mut b).unwrap();
        assert!(cursor.accept(&b, &f.trust, &f.evidence).is_err());
        assert_eq!(cursor.head().unwrap(), before);
        assert_eq!(cursor.ledger(), &ledger);
    }
    let key = *cursor.ledger().coins.keys().next().unwrap();
    let bad = owner_command(
        &cursor,
        key,
        cursor.ledger().coins[&key].payment.amount,
        11,
        12,
        &f.trust,
    );
    assert!(cursor
        .template(vec![bad], public(10), &f.trust, &f.evidence)
        .is_err());
    assert_eq!(cursor.head().unwrap(), before);
}
#[test]
fn unsigned_cached_state_bft_and_alternate_trust_cannot_be_replay_bases() {
    let f = Fixture::new();
    let mut cursor = Cursor::new(f.earth.region, &f.trust).unwrap();
    assert!(cursor
        .install(f.earth.finalized.unwrap(), &f.trust, &f.evidence)
        .is_err());
    let mut b = bootstrap();
    b.admissions[0].rules = crate::bft::RULES.into();
    b.admissions[0].signature = signature(1, &b.admissions[0].bytes().unwrap());
    let trust = Trust::verify(&b, &public(1), b.currency.id().unwrap()).unwrap();
    assert!(Cursor::new(trust.named("earth").unwrap(), &trust).is_err());
    assert!(cursor
        .template(vec![], public(10), &trust, &VerifiedEvidence::default())
        .is_err());
    assert!(
        serde_json::from_str::<Record>(r#"{"kind":"ledger","ledger":{"minted":"999999"}}"#)
            .is_err()
    );
    assert_eq!(cursor.head().unwrap().observation.height, 0);
}
#[test]
fn real_long_owner_payments_delayed_return_import_and_private_archive_replay() {
    let mut f = Fixture::new();
    let initial = f.earth.finalized.unwrap();
    let (source, eid) = f.imported();
    for _ in 0..2 {
        advance(&mut f.proxima, &f.trust, &f.evidence, vec![]);
    }
    let recipient = finalize(&mut f.proxima, &f.trust, &mut f.evidence);
    let signed = intent(
        &f.proxima,
        &f.trust,
        coins(&f.proxima, 11),
        vec![Payment {
            owner: public(11),
            amount: Amount(18),
        }],
        Some(f.earth.region),
        Some(Payment {
            owner: public(12),
            amount: Amount(60),
        }),
        0,
        1,
        &[11],
    );
    let returned = signed.intent.id().unwrap();
    advance(
        &mut f.proxima,
        &f.trust,
        &f.evidence,
        vec![Command::Spend(Box::new(signed))],
    );
    let return_checkpoint = finalize(&mut f.proxima, &f.trust, &mut f.evidence);
    let raw = Evidence {
        snapshots: [initial, source, recipient, return_checkpoint]
            .into_iter()
            .map(|sid| f.evidence.snapshot(sid).unwrap().clone())
            .collect(),
    };
    let root = std::fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "rld-stream-{}",
            rld_core::generate_identity().public_key
        ));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("history.jsonl");
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path).unwrap();
    let mut append = |record: Record| {
        serde_json::to_writer(&mut file, &record).unwrap();
        file.write_all(b"\n").unwrap();
    };
    append(Record::Evidence { evidence: raw });
    let mut cursor = Cursor::new(f.earth.region, &f.trust).unwrap();
    for b in &f.earth.blocks {
        cursor.accept(b, &f.trust, &f.evidence).unwrap();
        append(Record::Block {
            block: Box::new(b.clone()),
        });
    }
    cursor.install(source, &f.trust, &f.evidence).unwrap();
    append(Record::Finalize { checkpoint: source });
    let mut input = *cursor
        .ledger()
        .coins
        .iter()
        .find(|(_, c)| c.payment.owner == public(10) && c.payment.amount == Amount(100))
        .unwrap()
        .0;
    let mut owner = 10;
    for _ in 0..1024 {
        let next = if owner == 20 { 21 } else { 20 };
        let command = owner_command(&cursor, input, Amount(100), owner, next, &f.trust);
        let b = block(&mut cursor, vec![command], &f.trust, &f.evidence);
        append(Record::Block { block: Box::new(b) });
        input = *cursor
            .ledger()
            .coins
            .iter()
            .find(|(_, c)| c.payment.owner == public(next) && c.payment.amount == Amount(100))
            .unwrap()
            .0;
        owner = next;
        assert!(cursor.retained_observations() <= MAX_BLOCKS);
    }
    let b = block(
        &mut cursor,
        vec![Command::Import {
            snapshot: return_checkpoint,
            export: returned,
        }],
        &f.trust,
        &f.evidence,
    );
    append(Record::Block { block: Box::new(b) });
    for _ in 0..2 {
        let b = block(&mut cursor, vec![], &f.trust, &f.evidence);
        append(Record::Block { block: Box::new(b) });
    }
    assert_eq!(
        cursor.ledger().imports.get(&returned),
        Some(&return_checkpoint)
    );
    assert!(cursor.ledger().exports.contains_key(&eid));
    let head = cursor.head().unwrap();
    assert!(head.observation.height > 4 * MAX_BLOCKS as u64);
    let original = cursor
        .ledger()
        .coins
        .values()
        .find(|c| c.payment.owner == public(12))
        .unwrap();
    assert_eq!(original.payment.amount, Amount(59));
    assert!(original.mature <= head.observation.height);
    let duplicate = Command::Import {
        snapshot: return_checkpoint,
        export: returned,
    };
    assert!(cursor
        .template(vec![duplicate], public(10), &f.trust, &f.evidence)
        .unwrap_err()
        .contains("permanent import tombstone"));
    let liquid = sum(cursor
        .ledger()
        .coins
        .values()
        .chain(f.proxima.ledger.coins.values())
        .map(|c| c.payment.amount))
    .unwrap();
    assert_eq!(liquid, Amount(300));
    file.sync_all().unwrap();
    drop(file);
    let bytes = std::fs::read(&path).unwrap();
    let cold = crate::stream_replay::check_archive(
        &path,
        &bootstrap(),
        &public(1),
        f.trust.currency().unwrap(),
        "earth",
        head.id().unwrap(),
    )
    .unwrap();
    assert_eq!(cold, head);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert!(crate::stream_replay::check_archive(
        &path,
        &bootstrap(),
        &public(1),
        f.trust.currency().unwrap(),
        "earth",
        Hash::ZERO
    )
    .is_err());
    let bad = root.join("truncated.jsonl");
    std::fs::copy(&path, &bad).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&bad)
        .unwrap()
        .set_len(bytes.len() as u64 - 1)
        .unwrap();
    assert!(crate::stream_replay::check_archive(
        &bad,
        &bootstrap(),
        &public(1),
        f.trust.currency().unwrap(),
        "earth",
        head.id().unwrap()
    )
    .is_err());
    let cli_checked = if let Some(binary) = std::env::var_os("RLD_STREAM_TEST_BINARY") {
        let genesis = root.join("bootstrap.json");
        std::fs::write(&genesis, serde_json::to_vec(&bootstrap()).unwrap()).unwrap();
        let unused = root.join("not-adopted");
        let invoke = |archive: &std::path::Path, expected: Hash| {
            std::process::Command::new(&binary)
                .args([
                    "--dir",
                    unused.to_str().unwrap(),
                    "--authority",
                    &public(1),
                    "--currency",
                    &f.trust.currency().unwrap().to_hex(),
                    "history-stream-check",
                    "--bootstrap",
                    genesis.to_str().unwrap(),
                    "--region",
                    "earth",
                    "--file",
                    archive.to_str().unwrap(),
                    "--expected-head",
                    &expected.to_hex(),
                ])
                .output()
                .unwrap()
        };
        let accepted = invoke(&path, head.id().unwrap());
        assert!(
            accepted.status.success(),
            "{}",
            String::from_utf8_lossy(&accepted.stderr)
        );
        let response: serde_json::Value = serde_json::from_slice(&accepted.stdout).unwrap();
        assert_eq!(response["head"], serde_json::to_value(&head).unwrap());
        assert_eq!(response["genesis_and_every_native_block_replayed"], true);
        for field in [
            "ledger_adopted",
            "signing_or_wallet_custody_restored",
            "incident_quarantine_reconciled",
            "ordinary_node_storage_upgraded",
            "independent_latest_anchor_qualified",
            "long_history_qualified",
            "live_rld",
        ] {
            assert_eq!(response[field], false, "{field}");
        }
        assert!(!unused.exists());
        assert!(!invoke(&path, Hash::ZERO).status.success());
        assert!(!invoke(&bad, head.id().unwrap()).status.success());
        std::fs::create_dir(&unused).unwrap();
        std::fs::write(unused.join("RESTORING"), b"interrupted private restore").unwrap();
        let interrupted = invoke(&path, head.id().unwrap());
        assert!(!interrupted.status.success());
        assert!(String::from_utf8_lossy(&interrupted.stderr).contains("restor"));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        true
    } else {
        false
    };
    println!(
        "{}",
        serde_json::json!({"format":"RLD-NATIVE-BOUNDED-STREAM-SAMPLE-V1","fixture_only":true,"live_rld":false,
        "native_implementation":implementation().unwrap(),"native_blocks":head.observation.height,"actual_signed_local_payments":1024,
        "retained_history_observations":cursor.retained_observations(),"archive_bytes":bytes.len(),"delayed_return_import_net":"59",
        "native_cli_checked":cli_checked,"incident_quarantine_reconciled":false,
        "duplicate_import_refused":true,"cold_native_replay_equal":true,"legacy_bounds_unchanged":true,
        "full_long_history_qualification":false,"ordinary_node_storage_upgraded":false})
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn private_archive_bounds_links_permissions_and_corrupt_records_refuse() {
    use std::fs::{File, OpenOptions};
    let f = Fixture::new();
    let root = std::fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "rld-stream-bound-{}",
            rld_core::generate_identity().public_key
        ));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("archive.jsonl");
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    drop(options.open(&path).unwrap());
    let cursor = Cursor::new(f.earth.region, &f.trust).unwrap();
    let expected = cursor.head().unwrap().id().unwrap();
    let check = |p: &std::path::Path| {
        crate::stream_replay::check_archive(
            p,
            &bootstrap(),
            &public(1),
            f.trust.currency().unwrap(),
            "earth",
            expected,
        )
    };
    assert!(check(&path).is_ok());
    let initial = std::fs::read(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let symlink_path = root.join("symlink");
        symlink(&path, &symlink_path).unwrap();
        assert!(check(&symlink_path).is_err());
        let hardlink = root.join("hardlink");
        std::fs::hard_link(&path, &hardlink).unwrap();
        assert!(check(&path).is_err());
        std::fs::remove_file(hardlink).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(check(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert_eq!(std::fs::read(&path).unwrap(), initial);
    for bytes in [
        b"{\"kind\":\"ledger\",\"ledger\":{}}\n".as_slice(),
        b"{broken}\n",
        b"{}",
    ] {
        std::fs::write(&path, bytes).unwrap();
        assert!(check(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
    let file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    file.set_len(crate::stream_replay::MAX_ARCHIVE_BYTES + 1)
        .unwrap();
    assert!(check(&path).unwrap_err().contains("oversized"));
    assert_eq!(
        File::open(&path).unwrap().metadata().unwrap().len(),
        crate::stream_replay::MAX_ARCHIVE_BYTES + 1
    );
    file.set_len(MAX_BYTES as u64 + 1).unwrap();
    assert!(check(&path).unwrap_err().contains("bound/truncated"));
    assert_eq!(
        File::open(&path).unwrap().metadata().unwrap().len(),
        MAX_BYTES as u64 + 1
    );
    std::fs::remove_dir_all(root).unwrap();
}
