//! Disk prefixes must reconstruct the original signed full native journal.
use super::*;

fn chain(count: usize) -> Fixture {
    let mut f = Fixture::new();
    for _ in 0..count {
        f.mine();
        f.finalize();
    }
    f
}
fn rewrite_object(f: &Fixture, m: &mut Manifest, index: usize, object: &Object) {
    let (r, raw) = reference(object).unwrap();
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(f.page(&r)).unwrap().write_all(&raw).unwrap();
    m.snapshots[index] = r;
    f.put_manifest(m);
}
fn refused_unchanged(f: &Fixture) {
    let manifest = fs::read(f.path.join("journal.json")).unwrap();
    let usage = archive_usage(&f.path.join("history")).unwrap();
    assert!(Store::open(&f.path, &public(1), f.pin).is_err());
    assert_eq!(fs::read(f.path.join("journal.json")).unwrap(), manifest);
    assert_eq!(archive_usage(&f.path.join("history")).unwrap(), usage);
}
#[test]
fn exact_prefixes_at_snapshot_capacity_match_full_native_journal_and_restore() {
    let mut f = chain(MAX_SNAPSHOTS);
    let full = canonical(&f.node().journal).unwrap();
    let ledger = f.node().chain.ledger.clone();
    let tip = f.node().chain.tip().unwrap();
    let m = f.manifest();
    let head = m.head().unwrap();
    let logical = f.node().journal.evidence.clone();
    let mut full_bytes = 0usize;
    let mut stored_bytes = 0usize;
    for (i, (r, s)) in m.snapshots.iter().zip(&logical.snapshots).enumerate() {
        full_bytes += canonical(&Object {
            format: OBJECT.into(),
            currency: f.pin,
            region: m.region,
            payload: Payload::Snapshot(Box::new(s.clone())),
        })
        .unwrap()
        .len();
        stored_bytes += r.bytes;
        match object(&f.path, &m, r).unwrap() {
            Payload::Snapshot(_) => assert_eq!(i, 0),
            Payload::SnapshotPrefix(p) => {
                assert_eq!(p.predecessor.hash, m.snapshots[i - 1].hash);
                assert_eq!(p.prefix_blocks, i);
                assert_eq!(p.suffix.blocks.len(), 1);
            }
            _ => panic!("snapshot payload"),
        }
    }
    assert!(stored_bytes * 4 < full_bytes);
    assert_eq!(canonical(&read_journal(&f.path).unwrap()).unwrap(), full);
    f.close();
    let store = Store::open_pinned(&f.path, &public(1), f.pin, head).unwrap();
    assert_eq!(store.chain.ledger, ledger);
    assert_eq!(store.chain.tip().unwrap(), tip);
    drop(store);
    let parent = f.path.parent().unwrap();
    let tag = rld_core::generate_identity().public_key;
    let image = parent.join(format!("rld-prefix-image-{tag}"));
    let target = parent.join(format!("rld-prefix-restore-{tag}"));
    crate::history_archive::seal(&f.path, &image, &public(1), f.pin, head).unwrap();
    crate::history_archive::restore(&image, &target, &public(1), f.pin, head).unwrap();
    let restored = Store::open_pinned(&target, &public(1), f.pin, head).unwrap();
    assert_eq!(restored.chain.ledger, ledger);
    assert_eq!(canonical(&restored.journal).unwrap(), full);
    drop(restored);
    fs::remove_dir_all(target).unwrap();
    fs::remove_dir_all(image).unwrap();
    println!(
        "{}",
        serde_json::json!({
            "format":"RLD-NATIVE-HISTORY-PREFIX-SAMPLE-V1", "fixture_only":true,
            "live_rld":false, "snapshots":MAX_SNAPSHOTS, "native_implementation":implementation().unwrap(),
            "full_snapshot_object_bytes":full_bytes, "prefix_snapshot_object_bytes":stored_bytes,
            "all_logical_native_bytes_equal":true, "fresh_image_restore_equal":true,
            "block_capacity_unchanged":true, "snapshot_capacity_unchanged":true,
            "transport_prefix_compression_implemented":false, "long_term_history_qualified":false
        })
    );
}
#[test]
fn prefixes_require_an_exact_earlier_listed_reference_and_never_adopt_orphans() {
    let mut f = chain(3);
    f.close();
    let original = f.manifest();
    let raw = fs::read(f.page(&original.snapshots[1])).unwrap();
    let base: Object = decode(&raw).unwrap();
    for mode in 0..5 {
        let mut changed = base.clone();
        if let Payload::SnapshotPrefix(p) = &mut changed.payload {
            match mode {
                0 => p.predecessor = original.snapshots[2].clone(), // forward
                1 => p.predecessor = original.pages[0].clone(),     // other type
                2 => p.predecessor.bytes += 1,
                3 => p.prefix_blocks += 1,
                _ => p.suffix.statement.region = Hash([9; 32]),
            }
        } else {
            panic!("prefix expected")
        }
        let mut m = original.clone();
        rewrite_object(&f, &mut m, 1, &changed);
        refused_unchanged(&f);
    }
    // The genuine predecessor remains on disk, but removing its direct listing
    // cannot turn an orphan into a recognized native proof.
    let mut missing = original.clone();
    missing.snapshots.remove(0);
    f.put_manifest(&missing);
    refused_unchanged(&f);
    let mut reordered = original.clone();
    reordered.snapshots.swap(0, 1);
    f.put_manifest(&reordered);
    refused_unchanged(&f);
    f.put_manifest(&original);
    f.reopen();
    assert_eq!(f.node().chain.height(), 3);
}
#[test]
fn missing_or_corrupt_prefix_objects_refuse_without_repair_or_pruning() {
    let mut f = chain(3);
    f.close();
    let m = f.manifest();
    let path = f.page(&m.snapshots[0]);
    let raw = fs::read(&path).unwrap();
    fs::remove_file(&path).unwrap();
    refused_unchanged(&f);
    fs::write(&path, b"{}").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    refused_unchanged(&f);
    fs::write(&path, raw).unwrap();
    f.reopen();
    assert_eq!(f.node().chain.height(), 3);
}
#[test]
fn rehashed_compressed_certificate_still_requires_native_signatures() {
    let mut f = chain(3);
    let mut forged = f.node().journal.clone();
    forged.evidence.snapshots[2].approvals[0].signature = "00".repeat(64);
    f.close();
    let raw = prepare(&f.path, &forged).unwrap();
    fs::write(f.path.join("journal.json"), raw).unwrap();
    let m = f.manifest();
    assert!(matches!(
        object(&f.path, &m, &m.snapshots[2]).unwrap(),
        Payload::SnapshotPrefix(_)
    ));
    assert_eq!(
        canonical(&read_journal(&f.path).unwrap()).unwrap(),
        canonical(&forged).unwrap()
    );
    refused_unchanged(&f);
}
#[test]
fn compressed_expansion_cannot_exceed_declared_logical_bytes() {
    let mut f = chain(8);
    f.close();
    let mut m = f.manifest();
    m.journal_bytes = m.snapshots.iter().map(|r| r.bytes).sum();
    f.put_manifest(&m);
    assert!(read_journal(&f.path)
        .unwrap_err()
        .contains("expanded snapshot logical bound"));
    refused_unchanged(&f);
}
#[test]
fn prior_storage_dialect_is_refused_unchanged_without_automatic_upgrade() {
    let mut f = chain(2);
    f.close();
    let mut m = f.manifest();
    m.format = "RLD-NATIVE-HISTORY-MANIFEST-V1".into();
    f.put_manifest(&m);
    refused_unchanged(&f);
}
#[test]
fn exact_duplicate_certificates_are_retained_and_native_replay_decides_equivalence() {
    let mut f = chain(3);
    let mut repeated = f.node().journal.clone();
    repeated
        .evidence
        .snapshots
        .push(repeated.evidence.snapshots[0].clone());
    repeated
        .evidence
        .snapshots
        .push(repeated.evidence.snapshots[2].clone());
    let expected = canonical(&repeated).unwrap();
    let ledger = f.node().chain.ledger.clone();
    f.close();
    let raw = prepare(&f.path, &repeated).unwrap();
    fs::write(f.path.join("journal.json"), raw).unwrap();
    let m = f.manifest();
    assert_eq!(m.snapshots[0].hash, m.snapshots[3].hash);
    assert_eq!(m.snapshots[2].hash, m.snapshots[4].hash);
    assert_eq!(
        canonical(&read_journal(&f.path).unwrap()).unwrap(),
        expected
    );
    f.reopen();
    assert_eq!(f.node().chain.ledger, ledger);
    // Another unanimous signature encoding is not an equivalent certificate.
    let mut forged = repeated;
    forged.evidence.snapshots[4].approvals[0].signature = "00".repeat(64);
    f.close();
    let raw = prepare(&f.path, &forged).unwrap();
    fs::write(f.path.join("journal.json"), raw).unwrap();
    assert_eq!(
        canonical(&read_journal(&f.path).unwrap()).unwrap(),
        canonical(&forged).unwrap()
    );
    refused_unchanged(&f);
}
