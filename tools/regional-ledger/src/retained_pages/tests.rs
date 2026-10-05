use super::*;
use std::{
    collections::BTreeMap,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    index: u64,
    previous: Hash,
    payload: String,
    approval: Approval,
}
fn record_bytes(scope: &Scope, record: &Record) -> Vec<u8> {
    encode(
        "retained-pages-test-record",
        &(scope, record.index, record.previous, &record.payload),
    )
    .unwrap()
}
fn record(scope: &Scope, index: u64, previous: Hash) -> Record {
    let mut value = Record {
        index,
        previous,
        payload: format!("complete-original-request-and-response-{index}"),
        approval: Approval {
            key: crate::tests::public(2),
            signature: String::new(),
        },
    };
    value.approval.signature = crate::tests::signature(2, &record_bytes(scope, &value));
    value
}
fn fixture_scope(purpose: Purpose) -> Scope {
    let mut currency = Currency {
        format: DOMAIN.into(),
        fixture_only: true,
        implementation: implementation().unwrap(),
        origin: "earth".into(),
        authority: crate::tests::public(1),
        cap: Amount(300),
        block_reward: Amount(100),
        maturity: 2,
        signature: String::new(),
    };
    currency.signature = crate::tests::signature(1, &currency.bytes().unwrap());
    let mut keys = (2..=5).map(crate::tests::public).collect::<Vec<_>>();
    keys.sort();
    let mut admission = Admission {
        currency: currency.id().unwrap(),
        region: "earth".into(),
        rules: DOMAIN.into(),
        value_rules: None,
        validators: keys,
        signature: String::new(),
    };
    admission.signature = crate::tests::signature(1, &admission.bytes().unwrap());
    let package = Bootstrap {
        currency,
        admissions: vec![admission],
    };
    let pin = package.currency.id().unwrap();
    let trust = Trust::verify(&package, &crate::tests::public(1), pin).unwrap();
    let region = trust.regions.keys().next().copied().unwrap();
    Scope::bind(&trust, region, purpose, pin).unwrap()
}
fn private_root() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let base = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tmp")
        .canonicalize()
        .unwrap();
    let path = base.join(format!(
        "native-retained-pages-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    make_dir(&path).unwrap();
    path
}
type Inventory = BTreeMap<PathBuf, (Hash, u64, u32, u128)>;
fn inventory(root: &Path) -> Inventory {
    let mut result = BTreeMap::new();
    fn walk(path: &Path, result: &mut Inventory) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            let meta = fs::symlink_metadata(&path).unwrap();
            if meta.is_dir() {
                walk(&path, result);
            } else if meta.is_file() {
                #[cfg(unix)]
                use std::os::unix::fs::MetadataExt;
                #[cfg(unix)]
                let mode = meta.mode();
                #[cfg(not(unix))]
                let mode = 0;
                result.insert(
                    path.clone(),
                    (
                        Hash(Sha256::digest(fs::read(path).unwrap()).into()),
                        meta.len(),
                        mode,
                        meta.modified()
                            .unwrap()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_nanos(),
                    ),
                );
            }
        }
    }
    walk(root, &mut result);
    result
}
fn byte_capacity_inventory(root: &Path) -> Inventory {
    // Complete cryptographic hashing remains required. The bounded local drill
    // can select an independently recorded fast hash executable; no production
    // authority, cached digest or sampled payload is involved.
    let Some(program) = std::env::var_os("RLD_RETAINED_PAGES_TEST_HASH_PROGRAM") else {
        return inventory(root);
    };
    let mut result = BTreeMap::new();
    fn walk(path: &Path, program: &std::ffi::OsStr, result: &mut Inventory) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            let meta = fs::symlink_metadata(&path).unwrap();
            if meta.is_dir() {
                walk(&path, program, result);
            } else if meta.is_file() {
                let output = Command::new(program)
                    .args(["dgst", "-sha256", "-r"])
                    .arg(&path)
                    .output()
                    .unwrap();
                assert!(output.status.success());
                let text = String::from_utf8(output.stdout).unwrap();
                let hash = Hash::from_hex(text.split_whitespace().next().unwrap()).unwrap();
                #[cfg(unix)]
                use std::os::unix::fs::MetadataExt;
                #[cfg(unix)]
                let mode = meta.mode();
                #[cfg(not(unix))]
                let mode = 0;
                result.insert(
                    path,
                    (
                        hash,
                        meta.len(),
                        mode,
                        meta.modified()
                            .unwrap()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_nanos(),
                    ),
                );
            }
        }
    }
    walk(root, &program, &mut result);
    result
}
fn fill(stream: &mut Stream<Record>, count: u64) -> Hash {
    let mut head = stream.storage_head();
    for index in 0..count {
        let item = record(&stream.manifest.scope, index, head);
        head = stream.append(&[item], head).unwrap();
    }
    head
}
fn authenticated(stream: &Stream<Record>, scope: &Scope, head: Hash) -> u64 {
    let mut index = 0;
    let mut previous = scope.initial().unwrap();
    let count = stream
        .visit(head, |item| {
            require(
                item.index == index && item.previous == previous,
                "full record order/previous head",
            )?;
            verify_bytes(
                &item.approval.key,
                &record_bytes(scope, item),
                &item.approval.signature,
            )?;
            require(
                item.approval.key == crate::tests::public(2),
                "fixture record owner",
            )?;
            previous = next_head(previous, index, item)?;
            index += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(index, count);
    count
}

#[test]
fn complete_records_seal_only_full_pages_and_cold_child_is_read_only() {
    for purpose in [Purpose::Ledger, Purpose::BftSigner(crate::tests::public(2))] {
        let scope = fixture_scope(purpose);
        let root = private_root();
        let dir = root.join("stream");
        let mut stream = Stream::create(&dir, scope.clone()).unwrap();
        let head = fill(&mut stream, 145);
        assert_eq!(stream.record_count(), 145);
        assert_eq!(stream.manifest.pages.len(), 9);
        assert_eq!(stream.manifest.tail.len(), 1);
        assert_eq!(fs::read_dir(dir.join(OBJECTS)).unwrap().count(), 9);
        assert_eq!(authenticated(&stream, &scope, head), 145);
        drop(stream);
        keystore::private_create(&root.join("scope.json"), &bytes(&scope).unwrap()).unwrap();
        let before = inventory(&root);
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "retained_pages::tests::cold_child",
                "--ignored",
                "--test-threads=1",
            ])
            .env("RLD_RETAINED_PAGES_CHILD_DIR", &root)
            .env("RLD_RETAINED_PAGES_CHILD_HEAD", head.to_hex())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "cold child: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(inventory(&root), before);
    }
}

#[test]
#[ignore = "called only by the bounded parent with one exact fixture"]
fn cold_child() {
    let root = PathBuf::from(std::env::var_os("RLD_RETAINED_PAGES_CHILD_DIR").unwrap());
    let head = Hash::from_hex(&std::env::var("RLD_RETAINED_PAGES_CHILD_HEAD").unwrap()).unwrap();
    let scope: Scope =
        decode(&keystore::private_read(&root.join("scope.json"), MAX_BYTES).unwrap()).unwrap();
    assert_eq!(scope, fixture_scope(scope.purpose.clone()));
    let stream = Stream::<Record>::open(&root.join("stream"), &scope, head).unwrap();
    assert_eq!(authenticated(&stream, &scope, head), 145);
}

#[test]
fn wrong_head_domain_and_held_os_lock_refuse_without_writes() {
    let scope = fixture_scope(Purpose::Ledger);
    let root = private_root();
    let dir = root.join("stream");
    let mut stream = Stream::create(&dir, scope.clone()).unwrap();
    let initial = stream.storage_head();
    let head = fill(&mut stream, 17);
    let before = inventory(&root);
    assert!(Stream::<Record>::open(&dir, &scope, head).is_err());
    assert!(stream.append(&[record(&scope, 17, head)], initial).is_err());
    assert_eq!(inventory(&root), before);
    drop(stream);
    assert!(Stream::<Record>::open(&dir, &scope, initial).is_err());
    let mut other = scope.clone();
    other.purpose = Purpose::BftSigner(crate::tests::public(2));
    assert!(Stream::<Record>::open(&dir, &other, head).is_err());
    other = scope.clone();
    other.origin = id("foreign-stream-origin", &1).unwrap();
    assert!(Stream::<Record>::open(&dir, &other, head).is_err());
    assert_eq!(inventory(&root), before);
}

#[test]
fn missing_corrupt_reordered_forward_pages_refuse_without_repair() {
    for kind in ["missing", "corrupt", "reordered", "forward"] {
        let scope = fixture_scope(Purpose::Ledger);
        let root = private_root();
        let dir = root.join("stream");
        let mut stream = Stream::create(&dir, scope.clone()).unwrap();
        let head = fill(&mut stream, 33);
        let first = stream.manifest.pages[0].clone();
        drop(stream);
        let mut manifest: Manifest<Record> =
            decode(&keystore::private_read(&dir.join(MANIFEST), MAX_BYTES).unwrap()).unwrap();
        let path = dir.join(OBJECTS).join(page_name(first.hash));
        match kind {
            "missing" => {
                fs::rename(&path, root.join("retained-missing-page.json")).unwrap();
            }
            "corrupt" => {
                fs::write(&path, b"corrupt complete bytes").unwrap();
            }
            "reordered" => {
                manifest.pages.swap(0, 1);
                fs::write(dir.join(MANIFEST), bytes(&manifest).unwrap()).unwrap();
            }
            _ => {
                let mut page: Page<Record> =
                    decode(&keystore::private_read(&path, MAX_BYTES).unwrap()).unwrap();
                page.previous = Some(manifest.pages[1].hash);
                let raw = bytes(&page).unwrap();
                let hash = Hash(Sha256::digest(&raw).into());
                keystore::private_create(&dir.join(OBJECTS).join(page_name(hash)), &raw).unwrap();
                manifest.pages[0] = history::Reference {
                    hash,
                    bytes: raw.len(),
                };
                fs::write(dir.join(MANIFEST), bytes(&manifest).unwrap()).unwrap();
            }
        }
        let before = inventory(&root);
        assert!(
            Stream::<Record>::open(&dir, &scope, head).is_err(),
            "{kind}"
        );
        assert_eq!(inventory(&root), before);
    }
}

#[test]
fn publication_failure_keeps_original_head_and_all_residue() {
    for boundary in [Boundary::Pending, Boundary::Pages, Boundary::Committed] {
        let scope = fixture_scope(Purpose::Ledger);
        let root = private_root();
        let dir = root.join("stream");
        let mut stream = Stream::create(&dir, scope.clone()).unwrap();
        let head = fill(&mut stream, 15);
        let old_manifest = fs::read(dir.join(MANIFEST)).unwrap();
        stream.interruption = Some(boundary);
        let item = record(&scope, 15, head);
        assert!(stream.append(std::slice::from_ref(&item), head).is_err());
        assert_eq!(stream.storage_head(), head);
        assert_eq!(stream.record_count(), 15);
        if boundary == Boundary::Committed {
            let published: Manifest<Record> =
                decode(&fs::read(dir.join(MANIFEST)).unwrap()).unwrap();
            assert_eq!(published.count, 16);
            assert_ne!(published.head, head);
        } else {
            assert_eq!(fs::read(dir.join(MANIFEST)).unwrap(), old_manifest);
        }
        assert!(dir.join(PENDING).exists());
        assert_eq!(
            fs::read_dir(dir.join(OBJECTS)).unwrap().count(),
            usize::from(boundary != Boundary::Pending)
        );
        let before = inventory(&root);
        assert!(stream.append(&[item], head).is_err());
        drop(stream);
        assert!(Stream::<Record>::open(&dir, &scope, head).is_err());
        assert_eq!(inventory(&root), before);
    }
}

#[test]
fn hashes_never_authenticate_a_complete_altered_record() {
    let scope = fixture_scope(Purpose::Ledger);
    let root = private_root();
    let dir = root.join("stream");
    let mut stream = Stream::create(&dir, scope.clone()).unwrap();
    let initial = stream.storage_head();
    let mut item = record(&scope, 0, initial);
    item.payload.push_str("altered after signing");
    // The byte layer deliberately accepts self-consistent retained bytes.
    // The native consumer must authenticate every record before using it.
    let head = stream.append(&[item], initial).unwrap();
    let before = inventory(&root);
    assert!(stream
        .visit(head, |r| verify_bytes(
            &r.approval.key,
            &record_bytes(&scope, r),
            &r.approval.signature
        ))
        .is_err());
    assert_eq!(inventory(&root), before);
}

#[test]
fn pending_seal_retains_complete_unpublished_record() {
    let scope = fixture_scope(Purpose::BftSigner(crate::tests::public(2)));
    let root = private_root();
    let dir = root.join("stream");
    let mut stream = Stream::create(&dir, scope.clone()).unwrap();
    let head = fill(&mut stream, 15);
    let item = record(&scope, 15, head);
    stream.interruption = Some(Boundary::Pending);
    assert!(stream.append(std::slice::from_ref(&item), head).is_err());
    let raw = fs::read(dir.join(PENDING)).unwrap();
    let pending: Publication<Record> = decode(&raw).unwrap();
    assert_eq!(pending.expected_head, head);
    assert_eq!(pending.pages.len(), 1);
    assert_eq!(pending.pages[0].records.len(), 16);
    assert_eq!(
        bytes(&pending.pages[0].records[15]).unwrap(),
        bytes(&item).unwrap()
    );
    assert_eq!(pending.manifest.count, 16);
    assert_eq!(pending.manifest.tail.len(), 0);
    let complete = bytes(&pending.pages[0]).unwrap();
    assert_eq!(
        Hash(Sha256::digest(&complete).into()),
        pending.manifest.pages[0].hash
    );
    assert_eq!(complete.len(), pending.manifest.pages[0].bytes);
    assert!(
        raw.windows(item.approval.signature.len())
            .any(|v| v == item.approval.signature.as_bytes()),
        "pending lacks the exact complete signed record"
    );
    assert_eq!(fs::read_dir(dir.join(OBJECTS)).unwrap().count(), 0);
    assert_eq!(stream.storage_head(), head);
    let before = inventory(&root);
    drop(stream);
    assert!(Stream::<Record>::open(&dir, &scope, head).is_err());
    assert_eq!(inventory(&root), before);
}

#[test]
fn orphan_file_capacity_and_oversize_refusals_are_atomic() {
    let scope = fixture_scope(Purpose::Ledger);
    let root = private_root();
    let dir = root.join("stream");
    let mut stream = Stream::create(&dir, scope.clone()).unwrap();
    let head = fill(&mut stream, 15);
    // Orphan corpus is a fixture, not acknowledged custody: no fsync claim.
    for index in 0..history::MAX_FILES - 4 {
        let hash = id("retained-orphan-capacity-test", &index).unwrap();
        let path = dir.join(OBJECTS).join(page_name(hash));
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        std::io::Write::write_all(
            &mut options.open(path).unwrap(),
            b"retained incomplete residue",
        )
        .unwrap();
    }
    let before = inventory(&root);
    let refusal = stream
        .append(&[record(&scope, 15, head)], head)
        .unwrap_err();
    assert!(refusal.contains("archive capacity"), "{refusal}");
    assert_eq!(inventory(&root), before);
    assert_eq!(stream.storage_head(), head);
    assert!(!dir.join(PENDING).exists());
    let mut huge = record(&scope, 15, head);
    huge.payload = "x".repeat(MAX_BYTES);
    assert!(stream.append(&[huge], head).is_err());
    assert_eq!(inventory(&root), before);
}

#[test]
fn unsafe_or_unexpected_entries_refuse() {
    let scope = fixture_scope(Purpose::Ledger);
    let root = private_root();
    let dir = root.join("stream");
    let stream = Stream::<Record>::create(&dir, scope.clone()).unwrap();
    let head = stream.storage_head();
    drop(stream);
    keystore::private_create(&dir.join("unindexed.json"), b"retained residue").unwrap();
    let before = inventory(&root);
    assert!(Stream::<Record>::open(&dir, &scope, head).is_err());
    assert_eq!(inventory(&root), before);
    let root = private_root();
    let dir = root.join("stream");
    let mut stream = Stream::create(&dir, scope.clone()).unwrap();
    let head = fill(&mut stream, 16);
    let path = dir
        .join(OBJECTS)
        .join(page_name(stream.manifest.pages[0].hash));
    drop(stream);
    fs::hard_link(&path, root.join("retained-linked-page.json")).unwrap();
    let before = inventory(&root);
    assert!(Stream::<Record>::open(&dir, &scope, head).is_err());
    assert_eq!(inventory(&root), before);
}

#[test]
fn retained_bytes_include_orphans_and_manifest_at_archive_ceiling() {
    let start = std::time::Instant::now();
    let scope = fixture_scope(Purpose::Ledger);
    let root = private_root();
    let dir = root.join("stream");
    let mut stream = Stream::<Record>::create(&dir, scope.clone()).unwrap();
    let head = stream.storage_head();
    // Sparse fixture residue has no custody/valid page claim. Its retained
    // length still counts; the manifest pushes exactly256MiB over the ceiling.
    for index in 0..history::MAX_ARCHIVE_BYTES / MAX_BYTES as u64 {
        let hash = id("retained-byte-capacity-test", &index).unwrap();
        let path = dir.join(OBJECTS).join(page_name(hash));
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options
            .open(path)
            .unwrap()
            .set_len(MAX_BYTES as u64)
            .unwrap();
    }
    let prepared_seconds = start.elapsed().as_secs_f64();
    let before = byte_capacity_inventory(&root);
    let before_inventory_seconds = start.elapsed().as_secs_f64();
    let refusal = stream.append(&[record(&scope, 0, head)], head).unwrap_err();
    assert!(refusal.contains("total archive capacity"), "{refusal}");
    assert_eq!(stream.storage_head(), head);
    assert_eq!(stream.record_count(), 0);
    assert!(!dir.join(PENDING).exists());
    drop(stream);
    assert!(Stream::<Record>::open(&dir, &scope, head).is_err());
    let native_refusals_seconds = start.elapsed().as_secs_f64();
    assert_eq!(byte_capacity_inventory(&root), before);
    eprintln!("byte_capacity_timing prepared={prepared_seconds:.6} before_inventory={before_inventory_seconds:.6} native_refusals={native_refusals_seconds:.6} complete={:.6}", start.elapsed().as_secs_f64());
}

#[test]
fn native_external_archive_accounting_refuses_before_any_stream_publication() {
    let root = private_root();
    let scope = fixture_scope(Purpose::Ledger);
    let mut stream = Stream::create(&root.join("ledger"), scope.clone()).unwrap();
    let head = stream.storage_head();
    let original = inventory(&root);
    let request = record(&scope, 0, Hash::ZERO);
    for (files, bytes) in [
        (history::MAX_FILES, 0),
        (0, history::MAX_ARCHIVE_BYTES),
        (usize::MAX, 0),
        (0, u64::MAX),
    ] {
        let error = stream
            .append_accounted(std::slice::from_ref(&request), head, files, bytes)
            .unwrap_err();
        assert!(error.contains("total archive capacity"), "{error}");
        assert_eq!(stream.storage_head(), head);
        assert_eq!(stream.record_count(), 0);
        assert_eq!(inventory(&root), original);
    }
    // Small retained root-side metadata fits and never becomes record authority.
    stream
        .append_accounted(std::slice::from_ref(&request), head, 3, 128)
        .unwrap();
    assert_eq!(stream.record_count(), 1);
    eprintln!("native_external_archive_accounting file/byte/overflow refusals atomic; small root metadata fits");
}

#[test]
fn committed_response_recovery_at_exact_file_limit_needs_no_new_commit_file() {
    let root = private_root();
    let scope = fixture_scope(Purpose::BftSigner(crate::tests::public(2)));
    let dir = root.join("signer");
    let mut stream = Stream::<Record>::create(&dir, scope.clone()).unwrap();
    let old = stream.storage_head();
    let response = record(&scope, 0, Hash::ZERO);
    stream.interruption = Some(Boundary::Committed);
    assert!(stream.append(std::slice::from_ref(&response), old).is_err());
    drop(stream);
    // Exactly4096 retained files:4093 private orphans + LOCK/current/pending.
    // Proposed manifest is already published and no new page/commit is needed.
    for n in 0..history::MAX_FILES - 3 {
        let hash = id("committed-recovery-capacity-orphan", &n).unwrap();
        keystore::private_create(&dir.join(OBJECTS).join(page_name(hash)), b"").unwrap();
    }
    let before = inventory(&root);
    assert_eq!(before.len(), history::MAX_FILES);
    let (stream, ()) =
        Stream::<Record>::recover_one_authenticated(&dir, &scope, old, 0, 0, |view| {
            view.visit(|r, last| {
                require(
                    last && r.index == 0 && r.previous == Hash::ZERO,
                    "fixture complete single response",
                )?;
                verify_bytes(
                    &r.approval.key,
                    &record_bytes(&scope, r),
                    &r.approval.signature,
                )
            })
        })
        .expect("completed manifest at actual4096 files must not reserve a nonexistent commit");
    assert_eq!(stream.record_count(), 1);
    let mut retained = before;
    retained.remove(&dir.join(PENDING));
    assert_eq!(inventory(&root), retained);
    eprintln!("committed-response exact4096 file arithmetic passes; private orphans unchanged; storage-signature fixture only, no native BFT authority");
}

#[test]
fn held_stream_refuses_changed_canonical_disk_manifest_without_rewrite() {
    let root = private_root();
    let scope = fixture_scope(Purpose::Ledger);
    let dir = root.join("ledger");
    let mut stream = Stream::<Record>::create(&dir, scope.clone()).unwrap();
    let old = stream.storage_head();
    let head = stream
        .append(&[record(&scope, 0, Hash::ZERO)], old)
        .unwrap();
    let mut changed = stream.manifest.clone();
    changed.head = Hash([7; 32]);
    // Preserve the complete original bytes; the malicious replacement itself
    // remains canonical typed JSON, so syntax rejection cannot mask the gate.
    keystore::private_create(
        &root.join("original-manifest"),
        &bytes(&stream.manifest).unwrap(),
    )
    .unwrap();
    fs::write(dir.join(MANIFEST), bytes(&changed).unwrap()).unwrap();
    let before = inventory(&root);
    assert!(stream
        .visit(head, |_| Ok(()))
        .unwrap_err()
        .contains("disk manifest differs"));
    assert_eq!(stream.storage_head(), head);
    assert_eq!(inventory(&root), before);
}
