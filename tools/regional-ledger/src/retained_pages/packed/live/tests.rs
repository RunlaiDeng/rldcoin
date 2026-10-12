//! Fresh byte-only fixtures; these tests never initialize a Native ledger or custody.
use super::*;
use std::collections::BTreeMap;

struct Fixture {
    root: PathBuf,
    scope: Scope,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "rld-live-packed-{}",
            crate::contact_runtime::random().unwrap()
        ));
        make_dir(&root).unwrap();
        Self {
            root,
            scope: Scope {
                implementation: crate::implementation().unwrap(),
                currency: Hash([1; 32]),
                region: Hash([2; 32]),
                admission: Hash([3; 32]),
                purpose: super::super::super::Purpose::Ledger,
                origin: Hash([4; 32]),
            },
        }
    }
    fn path(&self) -> PathBuf {
        self.root.join("stream")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "Failed live packed fixture retained: {}",
                self.root.display()
            );
        } else {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }
}
fn inventory(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    for root in [dir.to_path_buf(), dir.join(OBJECTS)] {
        for item in fs::read_dir(root).unwrap() {
            let path = item.unwrap().path();
            if path.is_file() {
                files.insert(path.clone(), fs::read(path).unwrap());
            }
        }
    }
    files
}
fn append_range(
    stream: &mut AppendablePackedStreamCandidate<u64>,
    scope: &Scope,
    end: u64,
) -> Hash {
    let mut head = scope.initial().unwrap();
    let mut index = 0;
    while index < end {
        let records = (index..(index + PAGE as u64).min(end)).collect::<Vec<_>>();
        for record in &records {
            head = next_head(head, index, record).unwrap();
            index += 1;
        }
        let previous = stream.storage_head();
        assert_eq!(stream.append(&records, previous).unwrap(), head);
    }
    head
}

#[test]
fn append_cold_replay_keeps_complete_packs_pages_and_partial_tail() {
    let f = Fixture::new();
    let mut stream =
        AppendablePackedStreamCandidate::<u64>::create(&f.path(), f.scope.clone()).unwrap();
    let head = append_range(&mut stream, &f.scope, 1107);
    assert_eq!(stream.manifest.packs.len(), 1);
    assert_eq!(stream.manifest.complete.len(), 5);
    assert_eq!(stream.manifest.tail.len(), 3);
    assert_eq!(stream.record_count(), 1107);
    assert_eq!(usage(&f.path()).unwrap().0, 3);
    let before = inventory(&f.path());
    assert!(stream.append(&[1107], f.scope.initial().unwrap()).is_err());
    assert_eq!(inventory(&f.path()), before);
    drop(stream);
    let mut cold = AppendablePackedStreamCandidate::<u64>::open(&f.path(), &f.scope, head).unwrap();
    let mut records = Vec::new();
    assert_eq!(
        cold.visit(head, |record| {
            records.push(*record);
            Ok(())
        })
        .unwrap(),
        1107
    );
    assert_eq!(records, (0..1107).collect::<Vec<_>>());
    assert_eq!(inventory(&f.path()), before);
    let next = next_head(head, 1107, &1107u64).unwrap();
    assert_eq!(cold.append(&[1107], head).unwrap(), next);
    drop(cold);
    let mut wrong_scope = f.scope.clone();
    wrong_scope.currency = Hash([9; 32]);
    assert!(AppendablePackedStreamCandidate::<u64>::open(&f.path(), &wrong_scope, next).is_err());
    assert!(AppendablePackedStreamCandidate::<u64>::open(&f.path(), &f.scope, head).is_err());
    assert!(AppendablePackedStreamCandidate::<u64>::create(&f.path(), f.scope.clone()).is_err());
}

#[test]
fn pending_object_and_manifest_boundaries_refuse_without_recovery_or_head_release() {
    for boundary in 0..3 {
        let f = Fixture::new();
        let mut stream =
            AppendablePackedStreamCandidate::<u64>::create(&f.path(), f.scope.clone()).unwrap();
        let old = append_range(&mut stream, &f.scope, 1008);
        stream.interruption = Some(boundary);
        assert!(stream
            .append(&(1008..1024).collect::<Vec<_>>(), old)
            .is_err());
        assert_eq!(stream.storage_head(), old);
        assert!(f.path().join(PENDING).exists());
        let pending: serde_json::Value =
            serde_json::from_slice(&fs::read(f.path().join(PENDING)).unwrap()).unwrap();
        assert_eq!(pending["objects"].as_array().unwrap().len(), 1);
        assert!(!pending["objects"][0]["encoded_b64"]
            .as_str()
            .unwrap()
            .is_empty());
        let before = inventory(&f.path());
        assert!(stream.visit(old, |_| Ok(())).is_err());
        drop(stream);
        assert!(AppendablePackedStreamCandidate::<u64>::open(&f.path(), &f.scope, old).is_err());
        assert_eq!(inventory(&f.path()), before);
    }
}

#[test]
fn large_complete_pages_flush_before_the_unchanged_object_limit() {
    let f = Fixture::new();
    let mut stream =
        AppendablePackedStreamCandidate::<String>::create(&f.path(), f.scope.clone()).unwrap();
    let mut expected = f.scope.initial().unwrap();
    let mut count = 0;
    for marker in ["a", "b", "c"] {
        let mut page = vec![String::new(); PAGE];
        page[0] = marker.repeat(MAX_BYTES / 2);
        for record in &page {
            expected = next_head(expected, count, record).unwrap();
            count += 1;
        }
        let previous = stream.storage_head();
        assert_eq!(stream.append(&page, previous).unwrap(), expected);
    }
    assert_eq!(stream.manifest.packs.len(), 2);
    assert_eq!(stream.manifest.complete.len(), 1);
    assert!(stream
        .manifest
        .packs
        .iter()
        .all(|p| p.encoded.bytes <= MAX_BYTES && p.original.bytes <= MAX_BYTES));
    drop(stream);
    let cold =
        AppendablePackedStreamCandidate::<String>::open(&f.path(), &f.scope, expected).unwrap();
    let mut observed = 0;
    cold.visit(expected, |record| {
        if observed % PAGE == 0 {
            assert_eq!(
                record.as_bytes(),
                [b'a' + (observed / PAGE) as u8].repeat(MAX_BYTES / 2)
            );
        } else {
            assert!(record.is_empty());
        }
        observed += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(observed, PAGE * 3);
}

#[test]
fn altered_complete_pack_and_manifest_tail_refuse_without_rewrite() {
    let f = Fixture::new();
    let mut stream =
        AppendablePackedStreamCandidate::<u64>::create(&f.path(), f.scope.clone()).unwrap();
    let head = append_range(&mut stream, &f.scope, 1025);
    let pack = f
        .path()
        .join(OBJECTS)
        .join(name(stream.manifest.packs[0].encoded.hash));
    drop(stream);
    let original = fs::read(&pack).unwrap();
    let mut bad = original.clone();
    *bad.last_mut().unwrap() ^= 1;
    fs::write(&pack, &bad).unwrap();
    let before = inventory(&f.path());
    assert!(AppendablePackedStreamCandidate::<u64>::open(&f.path(), &f.scope, head).is_err());
    assert_eq!(inventory(&f.path()), before);
    // Separate negative input in this same fresh byte-only control fixture.
    fs::write(&pack, original).unwrap();
    let mut manifest: Manifest<u64> = decode(&fs::read(f.path().join(MANIFEST)).unwrap()).unwrap();
    manifest.tail[0] = 0;
    fs::write(f.path().join(MANIFEST), bytes(&manifest).unwrap()).unwrap();
    let before = inventory(&f.path());
    assert!(AppendablePackedStreamCandidate::<u64>::open(&f.path(), &f.scope, head).is_err());
    assert_eq!(inventory(&f.path()), before);
}

#[test]
fn orphan_and_publication_peak_count_and_byte_caps_precede_any_mutation() {
    let f = Fixture::new();
    let mut stream =
        AppendablePackedStreamCandidate::<u64>::create(&f.path(), f.scope.clone()).unwrap();
    keystore::private_create(
        &f.path().join(OBJECTS).join(name(Hash([99; 32]))),
        b"orphan",
    )
    .unwrap();
    let head = stream.storage_head();
    let before = inventory(&f.path());
    assert!(stream
        .append_accounted(&[1], head, history::MAX_FILES - 4, 0)
        .is_err());
    assert!(stream
        .append_accounted(&[1], head, 0, history::MAX_ARCHIVE_BYTES)
        .is_err());
    assert_eq!(inventory(&f.path()), before);
    assert_eq!(stream.storage_head(), head);
    stream
        .append_accounted(&[1], head, history::MAX_FILES - 5, 0)
        .unwrap();
    assert_eq!(
        fs::read(f.path().join(OBJECTS).join(name(Hash([99; 32])))).unwrap(),
        b"orphan"
    );
}

#[test]
fn legacy_stream_and_oversized_record_are_never_converted_or_written() {
    let f = Fixture::new();
    let mut old =
        super::super::super::Stream::<u64>::create(&f.root.join("old"), f.scope.clone()).unwrap();
    let head = old.storage_head();
    old.append(&[1], head).unwrap();
    let head = old.storage_head();
    drop(old);
    let original = fs::read(f.root.join("old/stream.json")).unwrap();
    assert!(
        AppendablePackedStreamCandidate::<u64>::open(&f.root.join("old"), &f.scope, head).is_err()
    );
    assert_eq!(fs::read(f.root.join("old/stream.json")).unwrap(), original);
    let mut stream =
        AppendablePackedStreamCandidate::<String>::create(&f.path(), f.scope.clone()).unwrap();
    let before = inventory(&f.path());
    let head = stream.storage_head();
    assert!(stream.append(&["x".repeat(MAX_BYTES)], head).is_err());
    assert_eq!(inventory(&f.path()), before);
}
