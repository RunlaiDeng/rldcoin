use super::body_witness_tests::{certified, header, replay, stream};
use super::*;
use crate::retained_pages::packed::archive::PackedArchiveCandidate;
use crate::tests::public;
use std::process::Command as Process;

#[derive(Serialize)]
struct CompletePage {
    format: String,
    scope: Scope,
    first: u64,
    previous: Option<Hash>,
    records: Vec<Record>,
}
#[derive(Serialize, Deserialize)]
struct Caller {
    bootstrap: Bootstrap,
    prefix_head: Hash,
    prefix_manifest: crate::history::Reference,
    prefix_height: u64,
    prefix_finalized: Option<Hash>,
    prefix_epoch: Hash,
    prefix_root: Hash,
    tail_head: Hash,
    whole_head: Hash,
    height: u64,
    finalized: Option<Hash>,
    epoch: Hash,
    root: Hash,
    count: u64,
}
impl Caller {
    fn pins(&self) -> NativeContinuationPinsCandidate {
        let h = header_from_bootstrap(&self.bootstrap);
        let currency = self.bootstrap.currency.id().unwrap();
        NativeContinuationPinsCandidate {
            prefix: NativePrefixPinsCandidate {
                storage_head: self.prefix_head,
                manifest: self.prefix_manifest.clone(),
                latest: PackedNativeBoundaryCandidate {
                    currency,
                    region: h.region,
                    height: self.prefix_height,
                    finalized: self.prefix_finalized,
                    epoch: self.prefix_epoch,
                    ledger_root: self.prefix_root,
                    record_count: 16,
                },
            },
            tail_head: self.tail_head,
            complete_head: self.whole_head,
            latest: PackedNativeBoundaryCandidate {
                currency,
                region: h.region,
                height: self.height,
                finalized: self.finalized,
                epoch: self.epoch,
                ledger_root: self.root,
                record_count: self.count,
            },
        }
    }
}
fn header_from_bootstrap(bootstrap: &Bootstrap) -> Header {
    Header {
        format: FORMAT.into(),
        bootstrap: bootstrap.clone(),
        region: bootstrap.admissions[0].id().unwrap(),
    }
}
fn inventory(root: &Path) -> BTreeMap<PathBuf, (Hash, u64, std::time::SystemTime)> {
    fn walk(path: &Path, out: &mut BTreeMap<PathBuf, (Hash, u64, std::time::SystemTime)>) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            let m = fs::symlink_metadata(&path).unwrap();
            if m.is_dir() {
                walk(&path, out)
            } else {
                out.insert(
                    path.clone(),
                    (
                        Hash(Sha256::digest(fs::read(&path).unwrap()).into()),
                        m.len(),
                        m.modified().unwrap(),
                    ),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, &mut out);
    out
}
fn fixture() -> (
    PathBuf,
    Header,
    Replay,
    Stream<Record>,
    NativePrefixPinsCandidate,
) {
    let h = header();
    let mut hot = replay(&h);
    let (root, flat) = stream(&h, &hot);
    let scope = h.scope(&hot.trust).unwrap();
    let mut head = scope.initial().unwrap();
    let mut records = vec![];
    for i in 0..16 {
        let record = Record::Certified(Box::new(certified(&hot)));
        hot.apply(&record, &flat).unwrap();
        head = crate::retained_pages::next_head(head, i, &record).unwrap();
        records.push(record);
    }
    let raw = serde_json::to_vec(&CompletePage {
        format: "RLD-NATIVE-COMPLETE-STREAM-PAGES-V1".into(),
        scope: scope.clone(),
        first: 0,
        previous: None,
        records,
    })
    .unwrap();
    let prefix = PackedArchiveCandidate::<Record>::seal_lossless_candidate(
        &root.join("prefix"),
        scope,
        head,
        [Ok(raw)],
    )
    .unwrap();
    let manifest = prefix.manifest_reference_candidate().unwrap();
    drop(prefix);
    let pins = NativePrefixPinsCandidate {
        storage_head: head,
        manifest,
        latest: PackedNativeBoundaryCandidate {
            currency: hot.trust.currency().unwrap(),
            region: h.region,
            height: 16,
            finalized: hot.chain.finalized,
            epoch: hot.chain.epoch,
            ledger_root: hot.chain.ledger.root().unwrap(),
            record_count: 16,
        },
    };
    (root, h, hot, flat, pins)
}
fn create(
    root: &Path,
    h: &Header,
    prefix: &NativePrefixPinsCandidate,
) -> (NativeContinuationCandidate, NativeContinuationPinsCandidate) {
    NativeContinuationCandidate::create(
        &root.join("prefix"),
        &root.join("tail"),
        &h.bootstrap,
        &public(1),
        prefix.latest.currency,
        prefix,
    )
    .unwrap()
}
#[test]
fn actual16_plus16_native_tail_append_and_separate_cold_matches() {
    let (root, h, mut hot, flat, prefix) = fixture();
    let original = inventory(&root.join("prefix"));
    let (mut store, mut pins) = create(&root, &h, &prefix);
    for i in 0..16 {
        let next = certified(&hot);
        let record = Record::Certified(Box::new(next.clone()));
        hot.apply(&record, &flat).unwrap();
        let independent_head =
            crate::retained_pages::next_head(pins.complete_head, 16 + i, &record).unwrap();
        pins = store.append_certified(&next, &pins).unwrap();
        assert_eq!(pins.complete_head, independent_head);
        assert_eq!(pins.latest.height, 17 + i);
        assert_eq!(pins.latest.ledger_root, hot.chain.ledger.root().unwrap());
    }
    assert_eq!(store.inspect(&pins).unwrap(), pins.latest);
    drop(store);
    assert_eq!(inventory(&root.join("prefix")), original);
    let caller = Caller {
        bootstrap: h.bootstrap.clone(),
        prefix_head: prefix.storage_head,
        prefix_manifest: prefix.manifest,
        prefix_height: 16,
        prefix_finalized: prefix.latest.finalized,
        prefix_epoch: prefix.latest.epoch,
        prefix_root: prefix.latest.ledger_root,
        tail_head: pins.tail_head,
        whole_head: pins.complete_head,
        height: 32,
        finalized: hot.chain.finalized,
        epoch: hot.chain.epoch,
        root: hot.chain.ledger.root().unwrap(),
        count: 32,
    };
    crate::keystore::private_create(
        &root.join("caller.json"),
        &serde_json::to_vec(&caller).unwrap(),
    )
    .unwrap();
    let before = inventory(&root);
    let output = Process::new(std::env::current_exe().unwrap())
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .args([
            "storage::paged::continuation_tests::cold_child",
            "--exact",
            "--ignored",
            "--nocapture",
        ])
        .env("RLD_CONTINUATION_CHILD", &root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout)
        .contains("continuation-native-complete height32 records32"));
    assert_eq!(inventory(&root), before);
}
#[test]
#[ignore = "separate cold process with exact caller-owned no-value fixture"]
fn cold_child() {
    let root = PathBuf::from(std::env::var_os("RLD_CONTINUATION_CHILD").unwrap());
    let caller: Caller = serde_json::from_slice(
        &crate::keystore::private_read(&root.join("caller.json"), MAX_BYTES).unwrap(),
    )
    .unwrap();
    let pins = caller.pins();
    let store = NativeContinuationCandidate::open(
        &root.join("prefix"),
        &root.join("tail"),
        &caller.bootstrap,
        &public(1),
        pins.latest.currency,
        &pins,
    )
    .unwrap();
    assert_eq!(store.inspect(&pins).unwrap(), pins.latest);
    println!("continuation-native-complete height32 records32 full_genesis_replay=true no_ordinary_signer_adoption=true");
}
#[test]
fn wrong_pins_and_actual_bad_signature_refuse_without_any_publication() {
    let (root, h, hot, _flat, prefix) = fixture();
    let (mut store, pins) = create(&root, &h, &prefix);
    let next = certified(&hot);
    let before = inventory(&root);
    for choice in 0..5 {
        let mut wrong = pins.clone();
        match choice {
            0 => wrong.prefix.manifest.hash = Hash([9; 32]),
            1 => wrong.prefix.latest.ledger_root = Hash([9; 32]),
            2 => wrong.tail_head = Hash([9; 32]),
            3 => wrong.complete_head = Hash([9; 32]),
            _ => wrong.latest.finalized = Some(Hash([9; 32])),
        }
        assert!(store.inspect(&wrong).is_err());
        assert!(store.append_certified(&next, &wrong).is_err());
        assert_eq!(inventory(&root), before);
    }
    let mut bad = next.clone();
    bad.bft.as_mut().unwrap().committed.votes[0]
        .approval
        .signature = "00".repeat(64);
    let signature_error = crate::conflict::CertifiedHistory::from_snapshot(&bad)
        .verify(&hot.trust)
        .unwrap_err();
    assert_eq!(
        store.append_certified(&bad, &pins).unwrap_err(),
        signature_error
    );
    assert_eq!(inventory(&root), before);
    let updated = store.append_certified(&next, &pins).unwrap();
    drop(store);
    let before = inventory(&root);
    assert!(NativeContinuationCandidate::open(
        &root.join("prefix"),
        &root.join("tail"),
        &h.bootstrap,
        &public(1),
        prefix.latest.currency,
        &pins
    )
    .is_err());
    assert_eq!(inventory(&root), before);
    let opened = NativeContinuationCandidate::open(
        &root.join("prefix"),
        &root.join("tail"),
        &h.bootstrap,
        &public(1),
        prefix.latest.currency,
        &updated,
    )
    .unwrap();
    assert_eq!(opened.inspect(&updated).unwrap(), updated.latest);
}
#[test]
fn all_tail_publication_interruptions_refuse_reopen_and_preserve_prefix() {
    for boundary in 0..3 {
        let (root, h, mut hot, flat, prefix) = fixture();
        let original = inventory(&root.join("prefix"));
        let (mut store, mut pins) = create(&root, &h, &prefix);
        for _ in 0..15 {
            let next = certified(&hot);
            hot.apply(&Record::Certified(Box::new(next.clone())), &flat)
                .unwrap();
            pins = store.append_certified(&next, &pins).unwrap();
        }
        let next = certified(&hot);
        store.interrupt_at(boundary);
        assert!(store.append_certified(&next, &pins).is_err());
        assert!(store.inspect(&pins).is_err());
        drop(store);
        let before = inventory(&root);
        assert!(NativeContinuationCandidate::open(
            &root.join("prefix"),
            &root.join("tail"),
            &h.bootstrap,
            &public(1),
            prefix.latest.currency,
            &pins
        )
        .is_err());
        assert!(NativeContinuationCandidate::create(
            &root.join("prefix"),
            &root.join("tail"),
            &h.bootstrap,
            &public(1),
            prefix.latest.currency,
            &prefix
        )
        .is_err());
        assert_eq!(inventory(&root), before);
        assert_eq!(inventory(&root.join("prefix")), original);
    }
}
#[test]
fn aggregate_prefix_orphans_cannot_hide_behind_separate_tail_capacity() {
    let (root, h, hot, _flat, prefix) = fixture();
    let (mut store, pins) = create(&root, &h, &prefix);
    for index in 0..crate::history::MAX_FILES - 3 {
        let hash = id("continuation-owned-orphan-capacity", &index).unwrap();
        crate::keystore::private_create(
            &root
                .join("prefix/packs")
                .join(format!("{}.pack", hash.to_hex())),
            b"",
        )
        .unwrap();
    }
    let before = inventory(&root);
    assert!(store
        .append_certified(&certified(&hot), &pins)
        .unwrap_err()
        .contains("aggregate retained capacity"));
    assert_eq!(inventory(&root), before);
}
