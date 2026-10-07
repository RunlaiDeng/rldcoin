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
struct IndependentCaller {
    bootstrap: Bootstrap,
    region: Hash,
    storage_head: Hash,
    height: u64,
    finalized: Option<Hash>,
    epoch: Hash,
    ledger_root: Hash,
    count: u64,
}
impl IndependentCaller {
    fn boundary(&self) -> PackedNativeBoundaryCandidate {
        PackedNativeBoundaryCandidate {
            currency: self.bootstrap.currency.id().unwrap(),
            region: self.region,
            height: self.height,
            finalized: self.finalized,
            epoch: self.epoch,
            ledger_root: self.ledger_root,
            record_count: self.count,
        }
    }
}
fn inventory(root: &Path) -> BTreeMap<PathBuf, (Hash, u64, std::time::SystemTime)> {
    let mut out = BTreeMap::new();
    fn walk(p: &Path, out: &mut BTreeMap<PathBuf, (Hash, u64, std::time::SystemTime)>) {
        for e in fs::read_dir(p).unwrap() {
            let p = e.unwrap().path();
            let m = fs::symlink_metadata(&p).unwrap();
            if m.is_dir() {
                walk(&p, out);
            } else {
                out.insert(
                    p.clone(),
                    (
                        Hash(Sha256::digest(fs::read(p).unwrap()).into()),
                        m.len(),
                        m.modified().unwrap(),
                    ),
                );
            }
        }
    }
    walk(root, &mut out);
    out
}
fn fixture() -> (PathBuf, Header, Scope, Vec<Record>, IndependentCaller) {
    let h = header();
    let mut r = replay(&h);
    let (root, flat) = stream(&h, &r);
    let scope = h.scope(&r.trust).unwrap();
    let mut records = vec![];
    let mut head = scope.initial().unwrap();
    for index in 0..16 {
        let record = Record::Certified(Box::new(certified(&r)));
        r.apply(&record, &flat).unwrap();
        head = crate::retained_pages::next_head(head, index, &record).unwrap();
        records.push(record);
    }
    let caller = IndependentCaller {
        bootstrap: h.bootstrap.clone(),
        region: h.region,
        storage_head: head,
        height: r.chain.height(),
        finalized: r.chain.finalized,
        epoch: r.chain.epoch,
        ledger_root: r.chain.ledger.root().unwrap(),
        count: 16,
    };
    (root, h, scope, records, caller)
}
fn seal(root: &Path, scope: Scope, records: Vec<Record>, head: Hash) -> PathBuf {
    let raw = serde_json::to_vec(&CompletePage {
        format: "RLD-NATIVE-COMPLETE-STREAM-PAGES-V1".into(),
        scope: scope.clone(),
        first: 0,
        previous: None,
        records,
    })
    .unwrap();
    let dir = root.join("packed");
    drop(PackedArchiveCandidate::<Record>::seal(&dir, scope, head, [Ok(raw)]).unwrap());
    dir
}
#[test]
fn actual16_signed_heights_execute_from_genesis_and_separate_cold_child_matches() {
    let (root, h, scope, records, caller) = fixture();
    let first_sid = match &records[0] {
        Record::Certified(s) => s.statement.id().unwrap(),
        _ => unreachable!(),
    };
    let expected = caller.boundary();
    assert_eq!(expected.height, 16);
    let dir = seal(&root, scope.clone(), records, caller.storage_head);
    let boundary = inspect_packed_native_candidate(
        &dir,
        &caller.bootstrap,
        &public(1),
        expected.currency,
        caller.storage_head,
        &expected,
    )
    .unwrap();
    assert_eq!(boundary, expected);
    let archive =
        PackedArchiveCandidate::<Record>::open(&dir, &scope, caller.storage_head).unwrap();
    let source = super::packed_inspection::PackedHistory {
        archive: &archive,
        scope,
        current_head: caller.storage_head,
    };
    let mut executed = replay(&h);
    archive
        .visit(caller.storage_head, |record| {
            executed.apply_retained(record, &source)
        })
        .unwrap();
    super::body_witness_tests::evict_real_bodies(&mut executed);
    assert!(executed.prior_body(first_sid, &source).unwrap().is_some());
    assert_eq!(executed.chain.ledger.root().unwrap(), expected.ledger_root);
    drop(archive);

    crate::keystore::private_create(
        &root.join("caller.json"),
        &serde_json::to_vec(&caller).unwrap(),
    )
    .unwrap();
    let before = inventory(&root);
    let output = Process::new(std::env::current_exe().unwrap())
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .args([
            "storage::paged::packed_inspection_tests::cold_child",
            "--exact",
            "--ignored",
            "--nocapture",
        ])
        .env("RLD_PACKED_NATIVE_CANDIDATE_CHILD", &root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("actual-native-cold-height16"));
    assert_eq!(inventory(&root), before);
    let mut wrong = expected.clone();
    wrong.ledger_root = Hash([9; 32]);
    assert!(inspect_packed_native_candidate(
        &dir,
        &caller.bootstrap,
        &public(1),
        expected.currency,
        caller.storage_head,
        &wrong
    )
    .is_err());
    assert!(inspect_packed_native_candidate(
        &dir,
        &caller.bootstrap,
        &public(1),
        expected.currency,
        Hash([9; 32]),
        &expected
    )
    .is_err());
    assert!(inspect_packed_native_candidate(
        &dir,
        &caller.bootstrap,
        &public(2),
        expected.currency,
        caller.storage_head,
        &expected
    )
    .is_err());
    assert_eq!(inventory(&root), before);
}
#[test]
#[ignore = "invoked in separate process with independent caller inputs"]
fn cold_child() {
    let root = PathBuf::from(std::env::var_os("RLD_PACKED_NATIVE_CANDIDATE_CHILD").unwrap());
    let caller: IndependentCaller = serde_json::from_slice(
        &crate::keystore::private_read(&root.join("caller.json"), MAX_BYTES).unwrap(),
    )
    .unwrap();
    let expected = caller.boundary();
    assert_eq!(expected.height, 16);
    let got = inspect_packed_native_candidate(
        &root.join("packed"),
        &caller.bootstrap,
        &public(1),
        expected.currency,
        caller.storage_head,
        &expected,
    )
    .unwrap();
    assert_eq!(got, expected);
    println!(
        "actual-native-cold-height16 complete_signature_replay=true no_store_or_key_adoption=true"
    );
}
#[test]
fn hash_consistent_packed_bad_last_native_certificate_returns_no_boundary() {
    let (root, h, scope, mut records, mut caller) = fixture();
    let Record::Certified(last) = records.last_mut().unwrap() else {
        panic!("complete certificate")
    };
    last.bft.as_mut().unwrap().committed.votes[0]
        .approval
        .signature = "00".repeat(64);
    let trust = replay(&h).trust;
    let signature_failure = crate::conflict::CertifiedHistory::from_snapshot(last)
        .verify(&trust)
        .unwrap_err();
    let mut head = scope.initial().unwrap();
    for (i, record) in records.iter().enumerate() {
        head = crate::retained_pages::next_head(head, i as u64, record).unwrap();
    }
    caller.storage_head = head;
    let expected = caller.boundary();
    let dir = seal(&root, scope, records, head);
    let before = inventory(&root);
    let failure = inspect_packed_native_candidate(
        &dir,
        &caller.bootstrap,
        &public(1),
        expected.currency,
        head,
        &expected,
    )
    .unwrap_err();
    assert_eq!(
        failure, signature_failure,
        "must reach the exact actual Native signature failure"
    );
    assert_eq!(inventory(&root), before);
}

#[test]
fn actual_signed_native_page_recovers_exact_bytes_and_executes_after_lossless_decode() {
    use crate::retained_pages::packed::{
        encode_complete_page_pack_candidate,
        lossless::{
            encode_lossless_complete_pack_candidate, verify_lossless_complete_pack_candidate,
        },
        PackedPageContextCandidateV1,
    };
    let (root, _h, scope, records, caller) = fixture();
    let expected = caller.boundary();
    let page = serde_json::to_vec(&CompletePage {
        format: "RLD-NATIVE-COMPLETE-STREAM-PAGES-V1".into(),
        scope: scope.clone(),
        first: 0,
        previous: None,
        records,
    })
    .unwrap();
    let ctx = PackedPageContextCandidateV1 {
        scope: scope.clone(),
        first_record: 0,
        previous_page: None,
        previous_pack: None,
    };
    let (original_ref, original_pack) =
        encode_complete_page_pack_candidate::<Record>(&ctx, &[&page]).unwrap();
    let (encoded_ref, encoded) =
        encode_lossless_complete_pack_candidate::<Record>(&ctx, &original_ref, &original_pack)
            .unwrap();
    let restored = verify_lossless_complete_pack_candidate::<Record>(
        &ctx,
        &original_ref,
        &encoded_ref,
        &encoded,
    )
    .unwrap();
    assert_eq!(restored.original_pack, original_pack);
    assert_eq!(restored.complete.next_record, 16);
    let offset = b"RLD-NATIVE-COMPLETE-PAGE-PACK-CANDIDATE-V1\0".len() + 32 + 8 + 1 + 1 + 2;
    let n = u32::from_be_bytes(
        restored.original_pack[offset..offset + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    assert_eq!(offset + 4 + n, restored.original_pack.len());
    let recovered_page = restored.original_pack[offset + 4..].to_vec();
    assert_eq!(recovered_page, page);
    let dir = root.join("recovered");
    drop(
        PackedArchiveCandidate::<Record>::seal(
            &dir,
            scope,
            caller.storage_head,
            [Ok(recovered_page)],
        )
        .unwrap(),
    );
    let got = inspect_packed_native_candidate(
        &dir,
        &caller.bootstrap,
        &public(1),
        expected.currency,
        caller.storage_head,
        &expected,
    )
    .unwrap();
    assert_eq!(got, expected);
    assert!(encoded.len() < original_pack.len());
    println!("lossless-native-complete original_pack_bytes={} encoded_bytes={} decoded_bytes={} actual_height={} original_signatures_preserved=true long_history_qualification=false",original_pack.len(),encoded.len(),restored.original_pack.len(),got.height);
}
