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

#[derive(Serialize, Deserialize)]
struct LosslessCaller {
    caller: IndependentCaller,
    manifest: crate::history::Reference,
}
#[test]
fn lossless_durable_actual16_heights_cold_child_matches_and_raw_entry_refuses() {
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
    let dir = root.join("lossless-native");
    let archive = PackedArchiveCandidate::<Record>::seal_lossless_candidate(
        &dir,
        scope,
        caller.storage_head,
        [Ok(page)],
    )
    .unwrap();
    let manifest = archive.manifest_reference_candidate().unwrap();
    drop(archive);
    let got = inspect_lossless_packed_native_candidate(
        &dir,
        &caller.bootstrap,
        &public(1),
        expected.currency,
        caller.storage_head,
        &manifest,
        &expected,
    )
    .unwrap();
    assert_eq!(got, expected);
    let separate = LosslessCaller { caller, manifest };
    crate::keystore::private_create(
        &root.join("lossless-caller.json"),
        &serde_json::to_vec(&separate).unwrap(),
    )
    .unwrap();
    let before = inventory(&root);
    let output = Process::new(std::env::current_exe().unwrap())
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .args([
            "storage::paged::packed_inspection_tests::lossless_native_cold_child",
            "--exact",
            "--ignored",
            "--nocapture",
        ])
        .env("RLD_LOSSLESS_NATIVE_CHILD", &root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("actual-lossless-native-cold-height16")
    );
    let caller = &separate.caller;
    assert!(inspect_packed_native_candidate(
        &dir,
        &caller.bootstrap,
        &public(1),
        expected.currency,
        caller.storage_head,
        &expected
    )
    .is_err());
    let mut wrong = separate.manifest.clone();
    wrong.hash = Hash([9; 32]);
    assert!(inspect_lossless_packed_native_candidate(
        &dir,
        &caller.bootstrap,
        &public(1),
        expected.currency,
        caller.storage_head,
        &wrong,
        &expected
    )
    .is_err());
    let mut wrong = expected.clone();
    wrong.finalized = Some(Hash([9; 32]));
    assert!(inspect_lossless_packed_native_candidate(
        &dir,
        &caller.bootstrap,
        &public(1),
        expected.currency,
        caller.storage_head,
        &separate.manifest,
        &wrong
    )
    .is_err());
    assert_eq!(inventory(&root), before);
}
#[test]
#[ignore = "separate Native cold process, independent complete current manifest"]
fn lossless_native_cold_child() {
    let root = PathBuf::from(std::env::var_os("RLD_LOSSLESS_NATIVE_CHILD").unwrap());
    let separate: LosslessCaller = serde_json::from_slice(
        &crate::keystore::private_read(&root.join("lossless-caller.json"), MAX_BYTES).unwrap(),
    )
    .unwrap();
    let caller = separate.caller;
    let expected = caller.boundary();
    let got = inspect_lossless_packed_native_candidate(
        &root.join("lossless-native"),
        &caller.bootstrap,
        &public(1),
        expected.currency,
        caller.storage_head,
        &separate.manifest,
        &expected,
    )
    .unwrap();
    assert_eq!(got, expected);
    println!("actual-lossless-native-cold-height{} all_complete_signatures=true no_store_or_signer_adoption=true",got.height);
}
#[test]
fn lossless_hash_consistent_bad_final_certificate_never_returns_native_boundary() {
    let (root, h, scope, mut records, mut caller) = fixture();
    let Record::Certified(last) = records.last_mut().unwrap() else {
        unreachable!()
    };
    last.bft.as_mut().unwrap().committed.votes[0]
        .approval
        .signature = "00".repeat(64);
    let signature_failure = crate::conflict::CertifiedHistory::from_snapshot(last)
        .verify(&replay(&h).trust)
        .unwrap_err();
    let mut head = scope.initial().unwrap();
    for (i, record) in records.iter().enumerate() {
        head = crate::retained_pages::next_head(head, i as u64, record).unwrap();
    }
    caller.storage_head = head;
    let expected = caller.boundary();
    let page = serde_json::to_vec(&CompletePage {
        format: "RLD-NATIVE-COMPLETE-STREAM-PAGES-V1".into(),
        scope: scope.clone(),
        first: 0,
        previous: None,
        records,
    })
    .unwrap();
    let dir = root.join("bad-lossless-native");
    let archive =
        PackedArchiveCandidate::<Record>::seal_lossless_candidate(&dir, scope, head, [Ok(page)])
            .unwrap();
    let manifest = archive.manifest_reference_candidate().unwrap();
    drop(archive);
    let before = inventory(&root);
    let failure = inspect_lossless_packed_native_candidate(
        &dir,
        &caller.bootstrap,
        &public(1),
        expected.currency,
        head,
        &manifest,
        &expected,
    )
    .unwrap_err();
    assert_eq!(failure, signature_failure);
    assert_eq!(inventory(&root), before);
}

#[test]
fn consolidated128_native_heights_keep_working_coins_bounded_and_cold_matches() {
    consolidated_native_history(128, 0, false)
}
#[test]
fn actual4112_heights_evict_old_body_and_complete_late_certificate_cold_matches() {
    consolidated_native_history(4112, 16, false)
}
#[test]
fn streaming32_signed_native_heights_cold_matches_without_whole_page_list() {
    consolidated_native_history(32, 0, true)
}
#[test]
#[ignore = "single bounded long-history parent only; public no-value keys, no network or adopted state"]
fn streaming200016_native_heights_cross_halving_and_late_original_cold_matches() {
    consolidated_native_history(200016, 16, true)
}
fn consolidated_native_history(heights: u64, late_retries: usize, streaming: bool) {
    use super::body_witness_tests::certified_with_commands;
    use crate::tests::signature;
    let h = header();
    let mut r = replay(&h);
    let (root, flat) = stream(&h, &r);
    let scope = h.scope(&r.trust).unwrap();
    let mut logical = scope.initial().unwrap();
    let mut previous = None;
    let mut pending = Vec::new();
    let mut pages = vec![];
    let dir = root.join("lossless-native");
    let mut writer = streaming.then(|| {
        crate::retained_pages::packed::archive::LosslessArchiveWriterCandidate::<Record>::begin(
            &dir,
            scope.clone(),
        )
        .unwrap()
    });
    let mut payments = 0;
    let mut pending_group_peak = 0usize;
    let started = std::time::Instant::now();
    let mut original_bytes = 0;
    let mut first_record = None;
    for height in 1..=heights {
        let mature = r
            .chain
            .ledger
            .coins
            .iter()
            .filter(|(_, c)| c.payment.owner == public(10) && c.mature <= height)
            .take(3)
            .map(|(id, c)| (*id, c.payment.amount))
            .collect::<Vec<_>>();
        let commands = if mature.len() == 3 {
            let total = mature
                .iter()
                .try_fold(Amount::ZERO, |v, (_, a)| v.checked_add(*a))
                .unwrap();
            let intent = Intent {
                currency: r.trust.currency().unwrap(),
                region: r.chain.region,
                inputs: mature.iter().map(|(id, _)| *id).collect(),
                outputs: vec![Payment {
                    owner: public(10),
                    amount: total.checked_sub(Amount(1)).unwrap(),
                }],
                fee: Amount(1),
                destination: None,
                remote: None,
                destination_fee: Amount::ZERO,
                valid_through: height + 8,
            };
            let signed = SignedIntent {
                approvals: vec![Approval {
                    key: public(10),
                    signature: signature(10, &intent.bytes().unwrap()),
                }],
                intent,
            };
            payments += 1;
            vec![Command::Spend(Box::new(signed))]
        } else {
            vec![]
        };
        let record = Record::Certified(Box::new(certified_with_commands(&r, commands)));
        if height == 1 {
            first_record = Some(record.clone());
        }
        r.apply(&record, &flat).unwrap();
        assert_eq!(r.chain.height(), height);
        assert!(r.chain.ledger.coins.len() <= 12);
        assert!(r.evidence.snapshots.len() <= MAX_SNAPSHOTS);
        r.chain.ledger.audit().unwrap();
        logical = crate::retained_pages::next_head(logical, height - 1, &record).unwrap();
        pending.push(record);
        if pending.len() == 16 {
            let raw = serde_json::to_vec(&CompletePage {
                format: "RLD-NATIVE-COMPLETE-STREAM-PAGES-V1".into(),
                scope: scope.clone(),
                first: height - 16,
                previous,
                records: std::mem::take(&mut pending),
            })
            .unwrap();
            original_bytes += raw.len();
            previous = Some(Hash(Sha256::digest(&raw).into()));
            if let Some(writer) = writer.as_mut() {
                writer.retain_complete_page(raw).unwrap();
                let (pages, held, _) = writer.pending_candidate();
                assert!(pages <= 64 && held <= MAX_BYTES);
                pending_group_peak = pending_group_peak.max(held);
            } else {
                pages.push(Ok(raw));
            }
        }
        if streaming && height % 8192 == 0 {
            println!("streaming-native-progress height={} signed_payments={} original_bytes={} pending_group_peak={} elapsed_seconds={:.3}", height, payments, original_bytes, pending_group_peak, started.elapsed().as_secs_f64());
        }
    }
    if late_retries > 0 {
        assert!(heights > MAX_COINS as u64);
        let first = first_record.unwrap();
        let Record::Certified(snapshot) = &first else {
            unreachable!()
        };
        assert!(
            r.bodies.get(&snapshot.statement.id().unwrap()).is_none(),
            "actual original native body must have evicted at the unchanged4096 bound"
        );
        for index in 0..late_retries {
            logical =
                crate::retained_pages::next_head(logical, heights + index as u64, &first).unwrap();
            pending.push(first.clone());
        }
        assert_eq!(pending.len(), 16);
        let raw = serde_json::to_vec(&CompletePage {
            format: "RLD-NATIVE-COMPLETE-STREAM-PAGES-V1".into(),
            scope: scope.clone(),
            first: heights,
            previous,
            records: std::mem::take(&mut pending),
        })
        .unwrap();
        original_bytes += raw.len();
        if let Some(writer) = writer.as_mut() {
            writer.retain_complete_page(raw).unwrap();
            let (pages, held, _) = writer.pending_candidate();
            assert!(pages <= 64 && held <= MAX_BYTES);
            pending_group_peak = pending_group_peak.max(held);
        } else {
            pages.push(Ok(raw));
        }
    }
    assert!(payments > heights.saturating_sub(10));
    assert!(pending.is_empty());
    assert_eq!(
        r.chain.ledger.minted,
        Amount(rld_pow::cumulative_emission(heights.into()))
    );
    let hot_seconds = started.elapsed().as_secs_f64();
    let at = std::time::Instant::now();
    let archive = if let Some(writer) = writer {
        assert!(pages.is_empty());
        writer.finish(logical).unwrap()
    } else {
        PackedArchiveCandidate::<Record>::seal_lossless_candidate(&dir, scope, logical, pages)
            .unwrap()
    };
    let manifest = archive.manifest_reference_candidate().unwrap();
    drop(archive);
    let seal_seconds = at.elapsed().as_secs_f64();
    let caller = IndependentCaller {
        bootstrap: h.bootstrap.clone(),
        region: h.region,
        storage_head: logical,
        height: heights,
        finalized: r.chain.finalized,
        epoch: r.chain.epoch,
        ledger_root: r.chain.ledger.root().unwrap(),
        count: heights + late_retries as u64,
    };
    let expected = caller.boundary();
    let separate = LosslessCaller { caller, manifest };
    crate::keystore::private_create(
        &root.join("lossless-caller.json"),
        &serde_json::to_vec(&separate).unwrap(),
    )
    .unwrap();
    let before = inventory(&root);
    let at = std::time::Instant::now();
    let output = Process::new(std::env::current_exe().unwrap())
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .args([
            "storage::paged::packed_inspection_tests::lossless_native_cold_child",
            "--exact",
            "--ignored",
            "--nocapture",
        ])
        .env("RLD_LOSSLESS_NATIVE_CHILD", &root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout)
        .contains(&format!("actual-lossless-native-cold-height{heights}")));
    assert_eq!(inventory(&root), before);
    let cold_seconds = at.elapsed().as_secs_f64();
    let archive_bytes = inventory(&dir)
        .values()
        .map(|(_, bytes, _)| bytes)
        .sum::<u64>();
    println!("lossless-consolidated-complete height={} records={} signed_payments={} coins={} active={} original_page_bytes={} retained_archive_bytes={} hot_seconds={:.6} seal_seconds={:.6} cold_child_seconds={:.6} source_root={} streaming={} pending_group_peak={} complete_adoption_qualification=false",expected.height,expected.record_count,payments,r.chain.ledger.coins.len(),r.evidence.snapshots.len(),original_bytes,archive_bytes,hot_seconds,seal_seconds,cold_seconds,expected.ledger_root.to_hex(),streaming,pending_group_peak);
}
