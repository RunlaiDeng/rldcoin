//! Fresh public no-value source signatures only; no copied Store or signing custody.
use super::body_witness_tests::{certified_with_commands, header, replay, stream};
use super::*;
use crate::retained_pages::packed::archive::PackedArchiveCandidate;
use crate::tests::{public, signature};
use std::process::Command as Process;

#[derive(Serialize)]
struct Page {
    format: String,
    scope: Scope,
    first: u64,
    previous: Option<Hash>,
    records: Vec<Record>,
}
#[derive(Serialize, Deserialize)]
struct Caller {
    bootstrap: Bootstrap,
    query: ExportArchiveQueryCandidate,
    byte_head: Hash,
    checkpoint: Hash,
}
fn inventory(root: &Path) -> BTreeMap<PathBuf, (Hash, u64, std::time::SystemTime)> {
    let mut result = BTreeMap::new();
    fn visit(path: &Path, result: &mut BTreeMap<PathBuf, (Hash, u64, std::time::SystemTime)>) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            let meta = fs::symlink_metadata(&path).unwrap();
            if meta.is_dir() {
                visit(&path, result);
            } else {
                result.insert(
                    path.clone(),
                    (
                        Hash(Sha256::digest(fs::read(path).unwrap()).into()),
                        meta.len(),
                        meta.modified().unwrap(),
                    ),
                );
            }
        }
    }
    visit(root, &mut result);
    result
}
fn seal(dir: &Path, scope: Scope, records: &[Record]) -> Hash {
    seal_format(dir, scope, records, false).0
}
fn seal_format(
    dir: &Path,
    scope: Scope,
    records: &[Record],
    lossless: bool,
) -> (Hash, crate::history::Reference) {
    assert_eq!(records.len() % crate::history::PAGE_EVENTS, 0);
    let mut head = scope.initial().unwrap();
    for (index, record) in records.iter().enumerate() {
        head = crate::retained_pages::next_head(head, index as u64, record).unwrap();
    }
    let mut previous = None;
    let pages = records
        .chunks(crate::history::PAGE_EVENTS)
        .enumerate()
        .map(|(index, records)| {
            let raw = serde_json::to_vec(&Page {
                format: "RLD-NATIVE-COMPLETE-STREAM-PAGES-V1".into(),
                scope: scope.clone(),
                first: (index * crate::history::PAGE_EVENTS) as u64,
                previous,
                records: records.to_vec(),
            })
            .unwrap();
            previous = Some(Hash(Sha256::digest(&raw).into()));
            Ok(raw)
        })
        .collect::<Vec<_>>();
    let archive = if lossless {
        PackedArchiveCandidate::<Record>::seal_lossless_candidate(dir, scope, head, pages).unwrap()
    } else {
        PackedArchiveCandidate::<Record>::seal(dir, scope, head, pages).unwrap()
    };
    let manifest = archive.manifest_reference_candidate().unwrap();
    drop(archive);
    (head, manifest)
}
fn observe(root: &Path, caller: &Caller) -> Result<ExportArchiveObservationCandidate> {
    inspect_export_archive_candidate(
        &root.join("proof"),
        &caller.bootstrap,
        &public(1),
        caller.bootstrap.currency.id()?,
        caller.byte_head,
        &caller.query,
    )
}
fn check(observed: &ExportArchiveObservationCandidate, caller: &Caller) {
    assert!(observed.complete_genesis_replay);
    assert_eq!(observed.source_height, 80);
    assert_eq!(observed.record_count, 80);
    assert_eq!(observed.source_checkpoint, caller.checkpoint);
    assert_eq!(observed.currency, caller.bootstrap.currency.id().unwrap());
    assert_eq!(observed.export.id, caller.query.export);
    assert_eq!(observed.export.source, caller.query.source);
    assert_eq!(observed.export.destination, caller.query.destination);
    assert_eq!(observed.export.height, 66);
    assert_eq!(observed.export.recipient.owner, public(11));
    assert_eq!(observed.export.recipient.amount, Amount(100));
    assert_eq!(observed.export.destination_fee, Amount(1));
    assert!(
        !observed.remote_current_state_known
            && !observed.incident_safety_qualified
            && !observed.import_authority
            && !observed.recipient_maturity_qualified
            && !observed.owner_signing_authority
    );
}

#[test]
#[ignore = "exact fresh source-archive parent supplies public no-value proof and independently trusted currency/authority"]
fn export_archive_cold_child() {
    let root = PathBuf::from(std::env::var_os("RLD_EXPORT_ARCHIVE_CANDIDATE_CHILD").unwrap());
    let caller: Caller =
        serde_json::from_slice(&fs::read(root.join("receiver-query.json")).unwrap()).unwrap();
    let before = inventory(&root);
    check(&observe(&root, &caller).unwrap(), &caller);
    assert_eq!(inventory(&root), before);
    println!("export-archive fresh-process complete80 Native certificate replay export66 no import/maturity/freshness rights");
}

fn source_fixture(height_limit: u64) -> (Header, Replay, PathBuf, Scope, Vec<Record>, Hash) {
    source_fixture_with_batch(height_limit, 1)
}
// Public fixture construction only. This is not BFT voting/signing custody.
// Native execution still verifies every certificate before retaining its bytes.
pub(super) fn source_fixture_with_batch(
    height_limit: u64,
    batch: usize,
) -> (Header, Replay, PathBuf, Scope, Vec<Record>, Hash) {
    source_fixture_with_profile(height_limit, batch, crate::paged_bft::RULES)
}
pub(super) fn source_fixture_with_profile(
    height_limit: u64,
    batch: usize,
    destination_rules: &str,
) -> (Header, Replay, PathBuf, Scope, Vec<Record>, Hash) {
    assert!((1..=crate::history::PAGE_EVENTS).contains(&batch));
    let started = std::time::Instant::now();
    let mut append_ns = 0u128;
    let mut native_ns = 0u128;
    let mut pending = Vec::new();
    let mut h = header();
    let mut destination = h.bootstrap.admissions[0].clone();
    destination.region = "proxima".into();
    destination.rules = destination_rules.into();
    destination.value_rules = Some(crate::paged_bft::rules_hash_for(destination_rules).unwrap());
    destination.signature = signature(1, &destination.bytes().unwrap());
    let destination_id = destination.id().unwrap();
    h.bootstrap.admissions.push(destination);
    let mut native = replay(&h);
    let (root, mut flat) = stream(&h, &native);
    let scope = h.scope(&native.trust).unwrap();
    let mut records = Vec::new();
    let mut export_id = Hash::ZERO;
    for height in 1..=height_limit {
        let native_started = std::time::Instant::now();
        let commands = if height == 66 {
            let (input, coin) = native
                .chain
                .ledger
                .coins
                .iter()
                .find(|(_, coin)| coin.created == 1 && coin.payment.owner == public(10))
                .unwrap();
            let intent = Intent {
                currency: native.trust.currency().unwrap(),
                region: h.region,
                inputs: vec![*input],
                outputs: vec![Payment {
                    owner: public(10),
                    amount: Amount(coin.payment.amount.0 - 101),
                }],
                fee: Amount(1),
                destination: Some(destination_id),
                remote: Some(Payment {
                    owner: public(11),
                    amount: Amount(100),
                }),
                destination_fee: Amount(1),
                valid_through: 74,
            };
            export_id = intent.id().unwrap();
            let signed = SignedIntent {
                approvals: vec![Approval {
                    key: public(10),
                    signature: signature(10, &intent.bytes().unwrap()),
                }],
                intent,
            };
            vec![Command::Spend(Box::new(signed))]
        } else {
            vec![]
        };
        let record = Record::Certified(Box::new(certified_with_commands(&native, commands)));
        native.apply(&record, &flat).unwrap();
        native_ns += native_started.elapsed().as_nanos();
        assert!(native.evidence.snapshots.len() <= MAX_SNAPSHOTS);
        pending.push(record.clone());
        records.push(record);
        if pending.len() == batch {
            let append_started = std::time::Instant::now();
            flat.append(&pending, flat.storage_head()).unwrap();
            append_ns += append_started.elapsed().as_nanos();
            pending.clear();
        }
    }
    if !pending.is_empty() {
        let append_started = std::time::Instant::now();
        flat.append(&pending, flat.storage_head()).unwrap();
        append_ns += append_started.elapsed().as_nanos();
    }
    assert_eq!(flat.record_count(), height_limit);
    flat.visit(flat.storage_head(), |_| Ok(())).unwrap();
    println!("source_fixture_cost={{\"height\":{height_limit},\"batch\":{batch},\"native_ns\":{native_ns},\"append_ns\":{append_ns},\"total_ns\":{}}}",started.elapsed().as_nanos());
    (h, native, root, scope, records, export_id)
}

#[test]
fn complete_source_archive_beyond64_executes_export66_and_refuses_later_forgery_without_authority()
{
    let started = std::time::Instant::now();
    let (h, native, root, scope, records, export_id) = source_fixture(80);
    let destination_id = native
        .chain
        .ledger
        .exports
        .get(&export_id)
        .unwrap()
        .destination;
    native.chain.ledger.audit().unwrap();
    assert_eq!(native.chain.ledger.exports.len(), 1);
    let head = seal(&root.join("proof"), scope.clone(), &records);
    let caller = Caller {
        bootstrap: h.bootstrap.clone(),
        query: ExportArchiveQueryCandidate {
            source: h.region,
            destination: destination_id,
            export: export_id,
        },
        byte_head: head,
        checkpoint: native.chain.finalized.unwrap(),
    };
    crate::keystore::private_create(
        &root.join("receiver-query.json"),
        &serde_json::to_vec(&caller).unwrap(),
    )
    .unwrap();
    let before = inventory(&root);
    check(&observe(&root, &caller).unwrap(), &caller);
    let output = Process::new(std::env::current_exe().unwrap())
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .args([
            "storage::paged::export_archive_tests::export_archive_cold_child",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("RLD_EXPORT_ARCHIVE_CANDIDATE_CHILD", &root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(inventory(&root), before);
    let mut wrong = caller.query.clone();
    wrong.destination = h.region;
    assert!(inspect_export_archive_candidate(
        &root.join("proof"),
        &caller.bootstrap,
        &public(1),
        caller.bootstrap.currency.id().unwrap(),
        head,
        &wrong
    )
    .is_err());
    wrong = caller.query.clone();
    wrong.export = Hash([9; 32]);
    assert!(inspect_export_archive_candidate(
        &root.join("proof"),
        &caller.bootstrap,
        &public(1),
        caller.bootstrap.currency.id().unwrap(),
        head,
        &wrong
    )
    .is_err());
    assert!(inspect_export_archive_candidate(
        &root.join("proof"),
        &caller.bootstrap,
        &public(2),
        caller.bootstrap.currency.id().unwrap(),
        head,
        &caller.query
    )
    .is_err());
    assert!(inspect_export_archive_candidate(
        &root.join("proof"),
        &caller.bootstrap,
        &public(1),
        Hash([9; 32]),
        head,
        &caller.query
    )
    .is_err());
    assert_eq!(inventory(&root), before);
    let mut bad = records.clone();
    let Record::Certified(last) = bad.last_mut().unwrap() else {
        unreachable!()
    };
    last.bft.as_mut().unwrap().committed.votes[0]
        .approval
        .signature = "00".repeat(64);
    let bad_head = seal(&root.join("bad-late-signature"), scope.clone(), &bad);
    let before = inventory(&root);
    let error = inspect_export_archive_candidate(
        &root.join("bad-late-signature"),
        &caller.bootstrap,
        &public(1),
        caller.bootstrap.currency.id().unwrap(),
        bad_head,
        &caller.query,
    )
    .unwrap_err();
    assert!(error.contains("signature"), "{error}");
    assert_eq!(inventory(&root), before);
    let lossless_dir = root.join("lossless-proof");
    let (lossless_head, lossless_manifest) =
        seal_format(&lossless_dir, scope.clone(), &records, true);
    assert_eq!(lossless_head, head);
    let (lossless_bad_head, lossless_bad_manifest) =
        seal_format(&root.join("lossless-bad-late"), scope.clone(), &bad, true);
    let before_lossless = inventory(&root);
    check(
        &inspect_lossless_export_archive_candidate(
            &lossless_dir,
            &caller.bootstrap,
            &public(1),
            caller.bootstrap.currency.id().unwrap(),
            lossless_head,
            &lossless_manifest,
            &caller.query,
        )
        .unwrap(),
        &caller,
    );
    assert!(inspect_export_archive_candidate(
        &lossless_dir,
        &caller.bootstrap,
        &public(1),
        caller.bootstrap.currency.id().unwrap(),
        head,
        &caller.query,
    )
    .is_err());
    let mut wrong_manifest = lossless_manifest.clone();
    wrong_manifest.hash = Hash([9; 32]);
    assert!(inspect_lossless_export_archive_candidate(
        &lossless_dir,
        &caller.bootstrap,
        &public(1),
        caller.bootstrap.currency.id().unwrap(),
        head,
        &wrong_manifest,
        &caller.query,
    )
    .is_err());
    let error = inspect_lossless_export_archive_candidate(
        &root.join("lossless-bad-late"),
        &caller.bootstrap,
        &public(1),
        caller.bootstrap.currency.id().unwrap(),
        lossless_bad_head,
        &lossless_bad_manifest,
        &caller.query,
    )
    .unwrap_err();
    assert!(error.contains("signature"), "{error}");
    assert_eq!(inventory(&root), before_lossless);
    let incomplete_head = seal(&root.join("missing-genesis-prefix"), scope, &records[16..]);
    let before = inventory(&root);
    assert!(inspect_export_archive_candidate(
        &root.join("missing-genesis-prefix"),
        &caller.bootstrap,
        &public(1),
        caller.bootstrap.currency.id().unwrap(),
        incomplete_head,
        &caller.query
    )
    .is_err());
    assert_eq!(inventory(&root), before);
    let mut actual_cli_executed = false;
    if let Some(binary) = std::env::var_os("RLD_EXPORT_ARCHIVE_CANDIDATE_CLI") {
        crate::keystore::private_create(
            &root.join("trusted-bootstrap.json"),
            &serde_json::to_vec(&caller.bootstrap).unwrap(),
        )
        .unwrap();
        crate::keystore::private_create(
            &root.join("exact-query.json"),
            &serde_json::to_vec(&caller.query).unwrap(),
        )
        .unwrap();
        let before_cli = inventory(&root);
        let launch = |archive: &Path, byte_head: Hash| {
            Process::new(&binary)
                .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
                .args([
                    "--dir",
                    archive.to_str().unwrap(),
                    "--authority",
                    &public(1),
                    "--currency",
                    &caller.bootstrap.currency.id().unwrap().to_hex(),
                    "export-archive-inspect",
                    "--bootstrap",
                    root.join("trusted-bootstrap.json").to_str().unwrap(),
                    "--query",
                    root.join("exact-query.json").to_str().unwrap(),
                    "--carried-head",
                    &byte_head.to_hex(),
                ])
                .output()
                .unwrap()
        };
        let result = launch(&root.join("proof"), head);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(
            value["export"]["id"],
            serde_json::to_value(export_id).unwrap()
        );
        assert_eq!(value["source_height"], 80);
        assert_eq!(value["complete_genesis_replay"], true);
        for name in [
            "import_authority",
            "recipient_maturity_qualified",
            "incident_safety_qualified",
            "remote_current_state_known",
            "owner_signing_authority",
        ] {
            assert_eq!(value[name], false);
        }
        assert_eq!(inventory(&root), before_cli);
        let denied = launch(&root.join("bad-late-signature"), bad_head);
        assert!(!denied.status.success());
        assert!(
            denied.stdout.is_empty(),
            "bad late certificate released partial success"
        );
        assert_eq!(inventory(&root), before_cli);
        let launch_lossless =
            |archive: &Path, byte_head: Hash, manifest: &crate::history::Reference| {
                Process::new(&binary)
                    .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
                    .args([
                        "--dir",
                        archive.to_str().unwrap(),
                        "--authority",
                        &public(1),
                        "--currency",
                        &caller.bootstrap.currency.id().unwrap().to_hex(),
                        "export-archive-inspect",
                        "--bootstrap",
                        root.join("trusted-bootstrap.json").to_str().unwrap(),
                        "--query",
                        root.join("exact-query.json").to_str().unwrap(),
                        "--carried-head",
                        &byte_head.to_hex(),
                        "--carried-manifest",
                        &manifest.hash.to_hex(),
                        "--carried-manifest-bytes",
                        &manifest.bytes.to_string(),
                    ])
                    .output()
                    .unwrap()
            };
        let result = launch_lossless(&lossless_dir, head, &lossless_manifest);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(value["source_height"], 80);
        assert_eq!(value["record_count"], 80);
        assert_eq!(
            value["export"]["id"],
            serde_json::to_value(export_id).unwrap()
        );
        for name in [
            "import_authority",
            "recipient_maturity_qualified",
            "incident_safety_qualified",
            "remote_current_state_known",
            "owner_signing_authority",
        ] {
            assert_eq!(value[name], false);
        }
        let denied = launch_lossless(
            &root.join("lossless-bad-late"),
            lossless_bad_head,
            &lossless_bad_manifest,
        );
        assert!(!denied.status.success());
        assert!(
            denied.stdout.is_empty(),
            "lossless late forgery released partial success"
        );
        let denied = launch_lossless(&lossless_dir, head, &wrong_manifest);
        assert!(!denied.status.success());
        assert!(denied.stdout.is_empty());
        assert_eq!(inventory(&root), before_cli);
        println!("lossless_actual_cli_executed=true complete80/export66 compressed format no import or latest-state rights");
        actual_cli_executed = true;
    }
    // The original single-envelope proof bound is still enforced. This archive
    // observation is not accepted by the existing contact/import path.
    let evidence = Evidence {
        snapshots: records
            .iter()
            .map(|record| {
                let Record::Certified(snapshot) = record else {
                    unreachable!()
                };
                *snapshot.clone()
            })
            .collect(),
    };
    assert!(VerifiedEvidence::verify(&evidence, &native.trust).is_err());
    println!("export-archive complete source80/export66, full signatures/owner execution, active64, later-bad-signature/missing-prefix/wrong-route/root refusals, separate fresh-process cold, private bytes unchanged, ordinary import/maturity unqualified; actual_cli_executed={actual_cli_executed} elapsed={:.3}", started.elapsed().as_secs_f64());
}

#[test]
fn complete_source416_original_pack_exceeds_single_payload_without_raising_native_bounds() {
    let (h, native, root, scope, records, export_id) =
        source_fixture_with_batch(416, crate::history::PAGE_EVENTS);
    assert_eq!(native.chain.height(), 416);
    assert_eq!(records.len(), 416);
    assert!(native.evidence.snapshots.len() <= MAX_SNAPSHOTS);
    native.chain.ledger.audit().unwrap();
    let head = seal(&root.join("proof416"), scope, &records);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("proof416/packed.json")).unwrap()).unwrap();
    let refs: Vec<crate::history::Reference> =
        serde_json::from_value(manifest["packs"].clone()).unwrap();
    assert!(
        refs.iter().any(|object| object.bytes > 3 * 1024 * 1024),
        "fixture did not discriminate original payload bound"
    );
    assert!(refs.iter().all(|object| object.bytes <= MAX_BYTES));
    let destination = native
        .chain
        .ledger
        .exports
        .get(&export_id)
        .unwrap()
        .destination;
    let query = ExportArchiveQueryCandidate {
        source: h.region,
        destination,
        export: export_id,
    };
    for (leaf, raw) in [
        (
            "trusted-bootstrap416.json",
            serde_json::to_vec(&h.bootstrap).unwrap(),
        ),
        ("exact-query416.json", serde_json::to_vec(&query).unwrap()),
        ("byte-head416.json", serde_json::to_vec(&head).unwrap()),
    ] {
        crate::keystore::private_create(&root.join(leaf), &raw).unwrap();
    }
    println!("source416 complete original certificates and export66 generated, active64/object8MiB unchanged; receiver cold verification still required");
}

#[test]
fn public_fixture_complete16_batch_keeps_identical_native32_records_pages_and_cold_state() {
    let (left_header, left, left_root, left_scope, left_records, _) =
        source_fixture_with_batch(32, 1);
    let (right_header, right, right_root, right_scope, right_records, _) =
        source_fixture_with_batch(32, crate::history::PAGE_EVENTS);
    assert_eq!(
        serde_json::to_vec(&left_header.bootstrap).unwrap(),
        serde_json::to_vec(&right_header.bootstrap).unwrap()
    );
    assert_eq!(left_scope, right_scope);
    assert_eq!(
        serde_json::to_vec(&left_records).unwrap(),
        serde_json::to_vec(&right_records).unwrap()
    );
    assert_eq!(
        left.chain.ledger.root().unwrap(),
        right.chain.ledger.root().unwrap()
    );
    assert_eq!(left.chain.finalized, right.chain.finalized);
    let left_head = seal(&left_root.join("proof"), left_scope, &left_records);
    let right_head = seal(&right_root.join("proof"), right_scope, &right_records);
    assert_eq!(left_head, right_head);
    assert_eq!(
        fs::read(left_root.join("proof/packed.json")).unwrap(),
        fs::read(right_root.join("proof/packed.json")).unwrap()
    );
    let before_left = inventory(&left_root);
    let before_right = inventory(&right_root);
    let boundary = PackedNativeBoundaryCandidate {
        currency: left.trust.currency().unwrap(),
        region: left.chain.region,
        height: 32,
        finalized: left.chain.finalized,
        epoch: left.chain.epoch,
        ledger_root: left.chain.ledger.root().unwrap(),
        record_count: 32,
    };
    for (root, header, head) in [
        (&left_root, &left_header, left_head),
        (&right_root, &right_header, right_head),
    ] {
        assert_eq!(
            inspect_packed_native_candidate(
                &root.join("proof"),
                &header.bootstrap,
                &public(1),
                boundary.currency,
                head,
                &boundary
            )
            .unwrap(),
            boundary
        );
    }
    assert_eq!(inventory(&left_root), before_left);
    assert_eq!(inventory(&right_root), before_right);
    println!("public fixture construction comparison only: identical complete32 certificates, packed manifest and Native cold state; no original Agent signing custody or transport qualification");
}
