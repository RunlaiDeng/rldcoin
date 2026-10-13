//! Fixed-head process boundary only; explicit CLI carriage is not ordinary networking.
use super::body_witness_tests::{certified, certified_with_commands};
use super::export_archive_tests::{inventory, source_fixture_with_regions};
use super::*;
use crate::tests::{public, signature};
use std::{
    process::{Command as Process, Output},
    time::Instant,
};

fn phase(started: &Instant, name: &str) {
    eprintln!(
        "onward_cli_phase={}",
        serde_json::json!({"phase":name,"elapsed_seconds":started.elapsed().as_secs_f64()})
    );
}
fn invoke(binary: &Path, dir: &Path, currency: Hash, args: &[&str]) -> Output {
    Process::new(binary)
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .args([
            "--dir",
            dir.to_str().unwrap(),
            "--authority",
            &public(1),
            "--currency",
            &currency.to_hex(),
        ])
        .args(args)
        .output()
        .unwrap()
}
fn success(output: Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
fn refusal(binary: &Path, root: &Path, dir: &Path, currency: Hash, args: &[&str]) -> String {
    let before = inventory(root);
    let output = invoke(binary, dir, currency, args);
    assert!(
        !output.status.success(),
        "refused operation succeeded: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        output.stdout.is_empty(),
        "refusal released a partial success response"
    );
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(!error.trim().is_empty());
    assert_eq!(inventory(root), before);
    eprintln!(
        "onward_cli_refusal={}",
        serde_json::json!({"action":args[0],"error":error})
    );
    error
}
fn local_payment(region: Hash, currency: Hash, input: Hash) -> Command {
    let intent = Intent {
        currency,
        region,
        inputs: vec![input],
        outputs: vec![Payment {
            owner: public(13),
            amount: Amount(88),
        }],
        fee: Amount(1),
        destination: None,
        remote: None,
        destination_fee: Amount::ZERO,
        valid_through: 16,
    };
    let approval = Approval {
        key: public(12),
        signature: signature(12, &intent.bytes().unwrap()),
    };
    Command::Spend(Box::new(SignedIntent {
        intent,
        approvals: vec![approval],
    }))
}

#[test]
#[ignore = "fresh exact pinned native CLI export, acceptance and pending import process round-trip"]
fn complete_onward_cli_fixed_head_process_boundary() {
    // The parent binds this exact executable; no guessed target path or skipped CLI.
    let binary = PathBuf::from(
        std::env::var_os("RLD_ONWARD_HISTORY_CLI").expect("source-bound CLI path required"),
    );
    assert!(binary.is_absolute());
    let started = Instant::now();
    phase(&started, "native-source-and-reexport-begin");
    let (h, source, root, _, records, origin_export) = source_fixture_with_regions(
        80,
        16,
        crate::paged_bft::ORIGIN_HISTORY_RULES,
        "earth",
        &[("andromeda", crate::paged_bft::ONWARD_HISTORY_RULES)],
    );
    let pin = source.trust.currency().unwrap();
    let b = source.trust.named("proxima").unwrap();
    let c = source.trust.named("andromeda").unwrap();
    let origin = CompleteOriginHistory {
        source: h.region,
        destination: b,
        export: origin_export,
        snapshots: records
            .iter()
            .map(|record| match record {
                Record::Certified(s) => *s.clone(),
                _ => panic!("source certificate"),
            })
            .collect(),
    };
    let a80 = origin.snapshots[79].statement.id().unwrap();
    let b_dir = root.join("intermediate");
    let c_dir = root.join("destination");
    let mut intermediate = Store::create(&b_dir, h.bootstrap.clone(), b, &public(1), pin).unwrap();
    intermediate.accept_complete_origin_history(origin).unwrap();
    let snapshot = certified_with_commands(
        &intermediate.paged_replay.as_ref().unwrap().replay,
        vec![Command::Import {
            snapshot: a80,
            export: origin_export,
        }],
    );
    intermediate.finalize(snapshot).unwrap();
    let snapshot = certified(&intermediate.paged_replay.as_ref().unwrap().replay);
    intermediate.finalize(snapshot).unwrap();
    let input = id("output", &(origin_export, 0u32)).unwrap();
    let intent = Intent {
        currency: pin,
        region: b,
        inputs: vec![input],
        outputs: vec![Payment {
            owner: public(11),
            amount: Amount(8),
        }],
        fee: Amount(1),
        destination: Some(c),
        remote: Some(Payment {
            owner: public(12),
            amount: Amount(90),
        }),
        destination_fee: Amount(1),
        valid_through: 16,
    };
    let onward_export = intent.id().unwrap();
    let approval = Approval {
        key: public(11),
        signature: signature(11, &intent.bytes().unwrap()),
    };
    let snapshot = certified_with_commands(
        &intermediate.paged_replay.as_ref().unwrap().replay,
        vec![Command::Spend(Box::new(SignedIntent {
            intent,
            approvals: vec![approval],
        }))],
    );
    let b3 = intermediate.finalize(snapshot).unwrap();
    assert_eq!(intermediate.chain.height(), 3);
    assert_eq!(
        intermediate.chain.ledger.imports.get(&origin_export),
        Some(&a80)
    );
    assert_eq!(
        intermediate.chain.ledger.exports[&onward_export].dependencies,
        BTreeSet::from([a80])
    );
    assert!(!intermediate.chain.ledger.coins.contains_key(&input));
    let library_proof = intermediate.complete_onward_export(onward_export).unwrap();
    let b_head = intermediate.storage_head().unwrap();
    let b_chain = intermediate.chain.clone();
    drop(intermediate); // Release the actual Native OS lock before child processes.
    let destination = Store::create(&c_dir, h.bootstrap.clone(), c, &public(1), pin).unwrap();
    let c_empty_head = destination.storage_head().unwrap();
    let c_empty_root = destination.chain.ledger.root().unwrap();
    assert_eq!(destination.paged.as_ref().unwrap().record_count(), 0);
    drop(destination);
    phase(&started, "native-source-and-reexport-end");

    phase(&started, "cli-export-and-refusals-begin");
    let before = inventory(&root);
    let export_json = success(invoke(
        &binary,
        &b_dir,
        pin,
        &[
            "complete-onward-history-export",
            "--export",
            &onward_export.to_hex(),
            "--expected-head",
            &b_head.to_hex(),
        ],
    ));
    let proof: CompleteOnwardHistory = serde_json::from_value(export_json.clone()).unwrap();
    assert_eq!(proof, library_proof);
    assert_eq!(export_json, serde_json::to_value(&library_proof).unwrap());
    assert_eq!(inventory(&root), before);
    let proof_file = root.join("cli-onward-proof.json");
    crate::keystore::private_create(&proof_file, &serde_json::to_vec(&proof).unwrap()).unwrap();
    let proof_path = proof_file.to_str().unwrap();
    let wrong = Hash([9; 32]).to_hex();
    let wrong_export_head = refusal(
        &binary,
        &root,
        &b_dir,
        pin,
        &[
            "complete-onward-history-export",
            "--export",
            &onward_export.to_hex(),
            "--expected-head",
            &wrong,
        ],
    );
    let wrong_accept_head = refusal(
        &binary,
        &root,
        &c_dir,
        pin,
        &[
            "complete-onward-history-accept",
            "--file",
            proof_path,
            "--expected-head",
            &wrong,
        ],
    );
    let wrong_pending_head = refusal(
        &binary,
        &root,
        &c_dir,
        pin,
        &["complete-onward-history-pending", "--expected-head", &wrong],
    );
    let wrong_currency = refusal(
        &binary,
        &root,
        &c_dir,
        Hash([9; 32]),
        &[
            "complete-onward-history-accept",
            "--file",
            proof_path,
            "--expected-head",
            &c_empty_head.to_hex(),
        ],
    );
    for error in [&wrong_export_head, &wrong_accept_head, &wrong_pending_head] {
        assert!(
            error.contains("complete stream exact latest head/count"),
            "{error}"
        );
    }
    assert!(
        wrong_currency.contains("untrusted currency or non-fixture profile"),
        "{wrong_currency}"
    );
    let missing_pin = refusal(
        &binary,
        &root,
        &c_dir,
        pin,
        &["complete-onward-history-pending"],
    );
    assert!(missing_pin.contains("--expected-head"), "{missing_pin}");
    let canonical = serde_json::to_string(&proof).unwrap();
    for (name, raw, expected) in [
        (
            "duplicate-field",
            format!(
                "{{\"source\":{},{}",
                serde_json::to_string(&proof.source).unwrap(),
                &canonical[1..]
            ),
            "duplicate field",
        ),
        (
            "unknown-field",
            format!("{{\"unexpected\":true,{}", &canonical[1..]),
            "unknown field",
        ),
    ] {
        let file = root.join(format!("{name}.json"));
        crate::keystore::private_create(&file, raw.as_bytes()).unwrap();
        let error = refusal(
            &binary,
            &root,
            &c_dir,
            pin,
            &[
                "complete-onward-history-accept",
                "--file",
                file.to_str().unwrap(),
                "--expected-head",
                &c_empty_head.to_hex(),
            ],
        );
        assert!(error.contains(expected), "{name}: {error}");
    }
    for (name, mut bad) in [("bad-a-tail", proof.clone()), ("bad-b-tail", proof.clone())] {
        let last = if name == "bad-a-tail" {
            bad.origin.snapshots.last_mut().unwrap()
        } else {
            bad.snapshots.last_mut().unwrap()
        };
        last.bft.as_mut().unwrap().committed.votes[0]
            .approval
            .signature = "00".repeat(64);
        let file = root.join(format!("{name}.json"));
        crate::keystore::private_create(&file, &serde_json::to_vec(&bad).unwrap()).unwrap();
        let error = refusal(
            &binary,
            &root,
            &c_dir,
            pin,
            &[
                "complete-onward-history-accept",
                "--file",
                file.to_str().unwrap(),
                "--expected-head",
                &c_empty_head.to_hex(),
            ],
        );
        assert!(error.contains("signature"), "{error}");
    }
    let before = inventory(&root);
    assert_eq!(
        success(invoke(
            &binary,
            &c_dir,
            pin,
            &[
                "complete-onward-history-pending",
                "--expected-head",
                &c_empty_head.to_hex()
            ]
        )),
        serde_json::json!([])
    );
    assert_eq!(inventory(&root), before);
    phase(&started, "cli-export-and-refusals-end");

    phase(&started, "cli-accept-and-pending-begin");
    // Derive the precise expected event head independently from the CLI response.
    let evidence_head = crate::retained_pages::next_head(
        c_empty_head,
        0,
        &Record::OnwardHistory(Box::new(proof.clone())),
    )
    .unwrap();
    let expected_accept = serde_json::json!({"source_checkpoint":b3,"storage_head":evidence_head,
        "verified":true,"ledger_changed":false,"import_accepted":false,
        "recipient_maturity_qualified":false,"owner_signing_authority":false,
        "remote_current_state_known":false,"fixture_only":true});
    let source_bytes = inventory(&root)
        .into_iter()
        .filter(|(path, _)| !path.starts_with(&c_dir))
        .collect::<BTreeMap<_, _>>();
    let accepted = success(invoke(
        &binary,
        &c_dir,
        pin,
        &[
            "complete-onward-history-accept",
            "--file",
            proof_path,
            "--expected-head",
            &c_empty_head.to_hex(),
        ],
    ));
    assert_eq!(accepted, expected_accept);
    assert_eq!(
        inventory(&root)
            .into_iter()
            .filter(|(path, _)| !path.starts_with(&c_dir))
            .collect::<BTreeMap<_, _>>(),
        source_bytes
    );
    let before = inventory(&root);
    assert_eq!(
        success(invoke(
            &binary,
            &c_dir,
            pin,
            &[
                "complete-onward-history-accept",
                "--file",
                proof_path,
                "--expected-head",
                &evidence_head.to_hex()
            ]
        )),
        expected_accept
    );
    assert_eq!(inventory(&root), before);
    let stale_accept = refusal(
        &binary,
        &root,
        &c_dir,
        pin,
        &[
            "complete-onward-history-accept",
            "--file",
            proof_path,
            "--expected-head",
            &c_empty_head.to_hex(),
        ],
    );
    assert!(
        stale_accept.contains("complete stream exact latest head/count"),
        "{stale_accept}"
    );
    let before = inventory(&root);
    let pending_json = success(invoke(
        &binary,
        &c_dir,
        pin,
        &[
            "complete-onward-history-pending",
            "--expected-head",
            &evidence_head.to_hex(),
        ],
    ));
    let pending: Vec<Command> = serde_json::from_value(pending_json.clone()).unwrap();
    assert_eq!(
        pending,
        vec![Command::Import {
            snapshot: b3,
            export: onward_export
        }]
    );
    assert_eq!(pending_json, serde_json::to_value(&pending).unwrap());
    assert_eq!(inventory(&root), before);
    let mut destination = Store::open_pinned(&c_dir, &public(1), pin, evidence_head).unwrap();
    assert_eq!(
        (destination.chain.height(), destination.chain.finalized),
        (0, None)
    );
    assert_eq!(destination.chain.ledger.root().unwrap(), c_empty_root);
    assert!(
        destination.chain.ledger.coins.is_empty() && destination.chain.ledger.imports.is_empty()
    );
    assert_eq!(destination.paged.as_ref().unwrap().record_count(), 1);
    assert_eq!(
        destination.complete_onward_pending_imports().unwrap(),
        pending
    );
    for anchor in [a80, b3] {
        destination.evidence.snapshot(anchor).unwrap();
    }
    assert_eq!(inventory(&root), before);
    phase(&started, "cli-accept-and-pending-end");

    phase(&started, "native-recipient-import-and-payment-begin");
    let snapshot =
        certified_with_commands(&destination.paged_replay.as_ref().unwrap().replay, pending);
    destination.finalize(snapshot).unwrap();
    let imported = id("output", &(onward_export, 0u32)).unwrap();
    assert_eq!(
        destination.chain.ledger.coins[&imported].payment,
        Payment {
            owner: public(12),
            amount: Amount(89)
        }
    );
    assert_eq!(
        (
            destination.chain.height(),
            destination.chain.ledger.coins[&imported].mature
        ),
        (1, 3)
    );
    assert_eq!(
        destination.chain.ledger.coins[&imported].dependencies,
        BTreeSet::from([a80, b3])
    );
    let payment = local_payment(c, pin, imported);
    let Command::Spend(signed) = &payment else {
        unreachable!()
    };
    let payment_id = signed.intent.id().unwrap();
    let snapshot = certified(&destination.paged_replay.as_ref().unwrap().replay);
    destination.finalize(snapshot).unwrap();
    let snapshot = certified_with_commands(
        &destination.paged_replay.as_ref().unwrap().replay,
        vec![payment],
    );
    let final_statement = snapshot.statement.clone();
    let finality = destination.finalize(snapshot).unwrap();
    let final_head = destination.storage_head().unwrap();
    assert_eq!(destination.chain.height(), 3);
    assert_eq!(
        destination.chain.ledger.imports,
        BTreeMap::from([(onward_export, b3)])
    );
    assert!(!destination.chain.ledger.coins.contains_key(&imported));
    let paid = &destination.chain.ledger.coins[&id("output", &(payment_id, 0u32)).unwrap()];
    assert_eq!(
        paid.payment,
        Payment {
            owner: public(13),
            amount: Amount(88)
        }
    );
    assert_eq!(paid.dependencies, BTreeSet::from([a80, b3]));
    let totals = conservation_with_escrow(&[
        source.chain.clone(),
        b_chain.clone(),
        destination.chain.clone(),
    ])
    .unwrap();
    assert_eq!(
        totals,
        (
            Amount(rld_pow::cumulative_emission(80)),
            Amount(rld_pow::cumulative_emission(80)),
            Amount::ZERO,
            Amount::ZERO
        )
    );
    let import_commitment =
        id("native-history-imports", &destination.chain.ledger.imports).unwrap();
    drop(destination);
    phase(&started, "native-recipient-import-and-payment-end");

    phase(&started, "cold-cli-state-begin");
    let before = inventory(&root);
    assert_eq!(
        success(invoke(
            &binary,
            &c_dir,
            pin,
            &[
                "complete-onward-history-pending",
                "--expected-head",
                &final_head.to_hex()
            ]
        )),
        serde_json::json!([])
    );
    let cold = success(invoke(
        &binary,
        &c_dir,
        pin,
        &["history-check", "--expected-head", &final_head.to_hex()],
    ));
    for (key, wanted) in [
        ("history_head", serde_json::json!(final_head)),
        ("currency", serde_json::json!(pin)),
        ("region", serde_json::json!(c)),
        ("height", serde_json::json!(3)),
        ("tip", serde_json::json!(final_statement.block)),
        ("state", serde_json::json!(final_statement.state)),
        ("finality", serde_json::json!(finality)),
        ("validator_epoch", serde_json::json!(final_statement.epoch)),
        ("permanent_import_entries", serde_json::json!(1)),
        ("import_commitment", serde_json::json!(import_commitment)),
        ("logical_native_replay_complete", serde_json::json!(true)),
    ] {
        assert_eq!(cold[key], wanted, "{key}");
    }
    assert_eq!(final_statement.id().unwrap(), finality);
    assert_eq!(cold["independent_latest_state_anchor_qualified"], false);
    assert_eq!(inventory(&root), before);
    assert_eq!(
        inventory(&root)
            .into_iter()
            .filter(|(path, _)| !path.starts_with(&c_dir))
            .collect::<BTreeMap<_, _>>(),
        source_bytes
    );
    phase(&started, "cold-cli-state-end");
    println!(
        "onward_cli_result={}",
        serde_json::json!({"fixture_root":root,"source_height":80,
        "intermediate_height":3,"recipient_height":3,"source_export":origin_export,"onward_export":onward_export,
        "recipient_payment":payment_id,"accept":accepted,"pending":pending_json,"cold":cold,"totals":totals,
        "refusals":{"export_head":wrong_export_head,"accept_head":wrong_accept_head,"pending_head":wrong_pending_head,
            "currency":wrong_currency,"stale_after_accept":stale_accept},
        "elapsed_seconds":started.elapsed().as_secs_f64(),"actual_cli_executed":true,
        "ordinary_network_qualified":false,"independent_custody_qualified":false,"mainnet_qualified":false})
    );
}
