//! Fresh exact origin/receiver profiles; observations never initialize authority.
use super::body_witness_tests::{certified_with_commands, replay};
use super::export_archive_tests::{inventory, seal_format, source_fixture_with_profile};
use super::*;
use crate::tests::{public, signature};
use std::{process::Command as Process, time::Instant};

fn phase(at: &Instant, name: &str, event: &str) {
    eprintln!(
        "origin_archive_cut_phase={}",
        serde_json::json!({
            "phase": name, "event": event, "elapsed_seconds": at.elapsed().as_secs_f64(),
        })
    );
}

fn local_spend(r: &Replay, input: Hash, owner: u8, recipient: u8, amount: Amount) -> Command {
    let intent = Intent {
        currency: r.trust.currency().unwrap(),
        region: r.chain.region,
        inputs: vec![input],
        outputs: vec![Payment {
            owner: public(recipient),
            amount,
        }],
        fee: Amount(1),
        destination: None,
        remote: None,
        destination_fee: Amount::ZERO,
        valid_through: r.chain.height() + 8,
    };
    let approval = Approval {
        key: public(owner),
        signature: signature(owner, &intent.bytes().unwrap()),
    };
    Command::Spend(Box::new(SignedIntent {
        intent,
        approvals: vec![approval],
    }))
}

#[test]
#[ignore = "fresh two-region Native archive cut with spent-import closure and complete-tail authentication"]
fn origin_archive_cut_authenticates_spent_import_closure_and_all_tails() {
    let at = Instant::now();
    phase(&at, "source-construction", "begin");
    let (h, source, root, source_scope, source_records, export) =
        source_fixture_with_profile(80, 16, crate::paged_bft::ORIGIN_HISTORY_RULES);
    assert_eq!(h.bootstrap.admissions.len(), 2);
    assert_eq!(
        source.trust.region(h.region).unwrap().rules,
        crate::paged_bft::RULES
    );
    let destination_id = source.trust.named("proxima").unwrap();
    assert_eq!(
        source.trust.region(destination_id).unwrap().rules,
        crate::paged_bft::ORIGIN_HISTORY_RULES
    );
    let pin = source.trust.currency().unwrap();
    let authority = public(1);
    eprintln!(
        "origin_archive_cut_fixture={}",
        serde_json::json!({"root": root, "currency": pin})
    );
    let snapshots = source_records
        .iter()
        .map(|r| {
            let Record::Certified(s) = r else {
                panic!("source must be certified")
            };
            s.as_ref().clone()
        })
        .collect::<Vec<_>>();
    let source78_id = snapshots[77].statement.id().unwrap();
    let source79_id = snapshots[78].statement.id().unwrap();
    let source80_id = snapshots[79].statement.id().unwrap();
    let proof = CompleteOriginHistory {
        source: h.region,
        destination: destination_id,
        export,
        snapshots: snapshots[..79].to_vec(),
    };
    proof.shape(destination_id, &source.trust).unwrap();
    assert!(encode("complete-origin-history-v1", &proof).unwrap().len() <= MAX_BYTES);
    assert_eq!(source.chain.ledger.exports.len(), 1);
    assert_eq!(source.chain.ledger.exports[&export].height, 66);
    assert_eq!(
        source.chain.ledger.exports[&export].recipient.amount,
        Amount(100)
    );
    assert_eq!(
        source.chain.ledger.exports[&export].destination_fee,
        Amount(1)
    );
    phase(&at, "source-construction", "end");

    // Actual fresh Native execution supplies selected Chains and the fork base.
    // The helper's retained bytes are history, never a Ledger initializer.
    phase(&at, "source-selection-replay", "begin");
    let mut selected_source = replay(&h);
    let history = super::origin_history::test_history(&h, &selected_source, &source_records);
    for record in &source_records[..78] {
        selected_source.apply_retained(record, &history).unwrap();
    }
    let source78 = selected_source.chain.clone();
    let mut fork = selected_source.clone();
    selected_source
        .apply_retained(&source_records[78], &history)
        .unwrap();
    let source79 = selected_source.chain.clone();
    assert_eq!(source78.finalized, Some(source78_id));
    assert_eq!(source79.finalized, Some(source79_id));
    assert_eq!(
        source78.ledger.exports[&export],
        source79.ledger.exports[&export]
    );
    assert_eq!(
        source79.ledger.exports[&export],
        source.chain.ledger.exports[&export]
    );
    assert_ne!(source78.ledger.minted, source79.ledger.minted);
    phase(&at, "source-selection-replay", "end");

    phase(&at, "destination-construction", "begin");
    let dh = Header {
        format: FORMAT.into(),
        bootstrap: h.bootstrap.clone(),
        region: destination_id,
    };
    let mut destination = replay(&dh);
    let destination_scope = dh.scope(&destination.trust).unwrap();
    let mut flat =
        Stream::<Record>::create(&root.join("destination-events"), destination_scope.clone())
            .unwrap();
    let origin = Record::OriginHistory(Box::new(proof));
    destination.apply_retained(&origin, &flat).unwrap();
    flat.append(std::slice::from_ref(&origin), flat.storage_head())
        .unwrap();
    assert_eq!(destination.chain.height(), 0);
    assert!(
        destination.chain.ledger.coins.is_empty() && destination.chain.ledger.imports.is_empty()
    );
    let mut destination_records = vec![origin];
    let mut local = Vec::new();
    let imported = id("output", &(export, 0u32)).unwrap();
    let mut destination3 = None;
    let mut spend_id = Hash::ZERO;
    for height in 1..=15 {
        let commands = match height {
            1 => vec![Command::Import {
                snapshot: source79_id,
                export,
            }],
            3 => {
                let command = local_spend(&destination, imported, 11, 12, Amount(98));
                let Command::Spend(signed) = &command else {
                    unreachable!()
                };
                spend_id = signed.intent.id().unwrap();
                vec![command]
            }
            _ => vec![],
        };
        let record = Record::Certified(Box::new(certified_with_commands(&destination, commands)));
        destination.apply_retained(&record, &flat).unwrap();
        assert_eq!(destination.chain.height(), height);
        assert_eq!(
            destination.chain.ledger.imports.get(&export),
            Some(&source79_id)
        );
        assert!(destination.chain.ledger.exports.is_empty());
        if height == 1 {
            assert_eq!(
                destination.chain.ledger.coins[&imported].payment,
                Payment {
                    owner: public(11),
                    amount: Amount(99)
                }
            );
            assert_eq!(destination.chain.ledger.coins[&imported].mature, 3);
        }
        if height == 3 {
            assert!(!destination.chain.ledger.coins.contains_key(&imported));
            assert_eq!(
                destination.chain.ledger.coins[&id("output", &(spend_id, 0u32)).unwrap()].payment,
                Payment {
                    owner: public(12),
                    amount: Amount(98)
                }
            );
            destination3 = Some(destination.chain.clone());
        }
        local.push(record.clone());
        destination_records.push(record);
    }
    flat.append(&local, flat.storage_head()).unwrap();
    assert_eq!((destination_records.len(), flat.record_count()), (16, 16));
    destination
        .executed
        .require_boundary(&destination_scope, 16, flat.storage_head())
        .unwrap();
    let destination3 = destination3.unwrap();
    let destination3_id = destination3.finalized.unwrap();
    let destination15_id = destination.chain.finalized.unwrap();
    assert_eq!(destination3.height(), 3);
    assert!(!destination.chain.ledger.coins.contains_key(&imported));
    assert_eq!(destination.chain.ledger.imports.len(), 1);
    let before = inventory(&root);
    let original_ledger = destination.chain.ledger.clone();
    let original_head = flat.storage_head();
    let original_finality = destination.chain.finalized;
    let mut staged = destination.chain.clone();
    crate::paged_bft::prepare_parent(&mut staged, &destination.evidence).unwrap();
    let tombstone_error = staged
        .template(
            vec![Command::Import {
                snapshot: source79_id,
                export,
            }],
            public(10),
            &destination.trust,
            &destination.evidence,
        )
        .unwrap_err();
    assert_eq!(tombstone_error, "permanent import tombstone rejects replay");
    assert_eq!(staged.ledger, original_ledger);
    assert_eq!(destination.chain.ledger, original_ledger);
    assert_eq!(destination.chain.finalized, original_finality);
    assert_eq!(flat.storage_head(), original_head);
    assert_eq!(inventory(&root), before);
    let closed = conservation_with_escrow(&[source79.clone(), destination3.clone()]).unwrap();
    let nonclosed = conservation_with_escrow(&[source78.clone(), destination3.clone()]).unwrap();
    for (height, totals) in [(79u128, closed), (78, nonclosed)] {
        assert_eq!(totals.0, Amount(rld_pow::cumulative_emission(height)));
        assert_eq!(totals.0, totals.1);
        assert_eq!((totals.2, totals.3), (Amount::ZERO, Amount::ZERO));
    }
    assert_ne!(closed.0, nonclosed.0);
    assert_eq!(
        conservation_with_escrow(std::slice::from_ref(&source79))
            .unwrap()
            .3,
        Amount(100)
    );
    phase(&at, "destination-construction", "end");

    phase(&at, "seal-complete-archives", "begin");
    let source_dir = root.join("source-archive");
    let destination_dir = root.join("destination-archive");
    let source_head = seal_format(&source_dir, source_scope.clone(), &source_records, false).0;
    let destination_head = seal_format(
        &destination_dir,
        destination_scope.clone(),
        &destination_records,
        false,
    )
    .0;
    assert_eq!(destination_head, flat.storage_head());
    let make_query = |source_checkpoint,
                      source_carried,
                      destination_checkpoint,
                      destination_carried| OriginArchiveCutQueryCandidate {
        format: ORIGIN_ARCHIVE_CUT_FORMAT.into(),
        export,
        source: OriginArchiveSelectionCandidate {
            region: h.region,
            checkpoint: source_checkpoint,
            carried_head: source_carried,
        },
        destination: OriginArchiveSelectionCandidate {
            region: destination_id,
            checkpoint: destination_checkpoint,
            carried_head: destination_carried,
        },
    };
    let query = make_query(source79_id, source_head, destination3_id, destination_head);
    phase(&at, "seal-complete-archives", "end");
    phase(&at, "closed-cut", "begin");
    let before = inventory(&root);
    let observed = inspect_origin_archive_cut_candidate(
        &source_dir,
        &destination_dir,
        &h.bootstrap,
        &authority,
        pin,
        &query,
    )
    .unwrap();
    assert_eq!(inventory(&root), before);
    let Record::Certified(d3) = &destination_records[3] else {
        unreachable!()
    };
    assert_eq!(
        observed.selected,
        [snapshots[78].statement.clone(), d3.statement.clone()]
    );
    assert_eq!(
        (
            observed.issued,
            observed.liquid,
            observed.escrow,
            observed.pending_transfer
        ),
        closed
    );
    assert_eq!(
        (
            observed.source_record_count,
            observed.destination_record_count
        ),
        (80, 16)
    );
    assert_eq!(
        (
            observed.source_final_height,
            observed.destination_final_height
        ),
        (80, 15)
    );
    assert_eq!(
        (
            observed.source_final_checkpoint,
            observed.destination_final_checkpoint
        ),
        (source80_id, destination15_id)
    );
    assert_eq!(
        (observed.currency, observed.trust_binding),
        (pin, source.trust.binding)
    );
    assert!(observed.complete_genesis_replay);
    assert!(
        !observed.ledger_changed
            && !observed.signing_authority
            && !observed.current_spendability_authority
            && !observed.independent_freshness_verified
            && !observed.incident_safety_verified
            && !observed.import_authority
            && !observed.recovery_authority
    );
    phase(&at, "closed-cut", "end");

    // Selected D1 precedes its import. A later valid Import must not backfill
    // selected permanent-import state or demand that selected S cover S79.
    phase(&at, "pre-import-selected-control", "begin");
    let mut delayed = replay(&dh);
    let mut delayed_flat = Stream::<Record>::create(
        &root.join("delayed-import-events"),
        destination_scope.clone(),
    )
    .unwrap();
    let delayed_origin = destination_records[0].clone();
    delayed
        .apply_retained(&delayed_origin, &delayed_flat)
        .unwrap();
    delayed_flat
        .append(
            std::slice::from_ref(&delayed_origin),
            delayed_flat.storage_head(),
        )
        .unwrap();
    let mut delayed_records = vec![delayed_origin];
    let mut delayed_local = Vec::new();
    let mut delayed1 = None;
    for height in 1..=15 {
        let commands = match height {
            2 => vec![Command::Import {
                snapshot: source79_id,
                export,
            }],
            4 => vec![local_spend(&delayed, imported, 11, 12, Amount(98))],
            _ => vec![],
        };
        let record = Record::Certified(Box::new(certified_with_commands(&delayed, commands)));
        delayed.apply_retained(&record, &delayed_flat).unwrap();
        if height == 1 {
            assert!(delayed.chain.ledger.imports.is_empty());
            delayed1 = Some(delayed.chain.clone());
        }
        if height == 2 {
            assert_eq!(delayed.chain.ledger.coins[&imported].mature, 4);
        }
        delayed_local.push(record.clone());
        delayed_records.push(record);
    }
    delayed_flat
        .append(&delayed_local, delayed_flat.storage_head())
        .unwrap();
    delayed
        .executed
        .require_boundary(&destination_scope, 16, delayed_flat.storage_head())
        .unwrap();
    assert_eq!(
        delayed.chain.ledger.imports.get(&export),
        Some(&source79_id)
    );
    assert!(!delayed.chain.ledger.coins.contains_key(&imported));
    let delayed1 = delayed1.unwrap();
    let pre_import_totals =
        conservation_with_escrow(&[source78.clone(), delayed1.clone()]).unwrap();
    assert_eq!(
        pre_import_totals,
        conservation_with_escrow(std::slice::from_ref(&source78)).unwrap()
    );
    assert_eq!(pre_import_totals.3, Amount(100));
    let delayed_dir = root.join("pre-import-selected-archive");
    let delayed_head = seal_format(
        &delayed_dir,
        destination_scope.clone(),
        &delayed_records,
        false,
    )
    .0;
    let request = make_query(
        source78_id,
        source_head,
        delayed1.finalized.unwrap(),
        delayed_head,
    );
    let before = inventory(&root);
    let pre_import = inspect_origin_archive_cut_candidate(
        &source_dir,
        &delayed_dir,
        &h.bootstrap,
        &authority,
        pin,
        &request,
    )
    .unwrap();
    assert_eq!(inventory(&root), before);
    let Record::Certified(delayed1_record) = &delayed_records[1] else {
        unreachable!()
    };
    assert_eq!(
        pre_import.selected,
        [
            snapshots[77].statement.clone(),
            delayed1_record.statement.clone()
        ]
    );
    assert_eq!(
        (
            pre_import.issued,
            pre_import.liquid,
            pre_import.escrow,
            pre_import.pending_transfer
        ),
        pre_import_totals
    );
    assert_eq!(
        (
            pre_import.source_record_count,
            pre_import.destination_record_count
        ),
        (80, 16)
    );
    assert_eq!(
        (
            pre_import.source_final_height,
            pre_import.destination_final_height
        ),
        (80, 15)
    );
    assert_eq!(
        pre_import.destination_final_checkpoint,
        delayed.chain.finalized.unwrap()
    );
    phase(&at, "pre-import-selected-control", "end");

    let refuse = |name: &str,
                  src: &Path,
                  dst: &Path,
                  request: &OriginArchiveCutQueryCandidate,
                  auth: &str,
                  currency: Hash| {
        phase(&at, name, "begin");
        let before = inventory(&root);
        let error =
            inspect_origin_archive_cut_candidate(src, dst, &h.bootstrap, auth, currency, request)
                .unwrap_err();
        assert_eq!(inventory(&root), before);
        eprintln!(
            "origin_archive_cut_refusal={}",
            serde_json::json!({"name": name, "error": error})
        );
        phase(&at, name, "end");
        error
    };
    let earlier = make_query(source78_id, source_head, destination3_id, destination_head);
    let closure_error = refuse(
        "amount-valid-nonclosed-cut",
        &source_dir,
        &destination_dir,
        &earlier,
        &authority,
        pin,
    );
    assert!(
        closure_error.contains("selected source does not cover complete imported dependency"),
        "{closure_error}"
    );
    let mut bad_source = source_records.clone();
    let Record::Certified(last) = bad_source.last_mut().unwrap() else {
        unreachable!()
    };
    last.bft.as_mut().unwrap().committed.votes[0]
        .approval
        .signature = "00".repeat(64);
    let bad_source_dir = root.join("bad-source-tail");
    let bad_source_head = seal_format(&bad_source_dir, source_scope.clone(), &bad_source, false).0;
    let request = make_query(
        source79_id,
        bad_source_head,
        destination3_id,
        destination_head,
    );
    let error = refuse(
        "bad-source-tail",
        &bad_source_dir,
        &destination_dir,
        &request,
        &authority,
        pin,
    );
    assert!(error.contains("signature"), "{error}");
    let mut bad_destination = destination_records.clone();
    let Record::Certified(last) = bad_destination.last_mut().unwrap() else {
        unreachable!()
    };
    last.bft.as_mut().unwrap().committed.votes[0]
        .approval
        .signature = "00".repeat(64);
    let bad_destination_dir = root.join("bad-destination-tail");
    let bad_destination_head = seal_format(
        &bad_destination_dir,
        destination_scope.clone(),
        &bad_destination,
        false,
    )
    .0;
    let request = make_query(
        source79_id,
        source_head,
        destination3_id,
        bad_destination_head,
    );
    let error = refuse(
        "bad-destination-tail",
        &source_dir,
        &bad_destination_dir,
        &request,
        &authority,
        pin,
    );
    assert!(error.contains("signature"), "{error}");
    let mut bad_embedded = destination_records.clone();
    let Record::OriginHistory(proof) = &mut bad_embedded[0] else {
        unreachable!()
    };
    proof.snapshots[78].bft.as_mut().unwrap().committed.votes[0]
        .approval
        .signature = "00".repeat(64);
    let bad_embedded_dir = root.join("bad-embedded-origin");
    let bad_embedded_head = seal_format(
        &bad_embedded_dir,
        destination_scope.clone(),
        &bad_embedded,
        false,
    )
    .0;
    let request = make_query(source79_id, source_head, destination3_id, bad_embedded_head);
    let error = refuse(
        "bad-embedded-origin",
        &source_dir,
        &bad_embedded_dir,
        &request,
        &authority,
        pin,
    );
    assert!(error.contains("signature"), "{error}");

    // A real same-Export fork is Native-valid, not an edited signed certificate.
    phase(&at, "valid-alternate-source-branch", "begin");
    let (fork_input, fork_coin) = fork
        .chain
        .ledger
        .coins
        .iter()
        .find(|(_, c)| c.created == 2 && c.payment.owner == public(10))
        .unwrap();
    let command = local_spend(
        &fork,
        *fork_input,
        10,
        12,
        fork_coin.payment.amount.checked_sub(Amount(1)).unwrap(),
    );
    let mut fork_records = source_records[..78].to_vec();
    for height in 79..=80 {
        let commands = if height == 79 {
            vec![command.clone()]
        } else {
            vec![]
        };
        let record = Record::Certified(Box::new(certified_with_commands(&fork, commands)));
        let history = super::origin_history::test_history(&h, &fork, &fork_records);
        fork.apply_retained(&record, &history).unwrap();
        fork_records.push(record);
    }
    let Record::Certified(fork79) = &fork_records[78] else {
        unreachable!()
    };
    let fork79_id = fork79.statement.id().unwrap();
    assert_ne!(fork79_id, source79_id);
    assert_eq!(
        fork.chain.ledger.exports[&export],
        source79.ledger.exports[&export]
    );
    let fork_dir = root.join("valid-incompatible-source");
    let fork_head = seal_format(&fork_dir, source_scope, &fork_records, false).0;
    let before = inventory(&root);
    let valid_fork = inspect_historical_archive_candidate(
        &fork_dir,
        &h.bootstrap,
        &authority,
        pin,
        fork_head,
        &HistoricalArchiveQueryCandidate {
            format: HISTORICAL_ARCHIVE_QUERY_FORMAT.into(),
            region: h.region,
            checkpoint: fork79_id,
        },
    )
    .unwrap();
    assert_eq!(inventory(&root), before);
    assert_eq!(valid_fork.selected, fork79.statement);
    assert_eq!(valid_fork.selected_ledger_root, fork79.statement.state);
    assert_eq!(
        (
            valid_fork.archive_record_count,
            valid_fork.archive_final_height
        ),
        (80, 80)
    );
    assert_eq!(
        (
            valid_fork.issued,
            valid_fork.escrow,
            valid_fork.pending_transfer
        ),
        (closed.0, Amount::ZERO, Amount(100))
    );
    assert!(valid_fork.complete_genesis_replay);
    phase(&at, "valid-alternate-source-branch", "end");
    let request = make_query(fork79_id, fork_head, destination3_id, destination_head);
    let branch_error = refuse(
        "same-export-incompatible-branch",
        &fork_dir,
        &destination_dir,
        &request,
        &authority,
        pin,
    );
    assert!(
        branch_error.contains("embedded source branch differs"),
        "{branch_error}"
    );

    let mut missing = destination_records.clone();
    missing[0] = destination_records[1].clone();
    let missing_dir = root.join("missing-origin-proof");
    let missing_head = seal_format(&missing_dir, destination_scope, &missing, false).0;
    let request = make_query(source79_id, source_head, destination3_id, missing_head);
    refuse(
        "missing-origin-proof",
        &source_dir,
        &missing_dir,
        &request,
        &authority,
        pin,
    );
    let request = make_query(
        source79_id,
        Hash([9; 32]),
        destination3_id,
        destination_head,
    );
    refuse(
        "wrong-source-head",
        &source_dir,
        &destination_dir,
        &request,
        &authority,
        pin,
    );
    let request = make_query(source79_id, source_head, destination3_id, Hash([9; 32]));
    refuse(
        "wrong-destination-head",
        &source_dir,
        &destination_dir,
        &request,
        &authority,
        pin,
    );
    refuse(
        "wrong-authority",
        &source_dir,
        &destination_dir,
        &query,
        &public(2),
        pin,
    );
    refuse(
        "wrong-currency",
        &source_dir,
        &destination_dir,
        &query,
        &authority,
        Hash([9; 32]),
    );
    let mut request = make_query(source79_id, source_head, destination3_id, destination_head);
    request.destination.region = h.region;
    refuse(
        "duplicate-selected-region",
        &source_dir,
        &destination_dir,
        &request,
        &authority,
        pin,
    );

    let mut cli_executed = false;
    if let Some(binary) = std::env::var_os("RLD_ORIGIN_ARCHIVE_CUT_CLI") {
        phase(&at, "actual-cli", "begin");
        let bootstrap_file = root.join("trusted-bootstrap.json");
        let query_file = root.join("exact-origin-cut-query.json");
        crate::keystore::private_create(
            &bootstrap_file,
            &serde_json::to_vec(&h.bootstrap).unwrap(),
        )
        .unwrap();
        crate::keystore::private_create(&query_file, &serde_json::to_vec(&query).unwrap()).unwrap();
        let before = inventory(&root);
        let output = Process::new(binary)
            .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
            .args([
                "--dir",
                source_dir.to_str().unwrap(),
                "--authority",
                &authority,
                "--currency",
                &pin.to_hex(),
                "origin-archive-cut-inspect",
                "--destination-dir",
                destination_dir.to_str().unwrap(),
                "--bootstrap",
                bootstrap_file.to_str().unwrap(),
                "--query",
                query_file.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let cli: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(cli, serde_json::to_value(&observed).unwrap());
        assert_eq!(inventory(&root), before);
        cli_executed = true;
        phase(&at, "actual-cli", "end");
    }
    println!(
        "origin_archive_cut_result={}",
        serde_json::json!({
            "fixture_root": root, "source_heights": 80, "destination_heights": 15,
            "source_records": 80, "destination_records": 16,
            "imported_output_spent": true, "permanent_import_checkpoint": source79_id,
            "closed_pair_totals": closed, "amount_valid_nonclosed_pair_totals": nonclosed,
            "pre_import_selected_observation": pre_import,
            "nonclosed_error": closure_error, "valid_same_export_fork_error": branch_error,
            "duplicate_import_error": tombstone_error, "observation": observed,
            "actual_cli_executed": cli_executed, "elapsed_seconds": at.elapsed().as_secs_f64(),
            "historical_only": true, "arbitrary_region_qualified": false,
            "custody_qualified": false, "independent_qualified": false, "mainnet_qualified": false,
        })
    );
}
