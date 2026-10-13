//! Fresh public no-value signatures; no adopted value or copied stopped Store.
use super::body_witness_tests::{certified_with_commands, header, replay, stream};
use super::export_archive_tests::{inventory, seal_format};
use super::*;
use crate::tests::{channel_integration as channel, public};
use std::process::Command as Process;

#[test]
#[ignore = "fresh complete archive component with actual certificate eviction and authenticated historical selection"]
fn selected_archive_state_survives_eviction_and_authenticates_full_tail() {
    let started = std::time::Instant::now();
    let h = header();
    let mut native = replay(&h);
    let (root, mut flat) = stream(&h, &native);
    let scope = h.scope(&native.trust).unwrap();
    let pin = h.bootstrap.currency.id().unwrap();
    let authority = public(1);
    let mut records = Vec::new();
    let mut pending = Vec::new();
    let mut selected = None;
    for height in 1..=79 {
        let commands = if height == 4 {
            vec![channel::funding(&native.chain, &native.trust)]
        } else {
            vec![]
        };
        let record = Record::Certified(Box::new(certified_with_commands(&native, commands)));
        native.apply_retained(&record, &flat).unwrap();
        assert_eq!(native.chain.height(), height);
        assert!(native.chain.ledger.imports.is_empty());
        assert!(native.evidence.snapshots.len() <= MAX_SNAPSHOTS);
        if height == 4 {
            let Record::Certified(snapshot) = &record else {
                unreachable!()
            };
            let totals = conservation_with_escrow(std::slice::from_ref(&native.chain)).unwrap();
            assert_eq!(totals.0, Amount(rld_pow::cumulative_emission(4)));
            assert_eq!(totals.2, Amount(60));
            assert_eq!(totals.3, Amount::ZERO);
            assert_eq!(totals.1, totals.0.checked_sub(Amount(60)).unwrap());
            selected = Some((
                snapshot.statement.clone(),
                native.chain.ledger.root().unwrap(),
                totals,
            ));
        }
        records.push(record.clone());
        pending.push(record);
        if pending.len() == crate::history::PAGE_EVENTS {
            flat.append(&pending, flat.storage_head()).unwrap();
            pending.clear();
        }
    }
    let (selected_statement, selected_root, selected_totals) = selected.unwrap();
    let selected_id = selected_statement.id().unwrap();
    let final_id = native.chain.finalized.unwrap();
    let final_root = native.chain.ledger.root().unwrap();
    let final_totals = conservation_with_escrow(std::slice::from_ref(&native.chain)).unwrap();
    assert_eq!(native.chain.height(), 79);
    assert_eq!(final_totals.0, Amount(rld_pow::cumulative_emission(79)));
    assert_eq!(final_totals.2, Amount(60));
    assert_ne!(selected_totals.0, final_totals.0);
    assert_ne!(selected_root, final_root);
    assert_ne!(selected_id, final_id);
    assert_eq!(native.evidence.snapshots.len(), MAX_SNAPSHOTS);
    assert!(!native.evidence.snapshots.contains_key(&selected_id));

    // A complete retained old certificate is still authenticated, but cannot
    // recapture the height79 ledger under the selected height4 identity.
    let duplicate = records[3].clone();
    native.apply_retained(&duplicate, &flat).unwrap();
    records.push(duplicate.clone());
    pending.push(duplicate);
    assert_eq!(pending.len(), crate::history::PAGE_EVENTS);
    flat.append(&pending, flat.storage_head()).unwrap();
    assert_eq!(records.len(), 80);
    assert_eq!(flat.record_count(), 80);
    native
        .executed
        .require_boundary(&scope, flat.record_count(), flat.storage_head())
        .unwrap();
    assert_eq!(native.chain.height(), 79);
    assert_eq!(native.chain.finalized, Some(final_id));
    assert_eq!(native.chain.ledger.root().unwrap(), final_root);
    assert!(!native.evidence.snapshots.contains_key(&selected_id));
    flat.visit(flat.storage_head(), |_| Ok(())).unwrap();
    let proof = root.join("proof");
    let head = seal_format(&proof, scope.clone(), &records, false).0;
    assert_eq!(head, flat.storage_head());
    let query = HistoricalArchiveQueryCandidate {
        format: HISTORICAL_ARCHIVE_QUERY_FORMAT.into(),
        region: h.region,
        checkpoint: selected_id,
    };
    let before = inventory(&root);
    let observed =
        inspect_historical_archive_candidate(&proof, &h.bootstrap, &authority, pin, head, &query)
            .unwrap();
    assert_eq!(inventory(&root), before);
    assert_eq!(observed.selected, selected_statement);
    assert_eq!(observed.selected_ledger_root, selected_root);
    assert_eq!(observed.selected.state, selected_root);
    assert_eq!(
        (
            observed.issued,
            observed.liquid,
            observed.escrow,
            observed.pending_transfer
        ),
        selected_totals
    );
    assert_eq!(observed.archive_record_count, 80);
    assert_eq!(observed.archive_final_checkpoint, final_id);
    assert_eq!(observed.archive_final_height, 79);
    assert_eq!(observed.currency, pin);
    assert_eq!(observed.trust_binding, native.trust.binding);
    assert!(observed.complete_genesis_replay && observed.local_history_only);
    assert!(
        !observed.ledger_changed
            && !observed.signing_authority
            && !observed.current_spendability_authority
            && !observed.independent_freshness_verified
            && !observed.incident_safety_verified
            && !observed.import_authority
            && !observed.recovery_authority
    );

    // Every rejection leaves its fresh retained image unchanged. These are
    // malformed candidates, never substituted authenticated negative histories.
    let refuse = |dir: &Path,
                  carried: Hash,
                  q: &HistoricalArchiveQueryCandidate,
                  auth: &str,
                  currency: Hash,
                  fragment: &str| {
        let before = inventory(&root);
        let error =
            inspect_historical_archive_candidate(dir, &h.bootstrap, auth, currency, carried, q)
                .unwrap_err();
        assert!(error.contains(fragment), "{error}");
        assert_eq!(inventory(&root), before);
    };
    let mut bad_later = records.clone();
    let Record::Certified(last) = &mut bad_later[78] else {
        unreachable!()
    };
    last.bft.as_mut().unwrap().committed.votes[0]
        .approval
        .signature = "00".repeat(64);
    let bad_later_dir = root.join("bad-later-certificate");
    let bad_later_head = seal_format(&bad_later_dir, scope.clone(), &bad_later, false).0;
    refuse(
        &bad_later_dir,
        bad_later_head,
        &query,
        &authority,
        pin,
        "signature",
    );

    let mut bad_duplicate = records.clone();
    let Record::Certified(old) = &mut bad_duplicate[79] else {
        unreachable!()
    };
    old.bft.as_mut().unwrap().prepared.votes[0]
        .approval
        .signature = "00".repeat(64);
    let bad_duplicate_dir = root.join("bad-old-duplicate");
    let bad_duplicate_head =
        seal_format(&bad_duplicate_dir, scope.clone(), &bad_duplicate, false).0;
    refuse(
        &bad_duplicate_dir,
        bad_duplicate_head,
        &query,
        &authority,
        pin,
        "signature",
    );

    let missing_dir = root.join("missing-genesis-prefix");
    let missing_head = seal_format(&missing_dir, scope.clone(), &records[16..], false).0;
    refuse(&missing_dir, missing_head, &query, &authority, pin, "");
    let mut with_evidence = records.clone();
    with_evidence[4] = Record::Evidence(Box::default());
    let evidence_dir = root.join("unsupported-evidence-tail");
    let evidence_head = seal_format(&evidence_dir, scope.clone(), &with_evidence, false).0;
    refuse(
        &evidence_dir,
        evidence_head,
        &query,
        &authority,
        pin,
        "complete local certificates only",
    );

    let other_scope = Scope::bind(&native.trust, h.region, Purpose::Ledger, Hash([9; 32])).unwrap();
    assert_ne!(scope, other_scope);
    let scope_dir = root.join("different-storage-scope");
    let scope_head = seal_format(&scope_dir, other_scope, &records, false).0;
    refuse(&scope_dir, scope_head, &query, &authority, pin, "");
    assert_ne!(head, Hash([9; 32]));
    refuse(&proof, Hash([9; 32]), &query, &authority, pin, "");
    refuse(&proof, head, &query, &public(2), pin, "");
    assert_ne!(pin, Hash([9; 32]));
    refuse(&proof, head, &query, &authority, Hash([9; 32]), "");
    let mut wrong = query.clone();
    wrong.checkpoint = Hash([9; 32]);
    assert!(records.iter().all(
        |r| matches!(r, Record::Certified(s) if s.statement.id().unwrap() != wrong.checkpoint)
    ));
    refuse(
        &proof,
        head,
        &wrong,
        &authority,
        pin,
        "selected checkpoint absent",
    );
    wrong = query.clone();
    wrong.region = Hash([9; 32]);
    refuse(&proof, head, &wrong, &authority, pin, "");
    wrong = query.clone();
    wrong.format.push_str("-unknown");
    refuse(&proof, head, &wrong, &authority, pin, "exact query");
    wrong = query.clone();
    wrong.checkpoint = Hash::ZERO;
    refuse(&proof, head, &wrong, &authority, pin, "exact query");
    refuse(&proof, head, &query, &authority, Hash::ZERO, "exact query");

    let lossless_dir = root.join("unsupported-lossless");
    let lossless_head = seal_format(&lossless_dir, scope.clone(), &records, true).0;
    assert_eq!(lossless_head, head);
    refuse(&lossless_dir, lossless_head, &query, &authority, pin, "");
    let restoring_dir = root.join("incomplete-restore");
    let restoring_head = seal_format(&restoring_dir, scope, &records, false).0;
    crate::keystore::private_create(
        &restoring_dir.join("RESTORING"),
        b"RLD-NATIVE-HISTORY-RESTORING-V1\n",
    )
    .unwrap();
    refuse(
        &restoring_dir,
        restoring_head,
        &query,
        &authority,
        pin,
        "restoration is incomplete",
    );

    // The controller alone supplies the exact built binary. No guessed path or
    // implicit build. Its output must match the complete library observation.
    let mut cli_executed = false;
    if let Some(binary) = std::env::var_os("RLD_HISTORICAL_ARCHIVE_CLI") {
        let bootstrap_path = root.join("trusted-bootstrap.json");
        let query_path = root.join("exact-query.json");
        crate::keystore::private_create(
            &bootstrap_path,
            &serde_json::to_vec(&h.bootstrap).unwrap(),
        )
        .unwrap();
        crate::keystore::private_create(&query_path, &serde_json::to_vec(&query).unwrap()).unwrap();
        let before_cli = inventory(&root);
        let output = Process::new(binary)
            .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
            .args([
                "--dir",
                proof.to_str().unwrap(),
                "--authority",
                &authority,
                "--currency",
                &pin.to_hex(),
                "historical-archive-inspect",
                "--bootstrap",
                bootstrap_path.to_str().unwrap(),
                "--query",
                query_path.to_str().unwrap(),
                "--carried-head",
                &head.to_hex(),
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
        assert_eq!(inventory(&root), before_cli);
        cli_executed = true;
    }
    println!(
        "historical_archive_component={}",
        serde_json::json!({
            "fixture_root": root,
            "actual_certified_heights": 79,
            "retained_records": 80,
            "selected_height": 4,
            "selected_evicted_from_producer_active_evidence": true,
            "selected": observed,
            "actual_cli_executed": cli_executed,
            "elapsed_seconds": started.elapsed().as_secs_f64(),
            "scope": "one local complete raw archive; no live, import, freshness, incident, custody, recovery, lifecycle or mainnet qualification"
        })
    );
}
