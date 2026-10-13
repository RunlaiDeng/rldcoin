//! Fresh local-construction refusals. The C1 certificate is a negative fixture,
//! not Runtime consensus; no owner-payment, cold or service qualification follows.
use super::negative_seams::{authentic_alternate_a80, Target};
use super::queue_negative::authentic_wrapper_variant;
use super::*;
use crate::bft::{Context, Request};
use crate::bft_onward_network::{execution_cost, LocalConstructionWitness};
use crate::bft_runtime_envelope::Wire;

fn check(deadline: f64) {
    assert!(
        now() < deadline,
        "original 60-second local builder negatives exhausted"
    );
}
fn measured<T>(
    rows: &mut Vec<Value>,
    label: &str,
    expected_pure: u64,
    call: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let scope = execution_cost::Scope::begin();
    let result = call();
    let cost = scope.finish();
    assert!(cost.complete);
    assert_eq!(cost.calls, cost.successful + cost.failed);
    assert!(cost.max_depth <= 1);
    assert_eq!(cost.verification_calls, expected_pure, "{label}");
    assert!(cost.verification_seconds.is_finite());
    if result.is_ok() {
        assert_eq!(cost.failed, 0, "{label}");
        assert_eq!(cost.calls, cost.successful, "{label}");
    }
    assert!(rows.len() < 96);
    rows.push(json!({"label":label,"expected_pure":expected_pure,
        "pure":cost.verification_calls,"calls":cost.calls,"successful":cost.successful,
        "failed":cost.failed,"complete":cost.complete,"max_depth":cost.max_depth,
        "accepted":result.is_ok()}));
    result
}
fn warm(
    rows: &mut Vec<Value>,
    valid: &net::Envelope,
    node: &Store,
    ident: Hash,
) -> LocalConstructionWitness {
    let mut witness = LocalConstructionWitness::new();
    assert_eq!(
        measured(rows, "helper-first", 1, || valid
            .verify_for_construction(node, &mut witness))
        .unwrap(),
        ident
    );
    assert_eq!(
        measured(rows, "helper-hit", 0, || valid
            .verify_for_construction(node, &mut witness))
        .unwrap(),
        ident
    );
    witness
}
fn refuse(
    rows: &mut Vec<Value>,
    label: &str,
    valid: &net::Envelope,
    invalid: &net::Envelope,
    node: &Store,
    ident: Hash,
    pure: u64,
) {
    let mut witness = warm(rows, valid, node, ident);
    let expected = invalid.verify(node).unwrap_err();
    assert!(!expected.is_empty());
    assert_eq!(
        measured(rows, label, pure, || invalid
            .verify_for_construction(node, &mut witness))
        .unwrap_err(),
        expected
    );
    // Construction may remember foreign proof before body verification; failure
    // must clear and disable it, rather than export even that partial authority.
    for _ in 0..2 {
        assert_eq!(
            measured(rows, "after-error-full", 1, || valid
                .verify_for_construction(node, &mut witness))
            .unwrap(),
            ident
        );
    }
}
fn bytes(wire: &net::WireEnvelope) -> Vec<u8> {
    files::canonical_with_limit(wire, crate::contact::MAX_PAYLOAD).unwrap()
}

#[test]
#[ignore = "one fresh 60-second local builder witness refusal component"]
fn onward_local_builder_refuses_altered_authority_and_rechecks_safety() {
    let started = now();
    let deadline = started + 60.0;
    let (root, bootstrap, proof, _, b4, export) = ancestors();
    check(deadline);
    let mut target = Target::new(
        &root,
        "local-builder-negatives",
        &bootstrap,
        proof.history.destination,
    );
    let c1 = certified_with_commands(&target.node.paged_replay.as_ref().unwrap().replay, vec![]);
    target.node.finalize(c1.clone()).unwrap();
    target
        .node
        .accept_complete_onward_network_history(proof.clone())
        .unwrap();
    let message = target
        .actor
        .as_mut()
        .unwrap()
        .sign_fixture_control(
            &target.node,
            Request::Timeout {
                context: Context::current(&target.node).unwrap(),
                round: 0,
            },
        )
        .unwrap();
    assert!(matches!(&message,Message::Timeout(v) if v.context.parent_height==1 && v.round==0));
    let valid = net::Envelope {
        format: net::FORMAT.into(),
        currency: target.node.trust.currency().unwrap(),
        region: target.node.chain.region,
        history: Some(proof.clone()),
        evidence: Evidence {
            snapshots: vec![c1.clone()],
        },
        body: Body::Signed(Box::new(message)),
    };
    let ident = valid.verify(&target.node).unwrap();
    let native_head = target.node.storage_head().unwrap();
    assert_eq!(target.node.chain.ledger, Ledger::default());
    let pending = vec![Command::Import {
        snapshot: b4,
        export,
    }];
    assert_eq!(
        target
            .node
            .complete_onward_network_pending_imports()
            .unwrap(),
        pending
    );
    let before = inventory(&root);
    let mut rows = Vec::new();
    check(deadline);

    // Public material and public complete-envelope verification remain full.
    let (selected, evidence) = measured(&mut rows, "independent-material-one", 2, || {
        target.node.onward_network_material()
    })
    .unwrap();
    assert_eq!(selected.as_ref(), Some(&proof));
    assert_eq!(evidence.snapshots, vec![c1.clone()]);
    let normal = measured(&mut rows, "actual-builder-one", 1, || {
        net::local_envelope(valid.body.clone(), &target.node)
    })
    .unwrap();
    let canonical = bytes(&normal);
    let next = measured(&mut rows, "actual-new-builder-one", 1, || {
        net::local_envelope(valid.body.clone(), &target.node)
    })
    .unwrap();
    assert_eq!(bytes(&next), canonical);
    let full = measured(&mut rows, "actual-cap-zero-one", 4, || {
        net::local_envelope_with_limit_for_test(valid.body.clone(), &target.node, 0)
    })
    .unwrap();
    assert_eq!(bytes(&full), canonical);
    assert_eq!(
        measured(&mut rows, "independent-envelope", 1, || normal
            .clone()
            .expand()?
            .verify(&target.node))
        .unwrap(),
        ident
    );
    let dispatched = measured(&mut rows, "actual-wire-local", 1, || {
        Wire::local(valid.body.clone(), &target.node, bft_client::ONWARD_FORMAT)
    })
    .unwrap();
    assert_eq!(
        dispatched.wire_value().unwrap(),
        serde_json::to_value(&normal).unwrap()
    );
    assert_eq!(inventory(&root), before);
    check(deadline);

    // Exercise actual outgoing construction, not only its internal helper seam.
    let mut bad_body = valid.clone();
    let Body::Signed(message) = &mut bad_body.body else {
        panic!("signed body")
    };
    let Message::Timeout(vote) = message.as_mut() else {
        panic!("timeout body")
    };
    vote.approval.signature = "00".repeat(64);
    let bad_body_error = bad_body.verify(&target.node).unwrap_err();
    assert_eq!(
        measured(&mut rows, "actual-bad-body", 1, || Wire::local(
            bad_body.body.clone(),
            &target.node,
            bft_client::ONWARD_FORMAT
        ))
        .err()
        .unwrap(),
        bad_body_error
    );
    let mut bad_finality = c1.clone();
    bad_finality.bft.as_mut().unwrap().committed.votes[0]
        .approval
        .signature = "00".repeat(64);
    let mut bad_finalized = valid.clone();
    bad_finalized.body = Body::Finalized(Box::new(bad_finality));
    let bad_c_error = bad_finalized.verify(&target.node).unwrap_err();
    assert_eq!(
        measured(&mut rows, "actual-bad-finalized-c", 1, || Wire::local(
            bad_finalized.body.clone(),
            &target.node,
            bft_client::ONWARD_FORMAT
        ))
        .err()
        .unwrap(),
        bad_c_error
    );
    assert_eq!(inventory(&root), before);
    assert_eq!(target.node.storage_head().unwrap(), native_head);
    check(deadline);

    let mut missing_c = valid.clone();
    missing_c.evidence.snapshots.clear();
    refuse(
        &mut rows,
        "helper-missing-c",
        &valid,
        &missing_c,
        &target.node,
        ident,
        0,
    );
    let mut bad_c = valid.clone();
    bad_c.evidence.snapshots[0]
        .bft
        .as_mut()
        .unwrap()
        .committed
        .votes[0]
        .approval
        .signature = "00".repeat(64);
    refuse(
        &mut rows,
        "helper-bad-c",
        &valid,
        &bad_c,
        &target.node,
        ident,
        0,
    );
    refuse(
        &mut rows,
        "helper-bad-body",
        &valid,
        &bad_body,
        &target.node,
        ident,
        0,
    );
    let mut bad_proof = valid.clone();
    bad_proof.history.as_mut().unwrap().history.snapshots[3]
        .bft
        .as_mut()
        .unwrap()
        .committed
        .votes[0]
        .approval
        .signature = "00".repeat(64);
    refuse(
        &mut rows,
        "helper-changed-foreign-signature",
        &valid,
        &bad_proof,
        &target.node,
        ident,
        1,
    );
    check(deadline);

    // None must build an empty foreign context, never inherit this warm entry.
    let mut witness = warm(&mut rows, &valid, &target.node, ident);
    let mut no_history = valid.clone();
    no_history.history = None;
    let no_history_id = no_history.verify(&target.node).unwrap();
    assert_eq!(
        measured(&mut rows, "helper-valid-history-none", 0, || no_history
            .verify_for_construction(&target.node, &mut witness))
        .unwrap(),
        no_history_id
    );
    let mut import = valid.clone();
    import.body = Body::Submission(pending.clone());
    import.verify(&target.node).unwrap();
    import.history = None;
    refuse(
        &mut rows,
        "helper-history-none-import",
        &valid,
        &import,
        &target.node,
        ident,
        0,
    );

    // This is a lower-level binding-key control only, not a new signed Trust or
    // a Store admission. Full Native derivation must reject its forged binding.
    let mut foreign = LocalConstructionWitness::new();
    let original = measured(&mut rows, "helper-trust-first", 1, || {
        foreign.verify_anchors(&proof, valid.region, &target.node.trust)
    })
    .unwrap();
    assert_eq!(original.trust_binding, Some(target.node.trust.binding));
    let mut changed_trust = target.node.trust.clone();
    changed_trust.binding = sha(b"local-builder-negative-distinct-binding");
    assert_ne!(changed_trust.binding, target.node.trust.binding);
    let expected = proof
        .verify_anchors(valid.region, &changed_trust)
        .err()
        .unwrap();
    assert_eq!(expected, "complete onward trust binding differs");
    assert_eq!(
        measured(&mut rows, "helper-changed-trust-binding-refuses", 1, || {
            foreign.verify_anchors(&proof, valid.region, &changed_trust)
        })
        .err()
        .unwrap(),
        expected
    );
    assert_eq!(
        measured(
            &mut rows,
            "helper-original-trust-after-error-full",
            1,
            || foreign.verify_anchors(&proof, valid.region, &target.node.trust)
        )
        .unwrap()
        .trust_binding,
        Some(target.node.trust.binding)
    );
    let wrong_destination = proof.history.source;
    let expected = proof
        .verify_anchors(wrong_destination, &target.node.trust)
        .err()
        .unwrap();
    assert_eq!(
        measured(&mut rows, "helper-wrong-destination", 0, || foreign
            .verify_anchors(&proof, wrong_destination, &target.node.trust))
        .err()
        .unwrap(),
        expected
    );
    assert_eq!(
        measured(&mut rows, "helper-after-route-error-full", 1, || foreign
            .verify_anchors(&proof, valid.region, &target.node.trust))
        .unwrap()
        .trust_binding,
        Some(target.node.trust.binding)
    );
    assert_eq!(inventory(&root), before);
    assert_eq!(target.node.storage_head().unwrap(), native_head);
    assert_eq!(target.node.chain.ledger, Ledger::default());
    assert_eq!(
        target
            .node
            .complete_onward_network_pending_imports()
            .unwrap(),
        pending
    );
    check(deadline);

    // A real different 3-of-4 B4 QC is installed by Native. Both retained events
    // authenticate in the first scan; the first covering wrapper remains output.
    let variant = authentic_wrapper_variant(&proof);
    let mut alternate = valid.clone();
    alternate.history = Some(variant.clone());
    assert_ne!(
        measured(&mut rows, "independent-alternate-qc", 1, || alternate
            .verify(&target.node))
        .unwrap(),
        ident
    );
    let mut qc_witness = warm(&mut rows, &valid, &target.node, ident);
    let alternate_id = alternate.verify(&target.node).unwrap();
    for _ in 0..2 {
        assert_eq!(
            measured(&mut rows, "helper-alternate-qc-miss", 1, || alternate
                .verify_for_construction(&target.node, &mut qc_witness))
            .unwrap(),
            alternate_id
        );
    }
    assert_eq!(
        measured(&mut rows, "helper-first-qc-still-hit", 0, || valid
            .verify_for_construction(&target.node, &mut qc_witness))
        .unwrap(),
        ident
    );
    target
        .node
        .accept_complete_onward_network_history(variant)
        .unwrap();
    let variant_head = target.node.storage_head().unwrap();
    assert_ne!(variant_head, native_head);
    let with_variant = inventory(&root);
    let selected = measured(&mut rows, "actual-builder-two-qcs", 2, || {
        net::local_envelope(valid.body.clone(), &target.node)
    })
    .unwrap();
    assert_eq!(selected.history.as_ref(), Some(&proof));
    assert_eq!(bytes(&selected), canonical);
    let uncached = measured(&mut rows, "actual-cap-zero-two-qcs", 5, || {
        net::local_envelope_with_limit_for_test(valid.body.clone(), &target.node, 0)
    })
    .unwrap();
    assert_eq!(bytes(&uncached), canonical);
    let (selected, evidence) = measured(&mut rows, "independent-material-two-qcs", 3, || {
        target.node.onward_network_material()
    })
    .unwrap();
    assert_eq!(selected.as_ref(), Some(&proof));
    assert_eq!(evidence.snapshots, vec![c1]);
    assert_eq!(inventory(&root), with_variant);
    assert_eq!(target.node.storage_head().unwrap(), variant_head);
    assert_eq!(target.node.chain.ledger, Ledger::default());
    assert_eq!(
        target
            .node
            .complete_onward_network_pending_imports()
            .unwrap(),
        pending
    );
    check(deadline);

    // A staged helper-only between-calls mutation proves live safety is never
    // foreign-proof authority. Production construction takes an immutable Store.
    let mut before_incident = warm(&mut rows, &valid, &target.node, ident);
    let alternate_a = authentic_alternate_a80(&bootstrap, &proof);
    let conflict =
        Conflict::from_snapshots(&proof.history.origin.snapshots[79], &alternate_a).unwrap();
    target.node.observe_conflict(conflict).unwrap();
    assert_eq!(target.node.journal.incident_ids.len(), 1);
    assert!(target
        .node
        .safety
        .check_region(proof.history.origin.source)
        .is_err());
    let incident_head = target.node.storage_head().unwrap();
    let after_incident = inventory(&root);
    let expected = valid.verify(&target.node).unwrap_err();
    assert!(
        expected.contains("operations are quarantined"),
        "{expected}"
    );
    assert_eq!(
        measured(&mut rows, "helper-current-incident", 0, || valid
            .verify_for_construction(&target.node, &mut before_incident))
        .unwrap_err(),
        expected
    );
    assert_eq!(
        measured(&mut rows, "actual-builder-current-incident", 0, || {
            Wire::local(valid.body.clone(), &target.node, bft_client::ONWARD_FORMAT)
        })
        .err()
        .unwrap(),
        expected
    );
    assert!(target
        .node
        .complete_onward_network_pending_imports()
        .is_err());
    assert_eq!(target.node.storage_head().unwrap(), incident_head);
    assert_eq!(inventory(&root), after_incident);
    assert_eq!(target.node.chain.height(), 1);
    assert_eq!(target.node.chain.ledger, Ledger::default());
    check(deadline);
    eprintln!(
        "onward_local_builder_witness_negative_result={}",
        json!({
            "root":root,"elapsed_seconds":now()-started,"passed":true,"controls":rows,
            "normal_builder_one":true,"new_builder_independent":true,"cap_zero_full_byte_equivalence":true,
            "independent_public_and_material":true,"actual_bad_body_refuses":true,"actual_bad_finalized_c_refuses":true,
            "warm_c_and_body_reauthenticated":true,"missing_c_refuses":true,"history_none_does_not_inherit":true,
            "changed_foreign_signature_full_refusal":true,"errors_disable_witness":true,
            "helper_trust_binding_miss_and_refusal":true,"helper_destination_refuses":true,
            "authentic_two_qc_native_control":true,"two_qc_builder_two":true,"first_covering_wrapper_preserved":true,
            "current_incident_refuses_helper_and_constructor":true,"refusal_inventory_unchanged":true,"no_import_credit":true,
            "c1_certificate_fixture":true,"ordinary_service":false,"owner_payment_qualified":false,
            "fresh_process_cold":false,"independent_qualification":false
        })
    );
    // Preserve all files including the genuine incident. No repair or reopen.
}
