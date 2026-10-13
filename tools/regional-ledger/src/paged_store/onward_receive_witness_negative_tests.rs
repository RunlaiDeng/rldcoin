//! Fresh receive-witness refusal seams; no owner payment or cold qualification.
use super::negative_seams::{authentic_alternate_a80, Target};
use super::queue_negative::authentic_wrapper_variant;
use super::*;
use crate::bft::{Context, Request};
use crate::bft_onward_network::{execution_cost, ReceiveWitness};

fn check(deadline: f64) {
    assert!(
        now() < deadline,
        "original 60-second receive witness negatives exhausted"
    );
}
fn measured(
    envelope: &net::Envelope,
    node: &Store,
    witness: &mut ReceiveWitness,
    expected_pure: u64,
) -> Result<Hash> {
    let scope = execution_cost::Scope::begin();
    let result = envelope.verify_with_receive(node, witness);
    let cost = scope.finish();
    assert!(cost.complete);
    assert_eq!(cost.calls, cost.successful + cost.failed);
    assert!(cost.max_depth <= 1);
    assert_eq!(cost.verification_calls, expected_pure);
    assert!(cost.verification_seconds.is_finite());
    if result.is_ok() {
        assert_eq!(cost.failed, 0);
        assert_eq!(cost.calls, cost.successful);
    }
    result
}
fn warm(envelope: &net::Envelope, node: &Store, ident: Hash) -> ReceiveWitness {
    let mut witness = ReceiveWitness::new();
    assert_eq!(measured(envelope, node, &mut witness, 1).unwrap(), ident);
    assert_eq!(measured(envelope, node, &mut witness, 0).unwrap(), ident);
    witness
}
fn refuse(
    label: &str,
    valid: &net::Envelope,
    invalid: &net::Envelope,
    node: &Store,
    ident: Hash,
    pure: u64,
) {
    let mut witness = warm(valid, node, ident);
    let expected = invalid.verify(node).unwrap_err();
    assert_eq!(
        measured(invalid, node, &mut witness, pure).unwrap_err(),
        expected,
        "{label}"
    );
    // A failed complete envelope cannot publish an authorization seed. This
    // witness must remain disabled rather than reusing even its former entry.
    assert_eq!(measured(valid, node, &mut witness, 1).unwrap(), ident);
    assert_eq!(measured(valid, node, &mut witness, 1).unwrap(), ident);
}

#[test]
#[ignore = "one fresh 60-second receive witness refusal component"]
fn onward_receive_witness_refuses_altered_authority_and_rechecks_safety() {
    let started = now();
    let deadline = started + 60.0;
    let (root, bootstrap, proof, _, b4, export) = ancestors();
    check(deadline);
    let mut target = Target::new(
        &root,
        "receive-witness-negatives",
        &bootstrap,
        proof.history.destination,
    );
    // C1 is an authenticated empty fixture certificate, not Runtime consensus.
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
    assert!(matches!(&message, Message::Timeout(v) if v.context.parent_height==1 && v.round==0));
    // This body already has authentic local Runtime custody. A later complete
    // incoming proof still has to authenticate before same-body deduplication.
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
    let ledger = target.node.chain.ledger.clone();
    assert_eq!(ledger, Ledger::default());
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
    let before = inventory(&target.root);
    check(deadline);

    // Full wrapper identity includes every signature, not only checkpoint IDs.
    let mut witness = warm(&valid, &target.node, ident);
    let mut variant = valid.clone();
    variant.history = Some(authentic_wrapper_variant(&proof));
    let variant_id = variant.verify(&target.node).unwrap();
    assert_ne!(variant_id, ident);
    assert_eq!(
        measured(&variant, &target.node, &mut witness, 1).unwrap(),
        variant_id
    );
    assert_eq!(
        measured(&variant, &target.node, &mut witness, 1).unwrap(),
        variant_id
    );
    assert_eq!(
        measured(&valid, &target.node, &mut witness, 0).unwrap(),
        ident
    );
    assert_eq!(inventory(&target.root), before);
    check(deadline);

    // Public verification never sees an explicit receive's retained derivation.
    let scope = execution_cost::Scope::begin();
    assert_eq!(valid.verify(&target.node).unwrap(), ident);
    let public = scope.finish();
    assert!(public.complete);
    assert_eq!(
        (public.verification_calls, public.successful, public.failed),
        (1, 1, 0)
    );
    let mut new_call = ReceiveWitness::new();
    assert_eq!(
        measured(&valid, &target.node, &mut new_call, 1).unwrap(),
        ident
    );
    let mut disabled = ReceiveWitness::with_limit_for_test(0);
    assert_eq!(
        measured(&valid, &target.node, &mut disabled, 1).unwrap(),
        ident
    );
    assert_eq!(
        measured(&valid, &target.node, &mut disabled, 1).unwrap(),
        ident
    );

    // No history is valid for this empty C1 Timeout, but supplies no foreign
    // anchors to an Import body. The latter must fail even with a warm witness.
    let mut no_history = valid.clone();
    no_history.history = None;
    let no_history_id = no_history.verify(&target.node).unwrap();
    assert_eq!(
        measured(&no_history, &target.node, &mut witness, 0).unwrap(),
        no_history_id
    );
    let mut import = valid.clone();
    import.body = Body::Submission(pending.clone());
    import.verify(&target.node).unwrap();
    import.history = None;
    refuse(
        "history None cannot inherit a foreign Import anchor",
        &valid,
        &import,
        &target.node,
        ident,
        0,
    );
    check(deadline);

    let mut missing_c = valid.clone();
    missing_c.evidence.snapshots.clear();
    refuse(
        "certified C1 parent omitted",
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
        "C1 signature cannot reuse foreign authorization",
        &valid,
        &bad_c,
        &target.node,
        ident,
        0,
    );
    let mut bad_body = valid.clone();
    let Body::Signed(message) = &mut bad_body.body else {
        panic!("signed fixture body");
    };
    let Message::Timeout(vote) = message.as_mut() else {
        panic!("timeout fixture body");
    };
    vote.approval.signature = "00".repeat(64);
    refuse(
        "body signature cannot reuse foreign authorization",
        &valid,
        &bad_body,
        &target.node,
        ident,
        0,
    );
    let mut wrong_currency = valid.clone();
    wrong_currency.currency = Hash::ZERO;
    refuse(
        "current envelope domain remains mandatory",
        &valid,
        &wrong_currency,
        &target.node,
        ident,
        0,
    );
    check(deadline);

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
        "changed foreign signature misses and fully refuses",
        &valid,
        &bad_proof,
        &target.node,
        ident,
        1,
    );
    assert_eq!(inventory(&target.root), before);
    assert_eq!(target.node.storage_head().unwrap(), native_head);
    assert_eq!(target.node.chain.ledger, ledger);
    check(deadline);

    // Exercise the real incoming path, not only the pure helper. A complete bad
    // later envelope for an already retained body must not mutate any custody.
    let raw = strict_frame(bad_proof);
    let scope = execution_cost::Scope::begin();
    let error = target
        .actor
        .as_mut()
        .unwrap()
        .receive(&mut target.node, &raw)
        .unwrap_err();
    let rejected = scope.finish();
    assert!(rejected.complete && !error.is_empty());
    assert_eq!((rejected.verification_calls, rejected.failed), (1, 1));
    assert!(target.node.journal.incident_ids.is_empty());
    assert_eq!(inventory(&target.root), before);
    assert_eq!(target.node.storage_head().unwrap(), native_head);
    assert_eq!(target.node.chain.ledger, ledger);
    assert_eq!(
        target
            .node
            .complete_onward_network_pending_imports()
            .unwrap(),
        pending
    );
    check(deadline);

    // Last mutation: a real authenticated A80 conflict is retained after a
    // witness was populated. All subsequent checks see current quarantine.
    let mut warmed_before_incident = warm(&valid, &target.node, ident);
    let alternate = authentic_alternate_a80(&bootstrap, &proof);
    let conflict =
        Conflict::from_snapshots(&proof.history.origin.snapshots[79], &alternate).unwrap();
    target.node.observe_conflict(conflict).unwrap();
    assert_eq!(target.node.journal.incident_ids.len(), 1);
    assert!(target
        .node
        .safety
        .check_region(proof.history.origin.source)
        .is_err());
    assert_eq!(target.node.chain.ledger, ledger);
    let incident_head = target.node.storage_head().unwrap();
    let incident_before = inventory(&target.root);
    let expected = valid.verify(&target.node).unwrap_err();
    assert!(
        expected.contains("operations are quarantined"),
        "{expected}"
    );
    assert_eq!(
        measured(&valid, &target.node, &mut warmed_before_incident, 0).unwrap_err(),
        expected
    );
    assert!(target
        .node
        .complete_onward_network_pending_imports()
        .is_err());
    assert_eq!(target.node.storage_head().unwrap(), incident_head);
    assert_eq!(inventory(&target.root), incident_before);
    assert_eq!(target.node.chain.height(), 1);
    assert_eq!(target.node.chain.ledger, Ledger::default());
    check(deadline);
    eprintln!(
        "onward_receive_witness_negative_result={}",
        json!({
        "root":root,"elapsed_seconds":now()-started,"passed":true,
        "exact_hit":true,"authentic_alternate_qc_misses":true,"first_entry_preserved":true,
        "public_and_new_scope_independent":true,"zero_capacity_full_fallback":true,
        "valid_no_history_control":true,"no_history_import_refuses":true,
        "missing_c_parent_refuses":true,"altered_c_signature_refuses":true,
        "altered_body_signature_refuses":true,"wrong_currency_refuses":true,
        "changed_foreign_signature_full_refusal":true,"errors_disable_witness":true,
        "real_same_body_bad_proof_refuses_unchanged":true,"current_incident_refuses_warm_witness":true,
        "native_and_caller_unchanged_before_incident":true,"no_import_credit":true,
        "c1_certificate_fixture":true,"ordinary_service":false,"owner_payment_qualified":false,
        "fresh_process_cold":false,"independent_qualification":false})
    );
    // Retain this fresh incident and every original file; do not repair or reopen.
}
