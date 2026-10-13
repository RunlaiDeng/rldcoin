//! One fresh direct receive measurement, not owner-payment or scheduling qualification.
use super::negative_seams::Target;
use super::*;
use crate::bft::{Context, Request};
use crate::bft_runtime_archive::Archive;

fn check(deadline: f64) {
    assert!(
        now() < deadline,
        "original 30-second onward receive observation exhausted"
    );
}
fn measurement(probe: Value) -> Value {
    assert_eq!(probe["success"], true, "actual receive failed: {probe}");
    assert!(probe["error"].is_null());
    let started = probe["started_at"].as_f64().unwrap();
    let ended = probe["completed_at"].as_f64().unwrap();
    let seconds = probe["seconds"].as_f64().unwrap();
    assert!(started.is_finite() && ended.is_finite() && ended > started);
    assert!(seconds.is_finite() && seconds > 0.0);
    assert_eq!(ended - started, seconds);
    let cost = &probe["complete_onward_execution"];
    assert_eq!(cost["complete"], true, "incomplete execution observation");
    let calls = cost["calls"].as_u64().unwrap();
    let successful = cost["successful"].as_u64().unwrap();
    assert_eq!(cost["failed"], 0);
    assert_eq!(calls, successful);
    assert!(calls > 0, "complete proof execution was not observed");
    assert_eq!(
        cost["max_depth"], 1,
        "nested execution cannot be a pure service share"
    );
    let closure_seconds = cost["outermost_seconds"].as_f64().unwrap();
    let pure_count = cost["verification_calls"].as_u64().unwrap();
    let pure_seconds = cost["verification_seconds"].as_f64().unwrap();
    assert!(closure_seconds.is_finite() && closure_seconds >= 0.0 && closure_seconds <= seconds);
    assert!(
        pure_count > 0 && pure_count <= calls,
        "pure verification was not observed"
    );
    assert!(pure_seconds.is_finite() && pure_seconds >= 0.0 && pure_seconds <= closure_seconds);
    let ratio = closure_seconds / seconds;
    let pure_ratio = pure_seconds / seconds;
    json!({"complete":true,"invocation_count":calls,"successful_count":successful,
        "seconds":seconds,"closure_seconds":closure_seconds,"ratio":ratio,
        "pure_verification_count":pure_count,"pure_verification_seconds":pure_seconds,
        "pure_verification_ratio":pure_ratio,
        "hypothesis_supported":pure_count>=2 && pure_ratio>=0.25,"probe":probe})
}

#[test]
#[ignore = "one fresh 30-second complete-history receive observation"]
fn onward_receive_measures_complete_closure_execution() {
    run(false);
}

#[test]
#[ignore = "one fresh 30-second complete-history receive witness component"]
fn onward_receive_reuses_exact_closure_only_within_each_call() {
    run(true);
}

fn run(reuse: bool) {
    let started = now();
    let deadline = started + 30.0;
    let (root, bootstrap, proof, a80, b4, export) = ancestors();
    check(deadline);
    let currency = bootstrap.currency.id().unwrap();
    let c = proof.history.destination;
    let mut target = Target::new(&root, "receive-observation-target", &bootstrap, c);
    assert!(target
        .actor
        .as_ref()
        .unwrap()
        .fixture_retained_ids()
        .is_empty());

    // A second configured validator's original Agent signs the input; it never
    // retains the body in this receiver's Runtime. Both custody heads start at C0.
    let mut seeds = (2u8..6).collect::<Vec<_>>();
    seeds.sort_by_key(|seed| public(*seed));
    let seed = seeds[1];
    let sender = dir(&root.join("receive-observation-sender"));
    let signer = sender.join("signer");
    let original = Agent::create(&signer, &target.node, public(seed)).unwrap();
    assert_eq!(original.journal.creation.pin.height, 0);
    assert!(original.journal.records.is_empty());
    let initial = bft_client::State {
        format: bft_client::ONWARD_FORMAT.into(),
        binding: original.journal.binding.clone(),
        head: original.head().unwrap(),
        pending: None,
        outbox: None,
    };
    drop(original);
    let caller_path = dir(&sender.join("caller")).join("head.json");
    new_json(&caller_path, &initial);
    let key_path = sender.join("key.json");
    new_json(&key_path, &json!({"secret_key":hex::encode([seed;32])}));

    // An actual authenticated empty C1 suffices for the input's local parent.
    // This uses the public certificate fixture factory, not Runtime consensus.
    // No C2 certificate, Import execution, owner coin or maturity is fabricated.
    let c1 = certified_with_commands(&target.node.paged_replay.as_ref().unwrap().replay, vec![]);
    target.node.finalize(c1.clone()).unwrap();
    assert_eq!(target.node.chain.height(), 1);
    assert_eq!(
        target
            .node
            .accept_complete_onward_network_history(proof.clone())
            .unwrap(),
        b4
    );
    target
        .node
        .require_retained_onward_material(Some(&proof), std::slice::from_ref(&c1))
        .unwrap();
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
    check(deadline);

    let caller = bft_client::Client::lock(
        &caller_path,
        &signer,
        public(seed),
        bft_client::ONWARD_FORMAT.into(),
        &target.node,
    )
    .unwrap();
    assert_eq!(caller.read().unwrap(), initial);
    let request = Request::Timeout {
        context: Context::current(&target.node).unwrap(),
        round: 0,
    };
    let mut consent = initial.clone();
    consent.pending = Some(request.clone());
    let (consent, mut original) = caller
        .store_pending_for_sign(
            &target.node,
            bft_client::Transition {
                previous_sha256: sha(&files::canonical(&initial).unwrap()),
                proposed: consent,
            },
        )
        .unwrap();
    let signed = original
        .sign(&target.node, request, Some(&key_path), initial.head)
        .unwrap();
    assert!(!signed.recovered_exact_retry);
    assert_ne!(signed.head, initial.head);
    drop(original);
    let message = signed.message.clone();
    let mut response = consent.clone();
    response.pending = None;
    response.head = signed.head;
    response.outbox = Some(signed.message);
    let response = caller
        .store(
            &target.node,
            bft_client::Transition {
                previous_sha256: sha(&files::canonical(&consent).unwrap()),
                proposed: response,
            },
        )
        .unwrap();
    assert_eq!(caller.read().unwrap(), response);
    drop(caller);
    assert!(
        matches!(&message, Message::Timeout(vote) if vote.context.parent_height==1 && vote.round==0)
    );

    let envelope = net::Envelope {
        format: net::FORMAT.into(),
        currency,
        region: c,
        history: Some(proof.clone()),
        evidence: Evidence {
            snapshots: vec![c1.clone()],
        },
        body: Body::Signed(Box::new(message)),
    };
    let envelope_id = envelope.verify(&target.node).unwrap();
    let wire_value = serde_json::to_value(envelope.pack().unwrap()).unwrap();
    let wire_bytes = files::canonical_with_limit(&wire_value, crate::contact::MAX_PAYLOAD).unwrap();
    let body_id = sha(&files::canonical(&wire_value["body"]).unwrap());
    let raw = strict_frame(envelope);
    let raw_sha = sha(&raw);
    let native_head = target.node.storage_head().unwrap();
    let native_tip = target.node.chain.tip().unwrap();
    let ledger = target.node.chain.ledger.clone();
    let state_path = target.root.join("runtime-0/state.json");
    let before_state = fs::read(&state_path).unwrap();
    assert!(Archive::decode(&before_state)
        .unwrap()
        .runtime
        .messages
        .is_empty());
    let before = inventory(&target.root);
    let sender_before = inventory(&sender);
    check(deadline);

    let first_probe = target
        .actor
        .as_mut()
        .unwrap()
        .probe_fixture_receive(&mut target.node, &raw)
        .unwrap();
    let new_custody = measurement(first_probe);
    if reuse {
        assert_eq!(new_custody["pure_verification_count"], 1);
    }
    check(deadline);
    assert_eq!(
        target.actor.as_ref().unwrap().fixture_retained_ids(),
        vec![body_id]
    );
    let first_state = fs::read(&state_path).unwrap();
    assert_ne!(first_state, before_state);
    let archive = Archive::decode(&first_state).unwrap();
    assert_eq!(archive.runtime.messages.len(), 1);
    let retained = &archive.runtime.messages[&body_id];
    assert!(!retained.local);
    assert!(retained.value.is_none());
    assert_eq!(retained.sha256, sha(&wire_bytes));
    assert_eq!(retained.size_bytes, wire_bytes.len());
    assert_eq!(archive.envelope(retained).unwrap(), wire_value);
    let after_first = inventory(&target.root);
    let mut old_other = before.clone();
    let mut new_other = after_first.clone();
    assert!(old_other.remove(&state_path).is_some());
    assert!(new_other.remove(&state_path).is_some());
    assert_eq!(
        old_other, new_other,
        "new custody changed non-archive files"
    );
    assert_eq!(target.node.storage_head().unwrap(), native_head);
    assert_eq!(target.node.chain.tip().unwrap(), native_tip);
    assert_eq!(target.node.chain.ledger, ledger);
    assert_eq!(
        target
            .node
            .complete_onward_network_pending_imports()
            .unwrap(),
        pending
    );
    assert_eq!(inventory(&sender), sender_before);
    check(deadline);

    let duplicate_probe = target
        .actor
        .as_mut()
        .unwrap()
        .probe_fixture_receive(&mut target.node, &raw)
        .unwrap();
    let duplicate = measurement(duplicate_probe);
    if reuse {
        assert_eq!(duplicate["pure_verification_count"], 1);
    }
    check(deadline);
    assert_eq!(sha(&raw), raw_sha);
    assert_eq!(
        target.actor.as_ref().unwrap().fixture_retained_ids(),
        vec![body_id]
    );
    assert_eq!(fs::read(&state_path).unwrap(), first_state);
    assert_eq!(
        inventory(&target.root),
        after_first,
        "exact retry changed receiver bytes or mtimes"
    );
    assert_eq!(inventory(&sender), sender_before);
    assert_eq!(target.node.storage_head().unwrap(), native_head);
    assert_eq!(target.node.chain.tip().unwrap(), native_tip);
    assert_eq!(target.node.chain.height(), 1);
    assert_eq!(target.node.chain.ledger, Ledger::default());
    assert_eq!(
        target
            .node
            .complete_onward_network_pending_imports()
            .unwrap(),
        pending
    );
    target
        .node
        .require_retained_onward_material(Some(&proof), std::slice::from_ref(&c1))
        .unwrap();
    check(deadline);
    let elapsed = now() - started;
    assert!(elapsed < 30.0);
    let marker = if reuse {
        "onward_receive_witness_result"
    } else {
        "onward_receive_observation_result"
    };
    eprintln!(
        "{marker}={}",
        json!({
        "root":root,"elapsed_seconds":elapsed,"passed":true,
        "new_custody":new_custody,"duplicate":duplicate,
        "hypothesis_supported":new_custody["hypothesis_supported"],
        "currency":currency,"region":c,"origin_anchor":a80,"intermediate_anchor":b4,
        "envelope_id":envelope_id,"frame_sha256":raw_sha,"body_id":body_id,
        "one_preinstalled_exact_wrapper":true,"local_parent_height":1,
        "source_original_c0_agent":true,"receiver_original_c0_agent":true,
        "new_archive_records":1,"exact_duplicate_inventory_unchanged":true,
        "native_and_caller_unchanged":true,"no_import_credit":true,
        "c1_certificate_fixture":true,"ordinary_service":false,"owner_payment_qualified":false,
        "fresh_process_cold":false,"independent_qualification":false})
    );
    // Preserve every fresh fixture file on success and failure for the controller seal.
}
