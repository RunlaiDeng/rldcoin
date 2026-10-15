//! Isolated fresh counterexample: capture deferral can precede an ordinary Timeout.
//! No scheduler, cursor, threshold, timeout, signing or receive override is installed.
use super::*;

#[test]
#[ignore = "one fresh original ten-second actual Mesh capture/Timeout counterexample; no payment"]
fn durable_proposal_capture_defer_precedes_original_timeout() {
    assert_eq!(
        std::env::var("RLD_CAPTURE_DEFER_COUNTEREXAMPLE").as_deref(),
        Ok("1")
    );
    let started = clock();
    let deadline = started + 10.0;
    let mut f = fresh("capture-defer");
    let source_sha256 = hex::encode(Sha256::digest(include_bytes!("bft_capture_defer_tests.rs")));
    let scope = json!({"format":"RLD-CAPTURE-DEFER-COUNTEREXAMPLE-V1",
        "case":"durable-proposal-before-timeout-late-capture","root":f.root,
        "pid":std::process::id(),"started":started,"deadline":deadline,
        "scope_seconds":10,"external_stop_seconds":15,
        "regional_build_source_sha256":env!("RLD_REGIONAL_SOURCE"),
        "test_source_sha256":source_sha256,"fixture_only":true,"no_value":true,
        "owner_requests":0,"native_authority":false,"signing_authority":false,"mainnet":false});
    metadata(&f.root, "capture-defer-scope.json", &scope);
    eprintln!("capture_defer_counterexample_scope={scope}");
    let observer_root = directory(&f.root.join("observation")).unwrap();
    use crate::contact_runtime::service::{self, native_observation as observation};
    let instance = random().unwrap();
    let observer = observation::fixture_start(
        true,
        &observer_root,
        &instance,
        f.currency,
        f.region,
        &f.node_id,
    )
    .unwrap()
    .unwrap();
    // The real nonleader Runtime starts its unchanged original five-second clock.
    observation::fixture_begin_turn(clock()).unwrap();
    f.runtime.as_mut().unwrap().tick(&mut f.node).unwrap();
    observation::fixture_end_turn(&Ok(json!({}))).unwrap();
    assert_eq!(f.runtime.as_ref().unwrap().last_decision, Some("idle"));
    let entered = f.runtime.as_ref().unwrap().entered;
    let context = consensus::Context::current(&f.node).unwrap();
    let mut seeds = [2u8, 3, 4, 5];
    seeds.sort_by_key(|seed| public(*seed));
    let keys = seeds.iter().map(|seed| public(*seed)).collect::<Vec<_>>();
    let leader = consensus::leader(&context, 0, &keys).unwrap();
    assert_ne!(f.key, leader);
    let leader_index = keys.iter().position(|key| key == &leader).unwrap();
    let leader_signer = f.root.join("leader-signer");
    let leader_key = f.root.join("leader-key.json");
    create_json(
        &leader_key,
        &json!({"secret_key":hex::encode([seeds[leader_index];32])}),
    );
    let snapshot = f
        .runtime
        .as_ref()
        .unwrap()
        .candidate(&f.node, &context, None)
        .unwrap();
    let mut agent = consensus::Agent::create(&leader_signer, &f.node, leader).unwrap();
    let initial_leader_head = agent.head().unwrap();
    let signed = agent
        .sign(
            &f.node,
            consensus::Request::Propose {
                round: 0,
                timeout: None,
                snapshot: Box::new(snapshot),
            },
            Some(&leader_key),
            initial_leader_head,
        )
        .unwrap();
    let consensus::Message::Proposal(proposal) = signed.message.clone() else {
        panic!("actual leader Agent returned a nonproposal");
    };
    assert_eq!(proposal.context().unwrap(), context);
    assert_eq!(proposal.round, 0);
    assert_eq!(agent.record_count(), 1);
    drop(agent);
    // Independent third admitted signer: actual current-round Native eligibility,
    // with its own private key and separately retained caller; never fed to Runtime.
    let control_index = keys
        .iter()
        .position(|key| key != &f.key && key != &keys[leader_index])
        .unwrap();
    let control_key = keys[control_index].clone();
    let control_signer = f.root.join("control-signer");
    let control_key_file = f.root.join("control-key.json");
    create_json(
        &control_key_file,
        &json!({"secret_key":hex::encode([seeds[control_index];32])}),
    );
    let control_agent =
        consensus::Agent::create(&control_signer, &f.node, control_key.clone()).unwrap();
    let control_initial = bft_client::State {
        format: bft_client::ONWARD_FORMAT.into(),
        binding: control_agent.journal.binding.clone(),
        head: control_agent.head().unwrap(),
        pending: None,
        outbox: None,
    };
    let control_initial_head = control_initial.head;
    drop(control_agent);
    let control_caller_path = directory(&f.root.join("control-caller"))
        .unwrap()
        .join("head.json");
    create_json(&control_caller_path, &control_initial);
    let control_caller = bft_client::Client::lock(
        &control_caller_path,
        &control_signer,
        control_key.clone(),
        bft_client::ONWARD_FORMAT.into(),
        &f.node,
    )
    .unwrap();
    let control_request = consensus::Request::Prepare(proposal.clone());
    let mut control_pending = control_initial.clone();
    control_pending.pending = Some(control_request.clone());
    let (control_pending, mut control_agent) = control_caller
        .store_pending_for_sign(
            &f.node,
            bft_client::Transition {
                previous_sha256: state_hash(&control_initial).unwrap(),
                proposed: control_pending,
            },
        )
        .unwrap();
    let control_signed = control_agent
        .sign(
            &f.node,
            control_request.clone(),
            Some(&control_key_file),
            control_initial_head,
        )
        .unwrap();
    assert!(!control_signed.recovered_exact_retry);
    assert!(
        matches!(&control_signed.message, consensus::Message::Vote(v)
        if v.phase == consensus::Phase::Prepare && v.round == 0
        && v.context == context && v.approval.key == control_key)
    );
    assert_eq!(control_agent.record_count(), 1);
    let positive_caller_final_head = control_signed.head;
    let control_message = control_signed.message.clone();
    drop(control_agent);
    let mut control_response = control_pending.clone();
    control_response.pending = None;
    control_response.head = control_signed.head;
    control_response.outbox = Some(control_signed.message);
    let control_response =
        Runtime::publish_head(&control_caller, &f.node, &control_pending, control_response)
            .unwrap();
    assert_eq!(control_caller.read().unwrap(), control_response);
    assert!(control_response.pending.is_none());
    assert_eq!(control_response.outbox, Some(control_message.clone()));
    assert_ne!(control_response.head, control_initial_head);
    drop(control_caller);
    let (control_agent, control_status, control_retry) =
        consensus::Agent::inspect_with_response_status(
            &control_signer,
            &f.node,
            &control_request,
            control_initial_head,
        )
        .unwrap();
    assert_eq!(control_agent.record_count(), 1);
    assert_eq!(control_status.head, positive_caller_final_head);
    assert_eq!(control_retry.unwrap().message, control_message);
    drop(control_agent);
    let positive_prepared_at = clock();
    assert!(
        positive_prepared_at < entered + 5.0,
        "positive control missed original round clock"
    );
    let wire = Wire::local(
        net::Body::Signed(Box::new(signed.message)),
        &f.node,
        bft_client::ONWARD_FORMAT,
    )
    .unwrap();
    wire.verify(&f.node).unwrap();
    let payload =
        files::canonical_with_limit(&wire.wire_value().unwrap(), crate::contact::MAX_PAYLOAD)
            .unwrap();
    let payload_hash = Hash(Sha256::digest(&payload).into());
    let mut frame = Frame {
        format: crate::contact::FRAME_FORMAT.into(),
        kind: "regional-bft".into(),
        source_chain_id: f.region,
        destination_chain_id: f.region,
        export_id: payload_hash,
        payload_sha256: payload_hash,
        payload_b64: STANDARD.encode(payload),
        message_id: Hash::ZERO,
    };
    frame.message_id = frame.message().unwrap();
    let raw = files::canonical_with_limit(&frame, crate::contact::MAX_FRAME).unwrap();
    let sender_root = f.root.join("sender-transport");
    let sender_identity = initialize(
        &sender_root,
        &f.currency.to_hex(),
        &f.region.to_hex(),
        "public-no-value-capture-defer",
    )
    .unwrap();
    let sender_id = sender_identity["node_id"].as_str().unwrap().to_owned();
    let to_recipient = f.root.join("spool-sender-recipient");
    let to_sender = f.root.join("spool-recipient-sender");
    let sender_config = json!({"format":MESH,"network":f.currency,"state":sender_root,
        "contacts":[{"peer":f.node_id,"inbox":to_sender,"outbox":to_recipient}]});
    f.transport["contacts"] = json!([{"peer":sender_id,"inbox":to_recipient,"outbox":to_sender}]);
    let mut sender = Node::open(&sender_config).unwrap();
    let packet = sender.enqueue(&raw, &f.node_id).unwrap();
    let bundle = sender.prepare(&f.node_id).unwrap();
    drop(sender);
    let mut held = Node::open(&f.transport).unwrap();
    let retained = held.receive(&bundle, &sender_id).unwrap();
    assert_eq!(retained, vec![packet.clone()]);
    assert_eq!(
        held.frame_page_selected(None, 4, &[]).unwrap(),
        vec![(packet.clone(), raw.clone())]
    );
    let held_at = clock();
    assert!(
        held_at < entered + 5.0,
        "construction missed original live clock"
    );
    let Fresh {
        root,
        node,
        mut runtime,
        transport,
        config,
        signer,
        caller,
        initial_caller,
        key,
        node_id: _,
        currency,
        region: _,
        native_head,
    } = f;
    drop(node);
    let options = service::Options {
        ledger: root.join("ledger"),
        authority: public(1),
        currency,
        mesh_config: None,
        bft_config: None,
        listen: "127.0.0.1:0".parse().unwrap(),
        miner: None,
        interval: 0.5,
        insecure_tcp: false,
    };
    let mut cursor = None;
    let mut seen = Vec::new();
    while clock() < entered + 5.0 {
        within(deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    within(deadline);
    observation::fixture_begin_turn(clock()).unwrap();
    let deferred = service::tick_ledger(&options, &transport, &mut runtime, &mut cursor, &mut seen);
    observation::fixture_end_turn(&deferred).unwrap();
    let error = match deferred {
        Ok(_) => panic!("held post-Native Mesh must refuse"),
        Err(error) => error,
    };
    assert!(error.starts_with(&format!("CONTACT_STORAGE_IO:{}:", libc::EWOULDBLOCK)));
    assert_eq!(runtime.as_ref().unwrap().last_decision, Some("timeout"));
    assert!(cursor.is_none() && seen.is_empty());
    let cold = Store::open_pinned(&options.ledger, &public(1), currency, native_head).unwrap();
    let timeout_request = consensus::Request::Timeout {
        context: context.clone(),
        round: 0,
    };
    let (agent, status, response) = consensus::Agent::inspect_with_response_status(
        &signer,
        &cold,
        &timeout_request,
        initial_caller.head,
    )
    .unwrap();
    assert_eq!(agent.record_count(), 1);
    assert_eq!(status.state.round, 1);
    let response = response.unwrap();
    assert!(response.recovered_exact_retry);
    let timeout_message = response.message.clone();
    let timeout_head = status.head;
    drop(agent);
    let c = bft_client::Client::lock(
        &caller,
        &signer,
        key.clone(),
        bft_client::ONWARD_FORMAT.into(),
        &cold,
    )
    .unwrap();
    let caller_after_timeout = c.read().unwrap();
    assert_eq!(caller_after_timeout.head, timeout_head);
    assert!(caller_after_timeout.pending.is_none() && caller_after_timeout.outbox.is_none());
    drop(c);
    assert_eq!(
        runtime.as_ref().unwrap().fixture_controls().unwrap(),
        vec![timeout_message.clone()]
    );
    drop(cold);
    drop(held);
    let released_at = clock();
    within(deadline);
    observation::fixture_begin_turn(clock()).unwrap();
    let captured = service::tick_ledger(&options, &transport, &mut runtime, &mut cursor, &mut seen);
    observation::fixture_end_turn(&captured).unwrap();
    let captured = captured.unwrap();
    assert_eq!(captured["transport_receive_deferred"], false);
    assert_eq!(cursor, Some(packet.clone()));
    assert_eq!(seen, vec![packet.clone()]);
    let controls = runtime.as_ref().unwrap().fixture_controls().unwrap();
    assert!(controls.contains(&consensus::Message::Proposal(proposal.clone())));
    assert!(controls.contains(&timeout_message));
    assert!(!controls.iter().any(|message| matches!(message,
        consensus::Message::Vote(v) if v.approval.key == key && v.round == 0
          && v.phase == consensus::Phase::Prepare && v.context == context)));
    drop(runtime.take());
    // Compare only Native ledger and target signer/caller/Runtime custody.
    // Observer output and independent positive-control files are outside this set.
    let selected_inventory = |root: &Path| {
        let mut selected = BTreeMap::new();
        for name in ["ledger", "signer", "caller", "runtime"] {
            selected.extend(inventory(&root.join(name)));
        }
        selected
    };
    let cold_before = selected_inventory(&root);
    observer.finish(true).unwrap();
    let rows = fs::read_to_string(observer_root.join("native-schedule-events.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    let phase_rows = rows
        .iter()
        .filter(|row| row["phase"].as_str().unwrap().starts_with("bft-timeout-"))
        .collect::<Vec<_>>();
    assert_eq!(phase_rows.len(), 14);
    assert_eq!(
        phase_rows
            .iter()
            .map(|row| row["phase"].as_str().unwrap())
            .collect::<Vec<_>>(),
        PHASES
    );
    assert!(phase_rows
        .iter()
        .all(|row| row["turn"] == 2 && row["detail"] == json!({"process_stop_requested":false})));
    assert!(rows.iter().any(|row| row["turn"] == 2
        && row["phase"] == "mesh-receive-completed"
        && row["detail"]["deferred"] == true
        && row["detail"]["frame_count"] == 0));
    assert_eq!(
        rows.iter()
            .filter(|row| row["phase"] == "native-frame-completed"
                && row["detail"]["packet_id"] == packet
                && row["detail"]["frame_id"] == serde_json::to_value(frame.message_id).unwrap()
                && row["detail"]["runtime_present"] == true
                && row["turn"] == 3)
            .count(),
        1
    );
    // Actual Native first-sign refusal; no synthetic state or repair.
    let cold = Store::open_pinned(&options.ledger, &public(1), currency, native_head).unwrap();
    let (mut agent, status) = consensus::Agent::inspect_with_status(&signer, &cold).unwrap();
    let signed_before = agent.retained_messages(&cold).unwrap();
    assert!(signed_before.contains(&timeout_message));
    let before_head = status.head;
    let late = agent.sign(
        &cold,
        consensus::Request::Prepare(proposal),
        Some(&root.join("key.json")),
        before_head,
    );
    let late_error = match late {
        Ok(_) => panic!("old-round first-sign unexpectedly authorized"),
        Err(error) => error,
    };
    assert_eq!(late_error, "BFT old/exhausted round");
    assert_eq!(agent.head().unwrap(), before_head);
    assert_eq!(agent.retained_messages(&cold).unwrap(), signed_before);
    drop(agent);
    let c = bft_client::Client::lock(
        &caller,
        &signer,
        key,
        bft_client::ONWARD_FORMAT.into(),
        &cold,
    )
    .unwrap();
    assert!(c.read().unwrap().pending.is_none() && c.read().unwrap().outbox.is_none());
    drop(c);
    let reopened = Runtime::open(&config, &cold, &transport).unwrap();
    assert_eq!(reopened.fixture_controls().unwrap(), controls);
    assert_eq!(cold.chain.height(), 0);
    assert_eq!(cold.storage_head().unwrap(), native_head);
    assert!(
        cold.chain.ledger.coins.is_empty()
            && cold.chain.ledger.exports.is_empty()
            && cold.chain.ledger.imports.is_empty()
    );
    assert_eq!(cold.chain.ledger.minted, Amount::ZERO);
    drop(reopened);
    drop(cold);
    assert_eq!(selected_inventory(&root), cold_before);
    within(deadline);
    let ended = clock();
    let result = json!({"format":"RLD-CAPTURE-DEFER-COUNTEREXAMPLE-V1","root":root,
        "passed":true,"pid":std::process::id(),"started":started,"ended":ended,
        "deadline":deadline,"elapsed_seconds":ended-started,"test_source_sha256":source_sha256,
        "entered_at":entered,"held_at":held_at,"released_at":released_at,
        "packet_id":packet,"frame_id":frame.message_id,"timeout_steps":14,
        "late_prepare_error":late_error,"actual_mesh_defer":true,
        "timeout_durable":true,"late_proposal_retained":true,"new_r0_prepare_absent":true,
        "positive_prepare_signed":true,"positive_caller_initial_head":control_initial_head,
        "positive_caller_final_head":positive_caller_final_head,
        "positive_prepared_at":positive_prepared_at,"cold_inventory_unchanged":true,
        "cursor_seen_unchanged_during_defer":true,"native_height":0,"native_value_zero":true,
        "scope_seconds":10,"external_stop_seconds":15,"round_timeout_seconds":5,
        "regional_build_source_sha256":env!("RLD_REGIONAL_SOURCE"),
        "payment_qualified":false,"mainnet":false});
    metadata(&root, "capture-defer-result.json", &result);
    eprintln!("capture_defer_counterexample_result={result}");
    within(deadline);
}
