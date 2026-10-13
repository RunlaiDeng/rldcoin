//! Explicit single-payment timing observation; never a replacement acceptance cycle.
use super::*;

#[path = "prepare_transport_tests.rs"]
mod prepare_transport;

#[derive(serde::Serialize)]
pub(super) struct PaymentObservation {
    intent: Hash,
    output: Hash,
    height: u64,
    finality: Option<Hash>,
    finality_height: Option<u64>,
    created: Option<u64>,
    created_block: Option<Hash>,
    mature: Option<u64>,
    ready: bool,
    native_verified_at: f64,
}

pub(super) fn observe(options: &Options, intent: Hash) -> Result<PaymentObservation> {
    let node = Store::open_inspection(&options.ledger, &options.authority, options.currency)?;
    let output = crate::id("output", &(intent, 0u32))?;
    let coin = node.chain.ledger.coins.get(&output);
    if let Some(coin) = coin {
        require(
            coin.payment.owner == public(11) && coin.payment.amount == crate::Amount(100),
            "exact payment output changed recipient or amount",
        )?;
    }
    let finality_height = node
        .chain
        .finalized
        .map(|id| node.evidence.snapshot(id).map(|s| s.statement.height))
        .transpose()?;
    let created_block = coin
        .map(|coin| -> Result<Hash> {
            let block = node.block_at(coin.created)?;
            let intents = block
                .commands
                .iter()
                .filter_map(|command| match command {
                    crate::Command::Spend(signed) => Some(signed.intent.id()),
                    _ => None,
                })
                .collect::<Result<Vec<_>>>()?;
            require(
                intents.contains(&intent),
                "exact payment output has no selected native creation command",
            )?;
            block.header.id()
        })
        .transpose()?;
    let view = wallet::view(&node, &public(11))?;
    let ready = coin.is_some_and(|coin| {
        node.chain.height() >= coin.mature
            && finality_height.is_some_and(|height| height >= coin.created)
            && view.coins.iter().any(|owned| {
                owned.id == output
                    && owned.amount == crate::Amount(100)
                    && owned.mature_height == coin.mature
                    && owned.spendable_now
                    && owned.eligible_for_onward_export
                    && !owned.quarantined
            })
    });
    Ok(PaymentObservation {
        intent,
        output,
        height: node.chain.height(),
        finality: node.chain.finalized,
        finality_height,
        created: coin.map(|coin| coin.created),
        created_block,
        mature: coin.map(|coin| coin.mature),
        ready,
        native_verified_at: monotonic()?,
    })
}

fn has_intent(value: &Value, intent: Hash) -> bool {
    value
        .as_array()
        .is_some_and(|ids| ids.contains(&json!(intent)))
}

fn trace_time(value: &Value) -> Result<f64> {
    value
        .as_f64()
        .filter(|at| at.is_finite() && *at >= 0.0)
        .ok_or("payment trace requires a finite original clock".into())
}

fn trace_hash(value: &Value) -> Result<Hash> {
    let id: Hash = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    require(!id.is_zero(), "payment trace identity is absent")?;
    Ok(id)
}

fn validate_event(event: &Value) -> Result<()> {
    let phase = event["phase"]
        .as_str()
        .ok_or("payment trace phase missing")?;
    if !phase.starts_with("payment-") {
        return Ok(());
    }
    trace_time(&event["at"])?;
    if matches!(
        phase,
        "payment-packets-queued" | "payment-transport-prepared"
    ) {
        trace_hash(&event["node_id"])?;
        let packets = event["packets"]
            .as_array()
            .ok_or("payment packet observations missing")?;
        let limit = if phase == "payment-packets-queued" {
            require(!packets.is_empty(), "empty new packet queue observation")?;
            64
        } else {
            trace_hash(&event["peer"])?;
            require(
                trace_time(&event["started"])? <= trace_time(&event["at"])?,
                "prepared exchange starts after completion",
            )?;
            4
        };
        require(packets.len() <= limit, "payment packet observation bound")?;
        let mut ids = std::collections::BTreeSet::new();
        for packet in packets {
            require(
                ids.insert(trace_hash(&packet["packet_id"])?),
                "duplicate payment packet observation",
            )?;
            trace_hash(&packet["frame_id"])?;
            trace_hash(&packet["destination"])?;
        }
    }
    if matches!(
        phase,
        "payment-body-retained" | "payment-envelope-received" | "payment-frame-prepared"
    ) {
        trace_hash(&event["body_id"])?;
    }
    if matches!(
        phase,
        "payment-envelope-received" | "payment-frame-prepared"
    ) {
        trace_hash(&event["frame_id"])?;
    }
    if matches!(event["body"]["kind"].as_str(), Some("prepare" | "commit")) {
        let _: bft::Context =
            serde_json::from_value(event["body"]["context"].clone()).map_err(|e| e.to_string())?;
        require(
            event["body"]["round"].as_u64().is_some(),
            "payment vote round missing",
        )?;
        trace_hash(&event["body"]["value"])?;
        trace_hash(&event["body"]["signer"])?;
    }
    if matches!(phase, "payment-candidate-start" | "payment-candidate-ready") {
        let _: bft::Context =
            serde_json::from_value(event["context"].clone()).map_err(|e| e.to_string())?;
        require(
            event["round"].as_u64().is_some(),
            "payment trace round missing",
        )?;
        trace_hash(&event["leader"])?;
        if !event["high"].is_null() {
            trace_hash(&event["high"])?;
        }
    }
    let snapshot = if phase == "payment-candidate-ready" {
        &event["snapshot"]
    } else {
        &event["body"]["snapshot"]
    };
    if phase == "payment-candidate-ready" || !snapshot.is_null() {
        trace_hash(&snapshot["value"])?;
        trace_hash(&snapshot["block"])?;
        require(
            snapshot["height"].as_u64().is_some(),
            "payment trace height missing",
        )?;
        for id in snapshot["intents"]
            .as_array()
            .ok_or("payment trace intents missing")?
        {
            trace_hash(id)?;
        }
    }
    Ok(())
}

fn completed_candidate(
    sample: &Sample,
    recipient: &PaymentObservation,
    candidate: &Value,
) -> Result<bool> {
    if candidate["contains_original_intent"] != true
        || candidate["snapshot"]["height"].as_u64() != recipient.created
        || candidate["snapshot"]["block"] != json!(recipient.created_block)
        || (recipient.finality_height == recipient.created
            && candidate["snapshot"]["value"] != json!(recipient.finality))
    {
        return Ok(false);
    }
    let start = trace_time(&candidate["started"])?;
    let constructed = trace_time(&candidate["constructed"])?;
    let signed = trace_time(&candidate["signed_proposal_retained"])?;
    let input = trace_time(&candidate["input_native_at"])?;
    trace_hash(&candidate["signed_proposal_body"])?;
    require(sample.submitted <= sample.queued && sample.queued <= input && input <= start
        && start <= constructed && constructed <= signed && signed <= recipient.native_verified_at,
        "payment trace original input, construction and recipient clocks are incomplete or out of order")?;
    Ok(true)
}

fn submission_report(
    root: &Path,
    sample: Option<&Sample>,
    ended: f64,
    ready: bool,
) -> Result<Value> {
    let path = root.join("submission-ledger-3.json");
    if !path.exists() {
        require(
            sample.is_none(),
            "completed submission lost its original clock record",
        )?;
        return Ok(Value::Null);
    }
    let mut recorded = read(&path, 64 * 1024)?;
    let submitted = trace_time(&recorded["submitted"])?;
    trace_hash(&recorded["intent"])?;
    trace_hash(&recorded["input"])?;
    require(
        ended >= submitted,
        "submission report precedes original clock",
    )?;
    if let Some(sample) = sample {
        require(
            recorded["intent"] == json!(sample.intent)
                && recorded["input"] == json!(sample.input)
                && submitted == sample.submitted
                && trace_time(&recorded["queued"])? == sample.queued,
            "submission report differs from original wallet response",
        )?;
    }
    recorded["report_age_seconds"] = json!(ended - submitted);
    recorded["pending_age_seconds"] = if ready {
        Value::Null
    } else {
        json!(ended - submitted)
    };
    Ok(recorded)
}

fn bind_trace(root: &Path, sample: &Sample, recipient: &PaymentObservation) -> Result<Value> {
    require(
        recipient.ready
            && recipient.intent == sample.intent
            && recipient.output == crate::id("output", &(sample.intent, 0u32))?
            && recipient.created.is_some()
            && recipient.created_block.is_some()
            && recipient.finality.is_some(),
        "payment trace has no exact ready native output",
    )?;
    let mut events = Vec::new();
    for actor in 0..4 {
        let trace = read(
            &root.join(format!("carriage-ledger-{actor}.json")),
            4 * 1024 * 1024,
        )?;
        let records = trace["events"]
            .as_array()
            .ok_or("missing payment trace events")?;
        require(records.len() <= 4160, "payment trace bound")?;
        for event in records {
            validate_event(event)?;
        }
        events.extend(records.iter().cloned().map(|event| (actor, event)));
    }
    let (_, submission) = events
        .iter()
        .find(|(actor, event)| {
            *actor == 3
                && event["phase"] == "payment-body-retained"
                && event["local"] == true
                && event["body"]["kind"] == "submission"
                && has_intent(&event["body"]["intents"], sample.intent)
        })
        .ok_or("original submission has no authenticated local retention")?;
    let body_id = &submission["body_id"];
    let retained_at = trace_time(&submission["at"])?;
    require(
        sample.queued >= sample.submitted && retained_at >= sample.queued,
        "local submission clock changed",
    )?;
    let (_, prepared) = events
        .iter()
        .find(|(actor, event)| {
            *actor == 3
                && event["phase"] == "payment-frame-prepared"
                && event["body_id"] == *body_id
        })
        .ok_or("original submission has no prepared carriage frame")?;
    let frame_id = &prepared["frame_id"];
    require(
        trace_time(&prepared["at"])? >= retained_at,
        "submission frame predates native retention",
    )?;
    let mut candidates = Vec::new();
    for (actor, event) in &events {
        if event["phase"] != "payment-candidate-ready" {
            continue;
        }
        let (_, start) = events
            .iter()
            .rev()
            .find(|(peer, start)| {
                peer == actor
                    && start["phase"] == "payment-candidate-start"
                    && start["context"] == event["context"]
                    && start["round"] == event["round"]
                    && start["at"].as_f64() <= event["at"].as_f64()
            })
            .ok_or("candidate completion has no original construction start")?;
        let received = events
            .iter()
            .filter(|(peer, incoming)| {
                peer == actor
                    && incoming["phase"] == "payment-envelope-received"
                    && incoming["frame_id"] == *frame_id
                    && incoming["body_id"] == *body_id
                    && has_intent(&incoming["body"]["intents"], sample.intent)
            })
            .filter_map(|(_, incoming)| incoming["at"].as_f64())
            .min_by(f64::total_cmp);
        let signed = events
            .iter()
            .find(|(peer, signed)| {
                peer == actor
                    && signed["phase"] == "payment-body-retained"
                    && signed["local"] == true
                    && signed["body"]["kind"] == "proposal"
                    && signed["body"]["round"] == event["round"]
                    && signed["body"]["context"] == event["context"]
                    && signed["body"]["leader"] == event["leader"]
                    && signed["body"]["snapshot"] == event["snapshot"]
            })
            .map(|(_, signed)| signed);
        let high_input = if event["high"].is_null() {
            None
        } else {
            events
                .iter()
                .filter(|(peer, incoming)| {
                    peer == actor
                        && incoming["phase"] == "payment-body-retained"
                        && incoming["body"]["kind"] == "proposal"
                        && incoming["body"]["snapshot"]["value"] == event["high"]
                        && incoming["body"]["snapshot"] == event["snapshot"]
                        && incoming["body"]["context"] == event["context"]
                        && has_intent(&incoming["body"]["snapshot"]["intents"], sample.intent)
                })
                .filter_map(|(_, incoming)| incoming["at"].as_f64())
                .min_by(f64::total_cmp)
        };
        let (input_path, input_native_at) = if !event["high"].is_null() {
            ("native-prepared-proposal-retention", high_input)
        } else if *actor == 3 {
            ("local-native-submission-retention", Some(retained_at))
        } else {
            ("original-frame-native-submission-receive", received)
        };
        require(
            candidates.len() < 128,
            "payment candidate observation bound",
        )?;
        candidates.push(
            json!({"actor":actor,"context":event["context"],"round":event["round"],
            "high":event["high"],"started":start["at"],"constructed":event["at"],
            "local_submission_retained":if *actor==3 {submission["at"].clone()} else {Value::Null},
            "original_frame_native_received":received,"snapshot":event["snapshot"],
            "input_path":input_path,"input_native_at":input_native_at,
            "contains_original_intent":has_intent(&event["snapshot"]["intents"],sample.intent),
            "signed_proposal_retained":signed.map(|signed|&signed["at"]),
            "signed_proposal_body":signed.map(|signed|&signed["body_id"])}),
        );
    }
    let matches = candidates
        .iter()
        .map(|candidate| completed_candidate(sample, recipient, candidate))
        .collect::<Result<Vec<_>>>()?;
    require(
        matches.contains(&true),
        "recipient output has no observed exact signed including proposal",
    )?;
    Ok(json!({"submission_body":body_id,"submission_frame":frame_id,"candidates":candidates}))
}

#[test]
fn diagnostic_binding_rejects_missing_clocks_native_input_and_wrong_selected_block() {
    // These are reader metadata cases, not signed evidence or Native authority.
    let sample = Sample {
        intent: Hash([1; 32]),
        input: Hash([2; 32]),
        submitted: 1.0,
        queued: 2.0,
    };
    let recipient = PaymentObservation {
        intent: sample.intent,
        output: crate::id("output", &(sample.intent, 0u32)).unwrap(),
        height: 5,
        finality: Some(Hash([3; 32])),
        finality_height: Some(5),
        created: Some(5),
        created_block: Some(Hash([4; 32])),
        mature: Some(5),
        ready: true,
        native_verified_at: 8.0,
    };
    let good = json!({"contains_original_intent":true,"snapshot":{"height":5,"block":recipient.created_block,
        "value":recipient.finality},"input_native_at":3.0,"started":4.0,"constructed":5.0,
        "signed_proposal_retained":6.0,"signed_proposal_body":Hash([5;32])});
    assert!(completed_candidate(&sample, &recipient, &good).unwrap());
    for field in [
        "input_native_at",
        "started",
        "constructed",
        "signed_proposal_retained",
        "signed_proposal_body",
    ] {
        let mut missing = good.clone();
        missing[field] = Value::Null;
        assert!(
            completed_candidate(&sample, &recipient, &missing).is_err(),
            "missing {field} accepted"
        );
    }
    let mut late = good.clone();
    late["input_native_at"] = json!(4.5);
    assert!(completed_candidate(&sample, &recipient, &late).is_err());
    let mut wrong = good.clone();
    wrong["snapshot"]["block"] = json!(Hash([6; 32]));
    assert!(!completed_candidate(&sample, &recipient, &wrong).unwrap());
    let event = json!({"phase":"payment-frame-prepared","at":3.0,
        "frame_id":Hash([7;32]),"body_id":Hash([8;32])});
    validate_event(&event).unwrap();
    for field in ["at", "frame_id", "body_id"] {
        let mut missing = event.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            validate_event(&missing).is_err(),
            "missing event {field} accepted"
        );
    }
    PAYMENT_TRACE_ACTIVE.with(|active| active.set(false));
    trace_payment_event(|| panic!("disabled payment tracing evaluated its payload")).unwrap();
}

#[test]
fn diagnostic_packet_events_reject_missing_identity_bad_clocks_and_duplicate_packets() {
    let good = json!({"phase":"payment-transport-prepared","node_id":Hash([1;32]),
        "peer":Hash([2;32]),"started":2.0,"at":3.0,"packets":[{
            "packet_id":Hash([3;32]),"frame_id":Hash([4;32]),"destination":Hash([2;32])}]});
    validate_event(&good).unwrap();
    for field in ["node_id", "peer", "started", "at", "packets"] {
        let mut missing = good.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            validate_event(&missing).is_err(),
            "missing {field} accepted"
        );
    }
    for field in ["packet_id", "frame_id", "destination"] {
        let mut missing = good.clone();
        missing["packets"][0].as_object_mut().unwrap().remove(field);
        assert!(
            validate_event(&missing).is_err(),
            "missing {field} accepted"
        );
    }
    let mut late = good.clone();
    late["started"] = json!(4.0);
    assert!(validate_event(&late).is_err());
    let mut duplicate = good.clone();
    duplicate["packets"]
        .as_array_mut()
        .unwrap()
        .push(good["packets"][0].clone());
    assert!(validate_event(&duplicate).is_err());
    let mut queue = good;
    queue["phase"] = json!("payment-packets-queued");
    validate_event(&queue).unwrap();
    queue["packets"] = json!([]);
    assert!(validate_event(&queue).is_err());
}

#[test]
fn diagnostic_failed_reply_keeps_the_saved_original_submission_and_pending_age() {
    let root = directory(
        &fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("rld-payment-report-{}", random().unwrap())),
    )
    .unwrap();
    let file = root.join("submission-ledger-3.json");
    let original = json!({"intent":Hash([1;32]),"input":Hash([2;32]),"submitted":11.0,
        "queued":null,"queue_error":"observed reply unavailable","fixture_only":true});
    atomic(&file, &original, 64 * 1024).unwrap();
    let report = submission_report(&root, None, 17.0, false).unwrap();
    assert_eq!(report["submitted"], 11.0);
    assert_eq!(report["queued"], Value::Null);
    assert_eq!(report["pending_age_seconds"], 6.0);
    assert_eq!(report["queue_error"], original["queue_error"]);
    assert_eq!(read(&file, 64 * 1024).unwrap(), original);
    assert!(submission_report(&root, None, 10.0, false).is_err());
    let wrong = Sample {
        intent: Hash([3; 32]),
        input: Hash([2; 32]),
        submitted: 11.0,
        queued: 12.0,
    };
    assert!(submission_report(&root, Some(&wrong), 17.0, false).is_err());
}

#[test]
#[ignore = "explicit bounded no-value single-payment timing diagnostic; not full-cycle acceptance"]
fn single_payment_keeps_original_clock_and_binds_actual_signed_proposal() {
    let started = monotonic().unwrap();
    let deadline = started + 60.0;
    let root = directory(
        &fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("rld-payment-timing-{}", random().unwrap())),
    )
    .unwrap();
    eprintln!("Fresh single-payment timing diagnostic: {}", root.display());
    let stop = Arc::new(AtomicBool::new(false));
    let failed = Arc::new(AtomicBool::new(false));
    let (workers, seeds, _) = setup_with_timing(
        &root,
        deadline,
        stop.clone(),
        failed.clone(),
        crate::paged_bft::PACKED_RULES,
        true,
    )
    .unwrap();
    let actor_bindings = workers
        .iter()
        .zip(&seeds)
        .map(|(worker, seed)| {
            Ok((
                Hash::from_hex(&public(*seed)).map_err(|e| e.to_string())?,
                worker.transport_identity,
            ))
        })
        .collect::<Result<Vec<_>>>()
        .unwrap();
    let actor_bindings: [(Hash, Hash); 4] = actor_bindings.try_into().unwrap();
    let mut sample = None;
    let mut observations_log = Vec::new();
    let result = (|| -> Result<()> {
        loop {
            if observations(&workers, deadline)?
                .iter()
                .all(|node| node.height >= 3 && node.finalized)
            {
                break;
            }
            thread::sleep(Duration::from_millis(55));
        }
        sample = Some(payment(&workers[3], public(11), None, deadline)?);
        let original = sample.as_ref().ok_or("missing original sample")?;
        loop {
            let (sender, receiver) = mpsc::channel();
            workers[FIRST_RECIPIENT]
                .sender
                .send(Job::ObservePayment {
                    intent: original.intent,
                    reply: sender,
                })
                .map_err(|e| e.to_string())?;
            let observed = wait(receiver, deadline)?;
            require(
                observed.native_verified_at >= original.submitted,
                "recipient observation predates submission",
            )?;
            let ready = observed.ready;
            require(
                observations_log.len() < 256,
                "payment observation count bound",
            )?;
            observations_log.push(observed);
            if ready {
                break;
            }
            thread::sleep(Duration::from_millis(55));
        }
        require(
            monotonic()? < deadline,
            "single payment diagnostic deadline exhausted",
        )
    })();
    stop.store(true, Ordering::Release);
    let mut stopped_heads = Vec::new();
    let mut worker_errors = Vec::new();
    for (actor, worker) in workers.into_iter().enumerate() {
        match worker.thread.join() {
            Ok(Ok(state)) => stopped_heads.push(json!({"actor":actor,"head":state.head})),
            Ok(Err(error)) => worker_errors.push(json!({"actor":actor,"error":error})),
            Err(_) => worker_errors.push(json!({"actor":actor,"error":"wallet actor panicked"})),
        }
    }
    let mut binding = Value::Null;
    let mut prepare_transport = Value::Null;
    let result = result.and_then(|_| {
        require(
            worker_errors.is_empty() && stopped_heads.len() == 4,
            "payment diagnostic actor closure failed",
        )?;
        binding = bind_trace(
            &root,
            sample.as_ref().ok_or("no submission")?,
            observations_log.last().ok_or("no recipient observation")?,
        )?;
        prepare_transport = prepare_transport::bind_prepare_transport(
            &root,
            sample.as_ref().ok_or("no submission")?,
            observations_log.last().ok_or("no recipient observation")?,
            &binding,
            &actor_bindings,
        )?;
        Ok(())
    });
    let ended = monotonic().unwrap();
    let result = result.and_then(|_| {
        require(
            ended < deadline,
            "payment diagnostic closure exceeded original deadline",
        )
    });
    // A failed reply or controller wait can follow a valid signed submission.
    // Retain that original diagnostic clock without reopening any Native store.
    let reported = submission_report(
        &root,
        sample.as_ref(),
        ended,
        observations_log.last().is_some_and(|o| o.ready),
    );
    let submission_error = reported.as_ref().err().cloned();
    let sample = reported.as_ref().ok().cloned().unwrap_or(Value::Null);
    let result = result.and_then(|_| reported.map(|_| ()));
    atomic(
        &root.join("timing-observations.json"),
        &json!({"diagnostic_complete":result.is_ok(),
        "error":result.as_ref().err(),"sample":sample,"observations":observations_log,
        "submission_record_error":submission_error,
        "binding":binding,"prepare_transport":prepare_transport,"actor_bindings":actor_bindings,
        "worker_errors":worker_errors,"stopped_heads":stopped_heads,
        "whole_seconds":ended-started,"recipient_actor":FIRST_RECIPIENT,
        "full_payment_acceptance":false,"second_payment":false,"full_cold_custody":false,
        "latency_percentiles_qualified":false,"independent_operations":false,"fixture_only":true}),
        256 * 1024,
    )
    .unwrap();
    result.unwrap();
}
