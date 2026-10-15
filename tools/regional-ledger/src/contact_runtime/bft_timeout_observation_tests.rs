//! Fresh actual Timeout substeps only; no payment, ordinary Service or liveness claim.
use super::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const FORMAT: &str = "RLD-TIMEOUT-OBSERVATION-FIXTURE-V1";
const ORIGINAL_ERROR: &str =
    "fixture stopped after durable Native signature before caller response";
const PHASES: [&str; 14] = [
    "bft-timeout-action-started",
    "bft-timeout-caller-started",
    "bft-timeout-caller-completed",
    "bft-timeout-pending-started",
    "bft-timeout-pending-completed",
    "bft-timeout-native-sign-started",
    "bft-timeout-native-sign-completed",
    "bft-timeout-response-started",
    "bft-timeout-response-completed",
    "bft-timeout-flush-started",
    "bft-timeout-flush-completed",
    "bft-timeout-action-completed",
    "bft-timeout-persist-started",
    "bft-timeout-persist-completed",
];

struct Fresh {
    root: PathBuf,
    node: Store,
    runtime: Option<Runtime>,
    transport: Value,
    config: PathBuf,
    signer: PathBuf,
    caller: PathBuf,
    initial_caller: bft_client::State,
    key: String,
    node_id: String,
    currency: Hash,
    region: Hash,
    native_head: Hash,
}

fn fresh(case: &str) -> Fresh {
    let root = directory(
        &fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "rld-timeout-observation-{case}-{}",
                random().unwrap()
            )),
    )
    .unwrap();
    let bootstrap = fresh_bootstrap();
    let currency = bootstrap.currency.id().unwrap();
    let region = bootstrap.admissions[2].id().unwrap();
    let node = Store::create(
        &root.join("ledger"),
        bootstrap,
        region,
        &public(1),
        currency,
    )
    .unwrap();
    node.require_onward_network_state().unwrap();
    assert_eq!(node.chain.height(), 0);
    assert!(node.chain.ledger.coins.is_empty());
    assert!(node.chain.ledger.imports.is_empty());
    assert!(node.chain.ledger.exports.is_empty());
    assert_eq!(node.chain.ledger.minted, Amount::ZERO);
    let native_head = node.storage_head().unwrap();
    let mut seeds = [2u8, 3, 4, 5];
    seeds.sort_by_key(|seed| public(*seed));
    let keys = seeds.iter().map(|seed| public(*seed)).collect::<Vec<_>>();
    let context = consensus::Context::current(&node).unwrap();
    let leader = consensus::leader(&context, 0, &keys).unwrap();
    // This finite local fixture selects a configured nonleader; it never changes
    // the validator set, quorum or scheduling rule and is not ordinary scheduling.
    let selected = keys.iter().position(|key| key != &leader).unwrap();
    let mut ids = Vec::new();
    for i in 0..4 {
        let identity = initialize(
            &root.join(format!("transport-{i}")),
            &currency.to_hex(),
            &region.to_hex(),
            "public-no-value-timeout-observer",
        )
        .unwrap();
        ids.push(identity["node_id"].as_str().unwrap().to_owned());
    }
    let transport = json!({"format":MESH,"network":currency,
        "state":root.join(format!("transport-{selected}")),"contacts":[]});
    let signer = root.join("signer");
    let agent = consensus::Agent::create(&signer, &node, keys[selected].clone()).unwrap();
    assert_eq!(agent.record_count(), 0);
    let initial_caller = bft_client::State {
        format: bft_client::ONWARD_FORMAT.into(),
        binding: agent.journal.binding.clone(),
        head: agent.head().unwrap(),
        pending: None,
        outbox: None,
    };
    drop(agent);
    let caller = directory(&root.join("caller")).unwrap().join("head.json");
    create_json(&caller, &initial_caller);
    let key_file = root.join("key.json");
    create_json(
        &key_file,
        &json!({"secret_key":hex::encode([seeds[selected];32])}),
    );
    let archive = directory(&root.join("runtime")).unwrap();
    let config = root.join("config.json");
    create_json(
        &config,
        &json!({"format":bft_client::ONWARD_FORMAT,"state":archive,
        "signer_dir":signer,"head_file":caller,"key_file":key_file,"key":keys[selected],
        "miner":public(12),"validators":keys.iter().enumerate().map(|(i,key)|
            json!({"key":key,"node_id":ids[i]})).collect::<Vec<_>>(),
        "block_interval":0.5,"round_timeout":5.0,"stop_height":1,
        "startup_native_history_head":native_head}),
    );
    let runtime = Some(Runtime::open(&config, &node, &transport).unwrap());
    Fresh {
        root,
        node,
        runtime,
        transport,
        config,
        signer,
        caller,
        initial_caller,
        key: keys[selected].clone(),
        node_id: ids[selected].clone(),
        currency,
        region,
        native_head,
    }
}

fn caller_state(f: &Fresh) -> bft_client::State {
    let caller = bft_client::Client::lock(
        &f.caller,
        &f.signer,
        f.key.clone(),
        bft_client::ONWARD_FORMAT.into(),
        &f.node,
    )
    .unwrap();
    caller.read().unwrap()
}

fn metadata(root: &Path, name: &str, value: &Value) {
    assert!(value
        .as_object()
        .unwrap()
        .values()
        .all(|v| !v.is_array() && !v.is_object()));
    create_json(&root.join(name), value);
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn check_observer(
    root: &Path,
    f: &Fresh,
    instance: &str,
    interrupted: bool,
    expected: &[&str],
) -> usize {
    let scope_raw = fs::read(root.join("native-schedule-scope.json")).unwrap();
    let scope: Value = serde_json::from_slice(&scope_raw).unwrap();
    let raw = fs::read(root.join("native-schedule-events.jsonl")).unwrap();
    assert!(raw.len() <= 8 * 1024 * 1024 && raw.ends_with(b"\n"));
    let rows = raw
        .split(|b| *b == b'\n')
        .filter(|x| !x.is_empty())
        .map(|x| {
            assert!(x.len() <= 256 * 1024);
            serde_json::from_slice::<Value>(x).unwrap()
        })
        .collect::<Vec<_>>();
    assert!(rows.len() <= 16_384);
    let terminal = read_json(&root.join("native-schedule-terminal.json"));
    assert_eq!(scope["format"], "RLD-SERVICE-NATIVE-OBSERVATION-V1");
    assert_eq!(scope["pid"], std::process::id());
    assert_eq!(scope["currency"], serde_json::to_value(f.currency).unwrap());
    assert_eq!(scope["region"], serde_json::to_value(f.region).unwrap());
    assert_eq!(scope["node_id"], f.node_id);
    assert_eq!(scope["instance"], instance);
    assert_eq!(scope["clock"], "local-monotonic-seconds");
    assert_eq!(scope["max_rows"], 16_384);
    assert_eq!(scope["max_bytes"], 8 * 1024 * 1024);
    assert_eq!(scope["max_row_bytes"], 256 * 1024);
    assert_eq!(
        scope["regional_build_source_sha256"],
        env!("RLD_REGIONAL_SOURCE")
    );
    assert_eq!(terminal["format"], scope["format"]);
    assert_eq!(
        terminal["scope_sha256"],
        hex::encode(Sha256::digest(&scope_raw))
    );
    assert_eq!(terminal["events_sha256"], hex::encode(Sha256::digest(&raw)));
    assert_eq!(terminal["complete_rows_sha256"], terminal["events_sha256"]);
    assert_eq!(terminal["complete_rows_match_retained_bytes"], true);
    assert_eq!(terminal["events_bytes"], raw.len());
    assert_eq!(terminal["complete_rows_bytes"], raw.len());
    assert_eq!(terminal["rows"], rows.len());
    assert_eq!(terminal["last_sequence"], rows.len());
    assert_eq!(terminal["turns"], 2);
    assert!(terminal["active_turn"].is_null());
    assert_eq!(terminal["last_phase"], "turn-end");
    assert_eq!(terminal["requested_success"], !interrupted);
    assert_eq!(terminal["success"], !interrupted);
    assert_eq!(terminal["observer_error"], false);
    for item in [&scope, &terminal] {
        for flag in [
            "native_authority",
            "signing_authority",
            "custody_acknowledgment",
            "payment_qualification",
            "independent_freshness_qualified",
        ] {
            assert_eq!(item[flag], false);
        }
        assert_eq!(item["diagnostic_only"], true);
    }
    let mut phases = Vec::new();
    let mut last_at = scope["created_at"].as_f64().unwrap();
    let mut decision_sequence = None;
    let mut timeout_tick_completed = false;
    for (i, row) in rows.iter().enumerate() {
        assert_eq!(row["sequence"], i + 1);
        let at = row["at"].as_f64().unwrap();
        assert!(at.is_finite() && at >= last_at);
        last_at = at;
        let phase = row["phase"].as_str().unwrap();
        if phase == "bft-decision-observed" && row["turn"] == 2 {
            assert_eq!(row["detail"]["decision"], "timeout");
            assert_eq!(row["detail"]["context"]["parent_height"], 0);
            assert_eq!(row["detail"]["round"], 0);
            decision_sequence = Some(i);
        }
        if phase.starts_with("bft-timeout-") {
            assert_eq!(row["turn"], 2);
            assert!(decision_sequence.is_some_and(|n| n < i));
            let detail = row["detail"].as_object().unwrap();
            assert_eq!(detail.len(), 1);
            assert_eq!(detail["process_stop_requested"].as_bool(), Some(false));
            phases.push(phase);
        }
        if phase == "bft-tick-completed" && row["turn"] == 2 {
            timeout_tick_completed = true;
        }
    }
    assert_eq!(phases, expected);
    assert!(decision_sequence.is_some());
    assert_eq!(timeout_tick_completed, !interrupted);
    assert_eq!(terminal["last_at"].as_f64(), Some(last_at));
    let completed = terminal["completed_at"].as_f64().unwrap();
    assert!(completed.is_finite() && completed >= last_at && completed <= clock());
    phases.len()
}

fn run(interrupted: bool) {
    let started = clock();
    let deadline = started + 10.0;
    let case = if interrupted {
        "signed-interrupted"
    } else {
        "complete"
    };
    let mut f = fresh(case);
    within(deadline);
    let scope = json!({"format":FORMAT,"case":case,"root":f.root,"started":started,
        "deadline":deadline,"scope_seconds":10,"external_stop_seconds":15,
        "pid":std::process::id(),"regional_build_source_sha256":env!("RLD_REGIONAL_SOURCE"),
        "owner_requests":0,"fixture_only":true,"native_authority":false,
        "signing_authority":false,"mainnet":false});
    metadata(&f.root, "timeout-observation-scope.json", &scope);
    eprintln!("timeout_observation_scope={scope}");
    let observer_root = directory(&f.root.join("observation")).unwrap();
    let instance = random().unwrap();
    // cfg(test) narrow forwarding API; no writer or authority state exposed.
    use crate::contact_runtime::service::native_observation as observation;
    let guard = observation::fixture_start(
        true,
        &observer_root,
        &instance,
        f.currency,
        f.region,
        &f.node_id,
    )
    .unwrap()
    .unwrap();
    observation::fixture_begin_turn(clock()).unwrap();
    f.runtime.as_mut().unwrap().tick(&mut f.node).unwrap();
    observation::fixture_end_turn(&Ok(json!({}))).unwrap();
    assert_eq!(f.runtime.as_ref().unwrap().last_decision, Some("idle"));
    let entered = f.runtime.as_ref().unwrap().entered;
    while clock() < entered + 5.0 {
        within(deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    within(deadline);
    if interrupted {
        Runtime::fixture_stop_after_next_signature();
    }
    observation::fixture_begin_turn(clock()).unwrap();
    let actual = f.runtime.as_mut().unwrap().tick(&mut f.node);
    let error = actual.as_ref().err().cloned();
    let ended: Result<Value> = actual.map(|()| json!({}));
    observation::fixture_end_turn(&ended).unwrap();
    if interrupted {
        assert_eq!(error.as_deref(), Some(ORIGINAL_ERROR));
    } else {
        assert!(ended.is_ok(), "actual Timeout must complete");
    }
    guard.finish(!interrupted).unwrap();
    within(deadline);
    assert_eq!(f.runtime.as_ref().unwrap().last_decision, Some("timeout"));
    let expected = if interrupted {
        &PHASES[..6]
    } else {
        &PHASES[..]
    };
    let phase_rows = check_observer(&observer_root, &f, &instance, interrupted, expected);
    assert_eq!(f.node.chain.height(), 0);
    assert_eq!(f.node.storage_head().unwrap(), f.native_head);
    assert!(f.node.chain.ledger.coins.is_empty());
    assert!(f.node.chain.ledger.imports.is_empty());
    assert!(f.node.chain.ledger.exports.is_empty());
    assert_eq!(f.node.chain.ledger.minted, Amount::ZERO);
    let request = consensus::Request::Timeout {
        context: consensus::Context::current(&f.node).unwrap(),
        round: 0,
    };
    let (agent, status, response) = consensus::Agent::inspect_with_response_status(
        &f.signer,
        &f.node,
        &request,
        f.initial_caller.head,
    )
    .unwrap();
    assert_eq!(agent.record_count(), 1);
    assert_ne!(status.head, f.initial_caller.head);
    let response = response.unwrap();
    assert!(response.recovered_exact_retry);
    assert!(
        matches!(&response.message,consensus::Message::Timeout(v) if v.round==0 && v.context.parent_height==0)
    );
    let signed_message = response.message.clone();
    let signed_head = status.head;
    drop(agent);
    let caller = caller_state(&f);
    if interrupted {
        assert_eq!(caller.head, f.initial_caller.head);
        assert_eq!(caller.pending, Some(request));
        assert!(caller.outbox.is_none());
        assert!(f
            .runtime
            .as_ref()
            .unwrap()
            .fixture_controls()
            .unwrap()
            .is_empty());
        // Keep this actual signed/pending failure unchanged; no repair/reopen.
    } else {
        assert_eq!(caller.head, signed_head);
        assert!(caller.pending.is_none() && caller.outbox.is_none());
        assert_eq!(
            f.runtime.as_ref().unwrap().fixture_controls().unwrap(),
            vec![signed_message.clone()]
        );
        drop(f.runtime.take());
        let cold = Runtime::open(&f.config, &f.node, &f.transport).unwrap();
        assert_eq!(cold.fixture_controls().unwrap(), vec![signed_message]);
        let (agent, status) = consensus::Agent::inspect_with_status(&f.signer, &f.node).unwrap();
        assert_eq!(agent.record_count(), 1);
        assert_eq!(status.head, signed_head);
        drop(agent);
        assert_eq!(caller_state(&f), caller);
        drop(cold);
    }
    drop(f.runtime.take());
    within(deadline);
    let result = json!({"format":FORMAT,"case":case,"root":f.root,"passed":true,
        "elapsed_seconds":clock()-started,"phase_rows":phase_rows,"native_records":1,
        "native_height":0,"original_error_sha256":error.map(|e|hex::encode(Sha256::digest(e.as_bytes()))),
        "observer_success":!interrupted,"native_unchanged":true,"caller_complete":!interrupted,
        "pending_retained":interrupted,"native_response_exact":true,
        "regional_build_source_sha256":env!("RLD_REGIONAL_SOURCE"),"no_authority":true});
    metadata(&f.root, "timeout-observation-result.json", &result);
    eprintln!("timeout_observation_result={result}");
    within(deadline);
}

#[test]
#[ignore = "one fresh original ten-second actual Timeout observer component; no payment"]
fn timeout_substeps_follow_actual_native_sign_and_durable_runtime() {
    run(false);
}

#[test]
#[ignore = "one fresh original ten-second signed-interruption observer refusal; no payment"]
fn timeout_substeps_preserve_signed_pending_failure_without_completed_native_phase() {
    run(true);
}

#[path = "bft_capture_defer_tests.rs"]
mod capture_defer_tests;
