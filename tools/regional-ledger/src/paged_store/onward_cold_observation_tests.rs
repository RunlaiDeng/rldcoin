//! Fixed five-envelope process-cold observation, not owner or consensus qualification.
use super::negative_seams::Target;
use super::*;
use crate::bft::{Context, Request};
use crate::bft_runtime_archive::Archive;

const SELECTOR: &str = "storage::paged::onward_runtime_tests::cold_observation::onward_runtime_cold_open_measures_complete_archive_authentication";
const LOCAL_SELECTOR: &str = "storage::paged::onward_runtime_tests::cold_observation::onward_runtime_local_retention_measures_complete_builder_authentication";
const BUILDER_SELECTOR: &str = "storage::paged::onward_runtime_tests::cold_observation::onward_runtime_local_builder_reuses_exact_foreign_closure_only_within_each_construction";
const ARCHIVE_WITNESS_SELECTOR: &str = "storage::paged::onward_runtime_tests::cold_observation::onward_runtime_cold_archive_reuses_exact_foreign_closure_only_within_each_read";
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum OpenMode {
    Archive,
    ArchiveWitness,
    LocalMeasurement,
    LocalBuilderWitness,
}
impl OpenMode {
    fn local(self) -> bool {
        matches!(self, Self::LocalMeasurement | Self::LocalBuilderWitness)
    }
    fn selector(self) -> &'static str {
        match self {
            Self::Archive => SELECTOR,
            Self::ArchiveWitness => ARCHIVE_WITNESS_SELECTOR,
            Self::LocalMeasurement => LOCAL_SELECTOR,
            Self::LocalBuilderWitness => BUILDER_SELECTOR,
        }
    }
}
const CHILD_ENV: &str = "RLD_ONWARD_COLD_OBSERVATION_CHILD";
const CONTROL: &str = "cold-observation-control";
fn check(deadline: f64) {
    assert!(
        now() < deadline,
        "original 30-second cold observation exhausted"
    );
}
fn state_inventory(root: &Path) -> BTreeMap<PathBuf, (Hash, u64, std::time::SystemTime)> {
    let mut result = inventory(root);
    result.retain(|path, _| !path.starts_with(root.join(CONTROL)));
    result
}
#[derive(Serialize, Deserialize)]
struct CallerPin {
    signer: PathBuf,
    caller: PathBuf,
    key: String,
    initial_head: Hash,
    state: bft_client::State,
    message: Message,
}
struct InitialCaller {
    signer: PathBuf,
    caller: PathBuf,
    key_file: PathBuf,
    key: String,
    state: bft_client::State,
}
#[derive(Serialize, Deserialize)]
struct ColdPins {
    mode: OpenMode,
    parent_pid: u32,
    started: f64,
    deadline: f64,
    target: PathBuf,
    config: PathBuf,
    transport: Value,
    absent_key: PathBuf,
    currency: Hash,
    region: Hash,
    native_head: Hash,
    native_tip: Hash,
    native_root: Hash,
    a80: Hash,
    b4: Hash,
    export: Hash,
    c1: Snapshot,
    proof: CompleteOnwardNetworkHistory,
    proof_identity: Hash,
    callers: Vec<CallerPin>,
    archive_sha256: Hash,
    archive_bytes: usize,
    archive_ids: Vec<Hash>,
}
fn client(initial: &InitialCaller, node: &Store) -> bft_client::Client {
    bft_client::Client::lock(
        &initial.caller,
        &initial.signer,
        initial.key.clone(),
        bft_client::ONWARD_FORMAT.into(),
        node,
    )
    .unwrap()
}
fn envelope(
    node: &Store,
    proof: &CompleteOnwardNetworkHistory,
    c1: &Snapshot,
    body: Body,
) -> net::Envelope {
    net::Envelope {
        format: net::FORMAT.into(),
        currency: node.trust.currency().unwrap(),
        region: node.chain.region,
        history: Some(proof.clone()),
        evidence: Evidence {
            snapshots: vec![c1.clone()],
        },
        body,
    }
}
// After Runtime.open already performed full cold verification, this checks the
// exact retained composition and original bytes without a second auth loop.
fn archive_membership(pins: &ColdPins) {
    let raw = fs::read(pins.target.join("runtime-0/state.json")).unwrap();
    assert_eq!(
        (sha(&raw), raw.len()),
        (pins.archive_sha256, pins.archive_bytes)
    );
    let archive = Archive::decode(&raw).unwrap();
    assert_eq!(archive.format, crate::bft_runtime_archive::ONWARD_FORMAT);
    assert_eq!(
        archive.runtime.messages.keys().copied().collect::<Vec<_>>(),
        pins.archive_ids
    );
    assert_eq!(archive.runtime.messages.len(), 5);
    let mut timeout_keys = BTreeSet::new();
    let mut finalized = 0;
    for record in archive.runtime.messages.values() {
        let wire: net::WireEnvelope =
            serde_json::from_value(archive.envelope(record).unwrap()).unwrap();
        let complete = wire.expand().unwrap();
        assert_eq!(complete.history.as_ref(), Some(&pins.proof));
        assert_eq!(complete.evidence.snapshots, vec![pins.c1.clone()]);
        match &complete.body {
            Body::Signed(message) => {
                let Message::Timeout(vote) = message.as_ref() else {
                    panic!("only actual Timeout bodies");
                };
                assert_eq!(vote.context.parent_height, 1);
                assert_eq!(vote.context.previous, Some(pins.c1.statement.id().unwrap()));
                assert_eq!(vote.round, 0);
                assert!(timeout_keys.insert(vote.approval.key.clone()));
                let (index, caller) = pins
                    .callers
                    .iter()
                    .enumerate()
                    .find(|(_, caller)| caller.key == vote.approval.key)
                    .unwrap();
                assert_eq!(message.as_ref(), &caller.message);
                assert_eq!(record.local, index == 0);
                assert!(record.value.is_none());
            }
            Body::Finalized(snapshot) => {
                assert_eq!(snapshot.as_ref(), &pins.c1);
                assert_eq!(record.value, Some(pins.c1.statement.id().unwrap()));
                assert!(!record.local);
                finalized += 1;
            }
            _ => panic!("unexpected archive body"),
        }
    }
    assert_eq!(
        timeout_keys,
        pins.callers.iter().map(|p| p.key.clone()).collect()
    );
    assert_eq!(timeout_keys.len(), 4);
    assert_eq!(finalized, 1);
}
fn validate_probe(probe: &Value, native_seconds: f64, mode: OpenMode) -> Value {
    assert_eq!(probe["successful"], true);
    assert_eq!(probe["complete"], true);
    assert_eq!(probe["pending_seen"], false);
    assert_eq!(probe["outbox_seen"], false);
    let runtime_seconds = probe["runtime_open_seconds"].as_f64().unwrap();
    assert!(native_seconds.is_finite() && native_seconds > 0.0);
    assert!(runtime_seconds.is_finite() && runtime_seconds > 0.0);
    let mut sum = 0.0;
    for key in [
        "archive_auth_seconds",
        "caller_reconcile_seconds",
        "startup_flush_seconds",
        "agent_open_seconds",
        "retained_messages_seconds",
        "local_retention_seconds",
    ] {
        assert_eq!(
            probe["phase_success"][key.strip_suffix("_seconds").unwrap()],
            true
        );
        let seconds = probe[key].as_f64().unwrap();
        assert!(seconds.is_finite() && seconds >= 0.0);
        sum += seconds;
    }
    let measured = probe["measured_seconds"].as_f64().unwrap();
    let residual = probe["residual_seconds"].as_f64().unwrap();
    assert!(measured.is_finite() && measured >= 0.0 && measured <= runtime_seconds);
    assert!(residual.is_finite() && residual >= 0.0);
    assert!((sum - measured).abs() <= 1e-9);
    assert!((runtime_seconds - measured - residual).abs() <= 1e-9);
    let cost = &probe["archive_execution"];
    assert_eq!(cost["complete"], true);
    assert_eq!(cost["max_depth"], 1);
    assert_eq!(cost["failed"], 0);
    let calls = cost["calls"].as_u64().unwrap();
    assert_eq!(calls, cost["successful"].as_u64().unwrap());
    let pure = cost["verification_calls"].as_u64().unwrap();
    assert_eq!(
        pure, 1,
        "one read executes the exact foreign closure once while checking all five complete records"
    );
    assert_eq!(calls, pure);
    let foreign = cost["verification_seconds"].as_f64().unwrap();
    let outermost = cost["outermost_seconds"].as_f64().unwrap();
    let archive = probe["archive_auth_seconds"].as_f64().unwrap();
    assert!(archive > 0.0 && foreign.is_finite() && foreign >= 0.0);
    assert!(outermost.is_finite() && foreign <= outermost && outermost <= archive);
    if mode.local() {
        return validate_local_probe(probe, native_seconds, runtime_seconds, mode);
    }
    let ratio = foreign / runtime_seconds;
    json!({"native_open_seconds":native_seconds,"runtime_open_seconds":runtime_seconds,
        "archive_auth_seconds":archive,"archive_verification_count":pure,
        "archive_verification_seconds":foreign,"archive_verification_ratio":ratio,
        "archive_foreign_share":foreign/archive,
        "combined_open_foreign_share":foreign/(native_seconds+runtime_seconds),
        "expected_archive_foreign_executions":1,
        "hypothesis_supported":pure>=2 && ratio>=0.25,"runtime_open_probe":probe})
}
// Each Scope belongs to an existing call. The two construction calls are the
// hypothesis; the two retain calls remain independent authentication controls.
fn validate_local_probe(
    probe: &Value,
    native_seconds: f64,
    runtime_seconds: f64,
    mode: OpenMode,
) -> Value {
    let local_seconds = probe["local_retention_seconds"].as_f64().unwrap();
    assert!(local_seconds.is_finite() && local_seconds > 0.0 && local_seconds <= runtime_seconds);
    let calls = &probe["local_calls"];
    assert_eq!(calls["complete"], true);
    assert_eq!(calls["entered"], 2);
    assert_eq!(calls["completed"], 2);
    assert_eq!(calls["overflow"], false);
    let rows = calls["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    let mut builder_wall = 0.0;
    let mut retention_wall = 0.0;
    let mut builder_pure = 0.0;
    let mut retention_pure = 0.0;
    let mut builder_calls = 0;
    let mut retention_calls = 0;
    let mut repeated_builder = true;
    for (row, kind) in rows.iter().zip(["signed-timeout", "finalized"]) {
        assert_eq!(row["kind"], kind);
        assert_eq!(row["completed"], true);
        assert_eq!(row["successful"], true);
        // Current-source structure; the original four-call sample remains bound
        // to its earlier source and report. Both modes use the production path.
        for (name, expected) in [("construct", 1u64), ("retain", 1u64)] {
            let segment = &row[name];
            assert_eq!(segment["returned"], true);
            assert_eq!(segment["successful"], true);
            let seconds = segment["seconds"].as_f64().unwrap();
            assert!(seconds.is_finite() && seconds >= 0.0);
            let cost = &segment["execution"];
            assert_eq!(cost["complete"], true);
            assert_eq!(cost["max_depth"], 1);
            assert_eq!(cost["failed"], 0);
            assert_eq!(cost["calls"].as_u64().unwrap(), expected);
            assert_eq!(cost["successful"].as_u64().unwrap(), expected);
            let pure_calls = cost["verification_calls"].as_u64().unwrap();
            assert_eq!(pure_calls, expected);
            let pure = cost["verification_seconds"].as_f64().unwrap();
            let outermost = cost["outermost_seconds"].as_f64().unwrap();
            let inclusive = cost["seconds"].as_f64().unwrap();
            assert!(inclusive.is_finite() && inclusive >= 0.0);
            assert!(pure.is_finite() && pure >= 0.0);
            assert!(outermost.is_finite() && pure <= outermost && outermost <= seconds);
            assert!((inclusive - outermost).abs() <= 1e-9);
            if name == "construct" {
                builder_wall += seconds;
                builder_pure += pure;
                builder_calls += pure_calls;
                repeated_builder &= pure_calls >= 2;
            } else {
                retention_wall += seconds;
                retention_pure += pure;
                retention_calls += pure_calls;
            }
        }
    }
    let measured = builder_wall + retention_wall;
    assert!(measured.is_finite() && measured <= local_seconds);
    let residual = local_seconds - measured;
    assert!(residual.is_finite() && residual >= 0.0);
    let ratio = builder_pure / local_seconds;
    let runtime_ratio = builder_pure / runtime_seconds;
    assert!(ratio.is_finite() && (0.0..=1.0).contains(&ratio));
    assert!(runtime_ratio.is_finite() && (0.0..=1.0).contains(&runtime_ratio));
    let mut report = json!({"native_open_seconds":native_seconds,"runtime_open_seconds":runtime_seconds,
        "local_retention_seconds":local_seconds,"local_rows":rows,
        "local_measured_seconds":measured,"local_residual_seconds":residual,
        "builder_seconds":builder_wall,"builder_pure_count":builder_calls,
        "builder_pure_seconds":builder_pure,"builder_pure_ratio":ratio,
        "builder_pure_runtime_ratio":runtime_ratio,"retention_seconds":retention_wall,
        "retention_pure_count":retention_calls,"retention_pure_seconds":retention_pure,
        "expected_construct_pure_executions_per_body":1,
        "expected_retain_pure_executions_per_body":1,
        "expected_archive_foreign_executions":1,"local_retention_observation":true,
        "hypothesis_supported":repeated_builder && ratio>=0.25,"runtime_open_probe":probe});
    if mode == OpenMode::LocalBuilderWitness {
        assert_eq!((builder_calls, retention_calls), (2, 2));
        report["local_builder_witness"] = json!(true);
        report["builder_counter_passed"] = json!(true);
    }
    report
}
// These are three actual calls on one locked Client. Each call starts a fresh
// optional witness; cap0 exercises the same reader kernel without retention.
fn archive_read_controls(pins: &ColdPins, node: &Store) -> Value {
    let client = crate::bft_runtime_archive::Client::lock(
        &pins.target.join("runtime-0"),
        pins.callers[0].key.clone(),
        bft_client::ONWARD_FORMAT.into(),
        node,
    )
    .unwrap();
    let mut first: Option<(Archive, Hash)> = None;
    let mut rows = Vec::new();
    for (label, cap, expected) in [
        ("independent-read-one", None, 1u64),
        ("independent-read-two", None, 1u64),
        ("cap-zero-read", Some(0), 5u64),
    ] {
        check(pins.deadline);
        let started = std::time::Instant::now();
        let scope = crate::bft_onward_network::execution_cost::Scope::begin();
        let result = match cap {
            Some(limit) => client.read_authenticated_with_limit_for_test(node, limit),
            None => client.read_authenticated(node),
        };
        let execution = scope.finish();
        let seconds = started.elapsed().as_secs_f64();
        let (archive, digest) = result.unwrap();
        assert!(execution.complete);
        assert_eq!(execution.max_depth, 1);
        assert_eq!(execution.failed, 0);
        assert_eq!(execution.calls, expected);
        assert_eq!(execution.successful, expected);
        assert_eq!(execution.verification_calls, expected);
        assert!(seconds.is_finite() && seconds > 0.0);
        assert!(execution.seconds.is_finite() && execution.seconds >= 0.0);
        assert!(execution.verification_seconds.is_finite() && execution.verification_seconds > 0.0);
        assert!(execution.verification_seconds <= execution.outermost_seconds);
        assert!(execution.outermost_seconds <= execution.seconds && execution.seconds <= seconds);
        let canonical =
            files::canonical_with_limit(&archive, crate::bft_runtime_archive::MAX_STATE).unwrap();
        assert_eq!(digest, pins.archive_sha256);
        assert_eq!(
            (sha(&canonical), canonical.len()),
            (digest, pins.archive_bytes)
        );
        if let Some((original, original_digest)) = &first {
            assert_eq!(&archive, original);
            assert_eq!(&digest, original_digest);
        } else {
            first = Some((archive, digest));
        }
        rows.push(json!({"label":label,"expected_pure":expected,
            "pure":execution.verification_calls,"seconds":seconds,
            "execution":execution,"returned_equal":true}));
        check(pins.deadline);
    }
    assert_eq!(rows.len(), 3);
    json!(rows)
}

fn child(root: &Path, mode: OpenMode) {
    let control = root.join(CONTROL);
    let pins: ColdPins =
        serde_json::from_slice(&fs::read(control.join("pins.json")).unwrap()).unwrap();
    assert!(root.is_absolute() && pins.target.starts_with(root));
    assert_eq!(pins.mode, mode);
    assert_ne!(std::process::id(), pins.parent_pid);
    assert_eq!(pins.deadline - pins.started, 30.0);
    check(pins.deadline);
    assert!(!pins.absent_key.exists());
    let before = state_inventory(root);
    let native_started = now();
    let node = Store::open_pinned(
        &pins.target.join("ledger"),
        &public(1),
        pins.currency,
        pins.native_head,
    )
    .unwrap();
    let native_seconds = now() - native_started;
    check(pins.deadline);
    // No Native/Agent/envelope oracle or process witness runs between these
    // opens. The actual probe owns its bounded, non-overlapping execution Scopes.
    let (result, probe) = if mode.local() {
        TestRuntime::probe_open_local(&pins.config, &node, &pins.transport)
    } else {
        TestRuntime::probe_open(&pins.config, &node, &pins.transport)
    };
    new_json(&control.join("runtime-open-probe.json"), &probe);
    let actor = result.unwrap();
    let mut report = validate_probe(&probe, native_seconds, mode);
    check(pins.deadline);
    assert_eq!(node.storage_head().unwrap(), pins.native_head);
    assert_eq!(node.chain.tip().unwrap(), pins.native_tip);
    assert_eq!(node.chain.ledger.root().unwrap(), pins.native_root);
    assert_eq!(node.chain.region, pins.region);
    assert_eq!(node.chain.height(), 1);
    assert_eq!(node.chain.finalized, Some(pins.c1.statement.id().unwrap()));
    assert_eq!(node.chain.ledger, Ledger::default());
    assert!(node.journal.incident_ids.is_empty());
    assert_eq!(
        node.complete_onward_network_pending_imports().unwrap(),
        vec![Command::Import {
            snapshot: pins.b4,
            export: pins.export
        }]
    );
    node.require_retained_onward_material(Some(&pins.proof), std::slice::from_ref(&pins.c1))
        .unwrap();
    for anchor in [pins.a80, pins.b4] {
        assert!(node.evidence.snapshots.contains_key(&anchor));
    }
    archive_membership(&pins);
    for expected in &pins.callers {
        check(pins.deadline);
        let caller = bft_client::Client::lock(
            &expected.caller,
            &expected.signer,
            expected.key.clone(),
            bft_client::ONWARD_FORMAT.into(),
            &node,
        )
        .unwrap();
        assert_eq!(caller.read().unwrap(), expected.state);
        assert!(expected.state.pending.is_none() && expected.state.outbox.is_none());
        drop(caller);
        // Separate post-measurement custody acceptance, not a timed phase oracle.
        let (agent, status, messages) =
            Agent::inspect_with_retained_status(&expected.signer, &node).unwrap();
        assert_eq!(agent.journal.creation.pin.height, 0);
        assert_eq!(agent.head().unwrap(), expected.state.head);
        assert_eq!(status.head, expected.state.head);
        assert_ne!(expected.state.head, expected.initial_head);
        assert_eq!(agent.record_count(), 1);
        assert_eq!(messages, vec![expected.message.clone()]);
        drop(agent);
    }
    assert_eq!(actor.fixture_retained_ids(), pins.archive_ids);
    assert!(!pins.absent_key.exists());
    drop(actor);
    if mode == OpenMode::ArchiveWitness {
        let controls = archive_read_controls(&pins, &node);
        report["archive_witness"] = json!({
            "runtime_archive_calls":probe["archive_execution"]["verification_calls"],
            "independent_read_calls":[controls[0]["pure"],controls[1]["pure"]],
            "cap_zero_calls":controls[2]["pure"],
            "all_returned_archives_equal":true,"same_locked_client":true,
            "no_cross_read_retention":true,
        });
        report["archive_read_controls"] = controls;
    }
    drop(node);
    assert_eq!(
        state_inventory(root),
        before,
        "cold opens changed original state bytes or mtimes"
    );
    check(pins.deadline);
    report["parent_pid"] = json!(pins.parent_pid);
    report["child_pid"] = json!(std::process::id());
    report["archive_wrapper_identity"] = json!(pins.proof_identity);
    report["archive_sha256"] = json!(pins.archive_sha256);
    report["child_complete"] = json!(true);
    report["child_elapsed_seconds"] = json!(now() - pins.started);
    new_json(&control.join("child-result.json"), &report);
    check(pins.deadline);
}

#[test]
#[ignore = "one fresh 30-second fixed five-envelope process-cold observation"]
fn onward_runtime_cold_open_measures_complete_archive_authentication() {
    run(OpenMode::Archive);
}

#[test]
#[ignore = "one fresh 30-second fixed two-body local-construction observation"]
fn onward_runtime_local_retention_measures_complete_builder_authentication() {
    run(OpenMode::LocalMeasurement);
}

#[test]
#[ignore = "one fresh 30-second local builder witness counter and complete process-cold custody"]
fn onward_runtime_local_builder_reuses_exact_foreign_closure_only_within_each_construction() {
    run(OpenMode::LocalBuilderWitness);
}

#[test]
#[ignore = "one fresh 30-second archive witness and complete process-cold custody"]
fn onward_runtime_cold_archive_reuses_exact_foreign_closure_only_within_each_read() {
    run(OpenMode::ArchiveWitness);
}

fn run(mode: OpenMode) {
    if let Some(root) = std::env::var_os(CHILD_ENV) {
        child(&PathBuf::from(root), mode);
        return;
    }
    let started = now();
    let deadline = started + 30.0;
    let (root, bootstrap, proof, a80, b4, export) = ancestors();
    check(deadline);
    let control = dir(&root.join(CONTROL));
    let mut target = Target::new(
        &root,
        "cold-observation-target",
        &bootstrap,
        proof.history.destination,
    );
    let currency = target.node.trust.currency().unwrap();
    let mut seeds = (2u8..6).collect::<Vec<_>>();
    seeds.sort_by_key(|seed| public(*seed));
    let initial: bft_client::State =
        bft_client::decode(&fs::read(target.root.join("caller-0/head.json")).unwrap()).unwrap();
    let mut originals = vec![InitialCaller {
        signer: target.root.join("signer-0"),
        caller: target.root.join("caller-0/head.json"),
        key_file: target.root.join("key-0.json"),
        key: public(seeds[0]),
        state: initial,
    }];
    for (index, seed) in seeds.iter().enumerate().skip(1) {
        check(deadline);
        let sender = dir(&root.join(format!("cold-sender-{index}")));
        let signer = sender.join("signer");
        let original = Agent::create(&signer, &target.node, public(*seed)).unwrap();
        assert_eq!(original.journal.creation.pin.height, 0);
        assert_eq!(original.record_count(), 0);
        let state = bft_client::State {
            format: bft_client::ONWARD_FORMAT.into(),
            binding: original.journal.binding.clone(),
            head: original.head().unwrap(),
            pending: None,
            outbox: None,
        };
        drop(original);
        let caller = dir(&sender.join("caller")).join("head.json");
        new_json(&caller, &state);
        let key_file = sender.join("key.json");
        new_json(&key_file, &json!({"secret_key":hex::encode([*seed;32])}));
        originals.push(InitialCaller {
            signer,
            caller,
            key_file,
            key: public(*seed),
            state,
        });
    }
    let c1 = certified_with_commands(&target.node.paged_replay.as_ref().unwrap().replay, vec![]);
    target.node.finalize(c1.clone()).unwrap();
    target
        .node
        .accept_complete_onward_network_history(proof.clone())
        .unwrap();
    let native_head = target.node.storage_head().unwrap();
    let mut callers = Vec::new();
    for (index, initial) in originals.iter().enumerate() {
        check(deadline);
        let request = Request::Timeout {
            context: Context::current(&target.node).unwrap(),
            round: 0,
        };
        let message = if index == 0 {
            target
                .actor
                .as_mut()
                .unwrap()
                .sign_fixture_control(&target.node, request)
                .unwrap()
        } else {
            let caller = client(initial, &target.node);
            assert_eq!(caller.read().unwrap(), initial.state);
            let mut pending = initial.state.clone();
            pending.pending = Some(request.clone());
            let (pending, mut agent) = caller
                .store_pending_for_sign(
                    &target.node,
                    bft_client::Transition {
                        previous_sha256: sha(&files::canonical(&initial.state).unwrap()),
                        proposed: pending,
                    },
                )
                .unwrap();
            let signed = agent
                .sign(
                    &target.node,
                    request,
                    Some(&initial.key_file),
                    initial.state.head,
                )
                .unwrap();
            assert!(!signed.recovered_exact_retry);
            drop(agent);
            let message = signed.message.clone();
            let mut response = pending.clone();
            response.pending = None;
            response.head = signed.head;
            response.outbox = Some(signed.message);
            caller
                .store(
                    &target.node,
                    bft_client::Transition {
                        previous_sha256: sha(&files::canonical(&pending).unwrap()),
                        proposed: response,
                    },
                )
                .unwrap();
            drop(caller);
            let frame = strict_frame(envelope(
                &target.node,
                &proof,
                &c1,
                Body::Signed(Box::new(message.clone())),
            ));
            target
                .actor
                .as_mut()
                .unwrap()
                .receive(&mut target.node, &frame)
                .unwrap();
            let caller = client(initial, &target.node);
            let old = caller.read().unwrap();
            assert_eq!(old.outbox.as_ref(), Some(&message));
            let mut clean = old.clone();
            clean.outbox = None;
            caller
                .store(
                    &target.node,
                    bft_client::Transition {
                        previous_sha256: sha(&files::canonical(&old).unwrap()),
                        proposed: clean,
                    },
                )
                .unwrap();
            drop(caller);
            message
        };
        assert!(
            matches!(&message,Message::Timeout(v) if v.context.parent_height==1 && v.round==0 && v.approval.key==initial.key)
        );
        let caller = client(initial, &target.node);
        let state = caller.read().unwrap();
        assert!(state.pending.is_none() && state.outbox.is_none());
        assert_ne!(state.head, initial.state.head);
        drop(caller);
        callers.push(CallerPin {
            signer: initial.signer.clone(),
            caller: initial.caller.clone(),
            key: initial.key.clone(),
            initial_head: initial.state.head,
            state,
            message,
        });
    }
    let final_frame = strict_frame(envelope(
        &target.node,
        &proof,
        &c1,
        Body::Finalized(Box::new(c1.clone())),
    ));
    target
        .actor
        .as_mut()
        .unwrap()
        .receive(&mut target.node, &final_frame)
        .unwrap();
    assert_eq!(target.node.storage_head().unwrap(), native_head);
    assert_eq!(target.node.chain.ledger, Ledger::default());
    assert_eq!(target.node.chain.height(), 1);
    let archive = fs::read(target.root.join("runtime-0/state.json")).unwrap();
    let mut cold_config: Value =
        serde_json::from_slice(&fs::read(target.root.join("initial-config.json")).unwrap())
            .unwrap();
    cold_config["startup_native_history_head"] = json!(native_head);
    let absent_key = target.root.join("absent-cold-key.json");
    assert!(!absent_key.exists());
    cold_config["key_file"] = json!(absent_key);
    let config = control.join("cold-config.json");
    new_json(&config, &cold_config);
    let pins = ColdPins {
        mode,
        parent_pid: std::process::id(),
        started,
        deadline,
        target: target.root.clone(),
        config,
        transport: json!({"format":MESH,"network":currency,"state":target.root.join("transport-0"),"contacts":[]}),
        absent_key,
        currency,
        region: target.node.chain.region,
        native_head,
        native_tip: target.node.chain.tip().unwrap(),
        native_root: target.node.chain.ledger.root().unwrap(),
        a80,
        b4,
        export,
        c1,
        proof_identity: id("cold-observation-complete-wrapper", &proof).unwrap(),
        proof,
        callers,
        archive_sha256: sha(&archive),
        archive_bytes: archive.len(),
        archive_ids: target.actor.as_ref().unwrap().fixture_retained_ids(),
    };
    archive_membership(&pins);
    new_json(&control.join("pins.json"), &pins);
    drop(target);
    drop(originals);
    check(deadline);
    let before = state_inventory(&root);
    let stdout = control.join("child.stdout.log");
    let stderr = control.join("child.stderr.log");
    for path in [&stdout, &stderr] {
        crate::keystore::private_create(path, b"").unwrap();
    }
    let mut child = Process::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            mode.selector(),
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, &root)
        .stdout(Stdio::from(
            fs::OpenOptions::new().write(true).open(stdout).unwrap(),
        ))
        .stderr(Stdio::from(
            fs::OpenOptions::new().write(true).open(stderr).unwrap(),
        ))
        .spawn()
        .unwrap();
    let child_pid = child.id();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!(
                "original30 cold child deadline exhausted; preserve {}",
                root.display()
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(
        status.success(),
        "cold child failed; preserve {}",
        root.display()
    );
    check(deadline);
    assert_eq!(
        state_inventory(&root),
        before,
        "whole child changed original fixture state"
    );
    let mut report: Value =
        serde_json::from_slice(&fs::read(control.join("child-result.json")).unwrap()).unwrap();
    assert_eq!(report["child_complete"], true);
    assert_eq!(report["parent_pid"], std::process::id());
    assert_eq!(report["child_pid"], child_pid);
    assert_eq!(
        report["archive_wrapper_identity"],
        json!(pins.proof_identity)
    );
    check(deadline);
    report["root"] = json!(root);
    report["elapsed_seconds"] = json!(now() - started);
    report["passed"] = json!(true);
    report["fresh_process_cold"] = json!(true);
    report["archive_records"] = json!(5);
    report["original_c0_agents"] = json!(4);
    for key in [
        "inventory_unchanged",
        "native_and_caller_unchanged",
        "no_import_credit",
        "c1_certificate_fixture",
        "keyless_startup",
        "normal_child_join",
    ] {
        report[key] = json!(true);
    }
    for key in [
        "ordinary_service",
        "owner_payment_qualified",
        "independent_qualification",
    ] {
        report[key] = json!(false);
    }
    assert!(report["elapsed_seconds"].as_f64().unwrap() < 30.0);
    match mode {
        OpenMode::Archive => eprintln!("onward_cold_observation_result={report}"),
        OpenMode::ArchiveWitness => eprintln!("onward_archive_witness_result={report}"),
        OpenMode::LocalMeasurement => {
            eprintln!("onward_local_retention_observation_result={report}")
        }
        OpenMode::LocalBuilderWitness => eprintln!("onward_local_builder_witness_result={report}"),
    }
}
