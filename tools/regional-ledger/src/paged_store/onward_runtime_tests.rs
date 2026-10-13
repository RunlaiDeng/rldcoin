//! Fresh directly carried Runtime component; ordinary Service remains unqualified.
//! A/B certificates use fresh public no-value fixture construction. Positive C
//! certificates come only from the four original C0 Agents through Runtime::tick;
//! negative seams separately request real original-Agent Timeout responses.
use super::body_witness_tests::certified_with_commands;
use super::export_archive_tests::{inventory, source_fixture_with_regions};
use super::*;
use crate::bft::{Agent, Message, Phase};
use crate::bft_client;
use crate::bft_network::Body;
use crate::bft_onward_network as net;
use crate::contact_runtime::{initialize, TestRuntime, MESH};
use crate::tests::{public, signature};
use crate::wallet_client as files;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::process::{Command as Process, Stdio};
use std::time::Duration;

const TEST: &str =
    "storage::paged::onward_runtime_tests::four_original_onward_runtimes_import_and_cold_replay";
const CHILD: &str = "RLD_ONWARD_RUNTIME_COLD_CHILD";
#[path = "onward_owner_tests.rs"]
mod owner_spend;
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
enum Mode {
    Import,
    OwnerSpend,
}
impl Mode {
    fn selector(self) -> &'static str {
        match self {
            Self::Import => TEST,
            Self::OwnerSpend => owner_spend::TEST,
        }
    }
    fn height(self) -> u64 {
        match self {
            Self::Import => 2,
            Self::OwnerSpend => 5,
        }
    }
}
fn now() -> f64 {
    crate::bft_tick_schedule::monotonic().unwrap()
}
fn budget(deadline: f64) {
    assert!(
        now() < deadline,
        "original 120-second Onward Runtime component exhausted"
    );
}
fn sha(bytes: &[u8]) -> Hash {
    Hash(Sha256::digest(bytes).into())
}
fn new_json(path: &Path, value: &impl Serialize) {
    crate::keystore::private_create(
        path,
        &files::canonical_with_limit(value, crate::MAX_BYTES).unwrap(),
    )
    .unwrap();
}
fn dir(path: &Path) -> PathBuf {
    crate::contact_runtime::directory(path).unwrap();
    path.to_owned()
}
fn phase(start: f64, name: &str) {
    eprintln!(
        "onward_runtime_phase={}",
        json!({"phase":name,"elapsed_seconds":now()-start})
    );
}

// Scalar-only observations for the original owner target4 barrier. Logging and
// clock failures disable observations, never the underlying fixture operation.
struct OwnerOpenObservation {
    component_started_at: f64,
    deadline: f64,
    rows: usize,
    bytes: usize,
    enabled: bool,
    last_at: f64,
}
struct OwnerOpenSpan {
    operation: &'static str,
    actor: Option<usize>,
    started_at: f64,
}
impl OwnerOpenObservation {
    const PREFIX: &'static [u8] = b"onward_owner_open_observation=";
    const ROW_LIMIT: usize = 36;
    const BYTE_LIMIT: usize = 128 * 1024;

    fn new(component_started_at: f64, deadline: f64) -> Self {
        Self {
            component_started_at,
            deadline,
            rows: 0,
            bytes: 0,
            enabled: component_started_at.is_finite() && deadline.is_finite(),
            last_at: component_started_at,
        }
    }
    fn clock(&mut self) -> Option<f64> {
        if !self.enabled {
            return None;
        }
        match crate::bft_tick_schedule::monotonic() {
            Ok(at) if at.is_finite() && at >= self.last_at => {
                self.last_at = at;
                Some(at)
            }
            _ => {
                self.enabled = false;
                None
            }
        }
    }
    fn emit(
        &mut self,
        kind: &str,
        operation: &str,
        actor: Option<usize>,
        at: f64,
        completion: Option<Value>,
    ) {
        if !self.enabled {
            return;
        }
        let mut row = json!({
            "format":"RLD-ONWARD-OWNER-TARGET4-OPEN-V1",
            "row":self.rows + 1,"row_limit":Self::ROW_LIMIT,"byte_limit":Self::BYTE_LIMIT,
            "kind":kind,"operation":operation,"actor":actor,"target_height":4,
            "component_started_at":self.component_started_at,"deadline":self.deadline,
            "at":at,"within_original_deadline":at < self.deadline,
            "started_at":null,"completed_at":null,"seconds":null,
            "returned":null,"successful":null,"probe":null,"all_four_opened":null,
        });
        if let Some(Value::Object(fields)) = completion {
            row.as_object_mut().unwrap().extend(fields);
        }
        let Ok(encoded) = serde_json::to_vec(&row) else {
            self.enabled = false;
            return;
        };
        let length = Self::PREFIX.len() + encoded.len() + 1;
        if self.rows >= Self::ROW_LIMIT || length > Self::BYTE_LIMIT - self.bytes {
            self.enabled = false;
            return;
        }
        let mut line = Vec::with_capacity(length);
        line.extend_from_slice(Self::PREFIX);
        line.extend_from_slice(&encoded);
        line.push(b'\n');
        use std::io::Write;
        if std::io::stderr().lock().write_all(&line).is_err() {
            self.enabled = false;
            return;
        }
        self.rows += 1;
        self.bytes += length;
    }
    fn start(&mut self, operation: &'static str, actor: Option<usize>) -> Option<OwnerOpenSpan> {
        let dispatched_at = self.clock()?;
        self.emit("start", operation, actor, dispatched_at, None);
        // Start-row output is outside the measured operation. A start row alone
        // is only a dispatch lower bound; it never proves a call returned.
        Some(OwnerOpenSpan {
            operation,
            actor,
            started_at: self.clock()?,
        })
    }
    fn finish(&mut self, span: Option<OwnerOpenSpan>, successful: bool, probe: Option<Value>) {
        let Some(span) = span else { return };
        let Some(completed_at) = self.clock() else {
            return;
        };
        self.emit(
            "completion",
            span.operation,
            span.actor,
            completed_at,
            Some(json!({
                "started_at":span.started_at,"completed_at":completed_at,
                "seconds":completed_at-span.started_at,"returned":true,
                "successful":successful,"probe":probe,
                "all_four_opened":if span.operation == "barrier" { Some(true) } else { None },
            })),
        );
    }
}

// This helper is called ONLY for B. C must never call it.
fn install_b(node: &mut Store, commands: Vec<Command>) -> Snapshot {
    let snapshot = certified_with_commands(&node.paged_replay.as_ref().unwrap().replay, commands);
    node.finalize(snapshot.clone()).unwrap();
    snapshot
}
fn ancestors() -> (
    PathBuf,
    Bootstrap,
    CompleteOnwardNetworkHistory,
    Hash,
    Hash,
    Hash,
) {
    let (h, source, root, _, records, origin_export) = source_fixture_with_regions(
        80,
        16,
        crate::paged_bft::ORIGIN_NETWORK_RULES,
        "earth",
        &[("andromeda", crate::paged_bft::ONWARD_NETWORK_RULES)],
    );
    eprintln!(
        "Fresh Onward Runtime component retained at {}",
        root.display()
    );
    let currency = source.trust.currency().unwrap();
    let b = source.trust.named("proxima").unwrap();
    let c = source.trust.named("andromeda").unwrap();
    let origin = CompleteOriginHistory {
        source: h.region,
        destination: b,
        export: origin_export,
        snapshots: records
            .iter()
            .map(|r| match r {
                Record::Certified(s) => *s.clone(),
                _ => panic!("actual A certificate"),
            })
            .collect(),
    };
    assert_eq!(origin.snapshots.len(), 80);
    let a80 = origin.snapshots[79].statement.id().unwrap();
    let mut intermediate = Store::create(
        &root.join("intermediate"),
        h.bootstrap.clone(),
        b,
        &public(1),
        currency,
    )
    .unwrap();
    install_b(&mut intermediate, vec![]);
    intermediate
        .accept_complete_origin_history(origin.clone())
        .unwrap();
    install_b(
        &mut intermediate,
        vec![Command::Import {
            snapshot: a80,
            export: origin_export,
        }],
    );
    install_b(&mut intermediate, vec![]);
    let input = id("output", &(origin_export, 0u32)).unwrap();
    let intent = Intent {
        currency,
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
        valid_through: 128,
    };
    let export = intent.id().unwrap();
    let signed = SignedIntent {
        approvals: vec![Approval {
            key: public(11),
            signature: signature(11, &intent.bytes().unwrap()),
        }],
        intent,
    };
    let b4 = install_b(&mut intermediate, vec![Command::Spend(Box::new(signed))])
        .statement
        .id()
        .unwrap();
    let proof = intermediate.complete_onward_network_export(export).unwrap();
    install_b(&mut intermediate, vec![]); // Later empty B5 must not replace the actual export anchor.
    assert_eq!(
        proof,
        intermediate.complete_onward_network_export(export).unwrap()
    );
    assert_eq!(proof.history.origin, origin);
    assert_eq!(proof.history.snapshots.len(), 4);
    assert_eq!(proof.history.snapshots[3].statement.id().unwrap(), b4);
    assert_eq!(intermediate.chain.ledger.minted, Amount::ZERO);
    assert!(!intermediate.chain.ledger.coins.contains_key(&input));
    drop(intermediate);
    (root, h.bootstrap, proof, a80, b4, export)
}
fn config(
    root: &Path,
    n: usize,
    seeds: &[u8],
    ids: &[String],
    stop: u64,
    native_head: Hash,
) -> Value {
    json!({"format":bft_client::ONWARD_FORMAT,"state":root.join(format!("runtime-{n}")),
        "signer_dir":root.join(format!("signer-{n}")),"head_file":root.join(format!("caller-{n}/head.json")),
        "key_file":root.join(format!("key-{n}.json")),"key":public(seeds[n]),"miner":public(12),
        "validators":seeds.iter().enumerate().map(|(i,s)|json!({"key":public(*s),"node_id":ids[i]})).collect::<Vec<_>>(),
        "block_interval":0.5,"round_timeout":5.0,"stop_height":stop,"startup_native_history_head":native_head})
}
fn strict_frame(envelope: net::Envelope) -> Vec<u8> {
    let wire = envelope.pack().unwrap();
    let payload = files::canonical_with_limit(&wire, crate::contact::MAX_PAYLOAD).unwrap();
    let digest = sha(&payload);
    let mut frame = crate::contact::Frame {
        format: crate::contact::FRAME_FORMAT.into(),
        kind: "regional-bft".into(),
        source_chain_id: wire.region,
        destination_chain_id: wire.region,
        export_id: digest,
        payload_sha256: digest,
        payload_b64: STANDARD.encode(payload),
        message_id: Hash::ZERO,
    };
    frame.message_id = frame.message().unwrap();
    frame.retained_bytes().unwrap()
}
// Test-only direct-drive observations. No new clock, Native read, signed message
// or delivery decision is introduced. A missing terminal row is incomplete.
const LIVE_ROWS: usize = 4096;
const LIVE_BYTES: usize = 8 * 1024 * 1024;
struct LiveLog {
    file: fs::File,
    path: PathBuf,
    rows: usize,
    bytes: usize,
    calls: usize,
    pending: Option<usize>,
    deadline: f64,
}
impl LiveLog {
    fn new(root: &Path, started: f64, deadline: f64) -> Self {
        Self::with_coverage(
            root,
            started,
            deadline,
            "every tick and receive in the two original direct-drive loops only",
            "setup, keyless-recovery loop, explicit wrapper receipts/retries and cold child",
        )
    }
    fn with_coverage(
        root: &Path,
        started: f64,
        deadline: f64,
        coverage: &str,
        excluded: &str,
    ) -> Self {
        let path = root.join("onward-runtime-live.jsonl");
        crate::keystore::private_create(&path, b"").unwrap();
        let file = fs::OpenOptions::new().append(true).open(&path).unwrap();
        let mut log = Self {
            file,
            path,
            rows: 0,
            bytes: 0,
            calls: 0,
            pending: None,
            deadline,
        };
        log.row(
            json!({"kind":"header","format":"RLD-ONWARD-RUNTIME-LIVE-OBSERVATION-V1",
            "started_at":started,"deadline":deadline,"row_limit":LIVE_ROWS,"byte_limit":LIVE_BYTES,
            "coverage":coverage,"excluded":excluded,
            "clock":"existing OS monotonic probes","phase_times_overlap":true,
            "observer_io_between_calls":true,"signing_authority":false}),
        );
        log
    }
    fn row(&mut self, value: Value) {
        use std::io::Write;
        let mut raw = files::canonical_with_limit(&value, LIVE_BYTES).unwrap();
        raw.push(b'\n');
        assert!(
            self.rows < LIVE_ROWS && raw.len() <= LIVE_BYTES.saturating_sub(self.bytes),
            "live observation capacity exhausted; partial log is incomplete"
        );
        self.file.write_all(&raw).unwrap();
        self.rows += 1;
        self.bytes += raw.len();
    }
    fn begin(&mut self, metadata: Value) -> usize {
        assert!(self.pending.is_none());
        self.calls += 1;
        self.pending = Some(self.calls);
        self.row(json!({"kind":"dispatch","call":self.calls,"metadata":metadata}));
        self.calls
    }
    fn end(&mut self, call: usize, result: Result<Value>) {
        assert_eq!(self.pending, Some(call));
        let value = match result {
            Ok(value) => value,
            Err(error) => {
                self.row(json!({"kind":"probe-refusal","call":call,"error":error,
                    "complete":false,"actual_call_completion_unknown":true}));
                panic!(
                    "live probe refused; retained incomplete log at {}",
                    self.path.display()
                );
            }
        };
        self.row(json!({"kind":"completion","call":call,"probe":value}));
        self.pending = None;
        let started = value["started_at"].as_f64().unwrap();
        let completed = value["completed_at"].as_f64().unwrap();
        assert!(started.is_finite() && completed.is_finite() && completed >= started);
        assert_eq!(value["success"].as_bool(), Some(value["error"].is_null()));
        assert!(
            value["error"].is_null(),
            "actual Runtime call refused: {}",
            value["error"]
        );
    }
    fn finish(mut self) -> Value {
        assert!(self.pending.is_none());
        assert_eq!(self.rows, 1 + self.calls * 2);
        self.row(json!({"kind":"end","complete":true,"calls":self.calls,
            "rows_before_end":self.rows,"bytes_before_end":self.bytes}));
        self.file.sync_all().unwrap();
        drop(self.file);
        let raw = fs::read(&self.path).unwrap();
        assert_eq!(raw.len(), self.bytes);
        json!({"path":self.path,"sha256":sha(&raw),"rows":self.rows,
            "bytes":self.bytes,"calls":self.calls,"complete":true,
            "row_limit":LIVE_ROWS,"byte_limit":LIVE_BYTES,"scope":"direct-drive calls only"})
    }
}
// These are identities of the already decoded carried body, not independent
// authentication or a first-sign clock. Acceptance is the matching receive row.
fn live_body(body: &Body) -> Value {
    match body {
        Body::Signed(message) => match message.as_ref() {
            Message::Proposal(p) => json!({"kind":"proposal","context":p.context().unwrap(),
                "round":p.round,"signer":p.leader.key,"value":p.snapshot.statement.id().unwrap()}),
            Message::Vote(v) => {
                json!({"kind":match v.phase { Phase::Prepare=>"prepare", Phase::Commit=>"commit" },
                "context":v.context,"round":v.round,"signer":v.approval.key,"value":v.value})
            }
            Message::Timeout(t) => json!({"kind":"timeout","context":t.context,
                "round":t.round,"signer":t.approval.key,"high_value":t.high.as_ref().map(|q|q.value)}),
            _ => json!({"kind":"other-signed-control"}),
        },
        Body::Finalized(s) => json!({"kind":"finalized","height":s.statement.height,
            "value":s.statement.id().unwrap(),"certificate":s.bft.as_ref().map(|q|json!({
                "prepared":{"context":q.prepared.context,"round":q.prepared.round,"value":q.prepared.value,
                    "voters":q.prepared.votes.iter().map(|v|&v.approval.key).collect::<Vec<_>>()},
                "committed":{"context":q.committed.context,"round":q.committed.round,"value":q.committed.value,
                    "voters":q.committed.votes.iter().map(|v|&v.approval.key).collect::<Vec<_>>()}}))}),
        _ => json!({"kind":"other"}),
    }
}

// Predeclared component relay: every actual retained full frame, including
// Finalized, goes unchanged through every Runtime.receive. No message generation,
// leader choice, phase injection, dependency elision or fixture QC occurs here.
fn drive(
    actors: &mut [TestRuntime],
    nodes: &mut [Store],
    target: u64,
    seen: &mut BTreeSet<(usize, Hash)>,
    relayed: &mut BTreeSet<(usize, Hash)>,
    finalized_deliveries: &mut BTreeSet<(usize, u64)>,
    log: &mut LiveLog,
) {
    let deadline = log.deadline;
    loop {
        budget(deadline);
        let mut delivered = 0;
        for i in 0..4 {
            budget(deadline);
            let call = log.begin(json!({"operation":"tick","actor":i,"target_height":target,
                "native_height_before":nodes[i].chain.height()}));
            let mut probe = actors[i].probe_tick(&mut nodes[i]);
            if let Ok(value) = &mut probe {
                value["native_height_after"] = json!(nodes[i].chain.height());
            }
            log.end(call, probe);
            // Direct component carriage: offer every retained complete frame
            // after each actor turn, before ticking the next fixed actor.
            for sender in 0..4 {
                for body_id in actors[sender].fixture_retained_ids() {
                    if relayed.contains(&(sender, body_id)) {
                        continue;
                    }
                    // Only one bounded complete frame is materialized at a time.
                    let raw = actors[sender].fixture_retained_frame(body_id).unwrap();
                    let frame: crate::contact::Frame = serde_json::from_slice(&raw).unwrap();
                    let payload = STANDARD.decode(&frame.payload_b64).unwrap();
                    let wire: net::WireEnvelope = bft_client::decode(&payload).unwrap();
                    let body = live_body(&wire.body);
                    let final_height = match wire.body {
                        Body::Finalized(ref s) => Some(s.statement.height),
                        _ => None,
                    };
                    for i in 0..4 {
                        if seen.contains(&(i, frame.message_id)) {
                            continue;
                        }
                        budget(deadline);
                        let call =
                            log.begin(json!({"operation":"receive","sender":sender,"actor":i,
                            "target_height":target,"native_height_before":nodes[i].chain.height(),
                            "frame_id":frame.message_id,"payload_sha256":frame.payload_sha256,
                            "body_id":body_id,"body":body}));
                        let mut probe = actors[i].probe_fixture_receive(&mut nodes[i], &raw);
                        if let Ok(value) = &mut probe {
                            value["native_height_after"] = json!(nodes[i].chain.height());
                        }
                        log.end(call, probe);
                        seen.insert((i, frame.message_id));
                        if let Some(h) = final_height {
                            finalized_deliveries.insert((i, h));
                        }
                        delivered += 1;
                    }
                    relayed.insert((sender, body_id));
                }
            }
        }
        assert!(
            nodes.iter().all(|n| n.chain.height() <= target),
            "phase barrier crossed"
        );
        if nodes.iter().all(|n| n.chain.height() == target) && delivered == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    for i in 0..4 {
        assert!(
            finalized_deliveries.contains(&(i, target)),
            "actual Finalized frame was not received"
        );
    }
    let checkpoint = nodes[0].chain.finalized;
    assert!(nodes.iter().all(|n| n.chain.finalized == checkpoint));
    budget(deadline);
}
fn verify_import(node: &Store, a80: Hash, b4: Hash, export: Hash) {
    assert_eq!(node.chain.height(), 2);
    let snapshot = node
        .evidence
        .snapshot(node.chain.finalized.unwrap())
        .unwrap();
    assert_eq!(
        snapshot.blocks.last().unwrap().commands,
        vec![Command::Import {
            snapshot: b4,
            export
        }]
    );
    let imported = &node.chain.ledger.coins[&id("output", &(export, 0u32)).unwrap()];
    assert_eq!(
        imported.payment,
        Payment {
            owner: public(12),
            amount: Amount(89)
        }
    );
    assert_eq!(imported.mature, 4);
    assert_eq!(imported.dependencies, BTreeSet::from([a80, b4]));
    assert_eq!(node.chain.ledger.imports, BTreeMap::from([(export, b4)]));
    assert_eq!(node.chain.ledger.minted, Amount::ZERO);
    assert!(node
        .complete_onward_network_pending_imports()
        .unwrap()
        .is_empty());
    assert!(node.journal.incident_ids.is_empty());
    node.chain.ledger.audit().unwrap();
}
#[derive(Serialize, Deserialize)]
struct NodePins {
    native_head: Hash,
    state: Hash,
    finality: Hash,
    caller: bft_client::State,
    initial_head: Hash,
    signer_records: usize,
    original_messages: Hash,
    archive_hash: Hash,
    archive_bytes: usize,
    final_snapshot: Snapshot,
}
#[derive(Serialize, Deserialize)]
struct Pins {
    mode: Mode,
    checkpoints: Vec<Hash>,
    owner: Option<owner_spend::Pins>,
    parent_pid: u32,
    started: f64,
    deadline: f64,
    currency: Hash,
    region: Hash,
    a80: Hash,
    b4: Hash,
    export: Hash,
    proof: CompleteOnwardNetworkHistory,
    seeds: Vec<u8>,
    nodes: Vec<NodePins>,
}
fn cold_child(root: &Path, mode: Mode) {
    assert!(root.is_absolute());
    let pins: Pins =
        serde_json::from_slice(&fs::read(root.join("runtime-cold-pins.json")).unwrap()).unwrap();
    assert_eq!(
        pins.mode, mode,
        "cold selector differs from separately retained pins"
    );
    assert_eq!(pins.owner.is_some(), mode == Mode::OwnerSpend);
    assert_eq!(pins.checkpoints.len(), mode.height() as usize);
    assert_ne!(pins.parent_pid, std::process::id());
    assert_eq!(pins.deadline - pins.started, 120.0);
    budget(pins.deadline);
    let before = inventory(root);
    for i in 0..4 {
        budget(pins.deadline);
        let expected = &pins.nodes[i];
        let node = Store::open_pinned(
            &root.join(format!("ledger-{i}")),
            &public(1),
            pins.currency,
            expected.native_head,
        )
        .unwrap();
        assert_eq!(node.chain.region, pins.region);
        assert_eq!(node.chain.ledger.root().unwrap(), expected.state);
        assert_eq!(node.chain.finalized, Some(expected.finality));
        assert_eq!(
            node.evidence.snapshot(expected.finality).unwrap(),
            &expected.final_snapshot
        );
        assert_eq!(node.chain.height(), mode.height());
        assert_eq!(node.chain.finalized, pins.checkpoints.last().copied());
        for (index, checkpoint) in pins.checkpoints.iter().enumerate() {
            assert_eq!(
                node.evidence
                    .snapshot(*checkpoint)
                    .unwrap()
                    .statement
                    .height,
                index as u64 + 1
            );
        }
        match &pins.owner {
            Some(owner) => {
                owner_spend::verify_spend(&node, owner, pins.a80, pins.b4, pins.export);
                if i == 0 {
                    owner_spend::cold_owner(root, &node, owner);
                }
            }
            None => verify_import(&node, pins.a80, pins.b4, pins.export),
        }
        let transport: Value = serde_json::from_slice(
            &fs::read(root.join(format!("transport-config-{i}.json"))).unwrap(),
        )
        .unwrap();
        // Production open performs complete cold archive authentication before
        // reconciling caller state or recovering an outbox. No tick runs here.
        let actor = TestRuntime::open(
            &root.join(format!("cold-config-{i}.json")),
            &node,
            &transport,
        )
        .unwrap();
        let archive_path = root.join(format!("runtime-{i}/state.json"));
        let raw = fs::read(&archive_path).unwrap();
        assert_eq!(
            (sha(&raw), raw.len()),
            (expected.archive_hash, expected.archive_bytes)
        );
        let archive = crate::bft_runtime_archive::Archive::decode(&raw).unwrap();
        assert_eq!(archive.format, crate::bft_runtime_archive::ONWARD_FORMAT);
        let mut with_wrapper = 0;
        for record in archive.runtime.messages.values() {
            let value = archive.envelope(record).unwrap();
            let wire: net::WireEnvelope = serde_json::from_value(value).unwrap();
            if let Some(proof) = wire.history {
                assert_eq!(proof, pins.proof);
                with_wrapper += 1;
            }
        }
        assert!(
            with_wrapper > 0,
            "complete wrapper disappeared on cold open"
        );
        let caller = bft_client::Client::lock(
            &root.join(format!("caller-{i}/head.json")),
            &root.join(format!("signer-{i}")),
            public(pins.seeds[i]),
            bft_client::ONWARD_FORMAT.into(),
            &node,
        )
        .unwrap();
        assert_eq!(caller.read().unwrap(), expected.caller);
        assert!(expected.caller.pending.is_none() && expected.caller.outbox.is_none());
        drop(caller);
        let agent = Agent::inspect_with_status(&root.join(format!("signer-{i}")), &node)
            .unwrap()
            .0;
        assert_eq!(agent.journal.creation.pin.height, 0);
        assert_eq!(agent.head().unwrap(), expected.caller.head);
        assert_ne!(agent.head().unwrap(), expected.initial_head);
        assert_eq!(agent.record_count(), expected.signer_records);
        assert_eq!(
            id(
                "onward-runtime-original-messages",
                &agent.retained_messages(&node).unwrap()
            )
            .unwrap(),
            expected.original_messages
        );
        drop(agent);
        drop(actor);
        drop(node);
    }
    assert_eq!(
        inventory(root),
        before,
        "read-only fresh-process cold closure rewrote evidence"
    );
    budget(pins.deadline);
    phase(pins.started, "fresh-process-four-cold-complete");
}
#[test]
#[ignore = "one fresh full A/B plus four original C Runtime custody and direct-carriage component, original 120 seconds"]
fn four_original_onward_runtimes_import_and_cold_replay() {
    run(Mode::Import);
}
fn run(mode: Mode) {
    if let Some(root) = std::env::var_os(CHILD) {
        cold_child(&PathBuf::from(root), mode);
        return;
    }
    let started = now();
    let deadline = started + 120.0;
    let (root, bootstrap, proof, a80, b4, export) = ancestors();
    budget(deadline);
    phase(started, "fresh-A80-B4-ready");
    let currency = bootstrap.currency.id().unwrap();
    let region = proof.history.destination;
    let mut seeds = (2u8..6).collect::<Vec<_>>();
    seeds.sort_by_key(|s| public(*s));
    let mut nodes = Vec::new();
    let mut ids = Vec::new();
    let mut transports = Vec::new();
    for i in 0..4 {
        budget(deadline);
        nodes.push(
            Store::create(
                &root.join(format!("ledger-{i}")),
                bootstrap.clone(),
                region,
                &public(1),
                currency,
            )
            .unwrap(),
        );
        let path = root.join(format!("transport-{i}"));
        let identity = initialize(
            &path,
            &currency.to_hex(),
            &region.to_hex(),
            "public-no-value-onward-runtime-component",
        )
        .unwrap();
        ids.push(identity["node_id"].as_str().unwrap().to_owned());
        let transport = json!({"format":MESH,"network":currency,"state":path,"contacts":[]});
        new_json(&root.join(format!("transport-config-{i}.json")), &transport);
        transports.push(transport);
    }
    let mut owner =
        (mode == Mode::OwnerSpend).then(|| owner_spend::Owner::create(&root, &nodes[0]));
    let mut actors = Vec::new();
    let mut initial_heads = Vec::new();
    for i in 0..4 {
        budget(deadline);
        let agent = Agent::create(
            &root.join(format!("signer-{i}")),
            &nodes[i],
            public(seeds[i]),
        )
        .unwrap();
        assert_eq!(agent.journal.creation.pin.height, 0);
        let state = bft_client::State {
            format: bft_client::ONWARD_FORMAT.into(),
            binding: agent.journal.binding.clone(),
            head: agent.head().unwrap(),
            pending: None,
            outbox: None,
        };
        initial_heads.push(state.head);
        drop(agent);
        new_json(
            &dir(&root.join(format!("caller-{i}"))).join("head.json"),
            &state,
        );
        new_json(
            &root.join(format!("key-{i}.json")),
            &json!({"secret_key":hex::encode([seeds[i];32])}),
        );
        dir(&root.join(format!("runtime-{i}")));
        let path = root.join(format!("phase1-config-{i}.json"));
        new_json(
            &path,
            &config(&root, i, &seeds, &ids, 1, nodes[i].storage_head().unwrap()),
        );
        actors.push(TestRuntime::open(&path, &nodes[i], &transports[i]).unwrap());
    }
    // One predeclared same-scope interruption after the first actual Native
    // signature, before caller response publication. Runtime selects the request
    // and signer; the fixture never chooses a leader, phase, proposal or vote.
    TestRuntime::fixture_stop_after_next_signature();
    let interrupted = 'await_signature: loop {
        budget(deadline);
        for i in 0..4 {
            budget(deadline);
            match actors[i].tick(&mut nodes[i]) {
                Ok(())=>(),
                Err(error) if error=="fixture stopped after durable Native signature before caller response"=>break 'await_signature i,
                Err(error)=>panic!("unexpected first-sign Runtime refusal: {error}"),
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(nodes.iter().all(|node| node.chain.height() == 0
        && node.chain.ledger.coins.is_empty()
        && node.chain.ledger.imports.is_empty()));
    let caller = bft_client::Client::lock(
        &root.join(format!("caller-{interrupted}/head.json")),
        &root.join(format!("signer-{interrupted}")),
        public(seeds[interrupted]),
        bft_client::ONWARD_FORMAT.into(),
        &nodes[interrupted],
    )
    .unwrap();
    let pending = caller.read().unwrap();
    assert!(pending.pending.is_some() && pending.outbox.is_none());
    assert_eq!(pending.head, initial_heads[interrupted]);
    drop(caller);
    let agent = Agent::inspect_with_status(
        &root.join(format!("signer-{interrupted}")),
        &nodes[interrupted],
    )
    .unwrap()
    .0;
    let signed_head = agent.head().unwrap();
    let original_response = agent.retained_messages(&nodes[interrupted]).unwrap();
    let signed_records = agent.record_count();
    assert_ne!(signed_head, pending.head);
    assert_eq!(signed_records, 1);
    assert_eq!(original_response.len(), 1);
    drop(agent);
    let native_heads = nodes
        .iter()
        .map(|node| node.storage_head().unwrap())
        .collect::<Vec<_>>();
    drop(actors);
    let key = root.join(format!("key-{interrupted}.json"));
    let kept = root.join(format!("key-{interrupted}.kept-original.json"));
    assert!(!kept.exists());
    fs::rename(&key, &kept).unwrap();
    fs::File::open(&root).unwrap().sync_all().unwrap();
    let mut actors = Vec::new();
    for i in 0..4 {
        budget(deadline);
        actors.push(
            TestRuntime::open(
                &root.join(format!("phase1-config-{i}.json")),
                &nodes[i],
                &transports[i],
            )
            .unwrap(),
        );
        assert_eq!(nodes[i].storage_head().unwrap(), native_heads[i]);
        let caller = bft_client::Client::lock(
            &root.join(format!("caller-{i}/head.json")),
            &root.join(format!("signer-{i}")),
            public(seeds[i]),
            bft_client::ONWARD_FORMAT.into(),
            &nodes[i],
        )
        .unwrap();
        let state = caller.read().unwrap();
        drop(caller);
        assert!(state.pending.is_none() && state.outbox.is_none());
        let agent = Agent::inspect_with_status(&root.join(format!("signer-{i}")), &nodes[i])
            .unwrap()
            .0;
        if i == interrupted {
            assert_eq!(state.head, signed_head);
            assert_eq!(agent.head().unwrap(), signed_head);
            assert_eq!(agent.record_count(), signed_records);
            assert_eq!(
                agent.retained_messages(&nodes[i]).unwrap(),
                original_response
            );
        } else {
            assert_eq!(state.head, initial_heads[i]);
            assert_eq!(agent.head().unwrap(), initial_heads[i]);
            assert_eq!(agent.record_count(), 0);
        }
    }
    assert!(!key.exists());
    fs::rename(&kept, &key).unwrap();
    fs::File::open(&root).unwrap().sync_all().unwrap();
    phase(
        started,
        "actual-first-sign-keyless-exact-response-recovered",
    );
    let mut seen = BTreeSet::new();
    let mut relayed = BTreeSet::new();
    let mut finalized_deliveries = BTreeSet::new();
    let mut live = match mode {
        Mode::Import => LiveLog::new(&root, started, deadline),
        Mode::OwnerSpend => LiveLog::with_coverage(
            &root,
            started,
            deadline,
            owner_spend::COVERAGE,
            owner_spend::EXCLUDED,
        ),
    };
    drive(
        &mut actors,
        &mut nodes,
        1,
        &mut seen,
        &mut relayed,
        &mut finalized_deliveries,
        &mut live,
    );
    for node in &nodes {
        assert!(node.chain.ledger.coins.is_empty() && node.chain.ledger.imports.is_empty());
        assert_eq!(node.chain.ledger.minted, Amount::ZERO);
    }
    let c1 = nodes[0]
        .evidence
        .snapshot(nodes[0].chain.finalized.unwrap())
        .unwrap()
        .clone();
    assert!(c1.blocks.last().unwrap().commands.is_empty());
    phase(started, "actual-empty-C1-all-four");
    // Predeclared phase barrier: only configuration stop-height changes. All
    // original Native stores, Agent journals, caller heads, archives and original
    // absolute deadline remain. Every phase configuration is retained separately.
    drop(actors);
    let mut actors = Vec::new();
    for i in 0..4 {
        budget(deadline);
        let path = root.join(format!("phase2-config-{i}.json"));
        new_json(
            &path,
            &config(&root, i, &seeds, &ids, 2, nodes[i].storage_head().unwrap()),
        );
        actors.push(TestRuntime::open(&path, &nodes[i], &transports[i]).unwrap());
    }
    // Rewrap a real Runtime-created C1 certificate; no C fixture signatures/QC.
    let receipt = strict_frame(net::Envelope {
        format: net::FORMAT.into(),
        currency,
        region,
        history: Some(proof.clone()),
        evidence: Evidence {
            snapshots: vec![c1.clone()],
        },
        body: Body::Finalized(Box::new(c1.clone())),
    });
    for i in 0..4 {
        budget(deadline);
        let before = nodes[i].chain.ledger.clone();
        actors[i].receive(&mut nodes[i], &receipt).unwrap();
        assert_eq!(nodes[i].chain.height(), 1);
        assert_eq!(nodes[i].chain.ledger, before);
        assert_eq!(
            nodes[i].complete_onward_network_pending_imports().unwrap(),
            vec![Command::Import {
                snapshot: b4,
                export
            }]
        );
        let before = inventory(&root);
        actors[i].receive(&mut nodes[i], &receipt).unwrap();
        assert_eq!(
            inventory(&root),
            before,
            "exact receipt retry rewrote durable state"
        );
    }
    phase(started, "complete-wrapper-custody-no-credit");
    drive(
        &mut actors,
        &mut nodes,
        2,
        &mut seen,
        &mut relayed,
        &mut finalized_deliveries,
        &mut live,
    );
    for node in &nodes {
        verify_import(node, a80, b4, export);
    }
    let mut checkpoints = vec![
        c1.statement.id().unwrap(),
        nodes[0].chain.finalized.unwrap(),
    ];
    let mut owner_pins = None;
    if let Some(mut original_owner) = owner.take() {
        original_owner.immature(&nodes[0], b4, export);
        for target in 3..=5 {
            budget(deadline);
            if target == 5 {
                original_owner.queue(&nodes[0], a80, b4, export, deadline);
                phase(started, "C4-original-owner-pending-sign-head-exact-queue");
            }
            // Same original four actors' durable custody; only the explicit
            // stop-height barrier changes. No C certificate is constructed here.
            if mode == Mode::OwnerSpend && target == 4 {
                let mut observation = OwnerOpenObservation::new(started, deadline);
                let barrier = observation.start("barrier", None);
                let clearing = observation.start("actors-clear", None);
                actors.clear();
                observation.finish(clearing, true, None);
                for i in 0..4 {
                    budget(deadline);
                    let path = root.join(format!("phase{target}-config-{i}.json"));
                    let reading_head = observation.start("head", Some(i));
                    let head = nodes[i].storage_head();
                    observation.finish(reading_head, head.is_ok(), None);
                    let head = head.unwrap();
                    let constructing_config = observation.start("config", Some(i));
                    let configuration = config(&root, i, &seeds, &ids, target, head);
                    observation.finish(constructing_config, true, None);
                    let writing_config = observation.start("config-write", Some(i));
                    new_json(&path, &configuration);
                    observation.finish(writing_config, true, None);
                    let opening = observation.start("runtime-open", Some(i));
                    let (opened, probe) = TestRuntime::probe_open(&path, &nodes[i], &transports[i]);
                    observation.finish(opening, opened.is_ok(), Some(probe));
                    actors.push(opened.unwrap());
                }
                observation.finish(barrier, true, None);
            } else {
                actors.clear();
                for i in 0..4 {
                    budget(deadline);
                    let path = root.join(format!("phase{target}-config-{i}.json"));
                    new_json(
                        &path,
                        &config(
                            &root,
                            i,
                            &seeds,
                            &ids,
                            target,
                            nodes[i].storage_head().unwrap(),
                        ),
                    );
                    actors.push(TestRuntime::open(&path, &nodes[i], &transports[i]).unwrap());
                }
            }
            drive(
                &mut actors,
                &mut nodes,
                target,
                &mut seen,
                &mut relayed,
                &mut finalized_deliveries,
                &mut live,
            );
            checkpoints.push(nodes[0].chain.finalized.unwrap());
            if target < 5 {
                for node in &nodes {
                    assert!(node
                        .evidence
                        .snapshot(node.chain.finalized.unwrap())
                        .unwrap()
                        .blocks
                        .last()
                        .unwrap()
                        .commands
                        .is_empty());
                    assert_eq!(node.chain.ledger.imports, BTreeMap::from([(export, b4)]));
                    assert_eq!(
                        node.chain.ledger.coins[&id("output", &(export, 0u32)).unwrap()]
                            .payment
                            .amount,
                        Amount(89)
                    );
                }
            }
            if target == 3 {
                original_owner.immature(&nodes[0], b4, export);
            }
            phase(started, &format!("actual-C{target}-all-four"));
        }
        owner_pins = Some(original_owner.complete(&nodes, a80, b4, export));
    }
    // Bind every actual certificate vote to the corresponding original Agent's
    // authenticated retained response, not merely to its public signature.
    let mut original_messages = Vec::new();
    let mut records = Vec::new();
    for (i, node) in nodes.iter().enumerate() {
        budget(deadline);
        let agent = Agent::inspect_with_status(&root.join(format!("signer-{i}")), node)
            .unwrap()
            .0;
        assert_eq!(agent.journal.creation.pin.height, 0);
        original_messages.push(agent.retained_messages(node).unwrap());
        records.push(agent.record_count());
    }
    for node in &nodes {
        assert_eq!(node.chain.height(), mode.height());
        for (index, checkpoint) in checkpoints.iter().enumerate() {
            let snapshot = node.evidence.snapshot(*checkpoint).unwrap();
            assert_eq!(snapshot.statement.height, index as u64 + 1);
            let certificate = snapshot.bft.as_ref().unwrap();
            for (quorum, phase) in [
                (&certificate.prepared, Phase::Prepare),
                (&certificate.committed, Phase::Commit),
            ] {
                assert_eq!(quorum.phase, phase);
                assert_eq!(quorum.votes.len(), 3);
                assert_eq!(quorum.value, snapshot.statement.id().unwrap());
                assert_eq!(quorum.context.parent_height, snapshot.statement.height - 1);
                assert_eq!(quorum.context.previous, snapshot.base);
                assert!(quorum
                    .votes
                    .windows(2)
                    .all(|v| v[0].approval.key < v[1].approval.key));
                for vote in &quorum.votes {
                    let voter = seeds
                        .iter()
                        .position(|s| public(*s) == vote.approval.key)
                        .unwrap();
                    assert!(original_messages[voter]
                        .iter()
                        .any(|m| matches!(m,Message::Vote(v) if v.as_ref()==vote)));
                }
            }
        }
        let before = inventory(&root);
        assert_eq!(
            node.bft_candidate(
                vec![Command::Import {
                    snapshot: b4,
                    export
                }],
                public(12)
            )
            .unwrap_err(),
            "permanent import tombstone rejects replay"
        );
        assert_eq!(inventory(&root), before);
    }
    phase(
        started,
        match mode {
            Mode::Import => "actual-C2-import-original-3prepare-3commit",
            Mode::OwnerSpend => "actual-C1-through-C5-original-3prepare-3commit",
        },
    );
    let live_observation = live.finish();
    let mut node_pins = Vec::new();
    for i in 0..4 {
        budget(deadline);
        let caller = bft_client::Client::lock(
            &root.join(format!("caller-{i}/head.json")),
            &root.join(format!("signer-{i}")),
            public(seeds[i]),
            bft_client::ONWARD_FORMAT.into(),
            &nodes[i],
        )
        .unwrap();
        let state = caller.read().unwrap();
        drop(caller);
        assert!(state.pending.is_none() && state.outbox.is_none());
        assert_ne!(state.head, initial_heads[i]);
        let archive = fs::read(root.join(format!("runtime-{i}/state.json"))).unwrap();
        let native_head = nodes[i].storage_head().unwrap();
        new_json(
            &root.join(format!("cold-config-{i}.json")),
            &config(&root, i, &seeds, &ids, mode.height(), native_head),
        );
        node_pins.push(NodePins {
            native_head,
            state: nodes[i].chain.ledger.root().unwrap(),
            finality: nodes[i].chain.finalized.unwrap(),
            caller: state,
            initial_head: initial_heads[i],
            signer_records: records[i],
            original_messages: id("onward-runtime-original-messages", &original_messages[i])
                .unwrap(),
            archive_hash: sha(&archive),
            archive_bytes: archive.len(),
            final_snapshot: nodes[i]
                .evidence
                .snapshot(nodes[i].chain.finalized.unwrap())
                .unwrap()
                .clone(),
        });
    }
    let pins = Pins {
        mode,
        checkpoints,
        owner: owner_pins,
        parent_pid: std::process::id(),
        started,
        deadline,
        currency,
        region,
        a80,
        b4,
        export,
        proof,
        seeds,
        nodes: node_pins,
    };
    new_json(&root.join("runtime-cold-pins.json"), &pins);
    drop(actors);
    drop(nodes);
    budget(deadline);
    let child_stdout = root.join("runtime-cold-child.stdout.log");
    let child_stderr = root.join("runtime-cold-child.stderr.log");
    crate::keystore::private_create(&child_stdout, b"").unwrap();
    crate::keystore::private_create(&child_stderr, b"").unwrap();
    let out = fs::OpenOptions::new()
        .write(true)
        .open(&child_stdout)
        .unwrap();
    let err = fs::OpenOptions::new()
        .write(true)
        .open(&child_stderr)
        .unwrap();
    let mut child = Process::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            mode.selector(),
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, &root)
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .unwrap();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("original 120-second budget exhausted during fresh-process cold closure; retained {}",root.display());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(
        status.success(),
        "fresh-process cold child failed; retained {}",
        root.display()
    );
    budget(deadline);
    phase(started, "component-complete");
    match mode {
        Mode::Import => eprintln!(
            "onward_runtime_result={}",
            json!({"elapsed_seconds":now()-started,"root":root,"live_observation":live_observation,
            "c1_actual_runtime":true,"c2_actual_runtime":true,"native_import":true,"original_custody":true,
            "fresh_process_cold":true,"post_sign_keyless_recovery":true,"ordinary_service":false,"maturity_or_onward_spend":false,"independent_qualification":false})
        ),
        Mode::OwnerSpend => eprintln!(
            "onward_owner_runtime_result={}",
            json!({
            "elapsed_seconds":now()-started,"root":root,"live_observation":live_observation,
            "c1_actual_runtime":true,"c2_actual_runtime":true,"c3_actual_runtime":true,
            "c4_actual_runtime":true,"c5_actual_runtime":true,"native_import":true,"original_custody":true,
            "fresh_process_cold":true,"post_sign_keyless_recovery":true,"owner_creation_height":0,
            "immature_refusal_heights":[2,3],"exact_queue_retry":true,"owner_pending_before_sign":true,
            "owner_head_before_queue":true,"original_owner_spend":true,"all_five_certificates_original_custody":true,
            "owner_submission":pins.owner.as_ref().unwrap().report(),
            "ordinary_service":false,"independent_qualification":false})
        ),
    }
    // Success and failure both preserve this fresh scope; no cleanup/reopen of historical fixtures.
}

// Fresh public no-value refusal seams with independent original custody.
// One fresh 60-second component; no Runtime tick or new consensus qualification.
mod negative_seams {
    use super::*;
    use crate::bft::{Context, Request};
    use crate::bft_runtime_archive::{Archive, Header as EnvelopeHeader};

    const LIMIT: f64 = 60.0;
    fn check(deadline: f64) {
        assert!(
            now() < deadline,
            "original 60-second Onward Runtime negative scope exhausted"
        );
    }
    fn mark(started: f64, name: &str) {
        eprintln!(
            "onward_runtime_negative_phase={}",
            json!({"phase":name,"elapsed_seconds":now()-started})
        );
    }
    pub(super) struct Target {
        pub(super) root: PathBuf,
        pub(super) node: Store,
        pub(super) actor: Option<TestRuntime>,
        transport: Value,
        seeds: Vec<u8>,
        ids: Vec<String>,
    }
    impl Target {
        pub(super) fn new(root: &Path, name: &str, bootstrap: &Bootstrap, region: Hash) -> Self {
            let root = dir(&root.join(name));
            let currency = bootstrap.currency.id().unwrap();
            let node = Store::create(
                &root.join("ledger"),
                bootstrap.clone(),
                region,
                &public(1),
                currency,
            )
            .unwrap();
            let mut seeds = (2u8..6).collect::<Vec<_>>();
            seeds.sort_by_key(|seed| public(*seed));
            let mut ids = Vec::new();
            let mut transports = Vec::new();
            for i in 0..4 {
                let state = root.join(format!("transport-{i}"));
                let identity = initialize(
                    &state,
                    &currency.to_hex(),
                    &region.to_hex(),
                    "public-no-value-onward-negative",
                )
                .unwrap();
                ids.push(identity["node_id"].as_str().unwrap().to_owned());
                transports
                    .push(json!({"format":MESH,"network":currency,"state":state,"contacts":[]}));
            }
            let agent = Agent::create(&root.join("signer-0"), &node, public(seeds[0])).unwrap();
            assert_eq!(agent.journal.creation.pin.height, 0);
            let caller = bft_client::State {
                format: bft_client::ONWARD_FORMAT.into(),
                binding: agent.journal.binding.clone(),
                head: agent.head().unwrap(),
                pending: None,
                outbox: None,
            };
            drop(agent);
            new_json(&dir(&root.join("caller-0")).join("head.json"), &caller);
            new_json(
                &root.join("key-0.json"),
                &json!({"secret_key":hex::encode([seeds[0];32])}),
            );
            dir(&root.join("runtime-0"));
            let path = root.join("initial-config.json");
            new_json(
                &path,
                &config(&root, 0, &seeds, &ids, 0, node.storage_head().unwrap()),
            );
            let actor = TestRuntime::open(&path, &node, &transports[0]).unwrap();
            Self {
                root,
                node,
                actor: Some(actor),
                transport: transports.remove(0),
                seeds,
                ids,
            }
        }
        fn archive_path(&self) -> PathBuf {
            self.root.join("runtime-0/state.json")
        }
        fn caller_path(&self) -> PathBuf {
            self.root.join("caller-0/head.json")
        }
        fn caller(&self) -> bft_client::Client {
            bft_client::Client::lock(
                &self.caller_path(),
                &self.root.join("signer-0"),
                public(self.seeds[0]),
                bft_client::ONWARD_FORMAT.into(),
                &self.node,
            )
            .unwrap()
        }
        fn timeout(&mut self, round: u64) -> Message {
            let request = Request::Timeout {
                context: Context::current(&self.node).unwrap(),
                round,
            };
            let message = self
                .actor
                .as_mut()
                .unwrap()
                .sign_fixture_control(&self.node, request)
                .unwrap();
            match &message {
                Message::Timeout(vote) => assert_eq!(vote.round, round),
                _ => panic!("actual original Agent timeout required"),
            }
            message
        }
        // Actual consent precedes original Native signing. Deliberately stop
        // before publishing the response to the caller or Runtime archive.
        fn signed_pending(&self, round: u64) {
            let request = Request::Timeout {
                context: Context::current(&self.node).unwrap(),
                round,
            };
            let caller = self.caller();
            let old = caller.read().unwrap();
            assert!(old.pending.is_none() && old.outbox.is_none());
            let mut pending = old.clone();
            pending.pending = Some(request.clone());
            caller
                .store(
                    &self.node,
                    bft_client::Transition {
                        previous_sha256: sha(&files::canonical(&old).unwrap()),
                        proposed: pending.clone(),
                    },
                )
                .unwrap();
            drop(caller);
            let mut agent = Agent::open(&self.root.join("signer-0"), &self.node).unwrap();
            let signed = agent
                .sign(
                    &self.node,
                    request.clone(),
                    Some(&self.root.join("key-0.json")),
                    old.head,
                )
                .unwrap();
            assert!(!signed.recovered_exact_retry);
            assert_ne!(signed.head, old.head);
            drop(agent);
            let (agent, status, response) = Agent::inspect_with_response_status(
                &self.root.join("signer-0"),
                &self.node,
                &request,
                old.head,
            )
            .unwrap();
            let observed = response.unwrap();
            assert_eq!(observed.message, signed.message);
            assert_eq!(status.head, signed.head);
            assert!(observed.recovered_exact_retry);
            drop(agent);
            assert_eq!(self.caller().read().unwrap(), pending);
        }
        pub(super) fn stop(&mut self) {
            drop(self.actor.take());
        }
        fn open_refuses_unchanged(&self, expected: &str) {
            assert!(self.actor.is_none());
            // Pin the actual current Native head so a stale-head refusal cannot
            // mask the intended authentication/quarantine boundary.
            let path = self.root.join("negative-open-config.json");
            new_json(
                &path,
                &config(
                    &self.root,
                    0,
                    &self.seeds,
                    &self.ids,
                    0,
                    self.node.storage_head().unwrap(),
                ),
            );
            let pending: bft_client::State =
                bft_client::decode(&fs::read(self.caller_path()).unwrap()).unwrap();
            assert!(pending.pending.is_some() && pending.outbox.is_none());
            let before = inventory(&self.root);
            let head = self.node.storage_head().unwrap();
            let ledger = self.node.chain.ledger.clone();
            let error = match TestRuntime::open(&path, &self.node, &self.transport) {
                Ok(_) => panic!("cold refusal unexpectedly opened Runtime"),
                Err(error) => error,
            };
            assert!(
                error.contains(expected),
                "expected {expected:?}, got {error:?}"
            );
            assert_eq!(self.node.storage_head().unwrap(), head);
            assert_eq!(self.node.chain.ledger, ledger);
            assert_eq!(
                inventory(&self.root),
                before,
                "refusal mutated caller, signer, archive or Native files"
            );
            assert_eq!(
                bft_client::decode::<bft_client::State>(&fs::read(self.caller_path()).unwrap())
                    .unwrap(),
                pending
            );
            eprintln!(
                "onward_runtime_negative_refusal={}",
                json!({"target":self.root.file_name().unwrap().to_string_lossy(),"error":error})
            );
        }
        fn store_fault_archive(&self, archive: &Archive) {
            assert!(self.actor.is_none());
            let path = self.archive_path();
            let original = fs::read(&path).unwrap();
            crate::keystore::private_create(
                &self.root.join("original-archive-before-negative.json"),
                &original,
            )
            .unwrap();
            let raw = files::canonical_with_limit(archive, crate::bft_runtime_archive::MAX_STATE)
                .unwrap();
            // Hash/length/reference/canonical checks must all succeed: this is
            // deliberately an authentication fault, not a malformed-byte test.
            Archive::decode(&raw).unwrap();
            use std::io::Write;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&path)
                .unwrap();
            file.write_all(&raw).unwrap();
            file.sync_all().unwrap();
            fs::File::open(path.parent().unwrap())
                .unwrap()
                .sync_all()
                .unwrap();
        }
    }
    fn envelope(
        node: &Store,
        proof: Option<CompleteOnwardNetworkHistory>,
        message: Message,
    ) -> net::Envelope {
        net::Envelope {
            format: net::FORMAT.into(),
            currency: node.trust.currency().unwrap(),
            region: node.chain.region,
            history: proof,
            evidence: Evidence::default(),
            body: Body::Signed(Box::new(message)),
        }
    }
    // Used only with these C0 timeout records: no C prefix references can be
    // dropped, and every original unrelated archive member stays exact.
    fn replace_empty_prefix_record(
        archive: &mut Archive,
        old: Hash,
        envelope: &net::Envelope,
    ) -> Hash {
        let wire = envelope.pack().unwrap();
        assert!(wire.evidence.snapshots.is_empty());
        let value = serde_json::to_value(&wire).unwrap();
        let raw = files::canonical_with_limit(&value, crate::contact::MAX_PAYLOAD).unwrap();
        let ident = sha(&files::canonical(&value["body"]).unwrap());
        let mut record = archive.runtime.messages.remove(&old).unwrap();
        assert!(
            record.refs.is_empty()
                && record.origin_refs.is_none()
                && record.onward_history_ref.is_none()
        );
        record.header = EnvelopeHeader {
            format: wire.format,
            currency: wire.currency,
            region: wire.region,
        };
        record.body = value["body"].clone();
        record.sha256 = sha(&raw);
        record.size_bytes = raw.len();
        record.value = envelope.body.checkpoint_value().unwrap();
        record.onward_history_ref = wire.history.as_ref().map(|history| {
            let value = serde_json::to_value(history).unwrap();
            let reference = sha(&files::canonical(&value).unwrap());
            assert!(archive.snapshots.insert(reference, value).is_none());
            reference
        });
        assert!(archive.runtime.messages.insert(ident, record).is_none());
        ident
    }
    pub(super) fn authentic_alternate_a80(
        bootstrap: &Bootstrap,
        proof: &CompleteOnwardNetworkHistory,
    ) -> Snapshot {
        let origin = &proof.history.origin;
        let header = Header {
            format: FORMAT.into(),
            region: origin.source,
            bootstrap: bootstrap.clone(),
        };
        let mut fork = super::super::body_witness_tests::replay(&header);
        let records = origin
            .snapshots
            .iter()
            .cloned()
            .map(|s| Record::Certified(Box::new(s)))
            .collect::<Vec<_>>();
        let history = super::super::origin_history::test_history(&header, &fork, &records);
        for record in &records[..79] {
            fork.apply_retained(record, &history).unwrap();
        }
        let retained_export = fork.chain.ledger.exports[&origin.export].clone();
        let (input, coin) = fork
            .chain
            .ledger
            .coins
            .iter()
            .find(|(_, coin)| coin.created == 2 && coin.payment.owner == public(10))
            .unwrap();
        let intent = Intent {
            currency: bootstrap.currency.id().unwrap(),
            region: origin.source,
            inputs: vec![*input],
            outputs: vec![Payment {
                owner: public(15),
                amount: coin.payment.amount.checked_sub(Amount(1)).unwrap(),
            }],
            fee: Amount(1),
            destination: None,
            remote: None,
            destination_fee: Amount::ZERO,
            valid_through: 128,
        };
        let signed = SignedIntent {
            approvals: vec![Approval {
                key: public(10),
                signature: signature(10, &intent.bytes().unwrap()),
            }],
            intent,
        };
        let alternate = certified_with_commands(&fork, vec![Command::Spend(Box::new(signed))]);
        fork.apply_retained(&Record::Certified(Box::new(alternate.clone())), &history)
            .unwrap();
        assert_eq!(fork.chain.height(), 80);
        assert_eq!(fork.chain.ledger.exports[&origin.export], retained_export);
        Conflict::from_snapshots(&origin.snapshots[79], &alternate)
            .unwrap()
            .verify(&fork.trust)
            .unwrap();
        alternate
    }

    #[test]
    #[ignore = "one fresh 60-second Onward Runtime negative component, actual original custody; no ordinary service qualification"]
    fn onward_runtime_refuses_cold_authentication_before_recovery_and_retains_conflicts() {
        let started = now();
        let deadline = started + LIMIT;
        let (root, bootstrap, proof, _, _, _) = ancestors();
        check(deadline);
        let region = proof.history.destination;
        let alternate = authentic_alternate_a80(&bootstrap, &proof);
        let conflict =
            Conflict::from_snapshots(&proof.history.origin.snapshots[79], &alternate).unwrap();
        mark(started, "one-fresh-A80-B4-and-authentic-A-conflict-ready");

        // Empty archive: an actual signed response is recoverable, but retained
        // ancestor quarantine must refuse before even publishing that response.
        let mut empty = Target::new(&root, "empty-quarantine", &bootstrap, region);
        assert!(Archive::decode(&fs::read(empty.archive_path()).unwrap())
            .unwrap()
            .runtime
            .messages
            .is_empty());
        // Wrong old caller/archive formats refuse before creating their targets.
        let absent = empty.root.join("wrong-profile-absent");
        assert!(bft_client::Client::lock(
            &absent.join("caller/head.json"),
            &absent.join("signer"),
            public(empty.seeds[0]),
            bft_client::FORMAT.into(),
            &empty.node
        )
        .is_err());
        assert!(crate::bft_runtime_archive::Client::lock(
            &absent.join("archive"),
            public(empty.seeds[0]),
            bft_client::FORMAT.into(),
            &empty.node
        )
        .is_err());
        assert!(!absent.exists());
        empty.signed_pending(0);
        empty.stop();
        empty.node.observe_conflict(conflict.clone()).unwrap();
        assert_eq!(empty.node.journal.incident_ids.len(), 1);
        empty.open_refuses_unchanged("operations are quarantined");
        check(deadline);
        mark(started, "empty-archive-quarantine-before-recovery");

        // At least one authentic record sorts before the deliberately corrupted
        // final record. Whole byte graph validation succeeds before cold auth.
        let mut bad = Target::new(&root, "late-invalid-signature", &bootstrap, region);
        bad.timeout(0);
        bad.timeout(1);
        bad.signed_pending(2);
        bad.stop();
        let mut archive = Archive::decode(&fs::read(bad.archive_path()).unwrap()).unwrap();
        assert_eq!(archive.runtime.messages.len(), 2);
        let (&old, record) = archive.runtime.messages.last_key_value().unwrap();
        let original: net::WireEnvelope =
            serde_json::from_value(archive.envelope(record).unwrap()).unwrap();
        let mut invalid = original.expand().unwrap();
        invalid.verify(&bad.node).unwrap();
        let lower = *archive.runtime.messages.first_key_value().unwrap().0;
        let mut found = false;
        for byte in 0u16..256 {
            let Body::Signed(message) = &mut invalid.body else {
                panic!("signed timeout required")
            };
            let Message::Timeout(vote) = message.as_mut() else {
                panic!("timeout required")
            };
            let mut signature = [0u8; 64];
            signature[0] = byte as u8;
            vote.approval.signature = hex::encode(signature);
            let ident = sha(&files::canonical(&invalid.body).unwrap());
            if ident > lower {
                found = true;
                break;
            }
        }
        assert!(
            found,
            "could not place malformed signature after authentic record"
        );
        let expected = invalid.verify(&bad.node).unwrap_err();
        let changed = replace_empty_prefix_record(&mut archive, old, &invalid);
        assert_eq!(
            *archive.runtime.messages.last_key_value().unwrap().0,
            changed
        );
        let first = archive.runtime.messages.first_key_value().unwrap().1;
        crate::bft_runtime_envelope::Wire::decode(
            archive.envelope(first).unwrap(),
            bft_client::ONWARD_FORMAT,
        )
        .unwrap()
        .verify_cold(&bad.node)
        .unwrap();
        bad.store_fault_archive(&archive);
        bad.open_refuses_unchanged(&expected);
        check(deadline);
        mark(started, "late-byte-valid-invalid-signature-before-recovery");

        // This wrapper is genuinely Native-verifiable but was never installed
        // in this fresh target. Valid signatures alone cannot supply cold state.
        let mut absent = Target::new(&root, "uninstalled-wrapper", &bootstrap, region);
        let message = absent.timeout(0);
        absent.signed_pending(1);
        absent.stop();
        let valid = envelope(&absent.node, Some(proof.clone()), message);
        valid.verify(&absent.node).unwrap();
        let mut archive = Archive::decode(&fs::read(absent.archive_path()).unwrap()).unwrap();
        assert_eq!(archive.runtime.messages.len(), 1);
        let old = *archive.runtime.messages.keys().next().unwrap();
        replace_empty_prefix_record(&mut archive, old, &valid);
        absent.store_fault_archive(&archive);
        absent.open_refuses_unchanged("onward cold complete material absent from Native history");
        assert!(
            absent.node.chain.ledger.imports.is_empty()
                && absent.node.chain.ledger.coins.is_empty()
        );
        check(deadline);
        mark(started, "valid-uninstalled-wrapper-before-recovery");

        // Same body: successful new complete proof custody precedes dedup;
        // failed proof still authenticates, and a real incident survives bad tail.
        let mut incoming = Target::new(&root, "same-body-incoming", &bootstrap, region);
        let message = incoming.timeout(0);
        let valid = envelope(&incoming.node, Some(proof.clone()), message);
        valid.verify(&incoming.node).unwrap();
        let exact_wire = serde_json::to_value(valid.pack().unwrap()).unwrap();
        assert!(
            crate::bft_runtime_envelope::Wire::decode(exact_wire.clone(), bft_client::FORMAT)
                .is_err()
        );
        let mut old_wire = exact_wire;
        old_wire["format"] = Value::String(crate::bft_network::FORMAT.into());
        old_wire.as_object_mut().unwrap().remove("history");
        assert!(
            crate::bft_runtime_envelope::Wire::decode(old_wire, bft_client::ONWARD_FORMAT).is_err()
        );
        let archive_before = fs::read(incoming.archive_path()).unwrap();
        let caller_before = fs::read(incoming.caller_path()).unwrap();
        let native_before = incoming.node.storage_head().unwrap();
        incoming
            .actor
            .as_mut()
            .unwrap()
            .receive(&mut incoming.node, &strict_frame(valid.clone()))
            .unwrap();
        assert_ne!(incoming.node.storage_head().unwrap(), native_before);
        assert_eq!(
            incoming
                .node
                .complete_onward_network_pending_imports()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(fs::read(incoming.archive_path()).unwrap(), archive_before);
        assert_eq!(fs::read(incoming.caller_path()).unwrap(), caller_before);
        assert_eq!(incoming.node.chain.height(), 0);
        assert!(
            incoming.node.chain.ledger.coins.is_empty()
                && incoming.node.chain.ledger.imports.is_empty()
        );
        // Independently authenticate the same body under the received closure.
        let mut tailed = valid.clone();
        let history = &mut tailed.history.as_mut().unwrap().history;
        history.origin.snapshots[79] = alternate;
        // An extra later record is a corrupted complete real B4 certificate;
        // it is not represented as a valid new B5 or a produced failure block.
        let mut invalid_later = history.snapshots[3].clone();
        invalid_later.bft.as_mut().unwrap().committed.votes[0]
            .approval
            .signature = "00".repeat(64);
        history.snapshots.push(invalid_later);
        let mut forged = tailed.clone();
        forged.history.as_mut().unwrap().history.origin.snapshots[79]
            .bft
            .as_mut()
            .unwrap()
            .committed
            .votes[0]
            .approval
            .signature = "00".repeat(64);
        let before = inventory(&incoming.root);
        assert!(incoming
            .actor
            .as_mut()
            .unwrap()
            .receive(&mut incoming.node, &strict_frame(forged))
            .is_err());
        assert!(incoming.node.journal.incident_ids.is_empty());
        assert_eq!(inventory(&incoming.root), before);
        let ledger = incoming.node.chain.ledger.clone();
        let error = incoming
            .actor
            .as_mut()
            .unwrap()
            .receive(&mut incoming.node, &strict_frame(tailed))
            .unwrap_err();
        assert!(error.contains("conflict retained"), "{error}");
        assert_eq!(incoming.node.journal.incident_ids.len(), 1);
        assert!(incoming
            .node
            .safety
            .check_region(proof.history.origin.source)
            .is_err());
        assert_eq!(incoming.node.chain.ledger, ledger);
        assert_eq!(incoming.node.chain.height(), 0);
        assert_eq!(fs::read(incoming.archive_path()).unwrap(), archive_before);
        assert_eq!(fs::read(incoming.caller_path()).unwrap(), caller_before);
        let before = inventory(&incoming.root);
        assert!(incoming
            .actor
            .as_mut()
            .unwrap()
            .receive(&mut incoming.node, &strict_frame(valid))
            .is_err());
        assert!(incoming
            .node
            .complete_onward_network_pending_imports()
            .is_err());
        assert_eq!(inventory(&incoming.root), before);
        incoming.stop();
        check(deadline);
        mark(
            started,
            "same-body-full-auth-and-genuine-conflict-before-bad-tail",
        );
        eprintln!(
            "onward_runtime_negative_result={}",
            json!({"elapsed_seconds":now()-started,"root":root,"passed":true,
            "fresh_targets":4,"actual_original_c0_agents":true,"empty_quarantine_before_recovery":true,
            "late_invalid_archive_before_recovery":true,"uninstalled_wrapper_before_recovery":true,
            "same_body_sync_before_dedup":true,"forged_no_incident":true,"genuine_conflict_bad_tail_retained":true,
            "exact_qc_variant_case":false,"fresh_process_cold":false,"ordinary_service":false,"independent_qualification":false})
        );
    }
}

#[path = "onward_owner_queue_tests.rs"]
mod queue_negative;

#[path = "onward_receive_observation_tests.rs"]
mod receive_observation;

#[path = "onward_receive_witness_negative_tests.rs"]
mod receive_witness_negative;

#[path = "onward_cold_observation_tests.rs"]
mod cold_observation;

#[path = "onward_local_builder_negative_tests.rs"]
mod local_builder_negative;

#[path = "onward_archive_witness_negative_tests.rs"]
mod archive_witness_negative;

#[path = "onward_service_frame_tests.rs"]
mod service_frame;

#[path = "onward_service_routing_tests.rs"]
mod service_routing;
