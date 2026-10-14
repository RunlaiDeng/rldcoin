//! Real CLI/TLS proof custody only; C0 stop-height does not qualify payment.
//! Nested under onward_runtime_tests to reuse its fresh A80/B4(+B5 tail) helper.
use super::*;
use crate::contact_runtime::{tls_identity, Node};
use std::io::Write;
use std::net::TcpListener;
use std::process::{Child, ExitStatus};

const ROUTING_TEST: &str = "storage::paged::onward_runtime_tests::service_routing::ordinary_onward_service_tls_retains_complete_proof_without_credit";
const ROUTING_CHILD: &str = "RLD_ONWARD_SERVICE_ROUTING_COLD_CHILD";
const CLI_ENV: &str = "RLD_ONWARD_SERVICE_CLI";
const CLI_SHA_ENV: &str = "RLD_ONWARD_SERVICE_CLI_SHA256";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoutingPins {
    started: f64,
    deadline: f64,
    currency: Hash,
    proof: CompleteOnwardNetworkHistory,
    a80: Hash,
    b4: Hash,
    export: Hash,
    b_head: Hash,
    b_ledger_root: Hash,
    c_head: Hash,
    c_ledger_root: Hash,
    caller: bft_client::State,
    seed: u8,
    signer_records: usize,
    transports: Vec<Value>,
    tls: Vec<Value>,
    runtime_config: PathBuf,
    cli: PathBuf,
    cli_sha256: Hash,
}
fn routing_budget(deadline: f64) {
    assert!(
        now() < deadline,
        "original 60-second Onward Service routing scope exhausted"
    );
}
fn routing_phase(started: f64, name: &str) {
    eprintln!(
        "onward_service_routing_phase={}",
        json!({"phase":name,"elapsed_seconds":now()-started})
    );
}
fn output_file(path: &Path) -> fs::File {
    crate::keystore::private_create(path, b"").unwrap();
    fs::OpenOptions::new().write(true).open(path).unwrap()
}
// Test-only wait observations. Unbuffered rows survive process exit; only the
// terminal is fsynced. This does not qualify power-loss or Native custody.
struct WaitTrace {
    root: PathBuf,
    file: fs::File,
    started: f64,
    deadline: f64,
    rows: usize,
    bytes: usize,
    last: Option<Value>,
    terminal_written: bool,
}
impl WaitTrace {
    const MAX_ROWS: usize = 16_384;
    const MAX_BYTES: usize = 8 * 1024 * 1024;
    fn new(
        root: &Path,
        started: f64,
        deadline: f64,
        source_node_id: &str,
        currency: Hash,
        source_region: Hash,
    ) -> Self {
        let scope = json!({"format":"RLD-ONWARD-ROUTING-WAIT-V2","root":root,
            "started":started,"deadline":deadline,"pid":std::process::id(),
            "source_node_id":source_node_id,"currency":currency,"source_region":source_region,
            "max_rows":Self::MAX_ROWS,"max_bytes":Self::MAX_BYTES,
            "diagnostic_only":true,"fixture_only":true});
        new_json(&root.join("routing-wait-scope.json"), &scope);
        eprintln!("\nonward_service_routing_wait_scope={scope}");
        Self {
            root: root.into(),
            file: output_file(&root.join("routing-wait.jsonl")),
            started,
            deadline,
            rows: 0,
            bytes: 0,
            last: None,
            terminal_written: false,
        }
    }
    fn event(&mut self, phase: &str, detail: Value) -> crate::Result<()> {
        let row = json!({"sequence":self.rows+1,"at":now(),"phase":phase,"detail":detail});
        let mut raw = serde_json::to_vec(&row).map_err(|e| e.to_string())?;
        raw.push(b'\n');
        require(
            self.rows < Self::MAX_ROWS && self.bytes + raw.len() <= Self::MAX_BYTES,
            "routing wait diagnostic bound exhausted",
        )?;
        self.file.write_all(&raw).map_err(|e| e.to_string())?;
        self.rows += 1;
        self.bytes += raw.len();
        self.last = Some(row);
        Ok(())
    }
    fn finish(&mut self, wait_complete: bool) -> crate::Result<()> {
        self.file.sync_all().map_err(|e| e.to_string())?;
        let raw = fs::read(self.root.join("routing-wait.jsonl")).map_err(|e| e.to_string())?;
        require(
            raw.len() == self.bytes,
            "routing wait observation size differs",
        )?;
        let terminal = json!({"format":"RLD-ONWARD-ROUTING-WAIT-V2","root":self.root,
            "started":self.started,"deadline":self.deadline,"ended":now(),
            "pid":std::process::id(),"rows":self.rows,"bytes":self.bytes,"sha256":sha(&raw),
            "last":self.last,"wait_complete":wait_complete,"diagnostic_only":true,
            "routing_qualified":false});
        crate::keystore::private_create(
            &self.root.join("routing-wait-terminal.json"),
            &serde_json::to_vec(&terminal).map_err(|e| e.to_string())?,
        )?;
        self.terminal_written = true;
        eprintln!("\nonward_service_routing_wait_terminal={terminal}");
        Ok(())
    }
}
impl Drop for WaitTrace {
    fn drop(&mut self) {
        if self.terminal_written {
            return;
        }
        if let Err(error) = self.finish(false) {
            eprintln!("routing wait diagnostic terminal unavailable: {error}");
        }
    }
}
struct ServiceChild {
    process: Child,
    stdout: PathBuf,
    stderr: PathBuf,
    joined: bool,
}
impl ServiceChild {
    fn spawn(
        pins: &RoutingPins,
        root: &Path,
        label: &str,
        ledger: &Path,
        transport: &Path,
        listen: &str,
        runtime: Option<&Path>,
    ) -> Self {
        let stdout = root.join(format!("{label}.stdout"));
        let stderr = root.join(format!("{label}.stderr"));
        let mut command = Process::new(&pins.cli);
        command.args([
            "--dir",
            ledger.to_str().unwrap(),
            "--authority",
            &public(1),
            "--currency",
            &pins.currency.to_hex(),
            "--mesh-config",
            transport.to_str().unwrap(),
            "--mesh-listen",
            listen,
            "--interval",
            "0.1",
        ]);
        if let Some(path) = runtime {
            command.args(["--bft-config", path.to_str().unwrap()]);
        }
        // No subcommand, miner, plaintext flag, proof file or driver carriage.
        let process = command
            .stdout(Stdio::from(output_file(&stdout)))
            .stderr(Stdio::from(output_file(&stderr)))
            .spawn()
            .unwrap();
        Self {
            process,
            stdout,
            stderr,
            joined: false,
        }
    }
    fn running(&mut self) {
        if let Some(status) = self.process.try_wait().unwrap() {
            self.joined = true;
            panic!(
                "ordinary Service terminated early: {status}; retained stdout={} stderr={}",
                self.stdout.display(),
                self.stderr.display()
            );
        }
    }
    fn ready(&mut self, deadline: f64, listen: &str, fingerprint: &Value) {
        loop {
            routing_budget(deadline);
            self.running();
            let raw = fs::read(&self.stdout).unwrap();
            assert!(raw.len() <= 64 * 1024, "bounded Service startup output");
            if let Some(line) = raw.split(|b| *b == b'\n').find(|line| !line.is_empty()) {
                if let Ok(value) = serde_json::from_slice::<Value>(line) {
                    assert_eq!(value["listen"], listen);
                    assert_eq!(&value["tls"]["fingerprint"], fingerprint);
                    return;
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    fn request_stop(&mut self) {
        self.running();
        assert_eq!(
            unsafe { libc::kill(self.process.id() as libc::pid_t, libc::SIGTERM) },
            0
        );
    }
    fn join(&mut self, deadline: f64) -> ExitStatus {
        loop {
            routing_budget(deadline);
            if let Some(status) = self.process.try_wait().unwrap() {
                self.joined = true;
                return status;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
impl Drop for ServiceChild {
    fn drop(&mut self) {
        if self.joined {
            return;
        }
        // Failure cleanup only. Its stop time cannot convert the original timeout into success.
        unsafe {
            libc::kill(self.process.id() as libc::pid_t, libc::SIGTERM);
        }
        let until = std::time::Instant::now() + Duration::from_secs(4);
        while std::time::Instant::now() < until {
            if self.process.try_wait().ok().flatten().is_some() {
                self.joined = true;
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.process.kill();
        let _ = self.process.wait();
        self.joined = true;
    }
}
fn custody(root: &Path) -> BTreeMap<PathBuf, (Hash, u64, std::time::SystemTime)> {
    let mut files = inventory(&root.join("routing-signer"));
    files.extend(inventory(&root.join("routing-caller")));
    files
}
fn check_zero_credit(node: &Store, pins: &RoutingPins) {
    assert_eq!(node.chain.region, pins.proof.history.destination);
    assert_eq!(node.chain.height(), 0);
    assert!(node.chain.finalized.is_none());
    assert!(node.chain.ledger.coins.is_empty());
    assert!(node.chain.ledger.imports.is_empty());
    assert!(node.chain.ledger.exports.is_empty());
    assert_eq!(node.chain.ledger.minted, Amount::ZERO);
    assert_eq!(node.chain.ledger.root().unwrap(), pins.c_ledger_root);
    let commands = node.complete_onward_network_pending_imports().unwrap();
    assert_eq!(
        commands,
        vec![Command::Import {
            snapshot: pins.b4,
            export: pins.export
        }]
    );
    let (proof, evidence) = node.onward_network_material().unwrap();
    assert_eq!(proof, Some(pins.proof.clone()));
    assert!(evidence.snapshots.is_empty());
    node.require_retained_onward_material(Some(&pins.proof), &[])
        .unwrap();
    assert!(node.evidence.snapshot(pins.a80).is_ok());
    assert!(node.evidence.snapshot(pins.b4).is_ok());
    assert_eq!(node.paged.as_ref().unwrap().record_count(), 1);
}
fn check_source(node: &Store, pins: &RoutingPins) {
    assert_eq!(node.chain.height(), 5); // Existing helper has a genuine later empty B5.
    assert_eq!(node.storage_head().unwrap(), pins.b_head);
    assert_eq!(node.chain.ledger.root().unwrap(), pins.b_ledger_root);
    assert_eq!(node.chain.ledger.minted, Amount::ZERO);
    assert_eq!(
        node.chain
            .ledger
            .imports
            .get(&pins.proof.history.origin.export),
        Some(&pins.a80)
    );
    assert!(!node
        .chain
        .ledger
        .coins
        .contains_key(&id("output", &(pins.proof.history.origin.export, 0u32)).unwrap()));
    assert_eq!(
        node.chain.ledger.exports[&pins.export].dependencies,
        BTreeSet::from([pins.a80])
    );
    assert_eq!(
        node.complete_onward_network_export(pins.export).unwrap(),
        pins.proof
    );
}
fn caller_unchanged(root: &Path, node: &Store, pins: &RoutingPins) {
    let caller = bft_client::Client::lock(
        &root.join("routing-caller/head.json"),
        &root.join("routing-signer"),
        public(pins.seed),
        bft_client::ONWARD_FORMAT.into(),
        node,
    )
    .unwrap();
    assert_eq!(caller.read().unwrap(), pins.caller);
    assert!(pins.caller.pending.is_none() && pins.caller.outbox.is_none());
    drop(caller);
    let agent = Agent::inspect_with_status(&root.join("routing-signer"), node)
        .unwrap()
        .0;
    assert_eq!(agent.journal.creation.pin.height, 0);
    assert_eq!(agent.head().unwrap(), pins.caller.head);
    assert_eq!(agent.record_count(), pins.signer_records);
    assert!(agent.retained_messages(node).unwrap().is_empty());
    assert!(!root.join("routing-key-must-remain-absent.json").exists());
}
fn preflight_refusals(root: &Path, pins: &RoutingPins) {
    let original: Value = serde_json::from_slice(&fs::read(&pins.runtime_config).unwrap()).unwrap();
    let cases = [
        (
            "missing-bft-config",
            "complete onward network requires separately integrated ordinary runtime",
        ),
        (
            "wrong-format",
            "complete onward network requires separately integrated ordinary runtime",
        ),
        ("missing-format", "missing field `format`"),
        (
            "wrong-startup-head",
            "Rust BFT pinned startup Native head differs",
        ),
        (
            "unconfigured-local-key",
            "BFT validators differ from signed Native membership",
        ),
    ];
    for (name, expected) in cases {
        routing_budget(pins.deadline);
        let absent_transport = root.join(format!("refused-{name}-transport"));
        let absent_runtime = root.join(format!("refused-{name}-runtime"));
        let transport_path = root.join(format!("refused-{name}-mesh.json"));
        new_json(
            &transport_path,
            &json!({"format":MESH,"network":pins.currency,
            "state":absent_transport,"contacts":[]}),
        );
        let mut config = original.clone();
        config["state"] = json!(absent_runtime);
        match name {
            "wrong-format" => config["format"] = json!(bft_client::FORMAT),
            "missing-format" => {
                config.as_object_mut().unwrap().remove("format");
            }
            "wrong-startup-head" => config["startup_native_history_head"] = json!(Hash::ZERO),
            "unconfigured-local-key" => config["key"] = json!(public(90)),
            _ => (),
        }
        let config_path = root.join(format!("refused-{name}-bft.json"));
        new_json(&config_path, &config);
        let before_native = inventory(&root.join("routing-c"));
        let before_custody = custody(root);
        let runtime = (name != "missing-bft-config").then_some(config_path.as_path());
        let mut child = ServiceChild::spawn(
            pins,
            root,
            &format!("refused-{name}"),
            &root.join("routing-c"),
            &transport_path,
            "127.0.0.1:0",
            runtime,
        );
        let status = child.join(pins.deadline);
        assert!(
            !status.success(),
            "invalid Service preflight unexpectedly succeeded: {name}"
        );
        assert!(
            fs::read(&child.stdout).unwrap().is_empty(),
            "preflight released a Service startup response"
        );
        let error = fs::read_to_string(&child.stderr).unwrap();
        assert!(
            error.len() <= 64 * 1024 && error.contains(expected),
            "wrong preflight refusal: {name}: {error}"
        );
        assert!(!absent_transport.exists() && !absent_runtime.exists());
        assert_eq!(inventory(&root.join("routing-c")), before_native);
        assert_eq!(custody(root), before_custody);
        assert!(!root.join("routing-key-must-remain-absent.json").exists());
        eprintln!(
            "onward_service_routing_refusal={}",
            json!({"case":name,"error":error,
            "before_transport_or_caller_creation":true,"native_and_custody_unchanged":true})
        );
    }
}
fn cold_routing(root: &Path) {
    let pins: RoutingPins =
        serde_json::from_slice(&fs::read(root.join("routing-pins.json")).unwrap()).unwrap();
    routing_budget(pins.deadline);
    assert_eq!(sha(&fs::read(&pins.cli).unwrap()), pins.cli_sha256);
    let before = inventory(root);
    let b = Store::open_pinned_inspection(
        &root.join("intermediate"),
        &public(1),
        pins.currency,
        pins.b_head,
    )
    .unwrap();
    check_source(&b, &pins);
    drop(b);
    let c = Store::open_pinned_inspection(
        &root.join("routing-c"),
        &public(1),
        pins.currency,
        pins.c_head,
    )
    .unwrap();
    check_zero_credit(&c, &pins);
    caller_unchanged(root, &c, &pins);
    let runtime = TestRuntime::open(&pins.runtime_config, &c, &pins.transports[1]).unwrap();
    assert!(runtime.fixture_retained_ids().is_empty());
    drop(runtime);
    caller_unchanged(root, &c, &pins);
    drop(c);
    let b_transport = Node::open(&pins.transports[0]).unwrap();
    assert!(
        b_transport.observation()["retained_receipts"]
            .as_u64()
            .unwrap()
            >= 1
    );
    drop(b_transport);
    let c_transport = Node::open(&pins.transports[1]).unwrap();
    let received = c_transport.received_frames().unwrap();
    assert_eq!(received.len(), 1);
    let (frame, proof) = crate::contact::Frame::unpack_onward(&received[0].1).unwrap();
    assert_eq!(proof, pins.proof);
    assert_eq!(frame.source_chain_id, pins.proof.history.source);
    assert_eq!(frame.destination_chain_id, pins.proof.history.destination);
    assert_eq!(frame.export_id, pins.export);
    drop(c_transport);
    for i in 0..2 {
        assert_eq!(tls_identity(&pins.transports[i]).unwrap(), pins.tls[i]);
    }
    assert_eq!(
        inventory(root),
        before,
        "fresh-process complete cold checks changed retained bytes"
    );
    routing_budget(pins.deadline);
    // The child's stdout/stderr files remain unchanged throughout the inventory comparison above.
    eprintln!(
        "onward_service_routing_cold_result={}",
        json!({"root":root,"passed":true,"elapsed_seconds":now()-pins.started,
        "c_height":0,"pending_import":true,"credit":false,"original_caller_unchanged":true,"key_absent":true})
    );
}

#[test]
#[ignore = "fresh ordinary CLI pinned-TLS complete Onward proof custody; original 60 seconds including cold child"]
fn ordinary_onward_service_tls_retains_complete_proof_without_credit() {
    if let Some(root) = std::env::var_os(ROUTING_CHILD) {
        cold_routing(&PathBuf::from(root));
        return;
    }
    let started = now();
    let deadline = started + 60.0;
    let binary =
        PathBuf::from(std::env::var_os(CLI_ENV).expect("source-bound Service CLI required"));
    assert!(binary.is_absolute());
    let binary_sha =
        Hash::from_hex(&std::env::var(CLI_SHA_ENV).expect("source-bound CLI SHA256 required"))
            .unwrap();
    assert_eq!(sha(&fs::read(&binary).unwrap()), binary_sha);
    let (root, bootstrap, proof, a80, b4, export) = ancestors();
    routing_budget(deadline);
    routing_phase(started, "fresh-A80-B4-with-valid-B5-ready");
    let currency = bootstrap.currency.id().unwrap();
    let b = Store::open_inspection(&root.join("intermediate"), &public(1), currency).unwrap();
    let b_head = b.storage_head().unwrap();
    let b_ledger_root = b.chain.ledger.root().unwrap();
    drop(b);
    let c = Store::create(
        &root.join("routing-c"),
        bootstrap,
        proof.history.destination,
        &public(1),
        currency,
    )
    .unwrap();
    let c_initial_head = c.storage_head().unwrap();
    let c_ledger_root = c.chain.ledger.root().unwrap();
    let mut seeds = (2u8..6).collect::<Vec<_>>();
    seeds.sort_by_key(|seed| public(*seed));
    let mut ids = Vec::new();
    for i in 0..4 {
        let identity = initialize(
            &root.join(format!("routing-c-transport-{i}")),
            &currency.to_hex(),
            &proof.history.destination.to_hex(),
            "public-no-value-onward-service-routing",
        )
        .unwrap();
        ids.push(identity["node_id"].as_str().unwrap().to_owned());
    }
    let b_identity = initialize(
        &root.join("routing-b-transport"),
        &currency.to_hex(),
        &proof.history.source.to_hex(),
        "public-no-value-onward-service-source",
    )
    .unwrap();
    let b_id = b_identity["node_id"].as_str().unwrap().to_owned();
    let mut transports = vec![
        json!({"format":MESH,"network":currency,"state":root.join("routing-b-transport"),"contacts":[]}),
        json!({"format":MESH,"network":currency,"state":root.join("routing-c-transport-0"),"contacts":[]}),
    ];
    let tls = transports
        .iter()
        .map(|config| tls_identity(config).unwrap())
        .collect::<Vec<_>>();
    // Reserve distinct loopback endpoints during setup; release immediately before launch.
    // A bind race is a real refusal, never retried on a replacement endpoint.
    let sockets = [
        TcpListener::bind("127.0.0.1:0").unwrap(),
        TcpListener::bind("127.0.0.1:0").unwrap(),
    ];
    let addresses = sockets
        .iter()
        .map(|s| s.local_addr().unwrap())
        .collect::<Vec<_>>();
    transports[0]["contacts"] = json!([{"peer":ids[0],"host":"127.0.0.1","port":addresses[1].port(),"tls_cert_sha256":tls[1]["fingerprint"]}]);
    transports[1]["contacts"] = json!([{"peer":b_id,"host":"127.0.0.1","port":addresses[0].port(),"tls_cert_sha256":tls[0]["fingerprint"]}]);
    for (i, transport) in transports.iter().enumerate() {
        new_json(&root.join(format!("routing-transport-{i}.json")), transport);
        drop(Node::open(transport).unwrap()); // Commit configured advertisements before inventory pins.
    }
    let agent = Agent::create(&root.join("routing-signer"), &c, public(seeds[0])).unwrap();
    let caller = bft_client::State {
        format: bft_client::ONWARD_FORMAT.into(),
        binding: agent.journal.binding.clone(),
        head: agent.head().unwrap(),
        pending: None,
        outbox: None,
    };
    let signer_records = agent.record_count();
    drop(agent);
    new_json(
        &dir(&root.join("routing-caller")).join("head.json"),
        &caller,
    );
    let caller_lock = bft_client::Client::lock(
        &root.join("routing-caller/head.json"),
        &root.join("routing-signer"),
        public(seeds[0]),
        bft_client::ONWARD_FORMAT.into(),
        &c,
    )
    .unwrap();
    assert_eq!(caller_lock.read().unwrap(), caller);
    drop(caller_lock);
    dir(&root.join("routing-runtime"));
    let runtime_config = root.join("routing-runtime.json");
    new_json(
        &runtime_config,
        &json!({"format":bft_client::ONWARD_FORMAT,"state":root.join("routing-runtime"),
        "signer_dir":root.join("routing-signer"),"head_file":root.join("routing-caller/head.json"),
        "key_file":root.join("routing-key-must-remain-absent.json"),"key":public(seeds[0]),"miner":public(12),
        "validators":seeds.iter().enumerate().map(|(i,seed)|json!({"key":public(*seed),"node_id":ids[i]})).collect::<Vec<_>>(),
        "block_interval":0.5,"round_timeout":5.0,"stop_height":0,"startup_native_history_head":c_initial_head}),
    );
    let mut pins = RoutingPins {
        started,
        deadline,
        currency,
        proof,
        a80,
        b4,
        export,
        b_head,
        b_ledger_root,
        c_head: c_initial_head,
        c_ledger_root,
        caller,
        seed: seeds[0],
        signer_records,
        transports,
        tls,
        runtime_config: runtime_config.clone(),
        cli: binary.clone(),
        cli_sha256: binary_sha,
    };
    let original_custody = custody(&root);
    drop(c);
    preflight_refusals(&root, &pins);
    routing_budget(deadline);
    drop(sockets);
    let mut receiver = ServiceChild::spawn(
        &pins,
        &root,
        "routing-c-service",
        &root.join("routing-c"),
        &root.join("routing-transport-1.json"),
        &addresses[1].to_string(),
        Some(&runtime_config),
    );
    receiver.ready(
        deadline,
        &addresses[1].to_string(),
        &pins.tls[1]["fingerprint"],
    );
    let mut source = ServiceChild::spawn(
        &pins,
        &root,
        "routing-b-service",
        &root.join("intermediate"),
        &root.join("routing-transport-0.json"),
        &addresses[0].to_string(),
        None,
    );
    source.ready(
        deadline,
        &addresses[0].to_string(),
        &pins.tls[0]["fingerprint"],
    );
    routing_phase(started, "both-ordinary-cli-services-ready");
    // Declared after both children: an unwinding wait records its last actual
    // operation before either ServiceChild starts cleanup. No original clock resets.
    let mut trace = WaitTrace::new(
        &root,
        started,
        deadline,
        &b_id,
        pins.currency,
        pins.proof.history.source,
    );
    let mut accepted_at = None;
    loop {
        routing_budget(deadline);
        source.running();
        receiver.running();
        trace.event("native-open-started", json!({})).unwrap();
        let mut acquired = false;
        let candidate = match Store::open_inspection(&root.join("routing-c"), &public(1), currency)
        {
            Ok(node) => {
                acquired = true;
                trace
                    .event("native-open-completed", json!({"result":"ok"}))
                    .unwrap();
                trace.event("pending-query-started", json!({})).unwrap();
                let pending = node.complete_onward_network_pending_imports().unwrap();
                trace
                    .event("pending-query-completed", json!({"count":pending.len()}))
                    .unwrap();
                let mut candidate = None;
                if !pending.is_empty() {
                    trace.event("zero-credit-check-started", json!({})).unwrap();
                    check_zero_credit(&node, &pins);
                    trace
                        .event("zero-credit-check-completed", json!({}))
                        .unwrap();
                    trace.event("native-head-check-started", json!({})).unwrap();
                    let first_at = accepted_at.is_none().then(now);
                    let observed_head = node.storage_head().unwrap();
                    trace
                        .event("native-head-check-completed", json!({"head":observed_head}))
                        .unwrap();
                    if let Some((first_at, head)) = accepted_at {
                        assert_eq!(observed_head, head);
                        candidate = Some((first_at, head));
                        trace
                            .event(
                                "native-candidate",
                                json!({"first_pending_at":first_at,"head":head}),
                            )
                            .unwrap();
                    } else {
                        let first_at = first_at.expect("first pending observation clock");
                        accepted_at = Some((first_at, observed_head));
                        trace
                            .event(
                                "first-pending-observed",
                                json!({"at":first_at,"head":observed_head}),
                            )
                            .unwrap();
                    }
                }
                candidate
            }
            Err(error) if error == std::fs::TryLockError::WouldBlock.to_string() => {
                trace
                    .event("native-open-completed", json!({"result":"busy"}))
                    .unwrap();
                None
            }
            Err(error) => {
                trace
                    .event(
                        "native-open-completed",
                        json!({"result":"error","error":error}),
                    )
                    .unwrap();
                panic!("actual Service custody observation refused: {error}")
            }
        };
        // The successful Store has left its original match scope before this observation.
        trace
            .event(
                "inspection-ended",
                json!({"native_acquired":acquired,"native_candidate":candidate.is_some()}),
            )
            .unwrap();
        if let Some((first_at, head)) = candidate {
            // Optional status is diagnostic only. Unknown never supplies receipt custody.
            trace
                .event("receipt-status-read-started", json!({}))
                .unwrap();
            let detail = match fs::read(
                root.join("routing-b-transport/regional-contact-status.json"),
            ) {
                Err(error) => {
                    json!({"result":"read-error","kind":format!("{:?}",error.kind()),"error":error.to_string()})
                }
                Ok(raw) => match serde_json::from_slice::<Value>(&raw) {
                    Err(error) => json!({"result":"parse-error","error":error.to_string()}),
                    Ok(status) => json!({"result":"parsed",
                        "retained_receipts":status["mesh"]["retained_receipts"].as_u64(),
                        "progress_observation_available":status["progress_observation_available"],
                        "service_turn":status["service_turn"]}),
                },
            };
            trace
                .event("receipt-status-read-completed", detail)
                .unwrap();
            // Configured advertisements were established before launch. Full Node open
            // authenticates actual custody; it is not a general read-only inspection API.
            // The C Native lease is already released, and this Mesh lease ends below.
            trace
                .event("source-custody-open-started", json!({}))
                .unwrap();
            let (receipt_seen, detail, refusal) = match Node::open(&pins.transports[0]) {
                Ok(node) => {
                    let observation = node.observation();
                    assert_eq!(observation["network"], json!(pins.currency));
                    assert_eq!(observation["region"], json!(pins.proof.history.source));
                    assert_eq!(observation["node_id"], b_id);
                    assert_eq!(observation["ledger_authority"], false);
                    let count = observation["retained_receipts"]
                        .as_u64()
                        .expect("authenticated retained receipt count");
                    (
                        count >= 1,
                        json!({"result":"ok","retained_receipts":count,"observation":observation}),
                        None,
                    )
                }
                Err(error)
                    if [libc::EWOULDBLOCK, libc::EAGAIN]
                        .iter()
                        .any(|code| error.starts_with(&format!("CONTACT_STORAGE_IO:{code}:"))) =>
                {
                    (false, json!({"result":"busy","error":error}), None)
                }
                Err(error) => (false, json!({"result":"error","error":error}), Some(error)),
            };
            trace
                .event("source-custody-open-completed", detail)
                .unwrap();
            if let Some(error) = refusal {
                panic!("authenticated source custody observation refused: {error}");
            }
            let age = now() - first_at;
            let ready = age >= 0.5 && receipt_seen;
            trace
                .event(
                    "wait-condition",
                    json!({"first_pending_at":first_at,
                    "age_seconds":age,"receipt_seen":receipt_seen,"ready":ready}),
                )
                .unwrap();
            if ready {
                pins.c_head = head;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    trace.finish(true).unwrap();
    drop(trace);
    assert_ne!(pins.c_head, c_initial_head);
    routing_phase(started, "native-pending-without-credit-observed");
    // Request both stops first; join under the original acceptance deadline.
    source.request_stop();
    receiver.request_stop();
    assert!(
        source.join(deadline).success(),
        "source Service normal shutdown failed"
    );
    assert!(
        receiver.join(deadline).success(),
        "receiver Service normal shutdown failed"
    );
    assert_eq!(custody(&root), original_custody);
    routing_phase(started, "both-services-normal-stop");
    // The original startup pin is retained unchanged. Cold auth uses an explicitly new
    // read-only configuration pin for the actual post-receipt Native head, never a sign.
    let mut cold_config: Value =
        serde_json::from_slice(&fs::read(&runtime_config).unwrap()).unwrap();
    cold_config["startup_native_history_head"] = json!(pins.c_head);
    pins.runtime_config = root.join("routing-cold-runtime.json");
    new_json(&pins.runtime_config, &cold_config);
    new_json(&root.join("routing-pins.json"), &pins);
    let child_out = root.join("routing-cold.stdout");
    let child_err = root.join("routing-cold.stderr");
    let mut child = Process::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            ROUTING_TEST,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ROUTING_CHILD, &root)
        .stdout(Stdio::from(output_file(&child_out)))
        .stderr(Stdio::from(output_file(&child_err)))
        .spawn()
        .unwrap();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!(
                "original 60-second scope exhausted during fresh child cold replay; retained {}",
                root.display()
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(
        status.success(),
        "fresh child cold refusal; retained {} and {}",
        child_out.display(),
        child_err.display()
    );
    routing_budget(deadline);
    assert_eq!(sha(&fs::read(&binary).unwrap()), binary_sha);
    eprintln!(
        "onward_service_routing_result={}",
        json!({"root":root,"passed":true,"component_seconds":now()-started,
        "cli_sha256":binary_sha,"ordinary_cli_startup":true,"pinned_tls":true,"automatic_export_scan":true,
        "complete_A80_B4":true,"later_B5_preserved":true,"c_height":0,"pending_import":true,"credit":false,
        "source_debit_retained":true,"permanent_origin_import":true,"original_caller_unchanged":true,"key_absent":true,
        "normal_join":true,"fresh_process_cold":true,"cold_inventory_unchanged":true,"preflight_refusals":5,
        "source_receipt_authenticated":true,"optional_status_not_receipt_authority":true,
        "two_payments_verified":false,"ordinary_consensus_qualified":false,"independent_custody":false,"mainnet":false})
    );
}
