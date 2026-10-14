//! One real Service process, one authenticated peer, no payment qualification.
//! Included directly below contact_runtime::service so original private TLS helpers are shared.
use super::*;
use crate::tests::public;
use crate::{Amount, Bootstrap};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread::JoinHandle;

const TEST: &str = "contact_runtime::service::independent_transport_tests::ordinary_native_tick_completes_during_authenticated_peer_reply_wait";
const CHILD: &str = "RLD_SERVICE_INDEPENDENT_TRANSPORT_COLD_CHILD";
const CLI: &str = "RLD_ONWARD_SERVICE_CLI";
const CLI_SHA: &str = "RLD_ONWARD_SERVICE_CLI_SHA256";
const FORMAT: &str = "RLD-SERVICE-INDEPENDENT-TRANSPORT-TEST-V1";

fn io<T>(result: std::io::Result<T>) -> Result<T> {
    result.map_err(|error| error.to_string())
}
fn hash(raw: &[u8]) -> Hash {
    Hash(Sha256::digest(raw).into())
}
fn budget(deadline: f64) -> Result<()> {
    require(
        monotonic()? < deadline,
        "original 30-second transport independence scope exhausted",
    )
}
fn write_new(path: &Path, value: &impl Serialize) -> Result<()> {
    crate::keystore::private_create(path, &crate::wallet_client::canonical(value)?)
}
fn output(path: &Path) -> Result<fs::File> {
    crate::keystore::private_create(path, b"")?;
    io(fs::OpenOptions::new().write(true).open(path))
}
fn inventory(root: &Path) -> Result<BTreeMap<PathBuf, (Hash, u64, i64, i64)>> {
    fn visit(
        path: &Path,
        base: &Path,
        out: &mut BTreeMap<PathBuf, (Hash, u64, i64, i64)>,
    ) -> Result<()> {
        for entry in io(fs::read_dir(path))? {
            let path = io(entry)?.path();
            let meta = io(fs::symlink_metadata(&path))?;
            require(!meta.file_type().is_symlink(), "fixture inventory symlink")?;
            if meta.is_dir() {
                visit(&path, base, out)?;
            } else {
                require(
                    meta.is_file() && meta.len() <= 8 * 1024 * 1024,
                    "fixture inventory file bound",
                )?;
                let relative = path
                    .strip_prefix(base)
                    .map_err(|e| e.to_string())?
                    .to_owned();
                out.insert(
                    relative,
                    (
                        hash(&io(fs::read(path))?),
                        meta.len(),
                        meta.mtime(),
                        meta.mtime_nsec(),
                    ),
                );
                require(out.len() <= 256, "fixture inventory count bound")?;
            }
        }
        Ok(())
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result)?;
    Ok(result)
}
fn clean_child_environment(command: &mut Command) {
    for (key, _) in std::env::vars_os() {
        if key
            .to_str()
            .is_some_and(|key| key.starts_with("RLD_") && key.contains("CHILD"))
        {
            command.env_remove(key);
        }
    }
}

// Keep the held-entry inode open: an unlinked inode cannot be recycled while we compare it.
struct StatusFile {
    _file: fs::File,
    identity: Value,
    value: Value,
}
fn status(path: &Path) -> Result<Option<StatusFile>> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let meta = io(file.metadata())?;
    require(
        meta.is_file() && meta.len() <= 64 * 1024,
        "status file bound",
    )?;
    let mut raw = Vec::new();
    io((&file).take(64 * 1024 + 1).read_to_end(&mut raw))?;
    require(raw.len() <= 64 * 1024, "status read bound")?;
    let value = crate::wallet_http::decode_unique_with_limit(&raw, 64 * 1024)?;
    Ok(Some(StatusFile {
        _file: file,
        identity: json!({"dev":meta.dev(),"ino":meta.ino(),
        "mtime":meta.mtime(),"mtime_nsec":meta.mtime_nsec(),"sha256":hash(&raw)}),
        value,
    }))
}
fn successful(value: &Value, pins: &Pins) -> bool {
    value["format"] == super::FORMAT
        && value["currency"] == json!(pins.currency)
        && value["region"] == json!(pins.region)
        && value["local_height"] == 0
        && value["progress_observation_available"] == true
        && value["ledger_changed_by_native_verification_only"] == true
        && value["fixture_only"] == true
}
fn distinct(a: &StatusFile, b: &StatusFile) -> bool {
    (a.identity["dev"] != b.identity["dev"] || a.identity["ino"] != b.identity["ino"])
        && (a.identity["mtime"] != b.identity["mtime"]
            || a.identity["mtime_nsec"] != b.identity["mtime_nsec"])
}

fn completed_turn_during_hold(status: &Value, held: f64, observed: f64) -> bool {
    let turn = &status["service_turn"];
    let Some(started) = turn["started_at"].as_f64() else {
        return false;
    };
    let Some(completed) = turn["completed_at"].as_f64() else {
        return false;
    };
    turn["diagnostic_only"] == true
        && turn["clock"] == "local-monotonic-seconds"
        && turn["pid"].as_u64().is_some_and(|pid| pid > 1)
        && turn["sequence"]
            .as_u64()
            .is_some_and(|sequence| sequence > 0)
        && turn["instance"]
            .as_str()
            .is_some_and(|instance| Hash::from_hex(instance).is_ok())
        && started.is_finite()
        && completed.is_finite()
        && held <= started
        && started <= completed
        && completed <= observed
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pins {
    format: String,
    root: PathBuf,
    parent: u32,
    started: f64,
    deadline: f64,
    currency: Hash,
    region: Hash,
    head: Hash,
    ledger_root: Hash,
    configs: Vec<Value>,
    materials: Vec<Value>,
    cli: PathBuf,
    cli_sha256: Hash,
    test: PathBuf,
    test_sha256: Hash,
}
fn check_genesis(node: &Store, pins: &Pins) -> Result<()> {
    require(
        node.chain.region == pins.region
            && node.chain.height() == 0
            && node.chain.finalized.is_none()
            && node.storage_head()? == pins.head
            && node.chain.ledger.root()? == pins.ledger_root
            && node.chain.ledger.minted == Amount::ZERO
            && node.chain.ledger.coins.is_empty()
            && node.chain.ledger.imports.is_empty()
            && node.chain.ledger.exports.is_empty(),
        "ordinary Service changed genesis value or head",
    )
}
fn cold(root: &Path) -> Result<()> {
    let pins: Pins = serde_json::from_slice(&io(fs::read(root.join("pins.json")))?)
        .map_err(|e| e.to_string())?;
    require(
        pins.format == FORMAT
            && pins.root == root
            && pins.parent == unsafe { libc::getppid() } as u32,
        "cold child scope/parent binding",
    )?;
    budget(pins.deadline)?;
    let executable = io(std::env::current_exe())?;
    require(
        executable == pins.test
            && hash(&io(fs::read(&executable))?) == pins.test_sha256
            && hash(&io(fs::read(&pins.cli))?) == pins.cli_sha256,
        "cold child artifact binding",
    )?;
    let before = inventory(root)?;
    let node =
        Store::open_pinned_inspection(&root.join("ledger"), &public(1), pins.currency, pins.head)?;
    check_genesis(&node, &pins)?;
    drop(node);
    for (config, material) in pins.configs.iter().zip(&pins.materials) {
        drop(Node::open(config)?);
        require(
            crate::contact_runtime::tls_identity(config)? == *material,
            "cold TLS identity changed",
        )?;
    }
    require(
        inventory(root)? == before,
        "fresh cold authentication mutated retained inventory",
    )?;
    budget(pins.deadline)?;
    eprintln!(
        "service_independent_transport_cold_result={}",
        json!({"root":root,"passed":true,
        "elapsed_seconds":monotonic()?-pins.started,"height":0,"head":pins.head,
        "mode":"fresh-process-cold","pid":std::process::id(),"parent_pid":pins.parent,
        "started":pins.started,"deadline":pins.deadline,"cli_sha256":pins.cli_sha256,
        "native_and_mesh_cold":true,"inventory_unchanged":true,"test_sha256":pins.test_sha256})
    );
    Ok(())
}

struct ChildGuard {
    process: Child,
    joined: bool,
}
impl ChildGuard {
    fn live(&mut self) -> Result<()> {
        if let Some(status) = io(self.process.try_wait())? {
            self.joined = true;
            return Err(format!("Service exited before observation: {status}"));
        }
        Ok(())
    }
    fn join(&mut self, deadline: f64) -> Result<()> {
        loop {
            budget(deadline)?;
            if let Some(status) = io(self.process.try_wait())? {
                self.joined = true;
                return require(
                    status.success(),
                    &format!("owned process exited unsuccessfully: {status}"),
                );
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
    fn stop(&mut self, deadline: f64) -> Result<()> {
        self.live()?;
        require(
            unsafe { libc::kill(self.process.id() as i32, libc::SIGTERM) } == 0,
            "Service SIGTERM failed",
        )?;
        self.join(deadline)
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.joined {
            let _ = self.process.kill();
            let _ = self.process.wait();
        }
    }
}
struct PeerGuard {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<Value>>>,
}
impl PeerGuard {
    fn finished(&self) -> bool {
        self.thread
            .as_ref()
            .is_some_and(|thread| thread.is_finished())
    }
    fn join(&mut self) -> Result<Value> {
        self.thread
            .take()
            .ok_or("peer already joined")?
            .join()
            .map_err(|_| "owned TLS peer panicked")?
    }
}
impl Drop for PeerGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
fn accept_owned(listener: &TcpListener, stop: &AtomicBool, deadline: f64) -> Result<TcpStream> {
    loop {
        budget(deadline)?;
        require(!stop.load(Ordering::Acquire), "owned peer stopped")?;
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5))
            }
            Err(error) => return Err(error.to_string()),
        }
    }
}
fn peer(listener: TcpListener, stop: Arc<AtomicBool>, pins: Arc<Pins>) -> Result<Value> {
    let config = &pins.configs[1];
    let peer_id = Node::open(config)?.id.clone();
    let context = tls(
        json!({"Context":{"root":config["state"],"network":pins.currency,
        "peer":peer_id}}),
    )?;
    let context = Context(context["handle"].as_u64().ok_or("peer TLS context")?);
    let mut completed = Vec::new();
    let status_path = pins.root.join("service-mesh/regional-contact-status.json");
    let mut hold_report = None;
    let mut first_reply_started = None;
    for attempt in 0..2 {
        let stream = accept_owned(&listener, &stop, pins.deadline)?;
        let socket_started = monotonic()?;
        let deadline = (socket_started + 3.0).min(pins.deadline);
        let handle = tls(
            json!({"Accept":{"context":context.0,"fd":stream.as_raw_fd(),"deadline":deadline}}),
        )?
        .as_u64()
        .ok_or("peer accepted TLS handle")?;
        let connection = Connection(handle);
        drop(stream);
        let (challenge, id, network, peers) = {
            let node = Node::open(config)?;
            let challenge=node.sign("tcp-challenge",json!({"format":MESH,"adapter":"RLD-CONTACT-TCP-V4",
                "network":node.network,"node_id":node.id,"nonce":random()?,"tls_cert_sha256":pins.materials[1]["fingerprint"]}))?;
            (
                challenge,
                node.id.clone(),
                node.network.clone(),
                node.contacts.keys().cloned().collect::<Vec<_>>(),
            )
        };
        send(handle, deadline, challenge.clone())?;
        let request = recv(handle, deadline)?;
        let checked = crypto(
            json!({"Exchange":{"TcpRequest":{"network":network,"signed":request,
            "recipient":id,"peers":peers,"nonce":challenge["body"]["nonce"],"limits":limits()}}}),
        )?;
        let sender = checked["body"]["node_id"]
            .as_str()
            .ok_or("peer request sender")?;
        let (response, exchange) = {
            let mut node = Node::open(config)?;
            require(
                node.contacts.contains_key(sender),
                "unexpected request sender",
            )?;
            node.receive(&checked["body"]["bundle"], sender)?;
            let bundle = node.prepare(sender)?;
            let exchange = digest(&checked["body"]["bundle"])?;
            let response = node.sign(
                "tcp-response",
                json!({"format":MESH,"adapter":"RLD-CONTACT-TCP-V4",
                "network":network,"node_id":id,"to":sender,"nonce":checked["body"]["nonce"],
                "challenge":checked["body"]["challenge"],"exchange_id":exchange,
                "accepted":true,"bundle":bundle,"error":null}),
            )?;
            (response, exchange)
        }; // No mesh or Native lock crosses the hold or socket send.
        let custody_complete = monotonic()?;
        if attempt == 1 {
            let held = monotonic()?;
            let before = status(&status_path)?.ok_or("hold-entry status absent")?;
            let until = (held + 0.9).min(deadline - 0.1);
            require(
                until > held,
                "insufficient original socket deadline for held reply",
            )?;
            let mut first: Option<(StatusFile, f64)> = None;
            let mut observations = Vec::new();
            while monotonic()? < until && !stop.load(Ordering::Acquire) {
                if let Some(next) = status(&status_path)? {
                    let at = monotonic()?;
                    if at < until
                        && distinct(&before, &next)
                        && successful(&next.value, &pins)
                        && completed_turn_during_hold(&next.value, held, at)
                    {
                        if let Some((previous, previous_at)) = &first {
                            let previous_turn = &previous.value["service_turn"];
                            let next_turn = &next.value["service_turn"];
                            if at > *previous_at
                                && distinct(previous, &next)
                                && previous_turn["instance"] == next_turn["instance"]
                                && previous_turn["pid"] == next_turn["pid"]
                                && previous_turn["sequence"].as_u64()
                                    < next_turn["sequence"].as_u64()
                                && previous_turn["completed_at"].as_f64()
                                    <= next_turn["started_at"].as_f64()
                            {
                                observations.push(json!({"at":previous_at,"identity":previous.identity,"status":previous.value}));
                                observations.push(
                                    json!({"at":at,"identity":next.identity,"status":next.value}),
                                );
                                break;
                            }
                        } else {
                            first = Some((next, at));
                        }
                    }
                }
                thread::sleep(Duration::from_millis(5));
            }
            let released = monotonic()?;
            // Send the original authenticated positive reply even when the counter failed.
            send(connection.0, deadline, response)?;
            let sent = monotonic()?;
            let previous_reply = first_reply_started.ok_or("first exchange reply clock missing")?;
            let report = json!({"socket_started":socket_started,"socket_deadline":deadline,
                "first_reply_started":previous_reply,"second_reply_before_client_deadline_lower_bound":sent-previous_reply<3.0,
                "custody_complete":custody_complete,"held_at":held,"released_at":released,"reply_sent_at":sent,
                "hold_seconds":released-held,"before_identity":before.identity,
                "observation_deadline":until,"hold_deadline":held+1.0,
                "new_successful_native_statuses":observations,"exchange_sha256":exchange});
            write_new(&pins.root.join("held-peer-observation.json"), &report)?;
            require(
                observations.len() == 2,
                "two distinct successful Native statuses were not observed during the held reply",
            )?;
            require(
                released - held <= 1.0 && sent < deadline && sent - previous_reply < 3.0,
                "held reply exceeded original socket bound",
            )?;
            hold_report = Some(report);
        } else {
            first_reply_started = Some(monotonic()?);
            send(connection.0, deadline, response)?;
        }
        completed.push(exchange);
        drop(connection);
        if attempt == 0 {
            let until = (monotonic()? + 2.0).min(pins.deadline);
            loop {
                require(
                    !stop.load(Ordering::Acquire),
                    "owned peer stopped before control status",
                )?;
                if status(&status_path)?.is_some_and(|status| successful(&status.value, &pins)) {
                    break;
                }
                require(
                    monotonic()? < until,
                    "first ordinary exchange produced no successful Native status",
                )?;
                thread::sleep(Duration::from_millis(5));
            }
        }
    }
    Ok(json!({"authenticated_exchanges":completed,"held":hold_report,"peer_joined":true}))
}

fn run(root: &Path, started: f64, deadline: f64) -> Result<Value> {
    let binary = PathBuf::from(std::env::var_os(CLI).ok_or("bound actual Service CLI required")?);
    let binary_sha = Hash::from_hex(&std::env::var(CLI_SHA).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    require(
        binary.is_absolute() && hash(&io(fs::read(&binary))?) == binary_sha,
        "Service CLI artifact binding",
    )?;
    let executable = io(std::env::current_exe())?;
    let test_sha = hash(&io(fs::read(&executable))?);
    let bootstrap: Bootstrap = crate::tests::bootstrap();
    let currency = bootstrap.currency.id()?;
    let region = bootstrap.admissions[0].id()?;
    let node = Store::create(
        &root.join("ledger"),
        bootstrap,
        region,
        &public(1),
        currency,
    )?;
    let head = node.storage_head()?;
    let ledger_root = node.chain.ledger.root()?;
    drop(node);
    let native_before = inventory(&root.join("ledger"))?;
    let mut configs = Vec::new();
    let mut ids = Vec::new();
    let mut materials = Vec::new();
    for label in ["service-mesh", "peer-mesh"] {
        let identity = crate::contact_runtime::initialize(
            &root.join(label),
            &currency.to_hex(),
            &region.to_hex(),
            "public-no-value-service-independence",
        )?;
        ids.push(
            identity["node_id"]
                .as_str()
                .ok_or("mesh identity")?
                .to_owned(),
        );
        let config =
            json!({"format":MESH,"network":currency,"state":root.join(label),"contacts":[]});
        materials.push(crate::contact_runtime::tls_identity(&config)?);
        configs.push(config);
    }
    let peer_listener = io(TcpListener::bind("127.0.0.1:0"))?;
    io(peer_listener.set_nonblocking(true))?;
    let peer_address = io(peer_listener.local_addr())?;
    let service_reserved = io(TcpListener::bind("127.0.0.1:0"))?;
    let service_address = io(service_reserved.local_addr())?;
    configs[0]["contacts"] = json!([{"peer":ids[1],"host":"127.0.0.1","port":peer_address.port(),"tls_cert_sha256":materials[1]["fingerprint"]}]);
    configs[1]["contacts"] = json!([{"peer":ids[0],"host":"127.0.0.1","port":service_address.port(),"tls_cert_sha256":materials[0]["fingerprint"]}]);
    for (i, config) in configs.iter().enumerate() {
        write_new(&root.join(format!("transport-{i}.json")), config)?;
        drop(Node::open(config)?);
    }
    let pins = Arc::new(Pins {
        format: FORMAT.into(),
        root: root.to_owned(),
        parent: std::process::id(),
        started,
        deadline,
        currency,
        region,
        head,
        ledger_root,
        configs,
        materials,
        cli: binary.clone(),
        cli_sha256: binary_sha,
        test: executable.clone(),
        test_sha256: test_sha,
    });
    write_new(&root.join("pins.json"), pins.as_ref())?;
    budget(deadline)?;
    let stop = Arc::new(AtomicBool::new(false));
    let owned_stop = stop.clone();
    let peer_pins = pins.clone();
    let worker = thread::spawn(move || peer(peer_listener, owned_stop, peer_pins));
    let mut peer = PeerGuard {
        stop,
        thread: Some(worker),
    };
    let mut command = Command::new(&binary);
    clean_child_environment(&mut command);
    command.args([
        "--dir",
        root.join("ledger").to_str().ok_or("ledger path")?,
        "--authority",
        &public(1),
        "--currency",
        &currency.to_hex(),
        "--mesh-config",
        root.join("transport-0.json")
            .to_str()
            .ok_or("transport path")?,
        "--mesh-listen",
        &service_address.to_string(),
        "--interval",
        "0.1",
    ]);
    command
        .stdout(Stdio::from(output(&root.join("service.stdout"))?))
        .stderr(Stdio::from(output(&root.join("service.stderr"))?));
    drop(service_reserved); // No replacement endpoint or retry if the real bind fails.
    let mut service = ChildGuard {
        process: io(command.spawn())?,
        joined: false,
    };
    let result = (|| {
        write_new(
            &root.join("service-launch.json"),
            &json!({"pid":service.process.id(),"cli":binary,"cli_sha256":binary_sha,"started":started,"deadline":deadline}),
        )?;
        while !peer.finished() {
            budget(deadline)?;
            service.live()?;
            thread::sleep(Duration::from_millis(10));
        }
        peer.join()
    })();
    // Preserve the first observation error; later stop errors cannot replace it.
    let stopped = service.stop(deadline);
    peer.stop.store(true, Ordering::Release);
    let peer_cleanup = if peer.thread.is_some() {
        peer.join().map(|_| ())
    } else {
        Ok(())
    };
    let cleanup = json!({"root":root,"primary_error":result.as_ref().err(),
        "service_stop_error":stopped.as_ref().err(),"peer_join_error":peer_cleanup.as_ref().err()});
    let first_error = result
        .as_ref()
        .err()
        .or(stopped.as_ref().err())
        .or(peer_cleanup.as_ref().err())
        .cloned();
    let cleanup_saved = write_new(&root.join("cleanup-outcome.json"), &cleanup);
    if let Some(error) = first_error {
        eprintln!("service_independent_transport_cleanup={cleanup}");
        if let Err(save_error) = cleanup_saved {
            eprintln!("cleanup evidence write failed: {save_error}");
        }
        return Err(error);
    }
    cleanup_saved?;
    let observed = result?;
    for row in observed["held"]["new_successful_native_statuses"]
        .as_array()
        .ok_or("held Service turn observations absent")?
    {
        require(
            row["status"]["service_turn"]["pid"] == service.process.id(),
            "held Service turn belongs to another process",
        )?;
    }
    budget(deadline)?;
    require(
        inventory(&root.join("ledger"))? == native_before,
        "ordinary Service changed Native files",
    )?;
    require(
        hash(&io(fs::read(&binary))?) == binary_sha,
        "Service CLI changed",
    )?;
    let child_stdout = root.join("cold.stdout");
    let child_stderr = root.join("cold.stderr");
    let mut command = Command::new(&executable);
    clean_child_environment(&mut command);
    command
        .args([
            "--exact",
            TEST,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, root)
        .stdout(Stdio::from(output(&child_stdout)?))
        .stderr(Stdio::from(output(&child_stderr)?));
    let mut before = inventory(root)?;
    before.remove(Path::new("cold.stdout"));
    before.remove(Path::new("cold.stderr"));
    let mut child = ChildGuard {
        process: io(command.spawn())?,
        joined: false,
    };
    child.join(deadline)?;
    let raw = io(fs::read(&child_stderr))?;
    require(raw.len() <= 64 * 1024, "cold output bound")?;
    let reports = raw
        .split(|b| *b == b'\n')
        .filter_map(|line| line.strip_prefix(b"service_independent_transport_cold_result="))
        .collect::<Vec<_>>();
    require(reports.len() == 1, "cold child exact result count")?;
    let report: Value = serde_json::from_slice(reports[0]).map_err(|e| e.to_string())?;
    require(
        report["root"] == json!(root)
            && report["passed"] == true
            && report["head"] == json!(head)
            && report["test_sha256"] == json!(test_sha)
            && report["native_and_mesh_cold"] == true
            && report["inventory_unchanged"] == true
            && report["pid"] == child.process.id()
            && report["parent_pid"] == std::process::id()
            && report["mode"] == "fresh-process-cold"
            && report["started"] == json!(started)
            && report["deadline"] == json!(deadline)
            && report["cli_sha256"] == json!(binary_sha),
        "cold result binding",
    )?;
    let mut after = inventory(root)?;
    after.remove(Path::new("cold.stdout"));
    after.remove(Path::new("cold.stderr"));
    require(before == after, "cold child changed parent inventory")?;
    budget(deadline)?;
    Ok(
        json!({"root":root,"passed":true,"elapsed_seconds":monotonic()?-started,
        "started":started,"deadline":deadline,"pid":std::process::id(),"cold_pid":child.process.id(),
        "cold_stdout":child_stdout,"cold_stderr":child_stderr,
        "actual_cli":binary,"cli_sha256":binary_sha,"test_sha256":test_sha,
        "actual_pinned_tls":true,"full_request_authenticated":true,"durable_peer_custody":true,
        "new_native_tick_during_reply_hold":true,"two_successful_status_publications":true,
        "complete_native_turn_during_reply_hold":true,"native_head_unchanged":true,"native_height":0,
        "normal_service_stop":true,"peer_joined":true,"fresh_process_cold":true,
        "no_miner":true,"payment_qualified":false,"bft_liveness_qualified":false,
        "observation":observed,"cold":report}),
    )
}

#[test]
#[ignore = "fresh real CLI/TLS independent Native tick; original 30 seconds including stop and cold child"]
fn ordinary_native_tick_completes_during_authenticated_peer_reply_wait() {
    if let Some(root) = std::env::var_os(CHILD) {
        cold(&PathBuf::from(root)).unwrap();
        return;
    }
    let started = monotonic().unwrap();
    let deadline = started + 30.0;
    let root = directory(
        &io(fs::canonicalize(std::env::temp_dir()))
            .unwrap()
            .join(format!(
                "rld-service-independent-transport-{}",
                random().unwrap()
            )),
    )
    .unwrap();
    eprintln!(
        "\nservice_independent_transport_scope={}",
        json!({"root":root,"started":started,"deadline":deadline,"pid":std::process::id(),"fixture_only":true})
    );
    match run(&root, started, deadline) {
        Ok(report) => eprintln!("service_independent_transport_result={report}"),
        Err(error) => {
            eprintln!(
                "service_independent_transport_result={}",
                json!({"root":root,"passed":false,
                "elapsed_seconds":monotonic().ok().map(|at|at-started),"first_error":error,"payment_qualified":false})
            );
            panic!("transport independence failed: {error}");
        }
    }
}
