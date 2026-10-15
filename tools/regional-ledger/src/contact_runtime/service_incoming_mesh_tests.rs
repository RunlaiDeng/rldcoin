//! Fresh incoming Mesh refusal baselines; transport evidence only.
//! Each isolated selector has one original30 scope;35 is external stop only.
use super::*;
use std::net::Shutdown;
use std::sync::Mutex;

const INCOMING_FORMAT: &str = "RLD-INCOMING-MESH-BASELINE-V1";
#[derive(Clone, Copy, PartialEq, Eq)]
enum IncomingCase {
    BeforeChallenge,
    BeforeCustody,
}
impl IncomingCase {
    fn label(self) -> &'static str {
        match self {
            Self::BeforeChallenge => "mesh-held-before-challenge-open",
            Self::BeforeCustody => "mesh-held-after-authenticated-challenge",
        }
    }
}

// Guard::drop does not join its collector. This wrapper always calls finish,
// including on error, after later-declared owned workers have been joined.
struct IncomingCollector {
    guard: Option<carriage_observation::Guard>,
    sink: Option<carriage_observation::Sink>,
}
impl IncomingCollector {
    fn start(root: &Path, currency: Hash, region: Hash, id: &str) -> Result<Self> {
        let guard = carriage_observation::start(true, root, &random()?, currency, region, id)?
            .ok_or("incoming baseline observer absent")?;
        let sink = guard.sink();
        if sink.is_none() {
            let _ = guard.finish(false);
            return Err("incoming baseline observer sink absent".into());
        }
        Ok(Self {
            guard: Some(guard),
            sink,
        })
    }
    fn sink(&self) -> Result<&carriage_observation::Sink> {
        self.sink
            .as_ref()
            .ok_or("incoming baseline sink already closed".into())
    }
    fn finish(&mut self, success: bool) -> Result<()> {
        self.sink.take();
        self.guard
            .take()
            .ok_or("incoming collector already joined")?
            .finish(success)
    }
}
impl Drop for IncomingCollector {
    fn drop(&mut self) {
        self.sink.take();
        if let Some(guard) = self.guard.take() {
            let _ = guard.finish(false);
        }
    }
}

struct IncomingServerResult {
    operation_error: String,
    returned_at: f64,
    duplicate_released_at: f64,
}
// The retained duplicate shuts down the same underlying socket used by Native
// Accept. A stop flag also releases a worker still polling its owned listener.
struct IncomingServer {
    stop: Arc<AtomicBool>,
    socket: Arc<Mutex<Option<TcpStream>>>,
    returned: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<IncomingServerResult>>>,
}
struct IncomingSocketReset {
    socket: Arc<Mutex<Option<TcpStream>>>,
    armed: bool,
}
impl IncomingSocketReset {
    fn close_normally(&mut self) -> Result<()> {
        // Production Connection already closed its handle on refusal. Merely
        // drop our cancellation duplicate; do not manufacture EOF by shutdown.
        self.socket
            .lock()
            .map_err(|_| "incoming socket control poisoned")?
            .take();
        self.armed = false;
        Ok(())
    }
}
impl Drop for IncomingSocketReset {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(mut socket) = self.socket.lock() {
            if let Some(socket) = socket.take() {
                let _ = socket.shutdown(Shutdown::Both);
            }
        }
    }
}
impl IncomingServer {
    fn spawn(
        listener: TcpListener,
        config: Value,
        context: Context,
        material: Value,
        sink: carriage_observation::Sink,
        scope_deadline: f64,
    ) -> Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let socket = Arc::new(Mutex::new(None));
        let returned = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let worker_socket = socket.clone();
        let worker_returned = returned.clone();
        let worker = thread::Builder::new()
            .name("incoming baseline server".into())
            .spawn(move || {
                let stream = loop {
                    within(scope_deadline)?;
                    require(
                        !worker_stop.load(Ordering::Acquire),
                        "incoming server cancelled",
                    )?;
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => return Err(error.to_string()),
                    }
                };
                let duplicate = io(stream.try_clone())?;
                *worker_socket
                    .lock()
                    .map_err(|_| "incoming socket control poisoned")? = Some(duplicate);
                let mut socket_reset = IncomingSocketReset {
                    socket: worker_socket.clone(),
                    armed: true,
                };
                let operation = accept(&config, context.0, &material, stream, Some(&sink));
                // Move the whole Drop owner into this Rust2021 closure, not only
                // its Copy handle. Early returns still drop it inside the worker.
                drop(context);
                let returned_at = monotonic();
                worker_returned.store(true, Ordering::Release);
                // Production Close may already have shut down the socket.
                // Normal completion drops only; shutdown is exceptional cleanup.
                socket_reset.close_normally()?;
                let duplicate_released_at = monotonic()?;
                let returned_at = returned_at?;
                let operation_error = operation
                    .err()
                    .ok_or("incoming baseline unexpectedly accepted custody")?;
                // Context and Sink are owned by this worker and drop on every return.
                Ok(IncomingServerResult {
                    operation_error,
                    returned_at,
                    duplicate_released_at,
                })
            })
            .map_err(|error| format!("incoming server spawn refused: {error}"))?;
        Ok(Self {
            stop,
            socket,
            returned,
            worker: Some(worker),
        })
    }
    fn completed_before(&self, deadline: f64) -> Result<bool> {
        let worker = self
            .worker
            .as_ref()
            .ok_or("incoming server already joined")?;
        loop {
            if worker.is_finished() {
                return Ok(true);
            }
            let remaining = deadline - monotonic()?;
            if remaining <= 0.0 {
                return Ok(false);
            }
            thread::sleep(Duration::from_secs_f64(remaining.min(0.005)));
        }
    }
    fn cancel(&self) {
        self.stop.store(true, Ordering::Release);
        if let Ok(socket) = self.socket.lock() {
            if let Some(socket) = socket.as_ref() {
                let _ = socket.shutdown(Shutdown::Both);
            }
        }
    }
    fn join(&mut self) -> Result<IncomingServerResult> {
        let result = self
            .worker
            .take()
            .ok_or("incoming server already joined")?
            .join()
            .map_err(|_| "incoming server panicked".to_string())?;
        self.socket
            .lock()
            .map_err(|_| "incoming socket control poisoned")?
            .take();
        result
    }
}
impl Drop for IncomingServer {
    fn drop(&mut self) {
        if self.worker.is_some() {
            self.cancel();
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        if let Ok(mut socket) = self.socket.lock() {
            socket.take();
        }
    }
}

struct IncomingFixture {
    configs: Vec<Value>,
    ids: Vec<String>,
    materials: Vec<Value>,
    currency: Hash,
    region: Hash,
    native_head: Hash,
    native_value: Hash,
    native_before: BTreeMap<PathBuf, (u64, String)>,
    frame_raw: Vec<u8>,
    frame_id: Hash,
    packet_id: String,
    source_cursor: u64,
    recipient_before: BTreeMap<PathBuf, (u64, String)>,
    source_reserved: TcpListener,
    listener: Option<TcpListener>,
}
fn incoming_fixture(root: &Path, deadline: f64) -> Result<IncomingFixture> {
    let mut bootstrap = crate::tests::bootstrap();
    bootstrap.currency.origin = format!("incoming-{}", &random()?[..16]);
    bootstrap.currency.cap = crate::Amount::TOTAL_SUPPLY;
    bootstrap.currency.block_reward = rld_pow::subsidy(1).map_err(|error| error.to_string())?;
    bootstrap.admissions[0].region = bootstrap.currency.origin.clone();
    bootstrap.currency.signature = crate::tests::signature(1, &bootstrap.currency.bytes()?);
    let currency = bootstrap.currency.id()?;
    for admission in &mut bootstrap.admissions {
        admission.currency = currency;
        admission.signature = crate::tests::signature(1, &admission.bytes()?);
    }
    let region = bootstrap.admissions[0].id()?;
    let native = Store::create(
        &root.join("ledger"),
        bootstrap,
        region,
        &crate::tests::public(1),
        currency,
    )?;
    require(
        native.chain.height() == 0
            && native.chain.finalized.is_none()
            && native.chain.ledger.minted == crate::Amount::ZERO
            && native.chain.ledger.coins.is_empty()
            && native.chain.ledger.exports.is_empty()
            && native.chain.ledger.imports.is_empty(),
        "incoming baseline Native genesis is not zero-issued",
    )?;
    let native_head = native.storage_head()?;
    let native_value = native.chain.ledger.root()?;
    drop(native);
    let native_before = inventory(&root.join("ledger"))?;
    let listener = io(TcpListener::bind("127.0.0.1:0"))?;
    io(listener.set_nonblocking(true))?;
    let recipient_port = io(listener.local_addr())?.port();
    let source_reserved = io(TcpListener::bind("127.0.0.1:0"))?;
    let source_port = io(source_reserved.local_addr())?.port();
    let mut ids = Vec::new();
    let mut configs = Vec::new();
    let mut materials = Vec::new();
    for label in ["source-mesh", "recipient-mesh"] {
        let identity = initialize(
            &root.join(label),
            &currency.to_hex(),
            &region.to_hex(),
            "public-no-value-incoming-mesh-baseline",
        )?;
        ids.push(
            identity["node_id"]
                .as_str()
                .ok_or("incoming identity")?
                .to_owned(),
        );
        let config =
            json!({"format":MESH,"network":currency,"state":root.join(label),"contacts":[]});
        materials.push(crate::contact_runtime::tls_identity(&config)?);
        configs.push(config);
    }
    configs[0]["contacts"] = json!([{"peer":ids[1],"host":"127.0.0.1","port":recipient_port,
        "tls_cert_sha256":materials[1]["fingerprint"]}]);
    configs[1]["contacts"] = json!([{"peer":ids[0],"host":"127.0.0.1","port":source_port,
        "tls_cert_sha256":materials[0]["fingerprint"]}]);
    for config in &configs {
        drop(Node::open(config)?);
    }
    // A complete transport Frame, not Native consensus or owner/value authority.
    let payload = bytes(
        &json!({"format":crate::bft_network::FORMAT,"currency":currency,
        "region":region,"evidence":{"snapshots":[]},"body":{"Submission":[]}}),
    )?;
    let payload_sha256 = Hash(Sha256::digest(&payload).into());
    let mut frame = crate::contact::Frame {
        format: crate::contact::FRAME_FORMAT.into(),
        kind: "regional-bft".into(),
        source_chain_id: region,
        destination_chain_id: region,
        export_id: payload_sha256,
        payload_sha256,
        payload_b64: STANDARD.encode(payload),
        message_id: Hash::ZERO,
    };
    frame.message_id = frame.message()?;
    let frame_raw = frame.retained_bytes()?;
    let packet_id = Node::open(&configs[0])?.enqueue(&frame_raw, &ids[1])?;
    let source_raw = files::private_read_with_limit(
        &root.join("source-mesh/native-mesh-state.json"),
        32 * 1024 * 1024,
    )?;
    let image = state_image(&source_raw, currency, &ids[0])?;
    let source_cursor = image["state"]["cursor"]
        .as_u64()
        .ok_or("incoming source cursor")?;
    let recipient_before = inventory(&root.join("recipient-mesh"))?;
    within(deadline)?;
    Ok(IncomingFixture {
        configs,
        ids,
        materials,
        currency,
        region,
        native_head,
        native_value,
        native_before,
        frame_raw,
        frame_id: frame.message_id,
        packet_id,
        source_cursor,
        recipient_before,
        source_reserved,
        listener: Some(listener),
    })
}

fn incoming_context(fixture: &IncomingFixture) -> Result<Context> {
    let value = tls(json!({"Context":{"root":fixture.configs[1]["state"],
        "network":fixture.currency,"peer":fixture.ids[1]}}))?;
    Ok(Context(
        value["handle"].as_u64().ok_or("incoming TLS context")?,
    ))
}
fn incoming_held_probe(config: &Value) -> Result<String> {
    let failure = match Node::open(config) {
        Err(error) => error,
        Ok(_) => return Err("held recipient Mesh unexpectedly opened".into()),
    };
    require(
        failure.starts_with(&format!("CONTACT_STORAGE_IO:{}:", libc::EWOULDBLOCK))
            || failure.starts_with(&format!("CONTACT_STORAGE_IO:{}:", libc::EAGAIN)),
        "held recipient did not return typed acquisition WouldBlock",
    )?;
    require(
        lock_contention(&failure),
        "held Mesh classification differs",
    )?;
    require(
        Node::open_or_defer_mesh(config)?.is_none(),
        "held Mesh did not defer narrowly",
    )?;
    Ok(failure)
}

fn incoming_events(
    mesh_root: &Path,
    lane: &str,
    phases: &[&str],
    packet: &str,
    frame: Hash,
    challenge: Option<&str>,
) -> Result<(String, Value)> {
    let raw = files::private_read_with_limit(
        &mesh_root.join("carriage-boundary-events.jsonl"),
        8 * 1024 * 1024,
    )?;
    let rows = raw
        .split(|b| *b == b'\n')
        .filter(|row| !row.is_empty())
        .map(|row| crate::wallet_http::decode_unique_with_limit(row, 16 * 1024))
        .collect::<Result<Vec<_>>>()?;
    require(
        rows.len() == phases.len(),
        "incoming baseline exact event count",
    )?;
    for (index, (row, phase)) in rows.iter().zip(phases).enumerate() {
        require(
            row["phase"] == *phase
                && row["lane"] == lane
                && row["attempt_id"] == 1
                && row["attempt_sequence"] == index + 1,
            "incoming baseline exact one-attempt sequence",
        )?;
    }
    let terminal = read(
        &mesh_root.join("carriage-boundary-terminal.json"),
        64 * 1024,
    )?;
    require(
        terminal["success"] == true
            && terminal["loss"] == 0
            && terminal["errors"] == 0
            && terminal["active_attempts"] == 0
            && terminal["incomplete_attempts"] == 0
            && terminal["remaining_sink_handles"] == 0
            && terminal["attempts_started"] == 1
            && terminal["events_sha256"] == sha(&raw),
        "incoming baseline observer closure",
    )?;
    let last = rows.last().ok_or("incoming baseline event rows absent")?;
    if lane == "incoming" {
        require(
            last["detail"]["result"] == "error"
                && last["detail"]["error_tag"] == "CONTACT_STORAGE_IO"
                && last["detail"]["lock_contention"] == true,
            "incoming baseline lock refusal terminal",
        )?;
    } else {
        require(
            last["detail"]["result"] == "error"
                && last["detail"]["error_tag"] == "TLS_IO"
                && last["detail"]["lock_contention"] == false,
            "outgoing baseline TLS refusal terminal",
        )?;
        let prepared = rows
            .iter()
            .find(|row| row["phase"] == "prepare-completed")
            .ok_or("outgoing baseline prepared metadata absent")?;
        require(
            prepared["detail"]["packet_ids"] == json!([packet])
                && prepared["detail"]["frame_ids"] == json!([frame.to_hex()]),
            "outgoing baseline original packet/frame differs",
        )?;
    }
    let checked = rows
        .iter()
        .find(|row| row["phase"] == "request-verified")
        .map(|row| row["detail"].clone())
        .unwrap_or(Value::Null);
    if let Some(challenge) = challenge {
        let sent = rows
            .iter()
            .find(|row| row["phase"] == "challenge-send-started")
            .ok_or("incoming actual challenge-send metadata absent")?;
        require(
            checked["challenge_id"] == challenge
                && checked["packet_ids"] == json!([packet])
                && checked["frame_ids"] == json!([frame.to_hex()])
                && sent["detail"]["challenge_id"] == challenge,
            "incoming exact authenticated request metadata",
        )?;
    }
    Ok((sha(&raw), checked))
}

fn incoming_cold(root: &Path, fixture: &IncomingFixture, deadline: f64) -> Result<()> {
    within(deadline)?;
    let state_path = root.join("source-mesh/native-mesh-state.json");
    let raw = files::private_read_with_limit(&state_path, 32 * 1024 * 1024)?;
    drop(Node::open(&fixture.configs[0])?);
    require(
        files::private_read_with_limit(&state_path, 32 * 1024 * 1024)? == raw,
        "cold source changed exact evidence",
    )?;
    let image = state_image(&raw, fixture.currency, &fixture.ids[0])?;
    let next_cursor = fixture
        .source_cursor
        .checked_add(1)
        .ok_or("incoming source cursor overflow")?;
    require(
        image["state"]["cursor"] == next_cursor
            && image["state"]["messages"].get(&fixture.packet_id).is_some()
            && image["frames"]
                .as_object()
                .ok_or("incoming retained frame table")?
                .values()
                .any(|value| value["frame"] == STANDARD.encode(&fixture.frame_raw)),
        "incoming source reprepare or lost frame",
    )?;
    drop(Node::open(&fixture.configs[1])?);
    let mut recipient_after = inventory(&root.join("recipient-mesh"))?;
    for name in [
        "carriage-boundary-scope.json",
        "carriage-boundary-events.jsonl",
        "carriage-boundary-terminal.json",
    ] {
        require(
            recipient_after.remove(Path::new(name)).is_some(),
            "incoming observer file missing",
        )?;
    }
    require(
        recipient_after == fixture.recipient_before,
        "incoming refusal changed recipient custody",
    )?;
    let cold = Store::open_pinned_inspection(
        &root.join("ledger"),
        &crate::tests::public(1),
        fixture.currency,
        fixture.native_head,
    )?;
    require(
        cold.storage_head()? == fixture.native_head
            && cold.chain.ledger.root()? == fixture.native_value
            && cold.chain.height() == 0
            && cold.chain.finalized.is_none()
            && cold.chain.ledger.minted == crate::Amount::ZERO
            && cold.chain.ledger.coins.is_empty()
            && cold.chain.ledger.imports.is_empty()
            && cold.chain.ledger.exports.is_empty(),
        "incoming cold Native zero state changed",
    )?;
    drop(cold);
    require(
        inventory(&root.join("ledger"))? == fixture.native_before,
        "incoming Native retained bytes changed",
    )?;
    within(deadline)
}

fn incoming_run(root: &Path, started: f64, deadline: f64, case: IncomingCase) -> Result<Value> {
    let mut fixture = incoming_fixture(root, deadline)?;
    // Context creation precedes the deliberate recipient Mesh collision.
    let context = incoming_context(&fixture)?;
    fixture.recipient_before = inventory(&root.join("recipient-mesh"))?;
    let mut recipient_collector = IncomingCollector::start(
        &root.join("recipient-mesh"),
        fixture.currency,
        fixture.region,
        &fixture.ids[1],
    )?;
    let mut source_collector = if case == IncomingCase::BeforeChallenge {
        Some(IncomingCollector::start(
            &root.join("source-mesh"),
            fixture.currency,
            fixture.region,
            &fixture.ids[0],
        )?)
    } else {
        None
    };
    let mut held = None;
    let mut exact_error = None;
    let mut held_at = None;
    if case == IncomingCase::BeforeChallenge {
        held = Some(Lease::acquire(&root.join("recipient-mesh"), "Mesh")?);
        held_at = Some(monotonic()?);
        exact_error = Some(incoming_held_probe(&fixture.configs[1])?);
    }
    let mut server = IncomingServer::spawn(
        fixture.listener.take().ok_or("incoming listener absent")?,
        fixture.configs[1].clone(),
        context,
        fixture.materials[1].clone(),
        recipient_collector.sink()?.clone(),
        deadline,
    )?;
    let mut challenge_id: Option<String> = None;
    let mut prepared_sha: Option<String> = None;
    let mut socket_deadline = None;
    let mut client_verified_at = None;
    let client_operation = (|| -> Result<()> {
        if case == IncomingCase::BeforeChallenge {
            return outgoing_observed(
                &fixture.configs[0],
                &fixture.ids[1],
                &fixture.configs[0]["contacts"][0],
                Some(
                    source_collector
                        .as_ref()
                        .ok_or("source collector absent")?
                        .sink()?,
                ),
            );
        }
        let bundle = {
            let mut node = Node::open(&fixture.configs[0])?;
            node.prepare(&fixture.ids[1])?
        };
        let prepared_raw = bytes(&bundle)?;
        require(
            prepared_raw.len() <= EXCHANGE_LIMIT,
            "incoming original prepared bundle bound",
        )?;
        let packet_meta = carriage_packets(&bundle)?;
        require(
            packet_meta["packet_ids"] == json!([fixture.packet_id])
                && packet_meta["frame_ids"] == json!([fixture.frame_id.to_hex()])
                && packet_meta["destination_ids"] == json!([fixture.ids[1]]),
            "incoming original packet/frame/destination differs",
        )?;
        prepared_sha = Some(sha(&prepared_raw));
        new_json(&root.join("prepared-exchange.private.json"), &bundle)?;
        let original = monotonic()? + 3.0;
        socket_deadline = Some(original);
        let contact = &fixture.configs[0]["contacts"][0];
        let handle = tls(json!({"Connect":{"host":contact["host"],"port":contact["port"],
            "fingerprint":contact["tls_cert_sha256"],"network":fixture.currency,"peer":fixture.ids[1],"deadline":original}}))?
            .as_u64().ok_or("incoming controlled TLS handle")?;
        let connection = Connection(handle);
        let challenge = recv(handle, original)?;
        let verified = crypto(json!({"Exchange":{"Challenge":{"network":fixture.currency,
            "signed":challenge,"peer":fixture.ids[1],"fingerprint":contact["tls_cert_sha256"]}}}))?;
        let verified_at = monotonic()?;
        require(
            verified_at < original,
            "incoming challenge verified after original deadline",
        )?;
        client_verified_at = Some(verified_at);
        let nonce = verified["body"]["nonce"]
            .as_str()
            .ok_or("incoming challenge nonce")?
            .to_owned();
        challenge_id = Some(nonce.clone());
        // The production challenge Node is already dropped before this send/receive.
        held = Some(Lease::acquire(&root.join("recipient-mesh"), "Mesh")?);
        held_at = Some(monotonic()?);
        exact_error = Some(incoming_held_probe(&fixture.configs[1])?);
        let request = {
            let node = Node::open(&fixture.configs[0])?;
            require(
                node.id == fixture.ids[0] && node.network == fixture.currency.to_hex(),
                "incoming source identity changed",
            )?;
            require(
                monotonic()? < original,
                "incoming request expired before signing",
            )?;
            node.sign(
                "tcp-request",
                json!({"format":MESH,"adapter":"RLD-CONTACT-TCP-V4",
                "network":fixture.currency,"node_id":fixture.ids[0],"to":fixture.ids[1],
                "nonce":random()?,"challenge":nonce,"bundle":bundle}),
            )?
        };
        require(
            monotonic()? < original,
            "incoming request signing exceeded original deadline",
        )?;
        let authenticated = crypto(json!({"Exchange":{"TcpRequest":{"network":fixture.currency,
            "signed":request,"recipient":fixture.ids[1],"peers":[fixture.ids[0]],
            "nonce":nonce,"limits":limits()}}}))?;
        require(
            sha(&bytes(&authenticated["body"]["bundle"])?)
                == prepared_sha
                    .as_ref()
                    .ok_or("prepared digest absent")?
                    .as_str(),
            "incoming request changed complete original prepared bundle",
        )?;
        let raw_metadata = carriage_packets(&authenticated["body"]["bundle"])?;
        new_json(
            &root.join("client-checked-metadata.json"),
            &json!({"challenge_id":nonce,"peer":fixture.ids[0],
            "recipient":fixture.ids[1],"prepared_bundle_sha256":prepared_sha,"packet_metadata":raw_metadata,
            "request_sha256":sha(&bytes(&request)?),"envelope_authenticated":true,
            "packet_body_native_authority":false,"native_value_authority":false}),
        )?;
        new_json(&root.join("request.private.json"), &request)?;
        require(
            monotonic()? < original,
            "incoming request expired before send",
        )?;
        send(handle, original, request)?;
        // Expected server refusal closes this connection without an accepted reply.
        let reply = recv(handle, original);
        drop(connection);
        reply.map(|_| ())
    })();
    let client_returned_at = monotonic();
    // Production Close can wake the client before accept returns. Wait for
    // natural worker completion within the unchanged original scope before
    // deciding whether exceptional cancellation is needed; keep Mesh held.
    let natural_completion = server.completed_before(deadline);
    let exceptional_socket_cleanup =
        !matches!(natural_completion, Ok(true)) || !server.returned.load(Ordering::Acquire);
    if exceptional_socket_cleanup {
        server.cancel();
    }
    // Normal server join occurs while the exact test-owned Mesh lease is held.
    let server_result = server.join();
    let release_started_at = monotonic();
    drop(held.take());
    let released_at = monotonic();
    let recipient_footer = recipient_collector.finish(true);
    let source_footer = match source_collector.as_mut() {
        Some(collector) => collector.finish(true),
        None => Ok(()),
    };
    // Keep both original operation errors in private failure text before any
    // prerequisite assertion can replace them with a missing-clock diagnostic.
    // Public scope/result schemas and unknown failure fields stay unchanged.
    let raw_server_error = match &server_result {
        Ok(report) => report.operation_error.as_str(),
        Err(error) => error.as_str(),
    };
    let raw_client_error = match &client_operation {
        Err(error) => error.as_str(),
        Ok(()) => "UNEXPECTED_CLIENT_REPLY",
    };
    let operation_context =
        format!("raw_server_error=[{raw_server_error}]; raw_client_error=[{raw_client_error}]");
    let client_error = client_operation.err().ok_or_else(|| {
        format!("incoming client unexpectedly received a reply; {operation_context}")
    })?;
    require(
        client_error.starts_with("TLS_IO:"),
        &format!("incoming client unexpected refusal: {client_error}; {operation_context}"),
    )?;
    natural_completion.map_err(|error| format!("{error}; {operation_context}"))?;
    let server_report = server_result.map_err(|error| format!("{error}; {operation_context}"))?;
    recipient_footer.map_err(|error| format!("{error}; {operation_context}"))?;
    source_footer.map_err(|error| format!("{error}; {operation_context}"))?;
    let client_returned_at =
        client_returned_at.map_err(|error| format!("{error}; {operation_context}"))?;
    let release_started_at =
        release_started_at.map_err(|error| format!("{error}; {operation_context}"))?;
    let released_at = released_at.map_err(|error| format!("{error}; {operation_context}"))?;
    let held_at =
        held_at.ok_or_else(|| format!("incoming actual held clock absent; {operation_context}"))?;
    let exact_error = exact_error
        .ok_or_else(|| format!("incoming actual lock probe absent; {operation_context}"))?;
    require(
        server_report.operation_error == exact_error,
        &format!("incoming production refusal differs from actual held acquisition error; {operation_context}"),
    )?;
    require(
        !exceptional_socket_cleanup
            && server_report.returned_at <= server_report.duplicate_released_at,
        "normal baseline used test-owned socket shutdown",
    )?;
    require(
        held_at <= server_report.returned_at
            && server_report.returned_at <= release_started_at
            && release_started_at <= released_at,
        "incoming held Mesh did not cover exact production refusal",
    )?;
    within(deadline)?;
    let mut incoming_phases = vec![
        "attempt-started",
        "tls-accept-started",
        "tls-accept-completed",
        "challenge-open-started",
    ];
    if case == IncomingCase::BeforeCustody {
        incoming_phases.extend([
            "challenge-open-completed",
            "challenge-send-started",
            "challenge-send-completed",
            "request-receive-started",
            "request-receive-completed",
            "request-verified",
            "custody-open-started",
        ]);
    }
    incoming_phases.push("attempt-completed");
    let (incoming_sha, checked_metadata) = incoming_events(
        &root.join("recipient-mesh"),
        "incoming",
        &incoming_phases,
        &fixture.packet_id,
        fixture.frame_id,
        challenge_id.as_deref(),
    )?;
    if case == IncomingCase::BeforeCustody {
        require(
            checked_metadata["peer"] == fixture.ids[0]
                && checked_metadata["destination_ids"] == json!([fixture.ids[1]])
                && client_verified_at.ok_or("incoming challenge clock absent")? <= held_at
                && server_report.returned_at
                    < socket_deadline.ok_or("incoming original socket deadline absent")?
                && client_returned_at
                    < socket_deadline.ok_or("incoming original socket deadline absent")?,
            "incoming last checked source/challenge/destination differs",
        )?;
        new_json(
            &root.join("server-last-checked-metadata.json"),
            &checked_metadata,
        )?;
    }
    let outgoing_sha = if case == IncomingCase::BeforeChallenge {
        let phases = [
            "attempt-started",
            "prepare-open-started",
            "prepare-open-completed",
            "prepare-started",
            "prepare-completed",
            "connect-started",
            "attempt-completed",
        ];
        Some(
            incoming_events(
                &root.join("source-mesh"),
                "outgoing",
                &phases,
                &fixture.packet_id,
                fixture.frame_id,
                None,
            )?
            .0,
        )
    } else {
        None
    };
    incoming_cold(root, &fixture, deadline)?;
    // Retained listener reservation is owned until after all socket work and cold checks.
    drop(fixture.source_reserved);
    let test_binary_sha256 = sha(&io(fs::read(io(std::env::current_exe())?))?);
    within(deadline)?;
    let ended = monotonic()?;
    let mut result = json!({"format":INCOMING_FORMAT,"case":case.label(),"root":root,"pid":std::process::id(),
        "passed":true,"started":started,"deadline":deadline,"stop_deadline":started+35.0,"ended":ended,
        "elapsed_seconds":ended-started,"currency":fixture.currency,"region":fixture.region,
        "source_id":fixture.ids[0],"recipient_id":fixture.ids[1],"native_head":fixture.native_head,
        "native_value_root":fixture.native_value,"packet_id":fixture.packet_id,"frame_id":fixture.frame_id,
        "incoming_events_sha256":incoming_sha,"outgoing_events_sha256":outgoing_sha,
        "cleanup_duplicate_released_at":server_report.duplicate_released_at,"normal_test_socket_shutdown":false,
        "native_value_authority":false});
    let checks = json!({"held_mesh_at":held_at,"server_returned_at":server_report.returned_at,
        "client_returned_at":client_returned_at,"mesh_release_started_at":release_started_at,"mesh_released_at":released_at,
        "client_socket_deadline":socket_deadline,"challenge_id":challenge_id,"prepared_bundle_sha256":prepared_sha,
        "server_error":exact_error,"client_error":client_error,"actual_acquisition_would_block":true,
        "narrow_mesh_defer_none":true,"no_custody_or_reply":true,"native_zero_cold_and_unchanged":true,
        "source_cursor_advanced_once":true,"source_complete_frame_retained":true,"server_joined":true,
        "collectors_joined":true,"packet_body_native_authority":false,"whole_payment_pass":false,
        "payment_qualified":false,"mainnet":false,"test_binary_sha256":test_binary_sha256,
        "regional_build_source_sha256":env!("RLD_REGIONAL_SOURCE"),
        "server_checked_metadata_sha256":if case==IncomingCase::BeforeCustody { Some(sha(&bytes(&checked_metadata)?)) } else { None }});
    result
        .as_object_mut()
        .ok_or("incoming result object")?
        .extend(checks.as_object().ok_or("incoming checks object")?.clone());
    Ok(result)
}

fn incoming_failed(root: &Path, started: f64, deadline: f64, case: IncomingCase) -> Value {
    let mut result = json!({"format":INCOMING_FORMAT,"case":case.label(),"root":root,"pid":std::process::id(),
        "passed":false,"started":started,"deadline":deadline,"stop_deadline":started+35.0,"ended":monotonic().ok(),
        "elapsed_seconds":null,"currency":null,"region":null,"source_id":null,"recipient_id":null,
        "native_head":null,"native_value_root":null,"packet_id":null,"frame_id":null,
        "incoming_events_sha256":null,"outgoing_events_sha256":null,
        "cleanup_duplicate_released_at":null,"normal_test_socket_shutdown":null,"native_value_authority":false});
    let checks = json!({"held_mesh_at":null,"server_returned_at":null,"client_returned_at":null,
        "mesh_release_started_at":null,"mesh_released_at":null,"client_socket_deadline":null,"challenge_id":null,
        "prepared_bundle_sha256":null,"server_error":null,"client_error":null,"actual_acquisition_would_block":null,
        "narrow_mesh_defer_none":null,"no_custody_or_reply":null,"native_zero_cold_and_unchanged":null,
        "source_cursor_advanced_once":null,"source_complete_frame_retained":null,"server_joined":null,
        "collectors_joined":null,"packet_body_native_authority":false,"whole_payment_pass":false,
        "payment_qualified":false,"mainnet":false,"test_binary_sha256":null,
        "regional_build_source_sha256":env!("RLD_REGIONAL_SOURCE"),"server_checked_metadata_sha256":null});
    if let (Some(result), Some(checks)) = (result.as_object_mut(), checks.as_object()) {
        result.extend(checks.clone());
    }
    result
}
fn incoming_candidate(case: IncomingCase) -> Result<()> {
    require(
        !STOP.load(Ordering::Acquire),
        "incoming baseline process already stopped",
    )?;
    let started = monotonic()?;
    let deadline = started + 30.0;
    let root = io(fs::canonicalize(std::env::temp_dir()))?
        .join(format!("rld-incoming-mesh-baseline-{}", random()?));
    match fs::symlink_metadata(&root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        _ => return Err("incoming baseline root is not fresh".into()),
    }
    let root = directory(&root)?;
    let scope = json!({"format":INCOMING_FORMAT,"case":case.label(),"root":root,"pid":std::process::id(),
        "started":started,"deadline":deadline,"stop_deadline":started+35.0,
        "regional_build_source_sha256":env!("RLD_REGIONAL_SOURCE"),"fixture_only":true,
        "one_socket_attempt":true,"incoming_retry_implemented":false,"packet_body_native_authority":false,
        "native_value_authority":false,"whole_payment_pass":false,"payment_qualified":false,"mainnet":false});
    require(
        bytes(&scope)?.len() <= 64 * 1024,
        "incoming scope metadata bound",
    )?;
    new_json(&root.join("scope.json"), &scope)?;
    eprintln!("incoming_mesh_baseline_scope={}", scope);
    let result = incoming_run(&root, started, deadline, case);
    let outcome = match &result {
        Ok(value) => value.clone(),
        Err(_) => incoming_failed(&root, started, deadline, case),
    };
    require(
        bytes(&outcome)?.len() <= 64 * 1024,
        "incoming outcome metadata bound",
    )?;
    let failure_write = match &result {
        Err(error) => new_json(&root.join("private-failure.json"), &json!({"error":error})),
        Ok(_) => Ok(()),
    };
    let outcome_write = new_json(&root.join("outcome.json"), &outcome);
    eprintln!("incoming_mesh_baseline_result={}", outcome);
    result?;
    failure_write?;
    outcome_write?;
    within(deadline)
}

#[test]
#[ignore = "fresh actual pre-challenge Mesh refusal; original30 normal exit,35 stop only"]
fn incoming_challenge_refuses_actual_mesh_lock_before_tls_handshake() -> Result<()> {
    incoming_candidate(IncomingCase::BeforeChallenge)
}
#[test]
#[ignore = "fresh actual custody-open Mesh refusal; original30 normal exit,35 stop only"]
fn incoming_custody_refuses_actual_mesh_lock_after_authenticated_request() -> Result<()> {
    incoming_candidate(IncomingCase::BeforeCustody)
}
