//! Fresh actual incoming Mesh deferral tests. Transport envelope evidence only.
//! Each TLS selector uses one original30 scope;35 is stop only. Guard10/15.
use super::*;
use std::net::Shutdown;
use std::sync::{mpsc, Mutex};
const INCOMING_FORMAT: &str = "RLD-INCOMING-MESH-RETRY-CANDIDATE-V1";
const RESULT_KEYS: &str = "format case root pid passed started deadline stop_deadline ended elapsed_seconds currency region source_id recipient_id native_head native_value_root packet_id frame_id test_binary_sha256 regional_build_source_sha256 prepared_bundle_sha256 selected_bundle_sha256 selected_bad_bundle challenge_id request_sha256 reply_exchange_id incoming_events_sha256 server_checked_metadata_sha256 actual_defer_phase actual_defer_at original_incoming_deadline client_socket_deadline held_mesh_at client_challenge_verified_at client_request_sent_at server_returned_at client_returned_at cleanup_duplicate_released_at mesh_release_started_at mesh_released_at server_error client_error actual_defer_seen source_cursor_advanced_once source_complete_frame_retained native_zero_cold_and_unchanged server_joined client_joined collectors_joined normal_test_socket_shutdown recipient_custody_received reply_verified durable_before_positive_ack owned_workers_joined bad_first_transit_refused fatal_error_preserved stop_and_expiry_preopen_refused defer_then_fatal_preserved damaged_material_retained packet_body_native_authority native_value_authority whole_payment_pass payment_qualified mainnet";
#[derive(Clone, Copy, PartialEq, Eq)]
enum IncomingCase {
    CustodyRelease,
    CustodyExpiry,
    ChallengeRelease,
    ChallengeExpiry,
    BadBody,
    Guards,
}
impl IncomingCase {
    fn label(self) -> &'static str {
        match self {
            Self::CustodyRelease => "custody-release-after-actual-defer",
            Self::CustodyExpiry => "custody-held-to-original-expiry",
            Self::ChallengeRelease => "challenge-release-after-actual-defer",
            Self::ChallengeExpiry => "challenge-held-to-original-expiry",
            Self::BadBody => "bad-first-transit-after-actual-custody-defer",
            Self::Guards => "preopen-stop-expiry-and-fatal-guards",
        }
    }
    fn phase(self) -> &'static str {
        if matches!(self, Self::ChallengeRelease | Self::ChallengeExpiry) {
            "challenge"
        } else {
            "custody"
        }
    }
    fn release(self) -> bool {
        matches!(
            self,
            Self::CustodyRelease | Self::ChallengeRelease | Self::BadBody
        )
    }
    fn positive(self) -> bool {
        matches!(self, Self::CustodyRelease | Self::ChallengeRelease)
    }
    fn seconds(self) -> f64 {
        if self == Self::Guards {
            10.0
        } else {
            30.0
        }
    }
}
fn patch_record(record: &mut Value, update: Value) -> Result<()> {
    let target = record.as_object_mut().ok_or("incoming result object")?;
    for (key, value) in update.as_object().ok_or("incoming patch object")? {
        require(target.contains_key(key), "incoming unknown result key")?;
        target.insert(key.clone(), value.clone());
    }
    Ok(())
}
fn incoming_metadata(path: &Path, value: &Value) -> Result<()> {
    require(
        crate::wallet_client::canonical(value)?.len() <= 64 * 1024,
        "incoming metadata bound",
    )?;
    new_json(path, value)
}
fn recv_until<T>(receiver: &mpsc::Receiver<T>, deadline: f64) -> Result<T> {
    let remaining = deadline - monotonic()?;
    require(remaining > 0.0, "incoming control deadline exhausted")?;
    receiver
        .recv_timeout(Duration::from_secs_f64(remaining))
        .map_err(|e| format!("incoming bounded control receive: {e}"))
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
            "public-no-value-incoming-mesh-retry",
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

struct ServerReport {
    error: Option<String>,
    returned_at: f64,
    duplicate_released_at: f64,
}
struct IncomingServer {
    stop: Arc<AtomicBool>,
    socket: Arc<Mutex<Option<TcpStream>>>,
    returned: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<ServerReport>>>,
    deferred: mpsc::Receiver<IncomingMeshDeferObservation>,
}
struct IncomingSocketReset {
    socket: Arc<Mutex<Option<TcpStream>>>,
    armed: bool,
}
impl IncomingSocketReset {
    fn close_normally(&mut self) -> Result<()> {
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
        if self.armed {
            if let Ok(mut slot) = self.socket.lock() {
                if let Some(socket) = slot.take() {
                    let _ = socket.shutdown(Shutdown::Both);
                }
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
        deadline: f64,
    ) -> Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let socket = Arc::new(Mutex::new(None));
        let returned = Arc::new(AtomicBool::new(false));
        let ws = stop.clone();
        let sock = socket.clone();
        let wr = returned.clone();
        let (setup_tx, setup_rx) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("incoming retry server".into())
            .spawn(move || {
                let (_defer_reset, deferred) = install_incoming_mesh_defer_observer()?;
                setup_tx
                    .send(deferred)
                    .map_err(|_| "incoming observer handoff closed")?;
                let stream = loop {
                    within(deadline)?;
                    require(!ws.load(Ordering::Acquire), "incoming server cancelled")?;
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5))
                        }
                        Err(e) => return Err(e.to_string()),
                    }
                };
                *sock
                    .lock()
                    .map_err(|_| "incoming socket control poisoned")? =
                    Some(io(stream.try_clone())?);
                let mut reset = IncomingSocketReset {
                    socket: sock.clone(),
                    armed: true,
                };
                let operation = accept(&config, context.0, &material, stream, Some(&sink));
                // Whole Context owner is captured and retained through actual accept.
                drop(context);
                let returned_at = monotonic();
                wr.store(true, Ordering::Release);
                reset.close_normally()?;
                Ok(ServerReport {
                    error: operation.err(),
                    returned_at: returned_at?,
                    duplicate_released_at: monotonic()?,
                })
            })
            .map_err(|e| format!("incoming retry server spawn: {e}"))?;
        // If handoff fails, an owned guard already exists and joins the worker.
        let mut server = Self {
            stop,
            socket,
            returned,
            worker: Some(worker),
            deferred: mpsc::channel().1,
        };
        server.deferred = recv_until(&setup_rx, deadline)?;
        Ok(server)
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
        if let Ok(slot) = self.socket.lock() {
            if let Some(socket) = slot.as_ref() {
                let _ = socket.shutdown(Shutdown::Both);
            }
        }
    }
    fn join(&mut self) -> Result<ServerReport> {
        let result = self
            .worker
            .take()
            .ok_or("incoming server already joined")?
            .join()
            .map_err(|_| "incoming server panicked")?;
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
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
        if let Ok(mut slot) = self.socket.lock() {
            slot.take();
        }
    }
}
struct ChallengeNotice {
    at: f64,
    deadline: f64,
    challenge: String,
}
struct ClientReport {
    error: Option<String>,
    returned_at: f64,
    original_deadline: f64,
    verified_at: Option<f64>,
    challenge: Option<String>,
    request_sha: Option<String>,
    sent_at: Option<f64>,
    reply_exchange: Option<String>,
    reply_retained: bool,
}
struct ClientSocket {
    connection: Option<Connection>,
    slot: Arc<AtomicU64>,
}
impl Drop for ClientSocket {
    fn drop(&mut self) {
        self.connection.take();
        self.slot.store(0, Ordering::Release);
    }
}
struct IncomingClient {
    stop: Arc<AtomicBool>,
    handle: Arc<AtomicU64>,
    worker: Option<JoinHandle<Result<ClientReport>>>,
    challenge: mpsc::Receiver<ChallengeNotice>,
    permit: mpsc::SyncSender<()>,
}
impl IncomingClient {
    fn spawn(
        config: Value,
        peer: String,
        source: String,
        root: PathBuf,
        bundle: Value,
        selected_sha: String,
        scope_deadline: f64,
    ) -> Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let handle = Arc::new(AtomicU64::new(0));
        let ws = stop.clone();
        let wh = handle.clone();
        let (challenge_tx, challenge) = mpsc::sync_channel(1);
        let (permit, permit_rx) = mpsc::sync_channel(1);
        let worker=thread::Builder::new().name("incoming retry client".into()).spawn(move || {
   require(!ws.load(Ordering::Acquire),"incoming client cancelled before connect")?;
   let original=monotonic()?+3.0;require(original<=scope_deadline,"incoming client original deadline exceeds whole scope")?;
   let mut report=ClientReport{error:None,returned_at:0.0,original_deadline:original,verified_at:None,challenge:None,request_sha:None,sent_at:None,reply_exchange:None,reply_retained:false};
   let operation=(||->Result<()> {
    let contact=&config["contacts"][0];
    let handle=tls(json!({"Connect":{"host":contact["host"],"port":contact["port"],"fingerprint":contact["tls_cert_sha256"],"network":config["network"],"peer":peer,"deadline":original}}))?.as_u64().ok_or("incoming client TLS handle")?;
    wh.store(handle,Ordering::Release);let _socket=ClientSocket{connection:Some(Connection(handle)),slot:wh.clone()};
    let challenge=recv(handle,original)?;
    let verified=crypto(json!({"Exchange":{"Challenge":{"network":config["network"],"signed":challenge,"peer":peer,"fingerprint":contact["tls_cert_sha256"]}}}))?;
    let verified_at=monotonic()?;require(verified_at<original,"incoming challenge authenticated after original deadline")?;
    let nonce=verified["body"]["nonce"].as_str().ok_or("incoming challenge nonce")?.to_owned();
    report.verified_at=Some(verified_at);report.challenge=Some(nonce.clone());
    challenge_tx.send(ChallengeNotice{at:verified_at,deadline:original,challenge:nonce.clone()}).map_err(|_|"incoming challenge handoff closed")?;
    recv_until(&permit_rx,original)?;require(!ws.load(Ordering::Acquire),"incoming client cancelled before request")?;
    let request={let node=Node::open(&config)?;require(node.id==source,"incoming source identity changed")?;require(monotonic()?<original,"incoming request expired before signing")?;
     node.sign("tcp-request",json!({"format":MESH,"adapter":"RLD-CONTACT-TCP-V4","network":node.network,"node_id":node.id,"to":peer,"nonce":random()?,"challenge":nonce,"bundle":bundle}))?};
    require(monotonic()?<original,"incoming signing exceeded original deadline")?;
    let checked=crypto(json!({"Exchange":{"TcpRequest":{"network":config["network"],"signed":request,"recipient":peer,"peers":[source],"nonce":nonce,"limits":limits()}}}))?;
    require(sha(&bytes(&checked["body"]["bundle"])?)==selected_sha,"incoming selected complete exchange changed")?;
    report.request_sha=Some(sha(&bytes(&request)?));
    incoming_metadata(&root.join("client-checked-metadata.json"),&json!({"challenge_id":nonce,"peer":source,"recipient":peer,"selected_bundle_sha256":selected_sha,"packet_metadata":carriage_packets(&checked["body"]["bundle"])? ,"request_sha256":report.request_sha,"envelope_authenticated":true,"packet_body_native_authority":false,"native_value_authority":false}))?;
    require(monotonic()?<original,"incoming request expired before send")?;send(handle,original,request.clone())?;report.sent_at=Some(monotonic()?);
    let response=recv(handle,original)?;
    let node=Node::open(&config)?;let id=node.id.clone();drop(node);
    let checked=crypto(json!({"Exchange":{"TcpResponse":{"network":config["network"],"signed":response,"requester":id,"peer":peer,"sent":request,"limits":limits()}}}))?;
    require(checked["body"]["accepted"]==true,"incoming peer did not acknowledge custody")?;
    let exchange_id=checked["body"]["exchange_id"].as_str().ok_or("incoming reply exchange")?.to_owned();
    require(exchange_id==selected_sha,"incoming reply selected exchange binding changed")?;
    // Full received reply bundle is authenticated and durable locally, not only its outer response.
    Node::open(&config)?.receive(&checked["body"]["bundle"],&peer)?;
    report.reply_exchange=Some(exchange_id);report.reply_retained=true;within(scope_deadline)
   })();
   report.error=operation.err();report.returned_at=monotonic()?;Ok(report)
  }).map_err(|e|format!("incoming client spawn: {e}"))?;
        Ok(Self {
            stop,
            handle,
            worker: Some(worker),
            challenge,
            permit,
        })
    }
    fn completed_before(&self, deadline: f64) -> Result<bool> {
        let worker = self
            .worker
            .as_ref()
            .ok_or("incoming client already joined")?;
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
        let h = self.handle.load(Ordering::Acquire);
        if h != 0 {
            crate::contact_tls::interrupt(h);
        }
    }
    fn join(&mut self) -> Result<ClientReport> {
        self.worker
            .take()
            .ok_or("incoming client already joined")?
            .join()
            .map_err(|_| "incoming client panicked".to_string())?
    }
}
impl Drop for IncomingClient {
    fn drop(&mut self) {
        if self.worker.is_some() {
            self.cancel();
        }
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}

fn native_zero_cold(root: &Path, f: &IncomingFixture, deadline: f64) -> Result<()> {
    within(deadline)?;
    let native = Store::open_pinned_inspection(
        &root.join("ledger"),
        &crate::tests::public(1),
        f.currency,
        f.native_head,
    )?;
    require(
        native.storage_head()? == f.native_head
            && native.chain.ledger.root()? == f.native_value
            && native.chain.height() == 0
            && native.chain.finalized.is_none()
            && native.chain.ledger.minted == crate::Amount::ZERO
            && native.chain.ledger.coins.is_empty()
            && native.chain.ledger.exports.is_empty()
            && native.chain.ledger.imports.is_empty(),
        "incoming zero Native changed",
    )?;
    drop(native);
    require(
        inventory(&root.join("ledger"))? == f.native_before,
        "incoming Native exact retained bytes changed",
    )?;
    within(deadline)
}
fn source_cold(f: &IncomingFixture, prepared: bool, receipt: bool) -> Result<()> {
    let path = Path::new(
        f.configs[0]["state"]
            .as_str()
            .ok_or("incoming source root")?,
    )
    .join("native-mesh-state.json");
    let raw = files::private_read_with_limit(&path, 32 * 1024 * 1024)?;
    drop(Node::open(&f.configs[0])?);
    require(
        files::private_read_with_limit(&path, 32 * 1024 * 1024)? == raw,
        "incoming cold source changed retained evidence",
    )?;
    let image = state_image(&raw, f.currency, &f.ids[0])?;
    let expected = if prepared {
        f.source_cursor
            .checked_add(1)
            .ok_or("incoming cursor overflow")?
    } else {
        f.source_cursor
    };
    require(
        image["state"]["cursor"] == expected
            && image["state"]["messages"].get(&f.packet_id).is_some()
            && image["frames"]
                .as_object()
                .ok_or("source frames")?
                .values()
                .any(|v| v["frame"] == STANDARD.encode(&f.frame_raw)),
        "incoming source cursor/frame differs",
    )?;
    if receipt {
        require(
            image["state"]["receipts"].get(&f.packet_id).is_some()
                || image["state"]["archives"].get(&f.packet_id).is_some(),
            "incoming full retained reply lacks exact source receipt",
        )?;
    }
    Ok(())
}
fn recipient_cold(f: &IncomingFixture, positive: bool) -> Result<()> {
    let root = Path::new(
        f.configs[1]["state"]
            .as_str()
            .ok_or("incoming recipient root")?,
    );
    let node = Node::open(&f.configs[1])?;
    if positive {
        require(
            node.received_frames()?
                .iter()
                .any(|(id, raw)| id == &f.packet_id && raw == &f.frame_raw),
            "incoming cold recipient lacks exact full frame",
        )?;
    }
    drop(node);
    if positive {
        let raw =
            files::private_read_with_limit(&root.join("native-mesh-state.json"), 32 * 1024 * 1024)?;
        let image = state_image(&raw, f.currency, &f.ids[1])?;
        require(
            image["state"]["receipts"].get(&f.packet_id).is_some()
                || image["state"]["archives"].get(&f.packet_id).is_some(),
            "incoming cold destination custody receipt absent",
        )?;
    } else {
        let mut after = inventory(root)?;
        for name in [
            "carriage-boundary-scope.json",
            "carriage-boundary-events.jsonl",
            "carriage-boundary-terminal.json",
        ] {
            require(
                after.remove(Path::new(name)).is_some(),
                "incoming observer file absent",
            )?;
        }
        require(
            after == f.recipient_before,
            "fresh refusal changed recipient durable custody",
        )?;
    }
    Ok(())
}
fn read_incoming_rows(root: &Path) -> Result<(String, Vec<Value>)> {
    let raw = files::private_read_with_limit(
        &root.join("carriage-boundary-events.jsonl"),
        8 * 1024 * 1024,
    )?;
    require(raw.last() == Some(&b'\n'), "incoming partial observer tail")?;
    let rows = raw
        .split(|b| *b == b'\n')
        .filter(|r| !r.is_empty())
        .map(|r| crate::wallet_http::decode_unique_with_limit(r, 16 * 1024))
        .collect::<Result<Vec<_>>>()?;
    let terminal = read(&root.join("carriage-boundary-terminal.json"), 64 * 1024)?;
    require(
        terminal["success"] == true
            && terminal["requested_success"] == true
            && terminal["loss"] == 0
            && terminal["errors"] == 0
            && terminal["active_attempts"] == 0
            && terminal["incomplete_attempts"] == 0
            && terminal["remaining_sink_handles"] == 0
            && terminal["attempts_started"] == 1
            && terminal["events_sha256"] == sha(&raw)
            && terminal["events_bytes"] == raw.len()
            && terminal["rows"] == rows.len(),
        "incoming complete observer refused",
    )?;
    Ok((sha(&raw), rows))
}
fn selected_exchange(
    root: &Path,
    f: &IncomingFixture,
    case: IncomingCase,
) -> Result<(Value, String, String, Option<String>)> {
    let prepared = {
        let mut node = Node::open(&f.configs[0])?;
        node.prepare(&f.ids[1])?
    };
    let prepared_raw = bytes(&prepared)?;
    require(
        prepared_raw.len() <= EXCHANGE_LIMIT,
        "incoming prepared exchange bound",
    )?;
    let meta = carriage_packets(&prepared)?;
    require(
        meta["packet_ids"] == json!([f.packet_id])
            && meta["frame_ids"] == json!([f.frame_id.to_hex()])
            && meta["destination_ids"] == json!([f.ids[1]]),
        "incoming original preparation identity",
    )?;
    new_json(&root.join("prepared-exchange.private.json"), &prepared)?;
    let (selected, bad_error) = if case == IncomingCase::BadBody {
        let mut body = prepared["body"].clone();
        require(
            body["transits"].as_array().is_some_and(|v| v.len() == 1)
                && body["transits"][0]["hops"]
                    .as_array()
                    .is_some_and(|v| !v.is_empty()),
            "incoming bad first transit shape",
        )?;
        body["transits"][0]["hops"][0]["signature"] = json!("00".repeat(64));
        let selected = Node::open(&f.configs[0])?.sign("exchange", body)?;
        exchange(&selected, &f.currency.to_hex(), &f.ids[0], &f.ids[1])?;
        let error = match transit(
            &selected["body"]["transits"][0],
            &f.currency.to_hex(),
            json!(f.ids[1]),
            json!(f.ids[0]),
        ) {
            Err(error) => error,
            Ok(_) => return Err("deliberate bad first transit authenticated".into()),
        };
        (selected, Some(error))
    } else {
        (prepared.clone(), None)
    };
    let selected_raw = bytes(&selected)?;
    require(
        selected_raw.len() <= EXCHANGE_LIMIT,
        "incoming selected exchange bound",
    )?;
    let ordinary_sha = sha(&prepared_raw);
    let selected_sha = sha(&selected_raw);
    require(
        (case == IncomingCase::BadBody) == (ordinary_sha != selected_sha),
        "incoming ordinary/bad selected bundle distinction",
    )?;
    new_json(&root.join("selected-exchange.private.json"), &selected)?;
    Ok((selected, ordinary_sha, selected_sha, bad_error))
}
fn run_tls(root: &Path, scope_deadline: f64, case: IncomingCase, record: &mut Value) -> Result<()> {
    let mut f = incoming_fixture(root, scope_deadline)?;
    patch_record(
        record,
        json!({"currency":f.currency,"region":f.region,"source_id":f.ids[0],"recipient_id":f.ids[1],"native_head":f.native_head,"native_value_root":f.native_value,"packet_id":f.packet_id,"frame_id":f.frame_id,"selected_bad_bundle":case==IncomingCase::BadBody}),
    )?;
    let (selected, prepared_sha, selected_sha, bad_error) = selected_exchange(root, &f, case)?;
    patch_record(
        record,
        json!({"prepared_bundle_sha256":prepared_sha,"selected_bundle_sha256":selected_sha}),
    )?;
    let context = incoming_context(&f)?;
    f.recipient_before = inventory(&root.join("recipient-mesh"))?;
    let mut collector = IncomingCollector::start(
        &root.join("recipient-mesh"),
        f.currency,
        f.region,
        &f.ids[1],
    )?;
    let mut held = None;
    if case.phase() == "challenge" {
        held = Some(Lease::acquire(&root.join("recipient-mesh"), "Mesh")?);
        patch_record(record, json!({"held_mesh_at":monotonic()?}))?;
        incoming_held_probe(&f.configs[1])?;
    }
    let mut server = IncomingServer::spawn(
        f.listener.take().ok_or("incoming listener absent")?,
        f.configs[1].clone(),
        context,
        f.materials[1].clone(),
        collector.sink()?.clone(),
        scope_deadline,
    )?;
    let mut client = IncomingClient::spawn(
        f.configs[0].clone(),
        f.ids[1].clone(),
        f.ids[0].clone(),
        root.to_owned(),
        selected,
        selected_sha.clone(),
        scope_deadline,
    )?;
    let control = (|| -> Result<()> {
        if case.phase() == "custody" {
            let notice = recv_until(&client.challenge, scope_deadline)?;
            patch_record(
                record,
                json!({"client_socket_deadline":notice.deadline,"client_challenge_verified_at":notice.at,"challenge_id":notice.challenge}),
            )?;
            held = Some(Lease::acquire(&root.join("recipient-mesh"), "Mesh")?);
            patch_record(record, json!({"held_mesh_at":monotonic()?}))?;
            incoming_held_probe(&f.configs[1])?;
            client
                .permit
                .send(())
                .map_err(|_| "incoming request permit closed")?;
        }
        let (phase, original, at) = recv_until(&server.deferred, scope_deadline)?;
        require(
            phase == case.phase()
                && original.is_finite()
                && original <= scope_deadline
                && at.is_finite()
                && at < original,
            "incoming actual None phase/original clock differs",
        )?;
        require(
            record["held_mesh_at"]
                .as_f64()
                .ok_or("incoming held clock absent")?
                <= at,
            "incoming None predates held lease",
        )?;
        patch_record(
            record,
            json!({"actual_defer_phase":phase,"original_incoming_deadline":original,"actual_defer_at":at,"actual_defer_seen":true}),
        )?;
        if case.release() {
            patch_record(record, json!({"mesh_release_started_at":monotonic()?}))?;
            drop(held.take());
            patch_record(record, json!({"mesh_released_at":monotonic()?}))?;
            require(
                record["mesh_released_at"]
                    .as_f64()
                    .ok_or("incoming release clock")?
                    < original,
                "incoming controlled release was after original expiry",
            )?;
            if case.phase() == "challenge" {
                let notice = recv_until(&client.challenge, scope_deadline)?;
                patch_record(
                    record,
                    json!({"client_socket_deadline":notice.deadline,"client_challenge_verified_at":notice.at,"challenge_id":notice.challenge}),
                )?;
                client
                    .permit
                    .send(())
                    .map_err(|_| "incoming request permit closed")?;
            }
        }
        Ok(())
    })();
    // Natural finish precedes exceptional classification; no test EOF manufactures a passing path.
    let server_natural = server.completed_before(scope_deadline);
    let server_cancelled =
        !matches!(server_natural, Ok(true)) || !server.returned.load(Ordering::Acquire);
    if server_cancelled {
        server.cancel();
    }
    let server_result = server.join();
    let client_natural = client.completed_before(scope_deadline);
    let client_cancelled = !matches!(client_natural, Ok(true));
    if client_cancelled {
        client.cancel();
    }
    let client_result = client.join();
    if held.is_some() {
        patch_record(record, json!({"mesh_release_started_at":monotonic()?}))?;
        drop(held.take());
        patch_record(record, json!({"mesh_released_at":monotonic()?}))?;
    }
    let footer = collector.finish(true);
    let se = match &server_result {
        Ok(r) => r.error.as_deref().unwrap_or("SUCCESS"),
        Err(e) => e,
    };
    let ce = match &client_result {
        Ok(r) => r.error.as_deref().unwrap_or("SUCCESS"),
        Err(e) => e,
    };
    let context = format!("raw_server_error=[{se}]; raw_client_error=[{ce}]");
    control.map_err(|e| format!("{e}; {context}"))?;
    server_natural.map_err(|e| format!("{e}; {context}"))?;
    client_natural.map_err(|e| format!("{e}; {context}"))?;
    let sr = server_result.map_err(|e| format!("{e}; {context}"))?;
    let cr = client_result.map_err(|e| format!("{e}; {context}"))?;
    footer.map_err(|e| format!("{e}; {context}"))?;
    patch_record(
        record,
        json!({"server_error":sr.error,"client_error":cr.error,"server_returned_at":sr.returned_at,"client_returned_at":cr.returned_at,"cleanup_duplicate_released_at":sr.duplicate_released_at,"client_socket_deadline":cr.original_deadline,"client_challenge_verified_at":cr.verified_at,"challenge_id":cr.challenge,"request_sha256":cr.request_sha,"client_request_sent_at":cr.sent_at,"reply_exchange_id":cr.reply_exchange,"server_joined":true,"client_joined":true,"collectors_joined":true,"owned_workers_joined":true,"normal_test_socket_shutdown":server_cancelled||client_cancelled}),
    )?;
    require(
        !server_cancelled && !client_cancelled,
        &format!("incoming used exceptional socket cancellation; {context}"),
    )?;
    within(scope_deadline)?;
    let (events_sha, rows) = read_incoming_rows(&root.join("recipient-mesh"))?;
    let mut phases = vec![
        "attempt-started",
        "tls-accept-started",
        "tls-accept-completed",
        "challenge-open-started",
    ];
    if case.phase() == "custody" || case.release() {
        phases.extend([
            "challenge-open-completed",
            "challenge-send-started",
            "challenge-send-completed",
            "request-receive-started",
            "request-receive-completed",
            "request-verified",
            "custody-open-started",
        ]);
    }
    if case.positive() {
        phases.extend([
            "custody-open-completed",
            "custody-receive-started",
            "custody-receive-completed",
            "reply-prepare-started",
            "reply-prepare-completed",
            "reply-send-started",
            "reply-send-completed",
        ]);
    } else if case == IncomingCase::BadBody {
        phases.extend(["custody-open-completed", "custody-receive-started"]);
    }
    phases.push("attempt-completed");
    require(
        rows.len() == phases.len(),
        "incoming exact complete phase count",
    )?;
    let observer_scope = read(
        &root.join("recipient-mesh/carriage-boundary-scope.json"),
        64 * 1024,
    )?;
    let mut last_at = record["started"]
        .as_f64()
        .ok_or("incoming whole start clock")?;
    for (i, (row, phase)) in rows.iter().zip(&phases).enumerate() {
        let at = row["observed_at"]
            .as_f64()
            .filter(|at| at.is_finite())
            .ok_or("incoming phase clock")?;
        require(
            row["phase"] == *phase
                && row["lane"] == "incoming"
                && row["attempt_id"] == 1
                && row["attempt_sequence"] == i + 1
                && row["written_sequence"] == i + 1
                && at >= last_at
                && at <= sr.returned_at,
            "incoming one-attempt phase order/clock",
        )?;
        for key in [
            "format",
            "pid",
            "instance",
            "currency",
            "region",
            "node_id",
            "regional_build_source_sha256",
        ] {
            require(
                row[key] == observer_scope[key],
                "incoming event observer binding changed",
            )?;
        }
        require(
            row["pid"] == std::process::id()
                && row["currency"] == json!(f.currency)
                && row["region"] == json!(f.region)
                && row["node_id"] == f.ids[1]
                && row["regional_build_source_sha256"] == env!("RLD_REGIONAL_SOURCE"),
            "incoming event source/process/identity binding",
        )?;
        last_at = at;
    }
    let defer_at = record["actual_defer_at"]
        .as_f64()
        .ok_or("incoming actual None clock")?;
    let open_phase = if case.phase() == "challenge" {
        "challenge-open-started"
    } else {
        "custody-open-started"
    };
    let open_at = rows
        .iter()
        .find(|row| row["phase"] == open_phase)
        .and_then(|row| row["observed_at"].as_f64())
        .ok_or("incoming matching open phase")?;
    require(
        open_at <= defer_at && defer_at <= sr.returned_at,
        "incoming actual None outside matching open operation",
    )?;
    patch_record(record, json!({"incoming_events_sha256":events_sha}))?;
    if let Some(checked) = rows.iter().find(|r| r["phase"] == "request-verified") {
        let metadata = &checked["detail"];
        require(
            metadata["challenge_id"] == record["challenge_id"]
                && metadata["peer"] == f.ids[0]
                && metadata["packet_ids"] == json!([f.packet_id])
                && metadata["frame_ids"] == json!([f.frame_id.to_hex()])
                && metadata["destination_ids"] == json!([f.ids[1]]),
            "incoming exact authenticated request metadata",
        )?;
        incoming_metadata(&root.join("server-last-checked-metadata.json"), metadata)?;
        patch_record(
            record,
            json!({"server_checked_metadata_sha256":sha(&bytes(metadata)?)}),
        )?;
    }
    let incoming_original = record["original_incoming_deadline"]
        .as_f64()
        .ok_or("incoming original deadline absent")?;
    let terminal = &rows.last().ok_or("incoming terminal absent")?["detail"];
    if case.positive() {
        require(
            record["server_error"].is_null()
                && record["client_error"].is_null()
                && cr.reply_retained
                && terminal["result"] == "ok",
            &format!("incoming release failed; {context}"),
        )?;
        let receive = rows
            .iter()
            .find(|r| r["phase"] == "custody-receive-completed")
            .ok_or("incoming durable receive absent")?;
        let reply = rows
            .iter()
            .find(|r| r["phase"] == "reply-send-started")
            .ok_or("incoming positive reply absent")?;
        require(
            receive["detail"]["retained_packet_ids"] == json!([f.packet_id])
                && receive["observed_at"]
                    .as_f64()
                    .ok_or("incoming receive clock")?
                    <= reply["observed_at"]
                        .as_f64()
                        .ok_or("incoming reply clock")?,
            "incoming reply preceded complete durable receive",
        )?;
        patch_record(
            record,
            json!({"recipient_custody_received":true,"reply_verified":true,"durable_before_positive_ack":true}),
        )?;
    } else if case == IncomingCase::BadBody {
        require(
            record["server_error"].as_str() == bad_error.as_deref()
                && record["client_error"]
                    .as_str()
                    .is_some_and(|e| e.starts_with("TLS_IO:"))
                && !cr.reply_retained
                && terminal["result"] == "error"
                && terminal["lock_contention"] == false,
            &format!("incoming bad first transit did not preserve fatal; {context}"),
        )?;
        patch_record(
            record,
            json!({"recipient_custody_received":false,"reply_verified":false,"bad_first_transit_refused":true}),
        )?;
    } else {
        require(
            record["server_error"]
                == "TLS_TIMEOUT: original incoming deadline exhausted; retain complete evidence"
                && sr.returned_at >= incoming_original
                && record["client_error"]
                    .as_str()
                    .is_some_and(|e| e.starts_with("TLS_IO:") || e.starts_with("TLS_TIMEOUT:"))
                && !cr.reply_retained
                && terminal["error_tag"] == "TLS_TIMEOUT"
                && terminal["lock_contention"] == false,
            &format!("incoming original expiry failed; {context}"),
        )?;
        require(
            record["mesh_release_started_at"]
                .as_f64()
                .ok_or("incoming expiry release clock")?
                >= sr.returned_at,
            "incoming expiry lease released before worker refusal",
        )?;
        patch_record(
            record,
            json!({"recipient_custody_received":false,"reply_verified":false}),
        )?;
    }
    if case.release() {
        require(
            record["client_request_sent_at"]
                .as_f64()
                .ok_or("incoming request send clock")?
                < cr.original_deadline,
            "incoming request send exceeded original deadline",
        )?;
    }
    source_cold(&f, true, case.positive())?;
    recipient_cold(&f, case.positive())?;
    native_zero_cold(root, &f, scope_deadline)?;
    patch_record(
        record,
        json!({"source_cursor_advanced_once":true,"source_complete_frame_retained":true,"native_zero_cold_and_unchanged":true}),
    )?;
    drop(f.source_reserved);
    within(scope_deadline)
}

fn incoming_refusal(result: Result<Node>) -> Result<String> {
    match result {
        Err(error) => Ok(error),
        Ok(_) => Err("incoming refusal unexpectedly opened a Node".into()),
    }
}
struct IncomingStopReset(bool);
impl Drop for IncomingStopReset {
    fn drop(&mut self) {
        STOP.store(self.0, Ordering::Release);
    }
}
struct IncomingGuardWorker {
    worker: Option<JoinHandle<Result<(String, f64)>>>,
    deferred: mpsc::Receiver<IncomingMeshDeferObservation>,
    returned: Arc<AtomicBool>,
}
impl IncomingGuardWorker {
    fn spawn(config: Value, original: f64, scope_deadline: f64) -> Result<Self> {
        let (tx, rx) = mpsc::sync_channel(1);
        let returned = Arc::new(AtomicBool::new(false));
        let wr = returned.clone();
        let worker = thread::Builder::new()
            .name("incoming fatal-after-defer guard".into())
            .spawn(move || {
                let (_reset, deferred) = install_incoming_mesh_defer_observer()?;
                tx.send(deferred)
                    .map_err(|_| "incoming guard observer handoff closed")?;
                let result =
                    incoming_refusal(incoming_node_before_deadline(&config, original, "custody"));
                let at = monotonic();
                wr.store(true, Ordering::Release);
                Ok((result?, at?))
            })
            .map_err(|e| format!("incoming guard spawn: {e}"))?;
        let mut guard = Self {
            worker: Some(worker),
            deferred: mpsc::channel().1,
            returned,
        };
        guard.deferred = recv_until(&rx, scope_deadline)?;
        Ok(guard)
    }
    fn completed_before(&self, deadline: f64) -> Result<bool> {
        let worker = self
            .worker
            .as_ref()
            .ok_or("incoming guard already joined")?;
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
    fn join(&mut self) -> Result<(String, f64)> {
        self.worker
            .take()
            .ok_or("incoming guard already joined")?
            .join()
            .map_err(|_| "incoming guard panicked".to_string())?
    }
}
impl Drop for IncomingGuardWorker {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _reset = IncomingStopReset(STOP.swap(true, Ordering::AcqRel));
            let _ = worker.join();
        }
    }
}
fn damage_mesh_state(path: &Path) -> Result<()> {
    let mut file = io(std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path))?;
    io(std::io::Write::write_all(
        &mut file,
        b"invalid retained Mesh state; preserve this failed incoming fixture",
    ))?;
    io(file.sync_all())?;
    drop(file);
    io(fs::File::open(
        path.parent().ok_or("incoming damaged parent")?,
    ))?
    .sync_all()
    .map_err(|e| e.to_string())
}
fn run_guards(root: &Path, deadline: f64, record: &mut Value) -> Result<()> {
    require(
        !STOP.load(Ordering::Acquire),
        "incoming guard process already stopped",
    )?;
    for original in [
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        monotonic()? - 1.0,
    ] {
        require(
            incoming_refusal(incoming_node_before_deadline(
                &Value::Null,
                original,
                "custody",
            ))?
            .starts_with("TLS_TIMEOUT:"),
            "incoming nonfinite/expired guard inspected invalid config",
        )?;
    }
    {
        let reset = IncomingStopReset(STOP.swap(true, Ordering::AcqRel));
        let refused = incoming_refusal(incoming_node_before_deadline(
            &Value::Null,
            monotonic()? + 3.0,
            "challenge",
        ));
        drop(reset);
        require(
            refused? == "incoming Mesh acquisition cancelled; retain complete evidence",
            "incoming STOP guard inspected invalid config",
        )?;
    }
    require(
        !STOP.load(Ordering::Acquire),
        "incoming STOP guard was not reset",
    )?;
    patch_record(record, json!({"stop_and_expiry_preopen_refused":true}))?;
    let f = incoming_fixture(root, deadline)?;
    patch_record(
        record,
        json!({"currency":f.currency,"region":f.region,"source_id":f.ids[0],"recipient_id":f.ids[1],"native_head":f.native_head,"native_value_root":f.native_value,"packet_id":f.packet_id,"frame_id":f.frame_id,"selected_bad_bundle":false}),
    )?;
    let damaged = root.join("recipient-mesh/native-mesh-state.json");
    let mut held = Some(Lease::acquire(&root.join("recipient-mesh"), "Mesh")?);
    patch_record(record, json!({"held_mesh_at":monotonic()?}))?;
    incoming_held_probe(&f.configs[1])?;
    let original = monotonic()? + 3.0;
    require(
        original <= deadline,
        "incoming guard original helper deadline exceeds whole scope",
    )?;
    let mut worker = IncomingGuardWorker::spawn(f.configs[1].clone(), original, deadline)?;
    let mut damaged_before = None;
    let control = (|| -> Result<()> {
        let (phase, observed_deadline, at) = recv_until(&worker.deferred, deadline)?;
        require(
            phase == "custody"
                && observed_deadline == original
                && at.is_finite()
                && at < original
                && record["held_mesh_at"]
                    .as_f64()
                    .ok_or("incoming guard held clock")?
                    <= at,
            "incoming guard actual None deadline/phase differs",
        )?;
        patch_record(
            record,
            json!({"actual_defer_phase":phase,"original_incoming_deadline":observed_deadline,"actual_defer_at":at,"actual_defer_seen":true}),
        )?;
        // Fixed deliberate corruption occurs only after the worker's real None,
        // while this test still owns the actual Mesh lease. It is never repaired.
        damage_mesh_state(&damaged)?;
        damaged_before = Some(inventory(&root.join("recipient-mesh"))?);
        patch_record(record, json!({"mesh_release_started_at":monotonic()?}))?;
        drop(held.take());
        patch_record(record, json!({"mesh_released_at":monotonic()?}))?;
        require(
            record["mesh_released_at"]
                .as_f64()
                .ok_or("incoming guard release clock")?
                < original,
            "incoming guard release missed original helper deadline",
        )?;
        Ok(())
    })();
    // A control error releases only this test's own lease. The worker is joined
    // before its known measurements are classified or a result can be sealed.
    if held.is_some() {
        drop(held.take());
    }
    let natural = worker.completed_before(deadline);
    let cancelled = !matches!(natural, Ok(true)) || !worker.returned.load(Ordering::Acquire);
    let reset = if cancelled {
        Some(IncomingStopReset(STOP.swap(true, Ordering::AcqRel)))
    } else {
        None
    };
    let joined = worker.join();
    drop(reset);
    if let Ok((fatal, _)) = &joined {
        patch_record(
            record,
            json!({"owned_workers_joined":true,"server_error":fatal}),
        )?;
    }
    let raw_guard = match &joined {
        Ok((fatal, _)) => fatal.as_str(),
        Err(error) => error.as_str(),
    };
    let context = format!("actual_guard_error=[{raw_guard}]");
    control.map_err(|error| format!("{error}; {context}"))?;
    natural.map_err(|error| format!("{error}; {context}"))?;
    require(
        !cancelled,
        &format!("incoming guard required exceptional STOP cancellation; {context}"),
    )?;
    let (_fatal, returned_at) = joined?;
    require(
        returned_at < original,
        "incoming fatal-after-defer exceeded original helper deadline",
    )?;
    let expected = incoming_refusal(Node::open(&f.configs[1]))?;
    require(
        record["server_error"] == expected
            && !expected.starts_with("TLS_TIMEOUT:")
            && !expected.starts_with("incoming Mesh acquisition cancelled")
            && !lock_contention(&expected),
        "incoming real defer did not preserve actual fatal",
    )?;
    // A second complete helper call must preserve the same immediate fatal.
    let direct = incoming_refusal(incoming_node_before_deadline(
        &f.configs[1],
        monotonic()? + 3.0,
        "challenge",
    ))?;
    require(
        direct == expected,
        "incoming immediate full-open fatal changed",
    )?;
    require(
        inventory(&root.join("recipient-mesh"))?
            == damaged_before.ok_or("incoming damaged inventory absent")?,
        "incoming fatal open changed damaged retained material",
    )?;
    require(
        !STOP.load(Ordering::Acquire),
        "incoming guard left STOP set",
    )?;
    source_cold(&f, false, false)?;
    native_zero_cold(root, &f, deadline)?;
    patch_record(
        record,
        json!({"fatal_error_preserved":true,"defer_then_fatal_preserved":true,"damaged_material_retained":true,"source_complete_frame_retained":true,"native_zero_cold_and_unchanged":true}),
    )?;
    drop(f.source_reserved);
    drop(f.listener);
    within(deadline)
}
fn incoming_candidate(case: IncomingCase) -> Result<()> {
    let started = monotonic()?;
    let deadline = started + case.seconds();
    let stop_deadline = deadline + 5.0;
    let root = io(fs::canonicalize(std::env::temp_dir()))?
        .join(format!("rld-incoming-mesh-retry-{}", random()?));
    match fs::symlink_metadata(&root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        _ => return Err("incoming retry root is not fresh or inspection refused".into()),
    }
    let root = directory(&root)?;
    let scope = json!({"format":INCOMING_FORMAT,"case":case.label(),"root":root,"pid":std::process::id(),"started":started,"deadline":deadline,"stop_deadline":stop_deadline,"regional_build_source_sha256":env!("RLD_REGIONAL_SOURCE"),"fixture_only":true,"socket_attempts":if case==IncomingCase::Guards{0}else{1},"incoming_retry_implemented":true,"packet_body_native_authority":false,"native_value_authority":false,"whole_payment_pass":false,"payment_qualified":false,"mainnet":false});
    incoming_metadata(&root.join("scope.json"), &scope)?;
    eprintln!("incoming_mesh_candidate_scope={}", scope);
    let mut record = Value::Object(
        RESULT_KEYS
            .split_ascii_whitespace()
            .map(|key| (key.to_owned(), Value::Null))
            .collect(),
    );
    patch_record(
        &mut record,
        json!({"format":INCOMING_FORMAT,"case":case.label(),"root":root,"pid":std::process::id(),"passed":false,"started":started,"deadline":deadline,"stop_deadline":stop_deadline,"regional_build_source_sha256":env!("RLD_REGIONAL_SOURCE"),"selected_bad_bundle":case==IncomingCase::BadBody,"packet_body_native_authority":false,"native_value_authority":false,"whole_payment_pass":false,"payment_qualified":false,"mainnet":false}),
    )?;
    let result = (|| -> Result<()> {
        if case == IncomingCase::Guards {
            run_guards(&root, deadline, &mut record)?;
        } else {
            run_tls(&root, deadline, case, &mut record)?;
        }
        within(deadline)?;
        let executable = io(std::env::current_exe())?;
        let test_raw = io(fs::read(executable))?;
        let ended = monotonic()?;
        require(
            ended < deadline,
            "incoming whole scope exceeded original deadline",
        )?;
        patch_record(
            &mut record,
            json!({"passed":true,"ended":ended,"elapsed_seconds":ended-started,"test_binary_sha256":sha(&test_raw)}),
        )
    })();
    if result.is_err() {
        let ended = monotonic().ok();
        patch_record(
            &mut record,
            json!({"ended":ended,"elapsed_seconds":ended.map(|end|end-started)}),
        )?;
    }
    require(
        record.as_object().is_some_and(|value| value.len() == 64),
        "incoming result exact64 schema",
    )?;
    let failure_write = match &result {
        Err(error) => {
            incoming_metadata(&root.join("private-failure.json"), &json!({"error":error}))
        }
        Ok(()) => Ok(()),
    };
    let outcome_write = incoming_metadata(&root.join("outcome.json"), &record);
    eprintln!("incoming_mesh_candidate_result={}", record);
    // The primary error wins; no fixture is deleted or normalized after failure.
    result?;
    failure_write?;
    outcome_write
}
#[test]
#[ignore = "incoming actual fatal and STOP guards; original10 normal exit,15 stop only"]
fn incoming_mesh_preserves_preopen_stop_expiry_and_fatal_errors() -> Result<()> {
    incoming_candidate(IncomingCase::Guards)
}
#[test]
#[ignore = "incoming custody actual None then release; original30 normal exit,35 stop only"]
fn incoming_custody_retries_actual_mesh_defer_under_original_request() -> Result<()> {
    incoming_candidate(IncomingCase::CustodyRelease)
}
#[test]
#[ignore = "incoming custody held until original deadline; original30 normal exit,35 stop only"]
fn incoming_custody_refuses_mesh_held_to_original_deadline() -> Result<()> {
    incoming_candidate(IncomingCase::CustodyExpiry)
}
#[test]
#[ignore = "incoming challenge actual None then release; original30 normal exit,35 stop only"]
fn incoming_challenge_retries_actual_mesh_defer_before_original_deadline() -> Result<()> {
    incoming_candidate(IncomingCase::ChallengeRelease)
}
#[test]
#[ignore = "incoming challenge held until original deadline; original30 normal exit,35 stop only"]
fn incoming_challenge_refuses_mesh_held_to_original_deadline() -> Result<()> {
    incoming_candidate(IncomingCase::ChallengeExpiry)
}
#[test]
#[ignore = "incoming bad first transit after actual custody None; original30 normal exit,35 stop only"]
fn incoming_custody_refuses_bad_first_transit_after_actual_defer() -> Result<()> {
    incoming_candidate(IncomingCase::BadBody)
}
