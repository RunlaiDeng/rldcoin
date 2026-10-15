//! Fresh transport-only request deferral and refusal checks.
//! The original three-second connection deadline is never extended.
//! Each TLS case requires normal completion within30 seconds;35 is stop only.
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::collections::BTreeMap;
use std::sync::{atomic::AtomicU64, Arc};
use std::thread::JoinHandle;

const FORMAT: &str = "RLD-REQUEST-MESH-RETRY-CANDIDATE-V1";
#[derive(Clone, Copy, PartialEq, Eq)]
enum RequestCase {
    ReleaseAfterDefer,
    HoldUntilExpiry,
}
impl RequestCase {
    fn label(self) -> &'static str {
        match self {
            Self::ReleaseAfterDefer => "release-after-real-defer",
            Self::HoldUntilExpiry => "held-to-original-expiry",
        }
    }
    fn release(self) -> bool {
        self == Self::ReleaseAfterDefer
    }
}
struct DeferObserverReset;
impl Drop for DeferObserverReset {
    fn drop(&mut self) {
        REQUEST_MESH_DEFER_OBSERVER.with(|slot| {
            slot.borrow_mut().take();
        });
        REQUEST_MESH_PREPARED_SHA.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}
fn install_defer_observer() -> Result<(DeferObserverReset, std::sync::mpsc::Receiver<(f64, f64)>)> {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    REQUEST_MESH_DEFER_OBSERVER.with(|slot| -> Result<()> {
        require(
            slot.borrow().is_none(),
            "request defer observer already installed",
        )?;
        *slot.borrow_mut() = Some(sender);
        Ok(())
    })?;
    REQUEST_MESH_PREPARED_SHA.with(|slot| {
        slot.borrow_mut().take();
    });
    Ok((DeferObserverReset, receiver))
}
fn io<T>(value: std::io::Result<T>) -> Result<T> {
    value.map_err(|error| error.to_string())
}
fn within(deadline: f64) -> Result<()> {
    require(
        monotonic()? < deadline,
        "original request fixture scope exhausted",
    )
}
fn sha(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
}
fn inventory(root: &Path) -> Result<BTreeMap<PathBuf, (u64, String)>> {
    fn visit(base: &Path, path: &Path, out: &mut BTreeMap<PathBuf, (u64, String)>) -> Result<()> {
        for entry in io(fs::read_dir(path))? {
            let path = io(entry)?.path();
            let meta = io(fs::symlink_metadata(&path))?;
            require(
                !meta.file_type().is_symlink(),
                "request fixture inventory symlink",
            )?;
            if meta.is_dir() {
                visit(base, &path, out)?;
            } else {
                require(
                    meta.is_file() && meta.len() <= 8 * 1024 * 1024,
                    "request fixture file bound",
                )?;
                let raw = io(fs::read(&path))?;
                out.insert(
                    path.strip_prefix(base)
                        .map_err(|e| e.to_string())?
                        .to_owned(),
                    (meta.len(), sha(&raw)),
                );
                require(out.len() <= 4096, "request fixture inventory count bound")?;
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out)?;
    Ok(out)
}
// The disk wrapper is a bounded codec image, never a decoded ledger or authority.
// Full ordinary Node authentication still surrounds the retained-image checks.
fn state_image(raw: &[u8], network: Hash, node_id: &str) -> Result<Value> {
    let checked = crate::contact_state_codec::execute(
        &bytes(&json!({"Decode":{
        "network":network,"node_id":node_id,"limits":{
            "max_state":32 * 1024 * 1024,"max_messages":256,"max_transit":EXCHANGE_LIMIT},
        "size_bytes":raw.len(),"sha256":sha(raw)}}))?,
        raw,
    )?;
    Ok(checked["image"].clone())
}
fn new_json(path: &Path, value: &Value) -> Result<()> {
    crate::keystore::private_create(path, &crate::wallet_client::canonical(value)?)
}

// Every early return cancels the accept loop, interrupts only this owned TLS
// handle and joins the controlled peer. No detached fixture thread remains.
struct Peer {
    stop: Arc<AtomicBool>,
    handle: Arc<AtomicU64>,
    worker: Option<JoinHandle<Result<Value>>>,
}
impl Peer {
    fn join(&mut self) -> Result<Value> {
        self.worker
            .take()
            .ok_or("request fixture peer already joined")?
            .join()
            .map_err(|_| "request fixture peer panicked".to_string())?
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let handle = self.handle.load(Ordering::Acquire);
        if handle != 0 {
            crate::contact_tls::interrupt(handle);
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
struct PeerPins {
    source_root: PathBuf,
    recipient_config: Value,
    currency: Hash,
    fingerprint: Value,
    scope_deadline: f64,
    scenario: RequestCase,
    source_id: String,
    deferred: std::sync::mpsc::Receiver<(f64, f64)>,
}
fn controlled_peer(
    listener: TcpListener,
    pins: PeerPins,
    stop: Arc<AtomicBool>,
    retained_handle: Arc<AtomicU64>,
) -> Result<Value> {
    let PeerPins {
        source_root,
        recipient_config,
        currency,
        fingerprint,
        scope_deadline,
        scenario,
        source_id,
        deferred,
    } = pins;
    let node = Node::open(&recipient_config)?;
    let id = node.id.clone();
    drop(node);
    let context = tls(json!({"Context":{"root":recipient_config["state"],
        "network":currency,"peer":id}}))?;
    let context = Context(
        context["handle"]
            .as_u64()
            .ok_or("request fixture TLS context")?,
    );
    let stream = loop {
        within(scope_deadline)?;
        require(
            !stop.load(Ordering::Acquire),
            "request fixture peer cancelled",
        )?;
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5))
            }
            Err(error) => return Err(error.to_string()),
        }
    };
    let accepted_at = monotonic()?;
    let deadline = (accepted_at + 3.0).min(scope_deadline);
    let handle = tls(json!({"Accept":{"context":context.0,
        "fd":stream.as_raw_fd(),"deadline":deadline}}))?
    .as_u64()
    .ok_or("request fixture accepted TLS handle")?;
    let connection = Connection(handle);
    retained_handle.store(handle, Ordering::Release);
    drop(stream);
    // Accept retains ServerConnection only. The first send below performs the
    // actual handshake. Client Connect starts only after its durable prepare.
    let held = Lease::acquire(&source_root, "Mesh")?;
    let held_at = monotonic()?;
    let challenge = {
        let node = Node::open(&recipient_config)?;
        node.sign(
            "tcp-challenge",
            json!({"format":MESH,"adapter":"RLD-CONTACT-TCP-V4",
            "network":currency,"node_id":id,"nonce":random()?,
            "tls_cert_sha256":fingerprint}),
        )?
    }; // Recipient Node lease is released before socket handshake/send.
    let challenge_id = challenge["body"]["nonce"].clone();
    send(handle, deadline, challenge)?;
    let challenge_sent_at = monotonic()?;
    // Only a real production Ok(None) can notify this capacity-one channel.
    let remaining = deadline.min(scope_deadline) - monotonic()?;
    require(remaining > 0.0, "peer deadline before actual Mesh defer")?;
    let (original_deadline, actual_defer_at) = deferred
        .recv_timeout(Duration::from_secs_f64(remaining))
        .map_err(|_| "peer missing actual Mesh defer notification".to_string())?;
    let defer_seen_at = monotonic()?;
    require(
        original_deadline.is_finite()
            && actual_defer_at >= held_at
            && actual_defer_at <= defer_seen_at
            && actual_defer_at < original_deadline
            && original_deadline <= deadline,
        "actual defer original clock binding",
    )?;
    // Every value is scalar or null. No nested packet inventory.
    let mut report = json!({"accepted_at":accepted_at,"server_deadline":deadline,
        "mesh_held_at":held_at,"challenge_id":challenge_id,"challenge_sent_at":challenge_sent_at,
        "actual_defer_at":actual_defer_at,"defer_seen_at":defer_seen_at,
        "original_socket_deadline":original_deadline,"mesh_release_started_at":null,"mesh_released_at":null,
        "request_received_at":null,"request_verified_at":null,"peer_refusal_at":null,"peer_receive_error":null,
        "request_received":false,"custody_received":false,"peer_joined":true,
        "packet_id":null,"frame_id":null,"received_bundle_sha256":null,"request_sha256":null});
    if scenario.release() {
        report["mesh_release_started_at"] = json!(monotonic()?);
        drop(held); // Only the test-owned source Mesh lease; no Node crosses IO.
        report["mesh_released_at"] = json!(monotonic()?);
        let request = recv(handle, deadline)?;
        let received_at = monotonic()?;
        require(
            received_at < original_deadline,
            "request arrived after original deadline",
        )?;
        let checked = crypto(json!({"Exchange":{"TcpRequest":{
            "network":currency,"signed":request,"recipient":id,"peers":[source_id],
            "nonce":challenge_id,"limits":limits()}}}))?;
        let verified_at = monotonic()?;
        require(
            verified_at < original_deadline,
            "request authenticated after original deadline",
        )?;
        let packets = carriage_packets(&checked["body"]["bundle"])?;
        let packet_ids = packets["packet_ids"]
            .as_array()
            .ok_or("request packet IDs")?;
        let frame_ids = packets["frame_ids"].as_array().ok_or("request frame IDs")?;
        require(
            packet_ids.len() == 1
                && frame_ids.len() == 1
                && packet_ids[0].is_string()
                && frame_ids[0].is_string()
                && checked["body"]["node_id"] == source_id
                && checked["body"]["network"] == json!(currency)
                && checked["body"]["challenge"] == challenge_id,
            "request exact source/challenge/single packet shape",
        )?;
        report["packet_id"] = packet_ids[0].clone();
        report["frame_id"] = frame_ids[0].clone();
        report["received_bundle_sha256"] = json!(sha(&bytes(&checked["body"]["bundle"])?));
        report["request_sha256"] = json!(sha(&bytes(&request)?));
        report["request_received_at"] = json!(received_at);
        report["request_verified_at"] = json!(verified_at);
        report["request_received"] = json!(true);
        // Close without Node::receive or accepted reply: no request custody.
    } else {
        let error = match recv(handle, deadline) {
            Ok(_) => return Err("expiry peer unexpectedly received request".into()),
            Err(error) => error,
        };
        let refused_at = monotonic()?;
        require(
            refused_at >= original_deadline,
            "source closed before original expiry",
        )?;
        require(
            error.starts_with("TLS_IO:") || error.starts_with("TLS_TIMEOUT:"),
            "expiry peer unexpected receive refusal",
        )?;
        report["mesh_release_started_at"] = json!(monotonic()?);
        drop(held);
        report["mesh_released_at"] = json!(monotonic()?);
        report["peer_refusal_at"] = json!(refused_at);
        report["peer_receive_error"] = json!(error);
        // Receive failure is not an EOF claim; server timeout is allowed here.
    }
    retained_handle.store(0, Ordering::Release);
    drop(connection);
    drop(context);
    Ok(report)
}

fn run(root: &Path, started: f64, deadline: f64, scenario: RequestCase) -> Result<Value> {
    // Different signed origin label gives this fresh fixture a distinct currency.
    // It uses public no-value bootstrap signers and never mines or submits value.
    let mut bootstrap = crate::tests::bootstrap();
    bootstrap.currency.origin = format!("request-{}", &random()?[..16]);
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
    let ledger = Store::create(
        &root.join("ledger"),
        bootstrap,
        region,
        &crate::tests::public(1),
        currency,
    )?;
    require(
        ledger.chain.height() == 0
            && ledger.chain.finalized.is_none()
            && ledger.chain.ledger.minted == crate::Amount::ZERO
            && ledger.chain.ledger.coins.is_empty()
            && ledger.chain.ledger.imports.is_empty()
            && ledger.chain.ledger.exports.is_empty(),
        "request fixture genesis is not zero-issued",
    )?;
    let native_head = ledger.storage_head()?;
    let ledger_root = ledger.chain.ledger.root()?;
    drop(ledger);
    let native_before = inventory(&root.join("ledger"))?;
    within(deadline)?;

    let listener = io(TcpListener::bind("127.0.0.1:0"))?;
    io(listener.set_nonblocking(true))?;
    let recipient_port = io(listener.local_addr())?.port();
    let source_reserved = io(TcpListener::bind("127.0.0.1:0"))?;
    let source_port = io(source_reserved.local_addr())?.port();
    let mut configs = Vec::new();
    let mut ids = Vec::new();
    let mut materials = Vec::new();
    for label in ["source-mesh", "recipient-mesh"] {
        let identity = initialize(
            &root.join(label),
            &currency.to_hex(),
            &region.to_hex(),
            "public-no-value-request-retry-candidate",
        )?;
        ids.push(
            identity["node_id"]
                .as_str()
                .ok_or("request fixture identity")?
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
    // Complete transport Frame shape only. Empty Submission/evidence is NOT a
    // Native ledger proof, consensus envelope, owner request or value authority.
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
    let state_path = root.join("source-mesh/native-mesh-state.json");
    let source_before_raw = files::private_read_with_limit(&state_path, 32 * 1024 * 1024)?;
    let source_before = state_image(&source_before_raw, currency, &ids[0])?;
    let cursor_before = source_before["state"]["cursor"]
        .as_u64()
        .ok_or("request fixture cursor")?;
    let recipient_before = inventory(&root.join("recipient-mesh"))?;
    within(deadline)?;
    let (_defer_reset, deferred) = install_defer_observer()?;

    let guard = carriage_observation::start(
        true,
        &root.join("source-mesh"),
        &random()?,
        currency,
        region,
        &ids[0],
    )?
    .ok_or("request fixture observer absent")?;
    let sink = match guard.sink() {
        Some(sink) => sink,
        None => {
            let _ = guard.finish(false);
            return Err("request fixture observer sink absent".into());
        }
    };
    let stop = Arc::new(AtomicBool::new(false));
    let handle = Arc::new(AtomicU64::new(0));
    let peer_stop = stop.clone();
    let peer_handle = handle.clone();
    let peer_config = configs[1].clone();
    let fingerprint = materials[1]["fingerprint"].clone();
    let source_root = root.join("source-mesh");
    let source_id = ids[0].clone();
    let worker = match thread::Builder::new()
        .name("request fixture peer".into())
        .spawn(move || {
            controlled_peer(
                listener,
                PeerPins {
                    source_root,
                    recipient_config: peer_config,
                    currency,
                    fingerprint,
                    scope_deadline: deadline,
                    scenario,
                    source_id,
                    deferred,
                },
                peer_stop,
                peer_handle,
            )
        }) {
        Ok(worker) => worker,
        Err(error) => {
            drop(sink);
            let _ = guard.finish(false);
            return Err(format!("request fixture peer spawn refused: {error}"));
        }
    };
    let mut peer = Peer {
        stop,
        handle,
        worker: Some(worker),
    };
    let dispatch_clock = monotonic();
    // Exact production outgoing implementation, with its existing diagnostic
    // sink. It prepares once and owns one original three-second connection.
    let outgoing_result = match &dispatch_clock {
        Ok(_) => outgoing_observed(
            &configs[0],
            &ids[1],
            &configs[0]["contacts"][0],
            Some(&sink),
        ),
        Err(error) => Err(error.clone()),
    };
    let returned_clock = monotonic();
    peer.stop.store(true, Ordering::Release);
    let peer_result = peer.join();
    drop(sink);
    // A failed operation is an expected observation, never a successful exchange.
    // Collector true footer below qualifies only complete closed diagnostic bytes.
    let observer_result = guard.finish(true);
    let error = outgoing_result
        .err()
        .unwrap_or_else(|| "UNEXPECTED_OUTGOING_SUCCESS".into());
    let expected_error_tag = if scenario.release() {
        "TLS_IO"
    } else {
        "TLS_TIMEOUT"
    };
    if !error.starts_with(&format!("{expected_error_tag}:")) {
        // Both owned cleanup operations ran before retaining the first error.
        return Err(format!(
            "request fixture primary outgoing refusal: {error}; peer_cleanup={}; observer_cleanup={}",
            peer_result.is_ok(),
            observer_result.is_ok()
        ));
    }
    let peer_report = peer_result?;
    observer_result?;
    let dispatch_at = dispatch_clock?;
    let returned_at = returned_clock?;
    let prepared_bundle_sha256 = REQUEST_MESH_PREPARED_SHA
        .with(|slot| slot.borrow().clone())
        .ok_or("complete original prepared bundle observation absent")?;
    within(deadline)?;

    let events_raw = io(fs::read(
        root.join("source-mesh/carriage-boundary-events.jsonl"),
    ))?;
    require(
        events_raw.len() <= 8 * 1024 * 1024,
        "request fixture event bytes bound",
    )?;
    let rows = events_raw
        .split(|byte| *byte == b'\n')
        .filter(|row| !row.is_empty())
        .map(|row| crate::wallet_http::decode_unique_with_limit(row, 16 * 1024))
        .collect::<Result<Vec<_>>>()?;
    let mut expected = vec![
        "attempt-started",
        "prepare-open-started",
        "prepare-open-completed",
        "prepare-started",
        "prepare-completed",
        "connect-started",
        "connect-completed",
        "challenge-receive-started",
        "challenge-receive-completed",
        "challenge-verified",
        "request-open-started",
    ];
    if scenario.release() {
        expected.extend([
            "request-open-completed",
            "request-send-started",
            "request-send-completed",
            "reply-receive-started",
        ]);
    }
    expected.push("attempt-completed");
    require(rows.len() == expected.len(), "request fixture phase count")?;
    for (i, (row, phase)) in rows.iter().zip(expected).enumerate() {
        require(
            row["phase"] == phase
                && row["lane"] == "outgoing"
                && row["attempt_id"] == 1
                && row["attempt_sequence"] == i + 1,
            "request fixture exact one-attempt phase sequence",
        )?;
    }
    let terminal_index = rows.len() - 1;
    require(
        rows[4]["detail"]["packet_ids"] == json!([packet_id])
            && rows[4]["detail"]["frame_ids"] == json!([frame.message_id.to_hex()])
            && rows[9]["detail"]["challenge_id"] == peer_report["challenge_id"]
            && rows[terminal_index]["detail"]["result"] == "error"
            && rows[terminal_index]["detail"]["error_tag"] == expected_error_tag
            && rows[terminal_index]["detail"]["lock_contention"] == false,
        "request fixture packet/challenge/refusal binding",
    )?;
    let prepared_at = rows[4]["observed_at"]
        .as_f64()
        .ok_or("request fixture prepared clock")?;
    let request_open_at = rows[10]["observed_at"]
        .as_f64()
        .ok_or("request fixture request clock")?;
    let clock = |key: &str| {
        peer_report[key]
            .as_f64()
            .ok_or_else(|| format!("candidate peer clock {key}"))
    };
    require(
        request_open_at <= clock("actual_defer_at")?
            && clock("actual_defer_at")? <= clock("defer_seen_at")?
            && clock("defer_seen_at")? <= clock("mesh_release_started_at")?
            && clock("mesh_release_started_at")? <= clock("mesh_released_at")?
            && peer_report["custody_received"] == false
            && peer_report["peer_joined"] == true,
        "actual defer/release/no-custody ordering",
    )?;
    if scenario.release() {
        require(
            peer_report["request_received"] == true
                && peer_report["packet_id"] == packet_id
                && peer_report["frame_id"] == frame.message_id.to_hex()
                && peer_report["received_bundle_sha256"] == prepared_bundle_sha256
                && clock("mesh_release_started_at")?
                    <= rows[11]["observed_at"]
                        .as_f64()
                        .ok_or("request complete open clock")?
                && clock("request_received_at")? <= clock("request_verified_at")?
                && clock("request_verified_at")? < clock("original_socket_deadline")?,
            "released peer did not receive exact original complete request in time",
        )?;
    } else {
        require(
            peer_report["request_received"] == false
                && clock("mesh_release_started_at")? >= clock("original_socket_deadline")?
                && returned_at >= clock("original_socket_deadline")?,
            "held lease or source refusal did not reach original expiry",
        )?;
    }
    let remaining_lower_bound = 3.0 - (request_open_at - prepared_at);
    require(
        remaining_lower_bound > 0.0
            && prepared_at
                <= peer_report["mesh_held_at"]
                    .as_f64()
                    .ok_or("request fixture hold clock")?
            && peer_report["mesh_held_at"]
                .as_f64()
                .ok_or("request fixture hold clock")?
                <= peer_report["challenge_sent_at"]
                    .as_f64()
                    .ok_or("request fixture challenge send clock")?
            && peer_report["mesh_held_at"]
                .as_f64()
                .ok_or("request fixture hold clock")?
                <= request_open_at
            && request_open_at
                <= peer_report["mesh_released_at"]
                    .as_f64()
                    .ok_or("request fixture release clock")?,
        "request fixture collision not inside original socket budget and held lease",
    )?;
    let terminal = read(
        &root.join("source-mesh/carriage-boundary-terminal.json"),
        64 * 1024,
    )?;
    require(
        terminal["success"] == true
            && terminal["loss"] == 0
            && terminal["errors"] == 0
            && terminal["incomplete_attempts"] == 0
            && terminal["active_attempts"] == 0
            && terminal["remaining_sink_handles"] == 0
            && terminal["attempts_started"] == 1
            && terminal["events_sha256"] == sha(&events_raw),
        "request fixture diagnostic closure",
    )?;

    // These are planned live-scope checks of the newly created expected-refusal
    // component, never reopening an older stopped failed qualification fixture.
    let source_after_raw = io(fs::read(&state_path))?;
    drop(Node::open(&configs[0])?); // Full ordinary transport authentication.
    require(
        io(fs::read(&state_path))? == source_after_raw,
        "request fixture cold source rewrote evidence",
    )?;
    let source_after = state_image(&source_after_raw, currency, &ids[0])?;
    require(
        source_after["state"]["cursor"] == cursor_before + 1
            && source_after["state"]["messages"].get(&packet_id).is_some()
            && source_after["frames"]
                .as_object()
                .ok_or("request fixture retained frames")?
                .values()
                .any(|value| value["frame"] == STANDARD.encode(&frame_raw)),
        "request fixture re-prepared cursor or lost complete original frame",
    )?;
    drop(Node::open(&configs[1])?);
    require(
        inventory(&root.join("recipient-mesh"))? == recipient_before,
        "request fixture recipient retained request/custody",
    )?;
    require(
        inventory(&root.join("ledger"))? == native_before,
        "request fixture changed signed zero-issued Native genesis",
    )?;
    drop(source_reserved);
    within(deadline)?;
    let test_binary_sha256 = sha(&io(fs::read(io(std::env::current_exe())?))?);
    within(deadline)?;
    let ended = monotonic()?;
    // Fixed50 success keys: metadata25 + checks25, below macro recursion bound.
    let mut result = json!({"format":FORMAT,"case":scenario.label(),"root":root,"pid":std::process::id(),"passed":true,
        "started":started,"deadline":deadline,"ended":ended,
        "elapsed_seconds":ended-started,"dispatch_at":dispatch_at,"returned_at":returned_at,
        "currency":currency,"region":region,"native_head":native_head,"ledger_root":ledger_root,
        "packet_id":packet_id,
        "frame_id":frame.message_id,"events_sha256":sha(&events_raw),"cursor_before":cursor_before,
        "cursor_after":cursor_before+1,"prepared_at":prepared_at,"request_open_at":request_open_at,
        "original_remaining_seconds_lower_bound":remaining_lower_bound,"operation_error_tag":expected_error_tag,
        "peer":peer_report});
    let checks = json!({"production_request_retry":true,"native_value_authority":false,"complete_transport_frame_retained":true,
        "transport_payload_native_authority":false,"request_signed":scenario.release(),"request_sent":scenario.release(),
        "custody_received":false,"payment_qualified":false,"mainnet":false,
        "source_locked_before_challenge_send":true,"actual_mesh_defer_seen":true,
        "verified_challenge_seen":true,"request_send_absent":!scenario.release(),"peer_request_absent":!scenario.release(),
        "peer_joined":true,"observer_complete":true,"source_frame_retained":true,
        "native_genesis_zero_and_unchanged":true,"no_reprepare":true,
        "test_binary_sha256":test_binary_sha256,
        "regional_build_source_sha256":env!("RLD_REGIONAL_SOURCE"),
        "prepared_bundle_sha256":prepared_bundle_sha256,"whole_payment_pass":false,
        "source_id":ids[0],"recipient_id":ids[1]});
    result
        .as_object_mut()
        .ok_or("request fixture result object")?
        .extend(
            checks
                .as_object()
                .ok_or("request fixture checks object")?
                .clone(),
        );
    Ok(result)
}

fn run_candidate(scenario: RequestCase) -> Result<()> {
    let started = monotonic()?;
    let deadline = started + 30.0;
    let root = io(fs::canonicalize(std::env::temp_dir()))?
        .join(format!("rld-request-mesh-retry-candidate-{}", random()?));
    match fs::symlink_metadata(&root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        _ => return Err("request fixture root not fresh or inspection refused".into()),
    }
    let root = directory(&root)?;
    let scope = json!({"format":FORMAT,"case":scenario.label(),"root":root,"started":started,
        "deadline":deadline,"stop_deadline":started+35.0,"pid":std::process::id(),
        "regional_build_source_sha256":env!("RLD_REGIONAL_SOURCE"),
        "fixture_only":true,"request_retry_implemented":true,
        "whole_payment_pass":false,"payment_qualified":false,"mainnet":false});
    new_json(&root.join("scope.json"), &scope)?;
    eprintln!("request_mesh_candidate_scope={}", scope);
    let result = run(&root, started, deadline, scenario);
    let outcome = match &result {
        Ok(value) => value.clone(),
        Err(_) => failed_outcome(&root, started, deadline, scenario),
    };
    let failure_write = match &result {
        Err(error) => new_json(&root.join("private-failure.json"), &json!({"error":error})),
        Ok(_) => Ok(()),
    };
    let outcome_write = new_json(&root.join("outcome.json"), &outcome);
    eprintln!("request_mesh_candidate_result={}", outcome);
    // Keep the primary experiment error even if later evidence persistence fails.
    // Keep every fixture private for root's external stopped seal.
    result?;
    failure_write?;
    outcome_write
}

fn failed_outcome(root: &Path, started: f64, deadline: f64, scenario: RequestCase) -> Value {
    // Same50 keys as success; unknown observations remain null, never fabricated.
    let mut value = json!({"format":FORMAT,"case":scenario.label(),"root":root,
        "pid":std::process::id(),"passed":false,"started":started,"deadline":deadline,
        "ended":monotonic().ok(),"elapsed_seconds":null,"dispatch_at":null,"returned_at":null,
        "currency":null,"region":null,"native_head":null,"ledger_root":null,"packet_id":null,
        "frame_id":null,"events_sha256":null,"cursor_before":null,"cursor_after":null,
        "prepared_at":null,"request_open_at":null,"original_remaining_seconds_lower_bound":null,
        "operation_error_tag":"CANDIDATE_REFUSED","peer":null});
    let checks = json!({"production_request_retry":true,"native_value_authority":false,
        "complete_transport_frame_retained":null,"transport_payload_native_authority":false,
        "request_signed":null,"request_sent":null,"custody_received":null,
        "payment_qualified":false,"mainnet":false,"source_locked_before_challenge_send":null,
        "actual_mesh_defer_seen":null,"verified_challenge_seen":null,"request_send_absent":null,
        "peer_request_absent":null,"peer_joined":null,"observer_complete":null,
        "source_frame_retained":null,"native_genesis_zero_and_unchanged":null,"no_reprepare":null,
        "test_binary_sha256":null,"regional_build_source_sha256":env!("RLD_REGIONAL_SOURCE"),
        "prepared_bundle_sha256":null,"whole_payment_pass":false,"source_id":null,"recipient_id":null});
    if let (Some(value), Some(checks)) = (value.as_object_mut(), checks.as_object()) {
        value.extend(checks.clone());
    }
    value
}

#[test]
#[ignore = "actual Mesh defer then release; original30 normal exit,35 stop only"]
fn request_binding_retries_only_actual_mesh_defer_under_original_challenge() -> Result<()> {
    run_candidate(RequestCase::ReleaseAfterDefer)
}

#[test]
#[ignore = "Mesh held through original deadline; original30 normal exit,35 stop only"]
fn request_binding_refuses_mesh_held_until_original_deadline() -> Result<()> {
    run_candidate(RequestCase::HoldUntilExpiry)
}

// Isolated selector: STOP is process-global and must not race another Service.
#[test]
#[ignore = "fresh transport refusal guards; original10, external15 stop only"]
fn request_binding_preserves_preopen_deadline_stop_and_fatal_errors() -> Result<()> {
    fn refusal(result: Result<Node>) -> Result<String> {
        match result {
            Err(error) => Ok(error),
            Ok(_) => Err("request refusal guard unexpectedly opened a Node".into()),
        }
    }
    struct StopReset(bool);
    impl Drop for StopReset {
        fn drop(&mut self) {
            STOP.store(self.0, Ordering::Release);
        }
    }
    let started = monotonic()?;
    let deadline = started + 10.0;
    require(
        !STOP.load(Ordering::Acquire),
        "guard process already stopped",
    )?;
    // Invalid config cannot be inspected when an original deadline already refuses.
    for original in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, started - 1.0] {
        require(
            refusal(request_node_before_deadline(&Value::Null, original))?
                .starts_with("TLS_TIMEOUT:"),
            "expired/nonfinite original request deadline did not refuse before open",
        )?;
    }
    {
        let reset = StopReset(STOP.swap(true, Ordering::AcqRel));
        require(
            refusal(request_node_before_deadline(
                &Value::Null,
                monotonic()? + 3.0,
            ))? == "outgoing request binding cancelled; retain complete evidence",
            "STOP did not refuse before inspecting invalid configuration",
        )?;
        drop(reset);
    }
    within(deadline)?;
    let root = io(fs::canonicalize(std::env::temp_dir()))?
        .join(format!("rld-request-mesh-guards-{}", random()?));
    match fs::symlink_metadata(&root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        _ => return Err("request guards root is not fresh".into()),
    }
    let root = directory(&root)?;
    // This isolated transport identity carries no Native or ledger authority.
    let network = Hash(Sha256::digest(random()?.as_bytes()).into());
    let region = Hash(Sha256::digest(random()?.as_bytes()).into());
    initialize(
        &root,
        &network.to_hex(),
        &region.to_hex(),
        "public-no-value-request-refusal-guards",
    )?;
    let config = json!({"format":MESH,"network":network,"state":root,"contacts":[]});
    drop(Node::open(&config)?);
    let damaged = root.join("native-mesh-state.json");
    io(fs::write(
        &damaged,
        b"invalid retained Mesh state; preserve this failed fixture",
    ))?;
    let before = inventory(&root)?;
    let exact_fatal = match Node::open_or_defer_mesh(&config) {
        Err(error) => error,
        Ok(_) => return Err("corrupt complete Mesh open did not refuse".into()),
    };
    require(
        refusal(request_node_before_deadline(&config, monotonic()? + 3.0))? == exact_fatal,
        "request retry altered a complete-open fatal error",
    )?;
    require(
        inventory(&root)? == before,
        "fatal request open changed retained material",
    )?;
    within(deadline)?;
    eprintln!(
        "request_mesh_guards_result={}",
        json!({
        "root":root,"pid":std::process::id(),"started":started,"deadline":deadline,
        "ended":monotonic()?,"passed":true,"nonfinite_and_expired_preopen_refused":true,
        "stop_preopen_refused":true,"actual_corrupt_state_refused":true,
        "exact_fatal_error_preserved":true,"damaged_material_retained":true,
        "native_authority":false,"payment_qualified":false,"mainnet":false,
        "regional_build_source_sha256":env!("RLD_REGIONAL_SOURCE")})
    );
    Ok(())
}

#[cfg(test)]
#[path = "service_incoming_mesh_tests.rs"]
mod incoming_mesh_tests;
