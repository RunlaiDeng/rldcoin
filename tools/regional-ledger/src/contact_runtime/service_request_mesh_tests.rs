//! A fresh transport counterexample at the ordinary request-binding boundary.
//! One fresh request-binding refusal, no retry implementation or value qualification.
//! Run the exact ignored selector once with an external original 30 s / stop 35 s controller.
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::collections::BTreeMap;
use std::sync::{atomic::AtomicU64, Arc};
use std::thread::JoinHandle;

const FORMAT: &str = "RLD-REQUEST-HELD-MESH-BASELINE-V1";
fn io<T>(value: std::io::Result<T>) -> Result<T> {
    value.map_err(|error| error.to_string())
}
fn within(deadline: f64) -> Result<()> {
    require(
        monotonic()? < deadline,
        "original request-baseline scope exhausted",
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
            require(!meta.file_type().is_symlink(), "baseline inventory symlink")?;
            if meta.is_dir() {
                visit(base, &path, out)?;
            } else {
                require(
                    meta.is_file() && meta.len() <= 8 * 1024 * 1024,
                    "baseline file bound",
                )?;
                let raw = io(fs::read(&path))?;
                out.insert(
                    path.strip_prefix(base)
                        .map_err(|e| e.to_string())?
                        .to_owned(),
                    (meta.len(), sha(&raw)),
                );
                require(out.len() <= 4096, "baseline inventory count bound")?;
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
            .ok_or("baseline peer already joined")?
            .join()
            .map_err(|_| "baseline peer panicked".to_string())?
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
    } = pins;
    let node = Node::open(&recipient_config)?;
    let id = node.id.clone();
    drop(node);
    let context = tls(json!({"Context":{"root":recipient_config["state"],
        "network":currency,"peer":id}}))?;
    let context = Context(context["handle"].as_u64().ok_or("baseline TLS context")?);
    let stream = loop {
        within(scope_deadline)?;
        require(!stop.load(Ordering::Acquire), "baseline peer cancelled")?;
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5))
            }
            Err(error) => return Err(error.to_string()),
        }
    };
    let eof_socket = io(stream.try_clone())?;
    let accepted_at = monotonic()?;
    let deadline = (accepted_at + 3.0).min(scope_deadline);
    let handle = tls(json!({"Accept":{"context":context.0,
        "fd":stream.as_raw_fd(),"deadline":deadline}}))?
    .as_u64()
    .ok_or("baseline accepted TLS handle")?;
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
    // This deliberate TEST-owned source lease stays held until client closure.
    // It is never a production Native/recipient lease or a liveness example.
    let receive_error = match recv(handle, deadline) {
        Ok(_) => return Err("baseline unexpectedly received a request".into()),
        Err(error) => error,
    };
    let peer_refusal_at = monotonic()?;
    // Distinguish actual EOF from merely waiting until timeout: native Receive
    // maps UnexpectedEof into TLS_IO, while WouldBlock/TimedOut are TLS_TIMEOUT.
    require(
        receive_error.starts_with("TLS_IO:"),
        "baseline peer did not observe I/O closure",
    )?;
    require(
        peer_refusal_at < deadline,
        "baseline peer reached its socket deadline",
    )?;
    io(eof_socket.set_read_timeout(Some(Duration::from_secs_f64(deadline - peer_refusal_at))))?;
    let mut probe = [0u8; 1];
    require(
        io(eof_socket.peek(&mut probe))? == 0,
        "baseline peer did not observe TCP EOF",
    )?;
    drop(eof_socket);
    drop(held);
    let released_at = monotonic()?;
    retained_handle.store(0, Ordering::Release);
    drop(connection);
    drop(context);
    Ok(
        json!({"accepted_at":accepted_at,"server_deadline":deadline,"mesh_held_at":held_at,
        "challenge_id":challenge_id,"challenge_sent_at":challenge_sent_at,
        "peer_refusal_at":peer_refusal_at,"mesh_released_at":released_at,
        "peer_receive_error":receive_error,"request_received":false,
        "custody_received":false,"peer_joined":true}),
    )
}

fn run(root: &Path, started: f64, deadline: f64) -> Result<Value> {
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
        "baseline genesis is not zero-issued",
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
            "public-no-value-held-request-baseline",
        )?;
        ids.push(
            identity["node_id"]
                .as_str()
                .ok_or("baseline identity")?
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
        .ok_or("baseline cursor")?;
    let recipient_before = inventory(&root.join("recipient-mesh"))?;
    within(deadline)?;

    let guard = carriage_observation::start(
        true,
        &root.join("source-mesh"),
        &random()?,
        currency,
        region,
        &ids[0],
    )?
    .ok_or("baseline observer absent")?;
    let sink = match guard.sink() {
        Some(sink) => sink,
        None => {
            let _ = guard.finish(false);
            return Err("baseline observer sink absent".into());
        }
    };
    let stop = Arc::new(AtomicBool::new(false));
    let handle = Arc::new(AtomicU64::new(0));
    let peer_stop = stop.clone();
    let peer_handle = handle.clone();
    let peer_config = configs[1].clone();
    let fingerprint = materials[1]["fingerprint"].clone();
    let source_root = root.join("source-mesh");
    let worker = match thread::Builder::new()
        .name("request baseline peer".into())
        .spawn(move || {
            controlled_peer(
                listener,
                PeerPins {
                    source_root,
                    recipient_config: peer_config,
                    currency,
                    fingerprint,
                    scope_deadline: deadline,
                },
                peer_stop,
                peer_handle,
            )
        }) {
        Ok(worker) => worker,
        Err(error) => {
            drop(sink);
            let _ = guard.finish(false);
            return Err(format!("baseline peer spawn refused: {error}"));
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
    let typed_refusal = [libc::EWOULDBLOCK, libc::EAGAIN]
        .iter()
        .any(|code| error.starts_with(&format!("CONTACT_STORAGE_IO:{code}:")));
    if !typed_refusal {
        // Both owned cleanup operations ran before retaining the first error.
        return Err(format!(
            "baseline primary outgoing refusal: {error}; peer_cleanup={}; observer_cleanup={}",
            peer_result.is_ok(),
            observer_result.is_ok()
        ));
    }
    let peer_report = peer_result?;
    observer_result?;
    let dispatch_at = dispatch_clock?;
    let returned_at = returned_clock?;
    within(deadline)?;

    let events_raw = io(fs::read(
        root.join("source-mesh/carriage-boundary-events.jsonl"),
    ))?;
    require(
        events_raw.len() <= 8 * 1024 * 1024,
        "baseline event bytes bound",
    )?;
    let rows = events_raw
        .split(|byte| *byte == b'\n')
        .filter(|row| !row.is_empty())
        .map(|row| crate::wallet_http::decode_unique_with_limit(row, 16 * 1024))
        .collect::<Result<Vec<_>>>()?;
    let expected = [
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
        "attempt-completed",
    ];
    require(rows.len() == expected.len(), "baseline phase count")?;
    for (i, (row, phase)) in rows.iter().zip(expected).enumerate() {
        require(
            row["phase"] == phase
                && row["lane"] == "outgoing"
                && row["attempt_id"] == 1
                && row["attempt_sequence"] == i + 1,
            "baseline exact one-attempt phase sequence",
        )?;
    }
    require(
        rows[4]["detail"]["packet_ids"] == json!([packet_id])
            && rows[4]["detail"]["frame_ids"] == json!([frame.message_id.to_hex()])
            && rows[9]["detail"]["challenge_id"] == peer_report["challenge_id"]
            && rows[11]["detail"]["result"] == "error"
            && rows[11]["detail"]["error_tag"] == "CONTACT_STORAGE_IO"
            && rows[11]["detail"]["lock_contention"] == true,
        "baseline packet/challenge/refusal binding",
    )?;
    let prepared_at = rows[4]["observed_at"]
        .as_f64()
        .ok_or("baseline prepared clock")?;
    let request_open_at = rows[10]["observed_at"]
        .as_f64()
        .ok_or("baseline request clock")?;
    let remaining_lower_bound = 3.0 - (request_open_at - prepared_at);
    require(
        remaining_lower_bound > 0.0
            && prepared_at
                <= peer_report["mesh_held_at"]
                    .as_f64()
                    .ok_or("baseline hold clock")?
            && peer_report["mesh_held_at"]
                .as_f64()
                .ok_or("baseline hold clock")?
                <= peer_report["challenge_sent_at"]
                    .as_f64()
                    .ok_or("baseline challenge send clock")?
            && peer_report["mesh_held_at"]
                .as_f64()
                .ok_or("baseline hold clock")?
                <= request_open_at
            && request_open_at
                <= peer_report["mesh_released_at"]
                    .as_f64()
                    .ok_or("baseline release clock")?,
        "baseline collision not inside original socket budget and held lease",
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
        "baseline diagnostic closure",
    )?;

    // These are planned live-scope checks of the newly created expected-refusal
    // component, never reopening an older stopped failed qualification fixture.
    let source_after_raw = io(fs::read(&state_path))?;
    drop(Node::open(&configs[0])?); // Full ordinary transport authentication.
    require(
        io(fs::read(&state_path))? == source_after_raw,
        "baseline cold source rewrote evidence",
    )?;
    let source_after = state_image(&source_after_raw, currency, &ids[0])?;
    require(
        source_after["state"]["cursor"] == cursor_before + 1
            && source_after["state"]["messages"].get(&packet_id).is_some()
            && source_after["frames"]
                .as_object()
                .ok_or("baseline retained frames")?
                .values()
                .any(|value| value["frame"] == STANDARD.encode(&frame_raw)),
        "baseline re-prepared cursor or lost complete original frame",
    )?;
    drop(Node::open(&configs[1])?);
    require(
        inventory(&root.join("recipient-mesh"))? == recipient_before,
        "baseline recipient retained request/custody",
    )?;
    require(
        inventory(&root.join("ledger"))? == native_before,
        "baseline changed signed zero-issued Native genesis",
    )?;
    drop(source_reserved);
    within(deadline)?;
    let test_binary_sha256 = sha(&io(fs::read(io(std::env::current_exe())?))?);
    within(deadline)?;
    let ended = monotonic()?;
    let mut result = json!({"format":FORMAT,"root":root,"pid":std::process::id(),"passed":true,
        "started":started,"deadline":deadline,"ended":ended,
        "elapsed_seconds":ended-started,"dispatch_at":dispatch_at,"returned_at":returned_at,
        "currency":currency,"region":region,"native_head":native_head,"ledger_root":ledger_root,
        "native_genesis_unchanged":true,"minted":0,"packet_id":packet_id,
        "frame_id":frame.message_id,"events_sha256":sha(&events_raw),"cursor_before":cursor_before,
        "cursor_after":cursor_before+1,"prepared_at":prepared_at,"request_open_at":request_open_at,
        "original_remaining_seconds_lower_bound":remaining_lower_bound,"operation_error":error});
    let checks = json!({"peer":peer_report,"production_request_retry":false,"complete_transport_frame_retained":true,
        "transport_payload_native_authority":false,"request_signed":false,"request_sent":false,
        "custody_received":false,"c1_qc":false,"payment_qualified":false,"mainnet":false,
        "source_locked_before_challenge_send":true,"typed_mesh_acquisition_refusal":true,
        "verified_challenge_seen":true,"request_send_absent":true,"peer_request_absent":true,
        "peer_joined":true,"observer_complete":true,"source_frame_retained":true,
        "native_genesis_zero_and_unchanged":true,"no_reprepare":true,
        "test_binary_sha256":test_binary_sha256,
        "regional_build_source_sha256":env!("RLD_REGIONAL_SOURCE")});
    result
        .as_object_mut()
        .ok_or("baseline result object")?
        .extend(checks.as_object().ok_or("baseline checks object")?.clone());
    Ok(result)
}

#[test]
#[ignore = "one fresh original30 request-binding refusal; external stopped seal by35"]
fn request_binding_refuses_held_mesh_after_verified_challenge() -> Result<()> {
    let started = monotonic()?;
    let deadline = started + 30.0;
    let root = io(fs::canonicalize(std::env::temp_dir()))?
        .join(format!("rld-request-held-mesh-baseline-{}", random()?));
    match fs::symlink_metadata(&root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        _ => return Err("baseline root not fresh or inspection refused".into()),
    }
    let root = directory(&root)?;
    let scope = json!({"format":FORMAT,"root":root,"started":started,
        "deadline":deadline,"stop_deadline":started+35.0,"pid":std::process::id(),
        "regional_build_source_sha256":env!("RLD_REGIONAL_SOURCE"),
        "fixture_only":true,"request_retry_implemented":false,
        "whole_payment_pass":false,"payment_qualified":false,"mainnet":false});
    new_json(&root.join("scope.json"), &scope)?;
    eprintln!("request_mesh_baseline_scope={}", scope);
    let result = run(&root, started, deadline);
    let outcome = match &result {
        Ok(value) => value.clone(),
        Err(error) => json!({"format":FORMAT,"root":root,"pid":std::process::id(),
            "passed":false,"started":started,"deadline":deadline,"ended":monotonic().ok(),
            "regional_build_source_sha256":env!("RLD_REGIONAL_SOURCE"),
            "error_tag":if error.starts_with("CONTACT_STORAGE_IO:") {"CONTACT_STORAGE_IO"} else {"BASELINE_REFUSED"},
            "source_locked_before_challenge_send":null,"typed_mesh_acquisition_refusal":null,
            "verified_challenge_seen":null,"request_send_absent":null,"peer_request_absent":null,
            "peer_joined":null,"observer_complete":null,"source_frame_retained":null,
            "native_genesis_zero_and_unchanged":null,"no_reprepare":null,
            "whole_payment_pass":false,"payment_qualified":false,"mainnet":false}),
    };
    let failure_write = match &result {
        Err(error) => new_json(&root.join("private-failure.json"), &json!({"error":error})),
        Ok(_) => Ok(()),
    };
    let outcome_write = new_json(&root.join("outcome.json"), &outcome);
    eprintln!("request_mesh_baseline_result={}", outcome);
    // Keep the primary experiment error even if later evidence persistence fails.
    // Keep every fixture private for root's external stopped seal.
    result?;
    failure_write?;
    outcome_write
}
