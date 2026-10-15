//! Current production reply-custody refusal under a real source Mesh lease.
//! Transport envelope/custody evidence only; no Native consensus/value authority.
//! One original three-second socket attempt; normal whole30, external35 stop only.
use super::*;
use std::sync::mpsc;

const REPLY_FORMAT: &str = "RLD-REPLY-MESH-BASELINE-V1";
const OPT_IN: &str = "RLD_REPLY_MESH_BASELINE";
const RESULT_KEYS: &str = "format case root pid passed started deadline stop_deadline ended elapsed_seconds currency region source_id recipient_id native_head native_value_root source_packet_id source_frame_id reply_packet_id reply_frame_id test_binary_sha256 regional_build_source_sha256 prepared_bundle_sha256 request_sha256 response_sha256 reply_bundle_sha256 challenge_id exchange_id events_sha256 checked_metadata_sha256 dispatch_at outgoing_returned_at peer_accepted_at peer_deadline challenge_sent_at request_received_at request_verified_at peer_custody_completed_at reply_prepared_at source_mesh_held_at reply_sent_at source_mesh_release_started_at source_mesh_released_at prepared_at connect_started_at socket_deadline_lower_bound socket_deadline_upper_bound original_socket_deadline operation_error_tag exact_mesh_acquisition_refusal held_probe_typed_none peer_actual_custody_received reply_verified local_reply_receive_absent source_cursor_advanced_once original_frame_retained source_receipt_absent peer_suppression_unchanged reply_frame_absent native_zero_cold_unchanged peer_joined collector_joined normal_test_socket_shutdown all_original_clock_bounds_met transport_payload_native_authority native_value_authority whole_payment_pass payment_qualified mainnet request_mesh_defer_seen source_cursor_before source_cursor_after";

fn reply_patch(record: &mut Value, values: Value) -> Result<()> {
    let record = record.as_object_mut().ok_or("reply result object")?;
    for (key, value) in values.as_object().ok_or("reply patch object")? {
        require(record.contains_key(key), "reply result unknown key")?;
        record.insert(key.clone(), value.clone());
    }
    Ok(())
}
fn reply_metadata(path: &Path, value: &Value) -> Result<()> {
    require(
        crate::wallet_client::canonical(value)?.len() <= 64 * 1024,
        "reply scalar metadata bound",
    )?;
    new_json(path, value)
}
fn reply_clock(value: &Value, key: &str) -> Result<f64> {
    let at = value[key]
        .as_f64()
        .ok_or_else(|| format!("reply clock absent: {key}"))?;
    require(at.is_finite(), "reply clock nonfinite")?;
    Ok(at)
}
// Guard::drop alone does not join. Later-declared Peer always joins first.
struct ReplyCollector {
    guard: Option<carriage_observation::Guard>,
    sink: Option<carriage_observation::Sink>,
}
impl ReplyCollector {
    fn start(root: &Path, currency: Hash, region: Hash, id: &str) -> Result<Self> {
        let guard = carriage_observation::start(true, root, &random()?, currency, region, id)?
            .ok_or("reply observer absent")?;
        let sink = guard.sink();
        if sink.is_none() {
            let _ = guard.finish(false);
            return Err("reply observer sink absent".into());
        }
        Ok(Self {
            guard: Some(guard),
            sink,
        })
    }
    fn sink(&self) -> Result<&carriage_observation::Sink> {
        self.sink
            .as_ref()
            .ok_or("reply observer sink closed".into())
    }
    fn finish(&mut self, success: bool) -> Result<()> {
        self.sink.take();
        self.guard
            .take()
            .ok_or("reply collector joined twice")?
            .finish(success)
    }
}
impl Drop for ReplyCollector {
    fn drop(&mut self) {
        self.sink.take();
        if let Some(guard) = self.guard.take() {
            let _ = guard.finish(false);
        }
    }
}

struct ReplyFixture {
    configs: Vec<Value>,
    ids: Vec<String>,
    materials: Vec<Value>,
    currency: Hash,
    region: Hash,
    native_head: Hash,
    native_value: Hash,
    native_before: BTreeMap<PathBuf, (u64, String)>,
    source_frame: Vec<u8>,
    reply_frame: Vec<u8>,
    source_frame_id: Hash,
    reply_frame_id: Hash,
    source_packet: String,
    reply_packet: String,
    source_before: Value,
    source_cursor: u64,
    source_reserved: TcpListener,
    listener: Option<TcpListener>,
}
fn reply_frame(currency: Hash, region: Hash, origin: bool) -> Result<(Hash, Vec<u8>)> {
    // Both payloads are complete transport shapes. Neither empty Submission
    // is a Native consensus proof, owner request, payment or adoption authority.
    let mut payload = json!({"format":crate::bft_network::FORMAT,"currency":currency,
        "region":region,"evidence":{"snapshots":[]},"body":{"Submission":[]}});
    if origin {
        payload["format"] = json!(crate::bft_network::ORIGIN_FORMAT);
        payload["origins"] = json!([]);
    }
    let payload = bytes(&payload)?;
    let digest = Hash(Sha256::digest(&payload).into());
    let mut frame = crate::contact::Frame {
        format: crate::contact::FRAME_FORMAT.into(),
        kind: "regional-bft".into(),
        source_chain_id: region,
        destination_chain_id: region,
        export_id: digest,
        payload_sha256: digest,
        payload_b64: STANDARD.encode(payload),
        message_id: Hash::ZERO,
    };
    frame.message_id = frame.message()?;
    Ok((frame.message_id, frame.retained_bytes()?))
}
fn reply_fixture(root: &Path, deadline: f64) -> Result<ReplyFixture> {
    let mut bootstrap = crate::tests::bootstrap();
    bootstrap.currency.origin = format!("reply-{}", &random()?[..16]);
    bootstrap.currency.cap = crate::Amount::TOTAL_SUPPLY;
    bootstrap.currency.block_reward = rld_pow::subsidy(1).map_err(|e| e.to_string())?;
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
        "reply Native genesis not zero-issued",
    )?;
    let native_head = native.storage_head()?;
    let native_value = native.chain.ledger.root()?;
    drop(native);
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
            "public-no-value-reply-mesh-baseline",
        )?;
        ids.push(
            identity["node_id"]
                .as_str()
                .ok_or("reply identity")?
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
    let (source_frame_id, source_frame) = reply_frame(currency, region, false)?;
    let (reply_frame_id, reply_frame) = reply_frame(currency, region, true)?;
    require(
        source_frame_id != reply_frame_id,
        "reply frame must differ from source frame",
    )?;
    let source_packet = Node::open(&configs[0])?.enqueue(&source_frame, &ids[1])?;
    let reply_packet = Node::open(&configs[1])?.enqueue(&reply_frame, &ids[0])?;
    let raw = files::private_read_with_limit(
        &root.join("source-mesh/native-mesh-state.json"),
        32 * 1024 * 1024,
    )?;
    let source_before = state_image(&raw, currency, &ids[0])?;
    let source_cursor = source_before["state"]["cursor"]
        .as_u64()
        .ok_or("reply source cursor")?;
    for key in ["receipts", "archives", "peer_inventory"] {
        require(
            source_before["state"][key]
                .as_object()
                .is_some_and(|v| v.is_empty()),
            "reply fresh source already has receipt/archive/suppression",
        )?;
    }
    within(deadline)?;
    Ok(ReplyFixture {
        configs,
        ids,
        materials,
        currency,
        region,
        native_head,
        native_value,
        native_before,
        source_frame,
        reply_frame,
        source_frame_id,
        reply_frame_id,
        source_packet,
        reply_packet,
        source_before,
        source_cursor,
        source_reserved,
        listener: Some(listener),
    })
}
struct ReturnNotice {
    at: Result<f64>,
    error: Option<String>,
}
struct ReplyPins {
    root: PathBuf,
    source_config: Value,
    recipient_config: Value,
    source_id: String,
    recipient_id: String,
    fingerprint: Value,
    currency: Hash,
    source_packet: String,
    source_frame: Hash,
    reply_packet: String,
    reply_frame: Hash,
    scope_deadline: f64,
    returned: mpsc::Receiver<ReturnNotice>,
}
fn reply_peer(
    listener: TcpListener,
    pins: ReplyPins,
    stop: Arc<AtomicBool>,
    retained_handle: Arc<AtomicU64>,
) -> Result<Value> {
    let context = tls(json!({"Context":{"root":pins.recipient_config["state"],
        "network":pins.currency,"peer":pins.recipient_id}}))?;
    let context = Context(context["handle"].as_u64().ok_or("reply TLS context")?);
    // Entire Context owner is local to this worker through the operation and
    // explicit drop below; never capture just Copy context.0 from another thread.
    let operation = (|| {
        let stream = loop {
            within(pins.scope_deadline)?;
            require(!stop.load(Ordering::Acquire), "reply peer cancelled")?;
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(e) => return Err(e.to_string()),
            }
        };
        let accepted_at = monotonic()?;
        let deadline = (accepted_at + 3.0).min(pins.scope_deadline);
        let handle = tls(
            json!({"Accept":{"context":context.0,"fd":stream.as_raw_fd(),"deadline":deadline}}),
        )?
        .as_u64()
        .ok_or("reply TLS accepted handle")?;
        let connection = Connection(handle);
        retained_handle.store(handle, Ordering::Release);
        drop(stream);
        let challenge = {
            let node = Node::open(&pins.recipient_config)?;
            require(
                node.id == pins.recipient_id,
                "reply challenge identity changed",
            )?;
            node.sign(
                "tcp-challenge",
                json!({"format":MESH,"adapter":"RLD-CONTACT-TCP-V4",
                "network":pins.currency,"node_id":pins.recipient_id,"nonce":random()?,
                "tls_cert_sha256":pins.fingerprint}),
            )?
        };
        let challenge_id = challenge["body"]["nonce"].clone();
        within(deadline)?;
        send(handle, deadline, challenge)?;
        let challenge_sent_at = monotonic()?;
        let request = recv(handle, deadline)?;
        let request_received_at = monotonic()?;
        let checked = crypto(json!({"Exchange":{"TcpRequest":{"network":pins.currency,
            "signed":request,"recipient":pins.recipient_id,"peers":[pins.source_id],
            "nonce":challenge_id,"limits":limits()}}}))?;
        let request_verified_at = monotonic()?;
        within(deadline)?;
        let bundle = &checked["body"]["bundle"];
        let detail = carriage_packets(bundle)?;
        require(
            detail["packet_ids"] == json!([pins.source_packet])
                && detail["frame_ids"] == json!([pins.source_frame.to_hex()])
                && detail["destination_ids"] == json!([pins.recipient_id]),
            "reply peer did not authenticate exact original transport request",
        )?;
        let prepared_sha = sha(&bytes(bundle)?);
        let request_sha = sha(&bytes(&request)?);
        // Preserve complete authenticated wire evidence privately, never stdout.
        new_json(&pins.root.join("private-original-bundle.json"), bundle)?;
        new_json(&pins.root.join("private-request.json"), &request)?;
        let (response, custody_at, prepared_at, reply_bundle_sha) = {
            let mut node = Node::open(&pins.recipient_config)?;
            require(
                node.id == pins.recipient_id && node.network == pins.currency.to_hex(),
                "reply custody identity changed",
            )?;
            within(deadline)?;
            let retained = node.receive(bundle, &pins.source_id)?;
            let custody_at = monotonic()?;
            require(
                retained == vec![pins.source_packet.clone()],
                "reply actual durable source custody differs",
            )?;
            within(deadline)?;
            let reply = node.prepare(&pins.source_id)?;
            let prepared_at = monotonic()?;
            let packets = carriage_packets(&reply)?;
            require(
                packets["packet_ids"] == json!([pins.reply_packet])
                    && packets["frame_ids"] == json!([pins.reply_frame.to_hex()])
                    && packets["destination_ids"] == json!([pins.source_id]),
                "reply must carry exact queued reverse frame",
            )?;
            let receipts = reply["body"]["receipts"]
                .as_array()
                .ok_or("reply receipt list")?;
            require(
                receipts.len() == 1 && receipts[0]["body"]["packet_id"] == pins.source_packet,
                "reply must carry actual destination custody receipt",
            )?;
            let reply_bundle_sha = sha(&bytes(&reply)?);
            within(deadline)?;
            let response = node.sign(
                "tcp-response",
                json!({"format":MESH,"adapter":"RLD-CONTACT-TCP-V4",
                "network":pins.currency,"node_id":pins.recipient_id,"to":pins.source_id,
                "nonce":checked["body"]["nonce"],"challenge":checked["body"]["challenge"],
                "exchange_id":digest(bundle)?,"accepted":true,"bundle":reply,"error":null}),
            )?;
            within(deadline)?;
            (response, custody_at, prepared_at, reply_bundle_sha)
        }; // No peer Node/Native lease crosses socket IO or control wait.
        let response_sha = sha(&bytes(&response)?);
        new_json(&pins.root.join("private-response.json"), &response)?;
        let held = Lease::acquire(
            Path::new(
                pins.source_config["state"]
                    .as_str()
                    .ok_or("reply source root")?,
            ),
            "Mesh",
        )?;
        let held_at = monotonic()?;
        let expected = match Node::open(&pins.source_config) {
            Err(error) => error,
            Ok(_) => return Err("reply held source Mesh unexpectedly opened".into()),
        };
        require(
            [libc::EWOULDBLOCK, libc::EAGAIN]
                .iter()
                .any(|code| expected.starts_with(&format!("CONTACT_STORAGE_IO:{code}:"))),
            "reply probe not exact typed Mesh acquisition refusal",
        )?;
        require(
            Node::open_or_defer_mesh(&pins.source_config)?.is_none(),
            "reply held Mesh did not yield typed None",
        )?;
        within(deadline)?;
        send(handle, deadline, response.clone())?;
        let reply_sent_at = monotonic()?;
        let remaining = deadline - monotonic()?;
        require(
            remaining > 0.0,
            "reply notice original peer deadline exhausted",
        )?;
        let notice = pins
            .returned
            .recv_timeout(Duration::from_secs_f64(remaining))
            .map_err(|e| format!("reply source return notice absent: {e}"))?;
        let notice_at = monotonic()?;
        // Source's real operation error is retained before any missing clock
        // assertion, so instrumentation cannot mask an earlier protocol error.
        if notice.error.as_deref() != Some(expected.as_str()) {
            return Err(format!(
                "reply primary source result={:?}; exact_probe={expected}",
                notice.error
            ));
        }
        let returned_at = notice.at?;
        let release_started_at = monotonic()?;
        require(
            returned_at <= notice_at && notice_at <= release_started_at,
            "reply source lease released before actual outgoing return",
        )?;
        drop(held);
        let released_at = monotonic()?;
        let mut report = json!({"accepted_at":accepted_at,"peer_deadline":deadline,
            "challenge_sent_at":challenge_sent_at,"challenge_id":challenge_id,
            "request_received_at":request_received_at,"request_verified_at":request_verified_at,
            "custody_completed_at":custody_at,"reply_prepared_at":prepared_at,
            "mesh_held_at":held_at,"reply_sent_at":reply_sent_at,"source_returned_at":returned_at,
            "mesh_release_started_at":release_started_at,"mesh_released_at":released_at,
            "prepared_bundle_sha256":prepared_sha,"request_sha256":request_sha,
            "response_sha256":response_sha,"reply_bundle_sha256":reply_bundle_sha,
            "exchange_id":response["body"]["exchange_id"],"mesh_error_sha256":sha(expected.as_bytes()),
            "exact_mesh_acquisition_refusal":true,"held_probe_typed_none":true,
            "actual_custody_received":true,"normal_test_socket_shutdown":false});
        // No duplicate socket is retained and no test shutdown runs normally.
        // This connection closes only after the actual outgoing Mesh error.
        retained_handle.store(0, Ordering::Release);
        drop(connection);
        report["peer_operation_completed_at"] = json!(monotonic()?);
        report["format"] = json!(REPLY_FORMAT);
        report["root"] = json!(pins.root);
        report["pid"] = json!(std::process::id());
        reply_metadata(&pins.root.join("checked-metadata.json"), &report)?;
        Ok(report)
    })();
    retained_handle.store(0, Ordering::Release);
    drop(context); // Whole owner survives every successful/error operation path.
    operation
}

fn reply_native_zero(root: &Path, f: &ReplyFixture, deadline: f64) -> Result<()> {
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
        "reply zero Native changed",
    )?;
    drop(native);
    require(
        inventory(&root.join("ledger"))? == f.native_before,
        "reply Native retained bytes changed",
    )?;
    within(deadline)
}
fn reply_cold(root: &Path, f: &ReplyFixture) -> Result<()> {
    let source_path = root.join("source-mesh/native-mesh-state.json");
    let source_raw = files::private_read_with_limit(&source_path, 32 * 1024 * 1024)?;
    let source = Node::open(&f.configs[0])?;
    require(
        source.received_frames()?.is_empty(),
        "reply source received reverse frame despite refusal",
    )?;
    drop(source);
    require(
        files::private_read_with_limit(&source_path, 32 * 1024 * 1024)? == source_raw,
        "reply cold source rewrote retained bytes",
    )?;
    let source = state_image(&source_raw, f.currency, &f.ids[0])?;
    require(
        source["state"]["cursor"] == f.source_cursor + 1
            && source["state"]["messages"]
                .as_object()
                .is_some_and(|m| m.len() == 1 && m.contains_key(&f.source_packet))
            && source["state"]["receipts"] == f.source_before["state"]["receipts"]
            && source["state"]["archives"] == f.source_before["state"]["archives"]
            && source["state"]["peer_inventory"] == f.source_before["state"]["peer_inventory"]
            && source["frames"].as_object().is_some_and(|m| {
                m.len() == 1
                    && m.values()
                        .any(|v| v["frame"] == STANDARD.encode(&f.source_frame))
            }),
        "reply refusal lost original/cursor or stored reply receipt/suppression/frame",
    )?;
    let peer_path = root.join("recipient-mesh/native-mesh-state.json");
    let peer_raw = files::private_read_with_limit(&peer_path, 32 * 1024 * 1024)?;
    let peer = Node::open(&f.configs[1])?;
    require(
        peer.received_frames()? == vec![(f.source_packet.clone(), f.source_frame.clone())],
        "reply cold peer lacks exact authenticated complete source custody",
    )?;
    drop(peer);
    require(
        files::private_read_with_limit(&peer_path, 32 * 1024 * 1024)? == peer_raw,
        "reply cold peer rewrote retained bytes",
    )?;
    let peer = state_image(&peer_raw, f.currency, &f.ids[1])?;
    require(
        peer["state"]["receipts"].get(&f.source_packet).is_some()
            && peer["state"]["messages"].get(&f.reply_packet).is_some()
            && peer["frames"].as_object().is_some_and(|m| {
                m.values()
                    .any(|v| v["frame"] == STANDARD.encode(&f.reply_frame))
            }),
        "reply cold peer lost real custody receipt or queued reverse frame",
    )
}

fn reply_run(root: &Path, deadline: f64, record: &mut Value) -> Result<()> {
    require(
        !STOP.load(Ordering::Acquire),
        "reply fixture process already stopped",
    )?;
    let mut f = reply_fixture(root, deadline)?;
    reply_patch(
        record,
        json!({"currency":f.currency,"region":f.region,"source_id":f.ids[0],
        "recipient_id":f.ids[1],"native_head":f.native_head,"native_value_root":f.native_value,
        "source_packet_id":f.source_packet,"source_frame_id":f.source_frame_id,
        "reply_packet_id":f.reply_packet,"reply_frame_id":f.reply_frame_id,"source_cursor_before":f.source_cursor}),
    )?;
    let (_reset, request_deferred) = install_defer_observer()?;
    let mut collector =
        ReplyCollector::start(&root.join("source-mesh"), f.currency, f.region, &f.ids[0])?;
    let (notice_sender, returned) = mpsc::sync_channel(1);
    let stop = Arc::new(AtomicBool::new(false));
    let handle = Arc::new(AtomicU64::new(0));
    let peer_stop = stop.clone();
    let peer_handle = handle.clone();
    let pins = ReplyPins {
        root: root.to_owned(),
        source_config: f.configs[0].clone(),
        recipient_config: f.configs[1].clone(),
        source_id: f.ids[0].clone(),
        recipient_id: f.ids[1].clone(),
        fingerprint: f.materials[1]["fingerprint"].clone(),
        currency: f.currency,
        source_packet: f.source_packet.clone(),
        source_frame: f.source_frame_id,
        reply_packet: f.reply_packet.clone(),
        reply_frame: f.reply_frame_id,
        scope_deadline: deadline,
        returned,
    };
    let listener = f.listener.take().ok_or("reply listener already taken")?;
    let worker = thread::Builder::new()
        .name("reply custody baseline peer".into())
        .spawn(move || reply_peer(listener, pins, peer_stop, peer_handle))
        .map_err(|e| format!("reply peer spawn refused: {e}"))?;
    let mut peer = Peer {
        stop,
        handle,
        worker: Some(worker),
    };
    let dispatch_clock = monotonic();
    let operation = match &dispatch_clock {
        Ok(_) => outgoing_observed(
            &f.configs[0],
            &f.ids[1],
            &f.configs[0]["contacts"][0],
            Some(collector.sink()?),
        ),
        Err(error) => Err(error.clone()),
    };
    let returned_clock = monotonic();
    let operation_error = operation.err();
    let notice_result = notice_sender.try_send(ReturnNotice {
        at: returned_clock.clone(),
        error: operation_error.clone(),
    });
    let peer_result = peer.join();
    let collector_result = collector.finish(true);
    // Both owned joins complete before propagating the primary operation error.
    let operation_error = operation_error.unwrap_or_else(|| "UNEXPECTED_OUTGOING_SUCCESS".into());
    if ![libc::EWOULDBLOCK, libc::EAGAIN]
        .iter()
        .any(|code| operation_error.starts_with(&format!("CONTACT_STORAGE_IO:{code}:")))
    {
        return Err(format!("reply primary outgoing result={operation_error}; peer={peer_result:?}; collector={collector_result:?}; notice={notice_result:?}"));
    }
    let peer_report = peer_result.map_err(|e| {
        format!(
            "reply primary outgoing={operation_error}; peer={e}; collector={collector_result:?}"
        )
    })?;
    collector_result?;
    notice_result.map_err(|e| format!("reply source notice: {e}"))?;
    let returned_at = returned_clock?;
    let dispatch_at = dispatch_clock?;
    require(
        peer_report["mesh_error_sha256"] == sha(operation_error.as_bytes()),
        "reply exact Mesh error mismatch",
    )?;
    require(
        matches!(request_deferred.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "reply collision occurred during earlier request binding",
    )?;
    let prepared_sha = REQUEST_MESH_PREPARED_SHA
        .with(|s| s.borrow().clone())
        .ok_or("reply original prepared SHA absent")?;
    require(
        peer_report["prepared_bundle_sha256"] == prepared_sha,
        "reply changed complete original bundle",
    )?;
    let events_raw = files::private_read_with_limit(
        &root.join("source-mesh/carriage-boundary-events.jsonl"),
        8 * 1024 * 1024,
    )?;
    let rows = events_raw
        .split(|b| *b == b'\n')
        .filter(|r| !r.is_empty())
        .map(|r| crate::wallet_http::decode_unique_with_limit(r, 16 * 1024))
        .collect::<Result<Vec<_>>>()?;
    let phases = [
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
        "request-open-completed",
        "request-send-started",
        "request-send-completed",
        "reply-receive-started",
        "reply-receive-completed",
        "reply-verified",
        "reply-custody-open-started",
        "attempt-completed",
    ];
    require(rows.len() == phases.len(), "reply exact phase count")?;
    let mut previous = dispatch_at;
    for (index, (row, phase)) in rows.iter().zip(phases).enumerate() {
        let at = reply_clock(row, "observed_at")?;
        require(
            row["phase"] == phase
                && row["lane"] == "outgoing"
                && row["attempt_id"] == 1
                && row["attempt_sequence"] == index + 1
                && at >= previous
                && at <= returned_at,
            "reply exact original outgoing phase/clock order",
        )?;
        previous = at;
    }
    require(
        rows[4]["detail"]["packet_ids"] == json!([f.source_packet])
            && rows[4]["detail"]["frame_ids"] == json!([f.source_frame_id.to_hex()])
            && rows[9]["detail"]["challenge_id"] == peer_report["challenge_id"]
            && rows[16]["detail"]["packet_ids"] == json!([f.reply_packet])
            && rows[16]["detail"]["frame_ids"] == json!([f.reply_frame_id.to_hex()])
            && rows[16]["detail"]["destination_ids"] == json!([f.ids[0]])
            && rows[16]["detail"]["challenge_id"] == peer_report["challenge_id"]
            && rows[16]["detail"]["exchange_id"] == peer_report["exchange_id"]
            && rows[18]["detail"]["result"] == "error"
            && rows[18]["detail"]["error_tag"] == "CONTACT_STORAGE_IO"
            && rows[18]["detail"]["lock_contention"] == true,
        "reply exact authenticated response and Mesh terminal binding",
    )?;
    let prepared_at = reply_clock(&rows[4], "observed_at")?;
    let connect_at = reply_clock(&rows[5], "observed_at")?;
    let lower = prepared_at + 3.0;
    let upper = connect_at + 3.0;
    // The production clock assignment lies strictly between these two events.
    // Its exact value is not exposed and remains null; this lower-bound test
    // proves the error precedes the real original deadline without extending it.
    require(
        dispatch_at <= prepared_at
            && prepared_at <= connect_at
            && connect_at <= reply_clock(&peer_report, "accepted_at")?
            && reply_clock(&peer_report, "accepted_at")?
                <= reply_clock(&peer_report, "challenge_sent_at")?
            && reply_clock(&peer_report, "request_received_at")?
                <= reply_clock(&peer_report, "request_verified_at")?
            && reply_clock(&peer_report, "request_verified_at")?
                <= reply_clock(&peer_report, "custody_completed_at")?
            && reply_clock(&peer_report, "custody_completed_at")?
                <= reply_clock(&peer_report, "reply_prepared_at")?
            && reply_clock(&peer_report, "reply_prepared_at")?
                <= reply_clock(&peer_report, "mesh_held_at")?
            && reply_clock(&peer_report, "mesh_held_at")? <= reply_clock(&rows[16], "observed_at")?
            && reply_clock(&rows[16], "observed_at")? <= reply_clock(&rows[17], "observed_at")?
            && reply_clock(&peer_report, "reply_sent_at")? < lower
            && returned_at < lower
            && returned_at <= reply_clock(&peer_report, "mesh_release_started_at")?
            && reply_clock(&peer_report, "mesh_release_started_at")?
                <= reply_clock(&peer_report, "mesh_released_at")?
            && reply_clock(&peer_report, "mesh_released_at")?
                < reply_clock(&peer_report, "peer_deadline")?,
        "reply original clock/real held Mesh collision binding",
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
        "reply observer incomplete",
    )?;
    reply_cold(root, &f)?;
    reply_native_zero(root, &f, deadline)?;
    let checked_raw =
        files::private_read_with_limit(&root.join("checked-metadata.json"), 64 * 1024)?;
    let artifact_sha = sha(&io(fs::read(io(std::env::current_exe())?))?);
    within(deadline)?;
    reply_patch(
        record,
        json!({"prepared_bundle_sha256":prepared_sha,"request_sha256":peer_report["request_sha256"],
        "response_sha256":peer_report["response_sha256"],"reply_bundle_sha256":peer_report["reply_bundle_sha256"],
        "challenge_id":peer_report["challenge_id"],"exchange_id":peer_report["exchange_id"],
        "events_sha256":sha(&events_raw),"checked_metadata_sha256":sha(&checked_raw),"dispatch_at":dispatch_at,
        "outgoing_returned_at":returned_at,"prepared_at":prepared_at,"connect_started_at":connect_at,
        "socket_deadline_lower_bound":lower,"socket_deadline_upper_bound":upper,"test_binary_sha256":artifact_sha,
        "operation_error_tag":"CONTACT_STORAGE_IO"}),
    )?;
    for (target, source) in [
        ("peer_accepted_at", "accepted_at"),
        ("peer_deadline", "peer_deadline"),
        ("challenge_sent_at", "challenge_sent_at"),
        ("request_received_at", "request_received_at"),
        ("request_verified_at", "request_verified_at"),
        ("peer_custody_completed_at", "custody_completed_at"),
        ("reply_prepared_at", "reply_prepared_at"),
        ("source_mesh_held_at", "mesh_held_at"),
        ("reply_sent_at", "reply_sent_at"),
        ("source_mesh_release_started_at", "mesh_release_started_at"),
        ("source_mesh_released_at", "mesh_released_at"),
    ] {
        record[target] = peer_report[source].clone();
    }
    reply_patch(
        record,
        json!({"exact_mesh_acquisition_refusal":true,"held_probe_typed_none":true,
        "peer_actual_custody_received":true,"reply_verified":true,"local_reply_receive_absent":true,
        "source_cursor_advanced_once":true,"original_frame_retained":true,"source_receipt_absent":true,
        "peer_suppression_unchanged":true,"reply_frame_absent":true,"native_zero_cold_unchanged":true,
        "peer_joined":true,"collector_joined":true,"normal_test_socket_shutdown":false,
        "all_original_clock_bounds_met":true,"request_mesh_defer_seen":false,"source_cursor_after":f.source_cursor+1}),
    )?;
    drop(f.source_reserved);
    within(deadline)
}

fn reply_candidate() -> Result<()> {
    require(
        std::env::var(OPT_IN).as_deref() == Ok("1"),
        "reply Mesh baseline opt-in required",
    )?;
    let started = monotonic()?;
    let deadline = started + 30.0;
    let root = io(fs::canonicalize(std::env::temp_dir()))?
        .join(format!("rld-reply-mesh-baseline-{}", random()?));
    match fs::symlink_metadata(&root) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        _ => return Err("reply fixture root not fresh or inspection refused".into()),
    }
    let root = directory(&root)?;
    let scope = json!({"format":REPLY_FORMAT,"case":"held-source-mesh-after-verified-response",
        "root":root,"pid":std::process::id(),"started":started,"deadline":deadline,"stop_deadline":started+35.0,
        "regional_build_source_sha256":env!("RLD_REGIONAL_SOURCE"),"fixture_only":true,
        "production_outgoing_observed":true,"production_reply_retry_implemented":false,
        "transport_payload_native_authority":false,"native_value_authority":false,
        "whole_payment_pass":false,"payment_qualified":false,"mainnet":false});
    reply_metadata(&root.join("scope.json"), &scope)?;
    eprintln!("reply_mesh_baseline_scope={scope}");
    let mut record = Value::Object(
        RESULT_KEYS
            .split_whitespace()
            .map(|key| (key.to_owned(), Value::Null))
            .collect(),
    );
    reply_patch(
        &mut record,
        json!({"format":REPLY_FORMAT,"case":"held-source-mesh-after-verified-response",
        "root":root,"pid":std::process::id(),"passed":false,"started":started,"deadline":deadline,
        "stop_deadline":started+35.0,"regional_build_source_sha256":env!("RLD_REGIONAL_SOURCE"),
        "transport_payload_native_authority":false,"native_value_authority":false,
        "whole_payment_pass":false,"payment_qualified":false,"mainnet":false}),
    )?;
    let result = reply_run(&root, deadline, &mut record);
    let ended = monotonic();
    let result = result.and_then(|()| {
        let ended = ended.as_ref().map_err(Clone::clone)?;
        require(
            *ended < deadline,
            "reply whole original30 deadline exhausted",
        )?;
        record["passed"] = json!(true);
        Ok(())
    });
    record["ended"] = json!(ended.as_ref().ok());
    record["elapsed_seconds"] = json!(ended.as_ref().ok().map(|end| *end - started));
    let failure_write = match &result {
        Err(error) => new_json(&root.join("private-failure.json"), &json!({"error":error})),
        Ok(()) => Ok(()),
    };
    let outcome_write = reply_metadata(&root.join("outcome.json"), &record);
    eprintln!("reply_mesh_baseline_result={record}");
    // Preserve expected-refusal evidence and all unexpected residue. External
    // stopped-seal/controller owns this fresh root; this test deletes nothing.
    result?;
    failure_write?;
    outcome_write
}
#[test]
#[ignore = "actual reply Mesh fatal after authenticated durable peer reply; original30 normal,35 stop only"]
fn outgoing_reply_custody_refuses_real_mesh_after_verified_response() -> Result<()> {
    reply_candidate()
}
