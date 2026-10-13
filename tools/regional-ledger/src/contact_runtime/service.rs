use super::*;
use crate::{storage::Store, Hash};
use serde_json::{json, Value};
use std::{
    fs,
    net::{SocketAddrV4, TcpListener, TcpStream},
    os::fd::IntoRawFd,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

static STOP: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
thread_local! {
    static CARRIAGE_TRACE: std::cell::RefCell<Option<Vec<Value>>> = const { std::cell::RefCell::new(None) };
    static SUBWORK_TRACE: std::cell::RefCell<std::collections::BTreeMap<&'static str,(usize,f64)>> = const { std::cell::RefCell::new(std::collections::BTreeMap::new()) };
    static PAYMENT_TRACE_ACTIVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[cfg(test)]
pub(super) fn payment_trace_enabled() -> bool {
    PAYMENT_TRACE_ACTIVE.with(|active| active.get())
}
#[cfg(test)]
pub(super) fn start_payment_trace() {
    start_work_trace();
    PAYMENT_TRACE_ACTIVE.with(|active| active.set(true));
}
#[cfg(test)]
pub(super) fn trace_payment_event(build: impl FnOnce() -> Result<Value>) -> Result<()> {
    if !payment_trace_enabled() {
        return Ok(());
    }
    let mut event = build()?;
    event["at"] = json!(monotonic()?);
    CARRIAGE_TRACE.with(|trace| -> Result<()> {
        let mut trace = trace.borrow_mut();
        let records = trace
            .as_mut()
            .ok_or("payment diagnostic trace unavailable")?;
        require(records.len() < 4096, "diagnostic carriage record bound")?;
        records.push(event);
        Ok(())
    })
}
#[cfg(test)]
fn trace_exchange(phase: &str, peer: &str, bundle: &Value) -> Result<()> {
    CARRIAGE_TRACE.with(|trace| -> Result<()> {
        let mut trace = trace.borrow_mut();
        let Some(records) = trace.as_mut() else {
            return Ok(());
        };
        require(records.len() < 4096, "diagnostic carriage record bound")?;
        let packets = bundle["body"]["transits"]
            .as_array()
            .ok_or("diagnostic transits")?
            .iter()
            .map(|t| {
                json!({"packet_id":t["routing"]["body"]["packet_id"],
                "frame_id":t["routing"]["body"]["frame_id"],
                "destination":t["packet"]["body"]["destination"]})
            })
            .collect::<Vec<_>>();
        records.push(json!({"phase":phase,"peer":peer,"at":monotonic()?,"packets":packets}));
        Ok(())
    })
}
#[cfg(test)]
pub(super) fn start_work_trace() {
    SUBWORK_TRACE.with(|trace| trace.borrow_mut().clear());
    CARRIAGE_TRACE.with(|trace| *trace.borrow_mut() = Some(Vec::new()));
}
#[cfg(test)]
pub(super) fn take_work_trace() -> Vec<Value> {
    PAYMENT_TRACE_ACTIVE.with(|active| active.set(false));
    let mut records = CARRIAGE_TRACE.with(|trace| trace.borrow_mut().take().unwrap_or_default());
    SUBWORK_TRACE.with(|trace| {
        for (phase, (calls, seconds)) in std::mem::take(&mut *trace.borrow_mut()) {
            records.push(json!({"phase":phase,"calls":calls,"seconds":seconds}));
        }
    });
    records
}
#[cfg(test)]
pub(super) fn trace_subwork(phase: &'static str, started: f64) -> Result<()> {
    if CARRIAGE_TRACE.with(|trace| trace.borrow().is_none()) {
        return Ok(());
    }
    let seconds = monotonic()? - started;
    SUBWORK_TRACE.with(|trace| -> Result<()> {
        let mut trace = trace.borrow_mut();
        require(
            trace.contains_key(phase) || trace.len() < 64,
            "diagnostic subwork phase bound",
        )?;
        let total = trace.entry(phase).or_default();
        total.0 = total
            .0
            .checked_add(1)
            .ok_or("diagnostic work count overflow")?;
        total.1 += seconds;
        Ok(())
    })
}
#[cfg(test)]
pub(super) fn trace_work(phase: &'static str, started: f64) -> Result<()> {
    // Phase-only durations carry no event identity or original payment clock.
    // Preserve their complete count and total in the existing bounded map;
    // identified carriage events keep their separate unchanged strict bound.
    trace_subwork(phase, started)
}
extern "C" fn stop(_: i32) {
    STOP.store(true, Ordering::Release);
}
pub(crate) fn monotonic() -> Result<f64> {
    crate::bft_tick_schedule::monotonic()
}

pub struct Options {
    pub ledger: PathBuf,
    pub authority: String,
    pub currency: Hash,
    pub mesh_config: Option<PathBuf>,
    pub bft_config: Option<PathBuf>,
    pub listen: SocketAddrV4,
    pub miner: Option<String>,
    pub interval: f64,
    pub insecure_tcp: bool,
}

struct Connection(u64);
impl Drop for Connection {
    fn drop(&mut self) {
        let _ = tls(json!({"Close":{"handle":self.0}}));
    }
}
struct Context(u64);
impl Drop for Context {
    fn drop(&mut self) {
        let _ = tls(json!({"ContextClose":{"handle":self.0}}));
    }
}

fn limits() -> Value {
    json!({"contacts":16,"nodes":64,"transits":4,"messages":256,"exchange":EXCHANGE_LIMIT})
}
fn recv(handle: u64, deadline: f64) -> Result<Value> {
    tls(json!({"Receive":{"handle":handle,"deadline":deadline}}))
}
fn send(handle: u64, deadline: f64, value: Value) -> Result<()> {
    tls(json!({"Send":{"handle":handle,"deadline":deadline,"value":value}}))?;
    Ok(())
}

fn accept(config: &Value, context: u64, material: &Value, stream: TcpStream) -> Result<()> {
    let deadline = monotonic()? + 3.0;
    let fd = stream.into_raw_fd();
    // The native Accept operation owns the descriptor on both success and refusal.
    let handle = tls(json!({"Accept":{"context":context,"fd":fd,"deadline":deadline}}))?
        .as_u64()
        .ok_or("TLS accepted handle")?;
    let connection = Connection(handle);
    let (challenge, id, network, peers) = {
        let node = Node::open(config)?;
        let value=node.sign("tcp-challenge",json!({"format":MESH,"adapter":"RLD-CONTACT-TCP-V4",
            "network":node.network,"node_id":node.id,"nonce":random()?,"tls_cert_sha256":material["fingerprint"]}))?;
        (
            value,
            node.id.clone(),
            node.network.clone(),
            node.contacts.keys().cloned().collect::<Vec<_>>(),
        )
    };
    send(handle, deadline, challenge.clone())?;
    let request = recv(handle, deadline)?;
    let checked = crypto(
        json!({"Exchange":{"TcpRequest":{"network":network,"signed":request,"recipient":id,
        "peers":peers,"nonce":challenge["body"]["nonce"],"limits":limits()}}}),
    )?;
    let peer = checked["body"]["node_id"].as_str().ok_or("request peer")?;
    let response = {
        let mut node = Node::open(config)?;
        // All incoming bytes are durable before producing a positive acknowledgment.
        node.receive(&checked["body"]["bundle"], peer)?;
        let bundle = node.prepare(peer)?;
        node.sign("tcp-response",json!({"format":MESH,"adapter":"RLD-CONTACT-TCP-V4","network":network,
            "node_id":id,"to":peer,"nonce":checked["body"]["nonce"],"challenge":checked["body"]["challenge"],
            "exchange_id":digest(&checked["body"]["bundle"])? ,"accepted":true,"bundle":bundle,"error":null}))?
    };
    send(connection.0, deadline, response)
}

pub(super) fn outgoing(config: &Value, peer: &str, contact: &Value) -> Result<()> {
    // The preparation and cursor commit completes before opening a socket.
    let (bundle, id, network) = {
        let mut node = Node::open(config)?;
        (node.prepare(peer)?, node.id.clone(), node.network.clone())
    };
    let deadline = monotonic()? + 3.0;
    let handle=tls(json!({"Connect":{"host":contact["host"],"port":contact["port"],
        "fingerprint":contact["tls_cert_sha256"],"network":network,"peer":peer,"deadline":deadline}}))?.as_u64().ok_or("TLS connected handle")?;
    let connection = Connection(handle);
    let challenge = recv(handle, deadline)?;
    let verified = crypto(
        json!({"Exchange":{"Challenge":{"network":network,"signed":challenge,"peer":peer,"fingerprint":contact["tls_cert_sha256"]}}}),
    )?;
    let request = {
        let node = Node::open(config)?;
        node.sign("tcp-request",json!({"format":MESH,"adapter":"RLD-CONTACT-TCP-V4",
        "network":network,"node_id":id,"to":peer,"nonce":random()?,"challenge":verified["body"]["nonce"],"bundle":bundle}))?
    };
    send(handle, deadline, request.clone())?;
    let response = recv(handle, deadline)?;
    let checked = crypto(
        json!({"Exchange":{"TcpResponse":{"network":network,"signed":response,"requester":id,
        "peer":peer,"sent":request,"limits":limits()}}}),
    )?;
    require(
        checked["body"]["accepted"] == true,
        "peer did not acknowledge custody; retain complete evidence",
    )?;
    // A verified socket reply alone does not suppress carriage. Retain its complete bundle locally.
    Node::open(config)?.receive(&checked["body"]["bundle"], peer)?;
    drop(connection);
    Ok(())
}

fn codec(mode: &str, raw: &[u8]) -> Result<Vec<u8>> {
    crate::contact_spool_codec::execute(
        &bytes(&json!({mode:{"limit":EXCHANGE_LIMIT,"size_bytes":raw.len(),
        "sha256":hex::encode(Sha256::digest(raw))}}))?,
        raw,
    )
    .map(|(_, raw)| raw)
}
pub(super) fn spool(config: &Value, peer: &str, contact: &Value) -> Result<()> {
    // One fully authenticated transport state under one OS lease for this
    // bounded directory turn. Every later complete envelope still authenticates.
    // This lease is never carried across a TCP connection or socket wait.
    #[cfg(test)]
    let started = monotonic()?;
    let mut node = Node::open(config)?;
    #[cfg(test)]
    trace_work("mesh-open-spool", started)?;
    spool_node(&mut node, peer, contact)
}

pub(super) fn spool_directory_turn(config: &Value) -> Result<Vec<String>> {
    directory_turn(config, &|| false)
}

fn directory_turn(config: &Value, stopped: &dyn Fn() -> bool) -> Result<Vec<String>> {
    directory_phase(config, stopped, DirectoryPhase::Duplex)
}

#[derive(Clone, Copy)]
enum DirectoryPhase {
    Duplex,
    Receive,
    Publish,
}

fn directory_phase(
    config: &Value,
    stopped: &dyn Fn() -> bool,
    phase: DirectoryPhase,
) -> Result<Vec<String>> {
    let mut node = Some(open_directory_node(config)?);
    directory_phase_node(config, stopped, phase, &mut node)
}

fn open_directory_node(config: &Value) -> Result<Node> {
    #[cfg(test)]
    let started = monotonic()?;
    let node = Node::open(config)?;
    #[cfg(test)]
    trace_work("mesh-open-spool", started)?;
    Ok(node)
}

fn directory_phase_node(
    config: &Value,
    stopped: &dyn Fn() -> bool,
    phase: DirectoryPhase,
    node: &mut Option<Node>,
) -> Result<Vec<String>> {
    let contacts = node
        .as_ref()
        .ok_or("missing initial directory turn node")?
        .contacts
        .clone();
    require(
        contacts
            .values()
            .all(|contact| contact.get("host").is_none()),
        "directory turn cannot retain a lease across sockets",
    )?;
    let mut errors = Vec::new();
    for (peer, contact) in contacts {
        if stopped() {
            break;
        }
        if node.is_none() {
            match Node::open(config) {
                Ok(reopened) => *node = Some(reopened),
                Err(error) => {
                    errors.push(error);
                    continue;
                }
            }
        }
        let node_ref = node.as_mut().ok_or("missing directory turn node")?;
        let result = match phase {
            DirectoryPhase::Duplex => spool_node(node_ref, &peer, &contact),
            DirectoryPhase::Receive => spool_receive(node_ref, &peer, &contact),
            DirectoryPhase::Publish => spool_publish(node_ref, &peer, &contact),
        };
        if let Err(error) = result {
            // A failed prepare/publication may leave uncertain in-memory state.
            // Release it; the next neighbor must open/authenticate durable state.
            node.take();
            errors.push(error);
        }
    }
    Ok(errors)
}

type ReceivedFrames = Vec<(String, Vec<u8>)>;

struct DirectoryReceive {
    errors: Vec<String>,
    frames: ReceivedFrames,
}

fn directory_receive_page(
    config: &Value,
    stopped: &dyn Fn() -> bool,
    cursor: Option<&str>,
    seen: &[String],
) -> Result<DirectoryReceive> {
    let mut node = Some(open_directory_node(config)?);
    let errors = directory_phase_node(config, stopped, DirectoryPhase::Receive, &mut node)?;
    // A failed last contact has discarded uncertain memory. Authenticate the
    // durable image again before selecting any complete received bytes.
    if node.is_none() {
        node = Some(Node::open(config)?);
    }
    #[cfg(test)]
    let started = monotonic()?;
    let frames = node
        .as_ref()
        .ok_or("missing receive page node")?
        .frame_page_selected(cursor, 4, seen)?;
    #[cfg(test)]
    CARRIAGE_TRACE.with(|trace| -> Result<()> {
        let mut trace = trace.borrow_mut();
        if let Some(records) = trace.as_mut() {
            require(records.len() < 4096, "diagnostic carriage record bound")?;
            records.push(json!({"phase":"native-page-selected","at":monotonic()?,
                "packet_ids":frames.iter().map(|(id,_)|id).collect::<Vec<_>>(),
                "after":cursor,"seen_count":seen.len(),"native_authority":false}));
        }
        Ok(())
    })?;
    #[cfg(test)]
    trace_work("mesh-native-page", started)?;
    // Only bounded owned bytes cross this boundary. No transport lease or
    // transport observation initializes the Native ledger or grants authority.
    drop(node);
    Ok(DirectoryReceive { errors, frames })
}

fn spool_node(node: &mut Node, peer: &str, contact: &Value) -> Result<()> {
    spool_receive(node, peer, contact)?;
    spool_publish(node, peer, contact)
}

fn spool_receive(node: &mut Node, peer: &str, contact: &Value) -> Result<()> {
    let compressed = contact["adapter"] == "RLD-CONTACT-SPOOL-ZLIB-V1";
    let limits = json!({"batch":EXCHANGE_LIMIT,"files":256,"bytes":64*1024*1024});
    let adapter = if compressed {
        json!("RLD-CONTACT-SPOOL-ZLIB-V1")
    } else {
        Value::Null
    };
    if let Some(path) = contact["inbox"].as_str() {
        let inventory = crate::contact_spool::execute(
            &bytes(&json!({"Inventory":{"path":path,"adapter":adapter,"limits":limits}}))?,
            &[],
            &[],
        )?;
        for name in inventory["files"]
            .as_array()
            .ok_or("spool files")?
            .iter()
            .take(4)
        {
            let name = name.as_str().ok_or("spool filename")?;
            let target = Path::new(path).join(name);
            let encoded = files::private_read_with_limit(&target, EXCHANGE_LIMIT)?;
            let raw = if compressed {
                codec("Decode", &encoded)?
            } else {
                encoded
            };
            let value = crate::wallet_http::decode_unique_with_limit(&raw, EXCHANGE_LIMIT)?;
            require(
                bytes(&value)? == raw && name == format!("{}.json", digest(&value)?),
                "spool exact canonical exchange filename",
            )?;
            #[cfg(test)]
            let started = monotonic()?;
            node.receive(&value, peer)?;
            #[cfg(test)]
            trace_work("mesh-receive", started)?;
            #[cfg(test)]
            trace_exchange("durable-transport-receive", peer, &value)?;
            fs::remove_file(&target).map_err(|e| e.to_string())?;
            crate::contact_storage::directory(Path::new(path))?
                .sync_all()
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn spool_publish(node: &mut Node, peer: &str, contact: &Value) -> Result<()> {
    let compressed = contact["adapter"] == "RLD-CONTACT-SPOOL-ZLIB-V1";
    let limits = json!({"batch":EXCHANGE_LIMIT,"files":256,"bytes":64*1024*1024});
    let adapter = if compressed {
        json!("RLD-CONTACT-SPOOL-ZLIB-V1")
    } else {
        Value::Null
    };
    if let Some(path) = contact["outbox"].as_str() {
        #[cfg(test)]
        let started = monotonic()?;
        let bundle = node.prepare(peer)?;
        #[cfg(test)]
        trace_payment_event(|| {
            let packets = bundle["body"]["transits"]
                .as_array()
                .ok_or("diagnostic prepared transits")?
                .iter()
                .map(|transit| {
                    json!({"packet_id":transit["routing"]["body"]["packet_id"],
                    "frame_id":transit["routing"]["body"]["frame_id"],
                    "destination":transit["packet"]["body"]["destination"]})
                })
                .collect::<Vec<_>>();
            Ok(
                json!({"phase":"payment-transport-prepared","node_id":node.id,
                "peer":peer,"started":started,"packets":packets}),
            )
        })?;
        #[cfg(test)]
        trace_work("mesh-prepare", started)?;
        let raw = bytes(&bundle)?;
        let encoded = if compressed {
            codec("Encode", &raw)?
        } else {
            raw.clone()
        };
        let target = Path::new(path).join(format!("{}.json", digest(&bundle)?));
        crate::contact_spool::execute(
            &bytes(
                &json!({"Publish":{"path":target,"adapter":adapter,"limits":limits,
            "encoded_size":encoded.len(),"encoded_sha256":hex::encode(Sha256::digest(&encoded)),
            "data_size":raw.len(),"data_sha256":hex::encode(Sha256::digest(&raw))}}),
            )?,
            &encoded,
            &raw,
        )?;
        #[cfg(test)]
        trace_exchange("published-transport-exchange", peer, &bundle)?;
    }
    Ok(())
}

fn configuration(options: &Options, region: Hash) -> Result<Value> {
    if let Some(path) = &options.mesh_config {
        return read(path, 64 * 1024);
    }
    let root = directory(&options.ledger.join("transport"))?;
    let _lock = Lease::acquire(&root, "Startup")?;
    let path = root.join("native-config.json");
    if fs::symlink_metadata(&path).is_ok() {
        return read(&path, 64 * 1024);
    }
    require(
        !root.join("config.json").exists(),
        "legacy startup configuration requires a fresh Rust fixture",
    )?;
    if !root.join("identity.private.json").exists() {
        crypto(
            json!({"Initialize":{"root":root,"network":options.currency,"region":region,"label":"regional-node"}}),
        )?;
    }
    let config = json!({"format":MESH,"network":options.currency,"state":root,"contacts":[]});
    atomic(&path, &config, 64 * 1024)?;
    Ok(config)
}

pub(super) fn tick_ledger(
    options: &Options,
    config: &Value,
    runtime: &mut Option<super::bft::Runtime>,
    cursor: &mut Option<String>,
    seen: &mut Vec<String>,
) -> Result<Value> {
    // Capture complete received bytes under the transport lock, then release it before native ledger replay.
    #[cfg(test)]
    let started = monotonic()?;
    let frames = Node::open(config)?.frame_page_selected(cursor.as_deref(), 4, seen)?;
    #[cfg(test)]
    trace_work("mesh-native-page", started)?;
    tick_ledger_frames(options, config, runtime, cursor, seen, frames, None)
        .map(|tick| tick.observation)
}

struct LedgerTick {
    observation: Value,
    outgoing_errors: Vec<String>,
}

fn tick_ledger_frames(
    options: &Options,
    config: &Value,
    runtime: &mut Option<super::bft::Runtime>,
    cursor: &mut Option<String>,
    seen: &mut Vec<String>,
    frames: ReceivedFrames,
    directory: Option<&dyn Fn() -> bool>,
) -> Result<LedgerTick> {
    #[cfg(test)]
    let started = monotonic()?;
    let mut store = Store::open(&options.ledger, &options.authority, options.currency)?;
    #[cfg(test)]
    trace_work("native-store-open", started)?;
    for (id, raw) in &frames {
        if !seen.contains(id) {
            seen.push(id.clone());
            if seen.len() > 512 {
                seen.remove(0);
            }
        }
        let (frame, _) = crate::contact_frame::inspect_bytes(
            raw,
            None,
            None,
            crate::contact::MAX_PAYLOAD,
            crate::contact::MAX_FRAME,
        )?;
        if frame.destination_chain_id != store.chain.region {
            *cursor = Some(id.clone());
            continue;
        }
        if frame.kind == "regional-bft" {
            if let Some(runtime) = runtime {
                #[cfg(test)]
                let started = monotonic()?;
                runtime.receive(&mut store, raw)?;
                #[cfg(test)]
                trace_work("native-envelope-receive", started)?;
                #[cfg(test)]
                CARRIAGE_TRACE.with(|trace| -> Result<()> {
                    let mut trace = trace.borrow_mut();
                    if let Some(records) = trace.as_mut() {
                        require(records.len() < 4096, "diagnostic carriage record bound")?;
                        records.push(json!({"phase":"native-receive","at":monotonic()?,
                            "packet_id":id,"frame_id":frame.message_id}));
                    }
                    Ok(())
                })?;
            }
            *cursor = Some(id.clone());
            continue;
        }
        if frame.kind == "source-finality" {
            let (_, history) = crate::contact::Frame::unpack_origin(raw)?;
            store.accept_complete_origin_history(history)?;
        } else {
            store.contact_apply(raw, options.miner.clone())?;
        }
        *cursor = Some(id.clone());
    }
    if let Some(runtime) = runtime {
        #[cfg(test)]
        let started = monotonic()?;
        runtime.tick(&mut store)?;
        #[cfg(test)]
        trace_work("native-consensus-tick", started)?;
    }
    let region = store.chain.region;
    let height = store.chain.height();
    let mut offers = Vec::new();
    if let Some(sid) = store.chain.finalized {
        for (eid, record) in &store.chain.ledger.exports {
            if store.evidence.export(sid, *eid).is_ok() {
                offers.push((record.destination, store.contact_export(*eid)?));
            }
        }
    }
    drop(store);
    // Native replay and signing finish before opening this custody lease.
    // Directory-only carriage shares it through durable preparation; socket
    // adapters retain their original independent open/wait boundaries.
    let first = if directory.is_some() {
        let mut node = open_directory_node(config)?;
        if let Some(runtime) = runtime {
            #[cfg(test)]
            let started = monotonic()?;
            runtime.broadcast_node(&mut node)?;
            #[cfg(test)]
            trace_work("native-broadcast", started)?;
        }
        node
    } else {
        if let Some(runtime) = runtime {
            #[cfg(test)]
            let started = monotonic()?;
            runtime.broadcast(config)?;
            #[cfg(test)]
            trace_work("native-broadcast", started)?;
        }
        Node::open(config)?
    };
    let mut node = Some(first);
    let node_ref = node.as_mut().ok_or("missing post-ledger custody node")?;
    let adverts = node_ref.advertised_destinations()?;
    for (region, raw) in offers {
        for (destination, label) in &adverts {
            if *label == region.to_hex() {
                node_ref.enqueue(&raw, destination)?;
            }
        }
    }
    node_ref.archive_completed()?;
    let observation = json!({"format":FORMAT,"currency":options.currency,"region":region,"local_height":height,
        "progress_observation_available":true,"mesh":node_ref.observation(),
        "ledger_changed_by_native_verification_only":true,"fixture_only":true});
    let outgoing_errors = match directory {
        Some(stopped) => directory_phase_node(config, stopped, DirectoryPhase::Publish, &mut node)?,
        None => Vec::new(),
    };
    Ok(LedgerTick {
        observation,
        outgoing_errors,
    })
}

#[cfg(test)]
pub(super) fn directory_ledger_turn(
    options: &Options,
    config: &Value,
    runtime: &mut Option<super::bft::Runtime>,
    cursor: &mut Option<String>,
    seen: &mut Vec<String>,
) -> Result<Value> {
    directory_ledger_turn_stopped(options, config, runtime, cursor, seen, &|| false)
}

fn directory_ledger_turn_stopped(
    options: &Options,
    config: &Value,
    runtime: &mut Option<super::bft::Runtime>,
    cursor: &mut Option<String>,
    seen: &mut Vec<String>,
    stopped: &dyn Fn() -> bool,
) -> Result<Value> {
    let received = directory_receive_page(config, stopped, cursor.as_deref(), seen)?;
    let mut errors = received.errors;
    let result = tick_ledger_frames(
        options,
        config,
        runtime,
        cursor,
        seen,
        received.frames,
        Some(stopped),
    );
    if result
        .as_ref()
        .err()
        .is_some_and(|error| lock_contention(error))
    {
        errors.extend(directory_phase(config, stopped, DirectoryPhase::Publish)?);
    }
    let tick = result?;
    errors.extend(tick.outgoing_errors);
    let mut observation = tick.observation;
    observation["transport_attempt_errors"] = json!(errors);
    Ok(observation)
}

fn lock_contention(error: &str) -> bool {
    // Match the Native lock API's exact typed refusal, and the OS errno bound
    // by the transport file adapter. Proof/permission failures stay fatal.
    error == std::fs::TryLockError::WouldBlock.to_string()
        || error.starts_with(&format!("CONTACT_STORAGE_IO:{}:", libc::EWOULDBLOCK))
        || error.starts_with(&format!("CONTACT_STORAGE_IO:{}:", libc::EAGAIN))
}

fn unknown_progress(currency: Hash, region: Hash) -> Value {
    json!({"format":FORMAT,"currency":currency,"region":region,
        "progress_observation_available":false,
        "diagnostic":"Native or transport OS lock contention; progress is unknown",
        "fixture_only":true})
}

pub fn run(options: Options) -> Result<()> {
    require(
        options.interval.is_finite() && (0.05..=3600.0).contains(&options.interval),
        "contact interval outside bound",
    )?;
    require(
        !options.insecure_tcp,
        "Rust runtime requires pinned TLS; plaintext adapter is not enabled",
    )?;
    require(
        options.bft_config.is_none() || options.miner.is_none(),
        "BFT runtime cannot enable uncertified import mining",
    )?;
    let store = Store::open_inspection(&options.ledger, &options.authority, options.currency)?;
    let region = store.chain.region;
    drop(store);
    let config = configuration(&options, region)?;
    let node = Node::open(&config)?;
    require(
        node.network == options.currency.to_hex() && node.region == region.to_hex(),
        "configured transport differs from native currency/region",
    )?;
    for contact in node.contacts.values() {
        if contact.get("host").is_some() {
            require(
                contact["tls_cert_sha256"].is_string(),
                "TCP neighbor requires independent certificate pin",
            )?;
        }
    }
    let contacts = node.contacts.clone();
    let root = node.root.clone();
    let id = node.id.clone();
    drop(node);
    let _service = Lease::acquire(&root, "Service")?;
    let mut bft = if let Some(path) = &options.bft_config {
        let store = Store::open_inspection(&options.ledger, &options.authority, options.currency)?;
        Some(super::bft::Runtime::open(path, &store, &config)?)
    } else {
        None
    };
    let mut receive_cursor = None;
    let mut receive_seen = Vec::new();
    let context = tls(json!({"Context":{"root":root,"network":options.currency,"peer":id}}))?;
    let context_handle = Context(context["handle"].as_u64().ok_or("TLS context handle")?);
    let listener = TcpListener::bind(options.listen).map_err(|e| e.to_string())?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    println!(
        "{}",
        json!({"format":FORMAT,"listen":listener.local_addr().map_err(|e|e.to_string())?.to_string(),"tls":context["material"],"fixture_only":true})
    );
    STOP.store(false, Ordering::Release);
    unsafe {
        libc::signal(libc::SIGTERM, stop as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, stop as *const () as libc::sighandler_t);
    }
    let running = Arc::new(AtomicBool::new(true));
    let inbound_running = running.clone();
    let inbound_config = config.clone();
    let material = context["material"].clone();
    let handle = context_handle.0;
    let inbound = thread::spawn(move || -> Result<()> {
        let mut workers: Vec<JoinHandle<Result<()>>> = Vec::new();
        while inbound_running.load(Ordering::Acquire) {
            let mut i = 0;
            while i < workers.len() {
                if workers[i].is_finished() {
                    let w = workers.remove(i);
                    if let Err(error) = w.join().map_err(|_| "inbound worker panicked")? {
                        eprintln!("inbound contact refused: {error}");
                    }
                } else {
                    i += 1;
                }
            }
            match listener.accept() {
                Ok((stream, _)) if workers.len() < 2 => {
                    let config = inbound_config.clone();
                    let material = material.clone();
                    workers.push(thread::spawn(move || {
                        accept(&config, handle, &material, stream)
                    }));
                }
                Ok((stream, _)) => drop(stream),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10))
                }
                Err(e) => return Err(e.to_string()),
            }
        }
        for worker in workers {
            if let Err(error) = worker.join().map_err(|_| "inbound worker panicked")? {
                eprintln!("inbound contact refused: {error}");
            }
        }
        Ok(())
    });
    let result = (|| {
        while !STOP.load(Ordering::Acquire) {
            require(
                !inbound.is_finished(),
                "Rust contact listener stopped unexpectedly",
            )?;
            let directory_only = contacts
                .values()
                .all(|contact| contact.get("host").is_none());
            if !directory_only {
                for (peer, contact) in &contacts {
                    if STOP.load(Ordering::Acquire) {
                        break;
                    }
                    let result = if contact.get("host").is_some() {
                        outgoing(&config, peer, contact)
                    } else {
                        spool(&config, peer, contact)
                    };
                    if let Err(error) = result {
                        eprintln!("contact attempt retained without custody claim: {error}");
                    }
                }
            }
            let result = if directory_only {
                directory_ledger_turn_stopped(
                    &options,
                    &config,
                    &mut bft,
                    &mut receive_cursor,
                    &mut receive_seen,
                    &|| STOP.load(Ordering::Acquire),
                )
            } else {
                tick_ledger(
                    &options,
                    &config,
                    &mut bft,
                    &mut receive_cursor,
                    &mut receive_seen,
                )
            };
            match result {
                Ok(observation) => atomic(
                    &root.join("regional-contact-status.json"),
                    &observation,
                    64 * 1024,
                )?,
                Err(error) if lock_contention(&error) => atomic(
                    &root.join("regional-contact-status.json"),
                    &unknown_progress(options.currency, region),
                    64 * 1024,
                )?,
                Err(error) => return Err(error),
            }
            let until = monotonic()? + options.interval;
            while !STOP.load(Ordering::Acquire) && monotonic()? < until {
                thread::sleep(Duration::from_millis(10));
            }
        }
        Ok(())
    })();
    running.store(false, Ordering::Release);
    let stopped = inbound
        .join()
        .map_err(|_| "Rust contact listener panicked")?;
    result?;
    stopped?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_lock_contention_is_unknown_then_replays_after_release() {
        let root = directory(
            &fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!("rld-rust-runtime-lock-{}", random().unwrap())),
        )
        .unwrap();
        let genesis = crate::tests::bootstrap();
        let authority = genesis.currency.authority.clone();
        let currency = genesis.currency.id().unwrap();
        let region = genesis.admissions[0].id().unwrap();
        let held =
            Store::create(&root.join("ledger"), genesis, region, &authority, currency).unwrap();
        let head = held.storage_head().unwrap();
        let transport = root.join("transport");
        initialize(
            &transport,
            &currency.to_hex(),
            &region.to_hex(),
            "public-no-value-lock-test",
        )
        .unwrap();
        let config = json!({"format":MESH,"network":currency,"state":transport,"contacts":[]});
        let options = Options {
            ledger: root.join("ledger"),
            authority,
            currency,
            mesh_config: None,
            bft_config: None,
            listen: "127.0.0.1:0".parse().unwrap(),
            miner: None,
            interval: 1.0,
            insecure_tcp: false,
        };
        let mut cursor = None;
        let mut seen = Vec::new();
        let mut runtime = None;
        let failure =
            tick_ledger(&options, &config, &mut runtime, &mut cursor, &mut seen).unwrap_err();
        // Exercise the current production dispatch predicate against an actual
        // Native OS refusal, without creating a synthetic success observation.
        assert!(lock_contention(&failure));
        let unknown = unknown_progress(currency, region);
        assert_eq!(unknown["progress_observation_available"], false);
        for field in ["local_height", "height", "round", "mesh", "ledger_changed"] {
            assert!(unknown.get(field).is_none());
        }
        assert!(cursor.is_none() && seen.is_empty());
        assert_eq!(held.storage_head().unwrap(), head);
        let failure =
            directory_ledger_turn(&options, &config, &mut runtime, &mut cursor, &mut seen)
                .unwrap_err();
        assert!(lock_contention(&failure));
        assert!(cursor.is_none() && seen.is_empty());
        assert_eq!(held.storage_head().unwrap(), head);
        // Capture and the Native refusal both release transport custody leases.
        drop(Node::open(&config).unwrap());
        drop(held);
        let status = tick_ledger(&options, &config, &mut runtime, &mut cursor, &mut seen).unwrap();
        assert_eq!(status["progress_observation_available"], true);
        assert_eq!(status["local_height"], 0);
        let status =
            directory_ledger_turn(&options, &config, &mut runtime, &mut cursor, &mut seen).unwrap();
        assert_eq!(status["progress_observation_available"], true);
        assert_eq!(status["local_height"], 0);
        let cold = Store::open_pinned(&options.ledger, &options.authority, currency, head).unwrap();
        assert_eq!(cold.chain.height(), 0);
        assert_eq!(cold.chain.ledger.minted, crate::Amount::ZERO);
        drop(cold);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_last_directory_contact_reopens_durable_receive_state() {
        let root = directory(
            &fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!("rld-rust-receive-page-{}", random().unwrap())),
        )
        .unwrap();
        let genesis = crate::tests::bootstrap();
        let currency = genesis.currency.id().unwrap();
        let region = genesis.admissions[0].id().unwrap();
        let transport = root.join("transport");
        initialize(
            &transport,
            &currency.to_hex(),
            &region.to_hex(),
            "public-no-value-receive-page-test",
        )
        .unwrap();
        let peer = initialize(
            &root.join("peer"),
            &currency.to_hex(),
            &region.to_hex(),
            "public-no-value-receive-page-peer",
        )
        .unwrap();
        let inbox = directory(&root.join("inbox")).unwrap();
        let config = json!({"format":MESH,"network":currency,"state":transport,
            "contacts":[{"peer":peer["node_id"],"inbox":inbox,"outbox":root.join("outbox")}]});
        drop(Node::open(&config).unwrap());
        let state = transport.join("native-mesh-state.json");
        let before = fs::read(&state).unwrap();
        let invalid = json!({"body":{},"format":"invalid-exchange"});
        let raw = bytes(&invalid).unwrap();
        let path = inbox.join(format!("{}.json", digest(&invalid).unwrap()));
        crate::keystore::private_create(&path, &raw).unwrap();
        start_work_trace();
        let received = directory_receive_page(&config, &|| false, None, &[]).unwrap();
        let work = take_work_trace();
        assert_eq!(received.errors.len(), 1);
        assert!(received.frames.is_empty());
        assert_eq!(fs::read(&path).unwrap(), raw);
        assert_eq!(fs::read(&state).unwrap(), before);
        let opens = work
            .iter()
            .filter(|event| event["phase"] == "mesh-state-decode-expand")
            .map(|event| event["calls"].as_u64().unwrap_or(1))
            .sum::<u64>();
        assert_eq!(opens, 2, "last-contact failure reused uncertain memory");
        drop(Node::open(&config).unwrap());
        fs::write(&state, b"{}").unwrap();
        assert!(directory_receive_page(&config, &|| false, None, &[]).is_err());
        assert_eq!(fs::read(&state).unwrap(), b"{}");
        assert_eq!(fs::read(&path).unwrap(), raw);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn only_exact_native_lock_and_current_os_errnos_defer_progress() {
        assert!(lock_contention(
            &std::fs::TryLockError::WouldBlock.to_string()
        ));
        for code in [libc::EAGAIN, libc::EWOULDBLOCK] {
            assert!(lock_contention(&format!(
                "CONTACT_STORAGE_IO:{code}:OS refusal"
            )));
        }
        for code in [libc::EACCES, libc::EINVAL, libc::EIO, libc::ENOENT] {
            assert!(!lock_contention(&format!(
                "CONTACT_STORAGE_IO:{code}:OS refusal"
            )));
        }
        for error in [
            "resource busy",
            "bad proof: resource busy",
            "operation would block",
            "bad proof: lock acquisition failed because the operation would block",
            "bad proof: CONTACT_STORAGE_IO:11:refusal",
            "CONTACT_STORAGE_IO:110:refusal",
        ] {
            assert!(!lock_contention(error));
        }
    }
}

#[cfg(test)]
#[path = "payment_tests.rs"]
mod payment_tests;

#[cfg(test)]
#[path = "trace_tests.rs"]
mod trace_tests;
