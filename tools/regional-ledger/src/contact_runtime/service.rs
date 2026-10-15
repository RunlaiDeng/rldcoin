use super::*;
#[path = "service_carriage_observation.rs"]
mod carriage_observation;
#[cfg(test)]
#[path = "service_independent_transport_tests.rs"]
mod independent_transport_tests;
#[path = "service_native_observation.rs"]
pub(super) mod native_observation;
#[cfg(test)]
#[path = "service_receipt_status_tests.rs"]
mod receipt_status_tests;
#[cfg(test)]
#[path = "regional_payload_decode_tests.rs"]
mod regional_payload_decode_tests;
#[cfg(test)]
#[path = "service_request_mesh_tests.rs"]
mod request_mesh_tests;
#[path = "service_workers.rs"]
mod service_workers;

use crate::{storage::Store, Hash};
use serde_json::{json, Value};
use std::{
    fs,
    net::{SocketAddrV4, TcpListener, TcpStream},
    os::fd::AsRawFd,
    sync::atomic::{AtomicBool, Ordering},
    thread::{self, ScopedJoinHandle},
    time::Duration,
};
#[cfg(test)]
use std::{sync::Arc, thread::JoinHandle};

static STOP: AtomicBool = AtomicBool::new(false);

// Sample the process signal flag only when diagnostics are active. This is
// separate from the scheduler's height/key stop condition and changes no action.
pub(super) fn observe_timeout_step(phase: &str) -> Result<()> {
    native_observation::event(phase, || {
        Ok(json!({"process_stop_requested":STOP.load(Ordering::Acquire)}))
    })
}
#[cfg(test)]
#[path = "post_native_trace.rs"]
mod post_native_trace;
#[cfg(test)]
#[path = "receive_trace.rs"]
mod receive_trace;
#[cfg(test)]
#[path = "receive_turn_trace.rs"]
mod receive_turn_trace;
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
    super::page_watch::observe_retained(&event);
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
fn trace_exchange(
    phase: &str,
    peer: &str,
    bundle: &Value,
    exchange_sha256: &str,
    receive: Option<receive_trace::Observation>,
) -> Result<()> {
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
        let at = monotonic()?;
        let mut event = json!({"phase":phase,"peer":peer,"at":at,"packets":packets,
            "exchange_sha256":exchange_sha256});
        if let Some(receive) = receive {
            require(phase == "durable-transport-receive", "receive clock phase")?;
            event["directory_receive"] = receive.value(at)?;
            if let Some(turn) = receive_turn_trace::observation(receive.file_started)? {
                event["directory_turn"] = turn;
            }
        }
        if phase == "published-transport-exchange" {
            if let Some(prefix) = post_native_trace::observation(at)? {
                event["post_native_work"] = prefix;
                event["node_id"] = bundle["body"]["node_id"].clone();
            }
        }
        records.push(event);
        Ok(())
    })
}
#[cfg(test)]
pub(super) fn start_work_trace() {
    receive_turn_trace::reset();
    SUBWORK_TRACE.with(|trace| trace.borrow_mut().clear());
    CARRIAGE_TRACE.with(|trace| *trace.borrow_mut() = Some(Vec::new()));
}
#[cfg(test)]
pub(super) fn take_work_trace() -> Vec<Value> {
    receive_turn_trace::reset();
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

fn carriage_event(
    observation: &mut Option<carriage_observation::Attempt>,
    phase: &str,
    detail: impl FnOnce() -> Result<Value>,
) {
    if let Some(observation) = observation {
        observation.event(phase, detail);
    }
}

fn carriage_packets(bundle: &Value) -> Result<Value> {
    let transits = bundle["body"]["transits"]
        .as_array()
        .ok_or("carriage diagnostic transits absent")?;
    require(transits.len() <= 4, "carriage diagnostic transit bound")?;
    Ok(json!({
        "packet_ids":transits.iter().map(|transit|&transit["routing"]["body"]["packet_id"]).collect::<Vec<_>>(),
        "frame_ids":transits.iter().map(|transit|&transit["routing"]["body"]["frame_id"]).collect::<Vec<_>>(),
        "destination_ids":transits.iter().map(|transit|&transit["packet"]["body"]["destination"]).collect::<Vec<_>>(),
        "receipt_count":bundle["body"]["receipts"].as_array().ok_or("carriage diagnostic receipts absent")?.len()}))
}

fn incoming_mesh_remaining(deadline: f64) -> Result<f64> {
    require(
        deadline.is_finite(),
        "TLS_TIMEOUT: invalid original incoming deadline",
    )?;
    require(
        !STOP.load(Ordering::Acquire),
        "incoming Mesh acquisition cancelled; retain complete evidence",
    )?;
    let remaining = deadline - monotonic()?;
    require(
        remaining > 0.0,
        "TLS_TIMEOUT: original incoming deadline exhausted; retain complete evidence",
    )?;
    Ok(remaining)
}

#[cfg(test)]
type IncomingMeshDeferObservation = (&'static str, f64, f64);
#[cfg(test)]
thread_local! {
    // Only actual Ok(None) observations enter this test-owned capacity-one
    // channel. The observer never releases a lease or authorizes a request.
    static INCOMING_MESH_DEFER_OBSERVER:
        std::cell::RefCell<Option<std::sync::mpsc::SyncSender<IncomingMeshDeferObservation>>> =
        const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
struct IncomingMeshDeferReset;
#[cfg(test)]
impl Drop for IncomingMeshDeferReset {
    fn drop(&mut self) {
        INCOMING_MESH_DEFER_OBSERVER.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}
#[cfg(test)]
fn install_incoming_mesh_defer_observer() -> Result<(
    IncomingMeshDeferReset,
    std::sync::mpsc::Receiver<IncomingMeshDeferObservation>,
)> {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    INCOMING_MESH_DEFER_OBSERVER.with(|slot| -> Result<()> {
        let mut slot = slot
            .try_borrow_mut()
            .map_err(|_| "incoming Mesh defer observer is borrowed")?;
        require(
            slot.is_none(),
            "incoming Mesh defer observer already installed",
        )?;
        *slot = Some(sender);
        Ok(())
    })?;
    Ok((IncomingMeshDeferReset, receiver))
}
#[cfg(test)]
fn observe_actual_incoming_mesh_defer(phase: &'static str, deadline: f64) {
    if let Ok(observed_at) = monotonic() {
        INCOMING_MESH_DEFER_OBSERVER.with(|observer| {
            if let Ok(observer) = observer.try_borrow() {
                if let Some(sender) = observer.as_ref() {
                    let _ = sender.try_send((phase, deadline, observed_at));
                }
            }
        });
    }
}

fn incoming_node_before_deadline(
    config: &Value,
    deadline: f64,
    phase: &'static str,
) -> Result<Node> {
    require(
        matches!(phase, "challenge" | "custody"),
        "incoming Mesh acquisition phase differs",
    )?;
    loop {
        incoming_mesh_remaining(deadline)?;
        // Only the actual Mesh acquisition WouldBlock may return None. Full
        // identity/state authentication, filesystem and capacity errors refuse.
        match Node::open_or_defer_mesh(config)? {
            Some(node) => {
                // Complete open is not preemptible and may update an advert.
                // Drop a late Node before challenge signing or custody receive.
                incoming_mesh_remaining(deadline)?;
                return Ok(node);
            }
            None => {
                #[cfg(test)]
                observe_actual_incoming_mesh_defer(phase, deadline);
                let remaining = incoming_mesh_remaining(deadline)?;
                // No Node, Native lease or TLS session mutex crosses this wait.
                thread::sleep(Duration::from_secs_f64(remaining.min(0.005)));
            }
        }
    }
}

fn accept(
    config: &Value,
    context: u64,
    material: &Value,
    stream: TcpStream,
    sink: Option<&carriage_observation::Sink>,
) -> Result<()> {
    let mut observation = sink.and_then(|sink| sink.begin_attempt("incoming", || Ok(json!({}))));
    let result = (|| {
        let deadline = monotonic()? + 3.0;
        // Native Accept borrows this descriptor and retains its own duplicate.
        // Keep the original owned until that call returns, including on refusal.
        let fd = stream.as_raw_fd();
        carriage_event(&mut observation, "tls-accept-started", || Ok(json!({})));
        let handle = tls(json!({"Accept":{"context":context,"fd":fd,"deadline":deadline}}))?
            .as_u64()
            .ok_or("TLS accepted handle")?;
        carriage_event(&mut observation, "tls-accept-completed", || Ok(json!({})));
        let connection = Connection(handle);
        drop(stream);
        let (challenge, id, network, peers) = {
            carriage_event(&mut observation, "challenge-open-started", || Ok(json!({})));
            let node = incoming_node_before_deadline(config, deadline, "challenge")?;
            carriage_event(&mut observation, "challenge-open-completed", || {
                Ok(json!({}))
            });
            incoming_mesh_remaining(deadline)?;
            let value=node.sign("tcp-challenge",json!({"format":MESH,"adapter":"RLD-CONTACT-TCP-V4",
            "network":node.network,"node_id":node.id,"nonce":random()?,"tls_cert_sha256":material["fingerprint"]}))?;
            incoming_mesh_remaining(deadline)?;
            (
                value,
                node.id.clone(),
                node.network.clone(),
                node.contacts.keys().cloned().collect::<Vec<_>>(),
            )
        };
        carriage_event(&mut observation, "challenge-send-started", || {
            Ok(json!({"challenge_id":challenge["body"]["nonce"]}))
        });
        incoming_mesh_remaining(deadline)?;
        send(handle, deadline, challenge.clone())?;
        carriage_event(&mut observation, "challenge-send-completed", || {
            Ok(json!({}))
        });
        carriage_event(&mut observation, "request-receive-started", || {
            Ok(json!({}))
        });
        let request = recv(handle, deadline)?;
        carriage_event(&mut observation, "request-receive-completed", || {
            Ok(json!({}))
        });
        let checked = crypto(
            json!({"Exchange":{"TcpRequest":{"network":network,"signed":request,"recipient":id,
        "peers":peers,"nonce":challenge["body"]["nonce"],"limits":limits()}}}),
        )?;
        let peer = checked["body"]["node_id"].as_str().ok_or("request peer")?;
        carriage_event(&mut observation, "request-verified", || {
            let mut detail = carriage_packets(&checked["body"]["bundle"])?;
            detail["peer"] = json!(peer);
            detail["challenge_id"] = checked["body"]["challenge"].clone();
            Ok(detail)
        });
        let response = {
            carriage_event(&mut observation, "custody-open-started", || Ok(json!({})));
            let mut node = incoming_node_before_deadline(config, deadline, "custody")?;
            require(
                node.id == id && node.network == network,
                "incoming custody identity changed after original challenge",
            )?;
            carriage_event(&mut observation, "custody-open-completed", || Ok(json!({})));
            // All incoming bytes are durable before producing a positive acknowledgment.
            carriage_event(&mut observation, "custody-receive-started", || {
                Ok(json!({"peer":peer}))
            });
            incoming_mesh_remaining(deadline)?;
            let retained = node.receive(&checked["body"]["bundle"], peer)?;
            carriage_event(&mut observation, "custody-receive-completed", || {
                Ok(json!({"peer":peer,"retained_packet_ids":retained}))
            });
            // Complete receive may finish after expiry. Keep any real durable
            // custody and report it above, but never turn a late result into ack.
            incoming_mesh_remaining(deadline)?;
            carriage_event(&mut observation, "reply-prepare-started", || Ok(json!({})));
            incoming_mesh_remaining(deadline)?;
            let bundle = node.prepare(peer)?;
            carriage_event(&mut observation, "reply-prepare-completed", || {
                let mut detail = carriage_packets(&bundle)?;
                detail["peer"] = json!(peer);
                Ok(detail)
            });
            incoming_mesh_remaining(deadline)?;
            let response = node.sign("tcp-response",json!({"format":MESH,"adapter":"RLD-CONTACT-TCP-V4","network":network,
            "node_id":id,"to":peer,"nonce":checked["body"]["nonce"],"challenge":checked["body"]["challenge"],
            "exchange_id":digest(&checked["body"]["bundle"])? ,"accepted":true,"bundle":bundle,"error":null}))?;
            incoming_mesh_remaining(deadline)?;
            response
        };
        carriage_event(&mut observation, "reply-send-started", || Ok(json!({})));
        incoming_mesh_remaining(deadline)?;
        send(connection.0, deadline, response)?;
        carriage_event(&mut observation, "reply-send-completed", || Ok(json!({})));
        Ok(())
    })();
    if let Some(observation) = observation {
        observation.finish(&result);
    }
    result
}

pub(super) fn outgoing(config: &Value, peer: &str, contact: &Value) -> Result<()> {
    outgoing_observed(config, peer, contact, None)
}

fn request_mesh_remaining(deadline: f64) -> Result<f64> {
    require(
        deadline.is_finite(),
        "TLS_TIMEOUT: invalid original request deadline",
    )?;
    require(
        !STOP.load(Ordering::Acquire),
        "outgoing request binding cancelled; retain complete evidence",
    )?;
    let remaining = deadline - monotonic()?;
    require(
        remaining > 0.0,
        "TLS_TIMEOUT: original request deadline exhausted; retain complete evidence",
    )?;
    Ok(remaining)
}

#[cfg(test)]
thread_local! {
    // A bounded observation of an actual acquisition deferral; it cannot release
    // a lease or authorize a request in the service thread.
    static REQUEST_MESH_DEFER_OBSERVER:
        std::cell::RefCell<Option<std::sync::mpsc::SyncSender<(f64, f64)>>> =
        const { std::cell::RefCell::new(None) };
    static REQUEST_MESH_PREPARED_SHA: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn observe_actual_request_mesh_defer(deadline: f64) {
    if let Ok(observed_at) = monotonic() {
        REQUEST_MESH_DEFER_OBSERVER.with(|observer| {
            if let Some(sender) = observer.borrow().as_ref() {
                let _ = sender.try_send((deadline, observed_at));
            }
        });
    }
}

fn request_node_before_deadline(config: &Value, deadline: f64) -> Result<Node> {
    loop {
        request_mesh_remaining(deadline)?;
        // Only Mesh acquisition WouldBlock returns None. Full authentication,
        // filesystem and capacity errors still refuse immediately.
        match Node::open_or_defer_mesh(config)? {
            Some(node) => {
                // Complete open cannot be preempted and may update an advert.
                // A late result must be dropped before request signing.
                request_mesh_remaining(deadline)?;
                return Ok(node);
            }
            None => {
                #[cfg(test)]
                observe_actual_request_mesh_defer(deadline);
                let remaining = request_mesh_remaining(deadline)?;
                // No Node, Native lease or TLS mutex is held while waiting.
                thread::sleep(Duration::from_secs_f64(remaining.min(0.005)));
            }
        }
    }
}

fn reply_mesh_remaining(deadline: f64) -> Result<f64> {
    require(
        deadline.is_finite(),
        "TLS_TIMEOUT: invalid original reply custody deadline",
    )?;
    require(
        !STOP.load(Ordering::Acquire),
        "outgoing reply custody cancelled; retain complete evidence",
    )?;
    let remaining = deadline - monotonic()?;
    require(
        remaining > 0.0,
        "TLS_TIMEOUT: original reply custody deadline exhausted; retain complete evidence",
    )?;
    Ok(remaining)
}

#[cfg(test)]
type ReplyMeshDeferObservation = (&'static str, f64, f64);
#[cfg(test)]
thread_local! {
    static REPLY_MESH_DEFER_OBSERVER:
        std::cell::RefCell<Option<std::sync::mpsc::SyncSender<ReplyMeshDeferObservation>>> =
        const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
struct ReplyMeshDeferReset;
#[cfg(test)]
impl Drop for ReplyMeshDeferReset {
    fn drop(&mut self) {
        REPLY_MESH_DEFER_OBSERVER.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}
#[cfg(test)]
fn install_reply_mesh_defer_observer() -> Result<(
    ReplyMeshDeferReset,
    std::sync::mpsc::Receiver<ReplyMeshDeferObservation>,
)> {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    REPLY_MESH_DEFER_OBSERVER.with(|slot| -> Result<()> {
        let mut slot = slot
            .try_borrow_mut()
            .map_err(|_| "reply Mesh defer observer is borrowed")?;
        require(
            slot.is_none(),
            "reply Mesh defer observer already installed",
        )?;
        *slot = Some(sender);
        Ok(())
    })?;
    Ok((ReplyMeshDeferReset, receiver))
}
#[cfg(test)]
fn observe_actual_reply_mesh_defer(deadline: f64) {
    if let Ok(observed_at) = monotonic() {
        REPLY_MESH_DEFER_OBSERVER.with(|slot| {
            if let Ok(observer) = slot.try_borrow() {
                if let Some(sender) = observer.as_ref() {
                    let _ = sender.try_send(("reply-custody", deadline, observed_at));
                }
            }
        });
    }
}

fn reply_node_before_deadline(
    config: &Value,
    deadline: f64,
    prepared_id: &str,
    prepared_network: &str,
) -> Result<Node> {
    loop {
        reply_mesh_remaining(deadline)?;
        // Only actual Mesh acquisition WouldBlock returns None. A complete
        // open may update an advert and cannot be hard-preempted; all errors
        // remain original errors, and no unchecked Node is retained or reused.
        match Node::open_or_defer_mesh(config)? {
            Some(node) => {
                require(
                    node.id == prepared_id && node.network == prepared_network,
                    "reply custody identity changed after original preparation",
                )?;
                reply_mesh_remaining(deadline)?;
                return Ok(node);
            }
            None => {
                #[cfg(test)]
                observe_actual_reply_mesh_defer(deadline);
                let remaining = reply_mesh_remaining(deadline)?;
                // No Node, Native lease or TLS session mutex crosses this wait.
                thread::sleep(Duration::from_secs_f64(remaining.min(0.005)));
            }
        }
    }
}

fn outgoing_observed(
    config: &Value,
    peer: &str,
    contact: &Value,
    sink: Option<&carriage_observation::Sink>,
) -> Result<()> {
    let mut observation =
        sink.and_then(|sink| sink.begin_attempt("outgoing", || Ok(json!({"peer":peer}))));
    let result = (|| {
        // The preparation and cursor commit completes before opening a socket.
        let (bundle, id, network) = {
            carriage_event(&mut observation, "prepare-open-started", || Ok(json!({})));
            let mut node = Node::open(config)?;
            carriage_event(&mut observation, "prepare-open-completed", || Ok(json!({})));
            carriage_event(&mut observation, "prepare-started", || Ok(json!({})));
            let bundle = node.prepare(peer)?;
            carriage_event(&mut observation, "prepare-completed", || {
                carriage_packets(&bundle)
            });
            (bundle, node.id.clone(), node.network.clone())
        };
        #[cfg(test)]
        REQUEST_MESH_DEFER_OBSERVER.with(|observer| {
            if observer.borrow().is_some() {
                if let Ok(raw) = bytes(&bundle) {
                    REQUEST_MESH_PREPARED_SHA.with(|slot| {
                        *slot.borrow_mut() = Some(hex::encode(Sha256::digest(raw)));
                    });
                }
            }
        });
        let deadline = monotonic()? + 3.0;
        carriage_event(&mut observation, "connect-started", || {
            Ok(json!({"peer":peer}))
        });
        let handle=tls(json!({"Connect":{"host":contact["host"],"port":contact["port"],
        "fingerprint":contact["tls_cert_sha256"],"network":network,"peer":peer,"deadline":deadline}}))?.as_u64().ok_or("TLS connected handle")?;
        carriage_event(&mut observation, "connect-completed", || Ok(json!({})));
        let connection = Connection(handle);
        carriage_event(&mut observation, "challenge-receive-started", || {
            Ok(json!({}))
        });
        let challenge = recv(handle, deadline)?;
        carriage_event(&mut observation, "challenge-receive-completed", || {
            Ok(json!({}))
        });
        let verified = crypto(
            json!({"Exchange":{"Challenge":{"network":network,"signed":challenge,"peer":peer,"fingerprint":contact["tls_cert_sha256"]}}}),
        )?;
        carriage_event(&mut observation, "challenge-verified", || {
            Ok(json!({"challenge_id":verified["body"]["nonce"]}))
        });
        let request = {
            carriage_event(&mut observation, "request-open-started", || Ok(json!({})));
            let node = request_node_before_deadline(config, deadline)?;
            carriage_event(&mut observation, "request-open-completed", || Ok(json!({})));
            require(
                node.id == id && node.network == network,
                "request identity changed after original preparation",
            )?;
            let body = json!({"format":MESH,"adapter":"RLD-CONTACT-TCP-V4",
        "network":network,"node_id":id,"to":peer,"nonce":random()?,"challenge":verified["body"]["nonce"],"bundle":bundle});
            request_mesh_remaining(deadline)?;
            node.sign("tcp-request", body)?
        };
        // Signing can finish after expiry; never emit that late result.
        request_mesh_remaining(deadline)?;
        carriage_event(&mut observation, "request-send-started", || {
            Ok(json!({"challenge_id":request["body"]["challenge"]}))
        });
        request_mesh_remaining(deadline)?;
        send(handle, deadline, request.clone())?;
        carriage_event(&mut observation, "request-send-completed", || Ok(json!({})));
        carriage_event(&mut observation, "reply-receive-started", || Ok(json!({})));
        let response = recv(handle, deadline)?;
        carriage_event(&mut observation, "reply-receive-completed", || {
            Ok(json!({}))
        });
        let checked = crypto(
            json!({"Exchange":{"TcpResponse":{"network":network,"signed":response,"requester":id,
        "peer":peer,"sent":request,"limits":limits()}}}),
        )?;
        require(
            checked["body"]["accepted"] == true,
            "peer did not acknowledge custody; retain complete evidence",
        )?;
        carriage_event(&mut observation, "reply-verified", || {
            let mut detail = carriage_packets(&checked["body"]["bundle"])?;
            detail["peer"] = json!(peer);
            detail["exchange_id"] = checked["body"]["exchange_id"].clone();
            detail["challenge_id"] = checked["body"]["challenge"].clone();
            Ok(detail)
        });
        // A verified socket reply alone does not suppress carriage. Retain its complete bundle locally.
        carriage_event(&mut observation, "reply-custody-open-started", || {
            Ok(json!({}))
        });
        let mut node = reply_node_before_deadline(config, deadline, &id, &network)?;
        carriage_event(&mut observation, "reply-custody-open-completed", || {
            Ok(json!({}))
        });
        carriage_event(&mut observation, "reply-custody-receive-started", || {
            Ok(json!({}))
        });
        reply_mesh_remaining(deadline)?;
        let retained = node.receive(&checked["body"]["bundle"], peer)?;
        // Complete receive may finish late. Report and retain genuine durable
        // custody before refusing expiry/STOP; never roll back real evidence.
        carriage_event(&mut observation, "reply-custody-receive-completed", || {
            Ok(json!({"peer":peer,"retained_packet_ids":retained}))
        });
        let original_identity = node.id == id && node.network == network;
        drop(node);
        require(
            original_identity,
            "reply custody identity changed during receive",
        )?;
        reply_mesh_remaining(deadline)?;
        drop(connection);
        Ok(())
    })();
    if let Some(observation) = observation {
        observation.finish(&result);
    }
    result
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

#[cfg(test)]
pub(super) fn directory_publish_fixture(config: &Value) -> Result<Vec<String>> {
    directory_phase(config, &|| false, DirectoryPhase::Publish)
}

#[cfg(test)]
pub(super) fn directory_receive_fixture(config: &Value) -> Result<Vec<String>> {
    directory_phase(config, &|| false, DirectoryPhase::Receive)
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
    #[cfg(test)]
    receive_turn_trace::open_started(monotonic)?;
    let node = Node::open(config)?;
    #[cfg(test)]
    receive_turn_trace::open_completed(monotonic)?;
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
    let contacts = contacts.into_iter();
    #[cfg(test)]
    let contacts = contacts.enumerate();
    for entry in contacts {
        #[cfg(test)]
        let (peer_index, (peer, contact)) = entry;
        #[cfg(not(test))]
        let (peer, contact) = entry;
        #[cfg(test)]
        receive_turn_trace::peer(peer_index)?;
        if stopped() {
            #[cfg(test)]
            receive_turn_trace::unsuccessful();
            break;
        }
        if node.is_none() {
            #[cfg(test)]
            receive_turn_trace::open_started(monotonic)?;
            match Node::open(config) {
                Ok(reopened) => {
                    #[cfg(test)]
                    receive_turn_trace::open_completed(monotonic)?;
                    *node = Some(reopened);
                }
                Err(error) => {
                    #[cfg(test)]
                    receive_turn_trace::unsuccessful();
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
            #[cfg(test)]
            receive_turn_trace::unsuccessful();
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
        #[cfg(test)]
        receive_turn_trace::open_started(monotonic)?;
        node = Some(Node::open(config)?);
        #[cfg(test)]
        receive_turn_trace::open_completed(monotonic)?;
    }
    #[cfg(test)]
    let started = monotonic()?;
    let frames = node
        .as_ref()
        .ok_or("missing receive page node")?
        .frame_page_selected(cursor, 4, seen)?;
    #[cfg(test)]
    let selection = super::page_observation::take();
    #[cfg(test)]
    CARRIAGE_TRACE.with(|trace| -> Result<()> {
        let mut trace = trace.borrow_mut();
        if let Some(records) = trace.as_mut() {
            require(records.len() < 4096, "diagnostic carriage record bound")?;
            let mut event = json!({"phase":"native-page-selected","at":monotonic()?,
                "packet_ids":frames.iter().map(|(id,_)|id).collect::<Vec<_>>(),
                "after":cursor,"seen_count":seen.len(),"native_authority":false});
            if let Some(selection) = selection {
                event["selection"] = selection;
            }
            records.push(event);
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
        #[cfg(test)]
        receive_turn_trace::inventory_started(monotonic)?;
        let inventory = crate::contact_spool::execute(
            &bytes(&json!({"Inventory":{"path":path,"adapter":adapter,"limits":limits}}))?,
            &[],
            &[],
        )?;
        #[cfg(test)]
        receive_turn_trace::inventory_completed(monotonic)?;
        let names = inventory["files"]
            .as_array()
            .ok_or("spool files")?
            .iter()
            .take(4);
        #[cfg(test)]
        let names = names.enumerate();
        for entry in names {
            #[cfg(test)]
            let (file_index, name) = entry;
            #[cfg(not(test))]
            let name = entry;
            #[cfg(test)]
            receive_turn_trace::file(file_index)?;
            let name = name.as_str().ok_or("spool filename")?;
            let target = Path::new(path).join(name);
            #[cfg(test)]
            let file_started = monotonic()?;
            let encoded = files::private_read_with_limit(&target, EXCHANGE_LIMIT)?;
            #[cfg(test)]
            let read_completed = monotonic()?;
            let raw = if compressed {
                codec("Decode", &encoded)?
            } else {
                encoded
            };
            #[cfg(test)]
            let codec_completed = monotonic()?;
            let value = crate::wallet_http::decode_unique_with_limit(&raw, EXCHANGE_LIMIT)?;
            #[cfg(test)]
            let parse_completed = monotonic()?;
            require(
                bytes(&value)? == raw
                    && name == format!("{}.json", hex::encode(Sha256::digest(&raw))),
                "spool exact canonical exchange filename",
            )?;
            #[cfg(test)]
            let started = monotonic()?;
            node.receive(&value, peer)?;
            #[cfg(test)]
            let receive_completed = monotonic()?;
            #[cfg(test)]
            trace_work("mesh-receive", started)?;
            #[cfg(test)]
            trace_exchange(
                "durable-transport-receive",
                peer,
                &value,
                name.strip_suffix(".json")
                    .ok_or("diagnostic exchange filename")?,
                Some(receive_trace::Observation {
                    file_started,
                    read_completed,
                    codec_completed,
                    parse_completed,
                    canonical_checked: started,
                    receive_completed,
                }),
            )?;
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
        let data_sha256 = hex::encode(Sha256::digest(&raw));
        let encoded = if compressed {
            codec("Encode", &raw)?
        } else {
            raw.clone()
        };
        let target = Path::new(path).join(format!("{data_sha256}.json"));
        crate::contact_spool::execute(
            &bytes(
                &json!({"Publish":{"path":target,"adapter":adapter,"limits":limits,
            "encoded_size":encoded.len(),"encoded_sha256":hex::encode(Sha256::digest(&encoded)),
            "data_size":raw.len(),"data_sha256":data_sha256}}),
            )?,
            &encoded,
            &raw,
        )?;
        #[cfg(test)]
        trace_exchange(
            "published-transport-exchange",
            peer,
            &bundle,
            &data_sha256,
            None,
        )?;
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
    native_observation::event("mesh-receive-started", || Ok(json!({})))?;
    let node = if runtime.is_some() {
        Node::open_or_defer_mesh(config)?
    } else {
        Some(Node::open(config)?)
    };
    let receive_deferred = node.is_none();
    let frames = match node {
        Some(node) => node.frame_page_selected(cursor.as_deref(), 4, seen)?,
        // No transport input was inspected. The cursor and seen set stay
        // unchanged; only already authenticated Native material is available
        // to the original Runtime. All later errors retain their meaning.
        None => Vec::new(),
    };
    native_observation::event("mesh-receive-completed", || {
        Ok(
            json!({"deferred":receive_deferred,"frame_count":frames.len(),
            "frame_packet_ids":frames.iter().map(|frame|&frame.0).collect::<Vec<_>>(),
            "cursor_before":cursor,"seen_count_before":seen.len()}),
        )
    })?;
    #[cfg(test)]
    trace_work("mesh-native-page", started)?;
    let mut tick = tick_ledger_frames(options, config, runtime, cursor, seen, frames, None)?;
    tick.observation["transport_receive_deferred"] = json!(receive_deferred);
    Ok(tick.observation)
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
    native_observation::event("native-store-open-started", || Ok(json!({})))?;
    #[cfg(test)]
    let started = monotonic()?;
    let mut store = Store::open(&options.ledger, &options.authority, options.currency)?;
    native_observation::event("native-store-open-completed", || {
        Ok(json!({"height":store.chain.height(),"region":store.chain.region}))
    })?;
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
        native_observation::event("native-frame-started", || {
            Ok(json!({"packet_id":id,"frame_id":frame.message_id,"kind":frame.kind}))
        })?;
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
            native_observation::event("native-frame-completed", || {
                Ok(
                    json!({"packet_id":id,"frame_id":frame.message_id,"height":store.chain.height(),
                    "handler":"regional-bft","runtime_present":runtime.is_some()}),
                )
            })?;
            *cursor = Some(id.clone());
            continue;
        }
        if frame.kind == "source-finality" {
            let (_, history) = crate::contact::Frame::unpack_origin(raw)?;
            store.accept_complete_origin_history(history)?;
        } else if frame.kind == "onward-source-finality" {
            let (_, history) = crate::contact::Frame::unpack_onward(raw)?;
            // Native keeps authentic ancestor conflicts before any later
            // proof refusal. Transport custody alone never credits a coin.
            store.accept_complete_onward_network_history(history)?;
        } else {
            store.contact_apply(raw, options.miner.clone())?;
        }
        native_observation::event("native-frame-completed", || {
            Ok(
                json!({"packet_id":id,"frame_id":frame.message_id,"height":store.chain.height(),
                "handler":frame.kind}),
            )
        })?;
        *cursor = Some(id.clone());
    }
    if let Some(runtime) = runtime {
        native_observation::event("native-runtime-started", || Ok(json!({})))?;
        #[cfg(test)]
        let started = monotonic()?;
        runtime.tick(&mut store)?;
        native_observation::event("native-runtime-completed", || {
            Ok(json!({"height":store.chain.height()}))
        })?;
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
    native_observation::event("native-store-released", || {
        Ok(json!({"height":height,"region":region}))
    })?;
    #[cfg(test)]
    let _post_native = if directory.is_some() && runtime.is_some() {
        post_native_trace::begin(|| {
            Ok(
                json!({"currency":options.currency,"region":region,"native_height":height,
                "scheduling":runtime.as_ref().ok_or("post-Native runtime absent")?.diagnostic_clock(),
                "signing_authority":false}),
            )
        })?
    } else {
        None
    };
    // Native replay and signing finish before opening this custody lease.
    // Directory-only carriage shares it through durable preparation; socket
    // adapters retain their original independent open/wait boundaries.
    let first = if directory.is_some() {
        native_observation::event("post-native-mesh-started", || Ok(json!({})))?;
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
        native_observation::event("post-native-mesh-started", || Ok(json!({})))?;
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
    native_observation::event("post-native-mesh-open-completed", || Ok(json!({})))?;
    let node_ref = node.as_mut().ok_or("missing post-ledger custody node")?;
    let adverts = node_ref.advertised_destinations()?;
    for (region, raw) in offers {
        for (destination, label) in &adverts {
            if *label == region.to_hex() {
                node_ref.enqueue(&raw, destination)?;
            }
        }
    }
    #[cfg(test)]
    let archive_started = payment_trace_enabled().then(monotonic).transpose()?;
    native_observation::event("mesh-archive-started", || Ok(json!({})))?;
    node_ref.archive_completed()?;
    native_observation::event("mesh-archive-completed", || Ok(json!({})))?;
    #[cfg(test)]
    if let Some(started) = archive_started {
        trace_subwork("mesh-archive-completed", started)?;
    }
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
    #[cfg(test)]
    let receive_turn = receive_turn_trace::begin(
        CARRIAGE_TRACE.with(|trace| trace.borrow().is_some()),
        monotonic,
    )?;
    let received = directory_receive_page(config, stopped, cursor.as_deref(), seen)?;
    #[cfg(test)]
    receive_turn_trace::end_receive();
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
    #[cfg(test)]
    if let Some(receive_turn) = receive_turn {
        receive_turn.finish(errors.is_empty(), monotonic)?;
    }
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
    let native_observation_enabled = native_observation::enabled_from_env()?;
    let carriage_observation_enabled = carriage_observation::enabled_from_env()?;
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
    if let Some(path) = &options.bft_config {
        super::bft::Runtime::preflight_service(path, &store)?;
    } else {
        // The new receiver requires its explicit, matching BFT Runtime.
        // Generic startup and uncertified mining retain their old refusal.
        crate::paged_bft::require_runtime_adoption(&store.trust.region(region)?.rules)?;
    }
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
    let directory_only = contacts
        .values()
        .all(|contact| contact.get("host").is_none());
    let service_instance = random()?;
    let carriage_started = carriage_observation::start(
        carriage_observation_enabled,
        &root,
        &service_instance,
        options.currency,
        region,
        &id,
    );
    let (carriage_observer, carriage_start_error) = match carriage_started {
        Ok(observer) => (observer, None),
        Err(error) => {
            eprintln!("carriage diagnostic unavailable; ordinary transport continues");
            (None, Some(error))
        }
    };
    let carriage_sink = carriage_observer
        .as_ref()
        .and_then(|observer| observer.sink());
    let mut workers = service_workers::Workers::new();
    if !directory_only {
        let outgoing_config = config.clone();
        let outgoing_sink = carriage_sink.clone();
        let interval = options.interval;
        workers.spawn("Rust contact outgoing", move |running| {
            // One ordered sweep at a time, with no queued catch-up sweeps.
            // Network waits never prevent the caller's sole Native Runtime
            // from attempting its next turn. Every contact still prepares,
            // authenticates and durably retains through the ordinary path.
            while running.load(Ordering::Acquire) && !STOP.load(Ordering::Acquire) {
                for (peer, contact) in &contacts {
                    if !running.load(Ordering::Acquire) || STOP.load(Ordering::Acquire) {
                        break;
                    }
                    let result = if contact.get("host").is_some() {
                        outgoing_observed(&outgoing_config, peer, contact, outgoing_sink.as_ref())
                    } else {
                        spool(&outgoing_config, peer, contact)
                    };
                    if let Err(error) = result {
                        eprintln!("contact attempt retained without custody claim: {error}");
                    }
                }
                let until = monotonic()? + interval;
                while running.load(Ordering::Acquire)
                    && !STOP.load(Ordering::Acquire)
                    && monotonic()? < until
                {
                    thread::sleep(Duration::from_millis(10));
                }
            }
            Ok(())
        })?;
    }
    let inbound_config = config.clone();
    let material = context["material"].clone();
    let handle = context_handle.0;
    let inbound_sink = carriage_sink.clone();
    workers.spawn("Rust contact listener", move |inbound_running| {
        thread::scope(|scope| {
            let mut workers: Vec<ScopedJoinHandle<'_, Result<()>>> = Vec::new();
            let result = (|| {
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
                            let sink = inbound_sink.clone();
                            workers.push(
                                thread::Builder::new()
                                    .name("Rust contact receive".into())
                                    .spawn_scoped(scope, move || {
                                        accept(&config, handle, &material, stream, sink.as_ref())
                                    })
                                    .map_err(|e| e.to_string())?,
                            );
                        }
                        Ok((stream, _)) => drop(stream),
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10))
                        }
                        Err(e) => return Err(e.to_string()),
                    }
                }
                Ok(())
            })();
            let mut stopped = Ok(());
            for worker in workers {
                match worker.join() {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => eprintln!("inbound contact refused: {error}"),
                    Err(_) => stopped = Err("inbound worker panicked".to_string()),
                }
            }
            preserve_cleanup_error(result, stopped)
        })
    })?;
    let native_observer = native_observation::start(
        native_observation_enabled,
        &root,
        &service_instance,
        options.currency,
        region,
        &id,
    )?;
    let mut completed_turns = 0u64;
    let result = (|| {
        while !STOP.load(Ordering::Acquire) {
            workers.require_running()?;
            let turn_started = monotonic()?;
            native_observation::begin_turn(turn_started)?;
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
            // Preserve the original Native/transport error if the observer also
            // fails. A diagnostic failure never turns that refusal into success.
            let observation_end = native_observation::end_turn(&result);
            let result = match (result, observation_end) {
                (Err(error), Err(observer)) => {
                    Err(format!("{error}; Native observation: {observer}"))
                }
                (Err(error), Ok(())) => Err(error),
                (Ok(_), Err(observer)) => Err(observer),
                (Ok(value), Ok(())) => Ok(value),
            };
            match result {
                Ok(mut observation) => {
                    if observation["progress_observation_available"] == true {
                        let completed = monotonic()?;
                        require(
                            completed >= turn_started,
                            "service turn clock moved backwards",
                        )?;
                        completed_turns = completed_turns
                            .checked_add(1)
                            .ok_or("service turn observation counter exhausted")?;
                        // Local diagnostics only, never authorization or a
                        // scheduling clock. Each successful turn now publishes
                        // a changed status even when ledger/mesh state is equal;
                        // immutable evidence retains its exact-byte reuse.
                        observation["service_turn"] = json!({
                            "instance":service_instance,"pid":std::process::id(),
                            "sequence":completed_turns,"started_at":turn_started,
                            "completed_at":completed,"clock":"local-monotonic-seconds",
                            "diagnostic_only":true
                        });
                    }
                    atomic(
                        &root.join("regional-contact-status.json"),
                        &observation,
                        64 * 1024,
                    )?;
                }
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
    let observation_ended = match native_observer {
        Some(observer) => observer.finish(result.is_ok()),
        None => Ok(()),
    };
    let result = preserve_cleanup_error(result, observation_ended);
    let stopped = workers.finish();
    let result = preserve_cleanup_error(result, stopped);
    // All ordinary workers and their incoming tasks have actually joined.
    // Close every producer before sealing only the diagnostic collector.
    drop(carriage_sink);
    let observation_ended = match carriage_observer {
        Some(observer) => observer.finish(result.is_ok()),
        None => Ok(()),
    };
    let result = preserve_cleanup_error(result, observation_ended);
    preserve_cleanup_error(result, carriage_start_error.map_or(Ok(()), Err))
}

fn preserve_cleanup_error(result: Result<()>, stopped: Result<()>) -> Result<()> {
    match (result, stopped) {
        (Err(error), Err(cleanup)) => Err(format!("{error}; contact worker cleanup: {cleanup}")),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_socket_owned_by_service_closes_on_tls_refusal() {
        use std::io::Read;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let (accepted, _) = listener.accept().unwrap();
        let result = accept(&Value::Null, u64::MAX, &Value::Null, accepted, None);
        assert_eq!(result.unwrap_err(), "TLS context handle absent");
        // Peer EOF proves the owned accepted stream is closed without
        // probing or closing a descriptor number another test could reuse.
        assert_eq!(client.read(&mut [0u8; 1]).unwrap(), 0);
    }

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
        let turn = receive_turn_trace::begin(true, monotonic).unwrap().unwrap();
        let received = directory_receive_page(&config, &|| false, None, &[]).unwrap();
        receive_turn_trace::end_receive();
        turn.finish(true, || panic!("failed receive turn cannot complete"))
            .unwrap();
        drop(turn);
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
