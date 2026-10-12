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
    let mut node = Node::open(config)?;
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
            node.receive(&value, peer)?;
            fs::remove_file(&target).map_err(|e| e.to_string())?;
            crate::contact_storage::directory(Path::new(path))?
                .sync_all()
                .map_err(|e| e.to_string())?;
        }
    }
    if let Some(path) = contact["outbox"].as_str() {
        let bundle = node.prepare(peer)?;
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

fn tick_ledger(
    options: &Options,
    config: &Value,
    runtime: &mut Option<super::bft::Runtime>,
    cursor: &mut Option<String>,
    seen: &mut Vec<String>,
) -> Result<Value> {
    // Capture complete received bytes under the transport lock, then release it before native ledger replay.
    let frames = Node::open(config)?.frame_page_selected(cursor.as_deref(), 4, seen)?;
    let mut store = Store::open(&options.ledger, &options.authority, options.currency)?;
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
                runtime.receive(&mut store, raw)?;
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
        runtime.tick(&mut store)?;
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
    if let Some(runtime) = runtime {
        runtime.broadcast(config)?;
    }
    let mut node = Node::open(config)?;
    let adverts = node.advertised_destinations()?;
    for (region, raw) in offers {
        for (destination, label) in &adverts {
            if *label == region.to_hex() {
                node.enqueue(&raw, destination)?;
            }
        }
    }
    node.archive_completed()?;
    Ok(
        json!({"format":FORMAT,"currency":options.currency,"region":region,"local_height":height,
        "mesh":node.observation(),"ledger_changed_by_native_verification_only":true,"fixture_only":true}),
    )
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
            match tick_ledger(
                &options,
                &config,
                &mut bft,
                &mut receive_cursor,
                &mut receive_seen,
            ) {
                Ok(observation) => atomic(
                    &root.join("regional-contact-status.json"),
                    &observation,
                    64 * 1024,
                )?,
                Err(error)
                    if error.contains("resource busy")
                        || error.contains("CONTACT_STORAGE_IO:35:") => {}
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
