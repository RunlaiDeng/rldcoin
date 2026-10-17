//! Ordinary node contact scheduling. Network workers hold no ledger/custody lock;
//! the main loop alone commits received bytes and native monetary transitions.
use crate::{
    carriage::{Budget, Carriage},
    contact::{peer_id, Frame, Packet},
    kernel::{Hash, Result},
    store::Store,
    tls::{self, Material, Neighbor},
};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, Receiver, SyncSender},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
fn err(e: impl std::fmt::Display) -> String {
    format!("RESOURCE_WAIT network {e}")
}
fn ensure(ok: bool, why: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(why.into())
    }
}
fn bytes32(v: &Value) -> Result<Hash> {
    hex::decode(v.as_str().ok_or("INVALID_ENCODING peer pin")?)
        .map_err(err)?
        .try_into()
        .map_err(|_| "INVALID_ENCODING peer pin".into())
}
fn fresh(path: &Path, raw: &[u8]) -> Result<()> {
    let mut o = OpenOptions::new();
    o.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path).map_err(err)?;
    f.write_all(raw).and_then(|_| f.sync_all()).map_err(err)?;
    File::open(path.parent().ok_or("INVALID_ENCODING material parent")?)
        .and_then(|f| f.sync_all())
        .map_err(err)
}
fn read(path: &Path, max: u64) -> Result<Zeroizing<Vec<u8>>> {
    let mut b = Zeroizing::new(Vec::new());
    File::open(path)
        .map_err(err)?
        .take(max + 1)
        .read_to_end(&mut b)
        .map_err(err)?;
    ensure(b.len() as u64 <= max, "INVALID_ENCODING material bound")?;
    Ok(b)
}
struct Incoming {
    raw: Vec<u8>,
    sender: Hash,
    challenge: Hash,
    reply: SyncSender<Result<Option<Frame>>>,
}
struct Outgoing {
    peer: Hash,
    packet: Hash,
    receipt: Result<Option<Frame>>,
}
pub struct Network {
    chain: Hash,
    key: SigningKey,
    material: Arc<Material>,
    carriage: Carriage,
    neighbors: Vec<Neighbor>,
    listener: SocketAddr,
    incoming: Receiver<Incoming>,
    outgoing: Receiver<Outgoing>,
    outbox: SyncSender<Outgoing>,
    stop: Arc<AtomicBool>,
    listener_thread: Option<JoinHandle<()>>,
    worker: Option<JoinHandle<()>>,
    suppressed: BTreeSet<(Hash, Hash)>,
    unavailable_until: BTreeMap<Hash, Instant>,
    probe: Instant,
    last_tip: Option<Hash>,
    last_scan: Instant,
    diagnostic: Option<String>,
}
impl Drop for Network {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.listener_thread.take() {
            let _ = h.join();
        }
        if let Some(h) = self.worker.take() {
            let _ = h.join();
        }
    }
}
impl Network {
    pub fn open(root: &Path, chain: Hash, config: Option<&[u8]>) -> Result<Self> {
        if !root.exists() {
            fs::create_dir(root).map_err(err)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(root, fs::Permissions::from_mode(0o700)).map_err(err)?;
            }
            File::open(root.parent().ok_or("INVALID_ENCODING network parent")?)
                .and_then(|f| f.sync_all())
                .map_err(err)?;
        }
        let keypath = root.join("contact.secret");
        if !keypath.exists() {
            ensure(
                !root.join("custody").exists(),
                "INVALID_CRYPTO missing retained contact key",
            )?;
            let key = crate::keyfile::generate()?;
            fresh(&keypath, &key.to_bytes())?;
        }
        let seed = read(&keypath, 32)?;
        let seed = Zeroizing::new(
            <[u8; 32]>::try_from(seed.as_slice()).map_err(|_| "INVALID_CRYPTO contact key")?,
        );
        let key = SigningKey::from_bytes(&seed);
        let identity = key.verifying_key().to_bytes();
        let tls_path = root.join("tls.secret");
        if !tls_path.exists() {
            let (cert, secret) = Material::generate(chain, identity)?;
            let mut bytes = Zeroizing::new((cert.len() as u32).to_be_bytes().to_vec());
            bytes.extend(cert);
            bytes.extend(secret.as_slice());
            fresh(&tls_path, &bytes)?;
        }
        let bytes = read(&tls_path, 16384)?;
        ensure(bytes.len() > 4, "INVALID_ENCODING TLS material")?;
        let n = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
        ensure(
            n <= 8192 && 4 + n < bytes.len(),
            "INVALID_ENCODING TLS material",
        )?;
        let material = Arc::new(Material::from_der(
            bytes[4..4 + n].to_vec(),
            Zeroizing::new(bytes[4 + n..].to_vec()),
            chain,
            identity,
        )?);
        let cfg: Value = match config {
            Some(b) => serde_json::from_slice(b).map_err(err)?,
            None => json!({"listen":"127.0.0.1:0","neighbors":[]}),
        };
        let listen: SocketAddr = cfg["listen"]
            .as_str()
            .ok_or("INVALID_ENCODING listen literal")?
            .parse()
            .map_err(err)?;
        let list = cfg["neighbors"]
            .as_array()
            .ok_or("INVALID_ENCODING neighbors")?;
        ensure(list.len() <= 64, "RESOURCE_WAIT neighbor bound")?;
        let mut neighbors = Vec::new();
        let mut identities = BTreeSet::new();
        let mut certificates = BTreeSet::new();
        for n in list {
            let key = bytes32(&n["key"])?;
            let pin = bytes32(&n["certificate_sha256"])?;
            ensure(
                crate::kernel::valid_point(key)
                    && key != identity
                    && identities.insert(key)
                    && certificates.insert(pin),
                "INVALID_CRYPTO neighbor identities/pins",
            )?;
            neighbors.push(Neighbor {
                key,
                endpoint: n["endpoint"]
                    .as_str()
                    .ok_or("INVALID_ENCODING endpoint literal")?
                    .parse()
                    .map_err(err)?,
                certificate_sha256: pin,
            });
        }
        let carriage = Carriage::open(&root.join("custody"), chain, identity, Budget::default())?;
        let listener = TcpListener::bind(listen).map_err(err)?;
        let bound = listener.local_addr().map_err(err)?;
        listener.set_nonblocking(true).map_err(err)?;
        let config = tls::server(&material, chain, neighbors.clone())?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let (tx, incoming) = mpsc::sync_channel::<Incoming>(8);
        let keycopy = key.clone();
        let peers = neighbors.clone();
        let active = Arc::new(AtomicUsize::new(0));
        let listener_thread = thread::spawn(move || {
            while !stopping.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((socket, _)) => {
                        if active.load(Ordering::Relaxed) >= 2 {
                            drop(socket);
                            continue;
                        }
                        active.fetch_add(1, Ordering::Relaxed);
                        let active = active.clone();
                        let config = config.clone();
                        let key = keycopy.clone();
                        let peers = peers.clone();
                        let tx = tx.clone();
                        thread::spawn(move || {
                            let _ = tls::accept(
                                socket,
                                config,
                                chain,
                                &key,
                                &peers,
                                |raw, sender, challenge| {
                                    let (reply, rx) = mpsc::sync_channel(1);
                                    tx.try_send(Incoming {
                                        raw: raw.to_vec(),
                                        sender,
                                        challenge,
                                        reply,
                                    })
                                    .map_err(err)?;
                                    rx.recv_timeout(Duration::from_secs(3)).map_err(err)?
                                },
                            );
                            active.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10))
                    }
                    Err(_) => break,
                }
            }
        });
        let (outbox, outgoing) = mpsc::sync_channel(32);
        Ok(Self {
            chain,
            key,
            material,
            carriage,
            neighbors,
            listener: bound,
            incoming,
            outgoing,
            outbox,
            stop,
            listener_thread: Some(listener_thread),
            worker: None,
            suppressed: BTreeSet::new(),
            unavailable_until: BTreeMap::new(),
            probe: Instant::now(),
            last_tip: None,
            last_scan: Instant::now() - Duration::from_secs(1),
            diagnostic: None,
        })
    }
    pub fn status(&self) -> Value {
        json!({"state":"ACTIVE_GROUND_ADAPTER","identity":hex::encode(self.key.verifying_key().to_bytes()),"peer_id":hex::encode(peer_id(self.key.verifying_key().to_bytes())),"listen":self.listener.to_string(),"certificate_sha256":hex::encode(self.material.fingerprint()),"neighbors":self.neighbors.len().to_string(),"diagnostic":self.diagnostic,"physical_route_qualified":false})
    }
    fn queue(&mut self, destination: Hash, kind: u8, payload: &[u8]) -> Result<()> {
        self.carriage
            .originate(&self.key, destination, kind, payload)?;
        Ok(())
    }
    fn respond(&mut self, store: &mut Store, p: &Packet, now: u64) -> Result<()> {
        if p.destination != [0; 32] && p.destination != peer_id(self.key.verifying_key().to_bytes())
        {
            return Ok(());
        }
        let destination = peer_id(p.origin);
        match p.kind {
            1 | 8 | 9 => {}
            2 => {
                store.submit_transaction(p.id, &p.payload, now)?;
            }
            3 => {
                store.accept(p.id, &p.payload, now)?;
            }
            4 => {
                if p.payload[..32] != store.ledger().tip().id() {
                    self.queue(destination, 6, &store.locator()?)?;
                }
            }
            5 => {
                for e in p.payload[2..].as_chunks::<33>().0 {
                    let id: Hash = e[1..].try_into().unwrap();
                    match e[0] {
                        1 if id == self.chain => {
                            self.queue(destination, 1, store.genesis_bytes())?
                        }
                        3 => {
                            if let Ok(raw) = store.get_block(id) {
                                self.queue(destination, 3, &raw)?;
                            }
                        }
                        _ => {}
                    }
                }
            }
            6 => {
                let inv = store.successor_inventory(&p.payload)?;
                self.queue(destination, 7, &inv)?;
            }
            7 => {
                let mut missing: Vec<u8> = Vec::new();
                for e in p.payload[2..].as_chunks::<33>().0 {
                    let id: Hash = e[1..].try_into().unwrap();
                    if e[0] == 3 && store.get_block(id).is_err() {
                        missing.extend(e)
                    }
                }
                if !missing.is_empty() {
                    let mut req = ((missing.len() / 33) as u16).to_be_bytes().to_vec();
                    req.extend(missing);
                    self.queue(destination, 5, &req)?;
                } else if u16::from_be_bytes(p.payload[..2].try_into().unwrap()) == 128 {
                    self.queue(destination, 6, &store.locator()?)?;
                }
            }
            _ => return Err("UNSUPPORTED_VERSION contact kind".into()),
        }
        Ok(())
    }
    pub fn tick(&mut self, store: &mut Store, now: u64) -> Result<()> {
        while let Ok(i) = self.incoming.try_recv() {
            let result = self
                .carriage
                .receive(&i.raw, i.sender, i.challenge, false, &self.key);
            let return_receipt = match &result {
                Ok(Some(f)) if f.result == Some(1) => {
                    let original = Frame::decode(&i.raw, self.chain)?;
                    original.packet.map(|p| (peer_id(p.origin), f.raw.clone()))
                }
                _ => None,
            };
            let _ = i.reply.send(result);
            if let Some((destination, receipt)) = return_receipt {
                if destination != peer_id(self.key.verifying_key().to_bytes()) {
                    self.queue(destination, 9, &receipt)?;
                }
            }
        }
        while let Ok(o) = self.outgoing.try_recv() {
            match o.receipt {
                Ok(Some(f)) => {
                    if f.result == Some(1) {
                        let p = self
                            .carriage
                            .packet(o.packet)?
                            .ok_or("MISSING_HISTORY outgoing packet")?;
                        self.carriage.retain_destination_receipt(&p, &f)?;
                    }
                    if matches!(f.result, Some(0 | 1)) {
                        // Persist exact hop observations before suppressing, too.
                        self.carriage.retain_hop_receipt(o.packet, &f)?;
                        self.suppressed.insert((o.peer, o.packet));
                    }
                }
                Ok(None) => {
                    self.suppressed.insert((o.peer, o.packet));
                }
                Err(e) => {
                    self.unavailable_until
                        .insert(o.peer, Instant::now() + Duration::from_secs(5));
                    self.diagnostic = Some(e);
                }
            }
        }
        if self.probe.elapsed() >= Duration::from_secs(30) {
            self.suppressed.clear();
            self.probe = Instant::now();
        }
        if self.last_tip != Some(store.ledger().tip().id()) {
            let peers: Vec<_> = self.neighbors.iter().map(|n| peer_id(n.key)).collect();
            let mut head = store.ledger().tip().id().to_vec();
            head.extend(store.ledger().tip().height().to_be_bytes());
            head.extend(store.ledger().tip().work_bytes());
            for peer in peers {
                self.queue(peer, 4, &head)?;
                self.queue(peer, 6, &store.locator()?)?;
            }
            self.last_tip = Some(store.ledger().tip().id());
        }
        if self.last_scan.elapsed() >= Duration::from_millis(200) {
            for p in self.carriage.pending()?.into_iter().take(32) {
                match self.respond(store, &p, now) {
                    Ok(()) => self.carriage.processed(p.id)?,
                    Err(e)
                        if e.contains("MISSING_HISTORY")
                            || e.contains("WAITING_FOR_HISTORY")
                            || e.contains("CLOCK_WAIT")
                            || e.contains("RESOURCE_WAIT") =>
                    {
                        self.diagnostic = Some(e);
                    }
                    Err(e) => {
                        self.diagnostic = Some(e);
                        self.carriage.processed(p.id)?;
                    }
                }
            }
            self.last_scan = Instant::now();
        }
        if self.worker.as_ref().is_some_and(|h| h.is_finished()) {
            if let Some(h) = self.worker.take() {
                let _ = h.join();
            }
        }
        if self.worker.is_none() {
            let keys: Vec<_> = self
                .neighbors
                .iter()
                .filter(|n| {
                    self.unavailable_until
                        .get(&n.key)
                        .is_none_or(|until| Instant::now() >= *until)
                })
                .map(|n| n.key)
                .collect();
            if let Some((peer, packets)) = self.carriage.prepare(&keys, &self.suppressed)? {
                if !packets.is_empty() {
                    let n = self
                        .neighbors
                        .iter()
                        .find(|n| n.key == peer)
                        .ok_or("INVALID_CRYPTO scheduler peer")?
                        .clone();
                    let key = self.key.clone();
                    let material = self.material.clone();
                    let chain = self.chain;
                    let tx = self.outbox.clone();
                    self.worker = Some(thread::spawn(move || {
                        for p in packets {
                            let receipt = tls::deliver(&material, chain, &key, &n, &p);
                            let failed = receipt.is_err();
                            if tx
                                .send(Outgoing {
                                    peer,
                                    packet: p.id,
                                    receipt,
                                })
                                .is_err()
                            {
                                break;
                            }
                            if failed {
                                break;
                            }
                        }
                    }));
                }
            }
        }
        Ok(())
    }
    pub fn queue_transaction(&mut self, raw: &[u8]) -> Result<()> {
        let peers: Vec<_> = self.neighbors.iter().map(|n| peer_id(n.key)).collect();
        for peer in peers {
            self.queue(peer, 2, raw)?;
        }
        Ok(())
    }
}
