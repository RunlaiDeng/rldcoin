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
    path::{Path, PathBuf},
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
pub(crate) type BackupMaterial = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>, Vec<u8>);
pub struct Network {
    root: PathBuf,
    config: Vec<u8>,
    chain: Hash,
    key: SigningKey,
    material: Arc<Material>,
    pub(crate) carriage: Carriage,
    neighbors: Vec<Neighbor>,
    offline_peers: Vec<Hash>,
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
    last_announce: Instant,
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
            File::open(
                root.parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new(".")),
            )
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
        let mut offline_peers = Vec::new();
        if let Some(peers) = cfg.get("offline_peers") {
            let peers = peers
                .as_array()
                .ok_or("INVALID_ENCODING offline peer list")?;
            ensure(peers.len() <= 64, "RESOURCE_WAIT offline peer bound")?;
            for p in peers {
                let k = bytes32(p)?;
                ensure(
                    crate::kernel::valid_point(k) && k != identity && !offline_peers.contains(&k),
                    "INVALID_CRYPTO offline peer",
                )?;
                offline_peers.push(k);
            }
        }
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
            root: root.to_path_buf(),
            config: serde_json::to_vec(&cfg).map_err(err)?,
            chain,
            key,
            material,
            carriage,
            neighbors,
            offline_peers,
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
            last_announce: Instant::now() - Duration::from_secs(1),
            last_scan: Instant::now() - Duration::from_secs(1),
            diagnostic: None,
        })
    }
    pub fn status(&self) -> Value {
        json!({"state":"ACTIVE_GROUND_ADAPTER","identity":hex::encode(self.key.verifying_key().to_bytes()),"peer_id":hex::encode(peer_id(self.key.verifying_key().to_bytes())),"listen":self.listener.to_string(),"certificate_sha256":hex::encode(self.material.fingerprint()),"neighbors":self.neighbors.len().to_string(),"diagnostic":self.diagnostic,"physical_route_qualified":false})
    }
    fn queue(&mut self, destination: Hash, kind: u8, payload: &[u8]) -> Result<()> {
        self.carriage
            .originate_unique(&self.key, destination, kind, payload)?;
        Ok(())
    }
    fn apply_history_group(
        &mut self,
        store: &mut Store,
        pending: &[Packet],
        now: u64,
    ) -> Result<BTreeSet<Hash>> {
        let local = peer_id(self.key.verifying_key().to_bytes());
        let mut parent = store.ledger().tip().id();
        let mut blocks = Vec::new();
        let mut packets = BTreeSet::new();
        let mut intent = Vec::new();
        for _ in 0..32 {
            let Some(p) = pending.iter().find(|p| {
                p.kind == 3
                    && (p.destination == [0; 32] || p.destination == local)
                    && p.payload[36..68] == parent
                    && !packets.contains(&p.id)
            }) else {
                break;
            };
            // Header hints only choose work to validate. The ordinary kernel
            // executes every complete member before either durable commit.
            parent = crate::kernel::block_id(&p.payload)?;
            blocks.push(p.payload.clone());
            packets.insert(p.id);
            intent.extend(p.id);
        }
        if blocks.len() < 2 {
            return Ok(BTreeSet::new());
        }
        let operation = crate::kernel::hash("HISTORY-OP", &intent);
        store.accept_history(operation, &blocks, now)?;
        for packet in &packets {
            self.carriage.processed(*packet)?;
        }
        Ok(packets)
    }
    fn respond(&mut self, store: &mut Store, p: &Packet, now: u64) -> Result<()> {
        if p.destination != [0; 32] && p.destination != peer_id(self.key.verifying_key().to_bytes())
        {
            return Ok(());
        }
        let destination = peer_id(p.origin);
        match p.kind {
            1 | 9 => {}
            8 => {
                if self.carriage.discover(p)? {
                    let peers: BTreeSet<_> = self
                        .neighbors
                        .iter()
                        .map(|n| peer_id(n.key))
                        .chain(self.offline_peers.iter().map(|k| peer_id(*k)))
                        .collect();
                    for peer in peers {
                        if peer != peer_id(p.origin) {
                            self.queue(peer, 8, p.payload())?;
                        }
                    }
                }
            }
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
                        2 => {
                            if let Ok(raw) = store.get_transaction(id) {
                                self.queue(destination, 2, &raw)?;
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
                let retained = self.carriage.pending_block_ids()?;
                for e in p.payload[2..].as_chunks::<33>().0 {
                    let id: Hash = e[1..].try_into().unwrap();
                    if e[0] == 3 && store.get_block(id).is_err() && !retained.contains(&id) {
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
        for _ in 0..8 {
            let Ok(i) = self.incoming.try_recv() else {
                break;
            };
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
        for _ in 0..32 {
            let Ok(o) = self.outgoing.try_recv() else {
                break;
            };
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
        if self.last_tip != Some(store.ledger().tip().id())
            && self.last_announce.elapsed() >= Duration::from_secs(1)
        {
            let peers: BTreeSet<_> = self
                .neighbors
                .iter()
                .map(|n| peer_id(n.key))
                .chain(self.offline_peers.iter().map(|k| peer_id(*k)))
                .collect();
            let mut head = store.ledger().tip().id().to_vec();
            for raw in store.template_transactions()? {
                self.queue_transaction(&raw)?;
            }
            head.extend(store.ledger().tip().height().to_be_bytes());
            head.extend(store.ledger().tip().work_bytes());
            let introductions: BTreeSet<_> = self
                .neighbors
                .iter()
                .map(|n| n.key)
                .chain(self.offline_peers.iter().copied())
                .chain([self.key.verifying_key().to_bytes()])
                .collect();
            let introductions: Vec<_> = introductions.into_iter().collect();
            for peer in peers {
                self.queue(peer, 4, &head)?;
                self.queue(peer, 6, &store.locator()?)?;
                if self.last_tip.is_none() {
                    for group in introductions.chunks(64) {
                        let mut payload = (group.len() as u16).to_be_bytes().to_vec();
                        for k in group {
                            payload.extend(k);
                        }
                        self.queue(peer, 8, &payload)?;
                    }
                }
            }
            self.last_tip = Some(store.ledger().tip().id());
            self.last_announce = Instant::now();
        }
        if self.last_scan.elapsed() >= Duration::from_millis(200) {
            let mut pending = self.carriage.pending()?;
            // Keep cursor admission fair; order only this bounded slice by height.
            pending.sort_by_key(|p| {
                if p.kind == 3 {
                    (
                        1,
                        u128::from_be_bytes(p.payload[68..84].try_into().unwrap()),
                    )
                } else {
                    (0, 0)
                }
            });
            pending.truncate(32);
            let installed = match self.apply_history_group(store, &pending, now) {
                Ok(ids) => ids,
                Err(e) => {
                    // An invalid or incomplete group cannot hide other admitted
                    // packets. Single-object processing retains its normal waits
                    // and refusals; an ambiguous write has poisoned the store.
                    self.diagnostic = Some(e);
                    BTreeSet::new()
                }
            };
            for p in pending.into_iter().take(32) {
                if installed.contains(&p.id) {
                    continue;
                }
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
        let peers: BTreeSet<_> = self
            .neighbors
            .iter()
            .map(|n| peer_id(n.key))
            .chain(self.offline_peers.iter().map(|k| peer_id(*k)))
            .collect();
        for peer in peers {
            self.queue(peer, 2, raw)?;
        }
        Ok(())
    }
    pub fn transaction_observation(&self, raw: &[u8]) -> Result<Value> {
        self.carriage.transaction_observation(raw)
    }
    pub(crate) fn backup_material(&self) -> Result<BackupMaterial> {
        Ok((
            read(&self.root.join("contact.secret"), 32)?,
            read(&self.root.join("tls.secret"), 16384)?,
            self.config.clone(),
        ))
    }
}

impl Network {
    pub fn offline_export(&mut self, peer: Hash) -> Result<Vec<Vec<u8>>> {
        ensure(
            self.offline_peers.contains(&peer),
            "INVALID_CRYPTO offline adapter not admitted",
        )?;
        let packets = self
            .carriage
            .prepare(&[peer], &BTreeSet::new())?
            .map(|(_, p)| p)
            .unwrap_or_default();
        packets
            .iter()
            .map(|p| {
                self.carriage
                    .prepare_offline(&self.key, peer, p)
                    .map(|f| f.raw().to_vec())
            })
            .collect()
    }
    pub fn offline_import(&mut self, peer: Hash, raw: &[u8]) -> Result<Option<Vec<u8>>> {
        ensure(
            self.offline_peers.contains(&peer),
            "INVALID_CRYPTO offline adapter not admitted",
        )?;
        let f = Frame::decode(raw, self.chain)?;
        if f.kind == 3 {
            self.carriage.offline_receipt(raw, peer)?;
            return Ok(None);
        }
        let result = self.carriage.receive(raw, peer, [0; 32], true, &self.key)?;
        if let Some(receipt) = &result {
            if receipt.result == Some(1) {
                let original = f.packet.as_ref().ok_or("INVALID_ENCODING offline packet")?;
                self.queue(peer_id(original.origin), 9, receipt.raw())?;
            }
        }
        Ok(result.map(|f| f.raw().to_vec()))
    }
    pub fn discovered_candidates(&self) -> Result<Value> {
        Ok(
            json!({"identities":self.carriage.candidate_identities()?.iter().map(hex::encode).collect::<Vec<_>>(),"endpoint_authority":false}),
        )
    }
    pub fn withdraw_transport(&mut self, id: Hash, acknowledge: bool) -> Result<()> {
        self.carriage.withdraw(id, acknowledge)
    }
}
