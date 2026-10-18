//! Ordinary node contact scheduling. Network workers hold no ledger/custody lock;
//! the main loop alone commits received bytes and native monetary transitions.
mod offline_history;

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
fn retained_config(root: &Path) -> Result<Option<Zeroizing<Vec<u8>>>> {
    match fs::symlink_metadata(root.join("config.next")) {
        Ok(_) => return Err("RESOURCE_WAIT interrupted contact configuration".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(err(e)),
    }
    let path = root.join("config.json");
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            ensure(
                metadata.is_file(),
                "INVALID_ENCODING contact configuration file",
            )?;
            read(&path, 65536).map(Some)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(err(e)),
    }
}
fn retain_config(root: &Path, raw: &[u8]) -> Result<()> {
    ensure(
        raw.len() <= 65536,
        "INVALID_ENCODING contact configuration bound",
    )?;
    if retained_config(root)?.as_deref().map(Vec::as_slice) == Some(raw) {
        // Even an exact repeated publication completes file/directory durability.
        File::open(root.join("config.json"))
            .and_then(|file| file.sync_all())
            .and_then(|_| File::open(root)?.sync_all())
            .map_err(err)?;
        return Ok(());
    }
    let pending = root.join("config.next");
    fresh(&pending, raw)?;
    // The exact complete old or new admission is visible after rename. An
    // interrupted pre-rename write stays retained and blocks silent fallback.
    fs::rename(&pending, root.join("config.json")).map_err(err)?;
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(err)
}
fn admission(cfg: &Value, identity: Hash) -> Result<(SocketAddr, Vec<Neighbor>, Vec<Hash>)> {
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
    Ok((listen, neighbors, offline_peers))
}
fn retained_material(root: &Path, chain: Hash, identity: Hash) -> Result<Material> {
    let bytes = read(&root.join("tls.secret"), 16384)?;
    ensure(bytes.len() > 4, "INVALID_ENCODING TLS material")?;
    let n = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    ensure(
        n <= 8192 && 4 + n < bytes.len(),
        "INVALID_ENCODING TLS material",
    )?;
    Material::from_der(
        bytes[4..4 + n].to_vec(),
        Zeroizing::new(bytes[4 + n..].to_vec()),
        chain,
        identity,
    )
}
/// Complete nonmutating material/admission verification, with no socket bind,
/// key generation, renewal, peer discovery or custody acknowledgment.
pub(crate) fn verify_backup_material(root: &Path, chain: Hash, identity: Hash) -> Result<()> {
    let seed = read(&root.join("contact.secret"), 32)?;
    let seed = Zeroizing::new(
        <[u8; 32]>::try_from(seed.as_slice()).map_err(|_| "INVALID_CRYPTO restored contact key")?,
    );
    ensure(
        SigningKey::from_bytes(&seed).verifying_key().to_bytes() == identity,
        "INVALID_CRYPTO restored contact identity",
    )?;
    let material = retained_material(root, chain, identity)?;
    let raw = read(&root.join("config.json"), 65536)?;
    let cfg: Value = serde_json::from_slice(&raw).map_err(err)?;
    let (_, neighbors, _) = admission(&cfg, identity)?;
    tls::server(&material, chain, neighbors)?;
    Ok(())
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
const LISTENER_RETRY: Duration = Duration::from_secs(5);
struct ConnectionSlot(Arc<AtomicUsize>);
impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}
struct ListenerTask {
    config: Arc<rustls::ServerConfig>,
    chain: Hash,
    key: SigningKey,
    peers: Vec<Neighbor>,
    inbox: SyncSender<Incoming>,
    stop: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
}
impl ListenerTask {
    fn run(self, listener: TcpListener) {
        while !self.stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((socket, _)) => {
                    if self.active.load(Ordering::Relaxed) >= 2 {
                        drop(socket);
                        continue;
                    }
                    self.active.fetch_add(1, Ordering::Relaxed);
                    let slot = ConnectionSlot(self.active.clone());
                    let config = self.config.clone();
                    let chain = self.chain;
                    let key = self.key.clone();
                    let peers = self.peers.clone();
                    let tx = self.inbox.clone();
                    let _ = thread::Builder::new().spawn(move || {
                        let _slot = slot;
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
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10))
                }
                Err(_) => break,
            }
        }
    }
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
    configured_listen: SocketAddr,
    listener: Option<SocketAddr>,
    listener_config: Arc<rustls::ServerConfig>,
    listener_retry: Instant,
    listener_error: Option<String>,
    active_connections: Arc<AtomicUsize>,
    inbox: SyncSender<Incoming>,
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
    pub fn resource_budget(&self) -> Budget {
        self.carriage.resource_budget()
    }
    pub fn open(root: &Path, chain: Hash, config: Option<&[u8]>) -> Result<Self> {
        Self::open_with_budget(root, chain, config, Budget::default())
    }
    pub fn open_with_budget(
        root: &Path,
        chain: Hash,
        config: Option<&[u8]>,
        budget: Budget,
    ) -> Result<Self> {
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
        let material = Arc::new(retained_material(root, chain, identity)?);
        let retained = retained_config(root)?;
        let cfg: Value = match config.or_else(|| retained.as_deref().map(Vec::as_slice)) {
            Some(b) => {
                ensure(
                    b.len() <= 65536,
                    "INVALID_ENCODING contact configuration bound",
                )?;
                serde_json::from_slice(b).map_err(err)?
            }
            None => {
                ensure(
                    !root.join("custody").exists(),
                    "MISSING_HISTORY retained contact configuration",
                )?;
                json!({"listen":"127.0.0.1:0","neighbors":[]})
            }
        };
        let (listen, neighbors, offline_peers) = admission(&cfg, identity)?;
        let carriage = Carriage::open(&root.join("custody"), chain, identity, budget)?;
        // Verify retained credentials and pins before constructing the adapter.
        // A socket wait never reconstructs custody or creates another identity.
        let listener_config = tls::server(&material, chain, neighbors.clone())?;
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, incoming) = mpsc::sync_channel::<Incoming>(8);
        let (outbox, outgoing) = mpsc::sync_channel(32);
        let mut adapter = Self {
            root: root.to_path_buf(),
            config: serde_json::to_vec(&cfg).map_err(err)?,
            chain,
            key,
            material,
            carriage,
            neighbors,
            offline_peers,
            configured_listen: listen,
            listener: None,
            listener_config,
            listener_retry: Instant::now(),
            listener_error: None,
            active_connections: Arc::new(AtomicUsize::new(0)),
            inbox: tx,
            incoming,
            outgoing,
            outbox,
            stop,
            listener_thread: None,
            worker: None,
            suppressed: BTreeSet::new(),
            unavailable_until: BTreeMap::new(),
            probe: Instant::now(),
            last_tip: None,
            last_announce: Instant::now() - Duration::from_secs(1),
            last_scan: Instant::now() - Duration::from_secs(1),
            diagnostic: None,
        };
        adapter.open_offline_history()?;
        // Publish validated local intent before opening a socket or returning an
        // adapter. A receipt or discovered route never writes this admission.
        retain_config(root, &adapter.config)?;
        adapter.poll_listener();
        Ok(adapter)
    }
    fn poll_listener(&mut self) {
        if self
            .listener_thread
            .as_ref()
            .is_some_and(|h| h.is_finished())
        {
            if let Some(h) = self.listener_thread.take() {
                let _ = h.join();
            }
            self.listener = None;
            self.listener_error = Some(err("listener stopped"));
            self.listener_retry = Instant::now() + LISTENER_RETRY;
        }
        if self.listener_thread.is_some() || Instant::now() < self.listener_retry {
            return;
        }
        let attempt = (|| -> Result<(TcpListener, SocketAddr)> {
            let listener = TcpListener::bind(self.configured_listen).map_err(err)?;
            listener.set_nonblocking(true).map_err(err)?;
            let bound = listener.local_addr().map_err(err)?;
            Ok((listener, bound))
        })();
        self.listener_retry = Instant::now() + LISTENER_RETRY;
        match attempt {
            Ok((listener, bound)) => {
                let task = ListenerTask {
                    config: self.listener_config.clone(),
                    chain: self.chain,
                    key: self.key.clone(),
                    peers: self.neighbors.clone(),
                    inbox: self.inbox.clone(),
                    stop: self.stop.clone(),
                    active: self.active_connections.clone(),
                };
                match thread::Builder::new().spawn(move || task.run(listener)) {
                    Ok(handle) => {
                        self.listener_thread = Some(handle);
                        self.listener = Some(bound);
                        self.listener_error = None;
                    }
                    Err(e) => {
                        self.listener = None;
                        self.listener_error = Some(err(e));
                    }
                }
            }
            Err(e) => {
                self.listener = None;
                self.listener_error = Some(e);
            }
        }
    }
    pub fn status(&self) -> Value {
        let listening = self
            .listener_thread
            .as_ref()
            .is_some_and(|h| !h.is_finished());
        json!({"state":if listening {"ACTIVE_GROUND_ADAPTER"} else {"LISTEN_WAIT"},"identity":hex::encode(self.key.verifying_key().to_bytes()),"peer_id":hex::encode(peer_id(self.key.verifying_key().to_bytes())),"listen":self.listener.filter(|_|listening).map(|a|a.to_string()),"configured_listen":self.configured_listen.to_string(),"listener_retry_seconds":"5","listener_diagnostic":self.listener_error,"certificate_sha256":hex::encode(self.material.fingerprint()),"neighbors":self.neighbors.len().to_string(),"diagnostic":self.listener_error.as_ref().or(self.diagnostic.as_ref()),"physical_route_qualified":false})
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
        // Listener availability is independent of outbound/offline custody and
        // local validation/mining. A bind failure must not skip their scheduling.
        self.poll_listener();
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
        match self.offer_offline_history(store) {
            Ok(()) => {}
            Err(offline_history::OfflineHistoryError::Contact(e)) => {
                // A full offline queue never disables ordinary native work.
                self.diagnostic = Some(e);
            }
            Err(offline_history::OfflineHistoryError::Native(e)) => return Err(e),
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
        let contact = read(&self.root.join("contact.secret"), 32)?;
        let tls = read(&self.root.join("tls.secret"), 16384)?;
        ensure(
            contact.as_slice() == self.key.as_bytes(),
            "INVALID_CRYPTO retained contact key changed",
        )?;
        ensure(
            self.material.matches_retained_record(&tls),
            "INVALID_CRYPTO retained TLS material changed",
        )?;
        ensure(
            retained_config(&self.root)?.as_deref().map(Vec::as_slice)
                == Some(self.config.as_slice()),
            "INVALID_CRYPTO retained contact configuration changed",
        )?;
        Ok((contact, tls, self.config.clone()))
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

#[cfg(test)]
mod listener_tests {
    use super::*;
    use std::sync::atomic::AtomicU64;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    fn root() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "rld-survivor-listener-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        root
    }
    #[test]
    fn listener_wait_preserves_material_and_offline_custody() {
        // Public NO-VALUE contact fixture, never ledger or monetary authority.
        let root = root();
        let blocker = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = blocker.local_addr().unwrap();
        let peer = SigningKey::from_bytes(&[41; 32]).verifying_key().to_bytes();
        let config = serde_json::to_vec(&json!({"listen":address.to_string(),"neighbors":[],"offline_peers":[hex::encode(peer)]})).unwrap();
        let mut network = Network::open(&root.join("contact"), [77; 32], Some(&config)).unwrap();
        let before = network.status();
        assert_eq!(before["state"], "LISTEN_WAIT");
        assert!(before["listen"].is_null());
        assert_eq!(before["configured_listen"], address.to_string());
        assert!(before["listener_diagnostic"]
            .as_str()
            .unwrap()
            .starts_with("RESOURCE_WAIT"));
        let key = fs::read(root.join("contact/contact.secret")).unwrap();
        let tls = fs::read(root.join("contact/tls.secret")).unwrap();
        network.queue(peer_id(peer), 4, &[0; 96]).unwrap();
        let frames = network.offline_export(peer).unwrap();
        assert_eq!(frames.len(), 1);
        drop(blocker);
        // A controlled supervisor transition only. The ordinary-process check
        // separately waits for the real five-second retry timer.
        network.listener_retry = Instant::now();
        network.poll_listener();
        let after = network.status();
        assert_eq!(after["state"], "ACTIVE_GROUND_ADAPTER");
        assert_eq!(after["listen"], address.to_string());
        assert!(after["listener_diagnostic"].is_null());
        assert_eq!(after["identity"], before["identity"]);
        assert_eq!(after["certificate_sha256"], before["certificate_sha256"]);
        assert!(fs::read(root.join("contact/contact.secret")).unwrap() == key);
        assert!(fs::read(root.join("contact/tls.secret")).unwrap() == tls);
        assert!(network.offline_export(peer).unwrap() == frames);
    }
    #[test]
    fn listener_restart_retains_occupied_connection_slots() {
        let root = root();
        let mut network = Network::open(&root.join("contact"), [78; 32], None).unwrap();
        // Model two still-live old workers with the exact production guards;
        // restarting the acceptor must not create another connection allowance.
        network.active_connections.fetch_add(2, Ordering::Relaxed);
        let first = ConnectionSlot(network.active_connections.clone());
        let second = ConnectionSlot(network.active_connections.clone());
        network.stop.store(true, Ordering::Relaxed);
        network.listener_thread.take().unwrap().join().unwrap();
        network.stop.store(false, Ordering::Relaxed);
        network.listener = None;
        network.listener_retry = Instant::now();
        network.poll_listener();
        let mut socket = std::net::TcpStream::connect(network.listener.unwrap()).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let refused = socket.read(&mut [0; 1]);
        assert!(
            matches!(refused, Ok(0))
                || refused.is_err_and(|e| e.kind() == std::io::ErrorKind::ConnectionReset)
        );
        assert_eq!(network.active_connections.load(Ordering::Relaxed), 2);
        drop(first);
        drop(second);
        assert_eq!(network.active_connections.load(Ordering::Relaxed), 0);
    }
    #[test]
    fn invalid_pins_do_not_become_a_listener_wait() {
        let root = root();
        let blocker = TcpListener::bind("127.0.0.1:0").unwrap();
        let config = serde_json::to_vec(&json!({"listen":blocker.local_addr().unwrap().to_string(),"neighbors":[{"key":hex::encode([0;32]),"endpoint":"127.0.0.1:1","certificate_sha256":hex::encode([0;32])}]})).unwrap();
        assert!(
            Network::open(&root.join("contact"), [79; 32], Some(&config))
                .err()
                .unwrap()
                .starts_with("INVALID_CRYPTO")
        );
    }

    #[test]
    fn retained_admission_and_explicit_replacement_survive_library_restart() {
        // Public NO-VALUE contact identities, never monetary custody.
        let root = root().join("contact");
        let peer = SigningKey::from_bytes(&[61; 32]).verifying_key().to_bytes();
        let other = SigningKey::from_bytes(&[62; 32]).verifying_key().to_bytes();
        let config = |offline| {
            serde_json::to_vec(&json!({
            "listen":"127.0.0.1:0",
            "neighbors":[{"key":hex::encode(other),"endpoint":"127.0.0.1:9","certificate_sha256":hex::encode([71;32])}],
            "offline_peers":[hex::encode(offline)]
        })).unwrap()
        };
        let first = Network::open(&root, [81; 32], Some(&config(peer))).unwrap();
        let identity = first.status()["identity"].clone();
        let certificate = first.status()["certificate_sha256"].clone();
        let original = first.config.clone();
        assert_eq!(fs::read(root.join("config.json")).unwrap(), original);
        drop(first);
        let mut resumed = Network::open(&root, [81; 32], None).unwrap();
        assert_eq!(resumed.config, original);
        assert_eq!(resumed.status()["identity"], identity);
        assert_eq!(resumed.status()["certificate_sha256"], certificate);
        assert_eq!(resumed.neighbors.len(), 1);
        assert_eq!(resumed.neighbors[0].endpoint.to_string(), "127.0.0.1:9");
        assert_eq!(resumed.neighbors[0].certificate_sha256, [71; 32]);
        assert!(resumed.offline_export(peer).is_ok());
        drop(resumed);
        let replaced = Network::open(&root, [81; 32], Some(&config(other))).unwrap();
        assert_ne!(replaced.config, original);
        let replacement = replaced.config.clone();
        drop(replaced);
        let mut resumed = Network::open(&root, [81; 32], None).unwrap();
        assert_eq!(resumed.config, replacement);
        assert!(resumed.offline_export(other).is_ok());
        assert!(resumed.offline_export(peer).is_err());
        assert!(!root.join("config.next").exists());
    }

    #[test]
    fn invalid_replacement_keeps_retained_admission_and_custody_unchanged() {
        let root = root().join("contact");
        let peer = SigningKey::from_bytes(&[63; 32]).verifying_key().to_bytes();
        let config = serde_json::to_vec(&json!({
            "listen":"127.0.0.1:0","neighbors":[],"offline_peers":[hex::encode(peer)]
        }))
        .unwrap();
        let mut network = Network::open(&root, [82; 32], Some(&config)).unwrap();
        network.queue(peer_id(peer), 4, &[0; 96]).unwrap();
        let frames = network.offline_export(peer).unwrap();
        let retained = fs::read(root.join("config.json")).unwrap();
        drop(network);
        let custody = fs::read(root.join("custody/carriage.sqlite3")).unwrap();
        let bad = serde_json::to_vec(&json!({
            "listen":"127.0.0.1:0","neighbors":[],"offline_peers":[hex::encode([0;32])]
        }))
        .unwrap();
        assert!(Network::open(&root, [82; 32], Some(&bad)).is_err());
        assert_eq!(fs::read(root.join("config.json")).unwrap(), retained);
        assert_eq!(
            fs::read(root.join("custody/carriage.sqlite3")).unwrap(),
            custody
        );
        assert!(!root.join("config.next").exists());
        let mut resumed = Network::open(&root, [82; 32], None).unwrap();
        assert_eq!(resumed.offline_export(peer).unwrap(), frames);
    }

    #[test]
    fn interrupted_admission_blocks_open_and_backup_without_repair() {
        for complete in [false, true] {
            let root = root().join("contact");
            let network = Network::open(&root, [83; 32], None).unwrap();
            let retained = fs::read(root.join("config.json")).unwrap();
            let pending = if complete {
                retained.clone()
            } else {
                b"{partial".to_vec()
            };
            fs::write(root.join("config.next"), &pending).unwrap();
            assert!(network.backup_material().is_err());
            drop(network);
            for explicit in [None, Some(retained.as_slice())] {
                assert!(Network::open(&root, [83; 32], explicit).is_err());
                assert_eq!(fs::read(root.join("config.json")).unwrap(), retained);
                assert_eq!(fs::read(root.join("config.next")).unwrap(), pending);
            }
        }
    }

    #[test]
    fn missing_or_damaged_admission_cannot_fall_back_or_enter_a_backup() {
        for replacement in [None, Some(b"{damaged".as_slice()), Some(b"{}".as_slice())] {
            let root = root().join("contact");
            let network = Network::open(&root, [84; 32], None).unwrap();
            if let Some(raw) = replacement {
                fs::write(root.join("config.json"), raw).unwrap();
            } else {
                fs::remove_file(root.join("config.json")).unwrap();
            }
            assert!(network.backup_material().is_err());
            drop(network);
            assert!(Network::open(&root, [84; 32], None).is_err());
            assert_eq!(
                fs::read(root.join("config.json")).ok().as_deref(),
                replacement
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn admission_symlink_is_not_followed_or_overwritten() {
        let root = root();
        let contact = root.join("contact");
        let network = Network::open(&contact, [85; 32], None).unwrap();
        let raw = fs::read(contact.join("config.json")).unwrap();
        drop(network);
        let other = root.join("other-config");
        fs::write(&other, &raw).unwrap();
        fs::remove_file(contact.join("config.json")).unwrap();
        std::os::unix::fs::symlink(&other, contact.join("config.json")).unwrap();
        assert!(Network::open(&contact, [85; 32], Some(&raw)).is_err());
        assert_eq!(fs::read(&other).unwrap(), raw);
        assert!(fs::symlink_metadata(contact.join("config.json"))
            .unwrap()
            .is_symlink());
    }
}
