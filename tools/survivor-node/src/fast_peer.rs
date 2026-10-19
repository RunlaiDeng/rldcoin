//! Direct pinned-neighbor payment data carriage. Network workers never access
//! wallet/retainer keys, caller approvals, ledgers or private signing commands.
pub mod codec;
mod head_control;
mod store;
use crate::{
    fast_payment::ensure,
    fast_retainer::{io, private, sync},
    fast_session::Id,
    kernel::{Hash, Result},
    tls::{self, Material, Neighbor},
};
use codec::Packet;
use ed25519_dalek::SigningKey;
pub use head_control::Boundary as HeadBoundary;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
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
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerPin {
    pub key: Id,
    pub endpoint: SocketAddr,
    pub certificate_sha256: Id,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub chain: Id,
    pub identity: Id,
    pub listen: SocketAddr,
    pub peers: Vec<PeerPin>,
}
impl Config {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        ensure(raw.len() <= 65536, "RESOURCE_WAIT peer admission size")?;
        let c: Self = serde_json::from_slice(raw).map_err(|_| "INVALID peer admission JSON")?;
        ensure(
            c.peers.len() <= 16 && crate::kernel::valid_point(c.identity.0),
            "INVALID peer admission count/identity",
        )?;
        let mut keys = BTreeSet::new();
        let mut pins = BTreeSet::new();
        for p in &c.peers {
            ensure(
                crate::kernel::valid_point(p.key.0)
                    && p.key != c.identity
                    && keys.insert(p.key)
                    && pins.insert(p.certificate_sha256)
                    && p.endpoint.port() != 0
                    && !p.endpoint.ip().is_unspecified(),
                "INVALID peer endpoint/key/pin",
            )?;
        }
        Ok(c)
    }
    pub fn digest(&self) -> Result<Hash> {
        Ok(codec::hash(
            "ADMISSION",
            &serde_json::to_vec(self).map_err(io)?,
        ))
    }
    fn neighbors(&self) -> Vec<Neighbor> {
        self.peers
            .iter()
            .map(|p| Neighbor {
                key: p.key.0,
                endpoint: p.endpoint,
                certificate_sha256: p.certificate_sha256.0,
            })
            .collect()
    }
}
fn fresh(path: &Path, raw: &[u8]) -> Result<()> {
    let mut o = OpenOptions::new();
    o.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path).map_err(io)?;
    f.write_all(raw).map_err(io)?;
    sync(&f, path)
}
fn read(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    private(path, true)?;
    let mut b = Zeroizing::new(Vec::new());
    File::open(path)
        .map_err(io)?
        .take(limit as u64 + 1)
        .read_to_end(&mut b)
        .map_err(io)?;
    ensure(b.len() <= limit, "RESOURCE_WAIT peer material bound")?;
    Ok(b)
}
fn material(root: &Path, chain: Hash) -> Result<(SigningKey, Material)> {
    private(root, false)?;
    ensure(
        !root.join("CREATING").exists()
            && !root.join("BINDING").exists()
            && !root.join("RESTORING").exists(),
        "RESOURCE_WAIT interrupted peer directory",
    )?;
    let seed = read(&root.join("identity.secret"), 32)?;
    let seed = Zeroizing::new(
        <[u8; 32]>::try_from(seed.as_slice()).map_err(|_| "INVALID retained peer identity")?,
    );
    let key = SigningKey::from_bytes(&seed);
    let raw = read(&root.join("tls.secret"), 16384)?;
    ensure(raw.len() > 4, "INVALID retained peer TLS")?;
    let n = u32::from_be_bytes(raw[..4].try_into().unwrap()) as usize;
    ensure(
        n <= 8192 && n + 4 < raw.len(),
        "INVALID retained peer TLS size",
    )?;
    let tls = Material::from_der(
        raw[4..4 + n].to_vec(),
        Zeroizing::new(raw[4 + n..].to_vec()),
        chain,
        key.verifying_key().to_bytes(),
    )?;
    Ok((key, tls))
}
pub fn provision(root: &Path, chain: Hash) -> Result<Value> {
    fs::create_dir(root).map_err(io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).map_err(io)?;
    }
    File::open(root.parent().ok_or("INVALID peer parent")?)
        .and_then(|f| f.sync_all())
        .map_err(io)?;
    fresh(&root.join("CREATING"), &chain)?;
    let key = crate::keyfile::generate()?;
    let identity = key.verifying_key().to_bytes();
    let (cert, secret) = Material::generate(chain, identity)?;
    let fingerprint: Hash = {
        use sha2::{Digest, Sha256};
        Sha256::digest(&cert).into()
    };
    let mut raw = Zeroizing::new((cert.len() as u32).to_be_bytes().to_vec());
    raw.extend(cert);
    raw.extend(secret.as_slice());
    fresh(&root.join("identity.secret"), &key.to_bytes())?;
    fresh(&root.join("tls.secret"), &raw)?;
    fs::remove_file(root.join("CREATING")).map_err(io)?;
    File::open(root).and_then(|f| f.sync_all()).map_err(io)?;
    Ok(
        json!({"chain":Id(chain),"identity":Id(identity),"certificate_sha256":Id(fingerprint),"wallet_authority":false,"mainnet":false}),
    )
}
pub fn bind(root: &Path, raw: &[u8], now: u64) -> Result<Value> {
    bind_inner(root, raw, None, now)
}
pub fn bind_controlled(root: &Path, raw: &[u8], head_file: &Path, now: u64) -> Result<Value> {
    bind_inner(root, raw, Some(head_file), now)
}
fn bind_inner(root: &Path, raw: &[u8], head_file: Option<&Path>, now: u64) -> Result<Value> {
    let config = Config::parse(raw)?;
    let (key, tls) = material(root, config.chain.0)?;
    ensure(
        key.verifying_key().to_bytes() == config.identity.0,
        "INVALID local peer identity",
    )?;
    tls::server(&tls, config.chain.0, config.neighbors())?;
    fresh(&root.join("BINDING"), &config.digest()?)?;
    fresh(
        &root.join("admission.json"),
        &serde_json::to_vec(&config).map_err(io)?,
    )?;
    let custody = if let Some(head_file) = head_file {
        store::Custody::create_controlled(
            &root.join("custody.journal"),
            &config,
            config.identity.0,
            tls.fingerprint(),
            head_file,
            now,
        )?
    } else {
        store::Custody::create(
            &root.join("custody.journal"),
            &config,
            config.identity.0,
            tls.fingerprint(),
            now,
        )?
    };
    fs::remove_file(root.join("BINDING")).map_err(io)?;
    File::open(root).and_then(|f| f.sync_all()).map_err(io)?;
    Ok(
        json!({"peer_head":Id(custody.head),"identity":config.identity,"config_digest":Id(config.digest()?),"transport_custody_only":true}),
    )
}
/// Reconcile exact retained data only; never start workers or first-sign.
pub fn recover_controlled(root: &Path, chain: Hash, head_file: &Path, now: u64) -> Result<Value> {
    let c = Config::parse(&read(&root.join("admission.json"), 65536)?)?;
    ensure(c.chain.0 == chain, "INVALID peer configured chain")?;
    let (key, tls) = material(root, chain)?;
    ensure(
        key.verifying_key().to_bytes() == c.identity.0,
        "INVALID peer retained identity",
    )?;
    let head = store::Custody::recover_controlled(
        &root.join("custody.journal"),
        &c,
        c.identity.0,
        tls.fingerprint(),
        head_file,
        now,
    )?;
    Ok(json!({"peer_head":Id(head),"head_control":"TRUSTED_FILE",
        "transport_custody_only":true,"wallet_key_loaded":false,"first_sign":false,
        "native_authority":false,"independent_freshness":false}))
}
/// Authenticate and report only the exact retained successor of a caller's
/// prior data head. No record, signature, network worker or wallet is created.
pub fn recover(
    root: &Path,
    chain: Hash,
    prior: Hash,
    packet_or_message: Hash,
    now: u64,
) -> Result<Value> {
    let c = Config::parse(&read(&root.join("admission.json"), 65536)?)?;
    ensure(c.chain.0 == chain, "INVALID peer configured chain")?;
    let (key, tls) = material(root, chain)?;
    ensure(
        key.verifying_key().to_bytes() == c.identity.0,
        "INVALID peer retained identity",
    )?;
    let head = store::Custody::recover(
        &root.join("custody.journal"),
        &c,
        c.identity.0,
        tls.fingerprint(),
        prior,
        packet_or_message,
        now,
    )?;
    Ok(
        json!({"peer_head":Id(head),"prior_peer_head":Id(prior),"packet_or_message":Id(packet_or_message),
        "transport_custody_only":true,"wallet_key_loaded":false,"first_sign":false,"records_appended":0}),
    )
}
fn write_sized(s: &mut impl Write, b: &[u8]) -> Result<()> {
    s.write_all(&(b.len() as u32).to_be_bytes())
        .and_then(|_| s.write_all(b))
        .and_then(|_| s.flush())
        .map_err(io)
}
fn read_sized(s: &mut impl Read, max: usize) -> Result<Vec<u8>> {
    let mut p = [0; 4];
    s.read_exact(&mut p).map_err(io)?;
    let n = u32::from_be_bytes(p) as usize;
    ensure((1..=max).contains(&n), "INVALID peer wire bound")?;
    let mut b = vec![0; n];
    s.read_exact(&mut b).map_err(io)?;
    Ok(b)
}
fn deliver(
    material: &Material,
    c: &Config,
    key: &SigningKey,
    peer: &Neighbor,
    p: &Packet,
) -> Result<Vec<u8>> {
    let mut stream = tls::connect_stream(material, c.chain.0, peer)?;
    let mut b = [0; 164];
    stream.read_exact(&mut b).map_err(io)?;
    let server = codec::check_challenge(&b, c.chain.0, peer.key)?;
    let client = codec::nonce()?;
    write_sized(
        &mut stream,
        &codec::delivery(c.chain.0, key, peer.key, server, client, p),
    )?;
    let mut response = vec![0; 293];
    stream.read_exact(&mut response).map_err(io)?;
    codec::check_response(
        &response,
        c.chain.0,
        c.identity.0,
        peer.key,
        p.id,
        Some((server, client)),
    )?;
    Ok(response)
}
struct Incoming {
    packet: Packet,
    server: Hash,
    client: Hash,
    reply: SyncSender<Result<Vec<u8>>>,
}
fn accept(
    socket: TcpStream,
    config: Arc<rustls::ServerConfig>,
    c: &Config,
    key: &SigningKey,
    tx: &SyncSender<Incoming>,
) -> Result<()> {
    let (peer, mut stream) = tls::accept_stream(socket, config, &c.neighbors())?;
    let server = codec::nonce()?;
    stream
        .write_all(&codec::challenge(c.chain.0, key, server))
        .and_then(|_| stream.flush())
        .map_err(io)?;
    let raw = read_sized(&mut stream, 232 + codec::MAX_PACKET)?;
    let (packet, client) = codec::check_delivery(&raw, c.chain.0, peer, c.identity.0, server)?;
    let (reply, rx) = mpsc::sync_channel(1);
    tx.try_send(Incoming {
        packet,
        server,
        client,
        reply,
    })
    .map_err(io)?;
    let raw = rx.recv_timeout(Duration::from_secs(3)).map_err(io)??;
    stream
        .write_all(&raw)
        .and_then(|_| stream.flush())
        .map_err(io)
}
struct Slot(Arc<AtomicUsize>);
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}
struct Outgoing {
    packet: Packet,
    peer: Neighbor,
}
struct OutResult {
    id: Hash,
    response: Result<Vec<u8>>,
}
pub struct Network {
    root: PathBuf,
    config: Config,
    key: SigningKey,
    material: Arc<Material>,
    custody: store::Custody,
    incoming: Receiver<Incoming>,
    incoming_tx: SyncSender<Incoming>,
    outgoing: SyncSender<Outgoing>,
    results: Receiver<OutResult>,
    stop: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    listener: Option<JoinHandle<()>>,
    worker: Option<JoinHandle<()>>,
    listen: Option<SocketAddr>,
    retry: Instant,
    in_flight: BTreeSet<Hash>,
    not_before: BTreeMap<Hash, Instant>,
    cursor: usize,
    diagnostic: Option<String>,
}
impl Network {
    pub fn open(root: &Path, chain: Hash, head: Hash, now: u64) -> Result<Self> {
        Self::open_inner(root, chain, Some(head), None, now)
    }
    pub fn open_controlled(root: &Path, chain: Hash, head_file: &Path, now: u64) -> Result<Self> {
        Self::open_inner(root, chain, None, Some(head_file), now)
    }
    pub fn set_head_observer(
        &mut self,
        observer: impl FnMut(HeadBoundary) -> Result<()> + Send + 'static,
    ) -> Result<()> {
        self.custody.set_observer(Box::new(observer))
    }
    fn open_inner(
        root: &Path,
        chain: Hash,
        head: Option<Hash>,
        head_file: Option<&Path>,
        now: u64,
    ) -> Result<Self> {
        let raw = read(&root.join("admission.json"), 65536)?;
        let c = Config::parse(&raw)?;
        ensure(c.chain.0 == chain, "INVALID peer configured chain")?;
        let (key, material) = material(root, chain)?;
        ensure(
            key.verifying_key().to_bytes() == c.identity.0,
            "INVALID peer retained identity",
        )?;
        let custody = if let Some(head_file) = head_file {
            store::Custody::open_controlled(
                &root.join("custody.journal"),
                &c,
                c.identity.0,
                material.fingerprint(),
                head_file,
                now,
            )?
        } else {
            store::Custody::open(
                &root.join("custody.journal"),
                &c,
                c.identity.0,
                material.fingerprint(),
                head.ok_or("MISSING explicit peer head")?,
                now,
            )?
        };
        let material = Arc::new(material);
        tls::server(&material, chain, c.neighbors())?;
        let (tx, incoming) = mpsc::sync_channel(8);
        let (outgoing, jobs) = mpsc::sync_channel::<Outgoing>(1);
        let (results_tx, results) = mpsc::sync_channel(2);
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let credentials = material.clone();
        let cfg = c.clone();
        let signer = key.clone();
        let worker = thread::Builder::new()
            .name("fast-peer-outbound".into())
            .spawn(move || {
                while !done.load(Ordering::Relaxed) {
                    match jobs.recv_timeout(Duration::from_millis(50)) {
                        Ok(job) => {
                            let response =
                                deliver(&credentials, &cfg, &signer, &job.peer, &job.packet);
                            if results_tx
                                .send(OutResult {
                                    id: job.packet.id,
                                    response,
                                })
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(_) => break,
                    }
                }
            })
            .map_err(io)?;
        let mut n = Self {
            root: root.to_path_buf(),
            config: c,
            key,
            material,
            custody,
            incoming,
            incoming_tx: tx,
            outgoing,
            results,
            stop,
            active: Arc::new(AtomicUsize::new(0)),
            listener: None,
            worker: Some(worker),
            listen: None,
            retry: Instant::now(),
            in_flight: BTreeSet::new(),
            not_before: BTreeMap::new(),
            cursor: 0,
            diagnostic: None,
        };
        n.start_listener();
        Ok(n)
    }
    fn start_listener(&mut self) {
        if self.listener.as_ref().is_some_and(|h| h.is_finished()) {
            if let Some(h) = self.listener.take() {
                let _ = h.join();
            }
            self.listen = None;
            self.retry = Instant::now() + Duration::from_secs(5);
        }
        if self.listener.is_some() || Instant::now() < self.retry {
            return;
        }
        let listener = match TcpListener::bind(self.config.listen).and_then(|l| {
            l.set_nonblocking(true)?;
            Ok(l)
        }) {
            Ok(l) => l,
            Err(e) => {
                self.diagnostic = Some(io(e));
                self.retry = Instant::now() + Duration::from_secs(5);
                return;
            }
        };
        self.listen = listener.local_addr().ok();
        let config = match tls::server(&self.material, self.config.chain.0, self.config.neighbors())
        {
            Ok(c) => c,
            Err(e) => {
                self.diagnostic = Some(e);
                return;
            }
        };
        let c = self.config.clone();
        let key = self.key.clone();
        let tx = self.incoming_tx.clone();
        let done = self.stop.clone();
        let active = self.active.clone();
        self.listener = thread::Builder::new()
            .name("fast-peer-listener".into())
            .spawn(move || {
                while !done.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((socket, _)) => {
                            if active.load(Ordering::Relaxed) >= 2 {
                                drop(socket);
                                continue;
                            }
                            active.fetch_add(1, Ordering::Relaxed);
                            let slot = Slot(active.clone());
                            let config = config.clone();
                            let c = c.clone();
                            let key = key.clone();
                            let tx = tx.clone();
                            let _ = thread::Builder::new().spawn(move || {
                                let _slot = slot;
                                let _ = accept(socket, config, &c, &key, &tx);
                            });
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10))
                        }
                        Err(_) => break,
                    }
                }
            })
            .ok();
    }
    pub fn head(&self) -> Hash {
        self.custody.head
    }
    pub fn queue(&mut self, destination: Hash, kind: u8, data: &[u8], now: u64) -> Result<Hash> {
        let p = Packet::create(self.config.chain.0, &self.key, destination, kind, data)?;
        self.custody.keep(&self.config, &p, false, now)?;
        Ok(p.id)
    }
    pub fn tick(&mut self, now: u64) -> Result<()> {
        let result = self.tick_inner(now);
        if let Err(e) = &result {
            self.diagnostic = Some(e.clone());
        }
        result
    }
    fn tick_inner(&mut self, now: u64) -> Result<()> {
        self.start_listener();
        self.custody.check()?;
        for _ in 0..2 {
            let Ok(incoming) = self.incoming.try_recv() else {
                break;
            };
            let result = self
                .custody
                .keep(&self.config, &incoming.packet, true, now)
                .map(|head| {
                    codec::response(
                        self.config.chain.0,
                        &self.key,
                        incoming.packet.sender,
                        incoming.server,
                        incoming.client,
                        incoming.packet.id,
                        head,
                    )
                });
            let _ = incoming.reply.try_send(result);
        }
        while let Ok(done) = self.results.try_recv() {
            self.in_flight.remove(&done.id);
            match done.response {
                Ok(raw) => self.custody.acknowledge(done.id, &raw, now)?,
                Err(e) => {
                    self.diagnostic = Some(e);
                    self.not_before
                        .insert(done.id, Instant::now() + Duration::from_secs(1));
                }
            }
        }
        let count = self.custody.order.len();
        for _ in 0..count {
            if !self.in_flight.is_empty() {
                break;
            }
            self.cursor %= count;
            let id = self.custody.order[self.cursor];
            self.cursor = (self.cursor + 1) % count;
            let item = self.custody.items.get(&id).unwrap();
            if item.received
                || item.response.is_some()
                || self
                    .not_before
                    .get(&id)
                    .is_some_and(|t| Instant::now() < *t)
            {
                continue;
            }
            let peer = self
                .config
                .neighbors()
                .into_iter()
                .find(|p| p.key == item.packet.destination)
                .ok_or("MISSING admitted peer")?;
            let packet = self.custody.get(id)?.packet;
            if self.outgoing.try_send(Outgoing { packet, peer }).is_ok() {
                self.in_flight.insert(id);
            } else {
                break;
            }
        }
        Ok(())
    }
    pub fn received(&mut self, id: Hash) -> Result<Packet> {
        let item = self.custody.get(id)?;
        ensure(item.received, "INVALID peer incoming role")?;
        Ok(item.packet)
    }
    pub(crate) fn admitted_ids(&self) -> Vec<Hash> {
        self.config.neighbors().into_iter().map(|p| p.key).collect()
    }
    pub(crate) fn local_scope(&self) -> (Hash, Hash) {
        (self.config.chain.0, self.config.identity.0)
    }
    pub(crate) fn check_custody(&mut self) -> Result<()> {
        self.custody.check()
    }
    /// One complete authenticated packet at a time under an unchanged full
    /// custody prefix. This observation grants no native receipt or value.
    pub(crate) fn visit_packets_after(
        &mut self,
        after: usize,
        mut visit: impl FnMut(&Packet, bool) -> Result<()>,
    ) -> Result<usize> {
        self.custody.check()?;
        ensure(
            after <= self.custody.order.len(),
            "INVALID observed peer custody cursor",
        )?;
        for id in &self.custody.order[after..] {
            let item = &self.custody.items[id];
            let p = Packet::decode(&item.packet.raw, self.config.chain.0)?;
            visit(&p, item.received)?;
        }
        self.custody.check()?;
        Ok(self.custody.order.len())
    }
    pub fn inventory(&mut self) -> Result<Value> {
        self.custody.check()?;
        Ok(json!(self.custody.order.iter().map(|id|{let x=&self.custody.items[id];json!({"id":Id(*id),"kind":x.packet.kind,"source":Id(x.packet.sender),"destination":Id(x.packet.destination),"received":x.received,"queued_at":x.at.to_string(),"destination_transport_custody":x.response.is_some(),"ledger_acceptance_known":false,"fast_completion_authorized":false})}).collect::<Vec<_>>()))
    }
    pub fn received_ids(&mut self, kind: u8) -> Result<Vec<Hash>> {
        self.custody.check()?;
        Ok(self
            .custody
            .order
            .iter()
            .filter(|id| {
                let i = &self.custody.items[*id];
                i.received && i.packet.kind == kind
            })
            .copied()
            .collect())
    }
    pub fn status(&self) -> Value {
        json!({"profile":"RLD-FAST-PEER-1","custody_version":if self.custody.controlled(){2}else{1},"head_control":if self.custody.controlled(){"TRUSTED_FILE"}else{"EXTERNAL_EXACT_HEAD"},"independent_freshness":false,"peer_head":Id(self.head()),"identity":self.config.identity,"listen":self.listen,"admitted_peers":self.config.peers.len(),"retained_packets":self.custody.items.len(),"in_flight":self.in_flight.len(),"custody_ready":self.custody.ready(),"diagnostic":self.diagnostic,"transport_custody_only":true,"native_import":"EXPLICIT_LOCAL_VERIFICATION","fast_completion_authorized":false,"mainnet":false})
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
}
impl Drop for Network {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.listener.take() {
            let _ = h.join();
        }
        if let Some(h) = self.worker.take() {
            let _ = h.join();
        }
    }
}
