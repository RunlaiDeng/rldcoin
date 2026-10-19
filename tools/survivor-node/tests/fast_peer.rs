//! PUBLIC NO-VALUE codec keys; fresh generated private transport material stays
//! local. Native fixture amounts derive only from fresh actual PoW/maturity.
#[allow(dead_code)]
#[path = "support/fast_funding.rs"]
mod support;
use rld_survivor_node::{
    fast_payment::Invoice,
    fast_peer::{self, codec, Config, Network, PeerPin},
    fast_session::Id,
    kernel::Hash,
};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    net::TcpListener,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use support::*;
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn directory(chain: Hash, label: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "rld-fast-peer-{}-{}-{label}",
        std::process::id(),
        hex::encode(chain)
    ));
    fs::create_dir(&p).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
    }
    p
}
fn hv(v: &Value, k: &str) -> Hash {
    hex::decode(v[k].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}
fn raw(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(v[k].as_str().unwrap()).unwrap()
}
fn write(p: &Path, b: &[u8]) {
    let mut o = fs::OpenOptions::new();
    o.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(p).unwrap();
    f.write_all(b).unwrap();
    f.sync_all().unwrap();
}
struct Pair {
    a: PathBuf,
    b: PathBuf,
    ca: Config,
    cb: Config,
    ah: Hash,
    bh: Hash,
}
fn pair(root: &Path, chain: Hash, wrong_pin: bool) -> Pair {
    let a = root.join("a");
    let b = root.join("b");
    let ai = fast_peer::provision(&a, chain).unwrap();
    let bi = fast_peer::provision(&b, chain).unwrap();
    let la = TcpListener::bind("127.0.0.1:0").unwrap();
    let lb = TcpListener::bind("127.0.0.1:0").unwrap();
    let ca = Config {
        chain: Id(chain),
        identity: Id(hv(&ai, "identity")),
        listen: la.local_addr().unwrap(),
        peers: vec![PeerPin {
            key: Id(hv(&bi, "identity")),
            endpoint: lb.local_addr().unwrap(),
            certificate_sha256: Id(if wrong_pin {
                [0; 32]
            } else {
                hv(&bi, "certificate_sha256")
            }),
        }],
    };
    let cb = Config {
        chain: Id(chain),
        identity: Id(hv(&bi, "identity")),
        listen: lb.local_addr().unwrap(),
        peers: vec![PeerPin {
            key: ca.identity,
            endpoint: ca.listen,
            certificate_sha256: Id(hv(&ai, "certificate_sha256")),
        }],
    };
    let ah = hv(
        &fast_peer::bind(&a, &serde_json::to_vec(&ca).unwrap(), now()).unwrap(),
        "peer_head",
    );
    let bh = hv(
        &fast_peer::bind(&b, &serde_json::to_vec(&cb).unwrap(), now()).unwrap(),
        "peer_head",
    );
    drop(la);
    drop(lb);
    Pair {
        a,
        b,
        ca,
        cb,
        ah,
        bh,
    }
}
#[test]
fn manual_public_vectors_bind_exact_packet_roles_nonce_domains_and_custody_scope() {
    let v: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/fast-peer-v1-vectors.json"
    ))
    .unwrap();
    let chain = hv(&v, "chain_hex");
    let a = hv(&v, "sender_hex");
    let b = hv(&v, "destination_hex");
    let s = hv(&v, "server_nonce_hex");
    let c = hv(&v, "client_nonce_hex");
    let p = codec::Packet::decode(&raw(&v, "packet_hex"), chain).unwrap();
    assert_eq!(p.id, hv(&v, "packet_id_hex"));
    assert_eq!(p.raw[101..133], raw(&v, "message_tag_hex"));
    assert_eq!(p.payload, raw(&v, "payload_hex"));
    assert_eq!(
        codec::check_challenge(&raw(&v, "challenge_hex"), chain, b).unwrap(),
        s
    );
    let (q, cc) = codec::check_delivery(&raw(&v, "delivery_hex"), chain, a, b, s).unwrap();
    assert_eq!(q.raw, p.raw);
    assert_eq!(cc, c);
    codec::check_response(&raw(&v, "response_hex"), chain, a, b, p.id, Some((s, c))).unwrap();
    assert!(codec::check_delivery(&raw(&v, "delivery_hex"), chain, a, b, [0; 32]).is_err());
    assert!(codec::check_response(
        &raw(&v, "response_hex"),
        chain,
        a,
        b,
        p.id,
        Some((s, [1; 32]))
    )
    .is_err());
    for index in [0, 4, 36, 68, 100, 101, 133, 137, p.raw.len() - 1] {
        let mut bad = p.raw.clone();
        bad[index] ^= 1;
        assert!(codec::Packet::decode(&bad, chain).is_err(), "byte{index}");
    }
    let mut oversized = p.raw.clone();
    oversized[133..137].fill(255);
    assert!(codec::Packet::decode(&oversized, chain).is_err());
    let mut oversized = raw(&v, "delivery_hex");
    oversized[164..168].fill(255);
    assert!(codec::check_delivery(&oversized, chain, a, b, s).is_err());
    let server_key = ed25519_dalek::SigningKey::from_bytes(&[152; 32]);
    let missing_head = codec::response(chain, &server_key, a, s, c, p.id, [0; 32]);
    assert!(codec::check_response(&missing_head, chain, a, b, p.id, Some((s, c))).is_err());
    let key = ed25519_dalek::SigningKey::from_bytes(&[151; 32]);
    let made = codec::Packet::create(chain, &key, b, 3, &p.payload).unwrap();
    assert_eq!(made.raw, p.raw);
    assert_eq!(
        codec::Packet::create(chain, &key, b, 3, &p.payload)
            .unwrap()
            .id,
        p.id
    );
    assert!(!v["wallet_authorization"].as_bool().unwrap());
}
#[test]
fn actual_pinned_tls_custody_is_durable_idempotent_and_preserved_on_restart() {
    let f = fixture();
    let root = directory(f.ledger.chain_id(), "tls");
    let p = pair(&root, f.ledger.chain_id(), false);
    let mut a = Network::open(&p.a, f.ledger.chain_id(), p.ah, now()).unwrap();
    let mut b = Network::open(&p.b, f.ledger.chain_id(), p.bh, now()).unwrap();
    let invoice = Invoice::propose(
        &f.ledger.funding_origin(f.channel).unwrap(),
        None,
        0,
        70,
        [1; 32],
    )
    .unwrap();
    let id = a.queue(p.cb.identity.0, 2, invoice.bytes(), now()).unwrap();
    let queued = a.head();
    let original_time = a.inventory().unwrap()[0]["queued_at"].clone();
    assert_eq!(
        a.queue(p.cb.identity.0, 2, invoice.bytes(), now()).unwrap(),
        id
    );
    assert_eq!(a.head(), queued);
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        assert!(Instant::now() < deadline, "original180 peer custody");
        a.tick(now()).unwrap();
        b.tick(now()).unwrap();
        if a.inventory().unwrap()[0]["destination_transport_custody"] == true {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(b.received(id).unwrap().payload, invoice.bytes());
    assert_eq!(a.inventory().unwrap()[0]["queued_at"], original_time);
    assert_eq!(a.inventory().unwrap()[0]["ledger_acceptance_known"], false);
    let ah = a.head();
    let bh = b.head();
    drop(a);
    drop(b);
    assert_eq!(
        hv(
            &fast_peer::recover(&p.a, f.ledger.chain_id(), queued, id, now()).unwrap(),
            "peer_head"
        ),
        ah
    );
    assert_eq!(
        hv(
            &fast_peer::recover(&p.b, f.ledger.chain_id(), p.bh, id, now()).unwrap(),
            "peer_head"
        ),
        bh
    );
    assert!(Network::open(&p.a, f.ledger.chain_id(), queued, now()).is_err());
    let mut a = Network::open(&p.a, f.ledger.chain_id(), ah, now()).unwrap();
    let mut b = Network::open(&p.b, f.ledger.chain_id(), bh, now()).unwrap();
    assert_eq!(
        a.queue(p.cb.identity.0, 2, invoice.bytes(), now()).unwrap(),
        id
    );
    assert_eq!(a.head(), ah);
    assert_eq!(b.received(id).unwrap().payload, invoice.bytes());
    for _ in 0..3 {
        a.tick(now()).unwrap();
        b.tick(now()).unwrap();
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(a.head(), ah);
    assert_eq!(b.head(), bh);
}
#[test]
fn wrong_certificate_pin_never_becomes_destination_custody_or_clears_pending_age() {
    let f = fixture();
    let root = directory(f.ledger.chain_id(), "wrong-pin");
    let p = pair(&root, f.ledger.chain_id(), true);
    let mut a = Network::open(&p.a, f.ledger.chain_id(), p.ah, now()).unwrap();
    let mut b = Network::open(&p.b, f.ledger.chain_id(), p.bh, now()).unwrap();
    let i = Invoice::propose(
        &f.ledger.funding_origin(f.channel).unwrap(),
        None,
        0,
        1,
        [1; 32],
    )
    .unwrap();
    a.queue(p.cb.identity.0, 2, i.bytes(), now()).unwrap();
    let before = a.inventory().unwrap()[0]["queued_at"].clone();
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        assert!(Instant::now() < deadline);
        a.tick(now()).unwrap();
        b.tick(now()).unwrap();
        if a.status()["diagnostic"]
            .as_str()
            .is_some_and(|s| s.contains("pin mismatch"))
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        a.inventory().unwrap()[0]["destination_transport_custody"],
        false
    );
    assert_eq!(a.inventory().unwrap()[0]["queued_at"], before);
    assert_eq!(b.inventory().unwrap(), json!([]));
}
#[test]
fn preserved_admission_identity_prefix_and_capacity_are_not_peer_expandable() {
    let f = fixture();
    let root = directory(f.ledger.chain_id(), "bounds");
    let p = pair(&root, f.ledger.chain_id(), false);
    let mut a = Network::open(&p.a, f.ledger.chain_id(), p.ah, now()).unwrap();
    let mut data = vec![0; 262144];
    data[..4].copy_from_slice(&[0, 2, 0, 1]);
    data[4..36].copy_from_slice(&f.ledger.chain_id());
    // Deliberately unexecuted native bodies test transport bytes/budgets only;
    // no ledger acceptance or funded-state authority is asserted by this shape.
    let mut accepted = 0u16;
    loop {
        data[262142..].copy_from_slice(&accepted.to_be_bytes());
        let before = a.head();
        match a.queue(p.cb.identity.0, 1, &data, now()) {
            Ok(_) => accepted += 1,
            Err(e) => {
                assert!(e.contains("reservation"), "{e}");
                assert_eq!(a.head(), before);
                break;
            }
        }
        assert!(accepted < 200);
    }
    assert_eq!(accepted, 127);
    let head = a.head();
    drop(a);
    let config_path = p.a.join("admission.json");
    let mut bad = p.ca.clone();
    let port = bad.peers[0].endpoint.port().saturating_add(1);
    bad.peers[0].endpoint.set_port(port);
    fs::write(&config_path, serde_json::to_vec(&bad).unwrap()).unwrap();
    assert!(Network::open(&p.a, f.ledger.chain_id(), head, now()).is_err());
}

#[test]
fn peer_tail_recovery_authenticates_one_exact_successor_without_appending_or_signing() {
    let f = fixture();
    let chain = f.ledger.chain_id();
    let root = directory(chain, "tail-recovery");
    let p = pair(&root, chain, false);
    let mut a = Network::open(&p.a, chain, p.ah, now()).unwrap();
    let invoice = Invoice::propose(
        &f.ledger.funding_origin(f.channel).unwrap(),
        None,
        0,
        7,
        [1; 32],
    )
    .unwrap();
    let id = a.queue(p.cb.identity.0, 2, invoice.bytes(), now()).unwrap();
    let current = a.head();
    let age = a.inventory().unwrap()[0]["queued_at"].clone();
    drop(a);
    let path = p.a.join("custody.journal");
    let retained = fs::read(&path).unwrap();
    let packet = codec::Packet::decode(&retained[205..retained.len() - 32], chain).unwrap();
    let message: Hash = packet.raw[101..133].try_into().unwrap();
    for token in [id, message] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_rld-fast-peer"))
            .args([
                "recover",
                p.a.to_str().unwrap(),
                &hex::encode(chain),
                &hex::encode(p.ah),
                &hex::encode(token),
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let v: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(hv(&v, "peer_head"), current);
        assert_eq!(v["wallet_key_loaded"], false);
        assert_eq!(v["first_sign"], false);
        assert_eq!(v["records_appended"], 0);
        assert_eq!(fs::read(&path).unwrap(), retained);
    }
    for (prior, token) in [(current, id), (p.ah, [1; 32])] {
        assert!(fast_peer::recover(&p.a, chain, prior, token, now()).is_err());
        assert_eq!(fs::read(&path).unwrap(), retained);
    }
    assert!(Network::open(&p.a, chain, p.ah, now()).is_err());
    let mut a = Network::open(&p.a, chain, current, now()).unwrap();
    assert_eq!(a.inventory().unwrap()[0]["queued_at"], age);
    let invoice2 = Invoice::propose(
        &f.ledger.funding_origin(f.channel).unwrap(),
        None,
        0,
        8,
        [2; 32],
    )
    .unwrap();
    let id2 = a
        .queue(p.cb.identity.0, 2, invoice2.bytes(), now())
        .unwrap();
    let next = a.head();
    drop(a);
    let retained = fs::read(&path).unwrap();
    assert!(fast_peer::recover(&p.a, chain, p.ah, id, now()).is_err());
    assert!(fast_peer::recover(&p.a, chain, current, id, now()).is_err());
    assert_eq!(
        hv(
            &fast_peer::recover(&p.a, chain, current, id2, now()).unwrap(),
            "peer_head"
        ),
        next
    );
    assert_eq!(fs::read(&path).unwrap(), retained);
}

#[test]
fn damaged_replaced_torn_and_rehashed_invalid_custody_is_preserved_and_refused() {
    for mode in 0..5 {
        let f = fixture();
        let chain = f.ledger.chain_id();
        let root = directory(chain, &format!("custody-fault-{mode}"));
        let p = pair(&root, chain, false);
        let mut a = Network::open(&p.a, chain, p.ah, now()).unwrap();
        let invoice = Invoice::propose(
            &f.ledger.funding_origin(f.channel).unwrap(),
            None,
            0,
            7,
            [1; 32],
        )
        .unwrap();
        let id = a.queue(p.cb.identity.0, 2, invoice.bytes(), now()).unwrap();
        let current = a.head();
        let path = p.a.join("custody.journal");
        let mut bad = fs::read(&path).unwrap();
        if mode == 1 {
            fs::rename(&path, p.a.join("retained-replaced.journal")).unwrap();
            write(&path, &bad);
            assert!(a.inventory().unwrap_err().contains("replaced file"));
            assert_eq!(a.status()["custody_ready"], false);
        } else if mode == 0 {
            let at = bad.len() - 33;
            bad[at] ^= 1;
            fs::write(&path, &bad).unwrap();
            assert!(a.inventory().unwrap_err().contains("changed prefix"));
            assert_eq!(a.status()["custody_ready"], false);
        } else {
            drop(a);
            if mode == 2 {
                bad.pop();
            } else {
                let end = bad.len() - 32;
                if mode == 3 {
                    bad[end - 1] ^= 1;
                } else {
                    bad[201..205].fill(255);
                }
                let digest = codec::hash("BOX-RECORD", &bad[152..end]);
                bad[end..].copy_from_slice(&digest);
            }
            fs::write(&path, &bad).unwrap();
            assert!(Network::open(&p.a, chain, current, now()).is_err());
            assert!(fast_peer::recover(&p.a, chain, p.ah, id, now()).is_err());
        }
        assert_eq!(fs::read(&path).unwrap(), bad, "preserve fault mode {mode}");
    }
}

struct Node {
    child: Option<std::process::Child>,
    input: Option<std::process::ChildStdin>,
    rx: std::sync::mpsc::Receiver<String>,
    head: Id,
    tip: Id,
    peer: Id,
    count: u64,
    deadline: Instant,
    root: PathBuf,
    label: String,
    initial: Value,
}
impl Node {
    fn start(
        root: &Path,
        label: &str,
        binary: &str,
        args: Vec<std::ffi::OsString>,
        deadline: Instant,
    ) -> Self {
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        let mut child = Command::new(binary)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(fs::File::create(root.join(format!("{label}.stderr.log"))).unwrap())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = child.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let log = root.join(format!("{label}.stdout.log"));
        std::thread::spawn(move || {
            let mut file = fs::File::create(log).unwrap();
            for line in BufReader::new(output).lines() {
                let line = line.unwrap();
                writeln!(file, "{line}").unwrap();
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut n = Self {
            child: Some(child),
            input: Some(input),
            rx,
            head: Id([0; 32]),
            tip: Id([0; 32]),
            peer: Id([0; 32]),
            count: 0,
            deadline,
            root: root.to_path_buf(),
            label: label.into(),
            initial: Value::Null,
        };
        let ready = n.receive();
        n.update(&ready);
        n.initial = ready;
        n
    }
    fn receive(&self) -> Value {
        let s = self
            .rx
            .recv_timeout(self.deadline.saturating_duration_since(Instant::now()))
            .expect("original180 peer process output");
        serde_json::from_str(&s).unwrap()
    }
    fn update(&mut self, v: &Value) {
        if v["session_head"].is_string() {
            self.head = Id(hv(v, "session_head"));
        }
        if v["selected_tip"].is_string() {
            self.tip = Id(hv(v, "selected_tip"));
        }
        if v["peer"]["peer_head"].is_string() {
            self.peer = Id(hv(&v["peer"], "peer_head"));
        } else if v["peer_head"].is_string() {
            self.peer = Id(hv(v, "peer_head"));
        }
    }
    fn send(&mut self, mut v: Value) -> Value {
        v["head"] = serde_json::to_value(self.head).unwrap();
        writeln!(self.input.as_mut().unwrap(), "{v}").unwrap();
        self.input.as_mut().unwrap().flush().unwrap();
        let out = self.receive();
        self.update(&out);
        out
    }
    fn ok(&mut self, v: Value) -> Value {
        let out = self.send(v);
        assert!(out["diagnostic"].is_null(), "{} {out}", self.label);
        out
    }
    fn request_id(&mut self) -> Id {
        self.count += 1;
        let mut b = [0; 32];
        b[..8].copy_from_slice(&self.count.to_be_bytes());
        Id(b)
    }
    fn execute(
        &mut self,
        a: rld_survivor_node::fast_session::Action,
        password: Option<&str>,
    ) -> (Id, Value) {
        let id = self.request_id();
        let out =
            self.ok(json!({"command":"execute","request_id":id,"action":a,"password":password}));
        (id, out)
    }
    fn wait_data(&mut self, id: Id) {
        loop {
            let r = self.send(json!({"command":"peer_data","packet":id}));
            if r["diagnostic"].is_null() {
                return;
            }
            assert!(Instant::now() < self.deadline, "original180 incoming data");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn drain(&mut self) {
        loop {
            let r = self.ok(json!({"command":"peer_inventory"}));
            let pending = r["packets"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v["received"] == false && v["destination_transport_custody"] != true);
            if !pending {
                return;
            }
            assert!(Instant::now() < self.deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn finish(&mut self) {
        self.input.take();
        let c = self.child.as_mut().unwrap();
        let pid = c.id();
        let status = loop {
            if let Some(s) = c.try_wait().unwrap() {
                break s;
            }
            assert!(Instant::now() < self.deadline, "original180 terminal");
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(status.success());
        write(&self.root.join(format!("{}.terminal.json",self.label)),json!({"pid":pid,"exit_code":status.code(),"success":status.success(),"forced_stop":false}).to_string().as_bytes());
        self.child.take();
    }
}
impl Drop for Node {
    fn drop(&mut self) {
        if let Some(c) = self.child.as_mut() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}
fn args(
    mode: &str,
    root: &Path,
    genesis: &Path,
    chain: Hash,
    head: Option<Id>,
    peer: Option<(&Path, Id)>,
) -> Vec<std::ffi::OsString> {
    let mut v = vec![
        mode.into(),
        root.as_os_str().into(),
        genesis.as_os_str().into(),
        hex::encode(chain).into(),
    ];
    if let Some(h) = head {
        v.push(hex::encode(h.0).into());
    }
    if let Some((p, h)) = peer {
        v.extend([
            "--peer-root".into(),
            p.as_os_str().into(),
            "--peer-head".into(),
            hex::encode(h.0).into(),
        ]);
    }
    v
}
fn vid(v: &Value, k: &str) -> Id {
    Id(hv(v, k))
}
#[test]
fn three_peer_enabled_processes_move_native_funding_and_actual_onward_authorization() {
    use rld_survivor_node::fast_session::Action;
    let deadline = Instant::now() + Duration::from_secs(180);
    let f = fixture();
    let chain = f.ledger.chain_id();
    let root = directory(chain, "three-process");
    let genesis = root.join("genesis");
    write(&genesis, &f.genesis);
    let mut infos = vec![];
    let mut peer_roots = vec![];
    let mut holds = vec![];
    for i in 0..3 {
        let p = root.join(format!("peer-{i}"));
        let mut n = Node::start(
            &root,
            &format!("init-{i}"),
            env!("CARGO_BIN_EXE_rld-fast-peer"),
            vec![
                "init".into(),
                p.as_os_str().into(),
                hex::encode(chain).into(),
            ],
            deadline,
        );
        infos.push(n.initial.clone());
        n.finish();
        peer_roots.push(p);
        holds.push(Some(TcpListener::bind("127.0.0.1:0").unwrap()));
    }
    let endpoints = holds
        .iter()
        .map(|l| l.as_ref().unwrap().local_addr().unwrap())
        .collect::<Vec<_>>();
    let mut peer_heads = vec![];
    for i in 0..3 {
        let c = Config {
            chain: Id(chain),
            identity: Id(hv(&infos[i], "identity")),
            listen: endpoints[i],
            peers: (0..3)
                .filter(|j| *j != i)
                .map(|j| PeerPin {
                    key: Id(hv(&infos[j], "identity")),
                    endpoint: endpoints[j],
                    certificate_sha256: Id(hv(&infos[j], "certificate_sha256")),
                })
                .collect(),
        };
        let path = root.join(format!("admission-{i}.json"));
        write(&path, &serde_json::to_vec(&c).unwrap());
        let mut n = Node::start(
            &root,
            &format!("bind-{i}"),
            env!("CARGO_BIN_EXE_rld-fast-peer"),
            vec![
                "bind".into(),
                peer_roots[i].as_os_str().into(),
                path.as_os_str().into(),
            ],
            deadline,
        );
        peer_heads.push(vid(&n.initial, "peer_head"));
        n.finish();
    }
    let mut nodes = vec![];
    let mut node_roots = vec![];
    for i in 0..3 {
        let p = root.join(format!("node-{i}"));
        let mut c = Node::start(
            &root,
            &format!("create-{i}"),
            env!("CARGO_BIN_EXE_rld-fast-payment-session"),
            args("create", &p, &genesis, chain, None, None),
            deadline,
        );
        let h = c.head;
        c.finish();
        holds[i].take();
        let n = Node::start(
            &root,
            &format!("serve-{i}"),
            env!("CARGO_BIN_EXE_rld-fast-payment-session"),
            args(
                "serve",
                &p,
                &genesis,
                chain,
                Some(h),
                Some((&peer_roots[i], peer_heads[i])),
            ),
            deadline,
        );
        assert_eq!(n.initial["peer"]["listen"], endpoints[i].to_string());
        nodes.push(n);
        node_roots.push(p);
    }
    let mut ids = [Vec::new(), Vec::new()];
    let mut at = 0;
    while at < f.history.len() {
        let n = u32::from_be_bytes(f.history[at..at + 4].try_into().unwrap()) as usize;
        at += 4;
        let block = hex::encode(&f.history[at..at + n]);
        at += n;
        let tip = nodes[0].tip;
        nodes[0].execute(
            Action::Native {
                tip,
                block: block.clone(),
            },
            None,
        );
        for j in 1..3 {
            let v=nodes[0].ok(json!({"command":"peer_queue","destination":Id(hv(&infos[j],"identity")),"kind":1,"payload":block}));
            ids[j - 1].push(vid(&v, "packet"));
        }
    }
    // No peer is given a decoded ledger or controller-carried block at import.
    // Only exact received packet IDs cross this local acceptance boundary.
    for j in 1..3 {
        for id in &ids[j - 1] {
            nodes[j].wait_data(*id);
            let r = nodes[j].request_id();
            nodes[j].ok(json!({"command":"peer_import","packet":id,"request_id":r}));
        }
        assert_eq!(nodes[j].tip.0, f.ledger.tip().id());
    }
    let mut actors = vec![];
    let mut key_paths = vec![];
    let delegation = hex::encode(delegation(&f));
    for (i, node) in nodes.iter_mut().enumerate() {
        let tip = node.tip;
        let a = if i < 2 {
            Action::OwnerCreate {
                tip,
                channel: Id(f.channel),
                owner: i as u8,
                delegation: delegation.clone(),
            }
        } else {
            Action::RetainerCreate {
                tip,
                channel: Id(f.channel),
                delegation: delegation.clone(),
            }
        };
        let (_, v) = node.execute(a, None);
        actors.push(vid(&v, "actor"));
        let p = root.join(format!("wallet-{i}.key"));
        write(
            &p,
            &rld_survivor_node::keyfile::encrypt(
                if i < 2 { &f.owners[i] } else { &f.retainer },
                chain,
                b"public no-value peer passphrase",
            )
            .unwrap(),
        );
        key_paths.push(p);
    }
    let mut last_receipt = None;
    for (round, payer, amount) in [(1u8, 0usize, 70u128), (2, 1, 25)] {
        let recipient = 1 - payer;
        let proposal=nodes[payer].ok(json!({"command":"propose","actor":actors[payer],"payer":payer,"amount":amount.to_string(),"invoice":Id([round;32])}));
        let inv = vid(&proposal, "invoice_id");
        let tip = nodes[payer].tip;
        let (payer_review, pv) = nodes[payer].execute(
            Action::OwnerPrepare {
                tip,
                actor: actors[payer],
                invoice: proposal["invoice_hex"].as_str().unwrap().into(),
            },
            None,
        );
        let mut restart = None;
        if round == 2 {
            nodes[recipient].drain();
            let h = nodes[recipient].head;
            let v = nodes[recipient].ok(json!({"command":"peer_status"}));
            let ph = vid(&v, "peer_head");
            nodes[recipient].finish();
            restart = Some((h, ph));
        }
        let sent=nodes[payer].ok(json!({"command":"peer_invoice","actor":actors[payer],"invoice":inv,"destination":Id(hv(&infos[recipient],"identity"))}));
        let invoice_packet = vid(&sent, "packet");
        if let Some((h, ph)) = restart {
            let inventory = nodes[payer].ok(json!({"command":"peer_inventory"}));
            let original = inventory["packets"]
                .as_array()
                .unwrap()
                .iter()
                .find(|v| vid(v, "id") == invoice_packet)
                .unwrap()["queued_at"]
                .clone();
            let mut observed = false;
            while !observed {
                let status = nodes[payer].ok(json!({"command":"peer_status"}));
                observed = status["peer"]["diagnostic"].is_string();
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(10));
            }
            nodes[recipient] = Node::start(
                &root,
                &format!("restarted-{recipient}"),
                env!("CARGO_BIN_EXE_rld-fast-payment-session"),
                args(
                    "serve",
                    &node_roots[recipient],
                    &genesis,
                    chain,
                    Some(h),
                    Some((&peer_roots[recipient], ph)),
                ),
                deadline,
            );
            nodes[recipient].count = 10000;
            nodes[recipient].wait_data(invoice_packet);
            let inventory = nodes[payer].ok(json!({"command":"peer_inventory"}));
            assert_eq!(
                inventory["packets"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|v| vid(v, "id") == invoice_packet)
                    .unwrap()["queued_at"],
                original
            );
        }
        nodes[recipient].wait_data(invoice_packet);
        let rr = nodes[recipient].request_id();
        let rv=nodes[recipient].ok(json!({"command":"peer_prepare","actor":actors[recipient],"packet":invoice_packet,"request_id":rr}));
        for (i, r, v) in [(payer, payer_review, &pv), (recipient, rr, &rv)] {
            let tip = nodes[i].tip;
            nodes[i].execute(
                Action::OwnerSign {
                    tip,
                    actor: actors[i],
                    invoice: inv,
                    review_request: r,
                    review: vid(v, "review_digest"),
                    key_file: key_paths[i].to_string_lossy().into(),
                    approved: true,
                },
                Some("public no-value peer passphrase"),
            );
        }
        let pa=nodes[0].ok(json!({"command":"peer_partial","actor":actors[0],"invoice":inv,"destination":Id(hv(&infos[1],"identity"))}));
        let pb=nodes[1].ok(json!({"command":"peer_partial","actor":actors[1],"invoice":inv,"destination":Id(hv(&infos[0],"identity"))}));
        let partials = [vid(&pa, "packet"), vid(&pb, "packet")];
        nodes[0].wait_data(partials[1]);
        nodes[1].wait_data(partials[0]);
        let full=nodes[0].ok(json!({"command":"peer_combine_send","actor":actors[0],"invoice":inv,"partial":partials[1],"destinations":[Id(hv(&infos[2],"identity"))]}));
        let receipt_packet = vid(&full["sent"][0], "packet");
        nodes[2].wait_data(receipt_packet);
        let r = nodes[2].request_id();
        let v=nodes[2].ok(json!({"command":"peer_prepare","actor":actors[2],"packet":receipt_packet,"request_id":r}));
        let receipt = vid(&v["review"], "receipt_id");
        let tip = nodes[2].tip;
        nodes[2].execute(
            Action::RetainerSign {
                tip,
                actor: actors[2],
                receipt,
                review_request: r,
                review: vid(&v, "review_digest"),
                key_file: key_paths[2].to_string_lossy().into(),
                approved: true,
            },
            Some("public no-value peer passphrase"),
        );
        if round == 1 {
            let ack = nodes[2].ok(json!({"command":"pending","actor":actors[2],"invoice":receipt}));
            let mut bad = hex::decode(ack["ack_hex"].as_str().unwrap()).unwrap();
            bad[339] ^= 1;
            let fake=nodes[2].ok(json!({"command":"peer_queue","destination":Id(hv(&infos[1],"identity")),"kind":5,"payload":hex::encode(bad)}));
            let fake = vid(&fake, "packet");
            nodes[1].wait_data(fake);
            let request = nodes[1].request_id();
            let refused=nodes[1].send(json!({"command":"peer_complete","actor":actors[1],"invoice":inv,"partial":partials[0],"ack":fake,"request_id":request}));
            assert!(refused["diagnostic"].is_string());
            assert!(refused["receipt_hex"].is_null());
        }
        for i in 0..2 {
            let ack=nodes[2].ok(json!({"command":"peer_ack","actor":actors[2],"receipt":receipt,"destination":Id(hv(&infos[i],"identity"))}));
            let ack = vid(&ack, "packet");
            nodes[i].wait_data(ack);
            let request = nodes[i].request_id();
            let complete=nodes[i].ok(json!({"command":"peer_complete","actor":actors[i],"invoice":inv,"partial":partials[1-i],"ack":ack,"request_id":request}));
            assert_eq!(complete["fast_completion_authorized"], false);
            last_receipt = Some(hex::decode(complete["receipt_hex"].as_str().unwrap()).unwrap());
        }
    }
    let origin = f.ledger.funding_origin(f.channel).unwrap();
    let receipt =
        rld_survivor_node::fast_payment::Payment::verify(&origin, &last_receipt.unwrap()).unwrap();
    assert_eq!(
        origin
            .verify_certificate(receipt.after_certificate())
            .unwrap()
            .balances,
        [555, 445]
    );
    for node in &mut nodes {
        node.drain();
        node.finish();
    }
}
