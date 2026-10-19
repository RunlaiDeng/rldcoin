//! PUBLIC NO-VALUE fixture keys only. Pool/data custody and own PoW candidates
//! do not grant ledger inclusion, independent freshness or performance claims.
#[allow(dead_code)]
#[path = "support/fast_funding.rs"]
mod support;
use rld_survivor_node::{
    fast_peer::{self, codec, Config, PeerPin},
    fast_session::{Action, Id, OnchainRequest, PoolMiningRequest, Session},
    kernel::{fast, Hash},
    keyfile,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    net::TcpListener,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use support::*;
fn directory(chain: Hash, label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "rld-fast-pool-{}-{}-{label}",
        std::process::id(),
        hex::encode(chain)
    ));
    fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    root
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
}
impl Node {
    fn start(
        location: (&Path, &str),
        state: &Path,
        genesis: &Path,
        chain: Hash,
        peer_root: &Path,
        heads: (Id, Id),
        deadline: Instant,
    ) -> Self {
        let (root, label) = location;
        use std::{
            io::{BufRead, BufReader},
            process::{Command, Stdio},
        };
        let mut child = Command::new(env!("CARGO_BIN_EXE_rld-fast-payment-session"))
            .args([
                "serve",
                state.to_str().unwrap(),
                genesis.to_str().unwrap(),
                &hex::encode(chain),
                &hex::encode(heads.0 .0),
                "--peer-root",
                peer_root.to_str().unwrap(),
                "--peer-head",
                &hex::encode(heads.1 .0),
            ])
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
        let mut node = Self {
            child: Some(child),
            input: Some(input),
            rx,
            head: heads.0,
            tip: Id(chain),
            peer: heads.1,
            count: 0,
            deadline,
            root: root.into(),
            label: label.into(),
        };
        let ready = node.receive();
        node.update(&ready);
        node
    }
    fn receive(&self) -> Value {
        serde_json::from_str(
            &self
                .rx
                .recv_timeout(self.deadline.saturating_duration_since(Instant::now()))
                .expect("original180 pool node response"),
        )
        .unwrap()
    }
    fn update(&mut self, v: &Value) {
        if v["session_head"].is_string() {
            self.head = id(v, "session_head");
        }
        if v["selected_tip"].is_string() {
            self.tip = id(v, "selected_tip");
        }
        if v["peer"]["peer_head"].is_string() {
            self.peer = id(&v["peer"], "peer_head");
        }
    }
    fn send(&mut self, mut v: Value) -> Value {
        assert!(
            Instant::now() < self.deadline,
            "original180 pool node request"
        );
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
    fn request(&mut self) -> Id {
        rid(&mut self.count)
    }
    fn execute(&mut self, a: Action, password: Option<&str>) -> (Id, Value) {
        let request = self.request();
        let v = self
            .ok(json!({"command":"execute","request_id":request,"action":a,"password":password}));
        (request, v)
    }
    fn wait_data(&mut self, packet: Id) {
        loop {
            let v = self.send(json!({"command":"peer_data","packet":packet}));
            if v["diagnostic"].is_null() {
                return;
            }
            assert!(Instant::now() < self.deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn submit_peer(&mut self, packet: Id) -> Id {
        self.wait_data(packet);
        let request = self.request();
        let v = self.ok(json!({"command":"peer_pool_submit","packet":packet,"request_id":request}));
        id(&v, "pool_operation")
    }
    fn import(&mut self, packet: Id) {
        self.wait_data(packet);
        let request = self.request();
        self.ok(json!({"command":"peer_import","packet":packet,"request_id":request}));
    }
    fn mine(&mut self, miner: Id, timestamp: u64) -> Value {
        let mut refresh = true;
        loop {
            let v=self.ok(json!({"command":"mine_pool","miner":miner,"timestamp":timestamp.to_string(),"attempts":4096,"scan_limit":128,"refresh":refresh}));
            refresh = false;
            if v["candidate"].is_string() {
                return v;
            }
        }
    }
    fn admit(&mut self, v: &Value) -> Id {
        let candidate = id(v, "candidate");
        let request = self.request();
        let v = self
            .ok(json!({"command":"admit_candidate","request_id":request,"candidate":candidate}));
        assert_eq!(v["candidate_selected"], true);
        candidate
    }
    fn authorize(&mut self, plan: OnchainRequest, path: &Path) -> Id {
        let (prepare, v) = self.execute(
            Action::OnchainPrepare {
                tip: self.tip,
                plan,
            },
            None,
        );
        let (sign, _) = self.execute(
            Action::OnchainSign {
                tip: self.tip,
                prepare_request: prepare,
                review: id(&v, "review_digest"),
                key_file: path.to_string_lossy().into(),
                approved: true,
            },
            Some("public no-value pool process passphrase"),
        );
        let request = self.request();
        let v = self
            .ok(json!({"command":"submit_authorized","request_id":request,"sign_request":sign}));
        id(&v, "pool_operation")
    }
    fn drain(&mut self) {
        loop {
            let v = self.ok(json!({"command":"peer_inventory"}));
            if !v["packets"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["received"] == false && p["destination_transport_custody"] != true)
            {
                return;
            }
            assert!(Instant::now() < self.deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn finish(&mut self) {
        self.drain();
        self.ok(json!({"command":"peer_status"}));
        self.input.take();
        let c = self.child.as_mut().unwrap();
        let pid = c.id();
        let status = loop {
            if let Some(s) = c.try_wait().unwrap() {
                break s;
            }
            assert!(Instant::now() < self.deadline, "original180 pool node stop");
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(status.success());
        write(
            &self.root.join(format!("{}.terminal.json", self.label)),
            json!({"pid":pid,"exit_code":status.code(),"success":true,"forced_stop":false})
                .to_string()
                .as_bytes(),
        );
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

#[test]
fn actual_peers_relay_signed_claims_mine_own_templates_and_retain_pool_on_restart() {
    let deadline = Instant::now() + Duration::from_secs(180);
    let f = fixture();
    let chain = f.ledger.chain_id();
    let root = directory(chain, "peer-process");
    let genesis = root.join("genesis");
    write(&genesis, &f.genesis);
    let pa = root.join("peer-a");
    let pb = root.join("peer-b");
    let ai = fast_peer::provision(&pa, chain).unwrap();
    let bi = fast_peer::provision(&pb, chain).unwrap();
    let la = TcpListener::bind("127.0.0.1:0").unwrap();
    let lb = TcpListener::bind("127.0.0.1:0").unwrap();
    let ca = Config {
        chain: Id(chain),
        identity: id(&ai, "identity"),
        listen: la.local_addr().unwrap(),
        peers: vec![PeerPin {
            key: id(&bi, "identity"),
            endpoint: lb.local_addr().unwrap(),
            certificate_sha256: id(&bi, "certificate_sha256"),
        }],
    };
    let cb = Config {
        chain: Id(chain),
        identity: id(&bi, "identity"),
        listen: lb.local_addr().unwrap(),
        peers: vec![PeerPin {
            key: ca.identity,
            endpoint: ca.listen,
            certificate_sha256: id(&ai, "certificate_sha256"),
        }],
    };
    let ah = id(
        &fast_peer::bind(&pa, &serde_json::to_vec(&ca).unwrap(), f.now).unwrap(),
        "peer_head",
    );
    let bh = id(
        &fast_peer::bind(&pb, &serde_json::to_vec(&cb).unwrap(), f.now).unwrap(),
        "peer_head",
    );
    drop(la);
    drop(lb);
    let sa = root.join("a");
    let sb = root.join("b");
    let a = Session::create(&sa, &f.genesis, chain, f.now).unwrap();
    let a_head = Id(a.head());
    drop(a);
    let b = Session::create(&sb, &f.genesis, chain, f.now).unwrap();
    let b_head = Id(b.head());
    drop(b);
    let mut a = Node::start(
        (&root, "a"),
        &sa,
        &genesis,
        chain,
        &pa,
        (a_head, ah),
        deadline,
    );
    let mut b = Node::start(
        (&root, "b"),
        &sb,
        &genesis,
        chain,
        &pb,
        (b_head, bh),
        deadline,
    );
    let mut packets = vec![];
    let mut at = 0;
    while at < f.history.len() {
        let z = u32::from_be_bytes(f.history[at..at + 4].try_into().unwrap()) as usize;
        at += 4;
        let block = &f.history[at..at + z];
        at += z;
        a.execute(
            Action::Native {
                tip: a.tip,
                block: hex::encode(block),
            },
            None,
        );
        let v=a.ok(json!({"command":"peer_block","block":Id(fast::block_id(block).unwrap()),"destination":cb.identity}));
        packets.push(id(&v, "packet"));
    }
    for packet in packets {
        b.import(packet);
    }
    assert_eq!(b.tip.0, f.ledger.tip().id());
    let keys = [root.join("owner-a.key"), root.join("owner-b.key")];
    for (i, path) in keys.iter().enumerate() {
        write(
            path,
            &keyfile::encrypt(
                &f.owners[i],
                chain,
                b"public no-value pool process passphrase",
            )
            .unwrap(),
        );
    }
    let close_time = f.ledger.tip().timestamp() + 600;
    let close = OnchainRequest {
        kind: 2,
        channel: Id(f.channel),
        actor: Id(f.owners[0].verifying_key().to_bytes()),
        inputs: vec![hex::encode(out(f.channel, 0))],
        fee: "1".into(),
        expiry: u128::MAX.to_string(),
        nonce: Id([41; 32]),
        certificate: String::new(),
        timestamp: close_time.to_string(),
    };
    let close_id = a.authorize(close, &keys[0]);
    let v = a.mine(Id(f.owners[0].verifying_key().to_bytes()), close_time);
    let own_close = a.admit(&v);
    let origin = f.ledger.funding_origin(f.channel).unwrap();
    let payment =
        rld_survivor_node::fast_payment::Payment::verify(&origin, &payment(&f, None, 0, 70, 42))
            .unwrap();
    let claim = OnchainRequest {
        kind: 4,
        channel: Id(f.channel),
        actor: Id(f.owners[1].verifying_key().to_bytes()),
        inputs: vec![hex::encode(out(f.channel, 1))],
        fee: "1".into(),
        expiry: u128::MAX.to_string(),
        nonce: Id([43; 32]),
        certificate: hex::encode(payment.after_certificate()),
        timestamp: (close_time + 600).to_string(),
    };
    let claim_id = a.authorize(claim.clone(), &keys[1]);
    for (i, key) in keys.iter().enumerate() {
        fs::rename(key, root.join(format!("retained-key-{i}"))).unwrap();
    }
    let v =
        a.ok(json!({"command":"peer_operation","operation":claim_id,"destination":cb.identity}));
    let packet = id(&v, "packet");
    b.wait_data(packet);
    assert_eq!(
        b.ok(json!({"command":"pool_status"}))["operations"],
        json!([])
    );
    assert_eq!(b.tip.0, f.ledger.tip().id());
    assert_eq!(b.submit_peer(packet), claim_id);
    let deferred = b.mine(Id(f.retainer.verifying_key().to_bytes()), close_time);
    assert_eq!(deferred["pool_template"]["selected_operations"], json!([]));
    assert_eq!(
        deferred["pool_template"]["deferred"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(b.tip.0, f.ledger.tip().id());
    let v =
        a.ok(json!({"command":"peer_operation","operation":close_id,"destination":cb.identity}));
    assert_eq!(b.submit_peer(id(&v, "packet")), close_id);
    let v = b.mine(Id(f.retainer.verifying_key().to_bytes()), close_time);
    assert_eq!(v["pool_template"]["selected_operations"], json!([close_id]));
    let remote_close = b.admit(&v);
    assert_ne!(own_close, remote_close);
    let v = b.ok(json!({"command":"peer_block","block":remote_close,"destination":ca.identity}));
    a.import(id(&v, "packet"));
    let first_time =
        b.ok(json!({"command":"pool_status"}))["operations"][0]["local_first_queued_at"].clone();
    b.finish();
    let heads = (b.head, b.peer);
    drop(b);
    let mut b = Node::start(
        (&root, "b-restarted"),
        &sb,
        &genesis,
        chain,
        &pb,
        heads,
        deadline,
    );
    b.count = 100000;
    let status = b.ok(json!({"command":"pool_status"}));
    assert_eq!(status["operations"][0]["local_first_queued_at"], first_time);
    assert_eq!(status["operations"][0]["state"], "RETAINED");
    let v = b.mine(Id(f.retainer.verifying_key().to_bytes()), close_time + 600);
    assert_eq!(v["pool_template"]["selected_operations"], json!([claim_id]));
    let claim_block = b.admit(&v);
    let status = b.ok(json!({"command":"pool_status"}));
    assert_eq!(status["operations"][0]["state"], "INCLUDED");
    assert_eq!(status["operations"][0]["local_first_queued_at"], first_time);
    let v = b.ok(json!({"command":"peer_block","block":claim_block,"destination":ca.identity}));
    a.import(id(&v, "packet"));
    assert_eq!(a.tip, claim_block);
    let mut inspect = claim;
    inspect.inputs = vec![hex::encode(out(claim_id.0, 0))];
    inspect.nonce = Id([44; 32]);
    inspect.timestamp = (close_time + 1200).to_string();
    let (_, v) = a.execute(
        Action::OnchainPrepare {
            tip: a.tip,
            plan: inspect,
        },
        None,
    );
    assert_eq!(v["review"]["known_miner_fee_ranges"], json!(["2", "0"]));
    assert_eq!(
        id(&v["review"], "funding_miner"),
        Id(f.miner.verifying_key().to_bytes())
    );
    a.finish();
    b.finish();
    assert!(
        Instant::now() < deadline,
        "original180 pool peer composition"
    );
}
fn write(path: &Path, raw: &[u8]) {
    let mut o = fs::OpenOptions::new();
    o.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path).unwrap();
    f.write_all(raw).unwrap();
    f.sync_all().unwrap();
}
fn id(v: &Value, key: &str) -> Id {
    serde_json::from_value(v[key].clone()).unwrap()
}
fn rid(n: &mut u64) -> Id {
    *n += 1;
    let mut b = [0; 32];
    b[..8].copy_from_slice(&n.to_be_bytes());
    Id(b)
}
fn execute(s: &mut Session, n: &mut u64, a: Action, now: u64) -> Value {
    let i = rid(n);
    let v = s.execute(i, s.head(), a, None, now).unwrap();
    assert!(v["diagnostic"].is_null(), "{v}");
    v
}
fn funded(f: &Fixture, root: &Path) -> (Session, u64) {
    let mut s = Session::create(root, &f.genesis, f.ledger.chain_id(), f.now).unwrap();
    let mut n = 0;
    let mut at = 0;
    while at < f.history.len() {
        let z = u32::from_be_bytes(f.history[at..at + 4].try_into().unwrap()) as usize;
        at += 4;
        let a = Action::Native {
            tip: Id(s.tip()),
            block: hex::encode(&f.history[at..at + z]),
        };
        at += z;
        execute(&mut s, &mut n, a, f.now);
    }
    (s, n)
}
fn submit(s: &mut Session, n: &mut u64, raw: &[u8], now: u64) -> Value {
    let a = Action::PoolSubmit {
        tip: Id(s.tip()),
        operation: hex::encode(raw),
    };
    execute(s, n, a, now)
}
fn candidate(
    s: &mut Session,
    f: &Fixture,
    time: u64,
    now: u64,
    mut refresh: bool,
    deadline: Instant,
) -> Value {
    loop {
        assert!(Instant::now() < deadline, "original180 pool candidate");
        let v = s
            .mine_pool(
                s.head(),
                PoolMiningRequest {
                    miner: Id(f.miner.verifying_key().to_bytes()),
                    timestamp: time.to_string(),
                    attempts: 4096,
                    scan_limit: 128,
                    refresh,
                },
                now,
            )
            .unwrap();
        refresh = false;
        if v["candidate"].is_string() {
            return v;
        }
    }
}
#[test]
fn signed_pool_preserves_age_conflicts_restart_recovery_and_reorganization() {
    let deadline = Instant::now() + Duration::from_secs(180);
    let f = fixture();
    let chain = f.ledger.chain_id();
    let root = directory(chain, "reorg");
    let state = root.join("session");
    let (mut s, mut n) = funded(&f, &state);
    let first = action(&f, 2, &f.owners[0], (&out(f.channel, 0), 1386), &[], 31);
    let second = action(&f, 2, &f.owners[0], (&out(f.channel, 0), 1386), &[], 32);
    let operation = Id(fast::operation_id(&first));
    let native = s.native_head();
    let v = submit(&mut s, &mut n, &first, f.now);
    assert_eq!(id(&v, "pool_operation"), operation);
    assert_eq!(v["pool_retained"], true);
    assert_eq!(s.native_head(), native);
    submit(&mut s, &mut n, &first, f.now + 1);
    submit(&mut s, &mut n, &second, f.now + 1);
    let status = s.pool_status(s.head(), f.now + 1).unwrap();
    assert_eq!(status["operations"].as_array().unwrap().len(), 2);
    assert_eq!(
        status["operations"][0]["local_first_queued_at"],
        f.now.to_string()
    );
    let mut bad = first.clone();
    let end = bad.len() - 1;
    bad[end] ^= 1;
    let head = s.head();
    let a = Action::PoolSubmit {
        tip: Id(s.tip()),
        operation: hex::encode(bad),
    };
    assert!(s.execute(rid(&mut n), head, a, None, f.now + 1).is_err());
    assert_eq!(s.head(), head);
    let v = candidate(
        &mut s,
        &f,
        f.ledger.tip().timestamp() + 600,
        f.now + 2,
        true,
        deadline,
    );
    assert_eq!(
        v["pool_template"]["selected_operations"],
        json!([operation])
    );
    assert_eq!(v["pool_template"]["deferred"].as_array().unwrap().len(), 1);
    assert_eq!(s.head(), head);
    assert_eq!(s.native_head(), native);
    assert_eq!(
        s.pool_status(head, f.now + 2).unwrap()["operations"][0]["state"],
        "RETAINED"
    );
    let before = s.head();
    assert!(s
        .admit_candidate(before, rid(&mut n), Id([1; 32]), f.now + 2)
        .is_err());
    assert_eq!(s.head(), before);
    let request = rid(&mut n);
    let mined = id(&v, "candidate");
    let receipt = s
        .admit_candidate(before, request, mined, f.now + 2)
        .unwrap();
    assert_eq!(receipt["candidate_selected"], true);
    let head = s.head();
    drop(s);
    let (mut s, recovered) = Session::recover(
        &state,
        &f.genesis,
        chain,
        before,
        request,
        id(&v, "admission_request_digest"),
        f.now + 2,
    )
    .unwrap();
    assert_eq!(s.head(), head);
    assert_eq!(s.tip(), mined.0);
    assert_eq!(recovered["key_loaded_by_recovery"], false);
    let status = s.pool_status(head, f.now + 2).unwrap();
    assert_eq!(status["operations"][0]["state"], "INCLUDED");
    assert_eq!(status["operations"][1]["state"], "RETAINED");
    let mut fork = f.ledger.clone();
    for _ in 0..2 {
        let block = mine(
            &mut fork,
            f.miner.verifying_key().to_bytes(),
            vec![],
            f.now + 3,
        );
        let tip = Id(s.tip());
        execute(
            &mut s,
            &mut n,
            Action::Native {
                tip,
                block: hex::encode(block),
            },
            f.now + 3,
        );
    }
    assert_eq!(s.tip(), fork.tip().id());
    let status = s.pool_status(s.head(), f.now + 3).unwrap();
    assert_eq!(status["operations"][0]["state"], "RETAINED");
    assert_eq!(
        status["operations"][0]["local_first_queued_at"],
        f.now.to_string()
    );
    assert_eq!(
        s.pool_operation(s.head(), operation, f.now + 3).unwrap(),
        first
    );
    let v = candidate(
        &mut s,
        &f,
        fork.tip().timestamp() + 600,
        f.now + 3,
        true,
        deadline,
    );
    let request = rid(&mut n);
    let head = s.head();
    s.admit_candidate(head, request, id(&v, "candidate"), f.now + 3)
        .unwrap();
    assert_eq!(
        s.pool_status(s.head(), f.now + 3).unwrap()["operations"][0]["state"],
        "INCLUDED"
    );
    assert!(Instant::now() < deadline, "original180 pool reorganization");
}
#[test]
fn operation_carriage_is_versioned_exact_and_requires_native_actor_signatures() {
    let f = fixture();
    let chain = f.ledger.chain_id();
    let raw = action(&f, 2, &f.owners[0], (&out(f.channel, 0), 1386), &[], 33);
    let data = codec::operation_payload(chain, &raw).unwrap();
    assert_eq!(data.len(), 38 + raw.len());
    assert_eq!(codec::operation(&data, chain).unwrap(), raw);
    let sender = ed25519_dalek::SigningKey::from_bytes(&[131; 32]);
    let destination = ed25519_dalek::SigningKey::from_bytes(&[132; 32])
        .verifying_key()
        .to_bytes();
    let p = codec::Packet::create(chain, &sender, destination, 6, &data).unwrap();
    assert_eq!(codec::Packet::decode(&p.raw, chain).unwrap().payload, data);
    for position in [0, 4, 36, 37, data.len() - 1] {
        let mut bad = data.clone();
        bad[position] ^= 1;
        assert!(codec::operation(&bad, chain).is_err());
        assert!(codec::Packet::create(chain, &sender, destination, 6, &bad).is_err());
    }
    let mut trailing = data.clone();
    trailing.push(0);
    assert!(codec::operation(&trailing, chain).is_err());
    assert!(codec::operation(&data, [1; 32]).is_err());
    assert!(codec::Packet::create(chain, &sender, destination, 7, &data).is_err());
}

#[test]
fn separately_assembled_public_operation_vector_has_exact_bytes_and_domains() {
    let v: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/fast-native-operation-carriage-v1-vectors.json"
    ))
    .unwrap();
    let raw = |key: &str| hex::decode(v[key].as_str().unwrap()).unwrap();
    let chain: Hash = raw("chain_hex").try_into().unwrap();
    let op = raw("operation_hex");
    assert_eq!(fast::operation_id(&op).as_slice(), raw("operation_id_hex"));
    let frame = raw("payload_hex");
    assert_eq!(codec::operation_payload(chain, &op).unwrap(), frame);
    assert_eq!(codec::operation(&frame, chain).unwrap(), op);
    let sender = ed25519_dalek::SigningKey::from_bytes(&[131; 32]);
    let destination = raw("destination_hex").try_into().unwrap();
    let packet = codec::Packet::create(chain, &sender, destination, 6, &frame).unwrap();
    assert_eq!(packet.raw, raw("packet_hex"));
    assert_eq!(packet.id.as_slice(), raw("packet_id_hex"));
    let decoded = codec::Packet::decode(&packet.raw, chain).unwrap();
    assert_eq!(decoded.payload, frame);
    assert_eq!(decoded.sender.as_slice(), raw("sender_hex"));
    assert_eq!(&packet.raw[101..133], raw("message_tag_hex"));
}

// Independent caller-record fixture assembly for cold signature/capacity checks.
// Its hashes alone never initialize a ledger; native and actor checks still run.
#[derive(Serialize)]
struct Intent {
    id: Id,
    action: Action,
    at: u64,
}
#[derive(Serialize)]
struct Done {
    id: Id,
    request: Id,
    effect: Option<Id>,
    review: Option<Id>,
    diagnostic: Option<String>,
}
fn record(kind: u8, prior: Hash, payload: &[u8]) -> (Vec<u8>, Hash) {
    use sha2::{Digest, Sha256};
    let mut b = vec![kind];
    b.extend(prior);
    b.extend((payload.len() as u32).to_be_bytes());
    b.extend(payload);
    let h: Hash =
        Sha256::digest([b"RLD-FAST-SESSION-1/RECORD\0".as_slice(), b.as_slice()].concat()).into();
    b.extend(h);
    (
        [(b.len() as u32).to_be_bytes().as_slice(), b.as_slice()].concat(),
        h,
    )
}
fn append_operation(path: &Path, head: Hash, request: Id, action: Action, now: u64) -> Hash {
    let digest = action.digest().unwrap();
    let intent = serde_json::to_vec(&Intent {
        id: request,
        action,
        at: now,
    })
    .unwrap();
    let (a, h) = record(1, head, &intent);
    let done = serde_json::to_vec(&Done {
        id: request,
        request: digest,
        effect: None,
        review: None,
        diagnostic: None,
    })
    .unwrap();
    let (b, h) = record(2, h, &done);
    let mut file = fs::OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(&a).unwrap();
    file.write_all(&b).unwrap();
    file.sync_all().unwrap();
    h
}
#[test]
fn cold_pool_capacity_is_permanent_and_rehashed_invalid_signature_is_not_authority() {
    let deadline = Instant::now() + Duration::from_secs(180);
    let f = fixture();
    let chain = f.ledger.chain_id();
    let root = directory(chain, "capacity");
    let state = root.join("session");
    let (s, mut n) = funded(&f, &state);
    let mut head = s.head();
    let tip = Id(s.tip());
    drop(s);
    let path = state.join("caller.journal");
    let owner = f.owners[0].verifying_key().to_bytes();
    let receiver = f.owners[1].verifying_key().to_bytes();
    let (input, coin) = f
        .ledger
        .coins()
        .iter()
        .find(|(_, c)| c.owner == owner && c.maturity <= 103 && c.amount > 10000)
        .unwrap();
    for i in 0..512 {
        let (op, _) = ordinary(
            chain,
            &f.owners[0],
            input,
            &[(receiver, i + 1), (owner, coin.amount - i - 2)],
        );
        head = append_operation(
            &path,
            head,
            rid(&mut n),
            Action::PoolSubmit {
                tip,
                operation: hex::encode(op),
            },
            f.now,
        );
    }
    let mut s = Session::open(&state, &f.genesis, chain, head, f.now).unwrap();
    let status = s.pool_status(head, f.now).unwrap();
    assert_eq!(status["operations"].as_array().unwrap().len(), 512);
    let (op, _) = ordinary(
        chain,
        &f.owners[0],
        input,
        &[(receiver, 999), (owner, coin.amount - 1000)],
    );
    assert!(s
        .execute(
            rid(&mut n),
            head,
            Action::PoolSubmit {
                tip,
                operation: hex::encode(op)
            },
            None,
            f.now
        )
        .unwrap_err()
        .contains("capacity"));
    assert_eq!(s.head(), head);
    drop(s);
    let root = directory(chain, "rehashed");
    let state = root.join("session");
    let (s, mut n) = funded(&f, &state);
    let head = s.head();
    drop(s);
    let path = state.join("caller.journal");
    let mut bad = action(&f, 2, &f.owners[0], (&out(f.channel, 0), 1386), &[], 34);
    let end = bad.len() - 1;
    bad[end] ^= 1;
    let head = append_operation(
        &path,
        head,
        rid(&mut n),
        Action::PoolSubmit {
            tip,
            operation: hex::encode(bad),
        },
        f.now,
    );
    let before = fs::read(&path).unwrap();
    assert!(Session::open(&state, &f.genesis, chain, head, f.now).is_err());
    assert_eq!(fs::read(path).unwrap(), before);
    assert!(Instant::now() < deadline, "original180 pool cold capacity");
}

#[test]
fn pool_cut_child() {
    let Some(path) = std::env::var_os("RLD_POOL_CUT_FILE") else {
        return;
    };
    let v: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let root = Path::new(v["state"].as_str().unwrap());
    let g = hex::decode(v["genesis"].as_str().unwrap()).unwrap();
    let chain = id(&v, "chain");
    let head = id(&v, "head");
    let action = serde_json::from_value(v["action"].clone()).unwrap();
    let now = v["now"].as_u64().unwrap();
    let mut s = Session::open(root, &g, chain.0, head.0, now).unwrap();
    s.execute_observed(id(&v, "request"), head.0, action, None, now, |b| {
        use rld_survivor_node::fast_session::Boundary;
        let cut = match b {
            Boundary::IntentDurable => "intent",
            Boundary::NativeActionEvaluated => "evaluated",
            Boundary::ReplyDurable => "reply",
            Boundary::ChildDurable => "child",
        };
        if cut == v["cut"].as_str().unwrap() {
            write(&root.parent().unwrap().join("cut-reached"), cut.as_bytes());
            loop {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    })
    .unwrap();
    panic!("required pool cut not reached");
}

struct CutChild(Option<std::process::Child>);
impl Drop for CutChild {
    fn drop(&mut self) {
        if let Some(c) = &mut self.0 {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}
#[test]
fn process_cuts_recover_only_exact_signed_pool_data_and_refuse_stale_selection() {
    use std::process::{Command, Stdio};
    let deadline = Instant::now() + Duration::from_secs(180);
    for (cut, stale) in [
        ("intent", false),
        ("evaluated", false),
        ("reply", false),
        ("intent", true),
    ] {
        let f = fixture();
        let chain = f.ledger.chain_id();
        let root = directory(chain, "pool-cut");
        let state = root.join("session");
        let (s, mut n) = funded(&f, &state);
        let prior = s.head();
        let native_head = s.native_head();
        let tip = s.tip();
        let raw = action(&f, 2, &f.owners[0], (&out(f.channel, 0), 1386), &[], 51);
        let operation = Id(fast::operation_id(&raw));
        let action = Action::PoolSubmit {
            tip: Id(if stale { [1; 32] } else { tip }),
            operation: hex::encode(&raw),
        };
        let request = rid(&mut n);
        let digest = action.digest().unwrap();
        drop(s);
        let native = fs::read(state.join("native.journal")).unwrap();
        let config = root.join("child.json");
        write(&config, json!({"state":state,"genesis":hex::encode(&f.genesis),"chain":Id(chain),"head":Id(prior),"action":action,"now":f.now,"request":request,"cut":cut}).to_string().as_bytes());
        let mut child = CutChild(Some(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "pool_cut_child", "--nocapture"])
                .env("RLD_POOL_CUT_FILE", config)
                .stdout(Stdio::from(
                    fs::File::create(root.join("child.stdout.log")).unwrap(),
                ))
                .stderr(Stdio::from(
                    fs::File::create(root.join("child.stderr.log")).unwrap(),
                ))
                .spawn()
                .unwrap(),
        ));
        while !root.join("cut-reached").exists() {
            assert!(Instant::now() < deadline, "original180 pool cut");
            assert!(
                child.0.as_mut().unwrap().try_wait().unwrap().is_none(),
                "pool child exited before boundary"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let c = child.0.as_mut().unwrap();
        let pid = c.id();
        c.kill().unwrap();
        let status = c.wait().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(status.signal(), Some(9));
        }
        child.0.take();
        write(&root.join("terminal.json"), json!({"pid":pid,"intentional_sigkill":true,"boundary":cut,"status":format!("{status:?}")}).to_string().as_bytes());
        let caller_path = state.join("caller.journal");
        let before = fs::read(&caller_path).unwrap();
        assert!(Session::open(&state, &f.genesis, chain, prior, f.now + 1).is_err());
        assert!(Session::recover(
            &state,
            &f.genesis,
            chain,
            prior,
            request,
            Id([1; 32]),
            f.now + 1
        )
        .is_err());
        assert_eq!(fs::read(&caller_path).unwrap(), before);
        let (mut s, v) =
            Session::recover(&state, &f.genesis, chain, prior, request, digest, f.now + 1).unwrap();
        assert_eq!(v["key_loaded_by_recovery"], false);
        assert_eq!(s.native_head(), native_head);
        assert_eq!(s.tip(), tip);
        assert_eq!(fs::read(state.join("native.journal")).unwrap(), native);
        let status = s.pool_status(s.head(), f.now + 1).unwrap();
        if stale {
            assert_eq!(v["diagnostic"], "RECOVERED_POOL_REJECTED_STALE_SELECTION");
            assert_eq!(status["operations"], json!([]));
        } else {
            assert!(v["diagnostic"].is_null());
            assert_eq!(id(&v, "pool_operation"), operation);
            assert_eq!(
                status["operations"][0]["local_first_queued_at"],
                f.now.to_string()
            );
            assert_eq!(status["operations"][0]["local_age_seconds"], "1");
            assert_eq!(status["operations"][0]["state"], "RETAINED");
            assert_eq!(
                s.pool_operation(s.head(), operation, f.now + 1).unwrap(),
                raw
            );
        }
        let head = s.head();
        drop(s);
        let bytes = fs::read(&caller_path).unwrap();
        let (s, _) =
            Session::recover(&state, &f.genesis, chain, prior, request, digest, f.now + 1).unwrap();
        assert_eq!(s.head(), head);
        assert_eq!(fs::read(caller_path).unwrap(), bytes);
    }
    assert!(Instant::now() < deadline, "original180 pool cut recovery");
}
