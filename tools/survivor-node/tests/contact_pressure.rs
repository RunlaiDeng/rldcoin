//! Public NO-VALUE intact-history fixture. A sole ordinary node must keep
//! validating/mining/paying under bounded unauthenticated loopback connections.
//! Actual loopback TLS is not independent-host or interstellar-route qualification.
use ed25519_dalek::SigningKey;
use rld_survivor_node::{
    kernel::genesis_id,
    keyfile,
    store::{Limits, Store},
};
use serde_json::{json, Value};
use std::{
    io::{BufRead, BufReader, Write},
    path::Path,
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
struct Node {
    child: Child,
    input: Option<ChildStdin>,
    output: Receiver<Value>,
}
impl Node {
    fn start(root: &Path, g: &Path, pin: [u8; 32], config: Option<&Path>) -> Self {
        let mut c = Command::new(env!("CARGO_BIN_EXE_rld-survivor-node"));
        c.arg("serve").arg(root).arg(g).arg(hex::encode(pin));
        if let Some(p) = config {
            c.arg(p);
        }
        let mut child = c
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let input = child.stdin.take();
        let out = child.stdout.take().unwrap();
        let (tx, output) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines() {
                let Ok(line) = line else { break };
                let value = serde_json::from_str(&line).unwrap();
                if tx.send(value).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            input,
            output,
        }
    }
    fn request(&mut self, v: Value) -> Value {
        writeln!(self.input.as_mut().unwrap(), "{v}").unwrap();
        loop {
            let x = self
                .output
                .recv_timeout(Duration::from_secs(30))
                .expect("native response deadline");
            assert!(x["diagnostic"].is_null(), "{x}");
            if x["result"]["event"].is_null() {
                return x;
            }
        }
    }
    fn status(&mut self) -> Value {
        self.request(json!({"method":"node_status"}))
    }
}
impl Drop for Node {
    fn drop(&mut self) {
        drop(self.input.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Pressure {
    started: Instant,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<(u64, u64, u64)>>,
}
impl Pressure {
    fn start(endpoint: std::net::SocketAddr) -> Self {
        assert!(
            endpoint.ip().is_loopback(),
            "loopback-only pressure fixture"
        );
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let worker = std::thread::spawn(move || {
            let mut stalled = Vec::new();
            let mut cycle = Instant::now();
            let (mut attempts, mut sent, mut holds) = (0, 0, 0);
            while !stopping.load(Ordering::Relaxed) {
                if stalled.is_empty() || cycle.elapsed() >= Duration::from_millis(3200) {
                    stalled.clear();
                    cycle = Instant::now();
                    for _ in 0..2 {
                        attempts += 1;
                        if let Ok(s) = std::net::TcpStream::connect_timeout(
                            &endpoint,
                            Duration::from_millis(50),
                        ) {
                            stalled.push(s);
                            holds += 1;
                        }
                    }
                }
                attempts += 1;
                if let Ok(mut s) =
                    std::net::TcpStream::connect_timeout(&endpoint, Duration::from_millis(50))
                {
                    let _ = s.set_write_timeout(Some(Duration::from_millis(50)));
                    // Invalid TLS bytes, never an authenticated frame or custody request.
                    if s.write_all(b"PUBLIC NO-VALUE INVALID TLS RECORD").is_ok() {
                        sent += 1;
                    }
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            (attempts, sent, holds)
        });
        Self {
            started: Instant::now(),
            stop,
            worker: Some(worker),
        }
    }
    fn finish(mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let (attempts, sent, holds) = self.worker.take().unwrap().join().unwrap();
        assert!(self.started.elapsed() >= Duration::from_secs(120));
        assert!(attempts >= 1000 && sent > 0 && holds > 0);
    }
}
impl Drop for Pressure {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(h) = self.worker.take() {
            let _ = h.join();
        }
    }
}

fn wait(deadline: Instant, mut ready: impl FnMut() -> bool) {
    loop {
        assert!(Instant::now() < deadline, "whole payment campaign deadline");
        if ready() {
            assert!(Instant::now() < deadline);
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
fn payment(
    n: &mut Node,
    chain: [u8; 32],
    key: &SigningKey,
    to: [u8; 32],
    file: &Path,
    operation: u8,
) -> String {
    let owner = key.verifying_key().to_bytes();
    let b = n.request(json!({"method":"wallet_state","owner":hex::encode(owner)}));
    let coin = b["result"]["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["eligible_next_height"] == true && c["reserved"] == false)
        .expect("mature available input");
    let amount = coin["amount"].as_str().unwrap().parse::<u128>().unwrap();
    assert!(amount > 2);
    let review=n.request(json!({"method":"propose_transfer","operation_id":hex::encode([operation;32]),"owner":hex::encode(owner),"inputs":[coin["outpoint"]],"outputs":[{"owner":hex::encode(to),"amount":(amount-1).to_string()}],"fee":"1"}));
    assert_eq!(review["chain_id"], hex::encode(chain));
    let signed=n.request(json!({"method":"sign_review","operation_id":hex::encode([operation;32]),"review_digest":review["result"]["review_digest"],"key_file":file,"password":"public no-value process passphrase"}));
    n.request(json!({"method":"submit_transaction","operation_id":hex::encode([operation+1;32]),"transaction_hex":signed["result"]["transaction_hex"]}));
    hex::encode([operation; 32])
}
#[test]
fn survivor_continues_native_payment_during_invalid_connection_pressure() {
    let deadline = Instant::now() + Duration::from_secs(180);
    let root = std::env::temp_dir().join(format!(
        "rld-survivor-contact-pressure-{}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    let v: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/survivor-v1/vectors.json"
    ))
    .unwrap();
    let mut g = hex::decode(v["genesis"]["manifest_hex"].as_str().unwrap()).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    g[45..53].copy_from_slice(&(now - 86400).to_be_bytes());
    getrandom::getrandom(&mut g[13..45]).unwrap();
    let pin = genesis_id(&g);
    let genesis = root.join("genesis.bin");
    std::fs::write(&genesis, &g).unwrap();
    // Explicit public NO-VALUE fixture seeds, never generated production custody.
    let ka = SigningKey::from_bytes(&[31; 32]);
    let kb = SigningKey::from_bytes(&[32; 32]);
    let kc = SigningKey::from_bytes(&[33; 32]);
    let akey = root.join("a.key");
    let bkey = root.join("b.key");
    for (path, key) in [(&akey, &ka), (&bkey, &kb)] {
        std::fs::write(
            path,
            keyfile::encrypt(key, pin, b"public no-value process passphrase").unwrap(),
        )
        .unwrap();
    }
    // This load cohort begins with an intact common native prefix. It does
    // not replace ordinary fresh-download or initial-mining qualification.
    let mut warm =
        rld_survivor_node::kernel::Ledger::from_genesis(&g, pin, Limits::default().coins).unwrap();
    let start = u64::from_be_bytes(g[45..53].try_into().unwrap());
    let mut prefix = Vec::new();
    for h in 1..=100 {
        let mut job = warm
            .mining_job(ka.verifying_key().to_bytes(), vec![], start + h * 600, now)
            .unwrap();
        let raw = job.attempt(1_000_000).unwrap();
        warm.execute(&raw).unwrap();
        prefix.push(raw);
    }
    for name in ["a", "b"] {
        let mut store = Store::open(&root.join(name), &g, pin, Limits::default()).unwrap();
        for (i, group) in prefix.chunks(32).enumerate() {
            store.accept_history([i as u8 + 1; 32], group, now).unwrap();
        }
    }
    let mut a = Node::start(&root.join("a"), &genesis, pin, None);
    let mut b = Node::start(&root.join("b"), &genesis, pin, None);
    let sa = a.status();
    let sb = b.status();
    a.request(json!({"method":"set_mining","enabled":true,"miner":hex::encode(ka.verifying_key().to_bytes())}));
    wait(deadline, || {
        a.status()["result"]["height"]
            .as_str()
            .unwrap()
            .parse::<u128>()
            .unwrap()
            >= 100
    });
    a.request(json!({"method":"set_mining","enabled":false}));
    let initial = a.status();
    drop(a);
    drop(b);
    let cfg = |own: &Value, peer: &Value| json!({"listen":own["result"]["relay"]["listen"],"neighbors":[{"key":peer["result"]["relay"]["identity"],"endpoint":peer["result"]["relay"]["listen"],"certificate_sha256":peer["result"]["relay"]["certificate_sha256"]}]});
    let ac = root.join("a.json");
    let bc = root.join("b.json");
    std::fs::write(&ac, cfg(&sa, &sb).to_string()).unwrap();
    std::fs::write(&bc, cfg(&sb, &sa).to_string()).unwrap();
    let mut a = Node::start(&root.join("a"), &genesis, pin, Some(&ac));
    let mut b = Node::start(&root.join("b"), &genesis, pin, Some(&bc));
    wait(deadline, || {
        b.status()["selected_tip"] == initial["selected_tip"]
    });
    let op = payment(&mut a, pin, &ka, kb.verifying_key().to_bytes(), &akey, 201);
    a.request(json!({"method":"set_mining","enabled":true,"miner":hex::encode(ka.verifying_key().to_bytes())}));
    wait(deadline, || {
        a.request(json!({"method":"operation_status","operation_id":op}))["result"]["ledger"]
            == "INCLUDED"
    });
    a.request(json!({"method":"set_mining","enabled":false}));
    let paid = a.status();
    wait(deadline, || {
        b.status()["selected_tip"] == paid["selected_tip"]
    });
    let balance = b.request(
        json!({"method":"wallet_state","owner":hex::encode(kb.verifying_key().to_bytes())}),
    );
    assert!(
        balance["result"]["available"]
            .as_str()
            .unwrap()
            .parse::<u128>()
            .unwrap()
            > 0
    );
    drop(a); // The source/founder process is gone before the next signature/block.
    let pressure = Pressure::start(
        sb["result"]["relay"]["listen"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap(),
    );
    let onward = payment(&mut b, pin, &kb, kc.verifying_key().to_bytes(), &bkey, 211);
    b.request(json!({"method":"set_mining","enabled":true,"miner":hex::encode(kb.verifying_key().to_bytes())}));
    wait(deadline, || {
        b.request(json!({"method":"operation_status","operation_id":onward}))["result"]["ledger"]
            == "INCLUDED"
    });
    b.request(json!({"method":"set_mining","enabled":false}));
    let prior_height: u128 = b.status()["result"]["height"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    b.request(json!({"method":"set_mining","enabled":true,"miner":hex::encode(kb.verifying_key().to_bytes())}));
    wait(deadline, || {
        b.status()["result"]["height"]
            .as_str()
            .unwrap()
            .parse::<u128>()
            .unwrap()
            >= prior_height + 101
    });
    b.request(json!({"method":"set_mining","enabled":false}));
    let own_balance = b.request(
        json!({"method":"wallet_state","owner":hex::encode(kb.verifying_key().to_bytes())}),
    );
    assert!(
        own_balance["result"]["available"]
            .as_str()
            .unwrap()
            .parse::<u128>()
            .unwrap()
            > 0
    );
    let final_status = b.status();
    let balance = b.request(
        json!({"method":"wallet_state","owner":hex::encode(kc.verifying_key().to_bytes())}),
    );
    assert!(
        balance["result"]["available"]
            .as_str()
            .unwrap()
            .parse::<u128>()
            .unwrap()
            > 0
    );
    assert_eq!(balance["confidence"], "CONDITIONAL");
    wait(deadline, || {
        let status = b.status();
        assert_eq!(status["storage_state"], "READY");
        pressure.started.elapsed() >= Duration::from_secs(120)
    });
    pressure.finish();
    let retained = b.request(json!({"method":"operation_status","operation_id":onward}));
    assert_eq!(retained["result"]["ledger"], "INCLUDED");
    assert_eq!(retained["result"]["signature_source"], "LOCAL_WALLET");
    let signed = hex::decode(retained["result"]["transaction_hex"].as_str().unwrap()).unwrap();
    drop(b);
    let cold = Store::open(&root.join("b"), &g, pin, Limits::default()).unwrap();
    assert_eq!(
        hex::encode(cold.ledger().tip().id()),
        final_status["selected_tip"]
    );
    assert_eq!(cold.signed_operation([211; 32]).unwrap(), Some(signed));
    let payer = cold.wallet_state(kb.verifying_key().to_bytes()).unwrap();
    let recipient = cold.wallet_state(kc.verifying_key().to_bytes()).unwrap();
    assert_eq!(
        payer.available.to_string(),
        own_balance["result"]["available"]
    );
    assert_eq!(
        payer.reserved.to_string(),
        own_balance["result"]["reserved"]
    );
    assert_eq!(
        recipient.available.to_string(),
        balance["result"]["available"]
    );
    assert_eq!(
        cold.ledger()
            .coins()
            .values()
            .map(|c| c.amount)
            .sum::<u128>(),
        cold.ledger().issued()
    );
    assert!(Instant::now() < deadline);
}
