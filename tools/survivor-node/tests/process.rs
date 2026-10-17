//! One real ordinary native process, public NO-VALUE reward identity and fresh
//! genesis. A local process campaign is not independent custody or power-loss.
use rld_survivor_node::{
    kernel::genesis_id,
    store::{Limits, Store},
};
use serde_json::{json, Value};
use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
struct Node {
    child: Child,
    input: Option<ChildStdin>,
    output: Receiver<Value>,
}
impl Node {
    fn send(&mut self, v: Value) {
        writeln!(self.input.as_mut().unwrap(), "{v}").unwrap();
    }
    fn receive(&self) -> Value {
        self.output
            .recv_timeout(Duration::from_secs(30))
            .expect("bounded ordinary-process observation")
    }
    fn request(&mut self, v: Value) -> Value {
        self.send(v);
        loop {
            let x = self.receive();
            assert!(x["diagnostic"].is_null(), "{x}");
            if x["result"]["event"].is_null() {
                return x;
            }
        }
    }
}
impl Drop for Node {
    fn drop(&mut self) {
        drop(self.input.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
#[test]
fn ordinary_process_single_node_mines_then_restarts() {
    let root = std::env::temp_dir().join(format!("rld-survivor-process-{}", std::process::id()));
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
    let mut discriminator = [0; 32];
    getrandom::getrandom(&mut discriminator).unwrap();
    g[13..45].copy_from_slice(&discriminator);
    let pin = genesis_id(&g);
    let file = root.join("genesis.bin");
    std::fs::write(&file, &g).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_rld-survivor-node"))
        .arg("serve")
        .arg(root.join("node"))
        .arg(&file)
        .arg(hex::encode(pin))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let input = child.stdin.take();
    let out = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(out).lines() {
            let Ok(line) = line else { break };
            let v = serde_json::from_str(&line).unwrap();
            if tx.send(v).is_err() {
                break;
            }
        }
    });
    let mut n = Node {
        child,
        input,
        output: rx,
    };
    let status = n.request(json!({"method":"node_status"}));
    assert_eq!(status["result"]["height"], "0");
    assert_eq!(status["result"]["mining"], false);
    n.request(json!({"method":"set_mining","enabled":true,"miner":v["wallet_public_keys"][0]}));
    let mut events = 0;
    while events < 102 {
        let x = n.receive();
        assert!(x["diagnostic"].is_null(), "{x}");
        if x["result"]["event"] == "SELECTED_CHANGE" {
            events += 1;
        }
    }
    n.request(json!({"method":"set_mining","enabled":false}));
    let balance = n.request(json!({"method":"wallet_state","owner":v["wallet_public_keys"][0]}));
    assert!(
        balance["result"]["available"]
            .as_str()
            .unwrap()
            .parse::<u128>()
            .unwrap()
            > 0
    );
    let tip = balance["selected_tip"].as_str().unwrap().to_string();
    let revision = balance["revision"].as_str().unwrap().to_string();
    // Abrupt process stop after acknowledged commits, then full native cold replay.
    n.child.kill().unwrap();
    n.child.wait().unwrap();
    drop(n);
    let s = Store::open(&root.join("node"), &g, pin, Limits::default()).unwrap();
    assert_eq!(hex::encode(s.ledger().tip().id()), tip);
    assert_eq!(s.revision().to_string(), revision);
    assert!(s.ledger().tip().height() >= 102);
}
