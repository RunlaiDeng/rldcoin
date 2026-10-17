//! Real timer and ordinary-process recovery. Fresh public NO-VALUE genesis;
//! generated contact/TLS material stays private and must never be printed.
use rld_survivor_node::kernel::genesis_id;
use serde_json::{json, Value};
use std::{
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
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
    fn request(&mut self, value: Value) -> Value {
        writeln!(self.input.as_mut().unwrap(), "{value}").unwrap();
        loop {
            let response = self.output.recv_timeout(Duration::from_secs(3)).unwrap();
            assert!(response["diagnostic"].is_null(), "{response}");
            if response["result"]["event"].is_null() {
                return response;
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
fn ordinary_mining_survives_bind_wait_and_same_listener_recovers_without_restart() {
    let whole = Instant::now() + Duration::from_secs(40);
    let root = std::env::temp_dir().join(format!(
        "rld-survivor-listener-recovery-{}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    let v: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/survivor-v1/vectors.json"
    ))
    .unwrap();
    let mut g = hex::decode(v["genesis"]["manifest_hex"].as_str().unwrap()).unwrap();
    getrandom::getrandom(&mut g[13..45]).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    g[45..53].copy_from_slice(&(now - 86400).to_be_bytes());
    let genesis = root.join("genesis.bin");
    std::fs::write(&genesis, &g).unwrap();
    let blocker = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = blocker.local_addr().unwrap();
    let config = root.join("config.json");
    std::fs::write(
        &config,
        json!({"listen":endpoint.to_string(),"neighbors":[]}).to_string(),
    )
    .unwrap();
    let node_path = root.join("node");
    let mut child = Command::new(env!("CARGO_BIN_EXE_rld-survivor-node"))
        .arg("serve")
        .arg(&node_path)
        .arg(&genesis)
        .arg(hex::encode(genesis_id(&g)))
        .arg(&config)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let input = child.stdin.take();
    let reader = BufReader::new(child.stdout.take().unwrap());
    let (tx, output) = mpsc::channel();
    std::thread::spawn(move || {
        for line in reader.lines() {
            let Ok(line) = line else { break };
            let value: Value = serde_json::from_str(&line).unwrap();
            if tx.send(value).is_err() {
                break;
            }
        }
    });
    let mut node = Node {
        child,
        input,
        output,
    };
    let initial = node.request(json!({"method":"node_status"}));
    assert_eq!(initial["result"]["relay"]["state"], "LISTEN_WAIT");
    assert!(initial["result"]["relay"]["listen"].is_null());
    assert_eq!(
        initial["result"]["relay"]["configured_listen"],
        endpoint.to_string()
    );
    assert!(initial["result"]["relay"]["listener_diagnostic"]
        .as_str()
        .unwrap()
        .starts_with("RESOURCE_WAIT"));
    let key = std::fs::read(node_path.join("contact/contact.secret")).unwrap();
    let tls = std::fs::read(node_path.join("contact/tls.secret")).unwrap();
    node.request(json!({"method":"set_mining","enabled":true,"miner":v["wallet_public_keys"][0]}));
    let mining = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(Instant::now() < mining && Instant::now() < whole);
        let status = node.request(json!({"method":"node_status"}));
        assert_eq!(status["result"]["relay"]["state"], "LISTEN_WAIT");
        assert_eq!(status["storage_state"], "READY");
        if status["result"]["height"]
            .as_str()
            .unwrap()
            .parse::<u128>()
            .unwrap()
            >= 2
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    drop(blocker);
    let observe = Instant::now() + Duration::from_secs(10);
    let final_status = loop {
        assert!(Instant::now() < observe && Instant::now() < whole);
        let status = node.request(json!({"method":"node_status"}));
        assert_eq!(status["storage_state"], "READY");
        if status["result"]["relay"]["state"] == "ACTIVE_GROUND_ADAPTER"
            && status["result"]["height"]
                .as_str()
                .unwrap()
                .parse::<u128>()
                .unwrap()
                >= 2
        {
            break status;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    let relay = &final_status["result"]["relay"];
    assert_eq!(relay["listen"], endpoint.to_string());
    assert_eq!(relay["identity"], initial["result"]["relay"]["identity"]);
    assert_eq!(
        relay["certificate_sha256"],
        initial["result"]["relay"]["certificate_sha256"]
    );
    assert!(std::fs::read(node_path.join("contact/contact.secret")).unwrap() == key);
    assert!(std::fs::read(node_path.join("contact/tls.secret")).unwrap() == tls);
    drop(TcpStream::connect_timeout(&endpoint, Duration::from_secs(1)).unwrap());
    node.request(json!({"method":"set_mining","enabled":false}));
    assert!(Instant::now() < whole);
}
