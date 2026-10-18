//! Ordinary NO-VALUE CLI startup must retain independently admitted contacts.
//! Generated private contact material stays inside the retained private fixture.
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    path::Path,
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct Node {
    child: Child,
    input: Option<ChildStdin>,
    output: Receiver<Value>,
    stopped: bool,
}
impl Node {
    fn start(root: &Path, genesis: &Path, chain: &str, config: Option<&Path>) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rld-survivor-node"));
        command.arg("serve").arg(root).arg(genesis).arg(chain);
        if let Some(path) = config {
            command.arg(path);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let input = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let (sender, output) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                let value = serde_json::from_str(&line).unwrap();
                if sender.send(value).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            input,
            output,
            stopped: false,
        }
    }
    fn request(&mut self, request: Value, deadline: Instant) -> Value {
        writeln!(self.input.as_mut().unwrap(), "{request}").unwrap();
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .expect("original 30-second configuration scope expired");
            let response = self
                .output
                .recv_timeout(remaining)
                .expect("ordinary native CLI response within original deadline");
            if response["result"]["event"].is_null() {
                return response;
            }
        }
    }
    fn stop(mut self, deadline: Instant) {
        drop(self.input.take());
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "ordinary EOF exit must be zero: {status}");
                self.stopped = true;
                return;
            }
            assert!(Instant::now() < deadline, "ordinary EOF shutdown deadline");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Node {
    fn drop(&mut self) {
        if !self.stopped {
            drop(self.input.take());
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[test]
fn ordinary_restart_without_config_argument_retains_offline_admission_and_listen_intent() {
    let started = Instant::now();
    let deadline = started + Duration::from_secs(30);
    let root = std::env::temp_dir().join(format!(
        "rld-survivor-retained-configuration-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let genesis = root.join("genesis.bin");
    let generated = Command::new(env!("CARGO_BIN_EXE_rld-survivor-node"))
        .arg("new-test-genesis")
        .arg(&genesis)
        .output()
        .unwrap();
    assert!(generated.status.success());
    let generated: Value = serde_json::from_slice(&generated.stdout).unwrap();
    assert_eq!(generated["network_kind"], "NO_VALUE_ONLY");
    assert_eq!(generated["initial_allocation"], "0");
    let chain = generated["chain_id"].as_str().unwrap();
    // This public fixture key is only an admitted contact, never monetary custody.
    let peer = hex::encode(
        SigningKey::from_bytes(&[171; 32])
            .verifying_key()
            .to_bytes(),
    );
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let listen = socket.local_addr().unwrap().to_string();
    drop(socket);
    let config = root.join("explicit-contact.json");
    fs::write(
        &config,
        serde_json::to_vec(&json!({
            "listen":listen,
            "neighbors":[],
            "offline_peers":[peer]
        }))
        .unwrap(),
    )
    .unwrap();
    let node_root = root.join("node");
    let mut first = Node::start(&node_root, &genesis, chain, Some(&config));
    let first_status = first.request(json!({"method":"node_status"}), deadline);
    assert!(first_status["diagnostic"].is_null(), "{first_status}");
    assert_eq!(first_status["result"]["relay"]["configured_listen"], listen);
    let first_export = first.request(json!({"method":"offline_export","peer_key":peer}), deadline);
    assert!(first_export["diagnostic"].is_null(), "{first_export}");
    assert!(first_export["result"]["frames"].is_array());
    first.stop(deadline);

    let mut second = Node::start(&node_root, &genesis, chain, None);
    let second_status = second.request(json!({"method":"node_status"}), deadline);
    let second_export =
        second.request(json!({"method":"offline_export","peer_key":peer}), deadline);
    second.stop(deadline);
    eprintln!(
        "configuration scope: first_exit=0 second_exit=0 elapsed_seconds={:.6} first_listen={} second_listen={} restart_export_error={} retained_private_state={}",
        started.elapsed().as_secs_f64(),
        first_status["result"]["relay"]["configured_listen"],
        second_status["result"]["relay"]["configured_listen"],
        second_export["error_code"],
        root.display()
    );
    assert_eq!(
        second_status["result"]["relay"]["identity"],
        first_status["result"]["relay"]["identity"]
    );
    assert_eq!(
        second_status["result"]["relay"]["certificate_sha256"],
        first_status["result"]["relay"]["certificate_sha256"]
    );
    let mut failures = Vec::new();
    if second_status["result"]["relay"]["configured_listen"]
        != first_status["result"]["relay"]["configured_listen"]
    {
        failures.push("restart discarded independently configured listen intent");
    }
    if !second_export["diagnostic"].is_null() || !second_export["result"]["frames"].is_array() {
        failures.push("restart discarded independently admitted offline peer");
    }
    assert!(Instant::now() < deadline);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
