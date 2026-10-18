//! Fresh ordinary NO-VALUE processes and native encrypted owner custody.
//! A file capsule is not a physical route or independent operator qualification.
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::Path,
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const PASSWORD: &str = "public no-value capsule-process passphrase";

struct Node {
    child: Child,
    input: Option<ChildStdin>,
    output: Receiver<Value>,
    deadline: Instant,
    stopped: bool,
}
impl Node {
    fn start(root: &Path, genesis: &Path, pin: &str, deadline: Instant) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_rld-survivor-node"))
            .arg("serve")
            .arg(root)
            .arg(genesis)
            .arg(pin)
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
                let value: Value = serde_json::from_str(&line.unwrap()).unwrap();
                if sender.send(value).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            input,
            output,
            deadline,
            stopped: false,
        }
    }
    fn request(&mut self, request: Value) -> Value {
        writeln!(self.input.as_mut().unwrap(), "{request}").unwrap();
        loop {
            let left = self
                .deadline
                .checked_duration_since(Instant::now())
                .expect("original180 capsule deadline");
            let reply = self
                .output
                .recv_timeout(left)
                .expect("ordinary native capsule response");
            assert!(reply["diagnostic"].is_null(), "{reply}");
            if reply["result"]["event"].is_null() {
                return reply["result"].clone();
            }
        }
    }
    fn status(&mut self) -> Value {
        self.request(json!({"method":"node_status"}))
    }
    fn stop(mut self) -> u32 {
        let pid = self.child.id();
        drop(self.input.take());
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "ordinary EOF exit: {status}");
                self.stopped = true;
                return pid;
            }
            assert!(Instant::now() < self.deadline, "original180 EOF deadline");
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
fn wait(deadline: Instant, mut ready: impl FnMut() -> bool) {
    loop {
        assert!(Instant::now() < deadline, "original180 behavior deadline");
        if ready() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
fn sign(
    node: &mut Node,
    owner: &str,
    file: &Path,
    input: &str,
    amount: u128,
    destination: &str,
    operation: u8,
) -> (String, String, String) {
    let operation = hex::encode([operation; 32]);
    let review=node.request(json!({"method":"propose_transfer","operation_id":operation,"owner":owner,"inputs":[input],"outputs":[{"owner":destination,"amount":(amount-1).to_string()}],"fee":"1"}));
    assert_eq!(review["review"]["inputs"], json!([input]));
    let signature=node.request(json!({"method":"sign_review","operation_id":operation,"review_digest":review["review_digest"],"key_file":file,"password":PASSWORD}));
    assert_eq!(signature["local_intent"], "SIGNED");
    let raw = signature["transaction_hex"].as_str().unwrap().to_owned();
    let transaction = node.request(json!({"method":"operation_status","operation_id":operation}));
    assert_eq!(transaction["transaction_hex"], raw);
    (
        operation,
        raw,
        transaction["transaction_id"].as_str().unwrap().to_owned(),
    )
}
fn include(
    node: &mut Node,
    owner: &str,
    operation: &str,
    raw: &str,
    submission: u8,
    deadline: Instant,
) {
    let retained=node.request(json!({"method":"submit_transaction","operation_id":hex::encode([submission;32]),"transaction_hex":raw}));
    assert_eq!(retained["submission"], "RETAINED");
    node.request(json!({"method":"set_mining","enabled":true,"miner":owner}));
    wait(deadline, || {
        node.request(json!({"method":"operation_status","operation_id":operation}))["ledger"]
            == "INCLUDED"
    });
    node.request(json!({"method":"set_mining","enabled":false}));
}

#[test]
fn ordinary_capsule_refresh_import_onward_payment_and_cold_replay() {
    let deadline = Instant::now() + Duration::from_secs(180);
    let root = std::env::temp_dir().join(format!(
        "rld-capsule-process-{}-{}",
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
    eprintln!(
        "retained private NO-VALUE capsule fixture: {}",
        root.display()
    );
    let genesis = root.join("fresh.genesis");
    let created = Command::new(env!("CARGO_BIN_EXE_rld-survivor-node"))
        .arg("new-test-genesis")
        .arg(&genesis)
        .output()
        .unwrap();
    assert!(created.status.success());
    let manifest: Value = serde_json::from_slice(&created.stdout).unwrap();
    assert_eq!(manifest["network_kind"], "NO_VALUE_ONLY");
    assert_eq!(manifest["initial_allocation"], "0");
    let pin = manifest["chain_id"].as_str().unwrap();
    let mut source = Node::start(&root.join("source"), &genesis, pin, deadline);
    let mut recipient = Node::start(&root.join("recipient"), &genesis, pin, deadline);
    let source_key = root.join("source.key");
    let recipient_key = root.join("recipient.key");
    let owner = source
        .request(json!({"method":"create_key","key_file":source_key,"password":PASSWORD}))["owner"]
        .as_str()
        .unwrap()
        .to_owned();
    let payee = recipient
        .request(json!({"method":"create_key","key_file":recipient_key,"password":PASSWORD}))
        ["owner"]
        .as_str()
        .unwrap()
        .to_owned();
    source.request(json!({"method":"set_mining","enabled":true,"miner":owner}));
    wait(deadline, || {
        source.status()["height"]
            .as_str()
            .unwrap()
            .parse::<u128>()
            .unwrap()
            >= 100
    });
    source.request(json!({"method":"set_mining","enabled":false}));
    let wallet = source.request(json!({"method":"wallet_state","owner":owner}));
    let coin = wallet["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["eligible_next_height"] == true && c["reserved"] == false)
        .unwrap();
    let input = coin["outpoint"].as_str().unwrap();
    let amount = coin["amount"].as_str().unwrap().parse::<u128>().unwrap();
    let (operation, intent, transaction) =
        sign(&mut source, &owner, &source_key, input, amount, &payee, 181);
    let before = root.join("before.capsule");
    let exported = source
        .request(json!({"method":"capsule_export","transaction_hex":intent,"capsule_file":before}));
    assert_eq!(exported["transaction_hex"], intent);
    let checked = recipient.request(
        json!({"method":"capsule_verify","capsule_file":before,"expected_transaction_hex":intent}),
    );
    assert_eq!(checked["native_history_verified"], true);
    assert_eq!(checked["local_ledger_acceptance"], false);
    assert_eq!(recipient.status()["height"], "0");
    assert_eq!(
        recipient.request(json!({"method":"wallet_state","owner":payee}))["unspent"],
        "0"
    );
    include(&mut source, &owner, &operation, &intent, 182, deadline);
    let after = root.join("after.capsule");
    let refreshed = source.request(
        json!({"method":"capsule_refresh","prior_capsule_file":before,"capsule_file":after}),
    );
    assert_eq!(refreshed["unchanged_intent"], true);
    assert_ne!(refreshed["capsule_id"], exported["capsule_id"]);
    let source_pid = source.stop();
    let imported = recipient.request(
        json!({"method":"capsule_import","capsule_file":after,"expected_transaction_hex":intent}),
    );
    assert_eq!(imported["complete_import"], true);
    assert_eq!(imported["transaction_hex"], intent);
    assert_eq!(imported["transaction"]["ledger"], "INCLUDED");
    assert_eq!(imported["selected_tip"], imported["carried_tip"]);
    let received = recipient.request(json!({"method":"wallet_state","owner":payee}));
    assert_eq!(received["unspent"], (amount - 1).to_string());
    let incoming = format!("{transaction}0000");
    let (onward_operation, onward, onward_id) = sign(
        &mut recipient,
        &payee,
        &recipient_key,
        &incoming,
        amount - 1,
        &owner,
        185,
    );
    include(
        &mut recipient,
        &payee,
        &onward_operation,
        &onward,
        186,
        deadline,
    );
    let terminal = recipient.status();
    let source_wallet = recipient.request(json!({"method":"wallet_state","owner":owner}));
    let recipient_wallet = recipient.request(json!({"method":"wallet_state","owner":payee}));
    let sum = source_wallet["unspent"]
        .as_str()
        .unwrap()
        .parse::<u128>()
        .unwrap()
        + recipient_wallet["unspent"]
            .as_str()
            .unwrap()
            .parse::<u128>()
            .unwrap();
    assert_eq!(sum.to_string(), terminal["issued"]);
    let recipient_pid = recipient.stop();
    assert_ne!(source_pid, recipient_pid);
    let mut cold = Node::start(&root.join("recipient"), &genesis, pin, deadline);
    let reopened = cold.status();
    for field in ["height", "issued", "state_root"] {
        assert_eq!(reopened[field], terminal[field]);
    }
    for (id, raw) in [(&transaction, &intent), (&onward_id, &onward)] {
        let retained = cold.request(json!({"method":"get_object","kind":"2","id":id}));
        assert_eq!(retained["bytes"], *raw);
    }
    assert_eq!(
        cold.request(json!({"method":"wallet_state","owner":owner}))["unspent"],
        source_wallet["unspent"]
    );
    assert_eq!(
        cold.request(json!({"method":"wallet_state","owner":payee}))["unspent"],
        recipient_wallet["unspent"]
    );
    cold.stop();
    assert!(
        Instant::now() < deadline,
        "original180 complete capsule scope"
    );
}
