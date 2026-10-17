//! Fresh ordinary NO-VALUE processes and deliberately public fixture keys.
//! Capacity refusal preserves the selected prefix; explicit provisioning resumes
//! the same history and verifies owner-authorized payment and recovery.
use ed25519_dalek::SigningKey;
use rld_survivor_node::{
    kernel::{genesis_id, issuance, Hash, Ledger},
    keyfile,
    operating_policy::OperatingPolicy,
    store::Limits,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const PASSWORD: &str = "PUBLIC NO-VALUE CAPACITY RECOVERY FIXTURE";
struct Node {
    child: Child,
    input: Option<ChildStdin>,
    output: Receiver<Value>,
}
impl Drop for Node {
    fn drop(&mut self) {
        self.input.take();
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}
impl Node {
    fn start(root: &Path, genesis: &Path, pin: Hash, policy: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_rld-survivor-node"))
            .arg("serve")
            .arg(root)
            .arg(genesis)
            .arg(hex::encode(pin))
            .arg("--operating-policy")
            .arg(policy)
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
                let v = serde_json::from_str(&line).unwrap();
                if tx.send(v).is_err() {
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
    fn raw(&mut self, value: Value) -> Value {
        writeln!(self.input.as_mut().unwrap(), "{value}").unwrap();
        loop {
            let value = self
                .output
                .recv_timeout(Duration::from_secs(30))
                .expect("bounded native response");
            if value["result"]["event"].is_null() {
                return value;
            }
        }
    }
    fn request(&mut self, value: Value) -> Value {
        let out = self.raw(value);
        assert!(out["diagnostic"].is_null(), "{out}");
        out
    }
    fn wait_included(&mut self, operation: Hash, check: &impl Fn()) {
        loop {
            check();
            let status = self.request(
                json!({"method":"operation_status","operation_id":hex::encode(operation)}),
            );
            if status["result"]["ledger"] == "INCLUDED" {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}
fn operation(n: u128) -> Hash {
    let mut out = [0; 32];
    out[16..].copy_from_slice(&n.to_be_bytes());
    out
}
fn mined(ledger: &Ledger, miner: Hash, start: u64, now: u64) -> Vec<u8> {
    ledger
        .mining_job(
            miner,
            vec![],
            start + (ledger.tip().height() as u64 + 1) * 600,
            now,
        )
        .unwrap()
        .attempt(1_000_000)
        .expect("finite real nonce budget")
}
fn reward(raw: &[u8]) -> Vec<u8> {
    let mut id = Sha256::digest(
        [
            b"RLD-SURVIVOR-1/REWARD\0".as_slice(),
            &raw[4..84],
            &raw[156..220],
        ]
        .concat(),
    )
    .to_vec();
    id.extend(0u16.to_be_bytes());
    id
}
fn transfer_output(raw: &[u8]) -> Vec<u8> {
    let mut id =
        Sha256::digest([b"RLD-SURVIVOR-1/TXID\0".as_slice(), &raw[..raw.len() - 64]].concat())
            .to_vec();
    id.extend(0u16.to_be_bytes());
    id
}
fn pay(
    node: &mut Node,
    op: Hash,
    owner: Hash,
    to: Hash,
    input: &[u8],
    amount: u128,
    key: &Path,
) -> Vec<u8> {
    let review = node.request(json!({"method":"propose_transfer","operation_id":hex::encode(op),"owner":hex::encode(owner),"inputs":[hex::encode(input)],"outputs":[{"owner":hex::encode(to),"amount":amount.to_string()}],"fee":"1"}));
    let signed = node.request(json!({"method":"sign_review","operation_id":hex::encode(op),"review_digest":review["result"]["review_digest"],"key_file":key,"password":PASSWORD}));
    let raw = hex::decode(signed["result"]["transaction_hex"].as_str().unwrap()).unwrap();
    let submit: Hash =
        Sha256::digest([b"PUBLIC NO-VALUE CAPACITY SUBMIT".as_slice(), &op].concat()).into();
    node.request(json!({"method":"submit_transaction","operation_id":hex::encode(submit),"transaction_hex":hex::encode(&raw)}));
    raw
}
#[test]
fn ordinary_capacity_pause_explicit_expansion_payments_and_streamed_restore() {
    let started = Instant::now();
    let check = || {
        assert!(
            started.elapsed() <= Duration::from_secs(180),
            "whole native capacity-recovery budget"
        )
    };
    let root = std::env::temp_dir().join(format!("rld-survivor-provision-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let start = now - 1_000_000;
    let mut genesis = b"RLDSGEN1".to_vec();
    genesis.extend(1u16.to_be_bytes());
    genesis.extend(1u16.to_be_bytes());
    genesis.push(0);
    let mut discriminator = [0; 32];
    getrandom::getrandom(&mut discriminator).unwrap();
    genesis.extend(discriminator);
    genesis.extend(start.to_be_bytes());
    genesis.push(0);
    genesis.extend([255; 31]);
    let pin = genesis_id(&genesis);
    let file = root.join("genesis.bin");
    std::fs::write(&file, &genesis).unwrap();
    let a = SigningKey::from_bytes(&[61; 32]);
    let b = SigningKey::from_bytes(&[62; 32]);
    let c = SigningKey::from_bytes(&[63; 32]);
    let pa = a.verifying_key().to_bytes();
    let pb = b.verifying_key().to_bytes();
    let pc = c.verifying_key().to_bytes();
    let keys: Vec<PathBuf> = [a, b]
        .iter()
        .enumerate()
        .map(|(i, key)| {
            let p = root.join(format!("public-fixture-{i}.key"));
            std::fs::write(&p, keyfile::encrypt(key, pin, PASSWORD.as_bytes()).unwrap()).unwrap();
            p
        })
        .collect();
    let mut small = OperatingPolicy::default().status(pin);
    small["ledger_database_bytes"] = json!("262144");
    let mut large = small.clone();
    large["ledger_database_bytes"] = json!("4194304");
    let small_file = root.join("small.json");
    let large_file = root.join("large.json");
    std::fs::write(&small_file, small.to_string()).unwrap();
    std::fs::write(&large_file, large.to_string()).unwrap();
    let path = root.join("node");
    let mut node = Node::start(&path, &file, pin, &small_file);
    let status = node.request(json!({"method":"node_status"}));
    assert_eq!(status["result"]["operating_policy"], small);
    let mut ledger = Ledger::from_genesis(&genesis, pin, Limits::default().coins).unwrap();
    let mut first_reward = None;
    let mut refused = None;
    for h in 1u128..=512 {
        check();
        let raw = mined(&ledger, pa, start, now);
        let out = node.raw(json!({"method":"accept_block","operation_id":hex::encode(operation(h)),"block_hex":hex::encode(&raw)}));
        if !out["diagnostic"].is_null() {
            assert!(
                out["diagnostic"]
                    .as_str()
                    .unwrap()
                    .starts_with("RESOURCE_WAIT"),
                "{out}"
            );
            assert_eq!(out["selected_tip"], hex::encode(ledger.tip().id()));
            refused = Some((h, raw));
            break;
        }
        ledger.execute(&raw).unwrap();
        if h == 1 {
            first_reward = Some(reward(&raw));
        }
    }
    let (height, raw) = refused.expect("the original small declared budget must actually refuse");
    let old_tip = ledger.tip().id();
    let old_height = ledger.tip().height();
    drop(node);
    check();
    let mut node = Node::start(&path, &file, pin, &large_file);
    let status = node.request(json!({"method":"node_status"}));
    assert_eq!(status["selected_tip"], hex::encode(old_tip));
    assert_eq!(status["result"]["height"], old_height.to_string());
    assert_eq!(status["result"]["operating_policy"], large);
    node.request(json!({"method":"accept_block","operation_id":hex::encode(operation(height)),"block_hex":hex::encode(&raw)}));
    ledger.execute(&raw).unwrap();
    while ledger.tip().height() < 101 {
        check();
        let h = ledger.tip().height() + 1;
        let raw = mined(&ledger, pa, start, now);
        node.request(json!({"method":"accept_block","operation_id":hex::encode(operation(h)),"block_hex":hex::encode(&raw)}));
        ledger.execute(&raw).unwrap();
    }
    let amount = issuance(1).0 - 1;
    let first = pay(
        &mut node,
        operation(10001),
        pa,
        pb,
        first_reward.as_ref().unwrap(),
        amount,
        &keys[0],
    );
    node.request(json!({"method":"set_mining","enabled":true,"miner":hex::encode(pa)}));
    node.wait_included(operation(10001), &check);
    let second = pay(
        &mut node,
        operation(10002),
        pb,
        pc,
        &transfer_output(&first),
        amount - 1,
        &keys[1],
    );
    node.wait_included(operation(10002), &check);
    node.request(json!({"method":"set_mining","enabled":false}));
    let balance = node.request(json!({"method":"wallet_state","owner":hex::encode(pc)}));
    assert!(
        balance["result"]["available"]
            .as_str()
            .unwrap()
            .parse::<u128>()
            .unwrap()
            > 0
    );
    let image = root.join("backup");
    let backup = node.request(json!({"method":"create_backup","destination":image,"password":PASSWORD,"wallet_key_files":keys}));
    let latest = backup["result"]["state_head"].as_str().unwrap().to_string();
    let final_status = node.request(json!({"method":"node_status"}));
    drop(node);
    check();
    let target = root.join("restored");
    let mut child = Command::new(env!("CARGO_BIN_EXE_rld-survivor-node"))
        .arg("restore")
        .arg(&target)
        .arg(&file)
        .arg(hex::encode(pin))
        .arg(&image)
        .arg("--operating-policy")
        .arg(&large_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(
        child.stdin.take().unwrap(),
        "{}",
        json!({"password":PASSWORD,"latest_state_head":latest})
    )
    .unwrap();
    let restored = child.wait_with_output().unwrap();
    assert!(restored.status.success());
    check();
    let mut node = Node::start(&target, &file, pin, &large_file);
    let status = node.request(json!({"method":"node_status"}));
    assert_eq!(status["selected_tip"], final_status["selected_tip"]);
    assert_eq!(status["revision"], final_status["revision"]);
    assert_eq!(status["result"]["freshness"], "MATCHES_PROVIDED_HEAD");
    for (op, exact) in [(operation(10001), first), (operation(10002), second)] {
        let status =
            node.request(json!({"method":"operation_status","operation_id":hex::encode(op)}));
        assert_eq!(status["result"]["ledger"], "INCLUDED");
        assert_eq!(status["result"]["transaction_hex"], hex::encode(exact));
    }
    let recovered = node.request(json!({"method":"wallet_state","owner":hex::encode(pc)}));
    assert_eq!(recovered["result"], balance["result"]);
    assert!(!target.join("RESTORING").exists());
}

#[test]
fn invalid_explicit_policy_refuses_before_creating_native_state_or_keys() {
    let v: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/survivor-v1/vectors.json"
    ))
    .unwrap();
    let g = hex::decode(v["genesis"]["manifest_hex"].as_str().unwrap()).unwrap();
    let pin = genesis_id(&g);
    let root = std::env::temp_dir().join(format!(
        "rld-survivor-invalid-policy-{}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    let file = root.join("genesis.bin");
    std::fs::write(&file, &g).unwrap();
    let valid = OperatingPolicy::default().status(pin);
    let original = valid.to_string();
    let cases = [
        "{\"unknown\":true}".to_string(),
        format!(
            "{},\"ledger_coins\":\"2\"}}",
            &original[..original.len() - 1]
        ),
        {
            let mut v = valid.clone();
            v["chain_id"] = json!(hex::encode([9; 32]));
            v.to_string()
        },
        {
            let mut v = valid;
            v["ledger_database_bytes"] = json!("0");
            v.to_string()
        },
    ];
    for (index, policy) in cases.into_iter().enumerate() {
        let target = root.join(format!("node-{index}"));
        let path = root.join(format!("policy-{index}.json"));
        std::fs::write(&path, policy).unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_rld-survivor-node"))
            .arg("serve")
            .arg(&target)
            .arg(&file)
            .arg(hex::encode(pin))
            .arg("--operating-policy")
            .arg(path)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(!target.exists());
    }
}
