//! Exercise the exact allowlisted archive through the system's independent tar
//! reader, then create a wallet and mine without neighbors using only its
//! extracted no-value executable. This is same-host engineering evidence, not
//! independent installation, hard-target collapse or consumer qualification.
use serde_json::{json, Value};
use std::{
    fs::OpenOptions,
    io::{BufRead, BufReader, Write},
    path::Path,
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    time::{Duration, Instant},
};

struct PackagedNode {
    child: Child,
    input: Option<ChildStdin>,
    output: Receiver<Value>,
}
impl PackagedNode {
    fn start(extracted: &Path, chain: &str) -> Self {
        let mut child = Command::new(extracted.join("rld-survivor-node"))
            .current_dir(extracted)
            .args(["serve", "private-node", "fresh.genesis", chain])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let input = child.stdin.take();
        let output = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
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
            output: rx,
        }
    }
    fn request(&mut self, request: Value, deadline: Instant) -> Value {
        writeln!(self.input.as_mut().unwrap(), "{request}").unwrap();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "packaged lifecycle deadline");
            let response = self
                .output
                .recv_timeout(remaining.min(Duration::from_secs(30)))
                .expect("bounded packaged native response");
            assert!(response["diagnostic"].is_null(), "{response}");
            if response["result"]["event"].is_null() {
                return response;
            }
        }
    }
    fn stop(mut self, deadline: Instant) {
        drop(self.input.take());
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "packaged native shutdown");
                break;
            }
            assert!(Instant::now() < deadline, "packaged shutdown deadline");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for PackagedNode {
    fn drop(&mut self) {
        drop(self.input.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn overbound_binary_refuses_before_any_archive_is_created() {
    let root = std::env::temp_dir().join(format!(
        "rld-survivor-package-overbound-{}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    let binary = root.join("public-overbound-elf-fixture");
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&binary)
        .unwrap();
    file.write_all(b"\x7fELF").unwrap();
    file.set_len(64 * 1024 * 1024 + 1).unwrap();
    drop(file);
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let archive = root.join("refused.tar");
    let result = Command::new(env!("CARGO_BIN_EXE_rld-survivor-package"))
        .arg(repo)
        .arg(&binary)
        .arg(&archive)
        .output()
        .unwrap();
    assert!(!result.status.success());
    let error = String::from_utf8(result.stderr).unwrap();
    assert!(
        error.contains("allowlisted regular-file size bound"),
        "{error}"
    );
    assert!(error.contains("67108865 bytes"), "{error}");
    assert!(!archive.exists());
    assert!(!archive.with_extension("tar.sha256").exists());
}
#[test]
fn extracted_candidate_creates_wallet_mines_without_peers_and_restarts() {
    let deadline = Instant::now() + Duration::from_secs(120);
    let root = std::env::temp_dir().join(format!("rld-survivor-package-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let tar = root.join("candidate.tar");
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_rld-survivor-package"))
        .arg(repo)
        .arg(env!("CARGO_BIN_EXE_rld-survivor-node"))
        .arg(&tar)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let listing = Command::new("tar").arg("-tf").arg(&tar).output().unwrap();
    assert!(listing.status.success());
    let listing = String::from_utf8(listing.stdout).unwrap();
    assert_eq!(listing.lines().count(), 12);
    assert!(!listing.contains("secret"));
    assert!(!listing.contains("sqlite"));
    let out = root.join("extracted");
    std::fs::create_dir(&out).unwrap();
    assert!(Command::new("tar")
        .arg("-xf")
        .arg(&tar)
        .arg("-C")
        .arg(&out)
        .status()
        .unwrap()
        .success());
    assert_eq!(
        std::fs::read(out.join("rld-survivor-node")).unwrap(),
        std::fs::read(env!("CARGO_BIN_EXE_rld-survivor-node")).unwrap()
    );
    for path in [
        "docs/protocol/PAYMENT_CAPSULE_V1.md",
        "docs/protocol/payment-capsule-v1-vectors.json",
    ] {
        assert!(listing.lines().any(|entry| entry == path));
        assert_eq!(
            std::fs::read(out.join(path)).unwrap(),
            std::fs::read(repo.join(path)).unwrap()
        );
    }
    let result = Command::new(out.join("rld-survivor-node"))
        .current_dir(&out)
        .args(["new-test-genesis", "fresh.genesis"])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(v["initial_allocation"], "0");
    assert_eq!(v["network_kind"], "NO_VALUE_ONLY");
    let chain = v["chain_id"].as_str().unwrap();
    let mut node = PackagedNode::start(&out, chain);
    let status = node.request(json!({"method":"node_status"}), deadline);
    assert_eq!(status["chain_id"], chain);
    assert_eq!(status["result"]["height"], "0");
    assert_eq!(status["result"]["issued"], "0");
    assert_eq!(status["result"]["mainnet"], false);
    assert_eq!(status["result"]["mining_enabled"], false);
    assert_eq!(status["result"]["relay"]["neighbors"], "0");

    // The package creates its own encrypted key through ordinary secure local
    // stdin. No public fixture seed, precreated wallet or peer supplies authority.
    let key = node.request(
        json!({"method":"create_key","key_file":"private-wallet.key","password":"public no-value package passphrase"}),
        deadline,
    );
    assert_eq!(key["result"].as_object().unwrap().len(), 2);
    assert_eq!(key["result"]["backup_scope"], "KEY_ONLY");
    let owner = key["result"]["owner"].as_str().unwrap();
    assert_eq!(hex::decode(owner).unwrap().len(), 32);
    assert!(std::fs::read(out.join("private-wallet.key"))
        .unwrap()
        .starts_with(b"RLDSKEY1"));
    let enabled = node.request(
        json!({"method":"set_mining","enabled":true,"miner":owner}),
        deadline,
    );
    assert_eq!(enabled["result"]["mining"], true);
    loop {
        let status = node.request(json!({"method":"node_status"}), deadline);
        assert_eq!(status["chain_id"], chain);
        assert_eq!(status["result"]["relay"]["neighbors"], "0");
        if status["result"]["height"]
            .as_str()
            .unwrap()
            .parse::<u128>()
            .unwrap()
            >= 3
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    node.request(json!({"method":"set_mining","enabled":false}), deadline);
    let mined = node.request(json!({"method":"node_status"}), deadline);
    let height = mined["result"]["height"]
        .as_str()
        .unwrap()
        .parse::<u128>()
        .unwrap();
    assert!((3..200_000).contains(&height));
    // C08's first era divides half the cap equally among 200,000 blocks.
    assert_eq!(
        mined["result"]["issued"],
        (height * (10u128.pow(35) / 2 / 200_000)).to_string()
    );
    assert_eq!(
        mined["result"]["mining_work_observation"]["count_exact"],
        true
    );
    assert!(
        mined["result"]["mining_work_observation"]["calls"]
            .as_str()
            .unwrap()
            .parse::<u128>()
            .unwrap()
            > 0
    );
    let wallet = node.request(json!({"method":"wallet_state","owner":owner}), deadline);
    assert_eq!(wallet["result"]["unspent"], mined["result"]["issued"]);
    assert_eq!(wallet["selected_tip"], mined["selected_tip"]);
    node.stop(deadline);

    // Cold startup is the extracted executable's full native replay, not a
    // separate test-library ledger or an alternate unbundled executable.
    let mut reopened = PackagedNode::start(&out, chain);
    let cold = reopened.request(json!({"method":"node_status"}), deadline);
    assert_eq!(cold["chain_id"], chain);
    assert_eq!(cold["selected_tip"], mined["selected_tip"]);
    assert_eq!(cold["revision"], mined["revision"]);
    for field in ["height", "issued", "state_root"] {
        assert_eq!(cold["result"][field], mined["result"][field]);
    }
    assert_eq!(cold["result"]["mining_enabled"], false);
    assert_eq!(cold["result"]["relay"]["neighbors"], "0");
    let cold_wallet = reopened.request(json!({"method":"wallet_state","owner":owner}), deadline);
    assert_eq!(cold_wallet["result"], wallet["result"]);
    reopened.stop(deadline);
    assert!(Instant::now() < deadline);
}
