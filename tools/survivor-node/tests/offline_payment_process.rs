//! Fresh ordinary NO-VALUE processes, real mining and only A -> relay ->
//! recipient file carriage. No controller-created ledger or reverse contact.
//! Same-host evidence is not independent operations or a physical stellar route.
use rld_survivor_node::{
    kernel::{genesis_id, Hash},
    store::{Limits, Store},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const PASSWORD: &str = "public no-value offline-process passphrase";

fn private_file(path: &Path) -> File {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).unwrap()
}

fn retain(path: &Path, bytes: &[u8]) {
    let mut file = private_file(path);
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

struct Node {
    child: Child,
    input: Option<ChildStdin>,
    output: Receiver<Value>,
    reader: Option<JoinHandle<()>>,
    deadline: Instant,
    label: String,
    terminal: PathBuf,
    stopped: bool,
}

impl Node {
    fn start(
        fixture: &Path,
        name: &str,
        run: &str,
        genesis: &Path,
        chain: &str,
        config: Option<&Path>,
        deadline: Instant,
    ) -> Self {
        assert!(
            Instant::now() < deadline,
            "ordinary process startup deadline"
        );
        let label = format!("{name}-{run}");
        let mut command = Command::new(env!("CARGO_BIN_EXE_rld-survivor-node"));
        command
            .arg("serve")
            .arg(fixture.join(name))
            .arg(genesis)
            .arg(chain);
        if let Some(config) = config {
            command.arg(config);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(private_file(
                &fixture.join(format!("{label}.stderr.log")),
            )))
            .spawn()
            .unwrap();
        let input = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let mut log = private_file(&fixture.join(format!("{label}.stdout.jsonl")));
        let (sender, output) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let line = line.unwrap();
                // Only native responses are logged. Password-bearing stdin and
                // generated key material are never written to these logs.
                writeln!(log, "{line}").unwrap();
                log.flush().unwrap();
                let value = serde_json::from_str(&line).unwrap();
                if sender.send(value).is_err() {
                    break;
                }
            }
            log.sync_all().unwrap();
        });
        Self {
            child,
            input,
            output,
            reader: Some(reader),
            deadline,
            label: label.clone(),
            terminal: fixture.join(format!("{label}.terminal.json")),
            stopped: false,
        }
    }

    fn request(&mut self, request: Value) -> Value {
        assert!(Instant::now() < self.deadline, "whole180 request deadline");
        writeln!(self.input.as_mut().unwrap(), "{request}").unwrap();
        loop {
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "whole180 response deadline");
            let response = self
                .output
                .recv_timeout(remaining.min(Duration::from_secs(30)))
                .unwrap_or_else(|error| panic!("{} response: {error}", self.label));
            assert!(
                response["diagnostic"].is_null(),
                "{}: {response}",
                self.label
            );
            if response["result"]["event"].is_null() {
                return response;
            }
        }
    }

    fn status(&mut self) -> Value {
        let status = self.request(json!({"method":"node_status"}));
        assert_eq!(status["result"]["mainnet"], false);
        assert_eq!(status["storage_state"], "READY");
        assert_eq!(status["result"]["relay"]["neighbors"], "0");
        status
    }

    fn wallet(&mut self, owner: &str) -> Value {
        self.request(json!({"method":"wallet_state","owner":owner}))
    }

    fn transaction(&mut self, id: &str) -> String {
        self.request(json!({"method":"get_object","kind":"2","id":id}))["result"]["bytes"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn stop(mut self) -> u32 {
        let pid = self.child.id();
        drop(self.input.take());
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                self.stopped = true;
                retain(
                    &self.terminal,
                    serde_json::to_string(&json!({
                        "pid":pid,"stdin_eof":true,"success":status.success(),
                        "exit_code":status.code(),"forced_stop":false
                    }))
                    .unwrap()
                    .as_bytes(),
                );
                assert!(
                    status.success(),
                    "{} ordinary terminal: {status}",
                    self.label
                );
                self.reader.take().unwrap().join().unwrap();
                return pid;
            }
            assert!(
                Instant::now() < self.deadline,
                "whole180 EOF shutdown deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if !self.stopped {
            drop(self.input.take());
            let _ = self.child.kill();
            let status = self.child.wait();
            if let Ok(mut record) = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&self.terminal)
            {
                let _ = writeln!(
                    record,
                    "{}",
                    json!({"pid":self.child.id(),"forced_stop":true,"status":format!("{status:?}")})
                );
                let _ = record.sync_all();
            }
        }
    }
}

struct Wallet {
    owner: String,
    file: PathBuf,
}

fn create_wallet(node: &mut Node, path: PathBuf) -> Wallet {
    let result = node.request(json!({"method":"create_key","key_file":path,"password":PASSWORD}));
    let fields = result["result"].as_object().unwrap();
    assert_eq!(fields.len(), 2);
    assert_eq!(fields["backup_scope"], "KEY_ONLY");
    let owner = fields["owner"].as_str().unwrap().to_owned();
    assert_eq!(hex::decode(&owner).unwrap().len(), 32);
    assert!(fs::read(&path).unwrap().starts_with(b"RLDSKEY1"));
    Wallet { owner, file: path }
}

struct Payment {
    operation: String,
    signed: String,
    id: String,
    input: String,
    amount: u128,
}

impl Payment {
    fn outpoint(&self) -> String {
        format!("{}0000", self.id)
    }
}

fn pay(
    node: &mut Node,
    wallet: &Wallet,
    input: &str,
    amount: u128,
    recipient: &str,
    operation: u8,
) -> Payment {
    assert!(amount > 2);
    let operation_id = hex::encode([operation; 32]);
    let review = node.request(json!({
        "method":"propose_transfer","operation_id":operation_id,
        "owner":wallet.owner,"inputs":[input],
        "outputs":[{"owner":recipient,"amount":(amount-1).to_string()}],"fee":"1"
    }));
    assert_eq!(review["result"]["review"]["inputs"], json!([input]));
    assert_eq!(review["result"]["review"]["owner"], wallet.owner);
    let signed = node.request(json!({
        "method":"sign_review","operation_id":operation_id,
        "review_digest":review["result"]["review_digest"],
        "key_file":wallet.file,"password":PASSWORD
    }));
    assert_eq!(signed["result"]["local_intent"], "SIGNED");
    let signed = signed["result"]["transaction_hex"]
        .as_str()
        .unwrap()
        .to_owned();
    let raw = hex::decode(&signed).unwrap();
    let unsigned = hex::decode(review["result"]["unsigned_hex"].as_str().unwrap()).unwrap();
    assert_eq!(raw.len(), unsigned.len() + 64);
    assert_eq!(raw[..unsigned.len()], unsigned);
    let mut digest = Sha256::new();
    digest.update(b"RLD-SURVIVOR-1/TXID\0");
    digest.update(&unsigned);
    let id = hex::encode(digest.finalize());
    let retained = node.request(json!({
        "method":"submit_transaction","operation_id":hex::encode([operation+1;32]),
        "transaction_hex":signed
    }));
    assert_eq!(retained["result"]["submission"], "RETAINED");
    assert_eq!(retained["result"]["transaction_id"], id);
    assert!(retained["result"]["ledger"].is_null());
    Payment {
        operation: operation_id,
        signed,
        id,
        input: input.to_owned(),
        amount: amount - 1,
    }
}

fn wait(deadline: Instant, mut condition: impl FnMut() -> bool) {
    while !condition() {
        assert!(Instant::now() < deadline, "whole180 behavior deadline");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        Instant::now() < deadline,
        "whole180 completed behavior deadline"
    );
}

fn include(node: &mut Node, wallet: &Wallet, payment: &Payment, deadline: Instant) -> Value {
    node.request(json!({"method":"set_mining","enabled":true,"miner":wallet.owner}));
    wait(deadline, || {
        let state =
            node.request(json!({"method":"operation_status","operation_id":payment.operation}));
        assert_eq!(state["result"]["transaction_hex"], payment.signed);
        assert_eq!(state["result"]["transaction_id"], payment.id);
        state["result"]["ledger"] == "INCLUDED"
    });
    node.request(json!({"method":"set_mining","enabled":false}));
    let status = node.status();
    assert_eq!(node.transaction(&payment.id), payment.signed);
    status
}

fn forward(
    source: &mut Node,
    receiver: &mut Node,
    sender: &str,
    destination: &str,
    directory: &Path,
    sequence: &mut u64,
) -> (usize, usize) {
    let exported = source.request(json!({"method":"offline_export","peer_key":destination}));
    assert_eq!(exported["result"]["receipt_required"], true);
    let mut carried = 0;
    let mut unreturned_receipts = 0;
    for frame in exported["result"]["frames"].as_array().unwrap() {
        let file = directory.join(format!("{:06}.frame", *sequence));
        *sequence += 1;
        retain(&file, &hex::decode(frame.as_str().unwrap()).unwrap());
        let imported = receiver
            .request(json!({"method":"offline_import","peer_key":sender,"frame_file":file}));
        assert_eq!(imported["result"]["ledger_acceptance"], false);
        carried += 1;
        unreturned_receipts += usize::from(!imported["result"]["receipt"].is_null());
        // The returned receipt is deliberately retained only in the receiver's
        // response log. It is never imported or carried in the reverse direction.
    }
    (carried, unreturned_receipts)
}

fn unspent(wallet: &Value) -> u128 {
    wallet["result"]["unspent"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

fn absent(wallet: &Value, input: &str) {
    assert!(!wallet["result"]["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .any(|coin| coin["outpoint"] == input));
}

#[test]
fn one_way_relay_payment_survives_both_source_and_relay_exit_and_spends_onward() {
    let started = Instant::now();
    let deadline = started + Duration::from_secs(180);
    let fixture = std::env::temp_dir().join(format!(
        "rld-survivor-offline-pay-process-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&fixture).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&fixture, fs::Permissions::from_mode(0o700)).unwrap();
    }
    eprintln!("retained private NO-VALUE fixture: {}", fixture.display());
    let genesis_file = fixture.join("fresh.genesis");
    let genesis = Command::new(env!("CARGO_BIN_EXE_rld-survivor-node"))
        .arg("new-test-genesis")
        .arg(&genesis_file)
        .output()
        .unwrap();
    retain(&fixture.join("genesis.stdout.json"), &genesis.stdout);
    retain(&fixture.join("genesis.stderr.log"), &genesis.stderr);
    assert!(genesis.status.success());
    let manifest: Value = serde_json::from_slice(&genesis.stdout).unwrap();
    assert_eq!(manifest["network_kind"], "NO_VALUE_ONLY");
    assert_eq!(manifest["initial_allocation"], "0");
    let chain = manifest["chain_id"].as_str().unwrap();
    let genesis_bytes = fs::read(&genesis_file).unwrap();
    let pin: Hash = hex::decode(chain).unwrap().try_into().unwrap();
    assert_eq!(genesis_id(&genesis_bytes), pin);

    let start = |name, run, config| {
        Node::start(&fixture, name, run, &genesis_file, chain, config, deadline)
    };
    let mut a = start("source", "initial", None);
    let mut relay = start("relay", "initial", None);
    let mut recipient = start("recipient", "initial", None);
    let a_wallet = create_wallet(&mut a, fixture.join("source-wallet.key"));
    let recipient_wallet = create_wallet(&mut recipient, fixture.join("recipient-wallet.key"));
    let initial_a = a.status();
    let initial_relay = relay.status();
    let initial_recipient = recipient.status();
    for status in [&initial_a, &initial_relay, &initial_recipient] {
        assert_eq!(status["chain_id"], chain);
        assert_eq!(status["result"]["height"], "0");
        assert_eq!(status["result"]["issued"], "0");
        assert_eq!(status["result"]["mining_enabled"], false);
    }
    let a_contact = initial_a["result"]["relay"]["identity"].as_str().unwrap();
    let relay_contact = initial_relay["result"]["relay"]["identity"]
        .as_str()
        .unwrap();
    let recipient_contact = initial_recipient["result"]["relay"]["identity"]
        .as_str()
        .unwrap();

    // This source has no admitted peers at all while producing the first mature
    // reward. All block templates, clocks and nonce attempts are ordinary native.
    a.request(json!({"method":"set_mining","enabled":true,"miner":a_wallet.owner}));
    wait(deadline, || {
        a.status()["result"]["height"]
            .as_str()
            .unwrap()
            .parse::<u128>()
            .unwrap()
            >= 100
    });
    a.request(json!({"method":"set_mining","enabled":false}));
    let source_funded = a.status();
    let funded = a.wallet(&a_wallet.owner);
    let reward = funded["result"]["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|coin| coin["eligible_next_height"] == true && coin["reserved"] == false)
        .expect("ordinary 100-block reward maturity");
    let reward_input = reward["outpoint"].as_str().unwrap().to_owned();
    let reward_amount: u128 = reward["amount"].as_str().unwrap().parse().unwrap();
    assert_eq!(
        unspent(&funded).to_string(),
        source_funded["result"]["issued"]
    );
    a.stop();
    relay.stop();
    recipient.stop();

    let config = |name: &str, peers: &[&str]| {
        let file = fixture.join(format!("{name}.contact.json"));
        retain(
            &file,
            serde_json::to_vec(&json!({
                "listen":"127.0.0.1:0","neighbors":[],"offline_peers":peers
            }))
            .unwrap()
            .as_slice(),
        );
        file
    };
    let a_config = config("source", &[relay_contact]);
    let relay_config = config("relay", &[a_contact, recipient_contact]);
    let recipient_config = config("recipient", &[relay_contact]);
    let mut a = start("source", "offline", Some(a_config.as_path()));
    let mut relay = start("relay", "offline", Some(relay_config.as_path()));
    let mut recipient = start("recipient", "offline", Some(recipient_config.as_path()));
    for (node, old) in [
        (&mut a, &initial_a),
        (&mut relay, &initial_relay),
        (&mut recipient, &initial_recipient),
    ] {
        let status = node.status();
        assert_eq!(status["chain_id"], chain);
        for field in ["identity", "certificate_sha256"] {
            assert_eq!(
                status["result"]["relay"][field],
                old["result"]["relay"][field]
            );
        }
    }
    let payment = pay(
        &mut a,
        &a_wallet,
        &reward_input,
        reward_amount,
        &recipient_wallet.owner,
        121,
    );
    let paid = include(&mut a, &a_wallet, &payment, deadline);
    absent(&a.wallet(&a_wallet.owner), &payment.input);
    let carried_files = fixture.join("forward-frames");
    fs::create_dir(&carried_files).unwrap();
    let mut file_sequence = 0;
    let mut a_to_relay = 0;
    let mut relay_to_recipient = 0;
    let mut unreturned_receipts = 0;
    wait(deadline, || {
        let (frames, receipts) = forward(
            &mut a,
            &mut relay,
            a_contact,
            relay_contact,
            &carried_files,
            &mut file_sequence,
        );
        a_to_relay += frames;
        unreturned_receipts += receipts;
        relay.status()["selected_tip"] == paid["selected_tip"]
    });
    // The destination has received no frame when the sender exits. Native
    // custody at the relay must be enough to finish the forward path later.
    assert_eq!(recipient.status()["result"]["height"], "0");
    assert_eq!(unspent(&recipient.wallet(&recipient_wallet.owner)), 0);
    let source_pid = a.stop();
    let original_relay_pid = relay.stop();
    let mut relay = start("relay", "retained", None);
    let relay_reopened = relay.status();
    assert_eq!(relay_reopened["selected_tip"], paid["selected_tip"]);
    for field in ["identity", "certificate_sha256"] {
        assert_eq!(
            relay_reopened["result"]["relay"][field],
            initial_relay["result"]["relay"][field]
        );
    }
    wait(deadline, || {
        let (frames, receipts) = forward(
            &mut relay,
            &mut recipient,
            relay_contact,
            recipient_contact,
            &carried_files,
            &mut file_sequence,
        );
        relay_to_recipient += frames;
        unreturned_receipts += receipts;
        recipient.status()["selected_tip"] == paid["selected_tip"]
    });
    assert!(a_to_relay > 0 && relay_to_recipient > 0 && unreturned_receipts > 0);
    assert_eq!(recipient.transaction(&payment.id), payment.signed);
    let received = recipient.wallet(&recipient_wallet.owner);
    assert_eq!(unspent(&received), payment.amount);
    let incoming_outpoint = payment.outpoint();
    let coin = received["result"]["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|coin| coin["outpoint"] == incoming_outpoint)
        .expect("exact original payment output");
    assert_eq!(coin["amount"], payment.amount.to_string());
    assert_eq!(coin["eligible_next_height"], true);
    assert_eq!(coin["reserved"], false);

    // The sender exited before destination delivery. The restarted relay also
    // exits before the next wallet review, signature or nonce trial.
    let relay_pid = relay.stop();
    assert_ne!(source_pid, relay_pid);
    assert_ne!(original_relay_pid, relay_pid);
    let source_custody =
        rusqlite::Connection::open(fixture.join("source/contact/custody/carriage.sqlite3"))
            .unwrap();
    let source_counts: (i64, i64, i64) = source_custody.query_row(
        "SELECT (SELECT count(*) FROM receipts),(SELECT count(*) FROM hop_receipts),(SELECT count(*) FROM packets WHERE kind=3 AND done=0)",
        [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
    ).unwrap();
    assert_eq!(source_counts.0, 0);
    assert_eq!(source_counts.1, 0);
    assert!(source_counts.2 > 0);
    drop(source_custody);

    let onward = pay(
        &mut recipient,
        &recipient_wallet,
        &incoming_outpoint,
        payment.amount,
        &a_wallet.owner,
        131,
    );
    assert_eq!(onward.input, incoming_outpoint);
    let finished = include(&mut recipient, &recipient_wallet, &onward, deadline);
    assert_eq!(finished["confidence"], "CONDITIONAL");
    assert_eq!(recipient.transaction(&payment.id), payment.signed);
    assert_eq!(recipient.transaction(&onward.id), onward.signed);
    let source_balance = recipient.wallet(&a_wallet.owner);
    let recipient_balance = recipient.wallet(&recipient_wallet.owner);
    absent(&source_balance, &payment.input);
    absent(&recipient_balance, &incoming_outpoint);
    let onward_output = source_balance["result"]["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|coin| coin["outpoint"] == onward.outpoint())
        .expect("actual onward output owned by the source address");
    assert_eq!(onward_output["amount"], onward.amount.to_string());
    assert_eq!(
        (unspent(&source_balance) + unspent(&recipient_balance)).to_string(),
        finished["result"]["issued"]
    );
    recipient.stop();

    let mut cold = start("recipient", "cold", None);
    let cold_status = cold.status();
    assert_eq!(cold_status["chain_id"], chain);
    assert_eq!(cold_status["selected_tip"], finished["selected_tip"]);
    assert_eq!(cold_status["revision"], finished["revision"]);
    for field in ["height", "issued", "state_root"] {
        assert_eq!(cold_status["result"][field], finished["result"][field]);
    }
    assert_eq!(cold_status["result"]["mining_enabled"], false);
    assert_eq!(cold.transaction(&payment.id), payment.signed);
    assert_eq!(cold.transaction(&onward.id), onward.signed);
    assert_eq!(
        cold.wallet(&a_wallet.owner)["result"],
        source_balance["result"]
    );
    assert_eq!(
        cold.wallet(&recipient_wallet.owner)["result"],
        recipient_balance["result"]
    );
    cold.stop();

    // Read-only native reconstruction after all processes stop supplies a
    // complete-map conservation check; it cannot preload any process ledger.
    let cold_store = Store::open(
        &fixture.join("recipient"),
        &genesis_bytes,
        pin,
        Limits::default(),
    )
    .unwrap();
    assert_eq!(
        hex::encode(cold_store.ledger().tip().id()),
        finished["selected_tip"]
    );
    assert_eq!(
        cold_store
            .ledger()
            .coins()
            .values()
            .map(|coin| coin.amount)
            .sum::<u128>(),
        cold_store.ledger().issued()
    );
    assert!(!cold_store
        .ledger()
        .coins()
        .contains_key(&hex::decode(&payment.input).unwrap()));
    assert!(!cold_store
        .ledger()
        .coins()
        .contains_key(&hex::decode(&incoming_outpoint).unwrap()));
    assert_eq!(
        cold_store
            .get_transaction(hash_from_hex(&payment.id))
            .unwrap(),
        hex::decode(&payment.signed).unwrap()
    );
    assert_eq!(
        cold_store
            .get_transaction(hash_from_hex(&onward.id))
            .unwrap(),
        hex::decode(&onward.signed).unwrap()
    );
    assert_eq!(
        cold_store.ledger().coins()[&hex::decode(onward.outpoint()).unwrap()].amount,
        onward.amount
    );
    drop(cold_store);
    retain(
        &fixture.join("result.json"),
        serde_json::to_vec_pretty(&json!({
            "profile":"RLD-SURVIVOR-1","network_kind":"NO_VALUE_ONLY",
            "chain_id":chain,"selected_tip":finished["selected_tip"],
            "source_terminal_pid":source_pid,"relay_terminal_pid":relay_pid,
            "original_relay_terminal_pid":original_relay_pid,
            "sender_stopped_before_destination_delivery":true,
            "relay_restarted_without_config_before_delivery":true,
            "forward_frames_a_relay":a_to_relay,"forward_frames_relay_recipient":relay_to_recipient,
            "unreturned_receipts":unreturned_receipts,"reverse_imports":0,
            "payment_id":payment.id,"onward_id":onward.id,
            "elapsed_seconds":started.elapsed().as_secs_f64(),"budget_seconds":180,
            "independent_operation":false,"physical_route_qualified":false
        }))
        .unwrap()
        .as_slice(),
    );
    assert!(Instant::now() < deadline, "original whole180 budget");
}

fn hash_from_hex(value: &str) -> Hash {
    hex::decode(value).unwrap().try_into().unwrap()
}
