//! PUBLIC NO-VALUE fixture keys only. Actual CLI owner approvals and custody
//! signatures; latency observations are a finite cohort, not G9/G10 qualification.
#[allow(dead_code)]
#[path = "support/fast_funding.rs"]
mod support;
use rld_survivor_node::{
    fast_payment::Payment,
    fast_peer::{self, Config, PeerPin},
    fast_session::{
        Action, Id, OpeningRequest, OpeningTerms, Session, TransferOutput, TransferRequest,
    },
    kernel::Hash,
    keyfile,
};
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const PASSWORD: &[u8] = b"public no-value live payment approvals";
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn id(v: &Value, k: &str) -> Id {
    serde_json::from_value(v[k].clone()).unwrap()
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
    fs::File::open(path.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
}
struct Client {
    child: Child,
    input: Option<ChildStdin>,
    output: mpsc::Receiver<Value>,
    head: Id,
    tip: Id,
    count: u64,
    deadline: Instant,
}
impl Client {
    fn start(root: &Path, index: usize, chain: Hash, deadline: Instant) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_rld-fast-payment-session"))
            .arg("serve-log-control")
            .arg(root.join(format!("node-{index}")))
            .arg(root.join("genesis"))
            .arg(hex::encode(chain))
            .arg(root.join(format!("caller-{index}.head")))
            .arg("--peer-root")
            .arg(root.join(format!("peer-{index}")))
            .arg("--peer-head-file")
            .arg(root.join(format!("peer-{index}.head")))
            .arg("--auto-sync")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(
                fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(root.join(format!("cli-{index}.stderr")))
                    .unwrap(),
            )
            .spawn()
            .unwrap();
        let input = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::sync_channel(16);
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                let Ok(v) = serde_json::from_str(&line) else {
                    break;
                };
                if tx.send(v).is_err() {
                    break;
                }
            }
        });
        let mut client = Self {
            child,
            input,
            output: rx,
            head: Id([0; 32]),
            tip: Id([0; 32]),
            count: 10000,
            deadline,
        };
        let ready = client.read();
        client.update(&ready);
        assert_eq!(ready["local_runtime"]["automatic_peer_carriage"], true);
        assert_eq!(ready["local_runtime"]["fee_monitor"], Value::Null);
        assert_eq!(ready["local_runtime"]["ordinary_miner"], Value::Null);
        client
    }
    fn read(&self) -> Value {
        self.output
            .recv_timeout(self.deadline.saturating_duration_since(Instant::now()))
            .expect("original180 live owner response")
    }
    fn update(&mut self, v: &Value) {
        self.head = id(v, "session_head");
        if v["selected_tip"].is_string() {
            self.tip = id(v, "selected_tip");
        }
    }
    fn send(&mut self, mut request: Value) -> Value {
        if request["command"] != "runtime_status" {
            request["head"] = json!(self.head);
        }
        let input = self.input.as_mut().unwrap();
        writeln!(input, "{request}").unwrap();
        input.flush().unwrap();
        let v = self.read();
        self.update(&v);
        v
    }
    fn ok(&mut self, request: Value) -> Value {
        let v = self.send(request);
        assert!(v["diagnostic"].is_null(), "{v}");
        v
    }
    fn request(&mut self) -> Id {
        self.count += 1;
        let mut b = [0; 32];
        b[..8].copy_from_slice(&self.count.to_be_bytes());
        Id(b)
    }
    fn execute(&mut self, action: Action, password: bool) -> (Id, Value) {
        let r = self.request();
        let v = self.ok(json!({"command":"execute","request_id":r,"action":action,
            "password":if password{Some(std::str::from_utf8(PASSWORD).unwrap())}else{None}}));
        (r, v)
    }
    fn mine(&mut self, miner: Id, timestamp: u64, operation: Id) -> Vec<u8> {
        let mut refresh = true;
        loop {
            let v=self.ok(json!({"command":"mine_pool","miner":miner,"timestamp":timestamp.to_string(),"attempts":4096,"scan_limit":128,"refresh":refresh}));
            refresh = false;
            assert!(v["pool_template"]["selected_operations"]
                .as_array()
                .unwrap()
                .contains(&json!(operation)));
            if v["candidate"].is_string() {
                let candidate = id(&v, "candidate");
                let raw = hex::decode(v["block_hex"].as_str().unwrap()).unwrap();
                let request = self.request();
                let v = self.ok(
                    json!({"command":"admit_candidate","request_id":request,"candidate":candidate}),
                );
                assert_eq!(v["candidate_selected"], true);
                return raw;
            }
            assert!(Instant::now() < self.deadline);
        }
    }
    fn wait(&mut self, packet: Id) {
        loop {
            let v = self.send(json!({"command":"peer_data","packet":packet}));
            if v["diagnostic"].is_null() {
                return;
            }
            assert!(v["diagnostic"].as_str().unwrap().contains("MISSING"), "{v}");
            assert!(Instant::now() < self.deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn stop(mut self) {
        drop(self.input.take());
        loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                assert!(s.success());
                break;
            }
            assert!(Instant::now() < self.deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
struct Fixture {
    funding: support::Fixture,
    root: PathBuf,
    nodes: Vec<Client>,
    actors: Vec<Id>,
    keys: Vec<PathBuf>,
    peers: Vec<Id>,
    deadline: Instant,
}
struct Attempt<'a> {
    file: &'a mut fs::File,
    start: Instant,
    round: u8,
    payer: usize,
    completed: bool,
}
impl<'a> Attempt<'a> {
    fn new(file: &'a mut fs::File, round: u8, payer: usize) -> Self {
        let mut a = Self {
            file,
            start: Instant::now(),
            round,
            payer,
            completed: false,
        };
        a.phase("original_submission");
        a
    }
    fn phase(&mut self, name: &str) {
        writeln!(
            self.file,
            "{}",
            json!({"round":self.round,"payer":self.payer,"stage":name,
            "elapsed_seconds":self.start.elapsed().as_secs_f64()})
        )
        .unwrap();
        self.file.sync_all().unwrap();
    }
    fn complete(&mut self) -> f64 {
        let elapsed = self.start.elapsed().as_secs_f64();
        self.completed = true;
        writeln!(self.file,"{}",json!({"round":self.round,"payer":self.payer,"stage":"recipient_durable_funded_onward_state",
            "completed":true,"elapsed_seconds":elapsed})).unwrap();
        self.file.sync_all().unwrap();
        elapsed
    }
}
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if !self.completed {
            let _ = writeln!(
                self.file,
                "{}",
                json!({"round":self.round,"payer":self.payer,"completed":false,
        "failed":std::thread::panicking(),"infinite_completion_latency":true,"original_pending_age_seconds":self.start.elapsed().as_secs_f64()})
            );
            let _ = self.file.sync_all();
        }
    }
}
impl Fixture {
    fn new() -> Self {
        Self::new_profile(false)
    }
    fn new_profile(first_use: bool) -> Self {
        let deadline = Instant::now() + Duration::from_secs(180);
        let funding = if first_use {
            support::mined_fixture(61200, deadline)
        } else {
            support::fixture()
        };
        let chain = funding.ledger.chain_id();
        let root = std::env::temp_dir().join(format!(
            "rld-live-owner-{}-{}",
            std::process::id(),
            hex::encode(chain)
        ));
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        write(&root.join("genesis"), &funding.genesis);
        let infos = (0..3)
            .map(|i| fast_peer::provision(&root.join(format!("peer-{i}")), chain).unwrap())
            .collect::<Vec<_>>();
        let listeners = (0..3)
            .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
            .collect::<Vec<_>>();
        let endpoints = listeners
            .iter()
            .map(|l| l.local_addr().unwrap())
            .collect::<Vec<_>>();
        let peers = infos.iter().map(|v| id(v, "identity")).collect::<Vec<_>>();
        for i in 0..3 {
            let config = Config {
                chain: Id(chain),
                identity: peers[i],
                listen: endpoints[i],
                peers: (0..3)
                    .filter(|j| *j != i)
                    .map(|j| PeerPin {
                        key: peers[j],
                        endpoint: endpoints[j],
                        certificate_sha256: id(&infos[j], "certificate_sha256"),
                    })
                    .collect(),
            };
            fast_peer::bind_controlled(
                &root.join(format!("peer-{i}")),
                &serde_json::to_vec(&config).unwrap(),
                &root.join(format!("peer-{i}.head")),
                now(),
            )
            .unwrap();
            let mut session = Session::create_log_controlled(
                &root.join(format!("node-{i}")),
                &funding.genesis,
                chain,
                &root.join(format!("caller-{i}.head")),
                now(),
            )
            .unwrap();
            if i == 0 {
                let mut at = 0;
                let mut count = 0u64;
                while at < funding.history.len() {
                    let n = u32::from_be_bytes(funding.history[at..at + 4].try_into().unwrap())
                        as usize;
                    at += 4;
                    count += 1;
                    let mut token = [0; 32];
                    token[..8].copy_from_slice(&count.to_be_bytes());
                    let out = session
                        .execute(
                            Id(token),
                            session.head(),
                            Action::Native {
                                tip: Id(session.tip()),
                                block: hex::encode(&funding.history[at..at + n]),
                            },
                            None,
                            now(),
                        )
                        .unwrap();
                    assert!(out["diagnostic"].is_null());
                    at += n;
                    assert!(Instant::now() < deadline);
                }
            }
        }
        drop(listeners);
        let mut nodes = (0..3)
            .map(|i| Client::start(&root, i, chain, deadline))
            .collect::<Vec<_>>();
        for node in &mut nodes {
            loop {
                let v = node.ok(json!({"command":"runtime_status"}));
                if node.tip.0 == funding.ledger.tip().id() {
                    break;
                }
                assert!(v["automatic_carriage"]["diagnostic"].is_null());
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        let mut keys = vec![];
        for i in 0..nodes.len() {
            let key = root.join(format!("wallet-{i}.key"));
            write(
                &key,
                &keyfile::encrypt(
                    if i < 2 {
                        &funding.owners[i]
                    } else {
                        &funding.retainer
                    },
                    chain,
                    PASSWORD,
                )
                .unwrap(),
            );
            keys.push(key);
        }
        assert!(Instant::now() < deadline);
        let mut fixture = Self {
            funding,
            root,
            nodes,
            actors: vec![],
            keys,
            peers,
            deadline,
        };
        if first_use {
            fixture.fund_and_open();
        }
        fixture.register_actors();
        fixture
    }
    fn register_actors(&mut self) {
        let delegation = hex::encode(support::delegation(&self.funding));
        for (i, node) in self.nodes.iter_mut().enumerate() {
            let action = if i < 2 {
                Action::OwnerCreate {
                    tip: node.tip,
                    channel: Id(self.funding.channel),
                    owner: i as u8,
                    delegation: delegation.clone(),
                }
            } else {
                Action::RetainerCreate {
                    tip: node.tip,
                    channel: Id(self.funding.channel),
                    delegation: delegation.clone(),
                }
            };
            let (_, v) = node.execute(action, false);
            self.actors.push(id(&v, "actor"));
        }
        assert!(Instant::now() < self.deadline);
    }
    fn native_sign(&mut self, owner: usize, prepare: Id, review: Id) -> (Id, Value) {
        let tip = self.nodes[owner].tip;
        self.nodes[owner].execute(
            Action::OnchainSign {
                tip,
                prepare_request: prepare,
                review,
                key_file: self.keys[owner].to_string_lossy().into(),
                approved: true,
            },
            true,
        )
    }
    fn include(&mut self, operation: Id) {
        let timestamp = self.funding.ledger.tip().timestamp() + 600;
        let raw = self.nodes[0].mine(
            Id(self.funding.miner.verifying_key().to_bytes()),
            timestamp,
            operation,
        );
        self.funding.ledger.execute(&raw, now()).unwrap();
        self.funding
            .history
            .extend((raw.len() as u32).to_be_bytes());
        self.funding.history.extend(&raw);
        for node in &mut self.nodes {
            loop {
                let v = node.ok(json!({"command":"runtime_status"}));
                if node.tip.0 == self.funding.ledger.tip().id() {
                    break;
                }
                assert!(v["automatic_carriage"]["diagnostic"].is_null());
                assert!(Instant::now() < self.deadline);
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
    fn fund_and_open(&mut self) {
        assert_eq!(self.funding.ledger.active_channels(), 0);
        let owners = self
            .funding
            .owners
            .each_ref()
            .map(|k| Id(k.verifying_key().to_bytes()));
        assert!(self
            .funding
            .ledger
            .coins()
            .values()
            .all(|c| c.owner != owners[1].0));
        let mut report = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(self.root.join("native-first-use.jsonl"))
            .unwrap();
        let start = Instant::now();
        let (input, coin) = self
            .funding
            .ledger
            .coins()
            .iter()
            .find(|(_, c)| c.owner == owners[0].0 && c.maturity <= 101)
            .unwrap();
        let tip = self.nodes[0].tip;
        let plan = TransferRequest {
            owner: owners[0],
            inputs: vec![hex::encode(input)],
            outputs: [
                (owners[0], 2000),
                (owners[1], 2000),
                (owners[0], coin.amount - 4001),
            ]
            .into_iter()
            .map(|(owner, amount)| TransferOutput {
                owner,
                amount: amount.to_string(),
            })
            .collect(),
            fee: "1".into(),
            expiry: u128::MAX.to_string(),
            timestamp: (self.funding.ledger.tip().timestamp() + 600).to_string(),
        };
        writeln!(report,"{}",json!({"phase":"original_native_transfer_submission","elapsed_seconds":start.elapsed().as_secs_f64()})).unwrap();
        report.sync_all().unwrap();
        let (prepared, v) = self.nodes[0].execute(Action::TransferPrepare { tip, plan }, false);
        let (signed, v) = self.native_sign(0, prepared, id(&v, "review_digest"));
        let operation = id(&v, "operation_id");
        let request = self.nodes[0].request();
        let queued = self.nodes[0]
            .ok(json!({"command":"submit_authorized","request_id":request,"sign_request":signed}));
        assert_eq!(id(&queued, "pool_operation"), operation);
        self.include(operation);
        self.funding.before = self.funding.ledger.clone();
        writeln!(report,"{}",json!({"phase":"ordinary_transfer_admitted_all_peers","elapsed_seconds":start.elapsed().as_secs_f64(),"operation":operation})).unwrap();
        report.sync_all().unwrap();
        let inputs = owners.map(|owner| {
            vec![hex::encode(
                self.funding
                    .ledger
                    .coins()
                    .iter()
                    .find(|(_, c)| c.owner == owner.0 && c.amount == 2000)
                    .unwrap()
                    .0,
            )]
        });
        let timestamp = self.funding.ledger.tip().timestamp() + 600;
        let terms = OpeningTerms {
            nonce: Id([19; 32]),
            owners,
            principal: ["600".into(), "400".into()],
            limits: ["6".into(), "5".into()],
            rates: ["2".into(), "3".into()],
            fees: ["1".into(), "1".into()],
            expiry: u128::MAX.to_string(),
            inputs,
        };
        let proposal = self.nodes[0].ok(
            json!({"command":"opening_proposal","terms":terms,"timestamp":timestamp.to_string()}),
        );
        assert_eq!(proposal["owner_signature_created"], false);
        assert_eq!(proposal["change"], json!(["1387", "1584"]));
        let tip = self.nodes[0].tip;
        let (ap, av) = self.nodes[0].execute(
            Action::OpenPrepare {
                tip,
                plan: OpeningRequest {
                    proposal: proposal["proposal_hex"].as_str().unwrap().into(),
                    owner: 0,
                    timestamp: timestamp.to_string(),
                },
            },
            false,
        );
        let ar = id(&av, "review_digest");
        let sent = self.nodes[0]
            .ok(json!({"command":"peer_opening","source_request":ap,"destination":self.peers[1]}));
        let packet = id(&sent, "packet");
        self.nodes[1].wait(packet);
        let bp = self.nodes[1].request();
        let bv=self.nodes[1].ok(json!({"command":"peer_open_prepare","packet":packet,"request_id":bp,"owner":1,"timestamp":timestamp.to_string()}));
        assert_eq!(av["review"]["own_index"], 0);
        assert_eq!(bv["review"]["own_index"], 1);
        assert_eq!(av["review"]["principal"], json!(["600", "400"]));
        assert_eq!(bv["review"]["principal"], av["review"]["principal"]);
        let br = id(&bv, "review_digest");
        let (asign, av) = self.native_sign(0, ap, ar);
        let (bsign, bv) = self.native_sign(1, bp, br);
        assert!(av["operation_hex"].is_null());
        assert!(bv["operation_hex"].is_null());
        let sent = self.nodes[1].ok(
            json!({"command":"peer_opening","source_request":bsign,"destination":self.peers[0]}),
        );
        let partial = id(&sent, "packet");
        self.nodes[0].wait(partial);
        let combined = self.nodes[0].request();
        let v=self.nodes[0].ok(json!({"command":"peer_open_combine","packet":partial,"request_id":combined,"prepare_request":ap,"sign_request":asign,"review":ar}));
        self.funding.channel = id(&v, "operation_id").0;
        let request = self.nodes[0].request();
        let queued = self.nodes[0].ok(
            json!({"command":"submit_authorized","request_id":request,"sign_request":combined}),
        );
        assert_eq!(id(&queued, "pool_operation").0, self.funding.channel);
        self.include(Id(self.funding.channel));
        assert_eq!(self.funding.ledger.active_channels(), 1);
        let origin = self
            .funding
            .ledger
            .funding_origin(self.funding.channel)
            .unwrap();
        assert_eq!(origin.initial(), [600, 400]);
        writeln!(report,"{}",json!({"phase":"joint_opening_admitted_all_peers","elapsed_seconds":start.elapsed().as_secs_f64(),"channel":Id(self.funding.channel),"settlement_or_fast_payment_claim":false})).unwrap();
        report.sync_all().unwrap();
    }
}

#[test]
fn actual_explicit_owner_forward_and_onward_payments_over_automatic_native_peers() {
    run_flow(25, Ending::Active, false);
}
#[test]
fn received_value_is_required_for_onward_and_closed_funding_is_only_historical() {
    run_flow(450, Ending::Closing, false);
}
#[test]
fn exhausted_fee_slots_preserve_principal_but_disable_another_payment() {
    run_flow(0, Ending::Active, true);
}
#[test]
fn greater_native_work_removes_usable_backing_but_keeps_complete_receipt_evidence() {
    run_flow(25, Ending::Reorganized, false);
}
#[test]
fn first_use_native_transfer_joint_opening_and_received_value_onward_payment() {
    run_flow_setup(450, Ending::Active, false, true);
}
#[derive(Clone, Copy)]
enum Ending {
    Active,
    Closing,
    Reorganized,
}
fn run_flow(reverse: u128, ending: Ending, exhaust: bool) {
    run_flow_setup(reverse, ending, exhaust, false);
}
fn run_flow_setup(reverse: u128, ending: Ending, exhaust: bool, first_use: bool) {
    let close_after = matches!(ending, Ending::Closing);
    let inactive = !matches!(ending, Ending::Active);
    let setup = Instant::now();
    let mut t = Fixture::new_profile(first_use);
    let setup_seconds = setup.elapsed().as_secs_f64();
    let mut report = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(t.root.join("original-payment-clocks.jsonl"))
        .unwrap();
    let rounds = if exhaust {
        (1u8..=6).map(|n| (n, 0usize, 1u128)).collect::<Vec<_>>()
    } else {
        vec![(1, 0, 70), (2, 1, reverse)]
    };
    let count = rounds.len();
    let expected_fee = if exhaust { 12 } else { 5 };
    writeln!(report,"{}",json!({"cohort":if first_use{"ACTUAL_NATIVE_FIRST_USE_THEN_FAST_PAYMENTS"}else if exhaust{"EXHAUSTED_FEE_SLOTS"}else if close_after{"RECEIVED_VALUE_REQUIRED_THEN_NATIVE_CLOSE"}else if inactive{"NATIVE_REORGANIZATION_REMOVES_FUNDING"}else{"PREFUNDED_STABLE_NATIVE_LOCAL_APPROVAL_BASELINE"},"planned":count,"reverse_amount":reverse.to_string(),"setup_seconds":setup_seconds,
        "p95_max_seconds":3,"p99_max_seconds":5,"independent":false,"G9_qualified":false})).unwrap();
    report.sync_all().unwrap();
    let mut latencies = vec![];
    let mut last = vec![];
    let origin = t.funding.ledger.funding_origin(t.funding.channel).unwrap();
    for (i, balance) in [600u128, 400].into_iter().enumerate() {
        let head = t.nodes[i].head;
        let v = t.nodes[i].ok(json!({"command":"owner_state","actor":t.actors[i]}));
        assert_eq!(t.nodes[i].head, head);
        assert_eq!(v["retained_principal"], balance.to_string());
        assert_eq!(v["conditional_onward_principal"], balance.to_string());
        assert_eq!(v["complete_receipt_retained"], false);
        assert_eq!(v["owner_spend_authorized"], false);
    }
    if close_after || first_use {
        let v=t.nodes[1].send(json!({"command":"propose","actor":t.actors[1],"payer":1,"amount":reverse.to_string(),"invoice":Id([110;32])}));
        assert_eq!(v["diagnostic"], "INVALID fast unfunded payment");
        assert!(v["invoice_hex"].is_null());
    }
    for (round, payer, amount) in rounds {
        let recipient = 1 - payer;
        let mut trace = Attempt::new(&mut report, round, payer);
        let proposal=t.nodes[payer].ok(json!({"command":"propose","actor":t.actors[payer],"payer":payer,"amount":amount.to_string(),"invoice":Id([round;32])}));
        let inv = id(&proposal, "invoice_id");
        let tip = t.nodes[payer].tip;
        let (pr, pv) = t.nodes[payer].execute(
            Action::OwnerPrepare {
                tip,
                actor: t.actors[payer],
                invoice: proposal["invoice_hex"].as_str().unwrap().into(),
            },
            false,
        );
        let sent=t.nodes[payer].ok(json!({"command":"peer_invoice","actor":t.actors[payer],"invoice":inv,"destination":t.peers[recipient]}));
        let packet = id(&sent, "packet");
        t.nodes[recipient].wait(packet);
        let rr = t.nodes[recipient].request();
        let rv=t.nodes[recipient].ok(json!({"command":"peer_prepare","actor":t.actors[recipient],"packet":packet,"request_id":rr}));
        trace.phase("both_reviews_durable");
        for (i, r, v) in [(payer, pr, &pv), (recipient, rr, &rv)] {
            let before = t.nodes[i].ok(json!({"command":"owner_state","actor":t.actors[i]}));
            assert_eq!(before["conditional_onward_state_available"], false);
            assert!(before["conditional_onward_principal"].is_null());
            assert_eq!(before["pending_payment"]["invoice"], json!(inv));
            assert_eq!(before["pending_payment"]["own_signature_retained"], false);
            assert_eq!(v["review"]["amount"], amount.to_string());
            assert_eq!(v["review"]["fee"], origin.rate(payer).unwrap().to_string());
            for (field, key) in [
                ("owner", t.funding.owners[i].verifying_key().to_bytes()),
                ("payer", t.funding.owners[payer].verifying_key().to_bytes()),
                (
                    "recipient",
                    t.funding.owners[recipient].verifying_key().to_bytes(),
                ),
                ("miner", t.funding.miner.verifying_key().to_bytes()),
                ("retainer", t.funding.retainer.verifying_key().to_bytes()),
            ] {
                assert_eq!(v["review"][field], json!(Id(key)));
            }
            assert_eq!(v["review"]["chain"], json!(Id(t.funding.ledger.chain_id())));
            assert_eq!(v["review"]["channel"], json!(Id(t.funding.channel)));
            let tip = t.nodes[i].tip;
            t.nodes[i].execute(
                Action::OwnerSign {
                    tip,
                    actor: t.actors[i],
                    invoice: inv,
                    review_request: r,
                    review: id(v, "review_digest"),
                    key_file: t.keys[i].to_string_lossy().into(),
                    approved: true,
                },
                true,
            );
            let after = t.nodes[i].ok(json!({"command":"owner_state","actor":t.actors[i]}));
            assert_eq!(after["pending_payment"]["own_signature_retained"], true);
            for field in ["original_prepared_at", "original_prepared_native_tip"] {
                assert_eq!(
                    after["pending_payment"][field],
                    before["pending_payment"][field]
                );
            }
        }
        trace.phase("both_explicit_owner_signatures_durable");
        let mut partials = vec![];
        for i in 0..2 {
            let v=t.nodes[i].ok(json!({"command":"peer_partial","actor":t.actors[i],"invoice":inv,"destination":t.peers[1-i]}));
            partials.push(id(&v, "packet"));
        }
        t.nodes[0].wait(partials[1]);
        t.nodes[1].wait(partials[0]);
        let full=t.nodes[0].ok(json!({"command":"peer_combine_send","actor":t.actors[0],"invoice":inv,"partial":partials[1],"destinations":[t.peers[2]]}));
        let packet = id(&full["sent"][0], "packet");
        t.nodes[2].wait(packet);
        let r = t.nodes[2].request();
        let v = t.nodes[2].ok(
            json!({"command":"peer_prepare","actor":t.actors[2],"packet":packet,"request_id":r}),
        );
        let receipt = id(&v["review"], "receipt_id");
        let tip = t.nodes[2].tip;
        t.nodes[2].execute(
            Action::RetainerSign {
                tip,
                actor: t.actors[2],
                receipt,
                review_request: r,
                review: id(&v, "review_digest"),
                key_file: t.keys[2].to_string_lossy().into(),
                approved: true,
            },
            true,
        );
        trace.phase("delegated_full_receipt_custody_durable");
        for i in [recipient, payer] {
            let v=t.nodes[2].ok(json!({"command":"peer_ack","actor":t.actors[2],"receipt":receipt,"destination":t.peers[i]}));
            let ack = id(&v, "packet");
            t.nodes[i].wait(ack);
            let request = t.nodes[i].request();
            let v=t.nodes[i].ok(json!({"command":"peer_complete","actor":t.actors[i],"invoice":inv,"partial":partials[1-i],"ack":ack,"request_id":request}));
            assert_eq!(v["fast_completion_authorized"], false);
            last = hex::decode(v["receipt_hex"].as_str().unwrap()).unwrap();
            if i == recipient {
                let view = t.nodes[i].ok(json!({"command":"owner_state","actor":t.actors[i]}));
                assert_eq!(view["native_backing_usable_now"], true);
                assert_eq!(view["conditional_onward_state_available"], true);
                assert_eq!(view["retained_state_sequence"], round.to_string());
                assert!(view["pending_payment"].is_null());
                let next=t.nodes[i].ok(json!({"command":"propose","actor":t.actors[i],"payer":i,"amount":"1","invoice":Id([120+round;32])}));
                assert!(next["invoice_hex"].is_string());
                assert_eq!(next["signed"], false);
                assert_eq!(next["reserved"], false);
                latencies.push(trace.complete());
            }
        }
        trace.phase("both_owners_complete");
        assert!(Instant::now() < t.deadline);
    }
    let payment = Payment::verify(&origin, &last).unwrap();
    let state = origin
        .verify_certificate(payment.after_certificate())
        .unwrap();
    let balances = if exhaust {
        [594, 406]
    } else {
        [530 + reverse, 470 - reverse]
    };
    assert_eq!(state.balances, balances);
    assert_eq!(state.slots, if exhaust { [6, 0] } else { [1, 1] });
    assert_eq!(
        origin.rate(0).unwrap() * state.slots[0] as u128
            + origin.rate(1).unwrap() * state.slots[1] as u128,
        expected_fee
    );
    if exhaust {
        let v = t.nodes[0].ok(json!({"command":"owner_state","actor":t.actors[0]}));
        assert_eq!(v["native_backing_usable_now"], true);
        assert_eq!(v["remaining_own_fee_slots"], "0");
        assert_eq!(v["retained_principal"], "594");
        assert_eq!(v["conditional_onward_state_available"], false);
        assert!(v["conditional_onward_principal"].is_null());
        assert!(v["pending_payment"].is_null());
        let blocked=t.nodes[0].send(json!({"command":"propose","actor":t.actors[0],"payer":0,"amount":"1","invoice":Id([100;32])}));
        assert_eq!(blocked["diagnostic"], "INVALID fast payer slot bound");
        assert!(blocked["invoice_hex"].is_null());
    }
    let mut sorted = latencies.clone();
    sorted.sort_by(f64::total_cmp);
    let max = sorted[count - 1];
    writeln!(report,"{}",json!({"submitted":count,"completed":count,"failed":0,"pending":0,"latencies_seconds":latencies,"p95_seconds":max,"p99_seconds":max,
        "diagnostic_target_met":max<=3.0,"population_qualification":false,"G9_qualified":false,"daily100M_qualified":false})).unwrap();
    report.sync_all().unwrap();
    drop(report);
    if matches!(ending, Ending::Reorganized) {
        let mut alternate = t.funding.before.clone();
        for _ in 0..2 {
            let block = support::mine_until(
                &mut alternate,
                t.funding.miner.verifying_key().to_bytes(),
                vec![],
                now(),
                t.deadline,
            );
            let tip = t.nodes[0].tip;
            t.nodes[0].execute(
                Action::Native {
                    tip,
                    block: hex::encode(block),
                },
                false,
            );
        }
        assert!(alternate.funding_origin(t.funding.channel).is_err());
        t.funding.ledger = alternate;
    }
    if close_after {
        let input = support::out(t.funding.channel, 1);
        let change = t.funding.ledger.coins()[&input].amount - 1;
        let close = support::action(
            &t.funding,
            2,
            &t.funding.owners[1],
            (&input, change),
            &[],
            190,
        );
        let block = support::mine_until(
            &mut t.funding.ledger,
            t.funding.miner.verifying_key().to_bytes(),
            vec![close],
            now(),
            t.deadline,
        );
        let tip = t.nodes[0].tip;
        t.nodes[0].execute(
            Action::Native {
                tip,
                block: hex::encode(block),
            },
            false,
        );
    }
    if inactive {
        for node in &mut t.nodes {
            loop {
                node.ok(json!({"command":"runtime_status"}));
                if node.tip.0 == t.funding.ledger.tip().id() {
                    break;
                }
                assert!(Instant::now() < t.deadline);
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        for (i, balance) in balances.iter().enumerate() {
            let v = t.nodes[i].ok(json!({"command":"owner_state","actor":t.actors[i]}));
            assert_eq!(v["native_backing_usable_now"], false);
            assert_eq!(v["conditional_onward_state_available"], false);
            assert_eq!(
                v["native_backing_diagnostic"],
                if close_after {
                    "WAITING fast backing closing"
                } else {
                    "WAITING_FOR_INPUT fast backing absent"
                }
            );
            assert!(v["conditional_onward_principal"].is_null());
            assert_eq!(v["retained_principal"], balance.to_string());
            assert_eq!(
                v["retained_miner_fee_entitlement"],
                expected_fee.to_string()
            );
            let blocked=t.nodes[i].send(json!({"command":"propose","actor":t.actors[i],"payer":i,"amount":"1","invoice":Id([200+i as u8;32])}));
            assert_eq!(blocked["diagnostic"], v["native_backing_diagnostic"]);
            assert!(blocked["invoice_hex"].is_null());
        }
    }
    for node in t.nodes.drain(..) {
        node.stop();
    }
    for (i, key) in t.keys.iter().enumerate() {
        fs::rename(key, t.root.join(format!("unavailable-{i}.key"))).unwrap();
        let mut cold = Session::open_log_controlled(
            &t.root.join(format!("node-{i}")),
            &t.funding.genesis,
            t.funding.ledger.chain_id(),
            &t.root.join(format!("caller-{i}.head")),
            now(),
        )
        .unwrap();
        assert_eq!(cold.tip(), t.funding.ledger.tip().id());
        let v = cold.exit_evidence(cold.head(), t.actors[i], now()).unwrap();
        assert_eq!(
            v["certificate_hex"],
            hex::encode(payment.after_certificate())
        );
        assert_eq!(v["wallet_key_loaded"], false);
        assert_eq!(v["sequence"], count.to_string());
        if let Some(balance) = balances.get(i) {
            let v = cold.owner_state(cold.head(), t.actors[i], now()).unwrap();
            assert_eq!(v["retained_principal"], balance.to_string());
            assert_eq!(
                v["retained_miner_fee_entitlement"],
                expected_fee.to_string()
            );
            assert_eq!(v["native_backing_usable_now"], !inactive);
            assert_eq!(
                v["conditional_onward_state_available"],
                !inactive && !(exhaust && i == 0)
            );
            assert_eq!(v["wallet_key_loaded"], false);
        }
    }
    assert!(Instant::now() < t.deadline);
    println!(
        "live_owner_baseline_seconds={}",
        serde_json::to_string(&latencies).unwrap()
    );
}

#[test]
fn pending_view_keeps_original_preparation_and_blocks_reuse_across_review_sign_and_restart() {
    let mut t = Fixture::new();
    let bad = t.nodes[2].send(json!({"command":"owner_state","actor":t.actors[2]}));
    assert_eq!(bad["diagnostic"], "INVALID owner observation role");
    let v=t.nodes[0].ok(json!({"command":"propose","actor":t.actors[0],"payer":0,"amount":"70","invoice":Id([91;32])}));
    let invoice = id(&v, "invoice_id");
    let raw = v["invoice_hex"].as_str().unwrap().to_string();
    let tip = t.nodes[0].tip;
    t.nodes[0].execute(
        Action::OwnerPrepare {
            tip,
            actor: t.actors[0],
            invoice: raw.clone(),
        },
        false,
    );
    let first = t.nodes[0].ok(json!({"command":"owner_state","actor":t.actors[0]}));
    assert_eq!(first["conditional_onward_state_available"], false);
    assert_eq!(first["retained_principal"], "600");
    assert!(first["conditional_onward_principal"].is_null());
    let prepared = first["pending_payment"]["original_prepared_at"]
        .as_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let blocked=t.nodes[0].send(json!({"command":"propose","actor":t.actors[0],"payer":0,"amount":"1","invoice":Id([92;32])}));
    assert_eq!(
        blocked["diagnostic"],
        "CONFLICT proposal role/pending invoice"
    );
    let tip = t.nodes[0].tip;
    let (review, rv) = t.nodes[0].execute(
        Action::OwnerReview {
            tip,
            actor: t.actors[0],
        },
        false,
    );
    let tip = t.nodes[0].tip;
    t.nodes[0].execute(
        Action::OwnerSign {
            tip,
            actor: t.actors[0],
            invoice,
            review_request: review,
            review: id(&rv, "review_digest"),
            key_file: t.keys[0].to_string_lossy().into(),
            approved: true,
        },
        true,
    );
    let tip = t.nodes[0].tip;
    t.nodes[0].execute(
        Action::OwnerPrepare {
            tip,
            actor: t.actors[0],
            invoice: raw,
        },
        false,
    );
    let after = t.nodes[0].ok(json!({"command":"owner_state","actor":t.actors[0]}));
    for field in [
        "original_prepared_at",
        "original_prepared_native_tip",
        "invoice",
        "logical_payment",
    ] {
        assert_eq!(
            after["pending_payment"][field],
            first["pending_payment"][field]
        );
    }
    assert_eq!(after["pending_payment"]["own_signature_retained"], true);
    assert_eq!(after["retained_state_sequence"], "0");
    assert_eq!(after["complete_receipt_retained"], false);
    let actor_head = after["actor_head"].clone();
    for node in t.nodes.drain(..) {
        node.stop();
    }
    fs::rename(&t.keys[0], t.root.join("unavailable-owner.key")).unwrap();
    let mut cold = Session::open_log_controlled(
        &t.root.join("node-0"),
        &t.funding.genesis,
        t.funding.ledger.chain_id(),
        &t.root.join("caller-0.head"),
        now(),
    )
    .unwrap();
    let original = fs::read(t.root.join("node-0/caller.journal")).unwrap();
    let head = cold.head();
    // A logical later observation tests age preservation; no physical delay or
    // product clock override is implied, and it grants no monetary rights.
    let observed = now() + 10;
    let v = cold.owner_state(head, t.actors[0], observed).unwrap();
    assert_eq!(v["actor_head"], actor_head);
    assert_eq!(
        v["pending_payment"]["original_prepared_at"],
        prepared.to_string()
    );
    assert_eq!(
        v["pending_payment"]["original_pending_age_seconds"],
        (observed - prepared).to_string()
    );
    assert_eq!(v["conditional_onward_state_available"], false);
    assert!(v["conditional_onward_principal"].is_null());
    assert_eq!(v["wallet_key_loaded"], false);
    assert_eq!(cold.head(), head);
    assert_eq!(
        fs::read(t.root.join("node-0/caller.journal")).unwrap(),
        original
    );
    assert!(cold.owner_state([0; 32], t.actors[0], observed).is_err());
    assert!(cold.owner_state(head, Id([0; 32]), observed).is_err());
    let actor_path = t
        .root
        .join("node-0/actors")
        .join(format!("{}.journal", hex::encode(t.actors[0].0)));
    let mut damaged = fs::read(&actor_path).unwrap();
    let last = damaged.len() - 1;
    damaged[last] ^= 1;
    fs::write(&actor_path, &damaged).unwrap();
    assert!(cold.owner_state(head, t.actors[0], observed).is_err());
    assert_eq!(fs::read(&actor_path).unwrap(), damaged);
    assert_eq!(
        fs::read(t.root.join("node-0/caller.journal")).unwrap(),
        original
    );
    assert!(Instant::now() < t.deadline);
}
