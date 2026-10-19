//! PUBLIC NO-VALUE fixture keys only. Retainer delegation is not coin authority.
#[allow(dead_code)]
#[path = "support/fast_funding.rs"]
mod support;
use rld_survivor_node::{
    fast_session::{Action, Id, OnchainRequest, Session, TransferOutput, TransferRequest},
    kernel::{fast, Hash},
    keyfile,
};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use support::*;
const PASSWORD: &[u8] = b"public no-value transfer funding passphrase";
fn dir(chain: Hash, label: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "rld-fast-transfer-{}-{}-{label}",
        std::process::id(),
        hex::encode(chain)
    ));
    fs::create_dir(&p).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
    }
    p
}
fn write(p: &Path, raw: &[u8]) {
    let mut o = fs::OpenOptions::new();
    o.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut file = o.open(p).unwrap();
    file.write_all(raw).unwrap();
    file.sync_all().unwrap();
}
fn id(v: &Value, k: &str) -> Id {
    serde_json::from_value(v[k].clone()).unwrap()
}
fn rid(n: &mut u64) -> Id {
    *n += 1;
    let mut raw = [0; 32];
    raw[..8].copy_from_slice(&n.to_be_bytes());
    Id(raw)
}
fn exec(s: &mut Session, n: &mut u64, a: Action, password: Option<&[u8]>, now: u64) -> (Id, Value) {
    let i = rid(n);
    let v = s.execute(i, s.head(), a, password, now).unwrap();
    (i, v)
}
fn funded(f: &Fixture, path: &Path) -> (Session, u64) {
    let mut s = Session::create(path, &f.genesis, f.ledger.chain_id(), f.now).unwrap();
    let mut n = 0;
    let mut at = 0;
    while at < f.history.len() {
        let z = u32::from_be_bytes(f.history[at..at + 4].try_into().unwrap()) as usize;
        at += 4;
        let tip = Id(s.tip());
        let (_, v) = exec(
            &mut s,
            &mut n,
            Action::Native {
                tip,
                block: hex::encode(&f.history[at..at + z]),
            },
            None,
            f.now,
        );
        at += z;
        assert!(v["diagnostic"].is_null(), "{v}");
    }
    (s, n)
}
fn transfer(f: &Fixture) -> TransferRequest {
    let input = out(f.channel, 1);
    let value = f.ledger.coins()[&input].amount;
    TransferRequest {
        owner: Id(f.owners[1].verifying_key().to_bytes()),
        inputs: vec![hex::encode(input)],
        outputs: vec![
            TransferOutput {
                owner: Id(f.retainer.verifying_key().to_bytes()),
                amount: "100".into(),
            },
            TransferOutput {
                owner: Id(f.owners[1].verifying_key().to_bytes()),
                amount: (value - 101).to_string(),
            },
        ],
        fee: "1".into(),
        expiry: u128::MAX.to_string(),
        timestamp: (f.ledger.tip().timestamp() + 600).to_string(),
    }
}
fn close(f: &Fixture, owner: usize) -> OnchainRequest {
    OnchainRequest {
        kind: 2,
        channel: Id(f.channel),
        actor: Id(f.owners[owner].verifying_key().to_bytes()),
        inputs: vec![hex::encode(out(f.channel, owner as u16))],
        fee: "1".into(),
        expiry: u128::MAX.to_string(),
        nonce: Id([81; 32]),
        certificate: String::new(),
        timestamp: (f.ledger.tip().timestamp() + 600).to_string(),
    }
}
fn sign(tip: Hash, prepare: Id, review: Id, key: &Path, approved: bool) -> Action {
    Action::OnchainSign {
        tip: Id(tip),
        prepare_request: prepare,
        review,
        key_file: key.to_string_lossy().into(),
        approved,
    }
}
#[test]
fn exact_transfer_review_signature_and_cross_operation_reservations_survive_cold_replay() {
    let deadline = Instant::now() + Duration::from_secs(180);
    let f = fixture();
    let chain = f.ledger.chain_id();
    let root = dir(chain, "review");
    let state = root.join("session");
    let (mut s, mut n) = funded(&f, &state);
    let plan = transfer(&f);
    let tip = s.tip();
    let (prepare, v) = exec(
        &mut s,
        &mut n,
        Action::TransferPrepare {
            tip: Id(tip),
            plan: plan.clone(),
        },
        None,
        f.now,
    );
    assert!(v["diagnostic"].is_null(), "{v}");
    assert_eq!(
        v["review"]["outputs"],
        serde_json::to_value(&plan.outputs).unwrap()
    );
    assert_eq!(v["review"]["operation_fee"], "1");
    let review = id(&v, "review_digest");
    let key = root.join("owner.key");
    write(
        &key,
        &keyfile::encrypt(&f.owners[1], chain, PASSWORD).unwrap(),
    );
    for a in [
        sign(tip, prepare, review, &root.join("absent.key"), false),
        sign(tip, prepare, Id([1; 32]), &root.join("absent.key"), true),
    ] {
        let (_, v) = exec(&mut s, &mut n, a, None, f.now);
        assert!(v["diagnostic"].is_string());
        assert!(!v["diagnostic"].as_str().unwrap().contains("MISSING key"));
        assert!(v["operation_hex"].is_null());
    }
    let h = s.head();
    let i = rid(&mut n);
    assert!(s
        .execute(
            i,
            h,
            Action::OnchainPrepare {
                tip: Id(tip),
                plan: close(&f, 1)
            },
            None,
            f.now
        )
        .unwrap_err()
        .contains("reserved"));
    assert_eq!(s.head(), h);
    let mut changed = plan.clone();
    changed.outputs[0].amount = "99".into();
    changed.outputs[1].amount =
        (changed.outputs[1].amount.parse::<u128>().unwrap() + 1).to_string();
    let i = rid(&mut n);
    assert!(s
        .execute(
            i,
            h,
            Action::TransferPrepare {
                tip: Id(tip),
                plan: changed
            },
            None,
            f.now
        )
        .unwrap_err()
        .contains("reserved"));
    assert_eq!(s.head(), h);
    let action = sign(tip, prepare, review, &key, true);
    let prior = s.head();
    let (request, v) = exec(&mut s, &mut n, action.clone(), Some(PASSWORD), f.now);
    assert!(v["diagnostic"].is_null(), "{v}");
    let raw = hex::decode(v["operation_hex"].as_str().unwrap()).unwrap();
    let outputs = plan
        .outputs
        .iter()
        .map(|o| (o.owner.0, o.amount.parse().unwrap()))
        .collect::<Vec<_>>();
    let (expected, txid) = ordinary(chain, &f.owners[1], &out(f.channel, 1), &outputs);
    assert_eq!(raw, expected);
    let head = s.head();
    drop(s);
    fs::rename(&key, root.join("retained-owner.key")).unwrap();
    let (mut s, recovered) = Session::recover(
        &state,
        &f.genesis,
        chain,
        prior,
        request,
        action.digest().unwrap(),
        f.now,
    )
    .unwrap();
    assert_eq!(s.head(), head);
    assert_eq!(recovered["operation_hex"], v["operation_hex"]);
    assert_eq!(recovered["key_loaded_by_recovery"], false);
    let (_, again) = exec(&mut s, &mut n, action, None, f.now);
    assert_eq!(again["operation_hex"], v["operation_hex"]);
    let mut ledger = f.ledger.clone();
    let block = mine(
        &mut ledger,
        f.miner.verifying_key().to_bytes(),
        vec![raw],
        f.now,
    );
    let tip = Id(s.tip());
    let (_, v) = exec(
        &mut s,
        &mut n,
        Action::Native {
            tip,
            block: hex::encode(block),
        },
        None,
        f.now,
    );
    assert!(v["diagnostic"].is_null());
    assert_eq!(
        ledger.coins()[&out(txid, 0)].owner,
        f.retainer.verifying_key().to_bytes()
    );
    assert_eq!(ledger.coins()[&out(txid, 0)].amount, 100);
    let head = s.head();
    drop(s);
    Session::open(&state, &f.genesis, chain, head, f.now).unwrap();
    // Reverse overlap: escrow approval first, then an ordinary funding transfer.
    let other = root.join("reverse");
    let (mut s, mut n) = funded(&f, &other);
    let tip = Id(s.tip());
    let (_, v) = exec(
        &mut s,
        &mut n,
        Action::OnchainPrepare {
            tip,
            plan: close(&f, 1),
        },
        None,
        f.now,
    );
    assert!(v["diagnostic"].is_null());
    let h = s.head();
    let i = rid(&mut n);
    assert!(s
        .execute(i, h, Action::TransferPrepare { tip, plan }, None, f.now)
        .unwrap_err()
        .contains("reserved"));
    assert_eq!(s.head(), h);
    assert!(Instant::now() < deadline, "original180 transfer review");
}

#[test]
fn invalid_native_transfers_never_produce_a_review_and_stale_signing_reads_no_key() {
    let deadline = Instant::now() + Duration::from_secs(180);
    let f = fixture();
    let chain = f.ledger.chain_id();
    let root = dir(chain, "invalid");
    let (mut s, mut n) = funded(&f, &root.join("session"));
    let plan = transfer(&f);
    let mut cases = vec![];
    let mut p = plan.clone();
    p.owner = Id(f.owners[0].verifying_key().to_bytes());
    cases.push(p);
    let mut p = plan.clone();
    p.outputs[0].amount = "101".into();
    cases.push(p);
    let mut p = plan.clone();
    p.outputs[0].amount = "0".into();
    cases.push(p);
    let mut p = plan.clone();
    p.outputs[0].owner = Id([0; 32]);
    cases.push(p);
    let mut p = plan.clone();
    p.fee = "0".into();
    cases.push(p);
    let mut p = plan.clone();
    p.expiry = f.ledger.tip().height().to_string();
    cases.push(p);
    let mut p = plan.clone();
    p.inputs.push(p.inputs[0].clone());
    cases.push(p);
    let mut p = plan.clone();
    p.inputs = vec![hex::encode([0; 34])];
    cases.push(p);
    let mut p = plan.clone();
    let (input, coin) = f
        .ledger
        .coins()
        .iter()
        .find(|(_, c)| c.maturity > 103)
        .unwrap();
    p.owner = Id(coin.owner);
    p.inputs = vec![hex::encode(input)];
    p.outputs = vec![TransferOutput {
        owner: p.owner,
        amount: (coin.amount - 1).to_string(),
    }];
    cases.push(p);
    for plan in cases {
        let tip = Id(s.tip());
        let (_, v) = exec(
            &mut s,
            &mut n,
            Action::TransferPrepare { tip, plan },
            None,
            f.now,
        );
        assert!(v["diagnostic"].is_string(), "{v}");
        assert!(v["review_digest"].is_null());
    }
    let tip = Id(s.tip());
    let (i, v) = exec(
        &mut s,
        &mut n,
        Action::TransferPrepare { tip, plan },
        None,
        f.now,
    );
    assert!(v["diagnostic"].is_null());
    let review = id(&v, "review_digest");
    let mut ledger = f.ledger.clone();
    let raw = mine(
        &mut ledger,
        f.miner.verifying_key().to_bytes(),
        vec![],
        f.now,
    );
    let tip = Id(s.tip());
    exec(
        &mut s,
        &mut n,
        Action::Native {
            tip,
            block: hex::encode(raw),
        },
        None,
        f.now,
    );
    let a = sign(s.tip(), i, review, &root.join("missing.key"), true);
    let (_, v) = exec(&mut s, &mut n, a, None, f.now);
    assert!(v["diagnostic"].is_string());
    assert!(!v["diagnostic"].as_str().unwrap().contains("MISSING key"));
    assert!(v["operation_hex"].is_null());
    // Remove the actual opening on a stronger branch, then re-review the same
    // reserved intent. Historical review/receipts cannot recreate its inputs.
    let mut fork = f.before.clone();
    for _ in 0..3 {
        let raw = mine(
            &mut fork,
            f.retainer.verifying_key().to_bytes(),
            vec![],
            f.now,
        );
        let tip = Id(s.tip());
        let (_, v) = exec(
            &mut s,
            &mut n,
            Action::Native {
                tip,
                block: hex::encode(raw),
            },
            None,
            f.now,
        );
        assert!(v["diagnostic"].is_null());
    }
    assert_eq!(s.tip(), fork.tip().id());
    let mut orphaned = transfer(&f);
    orphaned.timestamp = (fork.tip().timestamp() + 600).to_string();
    let tip = Id(s.tip());
    let (_, v) = exec(
        &mut s,
        &mut n,
        Action::TransferPrepare {
            tip,
            plan: orphaned,
        },
        None,
        f.now,
    );
    assert!(v["diagnostic"]
        .as_str()
        .unwrap()
        .contains("MISSING native transfer input"));
    assert!(v["review_digest"].is_null());
    assert!(Instant::now() < deadline, "original180 transfer negatives");
}

#[test]
fn maximum_transfer_signature_fits_the_existing_caller_reply_reservation() {
    let deadline = Instant::now() + Duration::from_secs(180);
    let f = aged_fixture(200_000);
    let chain = f.ledger.chain_id();
    let root = dir(chain, "maximum");
    let state = root.join("session");
    let (mut s, mut n) = funded(&f, &state);
    let mut ledger = f.ledger.clone();
    for _ in 0..40 {
        let raw = mine(
            &mut ledger,
            f.miner.verifying_key().to_bytes(),
            vec![],
            f.now,
        );
        let tip = Id(s.tip());
        let (_, v) = exec(
            &mut s,
            &mut n,
            Action::Native {
                tip,
                block: hex::encode(raw),
            },
            None,
            f.now,
        );
        assert!(v["diagnostic"].is_null());
    }
    let owner = f.owners[0].verifying_key().to_bytes();
    let inputs = ledger
        .coins()
        .iter()
        .filter(|(_, c)| c.owner == owner && c.maturity <= ledger.tip().height() + 1)
        .take(32)
        .collect::<Vec<_>>();
    assert_eq!(inputs.len(), 32);
    let total = inputs.iter().map(|(_, c)| c.amount).sum::<u128>();
    let mut outputs = (0..7)
        .map(|_| TransferOutput {
            owner: Id(f.retainer.verifying_key().to_bytes()),
            amount: "1".into(),
        })
        .collect::<Vec<_>>();
    outputs.push(TransferOutput {
        owner: Id(owner),
        amount: (total - 8).to_string(),
    });
    let plan = TransferRequest {
        owner: Id(owner),
        inputs: inputs.iter().map(|(i, _)| hex::encode(i)).collect(),
        outputs,
        fee: "1".into(),
        expiry: u128::MAX.to_string(),
        timestamp: (ledger.tip().timestamp() + 600).to_string(),
    };
    let tip = Id(s.tip());
    let (prepare, v) = exec(
        &mut s,
        &mut n,
        Action::TransferPrepare { tip, plan },
        None,
        f.now,
    );
    assert!(v["diagnostic"].is_null(), "{v}");
    let key = root.join("owner.key");
    write(
        &key,
        &keyfile::encrypt(&f.owners[0], chain, PASSWORD).unwrap(),
    );
    let a = sign(tip.0, prepare, id(&v, "review_digest"), &key, true);
    let prior = s.head();
    let (request, v) = exec(&mut s, &mut n, a.clone(), Some(PASSWORD), f.now);
    assert!(v["diagnostic"].is_null(), "{v}");
    let raw = hex::decode(v["operation_hex"].as_str().unwrap()).unwrap();
    assert_eq!(raw.len(), 1639);
    fast::validate_operation(&raw, chain).unwrap();
    let head = s.head();
    drop(s);
    fs::rename(&key, root.join("retained-owner.key")).unwrap();
    let (s, recovered) = Session::recover(
        &state,
        &f.genesis,
        chain,
        prior,
        request,
        a.digest().unwrap(),
        f.now,
    )
    .unwrap();
    assert_eq!(s.head(), head);
    assert_eq!(recovered["operation_hex"], v["operation_hex"]);
    assert_eq!(recovered["key_loaded_by_recovery"], false);
    assert!(Instant::now() < deadline, "original180 maximum transfer");
}

struct Node {
    child: Option<std::process::Child>,
    input: Option<std::process::ChildStdin>,
    rx: std::sync::mpsc::Receiver<String>,
    head: Id,
    tip: Id,
    count: u64,
    deadline: Instant,
    log: PathBuf,
}
impl Node {
    fn start(
        location: (&Path, &str),
        state: &Path,
        genesis: &Path,
        chain: Hash,
        head: Id,
        deadline: Instant,
    ) -> Self {
        use std::{
            io::{BufRead, BufReader},
            process::{Command, Stdio},
        };
        let (root, label) = location;
        let mut child = Command::new(env!("CARGO_BIN_EXE_rld-fast-payment-session"))
            .args([
                "serve",
                state.to_str().unwrap(),
                genesis.to_str().unwrap(),
                &hex::encode(chain),
                &hex::encode(head.0),
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
            let mut f = fs::File::create(log).unwrap();
            for line in BufReader::new(output).lines() {
                let line = line.unwrap();
                writeln!(f, "{line}").unwrap();
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut node = Self {
            child: Some(child),
            input: Some(input),
            rx,
            head,
            tip: Id(chain),
            count: 0,
            deadline,
            log: root.join(format!("{label}.terminal.json")),
        };
        let v = node.receive();
        node.update(&v);
        node
    }
    fn receive(&self) -> Value {
        serde_json::from_str(
            &self
                .rx
                .recv_timeout(self.deadline.saturating_duration_since(Instant::now()))
                .expect("original180 transfer process response"),
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
    }
    fn request(&mut self) -> Id {
        rid(&mut self.count)
    }
    fn command(&mut self, mut v: Value) -> Value {
        assert!(
            Instant::now() < self.deadline,
            "original180 transfer command"
        );
        v["head"] = serde_json::to_value(self.head).unwrap();
        writeln!(self.input.as_mut().unwrap(), "{v}").unwrap();
        self.input.as_mut().unwrap().flush().unwrap();
        let v = self.receive();
        self.update(&v);
        assert!(v["diagnostic"].is_null(), "{v}");
        v
    }
    fn execute(&mut self, action: Action, password: Option<&str>) -> (Id, Value) {
        let i = self.request();
        let v = self.command(
            json!({"command":"execute","request_id":i,"action":action,"password":password}),
        );
        (i, v)
    }
    fn authorize(&mut self, a: Action, key: &Path) -> (Id, Value) {
        let (prepare, v) = self.execute(a, None);
        let review = id(&v, "review_digest");
        let (signed, _) = self.execute(
            sign(self.tip.0, prepare, review, key, true),
            Some(std::str::from_utf8(PASSWORD).unwrap()),
        );
        let request = self.request();
        let queued = self.command(
            json!({"command":"submit_authorized","request_id":request,"sign_request":signed}),
        );
        (id(&queued, "pool_operation"), v)
    }
    fn mine(&mut self, miner: Id, timestamp: u64) -> Id {
        let mut refresh = true;
        loop {
            let v=self.command(json!({"command":"mine_pool","miner":miner,"timestamp":timestamp.to_string(),"attempts":4096,"scan_limit":128,"refresh":refresh}));
            refresh = false;
            if v["candidate"].is_string() {
                let candidate = id(&v, "candidate");
                let request = self.request();
                let v = self.command(
                    json!({"command":"admit_candidate","request_id":request,"candidate":candidate}),
                );
                assert_eq!(v["candidate_selected"], true);
                return candidate;
            }
        }
    }
    fn finish(&mut self) {
        self.input.take();
        let child = self.child.as_mut().unwrap();
        let pid = child.id();
        let status = loop {
            if let Some(s) = child.try_wait().unwrap() {
                break s;
            }
            assert!(
                Instant::now() < self.deadline,
                "original180 transfer node exit"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(status.success());
        write(
            &self.log,
            json!({"pid":pid,"exit_code":status.code(),"success":true,"forced_stop":false})
                .to_string()
                .as_bytes(),
        );
        self.child.take();
    }
}
impl Drop for Node {
    fn drop(&mut self) {
        if let Some(c) = &mut self.child {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

#[test]
fn actual_node_funds_retainer_then_claims_with_its_own_key_after_owner_keys_are_unavailable() {
    let deadline = Instant::now() + Duration::from_secs(180);
    let f = fixture();
    let chain = f.ledger.chain_id();
    let root = dir(chain, "process");
    let state = root.join("session");
    let genesis = root.join("genesis");
    write(&genesis, &f.genesis);
    let s = Session::create(&state, &f.genesis, chain, f.now).unwrap();
    let head = Id(s.head());
    drop(s);
    let mut node = Node::start((&root, "node"), &state, &genesis, chain, head, deadline);
    let mut at = 0;
    while at < f.history.len() {
        let z = u32::from_be_bytes(f.history[at..at + 4].try_into().unwrap()) as usize;
        at += 4;
        node.execute(
            Action::Native {
                tip: node.tip,
                block: hex::encode(&f.history[at..at + z]),
            },
            None,
        );
        at += z;
    }
    let keys = [root.join("owner-a.key"), root.join("owner-b.key")];
    for (i, path) in keys.iter().enumerate() {
        write(
            path,
            &keyfile::encrypt(&f.owners[i], chain, PASSWORD).unwrap(),
        );
    }
    let retainer_key = root.join("retainer.key");
    write(
        &retainer_key,
        &keyfile::encrypt(&f.retainer, chain, PASSWORD).unwrap(),
    );
    let plan = transfer(&f);
    let time = plan.timestamp.parse::<u64>().unwrap();
    let (funding, v) = node.authorize(
        Action::TransferPrepare {
            tip: node.tip,
            plan,
        },
        &keys[1],
    );
    let txid = id(&v["review"], "transaction_id");
    assert_ne!(funding, txid);
    let miner = Id(f.miner.verifying_key().to_bytes());
    node.mine(miner, time);
    let pool = node.command(json!({"command":"pool_status"}));
    assert_eq!(pool["operations"][0]["state"], "INCLUDED");
    let mut closing = close(&f, 0);
    closing.timestamp = (time + 600).to_string();
    node.authorize(
        Action::OnchainPrepare {
            tip: node.tip,
            plan: closing,
        },
        &keys[0],
    );
    for (i, path) in keys.iter().enumerate() {
        fs::rename(path, root.join(format!("retained-owner-{i}.key"))).unwrap();
    }
    node.mine(miner, time + 600);
    let origin = f.ledger.funding_origin(f.channel).unwrap();
    let receipt =
        rld_survivor_node::fast_payment::Payment::verify(&origin, &payment(&f, None, 0, 70, 82))
            .unwrap();
    let claim = OnchainRequest {
        kind: 4,
        channel: Id(f.channel),
        actor: Id(f.retainer.verifying_key().to_bytes()),
        inputs: vec![hex::encode(out(txid.0, 0))],
        fee: "1".into(),
        expiry: u128::MAX.to_string(),
        nonce: Id([83; 32]),
        certificate: hex::encode(receipt.after_certificate()),
        timestamp: (time + 1200).to_string(),
    };
    let (claim_id, v) = node.authorize(
        Action::OnchainPrepare {
            tip: node.tip,
            plan: claim,
        },
        &retainer_key,
    );
    assert_eq!(v["review"]["input_value"], "100");
    assert_eq!(v["review"]["owner_change"], "99");
    assert_eq!(v["review"]["known_miner_fee_ranges"], json!(["2", "0"]));
    assert_eq!(id(&v["review"], "funding_miner"), miner);
    fs::rename(&retainer_key, root.join("retained-retainer.key")).unwrap();
    node.mine(miner, time + 1200);
    let verify = TransferRequest {
        owner: Id(f.retainer.verifying_key().to_bytes()),
        inputs: vec![hex::encode(out(claim_id.0, 0))],
        outputs: vec![TransferOutput {
            owner: Id(f.retainer.verifying_key().to_bytes()),
            amount: "98".into(),
        }],
        fee: "1".into(),
        expiry: u128::MAX.to_string(),
        timestamp: (time + 1800).to_string(),
    };
    let (_, v) = node.execute(
        Action::TransferPrepare {
            tip: node.tip,
            plan: verify,
        },
        None,
    );
    assert_eq!(v["review"]["input_value"], "99");
    let head = node.head;
    let tip = node.tip;
    node.finish();
    let mut s = Session::open(&state, &f.genesis, chain, head.0, f.now + 180).unwrap();
    assert_eq!(s.tip(), tip.0);
    let status = s.pool_status(head.0, f.now + 180).unwrap();
    assert_eq!(status["operations"].as_array().unwrap().len(), 3);
    assert!(status["operations"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row["state"] == "INCLUDED"));
    assert!(
        Instant::now() < deadline,
        "original180 funded retainer composition"
    );
}

fn rehash_authorization(path: &Path, old: &str, new: &str) -> Hash {
    use sha2::{Digest, Sha256};
    let source = fs::read(path).unwrap();
    let mut result = source[..197].to_vec();
    let mut head: Hash =
        Sha256::digest([b"RLD-FAST-SESSION-1/HEADER\0".as_slice(), result.as_slice()].concat())
            .into();
    let mut at = 197;
    let mut replaced = false;
    while at < source.len() {
        let n = u32::from_be_bytes(source[at..at + 4].try_into().unwrap()) as usize;
        at += 4;
        let body = &source[at..at + n];
        at += n;
        let size = u32::from_be_bytes(body[33..37].try_into().unwrap()) as usize;
        let mut payload = body[37..37 + size].to_vec();
        if body[0] == 2 {
            let text = std::str::from_utf8(&payload).unwrap();
            let before = format!("\"authorization\":\"{old}\"");
            let after = format!("\"authorization\":\"{new}\"");
            if text.contains(&before) {
                payload = text.replace(&before, &after).into_bytes();
                replaced = true;
            }
        }
        let mut next = vec![body[0]];
        next.extend(head);
        next.extend((payload.len() as u32).to_be_bytes());
        next.extend(payload);
        head =
            Sha256::digest([b"RLD-FAST-SESSION-1/RECORD\0".as_slice(), next.as_slice()].concat())
                .into();
        next.extend(head);
        result.extend((next.len() as u32).to_be_bytes());
        result.extend(next);
    }
    assert!(replaced);
    fs::write(path, result).unwrap();
    head
}
#[test]
fn rehashed_caller_cannot_turn_a_changed_transfer_signature_into_authority() {
    let deadline = Instant::now() + Duration::from_secs(180);
    let f = fixture();
    let chain = f.ledger.chain_id();
    let root = dir(chain, "rehash");
    let state = root.join("session");
    let (mut s, mut n) = funded(&f, &state);
    let tip = Id(s.tip());
    let (prepare, v) = exec(
        &mut s,
        &mut n,
        Action::TransferPrepare {
            tip,
            plan: transfer(&f),
        },
        None,
        f.now,
    );
    let key = root.join("owner.key");
    write(
        &key,
        &keyfile::encrypt(&f.owners[1], chain, PASSWORD).unwrap(),
    );
    let (_, v) = exec(
        &mut s,
        &mut n,
        sign(tip.0, prepare, id(&v, "review_digest"), &key, true),
        Some(PASSWORD),
        f.now,
    );
    assert!(v["diagnostic"].is_null());
    let original = v["operation_hex"].as_str().unwrap().to_owned();
    let mut bad = hex::decode(&original).unwrap();
    let end = bad.len() - 1;
    bad[end] ^= 1;
    assert!(fast::validate_operation(&bad, chain).is_err());
    drop(s);
    let caller = state.join("caller.journal");
    write(
        &root.join("original-caller.journal"),
        &fs::read(&caller).unwrap(),
    );
    let head = rehash_authorization(&caller, &original, &hex::encode(bad));
    let before = fs::read(&caller).unwrap();
    let native = fs::read(state.join("native.journal")).unwrap();
    assert!(Session::open(&state, &f.genesis, chain, head, f.now).is_err());
    assert_eq!(fs::read(caller).unwrap(), before);
    assert_eq!(fs::read(state.join("native.journal")).unwrap(), native);
    assert!(Instant::now() < deadline, "original180 transfer rehash");
}

#[test]
fn transfer_cut_child() {
    let Some(path) = std::env::var_os("RLD_TRANSFER_CUT_FILE") else {
        return;
    };
    let v: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let state = Path::new(v["state"].as_str().unwrap());
    let genesis = hex::decode(v["genesis"].as_str().unwrap()).unwrap();
    let chain = id(&v, "chain");
    let head = id(&v, "head");
    let action = serde_json::from_value(v["action"].clone()).unwrap();
    let now = v["now"].as_u64().unwrap();
    let mut s = Session::open(state, &genesis, chain.0, head.0, now).unwrap();
    s.execute_observed(
        id(&v, "request"),
        head.0,
        action,
        Some(PASSWORD),
        now,
        |b| {
            use rld_survivor_node::fast_session::Boundary;
            let label = match b {
                Boundary::IntentDurable => "intent",
                Boundary::NativeActionEvaluated => "signed_memory",
                Boundary::ReplyDurable => "reply",
                Boundary::ChildDurable => "child",
            };
            if label == v["cut"].as_str().unwrap() {
                write(
                    &state.parent().unwrap().join("cut-reached"),
                    label.as_bytes(),
                );
                loop {
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        },
    )
    .unwrap();
    panic!("required transfer signing cut not reached");
}
struct Cut(Option<std::process::Child>);
impl Drop for Cut {
    fn drop(&mut self) {
        if let Some(c) = &mut self.0 {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}
#[test]
fn actual_transfer_process_cuts_preserve_reservations_and_never_first_sign_on_recovery() {
    use std::process::{Command, Stdio};
    let deadline = Instant::now() + Duration::from_secs(180);
    for cut in ["intent", "signed_memory", "reply"] {
        let f = fixture();
        let chain = f.ledger.chain_id();
        let root = dir(chain, "cut");
        let state = root.join("session");
        let (mut s, mut n) = funded(&f, &state);
        let tip = Id(s.tip());
        let plan = transfer(&f);
        let (prepare, v) = exec(
            &mut s,
            &mut n,
            Action::TransferPrepare {
                tip,
                plan: plan.clone(),
            },
            None,
            f.now,
        );
        let key = root.join("owner.key");
        write(
            &key,
            &keyfile::encrypt(&f.owners[1], chain, PASSWORD).unwrap(),
        );
        let action = sign(tip.0, prepare, id(&v, "review_digest"), &key, true);
        let prior = s.head();
        let native = s.native_head();
        let request = rid(&mut n);
        drop(s);
        let config = root.join("cut.json");
        write(&config,json!({"state":state,"genesis":hex::encode(&f.genesis),"chain":Id(chain),"head":Id(prior),"request":request,"action":action,"now":f.now,"cut":cut}).to_string().as_bytes());
        let mut child = Cut(Some(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "transfer_cut_child", "--nocapture"])
                .env("RLD_TRANSFER_CUT_FILE", config)
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
            assert!(Instant::now() < deadline, "original180 transfer cut");
            assert!(
                child.0.as_mut().unwrap().try_wait().unwrap().is_none(),
                "transfer child exited before boundary"
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
        write(&root.join("terminal.json"),json!({"pid":pid,"intentional_sigkill":true,"boundary":cut,"status":format!("{status:?}")}).to_string().as_bytes());
        fs::rename(&key, root.join("retained-owner.key")).unwrap();
        let before = fs::read(state.join("caller.journal")).unwrap();
        assert!(Session::recover(
            &state,
            &f.genesis,
            chain,
            prior,
            request,
            Id([1; 32]),
            f.now
        )
        .is_err());
        assert_eq!(fs::read(state.join("caller.journal")).unwrap(), before);
        let (mut s, v) = Session::recover(
            &state,
            &f.genesis,
            chain,
            prior,
            request,
            action.digest().unwrap(),
            f.now,
        )
        .unwrap();
        assert_eq!(s.native_head(), native);
        assert_eq!(v["key_loaded_by_recovery"], false);
        assert_eq!(v["operation_hex"].is_string(), cut == "reply");
        if cut == "reply" {
            fast::validate_operation(
                &hex::decode(v["operation_hex"].as_str().unwrap()).unwrap(),
                chain,
            )
            .unwrap();
        }
        let mut changed = plan;
        changed.fee = "2".into();
        changed.outputs[1].amount =
            (changed.outputs[1].amount.parse::<u128>().unwrap() - 1).to_string();
        let head = s.head();
        let i = rid(&mut n);
        assert!(s
            .execute(
                i,
                head,
                Action::TransferPrepare { tip, plan: changed },
                None,
                f.now
            )
            .unwrap_err()
            .contains("reserved"));
        assert_eq!(s.head(), head);
        let head = s.head();
        drop(s);
        let mut s = Session::open(&state, &f.genesis, chain, head, f.now).unwrap();
        let i = rid(&mut n);
        assert!(s
            .execute(
                i,
                head,
                Action::OnchainPrepare {
                    tip,
                    plan: close(&f, 1)
                },
                None,
                f.now
            )
            .unwrap_err()
            .contains("reserved"));
        assert_eq!(s.head(), head);
    }
    assert!(
        Instant::now() < deadline,
        "original180 transfer process cuts"
    );
}
