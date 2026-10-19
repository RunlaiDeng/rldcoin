//! PUBLIC NO-VALUE fixture keys only. Old logical genesis timestamps exercise
//! unchanged native windows; they do not measure physical elapsed-time safety.
#[allow(dead_code)]
#[path = "support/fast_funding.rs"]
mod support;
use rld_survivor_node::{
    fast_session::{Action, Id, OnchainRequest, Session},
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
const PASSWORD: &[u8] = b"public no-value native action passphrase";
fn directory(chain: Hash, label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "rld-fast-onchain-{}-{}-{label}",
        std::process::id(),
        hex::encode(chain)
    ));
    fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    root
}
fn write(path: &Path, raw: &[u8]) {
    let mut o = fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut file = o.open(path).unwrap();
    file.write_all(raw).unwrap();
    file.sync_all().unwrap();
}
fn id(v: &Value, key: &str) -> Id {
    serde_json::from_value(v[key].clone()).unwrap()
}
fn rid(n: &mut u64) -> Id {
    *n += 1;
    let mut b = [0; 32];
    b[..8].copy_from_slice(&n.to_be_bytes());
    Id(b)
}
fn execute(s: &mut Session, n: &mut u64, a: Action, pass: Option<&[u8]>, now: u64) -> (Id, Value) {
    let i = rid(n);
    let v = s.execute(i, s.head(), a, pass, now).unwrap();
    (i, v)
}
fn funded(f: &Fixture, root: &Path) -> (Session, u64) {
    let mut s = Session::create(root, &f.genesis, f.ledger.chain_id(), f.now).unwrap();
    let mut n = 0;
    let mut at = 0;
    while at < f.history.len() {
        let z = u32::from_be_bytes(f.history[at..at + 4].try_into().unwrap()) as usize;
        at += 4;
        let a = Action::Native {
            tip: Id(s.tip()),
            block: hex::encode(&f.history[at..at + z]),
        };
        at += z;
        assert!(execute(&mut s, &mut n, a, None, f.now).1["diagnostic"].is_null());
    }
    (s, n)
}
fn close(f: &Fixture) -> OnchainRequest {
    OnchainRequest {
        kind: 2,
        channel: Id(f.channel),
        actor: Id(f.owners[0].verifying_key().to_bytes()),
        inputs: vec![hex::encode(out(f.channel, 0))],
        fee: "1".into(),
        expiry: u128::MAX.to_string(),
        nonce: Id([91; 32]),
        certificate: String::new(),
        timestamp: (f.ledger.tip().timestamp() + 600).to_string(),
    }
}
#[test]
fn native_review_reserves_exact_fee_inputs_and_cold_authenticates_explicit_signatures() {
    let f = fixture();
    let chain = f.ledger.chain_id();
    let root = directory(chain, "review");
    let state = root.join("session");
    let (mut s, mut n) = funded(&f, &state);
    let plan = close(&f);
    let a = Action::OnchainPrepare {
        tip: Id(s.tip()),
        plan: plan.clone(),
    };
    let (prepared, v) = execute(&mut s, &mut n, a, None, f.now);
    assert!(v["diagnostic"].is_null(), "{v}");
    assert_eq!(v["review"]["operation_fee"], "1");
    assert_eq!(v["review"]["owner_change"], "1386");
    assert_eq!(v["review"]["operation"], "CLOSE");
    let review = id(&v, "review_digest");
    let key = root.join("owner.key");
    write(
        &key,
        &keyfile::encrypt(&f.owners[0], chain, PASSWORD).unwrap(),
    );
    for (approved, digest) in [(false, review), (true, Id([1; 32]))] {
        let a = Action::OnchainSign {
            tip: Id(s.tip()),
            prepare_request: prepared,
            review: digest,
            key_file: root.join("missing.key").to_string_lossy().into(),
            approved,
        };
        let v = execute(&mut s, &mut n, a, None, f.now).1;
        assert!(v["diagnostic"].is_string());
        assert!(!v["diagnostic"].as_str().unwrap().contains("MISSING key"));
        assert!(v["operation_hex"].is_null());
    }
    let mut conflict = plan.clone();
    conflict.nonce = Id([92; 32]);
    let h = s.head();
    let i = rid(&mut n);
    let tip = Id(s.tip());
    assert!(s
        .execute(
            i,
            h,
            Action::OnchainPrepare {
                tip,
                plan: conflict
            },
            None,
            f.now
        )
        .unwrap_err()
        .contains("reserved"));
    assert_eq!(s.head(), h);
    let sign = Action::OnchainSign {
        tip: Id(s.tip()),
        prepare_request: prepared,
        review,
        key_file: key.to_string_lossy().into(),
        approved: true,
    };
    let prior = s.head();
    let (i, v) = execute(&mut s, &mut n, sign.clone(), Some(PASSWORD), f.now);
    assert!(v["diagnostic"].is_null(), "{v}");
    let signed = hex::decode(v["operation_hex"].as_str().unwrap()).unwrap();
    assert_eq!(
        signed,
        action(&f, 2, &f.owners[0], (&out(f.channel, 0), 1386), &[], 91)
    );
    fast::validate_operation(&signed, chain).unwrap();
    let current = s.head();
    drop(s);
    fs::rename(&key, root.join("retained-owner.key")).unwrap();
    let (mut s, recovered) = Session::recover(
        &state,
        &f.genesis,
        chain,
        prior,
        i,
        sign.digest().unwrap(),
        f.now,
    )
    .unwrap();
    assert_eq!(s.head(), current);
    assert_eq!(recovered["operation_hex"], v["operation_hex"]);
    let repeat = execute(&mut s, &mut n, sign, None, f.now).1;
    assert_eq!(repeat["operation_hex"], v["operation_hex"]);
    assert!(repeat["diagnostic"].is_null());
    let mut next = f.ledger.clone();
    let raw = mine(&mut next, f.miner.verifying_key().to_bytes(), vec![], f.now);
    let tip = Id(s.tip());
    execute(
        &mut s,
        &mut n,
        Action::Native {
            tip,
            block: hex::encode(raw),
        },
        None,
        f.now,
    );
    let stale = Action::OnchainSign {
        tip: Id(s.tip()),
        prepare_request: prepared,
        review,
        key_file: root.join("absent.key").to_string_lossy().into(),
        approved: true,
    };
    let stale = execute(&mut s, &mut n, stale, None, f.now).1;
    assert!(stale["diagnostic"]
        .as_str()
        .unwrap()
        .contains("changed review tip"));
    let mut refreshed = plan.clone();
    refreshed.timestamp = (next.tip().timestamp() + 600).to_string();
    let tip = Id(s.tip());
    let (refreshed_id, refreshed) = execute(
        &mut s,
        &mut n,
        Action::OnchainPrepare {
            tip,
            plan: refreshed,
        },
        None,
        f.now,
    );
    assert!(refreshed["diagnostic"].is_null(), "{refreshed}");
    let tip = Id(s.tip());
    let refreshed = execute(
        &mut s,
        &mut n,
        Action::OnchainSign {
            tip,
            prepare_request: refreshed_id,
            review: id(&refreshed, "review_digest"),
            key_file: root.join("retained-owner.key").to_string_lossy().into(),
            approved: true,
        },
        Some(PASSWORD),
        f.now,
    )
    .1;
    assert_eq!(refreshed["operation_hex"], repeat["operation_hex"]);
    drop(s);
    let path = state.join("caller.journal");
    let mut bytes = fs::read(&path).unwrap();
    // Rehash the final reply after altering its stored signed operation. A record
    // digest cannot replace the native spending signature and original review.
    let mut at = 197;
    let mut last = 0;
    while at < bytes.len() {
        last = at;
        let z = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        at += 4 + z;
    }
    let body = last + 4;
    let z = u32::from_be_bytes(bytes[body + 33..body + 37].try_into().unwrap()) as usize;
    let mut done: Value = serde_json::from_slice(&bytes[body + 37..body + 37 + z]).unwrap();
    let mut raw = hex::decode(done["authorization"].as_str().unwrap()).unwrap();
    let end = raw.len() - 1;
    raw[end] ^= 1;
    done["authorization"] = hex::encode(raw).into();
    // Preserve the declared canonical field order; parsing as Value would sort it.
    let original = std::str::from_utf8(&bytes[body + 37..body + 37 + z])
        .unwrap()
        .to_owned();
    let old = repeat["operation_hex"].as_str().unwrap();
    let new = done["authorization"].as_str().unwrap();
    let changed = original.replace(old, new);
    assert_eq!(changed.len(), z);
    bytes[body + 37..body + 37 + z].copy_from_slice(changed.as_bytes());
    use sha2::{Digest, Sha256};
    let digest: Hash = Sha256::digest(
        [
            b"RLD-FAST-SESSION-1/RECORD\0".as_slice(),
            &bytes[body..bytes.len() - 32],
        ]
        .concat(),
    )
    .into();
    let end = bytes.len();
    bytes[end - 32..].copy_from_slice(&digest);
    fs::write(&path, &bytes).unwrap();
    assert!(Session::open(&state, &f.genesis, chain, digest, f.now).is_err());
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

#[test]
fn invalid_native_terms_funding_and_maturity_never_create_a_review_or_signature() {
    let f = fixture();
    let chain = f.ledger.chain_id();
    let root = directory(chain, "bad-terms");
    let (mut s, mut n) = funded(&f, &root.join("session"));
    let good = close(&f);
    let mut cases = vec![];
    let mut bad = good.clone();
    bad.actor = Id(f.retainer.verifying_key().to_bytes());
    cases.push(bad);
    let mut bad = good.clone();
    bad.fee = "0".into();
    cases.push(bad);
    let mut bad = good.clone();
    bad.fee = "999999".into();
    cases.push(bad);
    let mut bad = good.clone();
    bad.expiry = "102".into();
    cases.push(bad);
    let mut bad = good.clone();
    bad.certificate = hex::encode([0; 252]);
    cases.push(bad);
    let mut bad = good.clone();
    bad.inputs.push(bad.inputs[0].clone());
    cases.push(bad);
    let mut bad = good.clone();
    bad.inputs = vec![hex::encode([7; 34])];
    cases.push(bad);
    let mut bad = good.clone();
    bad.channel = Id([7; 32]);
    cases.push(bad);
    let mut bad = good.clone();
    bad.kind = 4;
    bad.certificate = hex::encode([0; 252]);
    cases.push(bad);
    let immature = f
        .ledger
        .coins()
        .iter()
        .find(|(_, coin)| coin.owner == good.actor.0 && coin.maturity > 103)
        .unwrap()
        .0;
    let mut bad = good.clone();
    bad.inputs = vec![hex::encode(immature)];
    cases.push(bad);
    for plan in cases {
        let tip = Id(s.tip());
        let v = execute(
            &mut s,
            &mut n,
            Action::OnchainPrepare { tip, plan },
            None,
            f.now,
        )
        .1;
        assert!(v["diagnostic"].is_string(), "{v}");
        assert!(v["review_digest"].is_null());
        assert!(v["operation_hex"].is_null());
        assert_eq!(s.tip(), f.ledger.tip().id());
    }
    let tip = Id(s.tip());
    let v = execute(
        &mut s,
        &mut n,
        Action::OnchainPrepare {
            tip,
            plan: good.clone(),
        },
        None,
        f.now,
    )
    .1;
    assert!(v["review_digest"].is_string());
    let mut fork = f.before.clone();
    for _ in 0..2 {
        let block = mine(&mut fork, f.miner.verifying_key().to_bytes(), vec![], f.now);
        let tip = Id(s.tip());
        execute(
            &mut s,
            &mut n,
            Action::Native {
                tip,
                block: hex::encode(block),
            },
            None,
            f.now,
        );
    }
    assert_eq!(s.tip(), fork.tip().id());
    let mut orphan = good;
    orphan.timestamp = (fork.tip().timestamp() + 600).to_string();
    let tip = Id(s.tip());
    let v = execute(
        &mut s,
        &mut n,
        Action::OnchainPrepare { tip, plan: orphan },
        None,
        f.now,
    )
    .1;
    assert!(v["diagnostic"]
        .as_str()
        .unwrap()
        .contains("MISSING native action input"));
    assert!(v["review_digest"].is_null());
}

#[test]
fn native_action_process_child() {
    let Some(path) = std::env::var_os("RLD_NATIVE_ACTION_CUT") else {
        return;
    };
    let raw = fs::read(path).unwrap();
    let v: Value = serde_json::from_slice(&raw).unwrap();
    let root = Path::new(v["root"].as_str().unwrap());
    let g = hex::decode(v["genesis"].as_str().unwrap()).unwrap();
    let chain = id(&v, "chain");
    let head = id(&v, "head");
    let action: Action = serde_json::from_value(v["action"].clone()).unwrap();
    let now = v["now"].as_u64().unwrap();
    let mut s = Session::open(root, &g, chain.0, head.0, now).unwrap();
    s.execute_observed(
        id(&v, "request"),
        head.0,
        action,
        Some(PASSWORD),
        now,
        |boundary| {
            use rld_survivor_node::fast_session::Boundary;
            let label = match boundary {
                Boundary::IntentDurable => "intent",
                Boundary::ChildDurable => "child",
                Boundary::NativeActionEvaluated => "signed_memory",
                Boundary::ReplyDurable => "reply",
            };
            if label == v["cut"].as_str().unwrap() {
                write(
                    &root.parent().unwrap().join("cut-reached"),
                    label.as_bytes(),
                );
                loop {
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        },
    )
    .unwrap();
    panic!("required native action boundary not reached");
}

#[test]
fn actual_process_cuts_never_first_sign_during_recovery_or_release_reserved_inputs() {
    use std::process::{Command, Stdio};
    let deadline = Instant::now() + Duration::from_secs(180);
    for cut in ["intent", "signed_memory", "reply"] {
        let f = fixture();
        let chain = f.ledger.chain_id();
        let root = directory(chain, cut);
        let state = root.join("session");
        let (mut s, mut n) = funded(&f, &state);
        let plan = close(&f);
        let tip = Id(s.tip());
        let (prepared, v) = execute(
            &mut s,
            &mut n,
            Action::OnchainPrepare {
                tip,
                plan: plan.clone(),
            },
            None,
            f.now,
        );
        let key = root.join("key");
        write(
            &key,
            &keyfile::encrypt(&f.owners[0], chain, PASSWORD).unwrap(),
        );
        let action = Action::OnchainSign {
            tip,
            prepare_request: prepared,
            review: id(&v, "review_digest"),
            key_file: key.to_string_lossy().into(),
            approved: true,
        };
        let prior = s.head();
        let request = rid(&mut n);
        drop(s);
        let config = root.join("child.json");
        write(&config,json!({"root":state,"genesis":hex::encode(&f.genesis),"chain":Id(chain),"head":Id(prior),"action":action,"now":f.now,"request":request,"cut":cut}).to_string().as_bytes());
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "native_action_process_child", "--nocapture"])
            .env("RLD_NATIVE_ACTION_CUT", &config)
            .stdout(Stdio::from(
                fs::File::create(root.join("child.stdout.log")).unwrap(),
            ))
            .stderr(Stdio::from(
                fs::File::create(root.join("child.stderr.log")).unwrap(),
            ))
            .spawn()
            .unwrap();
        let mut guard = Process {
            child: Some(child),
            input: None,
            rx: std::sync::mpsc::channel().1,
            head: Id(prior),
            tip,
            n,
            deadline,
            root: root.clone(),
        };
        while !root.join("cut-reached").exists() {
            assert!(Instant::now() < deadline, "original180 native action cut");
            assert!(
                guard.child.as_mut().unwrap().try_wait().unwrap().is_none(),
                "child exited before boundary"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let child = guard.child.as_mut().unwrap();
        let pid = child.id();
        child.kill().unwrap();
        let status = child.wait().unwrap();
        guard.child.take();
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(status.signal(), Some(9));
        }
        write(&root.join("terminal.json"),json!({"pid":pid,"intentional_sigkill":true,"boundary":cut,"status":format!("{status:?}")}).to_string().as_bytes());
        fs::rename(&key, root.join("retained-key")).unwrap();
        let (mut s, out) = Session::recover(
            &state,
            &f.genesis,
            chain,
            prior,
            request,
            action.digest().unwrap(),
            f.now,
        )
        .unwrap();
        assert_eq!(out["key_loaded_by_recovery"], false);
        assert_eq!(out["operation_hex"].is_string(), cut == "reply");
        if cut == "reply" {
            fast::validate_operation(
                &hex::decode(out["operation_hex"].as_str().unwrap()).unwrap(),
                chain,
            )
            .unwrap();
        }
        let mut changed = plan;
        changed.nonce = Id([99; 32]);
        let tip = Id(s.tip());
        let h = s.head();
        assert!(s
            .execute(
                rid(&mut n),
                h,
                Action::OnchainPrepare { tip, plan: changed },
                None,
                f.now
            )
            .unwrap_err()
            .contains("reserved"));
        assert_eq!(s.head(), h);
    }
}

struct Process {
    child: Option<std::process::Child>,
    input: Option<std::process::ChildStdin>,
    rx: std::sync::mpsc::Receiver<String>,
    head: Id,
    tip: Id,
    n: u64,
    deadline: Instant,
    root: PathBuf,
}
impl Process {
    fn start(root: &Path, f: &Fixture, deadline: Instant) -> Self {
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        let child = Command::new(env!("CARGO_BIN_EXE_rld-fast-payment-session"))
            .args([
                "create",
                root.join("session").to_str().unwrap(),
                root.join("genesis").to_str().unwrap(),
                &hex::encode(f.ledger.chain_id()),
            ])
            .output()
            .unwrap();
        assert!(child.status.success());
        let v: Value = serde_json::from_slice(&child.stdout).unwrap();
        let head = id(&v, "session_head");
        let mut child = Command::new(env!("CARGO_BIN_EXE_rld-fast-payment-session"))
            .args([
                "serve",
                root.join("session").to_str().unwrap(),
                root.join("genesis").to_str().unwrap(),
                &hex::encode(f.ledger.chain_id()),
                &hex::encode(head.0),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(fs::File::create(root.join("stderr.log")).unwrap())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = child.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let log = root.join("stdout.log");
        std::thread::spawn(move || {
            let mut log = fs::File::create(log).unwrap();
            for line in BufReader::new(output).lines() {
                let line = line.unwrap();
                writeln!(log, "{line}").unwrap();
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut p = Self {
            child: Some(child),
            input: Some(input),
            rx,
            head,
            tip: Id(f.ledger.chain_id()),
            n: 0,
            deadline,
            root: root.into(),
        };
        let ready = p.receive();
        p.update(&ready);
        p
    }
    fn receive(&self) -> Value {
        serde_json::from_str(
            &self
                .rx
                .recv_timeout(self.deadline.saturating_duration_since(Instant::now()))
                .expect("original180 process output"),
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
    fn send(&mut self, mut v: Value) -> Value {
        assert!(
            Instant::now() < self.deadline,
            "original180 process request"
        );
        v["head"] = serde_json::to_value(self.head).unwrap();
        writeln!(self.input.as_mut().unwrap(), "{v}").unwrap();
        self.input.as_mut().unwrap().flush().unwrap();
        let out = self.receive();
        self.update(&out);
        out
    }
    fn ok(&mut self, v: Value) -> Value {
        let out = self.send(v);
        assert!(out["diagnostic"].is_null(), "{out}");
        out
    }
    fn execute(&mut self, a: Action, password: Option<&[u8]>) -> (Id, Value) {
        let i = rid(&mut self.n);
        let v=self.ok(json!({"command":"execute","request_id":i,"action":a,"password":password.map(|p|std::str::from_utf8(p).unwrap())}));
        (i, v)
    }
    fn mine(&mut self, f: &mut Fixture, ops: Vec<Vec<u8>>) {
        let payload = ops.iter().map(hex::encode).collect::<Vec<_>>();
        let raw = loop {
            let v=self.ok(json!({"command":"mining_candidate","miner":Id(f.owners[0].verifying_key().to_bytes()),"operations":payload,"timestamp":(f.ledger.tip().timestamp()+600).to_string(),"attempts":4096}));
            if let Some(raw) = v["block_hex"].as_str() {
                break hex::decode(raw).unwrap();
            }
        };
        self.execute(
            Action::Native {
                tip: self.tip,
                block: hex::encode(&raw),
            },
            None,
        );
        f.ledger.execute(&raw, f.now).unwrap();
        assert_eq!(self.tip.0, f.ledger.tip().id());
    }
    fn authorize(&mut self, plan: OnchainRequest, key: &Path) -> Vec<u8> {
        let (i, v) = self.execute(
            Action::OnchainPrepare {
                tip: self.tip,
                plan,
            },
            None,
        );
        let (_, v) = self.execute(
            Action::OnchainSign {
                tip: self.tip,
                prepare_request: i,
                review: id(&v, "review_digest"),
                key_file: key.to_string_lossy().into(),
                approved: true,
            },
            Some(PASSWORD),
        );
        hex::decode(v["operation_hex"].as_str().unwrap()).unwrap()
    }
    fn finish(&mut self) {
        self.input.take();
        let c = self.child.as_mut().unwrap();
        let pid = c.id();
        let status = loop {
            if let Some(s) = c.try_wait().unwrap() {
                break s;
            }
            assert!(
                Instant::now() < self.deadline,
                "original180 process termination"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(status.success());
        write(
            &self.root.join("terminal.json"),
            json!({"pid":pid,"success":true,"exit_code":status.code(),"forced_stop":false})
                .to_string()
                .as_bytes(),
        );
        self.child.take();
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if let Some(c) = self.child.as_mut() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

#[test]
fn actual_node_authorizes_claims_and_mines_settlement_then_exact_mature_miner_spend() {
    let deadline = Instant::now() + Duration::from_secs(180);
    let mut f = aged_fixture(2_000_000);
    let chain = f.ledger.chain_id();
    let root = directory(chain, "settlement-process");
    write(&root.join("genesis"), &f.genesis);
    let mut p = Process::start(&root, &f, deadline);
    let mut at = 0;
    while at < f.history.len() {
        let z = u32::from_be_bytes(f.history[at..at + 4].try_into().unwrap()) as usize;
        at += 4;
        p.execute(
            Action::Native {
                tip: p.tip,
                block: hex::encode(&f.history[at..at + z]),
            },
            None,
        );
        at += z;
    }
    let keys = [&f.owners[0], &f.owners[1], &f.retainer];
    let mut paths = vec![];
    for (i, key) in keys.iter().enumerate() {
        let path = root.join(format!("key-{i}"));
        write(&path, &keyfile::encrypt(key, chain, PASSWORD).unwrap());
        paths.push(path);
    }
    let a = f.owners[0].verifying_key().to_bytes();
    let b = f.owners[1].verifying_key().to_bytes();
    let d = f.retainer.verifying_key().to_bytes();
    let m = f.miner.verifying_key().to_bytes();
    let (input, coin) = f
        .ledger
        .coins()
        .iter()
        .find(|(_, c)| c.owner == a && c.maturity <= 103 && c.amount > 10000)
        .unwrap();
    let (fund, fid) = ordinary(
        chain,
        &f.owners[0],
        input,
        &[(d, 100), (a, coin.amount - 101)],
    );
    p.mine(&mut f, vec![fund]);
    let origin = f.ledger.funding_origin(f.channel).unwrap();
    let first =
        rld_survivor_node::fast_payment::Payment::verify(&origin, &payment(&f, None, 0, 70, 94))
            .unwrap();
    let second = rld_survivor_node::fast_payment::Payment::verify(
        &origin,
        &payment(&f, Some(&first), 1, 25, 95),
    )
    .unwrap();
    let proof = hex::encode(second.after_certificate());
    let mut plan = close(&f);
    let op = p.authorize(plan.clone(), &paths[0]);
    let close_id = fast::operation_id(&op);
    p.mine(&mut f, vec![op]);
    let close_height = f.ledger.tip().height();
    plan.kind = 4;
    plan.actor = Id(d);
    plan.inputs = vec![hex::encode(out(fid, 0))];
    plan.certificate = proof.clone();
    plan.nonce = Id([96; 32]);
    plan.timestamp = (f.ledger.tip().timestamp() + 600).to_string();
    let op = p.authorize(plan.clone(), &paths[2]);
    p.mine(&mut f, vec![op]);
    plan.kind = 3;
    plan.actor = Id(b);
    plan.inputs = vec![hex::encode(out(f.channel, 1))];
    plan.nonce = Id([97; 32]);
    plan.timestamp = (f.ledger.tip().timestamp() + 600).to_string();
    let op = p.authorize(plan.clone(), &paths[1]);
    p.mine(&mut f, vec![op]);
    plan.kind = 5;
    plan.actor = Id(a);
    plan.inputs = vec![hex::encode(out(close_id, 0))];
    plan.certificate.clear();
    plan.nonce = Id([98; 32]);
    plan.timestamp = (f.ledger.tip().timestamp() + 600).to_string();
    let i = rid(&mut p.n);
    let refused=p.send(json!({"command":"execute","request_id":i,"action":Action::OnchainPrepare{tip:p.tip,plan:plan.clone()}}));
    assert!(refused["diagnostic"]
        .as_str()
        .unwrap()
        .contains("challenge window"));
    while f.ledger.tip().height() < close_height + 2016 {
        p.mine(&mut f, vec![]);
    }
    plan.timestamp = (f.ledger.tip().timestamp() + 600).to_string();
    let op = p.authorize(plan, &paths[0]);
    let settlement = fast::operation_id(&op);
    p.mine(&mut f, vec![op]);
    let height = f.ledger.tip().height();
    assert_eq!(f.ledger.coins()[&out(settlement, 1)].amount, 555);
    assert_eq!(f.ledger.coins()[&out(settlement, 2)].amount, 445);
    let fee = &f.ledger.coins()[&out(settlement, 5)];
    assert_eq!((fee.owner, fee.amount, fee.maturity), (m, 5, height + 100));
    let (spend, sid) = ordinary(chain, &f.miner, &out(settlement, 5), &[(a, 4)]);
    let refused=p.send(json!({"command":"mining_candidate","miner":Id(a),"operations":[hex::encode(&spend)],"timestamp":(f.ledger.tip().timestamp()+600).to_string(),"attempts":4096}));
    assert!(refused["diagnostic"].is_string());
    while f.ledger.tip().height() < height + 99 {
        p.mine(&mut f, vec![]);
    }
    p.mine(&mut f, vec![spend]);
    assert_eq!(f.ledger.coins()[&out(sid, 0)].amount, 4);
    assert_eq!(
        f.ledger.coins().values().map(|c| c.amount).sum::<u128>(),
        f.ledger.issued()
    );
    let head = p.head;
    p.finish();
    write(&root.join("hot-phase.json"),json!({"height":f.ledger.tip().height().to_string(),"remaining_ms":deadline.saturating_duration_since(Instant::now()).as_millis(),"logical_timestamps_only":true}).to_string().as_bytes());
    assert!(
        Instant::now() < deadline,
        "original180 before cold verification"
    );
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let cold = Instant::now();
    let mut s = Session::open(
        &root.join("session"),
        &f.genesis,
        chain,
        head.0,
        current_time,
    )
    .unwrap();
    assert_eq!(s.tip(), f.ledger.tip().id());
    assert_eq!(
        s.status(head.0, current_time).unwrap()["height"],
        f.ledger.tip().height().to_string()
    );
    write(&root.join("cold-phase.json"),json!({"cold_ms":cold.elapsed().as_millis(),"remaining_ms":deadline.saturating_duration_since(Instant::now()).as_millis(),"verified":true}).to_string().as_bytes());
    assert!(
        Instant::now() < deadline,
        "original180 complete cold verification"
    );
}
