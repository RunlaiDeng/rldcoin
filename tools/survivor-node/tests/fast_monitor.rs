//! PUBLIC NO-VALUE fixture keys only. Old logical native timestamps exercise
//! fixed rules, not physical time, independent custody or composed performance.
#[allow(dead_code)]
#[path = "support/fast_funding.rs"]
mod support;
use rld_survivor_node::{
    fast_payment::Payment,
    fast_session::{
        Action, BackgroundMiner, FeeMonitor, FeePolicy, Id, MonitorConfig, OnchainRequest, Session,
    },
    fast_store::{Limits, Store},
    kernel::{fast, Hash},
    keyfile,
};
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const PASSWORD: &[u8] = b"public no-value monitor fee wallet";
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn id(v: &Value, k: &str) -> Id {
    serde_json::from_value(v[k].clone()).unwrap()
}
fn write(p: &Path, raw: &[u8]) {
    let mut o = fs::OpenOptions::new();
    o.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(p).unwrap();
    f.write_all(raw).unwrap();
    f.sync_all().unwrap();
}
fn directory(chain: Hash, label: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "rld-fast-monitor-{}-{}-{label}",
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
fn execute(
    s: &mut Session,
    n: &mut u64,
    a: Action,
    password: Option<&[u8]>,
    at: u64,
) -> (Id, Value) {
    *n += 1;
    let mut raw = [0; 32];
    raw[..8].copy_from_slice(&n.to_be_bytes());
    let i = Id(raw);
    let v = s.execute(i, s.head(), a, password, at).unwrap();
    assert!(v["diagnostic"].is_null(), "{v}");
    (i, v)
}
struct Test {
    f: support::Fixture,
    root: PathBuf,
    node: PathBuf,
    head: PathBuf,
    key: PathBuf,
    s: Session,
    n: u64,
    policy: Id,
    terms: FeePolicy,
    proof: Vec<u8>,
    deadline: Instant,
}
impl Test {
    fn new(label: &str) -> Self {
        Self::profile(label, false)
    }
    fn logged(label: &str) -> Self {
        Self::profile(label, true)
    }
    fn profile(label: &str, logged: bool) -> Self {
        let deadline = Instant::now() + Duration::from_secs(180);
        let mut f = support::aged_fixture(2_000_000);
        let chain = f.ledger.chain_id();
        let root = directory(chain, label);
        let node = root.join("node");
        let head = root.join("head");
        let historical = f.ledger.tip().timestamp();
        let mut s = if logged {
            Session::create_log_controlled(&node, &f.genesis, chain, &head, historical).unwrap()
        } else {
            Session::create_controlled(&node, &f.genesis, chain, &head, historical).unwrap()
        };
        let mut n = 0;
        let mut at = 0;
        while at < f.history.len() {
            let size = u32::from_be_bytes(f.history[at..at + 4].try_into().unwrap()) as usize;
            at += 4;
            let a = Action::Native {
                tip: Id(s.tip()),
                block: hex::encode(&f.history[at..at + size]),
            };
            at += size;
            execute(&mut s, &mut n, a, None, historical);
        }
        let key = root.join("fee.key");
        write(
            &key,
            &keyfile::encrypt(&f.retainer, chain, PASSWORD).unwrap(),
        );
        write(&root.join("genesis"), &f.genesis);
        let (_, reg) = execute(
            &mut s,
            &mut n,
            Action::RetainerCreate {
                tip: Id(f.ledger.tip().id()),
                channel: Id(f.channel),
                delegation: hex::encode(support::delegation(&f)),
            },
            None,
            historical,
        );
        let actor = id(&reg, "actor");
        let origin = f.ledger.funding_origin(f.channel).unwrap();
        let first = Payment::verify(&origin, &support::payment(&f, None, 0, 70, 171)).unwrap();
        let (review, v) = execute(
            &mut s,
            &mut n,
            Action::RetainerPrepare {
                tip: Id(f.ledger.tip().id()),
                actor,
                receipt: hex::encode(first.bytes()),
            },
            None,
            historical,
        );
        execute(
            &mut s,
            &mut n,
            Action::RetainerSign {
                tip: Id(f.ledger.tip().id()),
                actor,
                receipt: Id(first.id()),
                review_request: review,
                review: id(&v, "review_digest"),
                key_file: key.to_string_lossy().into(),
                approved: true,
            },
            Some(PASSWORD),
            historical,
        );
        let second =
            Payment::verify(&origin, &support::payment(&f, Some(&first), 1, 25, 172)).unwrap();
        execute(
            &mut s,
            &mut n,
            Action::RetainerPrepare {
                tip: Id(f.ledger.tip().id()),
                actor,
                receipt: hex::encode(second.bytes()),
            },
            None,
            historical,
        );
        let proof = second.after_certificate().to_vec();
        // Ordinary C04 funds a distinct fee wallet; no channel owner's key file
        // exists in the service directory or enters the runtime.
        let input = support::out(f.channel, 0);
        let change = f.ledger.coins()[&input].amount - 101;
        let (fund, tx) = support::ordinary(
            chain,
            &f.owners[0],
            &input,
            &[
                (f.retainer.verifying_key().to_bytes(), 100),
                (f.owners[0].verifying_key().to_bytes(), change),
            ],
        );
        let close_input = support::out(f.channel, 1);
        let close_change = f.ledger.coins()[&close_input].amount - 1;
        let close = support::action(&f, 2, &f.owners[1], (&close_input, close_change), &[], 173);
        let block = support::mine_until(
            &mut f.ledger,
            f.miner.verifying_key().to_bytes(),
            vec![fund, close],
            now(),
            deadline,
        );
        let a = Action::Native {
            tip: Id(s.tip()),
            block: hex::encode(block),
        };
        execute(&mut s, &mut n, a, None, now());
        let terms = FeePolicy {
            chain: Id(chain),
            caller: Id(s.caller_binding()),
            owner: Id(f.retainer.verifying_key().to_bytes()),
            channels: vec![Id(f.channel)],
            inputs: vec![hex::encode(support::out(tx, 0))],
            max_fee: "1".into(),
            total_fee: "8".into(),
            max_operations: 8,
            expiry_height: (f.ledger.tip().height() + 5000).to_string(),
            expiry_time: (now() + 86400).to_string(),
            nonce: Id([174; 32]),
        };
        let (policy, _) = execute(
            &mut s,
            &mut n,
            Action::FeePolicyApprove {
                tip: Id(f.ledger.tip().id()),
                terms: terms.clone(),
                key_file: key.to_string_lossy().into(),
                approved: true,
            },
            Some(PASSWORD),
            now(),
        );
        assert!(Instant::now() < deadline);
        Self {
            f,
            root,
            node,
            head,
            key,
            s,
            n,
            policy,
            terms,
            proof,
            deadline,
        }
    }
    fn config(&self) -> MonitorConfig {
        MonitorConfig {
            policy_request: self.policy,
            key_file: self.key.to_string_lossy().into(),
            operation_fee: "1".into(),
        }
    }
}
#[test]
fn pending_joint_evidence_resumes_exact_preparation_and_keyless_retained_claim() {
    let mut t = Test::new("resume");
    let at = t.f.ledger.tip().timestamp() + 600;
    let p = OnchainRequest {
        kind: 3,
        channel: Id(t.f.channel),
        actor: t.terms.owner,
        inputs: t.terms.inputs.clone(),
        fee: "1".into(),
        expiry: t.terms.expiry_height.clone(),
        nonce: Id([175; 32]),
        certificate: hex::encode(&t.proof),
        timestamp: at.to_string(),
    };
    let a = Action::FeePolicyPrepare {
        tip: Id(t.s.tip()),
        policy_request: t.policy,
        plan: p,
    };
    execute(&mut t.s, &mut t.n, a, None, now());
    let cfg = t.config();
    let head = t.s.head();
    let mut m = FeeMonitor::start(&mut t.s, head, cfg.clone(), Some(PASSWORD), now()).unwrap();
    let observed = now();
    m.tick(&mut t.s, observed).unwrap();
    let v = m.status();
    assert_eq!(v["last_observation"]["protected_certificates"], 2);
    assert_eq!(
        v["last_observation"]["phase"],
        "SIGNED_WAITING_NATIVE_INCLUSION"
    );
    let op = id(&v["last_observation"], "operation");
    let raw = t.s.pool_operation(t.s.head(), op, now()).unwrap();
    let signed = fast::planning::signed_action(&raw, t.f.ledger.chain_id()).unwrap();
    assert_eq!(signed.kind, 3);
    assert_eq!(signed.certificate, t.proof);
    assert_eq!(signed.nonce, [175; 32]);
    assert_eq!(signed.actor, t.f.retainer.verifying_key().to_bytes());
    let budget = t.s.fee_policy_status(t.s.head(), t.policy, now()).unwrap();
    assert_eq!(budget["signed_operations"], 1);
    fs::rename(&t.key, t.root.join("unavailable.key")).unwrap();
    drop(m);
    let head = t.s.head();
    let mut locked = FeeMonitor::start(&mut t.s, head, cfg, None, now()).unwrap();
    locked.tick(&mut t.s, now()).unwrap();
    assert_eq!(locked.status()["fee_key_unlocked"], false);
    assert_eq!(
        t.s.fee_policy_status(t.s.head(), t.policy, now()).unwrap()["signed_operations"],
        1
    );
    let mut miner = BackgroundMiner::start(
        &mut t.s,
        head,
        Id(t.f.miner.verifying_key().to_bytes()),
        now(),
    )
    .unwrap();
    for _ in 0..64 {
        miner.tick(&mut t.s, now()).unwrap();
        if t.s.tip() != t.f.ledger.tip().id() {
            break;
        }
        assert!(Instant::now() < t.deadline);
    }
    locked.tick(&mut t.s, now()).unwrap();
    assert_eq!(
        locked.status()["last_observation"]["phase"],
        "PROTECTED_WAITING_WINDOW"
    );
    let chain = t.f.ledger.chain_id();
    drop(locked);
    drop(miner);
    drop(t.s);
    let mut s = Session::open_controlled(&t.node, &t.f.genesis, chain, &t.head, now()).unwrap();
    assert_eq!(
        s.fee_policy_status(s.head(), t.policy, now()).unwrap()["signed_fee_liability"],
        "1"
    );
    // The original pending full payment remains pending; no automatic retainer
    // acknowledgment is synthesized by evidence protection.
    let actors = fs::read_dir(t.node.join("actors"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(actors.len(), 1);
    let path = actors[0].path();
    let mut corrupt = fs::read(&path).unwrap();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    fs::write(&path, corrupt).unwrap();
    let cfg = MonitorConfig {
        policy_request: t.policy,
        key_file: "missing".into(),
        operation_fee: "1".into(),
    };
    let h = s.head();
    assert!(FeeMonitor::start(&mut s, h, cfg, None, now()).is_err());
    assert!(Instant::now() < t.deadline);
}
#[test]
fn activation_refuses_wrong_fee_key_fee_scope_and_unsigned_policy_without_loading_missing_key() {
    let mut t = Test::new("activation");
    let h = t.s.head();
    let mut c = t.config();
    c.key_file = "missing".into();
    c.operation_fee = "2".into();
    assert!(
        FeeMonitor::start(&mut t.s, h, c.clone(), Some(PASSWORD), now())
            .err()
            .unwrap()
            .contains("operation fee")
    );
    c.operation_fee = "1".into();
    c.policy_request = Id([199; 32]);
    assert!(FeeMonitor::start(&mut t.s, h, c, Some(PASSWORD), now())
        .err()
        .unwrap()
        .contains("consent"));
    let wrong = t.root.join("wrong.key");
    write(
        &wrong,
        &keyfile::encrypt(&t.f.owners[0], t.f.ledger.chain_id(), PASSWORD).unwrap(),
    );
    let mut c = t.config();
    c.key_file = wrong.to_string_lossy().into();
    assert!(FeeMonitor::start(&mut t.s, h, c, Some(PASSWORD), now())
        .err()
        .unwrap()
        .contains("fee-wallet key"));
    let cfg = t.config();
    let mut m = FeeMonitor::start(&mut t.s, h, cfg, None, now()).unwrap();
    let observed = now();
    m.tick(&mut t.s, observed).unwrap();
    assert_eq!(m.status()["last_observation"]["phase"], "LOCKED");
    assert_eq!(t.s.head(), h);
    assert!(m.tick(&mut t.s, observed - 1).is_err());
    assert_eq!(m.status()["observation_current"], false);
    assert_eq!(t.s.head(), h);
    let cfg = t.config();
    let mut unlocked = FeeMonitor::start(&mut t.s, h, cfg.clone(), Some(PASSWORD), now()).unwrap();
    let expiry = t.terms.expiry_time.parse::<u64>().unwrap() + 1;
    assert!(unlocked
        .tick(&mut t.s, expiry)
        .unwrap_err()
        .contains("EXPIRED"));
    assert_eq!(unlocked.status()["fee_key_unlocked"], false);
    assert_eq!(t.s.head(), h);
    assert!(
        FeeMonitor::start(&mut t.s, h, cfg.clone(), Some(PASSWORD), expiry)
            .err()
            .unwrap()
            .contains("EXPIRED")
    );
    assert!(FeeMonitor::start(&mut t.s, h, cfg, None, expiry).is_ok());
    let path = fs::read_dir(t.node.join("actors"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let retained = fs::read(&path).unwrap();
    let replacement = t.root.join("replacement.journal");
    write(&replacement, &retained);
    fs::rename(replacement, &path).unwrap();
    let cfg = t.config();
    assert!(FeeMonitor::start(&mut t.s, h, cfg, None, expiry)
        .err()
        .unwrap()
        .contains("replaced file"));
    assert!(Instant::now() < t.deadline);
}

#[test]
fn equal_sequence_native_principal_conflict_is_not_reported_as_protected() {
    let mut t = Test::new("native-principal-conflict");
    let origin = t.f.ledger.funding_origin(t.f.channel).unwrap();
    let first = Payment::verify(&origin, &support::payment(&t.f, None, 0, 71, 181)).unwrap();
    let second =
        Payment::verify(&origin, &support::payment(&t.f, Some(&first), 1, 25, 182)).unwrap();
    let input = hex::decode(&t.terms.inputs[0]).unwrap();
    let op = support::action(
        &t.f,
        3,
        &t.f.retainer,
        (&input, 99),
        second.after_certificate(),
        183,
    );
    let block = support::mine_until(
        &mut t.f.ledger,
        t.f.miner.verifying_key().to_bytes(),
        vec![op],
        now(),
        t.deadline,
    );
    let a = Action::Native {
        tip: Id(t.s.tip()),
        block: hex::encode(block),
    };
    execute(&mut t.s, &mut t.n, a, None, now());
    let h = t.s.head();
    let cfg = t.config();
    let mut monitor = FeeMonitor::start(&mut t.s, h, cfg, None, now()).unwrap();
    assert!(monitor
        .tick(&mut t.s, now())
        .unwrap_err()
        .contains("native principal at same sequence"));
    assert_eq!(t.s.head(), h);
    assert!(Instant::now() < t.deadline);
}
struct Cli {
    child: Child,
    input: Option<ChildStdin>,
    output: mpsc::Receiver<Value>,
    deadline: Instant,
}
impl Cli {
    fn open(root: &Path, node: &Path, head: &Path, chain: Hash, deadline: Instant) -> Self {
        Self::launch(root, node, head, chain, deadline, None)
    }
    fn sync(
        root: &Path,
        node: &Path,
        head: &Path,
        chain: Hash,
        deadline: Instant,
        peer: (&Path, &Path),
    ) -> Self {
        Self::launch(root, node, head, chain, deadline, Some(peer))
    }
    fn launch(
        root: &Path,
        node: &Path,
        head: &Path,
        chain: Hash,
        deadline: Instant,
        peer: Option<(&Path, &Path)>,
    ) -> Self {
        let mut token = [0; 8];
        getrandom::getrandom(&mut token).unwrap();
        let err = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(root.join(format!("stderr-{}", hex::encode(token))))
            .unwrap();
        let logged = fs::read(head).unwrap().starts_with(b"RLDFCLG1");
        let mut args = vec![
            if logged {
                "serve-log-control".to_string()
            } else {
                "serve-control".to_string()
            },
            node.to_str().unwrap().to_string(),
            root.join("genesis").to_str().unwrap().to_string(),
            hex::encode(chain),
            head.to_str().unwrap().to_string(),
        ];
        if let Some((r, h)) = peer {
            args.extend([
                "--peer-root".to_string(),
                r.to_str().unwrap().to_string(),
                "--peer-head-file".to_string(),
                h.to_str().unwrap().to_string(),
                "--auto-sync".to_string(),
            ]);
        }
        let mut child = Command::new(env!("CARGO_BIN_EXE_rld-fast-payment-session"))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(err)
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
        let mut c = Self {
            child,
            input,
            output: rx,
            deadline,
        };
        let ready = c.read();
        assert_eq!(ready["local_runtime"]["fee_monitor"], Value::Null);
        assert_eq!(ready["local_runtime"]["ordinary_miner"], Value::Null);
        c
    }
    fn read(&mut self) -> Value {
        self.output
            .recv_timeout(self.deadline.saturating_duration_since(Instant::now()))
            .unwrap()
    }
    fn command(&mut self, v: Value) -> Value {
        let v = self.raw_command(v);
        assert!(v["diagnostic"].is_null(), "{v}");
        v
    }
    fn raw_command(&mut self, v: Value) -> Value {
        let f = self.input.as_mut().unwrap();
        writeln!(f, "{v}").unwrap();
        f.flush().unwrap();
        self.read()
    }
    fn stop(mut self) {
        drop(self.input.take());
        loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                assert!(s.success());
                break;
            }
            assert!(Instant::now() < self.deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Cli {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
#[test]
fn idle_cli_protects_pending_payment_settles_and_observes_native_miner_maturity() {
    let t = Test::new("idle-cycle");
    let cfg = t.config();
    let chain = t.f.ledger.chain_id();
    let head = t.s.head();
    drop(t.s);
    let mut c = Cli::open(&t.root, &t.node, &t.head, chain, t.deadline);
    c.command(json!({"command":"monitor_start","head":Id(head),"config":cfg,"password":std::str::from_utf8(PASSWORD).unwrap()}));
    let ready = c.command(json!({"command":"runtime_status"}));
    c.command(json!({"command":"mining_start","head":ready["session_head"],"reward":Id(t.f.miner.verifying_key().to_bytes())}));
    let mut included = false;
    let row = loop {
        let v = c.command(json!({"command":"runtime_status"}));
        let m = &v["local_runtime"]["fee_monitor"];
        assert!(m["diagnostic"].is_null(), "{v}");
        assert!(
            v["local_runtime"]["ordinary_miner"]["diagnostic"].is_null(),
            "{v}"
        );
        let row = &m["last_observation"];
        if row["phase"] == "PROTECTED_WAITING_WINDOW" {
            included = true;
            assert_eq!(row["principal_sequence"], "2");
            assert_eq!(row["fee_slots"], json!(["1", "1"]));
        }
        if row["phase"] == "SETTLED" && row["eligible_for_next_block"] == true {
            break row.clone();
        }
        assert!(Instant::now() < t.deadline, "{v}");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(included);
    assert_eq!(row["miner_fee"], "5");
    c.command(json!({"command":"mining_stop"}));
    let stopped = c.command(json!({"command":"monitor_stop"}));
    c.stop();
    let mut restarted = Cli::open(&t.root, &t.node, &t.head, chain, t.deadline);
    let current = restarted.command(json!({"command":"runtime_status"}));
    assert_eq!(current["session_head"], stopped["session_head"]);
    assert_eq!(current["local_runtime"]["fee_monitor"], Value::Null);
    assert_eq!(current["local_runtime"]["ordinary_miner"], Value::Null);
    restarted.stop();
    let mut s = Session::open_controlled(&t.node, &t.f.genesis, chain, &t.head, now()).unwrap();
    let budget = s.fee_policy_status(s.head(), t.policy, now()).unwrap();
    assert_eq!(budget["signed_operations"], 2);
    assert_eq!(budget["signed_fee_liability"], "2");
    let native_head = s.native_head();
    drop(s);
    let store = Store::open(
        &t.node.join("native.journal"),
        &t.f.genesis,
        chain,
        native_head,
        now(),
        Limits::default(),
    )
    .unwrap();
    let mut ledger = store.ledger().clone();
    drop(store);
    assert!(ledger.funding_origin(t.f.channel).is_err());
    let op = id(&row, "operation");
    let output = support::out(op.0, 5);
    for (i, amount) in [555u128, 445].into_iter().enumerate() {
        let principal = &ledger.coins()[&support::out(op.0, 1 + i as u16)];
        assert_eq!(principal.owner, t.f.owners[i].verifying_key().to_bytes());
        assert_eq!(principal.amount, amount);
    }
    let coin = &ledger.coins()[&output];
    assert_eq!(coin.owner, t.f.miner.verifying_key().to_bytes());
    assert_eq!(coin.amount, 5);
    assert!(coin.maturity <= ledger.tip().height() + 1);
    let (spend, _) = support::ordinary(
        chain,
        &t.f.miner,
        &output,
        &[(t.f.owners[0].verifying_key().to_bytes(), 4)],
    );
    support::mine_until(
        &mut ledger,
        t.f.miner.verifying_key().to_bytes(),
        vec![spend],
        now(),
        t.deadline,
    );
    assert!(!ledger.coins().contains_key(&output));
    assert!(Instant::now() < t.deadline);
}
#[test]
fn idle_cli_ordinary_miner_needs_no_actor_policy_balance_or_spending_key() {
    let deadline = Instant::now() + Duration::from_secs(180);
    let v: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/native-fast-escrow-v1-vectors.json"
    ))
    .unwrap();
    let mut genesis = hex::decode(v["genesis_hex"].as_str().unwrap()).unwrap();
    getrandom::getrandom(&mut genesis[13..45]).unwrap();
    genesis[45..53].copy_from_slice(&(now() - 1000).to_be_bytes());
    let chain = fast::genesis_id(&genesis);
    let root = directory(chain, "mining-only");
    write(&root.join("genesis"), &genesis);
    let node = root.join("node");
    let head = root.join("head");
    let s = Session::create_controlled(&node, &genesis, chain, &head, now()).unwrap();
    let h = s.head();
    drop(s);
    let key = ed25519_dalek::SigningKey::from_bytes(&[177; 32]);
    let mut c = Cli::open(&root, &node, &head, chain, deadline);
    c.command(
        json!({"command":"mining_start","head":Id(h),"reward":Id(key.verifying_key().to_bytes())}),
    );
    loop {
        let v = c.command(json!({"command":"runtime_status"}));
        assert_eq!(v["actors"], json!([]));
        assert_eq!(v["local_runtime"]["fee_monitor"], Value::Null);
        if v["height"].as_str().unwrap().parse::<u128>().unwrap() >= 2 {
            break;
        }
        assert!(Instant::now() < deadline);
    }
    c.command(json!({"command":"mining_stop"}));
    c.stop();
}

#[test]
fn missed_native_window_refuses_automatic_settlement_of_unprotected_evidence() {
    let mut t = Test::new("missed-window");
    let head = t.s.head();
    let mut miner = BackgroundMiner::start(
        &mut t.s,
        head,
        Id(t.f.miner.verifying_key().to_bytes()),
        now(),
    )
    .unwrap();
    let required = t.f.ledger.tip().height() + 2017;
    loop {
        miner.tick(&mut t.s, now()).unwrap();
        let status = t.s.status(t.s.head(), now()).unwrap();
        if status["height"].as_str().unwrap().parse::<u128>().unwrap() >= required {
            break;
        }
        assert!(Instant::now() < t.deadline);
    }
    let head = t.s.head();
    let cfg = t.config();
    let mut m = FeeMonitor::start(&mut t.s, head, cfg, Some(PASSWORD), now()).unwrap();
    m.tick(&mut t.s, now()).unwrap();
    assert_eq!(
        m.status()["last_observation"]["phase"],
        "MISSED_PROTECTION_WINDOW"
    );
    assert_eq!(t.s.head(), head);
    assert_eq!(
        t.s.fee_policy_status(head, t.policy, now()).unwrap()["signed_operations"],
        0
    );
    assert!(Instant::now() < t.deadline);
}

#[test]
fn bounded_monitor_and_miner_observation_costs() {
    let mut t = Test::new("cost-observation");
    let limit = Instant::now() + Duration::from_secs(60);
    let cfg = t.config();
    let head = t.s.head();
    let mut monitor = FeeMonitor::start(&mut t.s, head, cfg, Some(PASSWORD), now()).unwrap();
    let mut monitoring = Duration::ZERO;
    let mut mining = Duration::ZERO;
    let mut admission = Duration::ZERO;
    for _ in 0..32 {
        let at = Instant::now();
        monitor.tick(&mut t.s, now()).unwrap();
        monitoring += at.elapsed();
        let at = Instant::now();
        let mut v;
        loop {
            v =
                t.s.mine_pool(
                    t.s.head(),
                    rld_survivor_node::fast_session::PoolMiningRequest {
                        miner: Id(t.f.miner.verifying_key().to_bytes()),
                        timestamp: (t.f.ledger.tip().timestamp() + 600).to_string(),
                        attempts: 4096,
                        scan_limit: 128,
                        refresh: false,
                    },
                    now(),
                )
                .unwrap();
            if !v["candidate"].is_null() {
                break;
            }
            assert!(Instant::now() < limit);
        }
        mining += at.elapsed();
        let at = Instant::now();
        let candidate = id(&v, "candidate");
        let mut raw = [0; 32];
        getrandom::getrandom(&mut raw).unwrap();
        t.s.admit_candidate(t.s.head(), Id(raw), candidate, now())
            .unwrap();
        let block = hex::decode(v["block_hex"].as_str().unwrap()).unwrap();
        t.f.ledger.execute(&block, now()).unwrap();
        admission += at.elapsed();
        assert!(Instant::now() < limit);
    }
    eprintln!(
        "bounded32 monitoring_seconds={} mining_seconds={} admission_seconds={}",
        monitoring.as_secs_f64(),
        mining.as_secs_f64(),
        admission.as_secs_f64()
    );
    assert_eq!(
        monitor.status()["last_observation"]["phase"],
        "PROTECTED_WAITING_WINDOW"
    );
}

fn synchronized_peer_pair(root: &Path, chain: Hash) -> [(PathBuf, PathBuf); 2] {
    use rld_survivor_node::fast_peer::{self, Config, PeerPin};
    use std::net::TcpListener;
    let roots = [root.join("transport-a"), root.join("transport-b")];
    let info = roots
        .each_ref()
        .map(|p| fast_peer::provision(p, chain).unwrap());
    let endpoints = [
        TcpListener::bind("127.0.0.1:0").unwrap(),
        TcpListener::bind("127.0.0.1:0").unwrap(),
    ];
    let heads = [root.join("transport-a.head"), root.join("transport-b.head")];
    for i in 0..2 {
        let j = 1 - i;
        let config = Config {
            chain: Id(chain),
            identity: id(&info[i], "identity"),
            listen: endpoints[i].local_addr().unwrap(),
            peers: vec![PeerPin {
                key: id(&info[j], "identity"),
                endpoint: endpoints[j].local_addr().unwrap(),
                certificate_sha256: id(&info[j], "certificate_sha256"),
            }],
        };
        fast_peer::bind_controlled(
            &roots[i],
            &serde_json::to_vec(&config).unwrap(),
            &heads[i],
            now(),
        )
        .unwrap();
    }
    [
        (roots[0].clone(), heads[0].clone()),
        (roots[1].clone(), heads[1].clone()),
    ]
}
#[test]
fn synchronized_idle_peers_bootstrap_claim_settle_and_mature_without_manual_carriage() {
    let t = Test::logged("synchronized-log-cycle");
    let chain = t.f.ledger.chain_id();
    let cfg = t.config();
    let source_head = t.s.head();
    let closing_tip = t.s.tip();
    let peers = synchronized_peer_pair(&t.root, chain);
    let remote = t.root.join("remote-node");
    let remote_head = t.root.join("remote.head");
    let blank =
        Session::create_log_controlled(&remote, &t.f.genesis, chain, &remote_head, now()).unwrap();
    drop(blank);
    drop(t.s);
    let mut a = Cli::sync(
        &t.root,
        &t.node,
        &t.head,
        chain,
        t.deadline,
        (&peers[0].0, &peers[0].1),
    );
    a.command(json!({"command":"monitor_start","head":Id(source_head),"config":cfg,"password":std::str::from_utf8(PASSWORD).unwrap()}));
    let mut b = Cli::sync(
        &t.root,
        &remote,
        &remote_head,
        chain,
        t.deadline,
        (&peers[1].0, &peers[1].1),
    );
    let ready = loop {
        let v = b.command(json!({"command":"runtime_status"}));
        if v["selected_tip"] == json!(Id(closing_tip)) {
            break v;
        }
        assert!(Instant::now() < t.deadline, "bootstrap: {v}");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(ready["actors"], json!([]));
    assert_eq!(ready["local_runtime"]["fee_monitor"], Value::Null);
    assert_eq!(ready["local_runtime"]["automatic_peer_carriage"], true);
    let mut head = ready["session_head"].clone();
    let mut started = false;
    for _ in 0..8 {
        let v=b.raw_command(json!({"command":"mining_start","head":head,"reward":Id(t.f.miner.verifying_key().to_bytes())}));
        if v["diagnostic"].is_null() {
            started = true;
            break;
        }
        assert!(v["diagnostic"].as_str().unwrap().contains("head"), "{v}");
        head = v["session_head"].clone();
        assert!(Instant::now() < t.deadline);
    }
    assert!(started);
    let log_path = t.root.join("sync-progress.jsonl");
    write(&log_path, b"");
    let mut log = fs::OpenOptions::new().append(true).open(log_path).unwrap();
    let mut protected = false;
    let settlement = loop {
        let av = a.command(json!({"command":"runtime_status"}));
        let bv = b.command(json!({"command":"runtime_status"}));
        writeln!(
            log,
            "{}",
            json!({"at":now().to_string(),"recipient":av,"miner":bv})
        )
        .unwrap();
        let m = &av["local_runtime"]["fee_monitor"];
        assert!(m["diagnostic"].is_null(), "{av}");
        assert!(av["automatic_carriage"]["diagnostic"].is_null(), "{av}");
        assert!(bv["automatic_carriage"]["diagnostic"].is_null(), "{bv}");
        if let Some(error) = bv["local_runtime"]["ordinary_miner"]["diagnostic"].as_str() {
            assert!(error.starts_with("CLOCK_WAIT"), "{bv}");
        }
        let row = &m["last_observation"];
        if row["phase"] == "PROTECTED_WAITING_WINDOW" {
            protected = true;
            assert_eq!(row["principal_sequence"], "2");
            assert_eq!(row["fee_slots"], json!(["1", "1"]));
        }
        if row["phase"] == "SETTLED" && row["eligible_for_next_block"] == true {
            break row.clone();
        }
        assert!(
            Instant::now() < t.deadline,
            "{}",
            json!({"recipient":av,"miner":bv})
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(protected);
    assert_eq!(settlement["miner_fee"], "5");
    let miner = b.command(json!({"command":"mining_stop"}));
    let stopped = a.command(json!({"command":"monitor_stop"}));
    assert!(miner["peer"]["retained_packets"].as_u64().unwrap() < 2048);
    assert!(stopped["peer"]["retained_packets"].as_u64().unwrap() < 2048);
    b.stop();
    a.stop();
    log.sync_all().unwrap();
    drop(log);
    let finish_started = Instant::now();
    let finish_path = t.root.join("cold-completion.jsonl");
    write(&finish_path, b"");
    let mut finish_log = fs::OpenOptions::new()
        .append(true)
        .open(finish_path)
        .unwrap();
    let mut phase = |name: &str| {
        writeln!(
            finish_log,
            "{}",
            json!({"phase":name,"elapsed":finish_started.elapsed().as_secs_f64()})
        )
        .unwrap();
        finish_log.sync_all().unwrap();
    };
    phase("stopped");
    let mut node =
        Session::open_log_controlled(&t.node, &t.f.genesis, chain, &t.head, now()).unwrap();
    phase("cold_session_before_spend");
    assert_eq!(
        node.fee_policy_status(node.head(), t.policy, now())
            .unwrap()["signed_operations"],
        2
    );
    let operation = id(&settlement, "operation");
    let fee = support::out(operation.0, 5);
    let coin = node.native_coin(node.head(), &fee, now()).unwrap();
    assert_eq!(coin["native_coin"]["amount"], "5");
    assert_eq!(
        coin["native_coin"]["owner"],
        json!(Id(t.f.miner.verifying_key().to_bytes()))
    );
    assert_eq!(coin["native_coin"]["mature_for_next_block"], true);
    for (i, amount) in [555u128, 445].into_iter().enumerate() {
        let principal = node
            .native_coin(node.head(), &support::out(operation.0, 1 + i as u16), now())
            .unwrap();
        assert_eq!(principal["native_coin"]["amount"], amount.to_string());
        assert_eq!(
            principal["native_coin"]["owner"],
            json!(Id(t.f.owners[i].verifying_key().to_bytes()))
        );
    }
    let (spend, transaction) = support::ordinary(
        chain,
        &t.f.miner,
        &fee,
        &[(t.f.owners[0].verifying_key().to_bytes(), 4)],
    );
    phase("current_native_outputs");
    let timestamp = coin["selected_timestamp"]
        .as_str()
        .unwrap()
        .parse::<u64>()
        .unwrap()
        + 600;
    let candidate = loop {
        let v = node
            .mining_candidate(
                node.head(),
                rld_survivor_node::fast_session::MiningRequest {
                    miner: Id(t.f.miner.verifying_key().to_bytes()),
                    operations: vec![hex::encode(&spend)],
                    timestamp: timestamp.to_string(),
                    attempts: 4096,
                },
                now(),
            )
            .unwrap();
        if !v["candidate"].is_null() {
            break v;
        }
        assert!(Instant::now() < t.deadline);
    };
    phase("own_native_spend_candidate");
    let mut request = [0; 32];
    getrandom::getrandom(&mut request).unwrap();
    let out = node
        .execute(
            Id(request),
            node.head(),
            Action::Native {
                tip: Id(node.tip()),
                block: candidate["block_hex"].as_str().unwrap().into(),
            },
            None,
            now(),
        )
        .unwrap();
    assert!(out["diagnostic"].is_null(), "{out}");
    phase("durable_native_spend");
    drop(node);
    let mut cold =
        Session::open_log_controlled(&t.node, &t.f.genesis, chain, &t.head, now()).unwrap();
    phase("cold_session_after_spend");
    assert!(cold.native_coin(cold.head(), &fee, now()).unwrap()["native_coin"].is_null());
    let received = cold
        .native_coin(cold.head(), &support::out(transaction, 0), now())
        .unwrap();
    assert_eq!(received["native_coin"]["amount"], "4");
    assert_eq!(
        received["native_coin"]["owner"],
        json!(Id(t.f.owners[0].verifying_key().to_bytes()))
    );
    phase("complete");
    assert!(Instant::now() < t.deadline);
}

#[test]
fn bounded_native_admission_phase_observation() {
    native_admission_phase(false);
}
#[test]
fn bounded_logged_native_admission_phase_observation() {
    native_admission_phase(true);
}
fn native_admission_phase(logged: bool) {
    use rld_survivor_node::fast_session::MiningRequest;
    use std::sync::{Arc, Mutex};
    let mut t = if logged {
        Test::logged("native-log-phase-observation")
    } else {
        Test::new("native-phase-observation")
    };
    let limit = Instant::now() + Duration::from_secs(60);
    let marks = Arc::new(Mutex::new(Vec::<(String, Instant)>::new()));
    let control = marks.clone();
    t.s.set_control_observer(move |b| {
        control
            .lock()
            .unwrap()
            .push((format!("control_{b:?}"), Instant::now()));
        Ok(())
    })
    .unwrap();
    let mut totals = std::collections::BTreeMap::<String, Duration>::new();
    for _ in 0..32 {
        let start = Instant::now();
        let candidate = loop {
            let v =
                t.s.mining_candidate(
                    t.s.head(),
                    MiningRequest {
                        miner: Id(t.f.miner.verifying_key().to_bytes()),
                        operations: vec![],
                        timestamp: (t.f.ledger.tip().timestamp() + 600).to_string(),
                        attempts: 4096,
                    },
                    now(),
                )
                .unwrap();
            if !v["candidate"].is_null() {
                break v;
            }
            assert!(Instant::now() < limit);
        };
        *totals.entry("candidate_and_pow".into()).or_default() += start.elapsed();
        marks.lock().unwrap().clear();
        let start = Instant::now();
        marks.lock().unwrap().push(("start".into(), start));
        let raw = hex::decode(candidate["block_hex"].as_str().unwrap()).unwrap();
        let a = Action::Native {
            tip: Id(t.s.tip()),
            block: candidate["block_hex"].as_str().unwrap().into(),
        };
        let mut r = [0; 32];
        getrandom::getrandom(&mut r).unwrap();
        let observer = marks.clone();
        let v =
            t.s.execute_observed(Id(r), t.s.head(), a, None, now(), move |b| {
                observer
                    .lock()
                    .unwrap()
                    .push((format!("caller_{b:?}"), Instant::now()))
            })
            .unwrap();
        assert!(v["diagnostic"].is_null(), "{v}");
        let m = marks.lock().unwrap();
        for w in m.windows(2) {
            *totals
                .entry(format!("{}_to_{}", w[0].0, w[1].0))
                .or_default() += w[1].1.duration_since(w[0].1);
        }
        drop(m);
        t.f.ledger.execute(&raw, now()).unwrap();
        assert!(Instant::now() < limit);
    }
    eprintln!(
        "native_admission_phase_totals32={}",
        serde_json::to_string(
            &totals
                .into_iter()
                .map(|(k, v)| (k, v.as_secs_f64()))
                .collect::<std::collections::BTreeMap<_, _>>()
        )
        .unwrap()
    );
    assert_eq!(t.s.tip(), t.f.ledger.tip().id());
    assert!(Instant::now() < t.deadline);
}

#[test]
fn head_log_cut_child() {
    let Some(config) = std::env::var_os("RLD_FAST_HEAD_LOG_CUT") else {
        return;
    };
    let v: Value = serde_json::from_slice(&fs::read(config).unwrap()).unwrap();
    let root = PathBuf::from(v["root"].as_str().unwrap());
    let g = fs::read(root.join("genesis")).unwrap();
    let chain = fast::genesis_id(&g);
    let mut s =
        Session::open_log_controlled(&root.join("node"), &g, chain, &root.join("head"), now())
            .unwrap();
    let cut = v["cut"].as_str().unwrap().to_string();
    let cr = cut.clone();
    let marker = root.join("marker");
    let cm = marker.clone();
    s.set_control_observer(move |b| {
        let name = match b {
            rld_survivor_node::fast_session::ControlBoundary::PrepareNextDurable => {
                "control-prepare"
            }
            rld_survivor_node::fast_session::ControlBoundary::Prepared => "control-prepared",
            rld_survivor_node::fast_session::ControlBoundary::CommitNextDurable => "control-commit",
            rld_survivor_node::fast_session::ControlBoundary::Committed => "control-committed",
        };
        if name == cr {
            write(&cm, name.as_bytes());
            loop {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        Ok(())
    })
    .unwrap();
    let action: Action = serde_json::from_value(v["action"].clone()).unwrap();
    let r = id(&v, "request");
    s.execute_observed(r, s.head(), action, Some(PASSWORD), now(), move |b| {
        let name = match b {
            rld_survivor_node::fast_session::Boundary::IntentDurable => "intent",
            rld_survivor_node::fast_session::Boundary::ChildDurable => "child",
            rld_survivor_node::fast_session::Boundary::NativeActionEvaluated => "evaluated",
            rld_survivor_node::fast_session::Boundary::ReplyDurable => "reply",
        };
        if name == cut {
            write(&marker, name.as_bytes());
            loop {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    })
    .unwrap();
    panic!("missing requested actual head-log boundary");
}
struct CutProcess(Child);
impl Drop for CutProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[test]
fn head_log_actual_process_cuts_recover_only_exact_native_or_retained_fee_signatures() {
    let deadline = Instant::now() + Duration::from_secs(180);
    for mode in ["native", "fee"] {
        for cut in [
            "control-prepare",
            "control-prepared",
            "intent",
            if mode == "native" {
                "child"
            } else {
                "evaluated"
            },
            "reply",
            "control-commit",
            "control-committed",
        ] {
            let mut t = Test::logged(&format!("head-log-cut-{mode}-{cut}"));
            let before_height = t.f.ledger.tip().height();
            let action = if mode == "native" {
                let candidate = loop {
                    let v =
                        t.s.mining_candidate(
                            t.s.head(),
                            rld_survivor_node::fast_session::MiningRequest {
                                miner: Id(t.f.miner.verifying_key().to_bytes()),
                                operations: vec![],
                                timestamp: (t.f.ledger.tip().timestamp() + 600).to_string(),
                                attempts: 4096,
                            },
                            now(),
                        )
                        .unwrap();
                    if !v["candidate"].is_null() {
                        break v;
                    }
                    assert!(Instant::now() < deadline);
                };
                Action::Native {
                    tip: Id(t.s.tip()),
                    block: candidate["block_hex"].as_str().unwrap().into(),
                }
            } else {
                let plan = OnchainRequest {
                    kind: 3,
                    channel: Id(t.f.channel),
                    actor: t.terms.owner,
                    inputs: t.terms.inputs.clone(),
                    fee: "1".into(),
                    expiry: t.terms.expiry_height.clone(),
                    nonce: Id([193; 32]),
                    certificate: hex::encode(&t.proof),
                    timestamp: (t.f.ledger.tip().timestamp() + 600).to_string(),
                };
                let a = Action::FeePolicyPrepare {
                    tip: Id(t.s.tip()),
                    policy_request: t.policy,
                    plan,
                };
                let (prepared, v) = execute(&mut t.s, &mut t.n, a, None, now());
                Action::FeePolicySign {
                    tip: Id(t.s.tip()),
                    policy_request: t.policy,
                    prepare_request: prepared,
                    review: id(&v, "review_digest"),
                    key_file: t.key.to_string_lossy().into(),
                }
            };
            let mut token = [0; 32];
            getrandom::getrandom(&mut token).unwrap();
            let request = Id(token);
            let prior = t.s.head();
            drop(t.s);
            let config = t.root.join("cut.json");
            write(
                &config,
                json!({"root":t.root,"action":action,"cut":cut,"request":request})
                    .to_string()
                    .as_bytes(),
            );
            let mut child = CutProcess(
                Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "head_log_cut_child", "--nocapture"])
                    .env("RLD_FAST_HEAD_LOG_CUT", &config)
                    .stdin(Stdio::null())
                    .stdout(fs::File::create(t.root.join("cut.stdout")).unwrap())
                    .stderr(fs::File::create(t.root.join("cut.stderr")).unwrap())
                    .spawn()
                    .unwrap(),
            );
            while !t.root.join("marker").exists() {
                assert!(child.0.try_wait().unwrap().is_none(), "{mode}/{cut}");
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(10));
            }
            child.0.kill().unwrap();
            let status = child.0.wait().unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                assert_eq!(status.signal(), Some(9));
            }
            fs::rename(&t.key, t.root.join("unavailable.key")).unwrap();
            let native = fs::read(t.node.join("native.journal")).unwrap();
            let (mut s, out) = Session::recover_log_controlled(
                &t.node,
                &t.f.genesis,
                t.f.ledger.chain_id(),
                &t.head,
                now(),
            )
            .unwrap();
            assert_eq!(out["recovery_first_execution"], false);
            assert_eq!(out["recovery_key_loaded"], false);
            assert_eq!(fs::read(t.node.join("native.journal")).unwrap(), native);
            let complete = matches!(cut, "reply" | "control-commit" | "control-committed");
            assert_eq!(
                out["operation_hex"].is_string(),
                mode == "fee" && complete,
                "{mode}/{cut}: {out}"
            );
            if mode == "native" {
                let included = matches!(
                    cut,
                    "child" | "reply" | "control-commit" | "control-committed"
                );
                assert_eq!(
                    out["height"],
                    (before_height + u128::from(included)).to_string()
                );
            }
            let scope = s.fee_policy_status(s.head(), t.policy, now()).unwrap();
            assert_eq!(
                scope["signed_operations"],
                if mode == "fee" && complete { 1 } else { 0 }
            );
            if cut.starts_with("control-p") {
                assert_eq!(s.head(), prior);
                assert_eq!(out["request_body_retained"], false);
            }
            assert!(Instant::now() < deadline);
            let recovered = s.head();
            drop(s);
            let mut reopened = Session::open_log_controlled(
                &t.node,
                &t.f.genesis,
                t.f.ledger.chain_id(),
                &t.head,
                now(),
            )
            .unwrap();
            assert_eq!(reopened.head(), recovered);
            assert_eq!(
                reopened.status(recovered, now()).unwrap()["caller_head_storage"],
                "APPEND_ONLY"
            );
        }
    }
}
#[test]
fn unused_head_log_prepare_cannot_adopt_an_extra_unprepared_native_child() {
    let mut t = Test::logged("head-log-unprepared-child");
    let before = t.s.native_head();
    let tip = t.s.tip();
    let candidate = loop {
        let v =
            t.s.mining_candidate(
                t.s.head(),
                rld_survivor_node::fast_session::MiningRequest {
                    miner: Id(t.f.miner.verifying_key().to_bytes()),
                    operations: vec![],
                    timestamp: (t.f.ledger.tip().timestamp() + 600).to_string(),
                    attempts: 4096,
                },
                now(),
            )
            .unwrap();
        if !v["candidate"].is_null() {
            break v;
        }
        assert!(Instant::now() < t.deadline);
    };
    let raw = hex::decode(candidate["block_hex"].as_str().unwrap()).unwrap();
    t.s.set_control_observer(|b| {
        if b == rld_survivor_node::fast_session::ControlBoundary::Prepared {
            panic!("stop before caller intent");
        }
        Ok(())
    })
    .unwrap();
    let a = Action::Native {
        tip: Id(tip),
        block: hex::encode(&raw),
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        t.s.execute(Id([194; 32]), t.s.head(), a, None, now())
    }));
    assert!(result.is_err());
    drop(t.s);
    let mut native = Store::open(
        &t.node.join("native.journal"),
        &t.f.genesis,
        t.f.ledger.chain_id(),
        before,
        now(),
        Limits::default(),
    )
    .unwrap();
    native.accept(&raw, before, tip, now()).unwrap();
    drop(native);
    let header = fs::read(&t.head).unwrap();
    let caller = fs::read(t.node.join("caller.journal")).unwrap();
    assert!(Session::recover_log_controlled(
        &t.node,
        &t.f.genesis,
        t.f.ledger.chain_id(),
        &t.head,
        now()
    )
    .is_err());
    assert_eq!(fs::read(&t.head).unwrap(), header);
    assert_eq!(fs::read(t.node.join("caller.journal")).unwrap(), caller);
    assert!(Instant::now() < t.deadline);
}
