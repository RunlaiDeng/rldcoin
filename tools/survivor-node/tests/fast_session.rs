//! PUBLIC NO-VALUE keys; actual fresh native PoW, maturity and locked backing.
//! Separate journals here do not establish independent operators or performance.
#[allow(dead_code)]
#[path = "support/fast_funding.rs"]
mod support;
use rld_survivor_node::{
    fast_payment::{Invoice, Payment},
    fast_session::{Action, Id, Session},
    kernel::Hash,
    keyfile,
};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};
use support::*;
const PASSWORD: &[u8] = b"public no-value payment-session passphrase";
fn directory(chain: Hash, label: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "rld-fast-session-{}-{}-{label}",
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
}
fn id(v: &Value, k: &str) -> Id {
    serde_json::from_value(v[k].clone()).unwrap()
}
fn request(
    s: &mut Session,
    n: &mut u64,
    a: Action,
    password: Option<&[u8]>,
    now: u64,
) -> (Id, Value) {
    *n += 1;
    let mut key = [0; 32];
    key[..8].copy_from_slice(&n.to_be_bytes());
    let i = Id(key);
    let v = s.execute(i, s.head(), a, password, now).unwrap();
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
        request(&mut s, &mut n, a, None, f.now);
        at += z;
    }
    (s, n)
}
#[test]
fn caller_session_composes_exact_owner_review_signatures_retention_and_onward_payment() {
    let f = fixture();
    let dir = directory(f.ledger.chain_id(), "roundtrip");
    let root = dir.join("node");
    let (mut s, mut n) = funded(&f, &root);
    let keya = dir.join("a.key");
    let keyb = dir.join("b.key");
    let keyr = dir.join("r.key");
    for (p, k) in [
        (&keya, &f.owners[0]),
        (&keyb, &f.owners[1]),
        (&keyr, &f.retainer),
    ] {
        write(
            p,
            &keyfile::encrypt(k, f.ledger.chain_id(), PASSWORD).unwrap(),
        );
    }
    let da = hex::encode(delegation(&f));
    let tip = Id(s.tip());
    let (_, a) = request(
        &mut s,
        &mut n,
        Action::OwnerCreate {
            tip,
            channel: Id(f.channel),
            owner: 0,
            delegation: da.clone(),
        },
        None,
        f.now,
    );
    let a = id(&a, "actor");
    let (_, b) = request(
        &mut s,
        &mut n,
        Action::OwnerCreate {
            tip,
            channel: Id(f.channel),
            owner: 1,
            delegation: da.clone(),
        },
        None,
        f.now,
    );
    let b = id(&b, "actor");
    let (_, r) = request(
        &mut s,
        &mut n,
        Action::RetainerCreate {
            tip,
            channel: Id(f.channel),
            delegation: da,
        },
        None,
        f.now,
    );
    let r = id(&r, "actor");
    let origin = f.ledger.funding_origin(f.channel).unwrap();
    let mut previous: Option<Payment> = None;
    for (payer, amount, nonce) in [(0, 70, 1), (1, 25, 2)] {
        let invoice =
            Invoice::propose(&origin, previous.as_ref(), payer, amount, [nonce; 32]).unwrap();
        let (ra, va) = request(
            &mut s,
            &mut n,
            Action::OwnerPrepare {
                tip,
                actor: a,
                invoice: hex::encode(invoice.bytes()),
            },
            None,
            f.now,
        );
        let (rb, vb) = request(
            &mut s,
            &mut n,
            Action::OwnerPrepare {
                tip,
                actor: b,
                invoice: hex::encode(invoice.bytes()),
            },
            None,
            f.now,
        );
        assert_eq!(va["review"]["amount"], amount.to_string());
        assert_eq!(va["review"]["fee"], if payer == 0 { "2" } else { "3" });
        let (_, pa) = request(
            &mut s,
            &mut n,
            Action::OwnerSign {
                tip,
                actor: a,
                invoice: Id(invoice.id()),
                review_request: ra,
                review: id(&va, "review_digest"),
                key_file: keya.to_string_lossy().into(),
                approved: true,
            },
            Some(PASSWORD),
            f.now,
        );
        let head = s.head();
        drop(s);
        s = Session::open(&root, &f.genesis, f.ledger.chain_id(), head, f.now).unwrap();
        let pending = s.pending(head, a, Id(invoice.id()), f.now).unwrap();
        assert_eq!(pending["partial_hex"], pa["partial_hex"]);
        let (_, pb) = request(
            &mut s,
            &mut n,
            Action::OwnerSign {
                tip,
                actor: b,
                invoice: Id(invoice.id()),
                review_request: rb,
                review: id(&vb, "review_digest"),
                key_file: keyb.to_string_lossy().into(),
                approved: true,
            },
            Some(PASSWORD),
            f.now,
        );
        let payment = Payment::combine(
            &origin,
            invoice.bytes(),
            &hex::decode(pa["partial_hex"].as_str().unwrap()).unwrap(),
            &hex::decode(pb["partial_hex"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let (rr, vr) = request(
            &mut s,
            &mut n,
            Action::RetainerPrepare {
                tip,
                actor: r,
                receipt: hex::encode(payment.bytes()),
            },
            None,
            f.now,
        );
        let (_, ack) = request(
            &mut s,
            &mut n,
            Action::RetainerSign {
                tip,
                actor: r,
                receipt: Id(payment.id()),
                review_request: rr,
                review: id(&vr, "review_digest"),
                key_file: keyr.to_string_lossy().into(),
                approved: true,
            },
            Some(PASSWORD),
            f.now,
        );
        for actor in [a, b] {
            let (_, v) = request(
                &mut s,
                &mut n,
                Action::OwnerComplete {
                    tip,
                    actor,
                    receipt: hex::encode(payment.bytes()),
                    ack: ack["ack_hex"].as_str().unwrap().into(),
                },
                None,
                f.now,
            );
            assert_eq!(v["receipt_hex"], hex::encode(payment.bytes()));
        }
        for actor in [a, b, r] {
            let head = s.head();
            let evidence = s.exit_evidence(head, actor, f.now).unwrap();
            assert_eq!(
                evidence["certificate_hex"],
                hex::encode(payment.after_certificate())
            );
            assert_eq!(evidence["backing_currentness_known"], false);
            assert_eq!(evidence["wallet_key_loaded"], false);
        }
        previous = Some(payment);
    }
    let head = s.head();
    drop(s);
    let mut s = Session::open(&root, &f.genesis, f.ledger.chain_id(), head, f.now).unwrap();
    assert_eq!(
        s.status(head, f.now).unwrap()["fast_completion_authorized"],
        false
    );
    assert_eq!(
        origin
            .verify_certificate(previous.unwrap().after_certificate())
            .unwrap()
            .balances,
        [555, 445]
    );
}

struct Node {
    child: Option<std::process::Child>,
    input: Option<std::process::ChildStdin>,
    rx: std::sync::mpsc::Receiver<String>,
    head: Id,
    tip: Id,
    count: u64,
    deadline: std::time::Instant,
    dir: PathBuf,
    label: String,
}
impl Node {
    fn start(dir: &Path, label: &str, args: &[std::ffi::OsString]) -> Self {
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        let mut c = Command::new(env!("CARGO_BIN_EXE_rld-fast-payment-session"))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(fs::File::create(dir.join(format!("{label}.stderr.log"))).unwrap())
            .spawn()
            .unwrap();
        let input = c.stdin.take().unwrap();
        let output = c.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let log = dir.join(format!("{label}.stdout.log"));
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
        let mut n = Self {
            child: Some(c),
            input: Some(input),
            rx,
            head: Id([0; 32]),
            tip: Id([0; 32]),
            count: 0,
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(180),
            dir: dir.to_path_buf(),
            label: label.into(),
        };
        let v = n.receive();
        n.head = id(&v, "session_head");
        n.tip = id(&v, "selected_tip");
        n
    }
    fn receive(&self) -> Value {
        serde_json::from_str(
            &self
                .rx
                .recv_timeout(
                    self.deadline
                        .saturating_duration_since(std::time::Instant::now()),
                )
                .expect("original180 payment session process"),
        )
        .unwrap()
    }
    fn send(&mut self, mut v: Value) -> Value {
        v["head"] = serde_json::to_value(self.head).unwrap();
        writeln!(self.input.as_mut().unwrap(), "{v}").unwrap();
        self.input.as_mut().unwrap().flush().unwrap();
        let v = self.receive();
        if !v["session_head"].is_null() {
            self.head = id(&v, "session_head");
        }
        if !v["selected_tip"].is_null() {
            self.tip = id(&v, "selected_tip");
        }
        v
    }
    fn execute(&mut self, a: Action, password: Option<&str>) -> (Id, Value) {
        self.count += 1;
        let mut b = [0; 32];
        b[..8].copy_from_slice(&self.count.to_be_bytes());
        let r = Id(b);
        let v =
            self.send(json!({"command":"execute","request_id":r,"action":a,"password":password}));
        assert!(v["diagnostic"].is_null(), "{v}");
        (r, v)
    }
    fn finish(&mut self, kill: bool) {
        let c = self.child.as_mut().unwrap();
        let pid = c.id();
        if kill {
            c.kill().unwrap();
        } else {
            self.input.take();
        }
        let status = loop {
            if let Some(s) = c.try_wait().unwrap() {
                break s;
            }
            assert!(std::time::Instant::now() < self.deadline);
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        #[cfg(unix)]
        let signal = {
            use std::os::unix::process::ExitStatusExt;
            status.signal()
        };
        #[cfg(not(unix))]
        let signal: Option<i32> = None;
        if kill {
            assert_eq!(signal, Some(9));
        } else {
            assert!(status.success());
        }
        fs::write(self.dir.join(format!("{}.terminal.json",self.label)),json!({"pid":pid,"signal":signal,"exit_code":status.code(),"success":status.success(),"requested_kill":kill}).to_string()).unwrap();
        self.child.take();
    }
}
impl Drop for Node {
    fn drop(&mut self) {
        if let Some(c) = self.child.as_mut() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}
fn native_args(
    mode: &str,
    root: &Path,
    genesis: &Path,
    chain: Hash,
    tail: &[String],
) -> Vec<std::ffi::OsString> {
    let mut a = vec![
        mode.into(),
        root.as_os_str().into(),
        genesis.as_os_str().into(),
        hex::encode(chain).into(),
    ];
    a.extend(tail.iter().map(Into::into));
    a
}
#[test]
fn three_actual_native_sessions_propose_review_sign_retain_and_pay_onward() {
    let f = fixture();
    let dir = directory(f.ledger.chain_id(), "three-process");
    let genesis = dir.join("genesis");
    write(&genesis, &f.genesis);
    let mut nodes = vec![];
    for label in ["a", "b", "r"] {
        let root = dir.join(label);
        let mut create = Node::start(
            &dir,
            &format!("{label}-create"),
            &native_args("create", &root, &genesis, f.ledger.chain_id(), &[]),
        );
        let head = create.head;
        create.finish(false);
        let n = Node::start(
            &dir,
            &format!("{label}-serve"),
            &native_args(
                "serve",
                &root,
                &genesis,
                f.ledger.chain_id(),
                &[hex::encode(head.0)],
            ),
        );
        nodes.push(n);
    }
    let mut at = 0;
    while at < f.history.len() {
        let n = u32::from_be_bytes(f.history[at..at + 4].try_into().unwrap()) as usize;
        at += 4;
        let block = hex::encode(&f.history[at..at + n]);
        at += n;
        for node in &mut nodes {
            node.execute(
                Action::Native {
                    tip: node.tip,
                    block: block.clone(),
                },
                None,
            );
        }
    }
    let d = hex::encode(delegation(&f));
    let mut actors = vec![];
    let mut key_paths = vec![];
    for (i, node) in nodes.iter_mut().enumerate() {
        let action = if i < 2 {
            Action::OwnerCreate {
                tip: node.tip,
                channel: Id(f.channel),
                owner: i as u8,
                delegation: d.clone(),
            }
        } else {
            Action::RetainerCreate {
                tip: node.tip,
                channel: Id(f.channel),
                delegation: d.clone(),
            }
        };
        let (_, v) = node.execute(action, None);
        actors.push(id(&v, "actor"));
        let path = dir.join(format!("{i}.key"));
        write(
            &path,
            &keyfile::encrypt(
                if i < 2 { &f.owners[i] } else { &f.retainer },
                f.ledger.chain_id(),
                PASSWORD,
            )
            .unwrap(),
        );
        key_paths.push(path);
    }
    let origin = f.ledger.funding_origin(f.channel).unwrap();
    let password = std::str::from_utf8(PASSWORD).unwrap();
    let mut last = None;
    for (payer, amount, nonce) in [(0usize, 70u128, 1u8), (1, 25, 2)] {
        let proposal=nodes[payer].send(json!({"command":"propose","actor":actors[payer],"payer":payer,"amount":amount.to_string(),"invoice":Id([nonce;32])}));
        assert!(proposal["diagnostic"].is_null(), "{proposal}");
        let raw = hex::decode(proposal["invoice_hex"].as_str().unwrap()).unwrap();
        let invoice = Invoice::verify(&origin, &raw).unwrap();
        let mut partials = vec![];
        for i in 0..2 {
            let node = &mut nodes[i];
            let (request_id, v) = node.execute(
                Action::OwnerPrepare {
                    tip: node.tip,
                    actor: actors[i],
                    invoice: hex::encode(&raw),
                },
                None,
            );
            assert_eq!(
                v["review"]["payer"],
                serde_json::to_value(Id(f.owners[payer].verifying_key().to_bytes())).unwrap()
            );
            let (_, v) = node.execute(
                Action::OwnerSign {
                    tip: node.tip,
                    actor: actors[i],
                    invoice: Id(invoice.id()),
                    review_request: request_id,
                    review: id(&v, "review_digest"),
                    key_file: key_paths[i].to_string_lossy().into(),
                    approved: true,
                },
                Some(password),
            );
            partials.push(hex::decode(v["partial_hex"].as_str().unwrap()).unwrap());
        }
        let p = Payment::combine(&origin, &raw, &partials[0], &partials[1]).unwrap();
        let node = &mut nodes[2];
        let (r, v) = node.execute(
            Action::RetainerPrepare {
                tip: node.tip,
                actor: actors[2],
                receipt: hex::encode(p.bytes()),
            },
            None,
        );
        let (_, v) = node.execute(
            Action::RetainerSign {
                tip: node.tip,
                actor: actors[2],
                receipt: Id(p.id()),
                review_request: r,
                review: id(&v, "review_digest"),
                key_file: key_paths[2].to_string_lossy().into(),
                approved: true,
            },
            Some(password),
        );
        let ack = v["ack_hex"].as_str().unwrap();
        for i in 0..2 {
            let node = &mut nodes[i];
            node.execute(
                Action::OwnerComplete {
                    tip: node.tip,
                    actor: actors[i],
                    receipt: hex::encode(p.bytes()),
                    ack: ack.into(),
                },
                None,
            );
        }
        last = Some(p);
    }
    assert_eq!(
        origin
            .verify_certificate(last.unwrap().after_certificate())
            .unwrap()
            .balances,
        [555, 445]
    );
    for n in &mut nodes {
        let out = n.send(json!({"command":"status"}));
        assert_eq!(out["fast_completion_authorized"], false);
        n.finish(false);
    }
    for label in ["a", "b", "r"] {
        let caller = fs::read(dir.join(label).join("caller.journal")).unwrap();
        assert!(!caller.windows(PASSWORD.len()).any(|w| w == PASSWORD));
    }
}

fn actual_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
#[test]
fn session_boundary_child() {
    let Ok(parent) = std::env::var("RLD_PAYMENT_SESSION_CUT_ROOT") else {
        return;
    };
    let phase = std::env::var("RLD_PAYMENT_SESSION_CUT_PHASE").unwrap();
    let dir = Path::new(&parent);
    let f = fixture();
    let root = dir.join("node");
    let (mut s, mut n) = funded(&f, &root);
    write(&dir.join("genesis"), &f.genesis);
    let key = dir.join("owner.key");
    write(
        &key,
        &keyfile::encrypt(&f.owners[0], f.ledger.chain_id(), PASSWORD).unwrap(),
    );
    let tip = Id(s.tip());
    let (_, v) = request(
        &mut s,
        &mut n,
        Action::OwnerCreate {
            tip,
            channel: Id(f.channel),
            owner: 0,
            delegation: hex::encode(delegation(&f)),
        },
        None,
        f.now,
    );
    let actor = id(&v, "actor");
    let invoice = Invoice::propose(
        &f.ledger.funding_origin(f.channel).unwrap(),
        None,
        0,
        70,
        [1; 32],
    )
    .unwrap();
    let tip = Id(s.tip());
    let (review_id, v) = request(
        &mut s,
        &mut n,
        Action::OwnerPrepare {
            tip,
            actor,
            invoice: hex::encode(invoice.bytes()),
        },
        None,
        f.now,
    );
    let mut key_id = [0; 32];
    key_id[0] = 250;
    let request_id = Id(key_id);
    let mut expected_native = None;
    let action = if phase == "native_child" {
        let mut fork = f.before.clone();
        let first = mine(
            &mut fork,
            f.retainer.verifying_key().to_bytes(),
            vec![],
            f.now,
        );
        let tip = Id(s.tip());
        request(
            &mut s,
            &mut n,
            Action::Native {
                tip,
                block: hex::encode(first),
            },
            None,
            f.now,
        );
        let last = mine(
            &mut fork,
            f.retainer.verifying_key().to_bytes(),
            vec![],
            f.now,
        );
        expected_native = Some(Id(fork.tip().id()));
        Action::Native {
            tip: Id(s.tip()),
            block: hex::encode(last),
        }
    } else {
        Action::OwnerSign {
            tip,
            actor,
            invoice: Id(invoice.id()),
            review_request: review_id,
            review: id(&v, "review_digest"),
            key_file: key.to_string_lossy().into(),
            approved: true,
        }
    };
    let before = s.head();
    let digest = action.digest().unwrap();
    let raw = payment(&f, None, 0, 70, 1);
    let expected = [vec![0], raw[323..387].to_vec(), raw[451..515].to_vec()].concat();
    let cut = match phase.as_str() {
        "intent" => rld_survivor_node::fast_session::Boundary::IntentDurable,
        "child" | "native_child" => rld_survivor_node::fast_session::Boundary::ChildDurable,
        "reply" => rld_survivor_node::fast_session::Boundary::ReplyDurable,
        _ => panic!("unknown test phase"),
    };
    s.execute_observed(request_id,before,action,Some(PASSWORD),actual_now(),|b|if b==cut{
  write(&dir.join("ready.json"),json!({"chain":Id(f.ledger.chain_id()),"prior":Id(before),"request_id":request_id,"request_digest":digest,"invoice":Id(invoice.id()),"actor":actor,"expected_partial":hex::encode(&expected),"expected_native":expected_native}).to_string().as_bytes());
  let deadline=std::time::Instant::now()+std::time::Duration::from_secs(180);while std::time::Instant::now()<deadline{std::thread::sleep(std::time::Duration::from_millis(20));}panic!("original180 awaited parent kill");
 }).unwrap();
    panic!("boundary was not observed");
}
#[cfg(unix)]
#[test]
fn actual_process_cuts_recover_existing_effects_without_key_files_or_first_signing() {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    for phase in ["intent", "child", "reply", "native_child"] {
        let mut nonce = [0; 32];
        getrandom::getrandom(&mut nonce).unwrap();
        let dir = directory(nonce, phase);
        struct Guard(Option<std::process::Child>);
        impl Drop for Guard {
            fn drop(&mut self) {
                if let Some(c) = self.0.as_mut() {
                    let _ = c.kill();
                    let _ = c.wait();
                }
            }
        }
        let mut child = Guard(Some(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "session_boundary_child", "--nocapture"])
                .env("RLD_PAYMENT_SESSION_CUT_ROOT", &dir)
                .env("RLD_PAYMENT_SESSION_CUT_PHASE", phase)
                .stdin(Stdio::null())
                .stdout(fs::File::create(dir.join("child.stdout.log")).unwrap())
                .stderr(fs::File::create(dir.join("child.stderr.log")).unwrap())
                .spawn()
                .unwrap(),
        ));
        let deadline = Instant::now() + Duration::from_secs(180);
        let ready: Value = loop {
            assert!(
                child.0.as_mut().unwrap().try_wait().unwrap().is_none(),
                "child exited before phase marker: {}",
                fs::read_to_string(dir.join("child.stderr.log")).unwrap()
            );
            if let Ok(b) = fs::read(dir.join("ready.json")) {
                if let Ok(v) = serde_json::from_slice(&b) {
                    break v;
                }
            }
            assert!(Instant::now() < deadline, "original180 session cut");
            std::thread::sleep(Duration::from_millis(10));
        };
        let pid = child.0.as_ref().unwrap().id();
        child.0.as_mut().unwrap().kill().unwrap();
        let status = child.0.as_mut().unwrap().wait().unwrap();
        child.0.take();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(9));
        write(
            &dir.join("terminal.json"),
            json!({"pid":pid,"signal":status.signal(),"requested_kill":true})
                .to_string()
                .as_bytes(),
        );
        fs::rename(
            dir.join("owner.key"),
            dir.join("retained-key-not-at-request-path"),
        )
        .unwrap();
        let chain = id(&ready, "chain");
        let prior = id(&ready, "prior");
        let rid = id(&ready, "request_id");
        let rd = id(&ready, "request_digest");
        let root = dir.join("node");
        let genesis = dir.join("genesis");
        let mut recovery = Node::start(
            &dir,
            "recovery",
            &native_args(
                "recover",
                &root,
                &genesis,
                chain.0,
                &[hex::encode(prior.0), hex::encode(rid.0), hex::encode(rd.0)],
            ),
        );
        let head = recovery.head;
        recovery.finish(false);
        let (mut session, v) = Session::recover(
            &root,
            &fs::read(&genesis).unwrap(),
            chain.0,
            prior.0,
            rid,
            rd,
            actual_now(),
        )
        .unwrap();
        assert_eq!(session.head(), head.0);
        assert_eq!(v["key_loaded_by_recovery"], false);
        if phase == "intent" {
            assert!(v["partial_hex"].is_null());
            let p = session
                .pending(
                    head.0,
                    id(&ready, "actor"),
                    id(&ready, "invoice"),
                    actual_now(),
                )
                .unwrap();
            assert!(p["partial_hex"].is_null());
        } else if phase == "native_child" {
            assert_eq!(
                serde_json::to_value(Id(session.tip())).unwrap(),
                ready["expected_native"]
            );
            assert!(v["partial_hex"].is_null());
        } else {
            assert_eq!(v["partial_hex"], ready["expected_partial"]);
        }
        assert_eq!(v["fast_completion_authorized"], false);
    }
}
#[test]
fn rehashed_caller_review_cannot_authorize_a_signature_and_stale_heads_refuse() {
    use sha2::{Digest, Sha256};
    let f = fixture();
    let dir = directory(f.ledger.chain_id(), "audit");
    let root = dir.join("node");
    let (mut s, mut n) = funded(&f, &root);
    let tip = Id(s.tip());
    let (_, v) = request(
        &mut s,
        &mut n,
        Action::OwnerCreate {
            tip,
            channel: Id(f.channel),
            owner: 0,
            delegation: hex::encode(delegation(&f)),
        },
        None,
        f.now,
    );
    let actor = id(&v, "actor");
    let i = Invoice::propose(
        &f.ledger.funding_origin(f.channel).unwrap(),
        None,
        0,
        70,
        [1; 32],
    )
    .unwrap();
    let old = s.head();
    let (_, v) = request(
        &mut s,
        &mut n,
        Action::OwnerPrepare {
            tip,
            actor,
            invoice: hex::encode(i.bytes()),
        },
        None,
        f.now,
    );
    assert!(s.status(old, f.now).is_err());
    let head = s.head();
    assert!(s.propose(head, actor, 0, 1, [2; 32], f.now).is_err());
    drop(s);
    let path = root.join("caller.journal");
    let mut raw = fs::read(&path).unwrap();
    let mut at = 197;
    let mut last = at;
    while at < raw.len() {
        last = at;
        let n = u32::from_be_bytes(raw[at..at + 4].try_into().unwrap()) as usize;
        at += 4 + n;
    }
    let start = last + 4 + 37;
    let end = raw.len() - 32;
    let needle = b"\"review\":\"";
    let found = raw[start..end]
        .windows(needle.len())
        .position(|b| b == needle)
        .unwrap()
        + start
        + needle.len();
    raw[found] = if raw[found] == b'0' { b'1' } else { b'0' };
    let forged: Hash = Sha256::digest(
        [
            b"RLD-FAST-SESSION-1/RECORD\0".as_slice(),
            &raw[last + 4..end],
        ]
        .concat(),
    )
    .into();
    raw[end..].copy_from_slice(&forged);
    fs::write(&path, &raw).unwrap();
    assert!(Session::open(&root, &f.genesis, f.ledger.chain_id(), forged, f.now).is_err());
    assert_eq!(fs::read(path).unwrap(), raw);
    assert!(!v["review_digest"].is_null());
}

#[test]
fn failed_approval_and_reorganized_backing_do_not_read_the_requested_key() {
    let f = fixture();
    let dir = directory(f.ledger.chain_id(), "pre-key");
    let root = dir.join("node");
    let (mut s, mut n) = funded(&f, &root);
    let tip = Id(s.tip());
    let (_, v) = request(
        &mut s,
        &mut n,
        Action::OwnerCreate {
            tip,
            channel: Id(f.channel),
            owner: 0,
            delegation: hex::encode(delegation(&f)),
        },
        None,
        f.now,
    );
    let actor = id(&v, "actor");
    let proposal = s.propose(s.head(), actor, 0, 70, [1; 32], f.now).unwrap();
    let raw = hex::decode(proposal["invoice_hex"].as_str().unwrap()).unwrap();
    let inv = Invoice::verify(&f.ledger.funding_origin(f.channel).unwrap(), &raw).unwrap();
    let (review_request, v) = request(
        &mut s,
        &mut n,
        Action::OwnerPrepare {
            tip,
            actor,
            invoice: hex::encode(raw),
        },
        None,
        f.now,
    );
    let review = id(&v, "review_digest");
    let missing = dir.join("never-created-key").to_string_lossy().to_string();
    for (approved, reference, expected) in [
        (false, review_request, "approval"),
        (true, Id([0; 32]), "review"),
    ] {
        let (_, v) = request(
            &mut s,
            &mut n,
            Action::OwnerSign {
                tip,
                actor,
                invoice: Id(inv.id()),
                review_request: reference,
                review,
                key_file: missing.clone(),
                approved,
            },
            Some(PASSWORD),
            f.now,
        );
        assert!(v["diagnostic"].as_str().unwrap().contains(expected), "{v}");
        assert!(v["partial_hex"].is_null());
    }
    let mut fork = f.before.clone();
    for _ in 0..2 {
        let b = mine(
            &mut fork,
            f.retainer.verifying_key().to_bytes(),
            vec![],
            f.now,
        );
        let tip = Id(s.tip());
        request(
            &mut s,
            &mut n,
            Action::Native {
                tip,
                block: hex::encode(b),
            },
            None,
            f.now,
        );
    }
    let tip = Id(s.tip());
    let (_, v) = request(
        &mut s,
        &mut n,
        Action::OwnerSign {
            tip,
            actor,
            invoice: Id(inv.id()),
            review_request,
            review,
            key_file: missing,
            approved: true,
        },
        Some(PASSWORD),
        f.now,
    );
    assert!(
        v["diagnostic"].as_str().unwrap().contains("backing absent"),
        "{v}"
    );
    assert!(v["partial_hex"].is_null());
    let head = s.head();
    drop(s);
    let mut s = Session::open(&root, &f.genesis, f.ledger.chain_id(), head, f.now).unwrap();
    assert_eq!(s.tip(), fork.tip().id());
    assert!(s.pending(head, actor, Id(inv.id()), f.now).unwrap()["partial_hex"].is_null());
}
#[cfg(unix)]
#[test]
fn caller_path_replacement_and_torn_actor_tail_suspend_new_signing() {
    use std::os::unix::fs::PermissionsExt;
    let f = fixture();
    let dir = directory(f.ledger.chain_id(), "custody");
    let root = dir.join("node");
    let (mut s, mut n) = funded(&f, &root);
    let tip = Id(s.tip());
    let (_, v) = request(
        &mut s,
        &mut n,
        Action::OwnerCreate {
            tip,
            channel: Id(f.channel),
            owner: 0,
            delegation: hex::encode(delegation(&f)),
        },
        None,
        f.now,
    );
    let actor = id(&v, "actor");
    let head = s.head();
    let caller = root.join("caller.journal");
    let raw = fs::read(&caller).unwrap();
    fs::rename(&caller, root.join("retained-original-caller")).unwrap();
    write(&caller, &raw);
    assert!(s.status(head, f.now).is_err());
    drop(s);
    let actor_path = root
        .join("actors")
        .join(format!("{}.journal", hex::encode(actor.0)));
    let original = fs::read(&actor_path).unwrap();
    let mut o = fs::OpenOptions::new()
        .append(true)
        .open(&actor_path)
        .unwrap();
    o.write_all(&[0, 0, 0]).unwrap();
    o.sync_all().unwrap();
    assert!(Session::open(&root, &f.genesis, f.ledger.chain_id(), head, f.now).is_err());
    assert_eq!(
        fs::read(&actor_path).unwrap(),
        [original.as_slice(), &[0, 0, 0]].concat()
    );
    fs::set_permissions(&caller, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Session::open(&root, &f.genesis, f.ledger.chain_id(), head, f.now).is_err());
}
