//! PUBLIC NO-VALUE native funding and actual work; no balance injection.
//! Distinct keys/processes on this host do not qualify independent operation.
#[allow(dead_code)]
#[path = "support/fast_funding.rs"]
mod support;
use rld_survivor_node::{
    fast_owner,
    fast_payment::Invoice,
    fast_retainer::{self, Creation},
    fast_store::{Limits, Store},
    kernel::{fast, Hash},
};
use std::{
    cell::Cell,
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};
use support::*;
fn directory(chain: Hash, label: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "rld-fast-native-{}-{}-{label}",
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
fn blocks(history: &[u8]) -> Vec<Vec<u8>> {
    let mut at = 0;
    let mut out = vec![];
    while at < history.len() {
        let n = u32::from_be_bytes(history[at..at + 4].try_into().unwrap()) as usize;
        at += 4;
        out.push(history[at..at + n].to_vec());
        at += n;
    }
    out
}
fn add(s: &mut Store, raw: &[u8], now: u64) -> rld_survivor_node::fast_store::Outcome {
    s.accept(raw, s.head(), s.ledger().tip().id(), now).unwrap()
}
fn open_funded(f: &Fixture, path: &Path) -> Store {
    let mut s = Store::create(
        path,
        &f.genesis,
        f.ledger.chain_id(),
        f.now,
        Limits::default(),
    )
    .unwrap();
    for b in blocks(&f.history) {
        add(&mut s, &b, f.now);
    }
    assert_eq!(s.ledger().tip(), f.ledger.tip());
    s
}
#[test]
fn stronger_retained_branch_removes_backing_from_both_signing_paths_across_restart() {
    let f = fixture();
    let dir = directory(f.ledger.chain_id(), "reorg");
    let path = dir.join("native");
    let mut s = open_funded(&f, &path);
    let funded_head = s.head();
    let origin = s.ledger().funding_origin(f.channel).unwrap();
    let mut owner = fast_owner::Journal::create(
        &dir.join("owner"),
        Creation {
            genesis: &f.genesis,
            chain: f.ledger.chain_id(),
            history: &f.history,
            delegation: &delegation(&f),
            current: s.current(s.head(), s.ledger().tip().id(), f.now).unwrap(),
            limit: 1024 * 1024,
        },
        0,
    )
    .unwrap();
    let mut retainer = fast_retainer::Journal::create(
        &dir.join("retainer"),
        Creation {
            genesis: &f.genesis,
            chain: f.ledger.chain_id(),
            history: &f.history,
            delegation: &delegation(&f),
            current: s.current(s.head(), s.ledger().tip().id(), f.now).unwrap(),
            limit: 1024 * 1024,
        },
    )
    .unwrap();
    let invoice = Invoice::propose(&origin, None, 0, 70, [1; 32]).unwrap();
    let review = owner
        .prepare(
            invoice.bytes(),
            owner.head(),
            s.current(s.head(), s.ledger().tip().id(), f.now).unwrap(),
        )
        .unwrap();
    let raw = payment(&f, None, 0, 70, 1);
    let review_r = retainer
        .prepare(
            &raw,
            retainer.head(),
            s.current(s.head(), s.ledger().tip().id(), f.now).unwrap(),
        )
        .unwrap();
    let mut competing = f.before.clone();
    for _ in 0..2 {
        let raw = mine(
            &mut competing,
            f.retainer.verifying_key().to_bytes(),
            vec![],
            f.now,
        );
        add(&mut s, &raw, f.now);
    }
    assert_eq!(s.ledger().tip().id(), competing.tip().id());
    assert_eq!(s.ledger().locked(), 0);
    let called = Cell::new(false);
    assert!(owner
        .sign(
            review.head,
            review.digest,
            s.current(s.head(), s.ledger().tip().id(), f.now).unwrap(),
            || {
                called.set(true);
                Ok(f.owners[0].clone())
            }
        )
        .is_err());
    assert!(!called.get());
    assert!(retainer
        .acknowledge(
            review_r.head,
            review_r.digest,
            s.current(s.head(), s.ledger().tip().id(), f.now).unwrap(),
            || {
                called.set(true);
                Ok(f.retainer.clone())
            }
        )
        .is_err());
    assert!(!called.get());
    let head = s.head();
    let tip = s.ledger().tip().id();
    let rev = s.revision();
    drop(s);
    assert!(Store::open(
        &path,
        &f.genesis,
        f.ledger.chain_id(),
        funded_head,
        f.now,
        Limits::default()
    )
    .is_err());
    let mut s = Store::open(
        &path,
        &f.genesis,
        f.ledger.chain_id(),
        head,
        f.now,
        Limits::default(),
    )
    .unwrap();
    assert_eq!(
        (s.ledger().tip().id(), s.revision(), s.known_blocks()),
        (tip, rev, 104)
    );
    assert!(origin
        .check_current(s.current(head, tip, f.now).unwrap().ledger, tip, f.now)
        .is_err());
    assert!(owner
        .sign(
            review.head,
            review.digest,
            s.current(head, tip, f.now).unwrap(),
            || {
                called.set(true);
                Ok(f.owners[0].clone())
            }
        )
        .is_err());
    assert!(!called.get());
}
#[test]
fn equal_work_uses_smaller_native_id_and_exact_duplicate_cannot_authenticate_changed_body() {
    let f = fixture();
    let dir = directory(f.ledger.chain_id(), "tie");
    let path = dir.join("native");
    let mut s = Store::create(
        &path,
        &f.genesis,
        f.ledger.chain_id(),
        f.now,
        Limits::default(),
    )
    .unwrap();
    let mut a = fast::Ledger::from_genesis(&f.genesis, f.ledger.chain_id(), 100000).unwrap();
    let mut b = a.clone();
    let ar = mine(&mut a, f.miner.verifying_key().to_bytes(), vec![], f.now);
    let br = mine(&mut b, f.retainer.verifying_key().to_bytes(), vec![], f.now);
    let mut order = [ar, br];
    order.sort_by_key(|r| std::cmp::Reverse(fast::block_id(r).unwrap()));
    add(&mut s, &order[0], f.now);
    let outcome = add(&mut s, &order[1], f.now);
    assert!(outcome.selected);
    assert_eq!(s.ledger().tip().id(), fast::block_id(&order[1]).unwrap());
    let retained = fs::read(&path).unwrap();
    let head = s.head();
    let revision = s.revision();
    assert!(add(&mut s, &order[0], f.now).already_known);
    assert_eq!(
        (s.head(), s.revision(), s.known_blocks()),
        (head, revision, 2)
    );
    let mut bad = order[0].clone();
    bad[269] ^= 1;
    assert!(s.accept(&bad, head, s.ledger().tip().id(), f.now).is_err());
    assert_eq!(fs::read(&path).unwrap(), retained);
    drop(s);
    let s = Store::open(
        &path,
        &f.genesis,
        f.ledger.chain_id(),
        head,
        f.now,
        Limits::default(),
    )
    .unwrap();
    assert_eq!(s.ledger().tip().id(), fast::block_id(&order[1]).unwrap());
}
#[test]
fn missing_parent_head_clock_and_capacity_fail_without_changing_native_state() {
    let f = fixture();
    let dir = directory(f.ledger.chain_id(), "capacity");
    let path = dir.join("native");
    let mut s = Store::create(
        &path,
        &f.genesis,
        f.ledger.chain_id(),
        f.now,
        Limits {
            bytes: 1024 * 1024,
            blocks: 1,
            coins: 100000,
        },
    )
    .unwrap();
    let chain = f.ledger.chain_id();
    let raws = blocks(&f.history);
    let header = fs::read(&path).unwrap();
    let h = s.head();
    assert!(s
        .accept(&raws[1], h, chain, f.now)
        .unwrap_err()
        .contains("WAITING_FOR_HISTORY"));
    assert_eq!(fs::read(&path).unwrap(), header);
    assert!(s.accept(&raws[0], [0; 32], chain, f.now).is_err());
    assert!(s.accept(&raws[0], h, [0; 32], f.now).is_err());
    assert!(s.accept(&raws[0], h, chain, f.now - 1).is_err());
    let o = add(&mut s, &raws[0], f.now);
    let saved = fs::read(&path).unwrap();
    assert!(s.accept(&raws[1], o.head, o.tip, f.now).is_err());
    assert_eq!(fs::read(&path).unwrap(), saved);
    let tiny = dir.join("tiny");
    let mut tiny_s = Store::create(
        &tiny,
        &f.genesis,
        chain,
        f.now,
        Limits {
            bytes: 165 + 4 + 132 + raws[0].len() - 1,
            blocks: 1,
            coins: 100000,
        },
    )
    .unwrap();
    assert!(tiny_s
        .accept(&raws[0], tiny_s.head(), chain, f.now)
        .is_err());
    assert_eq!(fs::metadata(tiny).unwrap().len(), 165);
}
#[test]
fn cold_replay_does_not_trust_rehashed_selected_tip_or_accept_truncated_tail() {
    use sha2::{Digest, Sha256};
    let f = fixture();
    let dir = directory(f.ledger.chain_id(), "cold");
    let path = dir.join("native");
    let mut s = Store::create(
        &path,
        &f.genesis,
        f.ledger.chain_id(),
        f.now,
        Limits::default(),
    )
    .unwrap();
    let raw = blocks(&f.history).remove(0);
    let before = s.head();
    let o = add(&mut s, &raw, f.now);
    drop(s);
    let s = Store::recover(
        &path,
        &f.genesis,
        f.ledger.chain_id(),
        before,
        o.block,
        f.now,
        Limits::default(),
    )
    .unwrap();
    assert_eq!(s.head(), o.head);
    drop(s);
    assert!(Store::recover(
        &path,
        &f.genesis,
        f.ledger.chain_id(),
        [0; 32],
        o.block,
        f.now,
        Limits::default()
    )
    .is_err());
    let mut saved = fs::read(&path).unwrap();
    let body_path = dir.join("changed-body");
    let mut changed = saved.clone();
    changed[165 + 4 + 52 + 269] ^= 1;
    let end = changed.len() - 32;
    let body_head: Hash =
        Sha256::digest([b"RLD-FAST-NODE-1/RECORD\0".as_slice(), &changed[169..end]].concat())
            .into();
    changed[end..].copy_from_slice(&body_head);
    fs::write(&body_path, &changed).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&body_path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(Store::open(
        &body_path,
        &f.genesis,
        f.ledger.chain_id(),
        body_head,
        f.now,
        Limits::default()
    )
    .is_err());
    assert_eq!(fs::read(&body_path).unwrap(), changed);
    let selected = 165 + 4 + 52 + raw.len();
    saved[selected..selected + 32].copy_from_slice(&f.ledger.chain_id());
    let end = saved.len() - 32;
    let forged: Hash =
        Sha256::digest([b"RLD-FAST-NODE-1/RECORD\0".as_slice(), &saved[169..end]].concat()).into();
    saved[end..].copy_from_slice(&forged);
    fs::write(&path, &saved).unwrap();
    assert!(Store::open(
        &path,
        &f.genesis,
        f.ledger.chain_id(),
        forged,
        f.now,
        Limits::default()
    )
    .is_err());
    assert_eq!(fs::read(&path).unwrap(), saved);
    let tail = dir.join("partial");
    fs::write(&tail, &saved[..saved.len() - 3]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tail, fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(Store::open(
        &tail,
        &f.genesis,
        f.ledger.chain_id(),
        o.head,
        f.now,
        Limits::default()
    )
    .is_err());
    assert_eq!(fs::read(&tail).unwrap(), saved[..saved.len() - 3]);
}
#[cfg(unix)]
#[test]
fn writer_lock_exact_prefix_and_inode_guard_native_current_authority() {
    use std::os::unix::fs::PermissionsExt;
    let f = fixture();
    let dir = directory(f.ledger.chain_id(), "identity");
    let path = dir.join("native");
    let mut s = Store::create(
        &path,
        &f.genesis,
        f.ledger.chain_id(),
        f.now,
        Limits::default(),
    )
    .unwrap();
    let head = s.head();
    assert!(Store::open(
        &path,
        &f.genesis,
        f.ledger.chain_id(),
        head,
        f.now,
        Limits::default()
    )
    .is_err());
    let exact = fs::read(&path).unwrap();
    fs::rename(&path, dir.join("original")).unwrap();
    fs::write(&path, &exact).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(s.current(head, f.ledger.chain_id(), f.now).is_err());
    assert!(!s.storage_ready());
    drop(s);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Store::open(
        &path,
        &f.genesis,
        f.ledger.chain_id(),
        head,
        f.now,
        Limits::default()
    )
    .is_err());
}
struct Process {
    child: Option<Child>,
    input: Option<ChildStdin>,
    output: mpsc::Receiver<String>,
    deadline: Instant,
    root: PathBuf,
    label: String,
}
enum Entry {
    Create,
    Serve(Hash),
    Recover(Hash, Hash),
}
impl Process {
    fn start(
        root: &Path,
        label: &str,
        genesis: &Path,
        chain: Hash,
        path: &Path,
        entry: Entry,
    ) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rld-fast-node"));
        command
            .arg(match entry {
                Entry::Create => "create",
                Entry::Serve(_) => "serve",
                Entry::Recover(_, _) => "recover",
            })
            .arg(path)
            .arg(genesis)
            .arg(hex::encode(chain));
        match entry {
            Entry::Create => {}
            Entry::Serve(h) => {
                command.arg(hex::encode(h));
            }
            Entry::Recover(h, b) => {
                command.arg(hex::encode(h)).arg(hex::encode(b));
            }
        }
        let mut c = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(fs::File::create(root.join(format!("{label}.stderr.log"))).unwrap())
            .spawn()
            .unwrap();
        let input = c.stdin.take().unwrap();
        let output = c.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        let log = root.join(format!("{label}.stdout.log"));
        std::thread::spawn(move || {
            let mut file = fs::File::create(log).unwrap();
            for l in BufReader::new(output).lines() {
                let l = l.unwrap();
                writeln!(file, "{l}").unwrap();
                if tx.send(l).is_err() {
                    break;
                }
            }
        });
        Self {
            child: Some(c),
            input: Some(input),
            output: rx,
            deadline: Instant::now() + Duration::from_secs(180),
            root: root.to_path_buf(),
            label: label.to_string(),
        }
    }
    fn receive(&self) -> serde_json::Value {
        let remain = self.deadline.saturating_duration_since(Instant::now());
        let line = self
            .output
            .recv_timeout(remain)
            .expect("original180 native process output");
        serde_json::from_str(&line).unwrap()
    }
    fn request(&mut self, head: Hash, tip: Hash, mut v: serde_json::Value) -> serde_json::Value {
        v["head"] = hex::encode(head).into();
        v["tip"] = hex::encode(tip).into();
        writeln!(self.input.as_mut().unwrap(), "{v}").unwrap();
        self.input.as_mut().unwrap().flush().unwrap();
        self.receive()
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
            assert!(
                Instant::now() < self.deadline,
                "original180 native process terminal"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        #[cfg(unix)]
        if kill {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(status.signal(), Some(9));
        }
        if !kill {
            assert!(status.success());
        }
        fs::write(self.root.join(format!("{}.terminal.json",self.label)),serde_json::json!({"pid":pid,"success":status.success(),"exit_code":status.code(),"controller_requested_kill":kill}).to_string()).unwrap();
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
fn hv(v: &serde_json::Value, k: &str) -> Hash {
    hex::decode(v[k].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}
fn actual_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
#[test]
fn actual_local_node_funding_reorg_cpu_mining_and_keyless_interruption_recovery() {
    use serde_json::json;
    let f = fixture();
    let dir = directory(f.ledger.chain_id(), "process");
    let genesis = dir.join("genesis");
    fs::write(&genesis, &f.genesis).unwrap();
    let path = dir.join("native");
    let mut creator = Process::start(
        &dir,
        "create",
        &genesis,
        f.ledger.chain_id(),
        &path,
        Entry::Create,
    );
    let created = creator.receive();
    assert_eq!(created["result"]["state"], "CREATED");
    let mut head = hv(&created, "storage_head");
    let mut tip = hv(&created, "selected_tip");
    creator.finish(false);
    let mut child = Process::start(
        &dir,
        "first",
        &genesis,
        f.ledger.chain_id(),
        &path,
        Entry::Serve(head),
    );
    let ready = child.receive();
    assert_eq!(hv(&ready, "storage_head"), head);
    let fake = child.request(
        head,
        tip,
        json!({"method":"status","ledger":{"balance":"999999"},"clock":0}),
    );
    assert!(fake["diagnostic"].is_string());
    assert_eq!(hv(&fake, "storage_head"), head);
    for raw in blocks(&f.history) {
        let r = child.request(
            head,
            tip,
            json!({"method":"accept_block","block":hex::encode(raw)}),
        );
        assert!(r["diagnostic"].is_null(), "{r}");
        head = hv(&r, "storage_head");
        tip = hv(&r, "selected_tip");
    }
    let funding = child.request(
        head,
        tip,
        json!({"method":"funding_origin","channel":hex::encode(f.channel)}),
    );
    assert_eq!(funding["result"]["current_local_backing"], true);
    let old_head = head;
    let mut fork = f.before.clone();
    let mut last = vec![];
    let mut prior = head;
    for _ in 0..2 {
        last = mine(
            &mut fork,
            f.retainer.verifying_key().to_bytes(),
            vec![],
            f.now,
        );
        prior = head;
        let r = child.request(
            head,
            tip,
            json!({"method":"accept_block","block":hex::encode(&last)}),
        );
        assert!(r["diagnostic"].is_null(), "{r}");
        head = hv(&r, "storage_head");
        tip = hv(&r, "selected_tip");
    }
    let absent = child.request(
        head,
        tip,
        json!({"method":"funding_origin","channel":hex::encode(f.channel)}),
    );
    assert!(absent["diagnostic"].as_str().unwrap().contains("MISSING"));
    let stale = child.request(old_head, tip, json!({"method":"status"}));
    assert!(stale["diagnostic"].is_string());
    child.finish(true);
    let mut recovered = Process::start(
        &dir,
        "recover",
        &genesis,
        f.ledger.chain_id(),
        &path,
        Entry::Recover(prior, fast::block_id(&last).unwrap()),
    );
    let r = recovered.receive();
    assert_eq!(r["result"]["state"], "EXACT_EXISTING_BLOCK_RECOVERED");
    assert_eq!(
        (hv(&r, "storage_head"), hv(&r, "selected_tip")),
        (head, tip)
    );
    recovered.finish(false);
    let mut child = Process::start(
        &dir,
        "restarted",
        &genesis,
        f.ledger.chain_id(),
        &path,
        Entry::Serve(head),
    );
    let ready = child.receive();
    assert_eq!(hv(&ready, "selected_tip"), tip);
    assert_eq!(ready["locked"], "0");
    let mut timestamp = fork.tip().timestamp() + 600;
    loop {
        let mut preview = fork
            .mining_job(
                f.miner.verifying_key().to_bytes(),
                vec![],
                timestamp,
                actual_now(),
            )
            .unwrap();
        if preview.search(1).0.is_none() {
            break;
        }
        timestamp += 1;
    }
    let timestamp = timestamp.to_string();
    let pending=child.request(head,tip,json!({"method":"mine","miner":hex::encode(f.miner.verifying_key().to_bytes()),"operations":[],"timestamp":timestamp,"attempts":1}));
    assert!(pending["diagnostic"].is_null(), "{pending}");
    assert_eq!(pending["result"]["state"], "SEARCH_PENDING");
    assert_eq!(pending["result"]["hash_calls"], "1");
    assert_eq!(hv(&pending, "storage_head"), head);
    let deadline = Instant::now() + Duration::from_secs(180);
    let r = loop {
        assert!(Instant::now() < deadline);
        let r=child.request(head,tip,json!({"method":"mine","miner":hex::encode(f.miner.verifying_key().to_bytes()),"operations":[],"timestamp":timestamp,"attempts":4096}));
        assert!(r["diagnostic"].is_null(), "{r}");
        if r["result"]["state"] == "BLOCK_ADMITTED" {
            break r;
        }
    };
    assert_ne!(hv(&r, "selected_tip"), tip);
    assert_eq!(r["height"], "104");
    assert_eq!(r["fast_completion_authorized"], false);
    let mined = hex::decode(r["result"]["block_hex"].as_str().unwrap()).unwrap();
    fork.execute(&mined, actual_now()).unwrap();
    assert_eq!(hv(&r, "selected_tip"), fork.tip().id());
    head = hv(&r, "storage_head");
    tip = hv(&r, "selected_tip");
    child.finish(false);
    let s = Store::open(
        &path,
        &f.genesis,
        f.ledger.chain_id(),
        head,
        actual_now(),
        Limits::default(),
    )
    .unwrap();
    assert_eq!(s.ledger().tip().id(), tip);
}

#[test]
fn warm_prefix_fault_suspends_current_authority_until_full_cold_verification() {
    let f = fixture();
    let dir = directory(f.ledger.chain_id(), "warm-corruption");
    let path = dir.join("native");
    let mut s = Store::create(
        &path,
        &f.genesis,
        f.ledger.chain_id(),
        f.now,
        Limits::default(),
    )
    .unwrap();
    let raw = blocks(&f.history).remove(0);
    let o = add(&mut s, &raw, f.now);
    assert!(s.check([0; 32], o.tip, f.now).is_err());
    assert!(s.storage_ready());
    let mut bytes = fs::read(&path).unwrap();
    let end = bytes.len() - 1;
    bytes[end] ^= 1;
    fs::write(&path, &bytes).unwrap();
    assert!(s.current(o.head, o.tip, f.now).is_err());
    assert!(!s.storage_ready());
    assert!(s.accept(&raw, o.head, o.tip, f.now).is_err());
    assert_eq!(fs::read(&path).unwrap(), bytes);
}
