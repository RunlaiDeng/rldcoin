//! PUBLIC NO-VALUE keys only. Separate same-host callers are not independent custody.
#[allow(dead_code)]
#[path = "support/fast_funding.rs"]
mod support;
use rld_survivor_node::{
    fast_session::{
        Action, Id, OpeningRequest, OpeningTerms, Session, TransferOutput, TransferRequest,
    },
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
const PASSWORD: &[u8] = b"public no-value joint opening passphrase";
fn dir(chain: Hash, label: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "rld-fast-opening-{}-{}-{label}",
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
    let mut f = o.open(p).unwrap();
    f.write_all(raw).unwrap();
    f.sync_all().unwrap();
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
fn terms(f: &Fixture) -> OpeningTerms {
    OpeningTerms {
        nonce: Id([91; 32]),
        owners: f
            .owners
            .each_ref()
            .map(|key| Id(key.verifying_key().to_bytes())),
        principal: ["100".into(), "100".into()],
        limits: ["10".into(), "10".into()],
        rates: ["2".into(), "3".into()],
        fees: ["1".into(), "1".into()],
        expiry: u128::MAX.to_string(),
        inputs: [
            vec![hex::encode(out(f.channel, 0))],
            vec![hex::encode(out(f.channel, 1))],
        ],
    }
}
fn request(proposal: &str, owner: u8, time: u64) -> OpeningRequest {
    OpeningRequest {
        proposal: proposal.into(),
        owner,
        timestamp: time.to_string(),
    }
}
fn sign(
    s: &mut Session,
    n: &mut u64,
    prepare: Id,
    review: Id,
    key: &Path,
    now: u64,
) -> (Id, Value) {
    let tip = Id(s.tip());
    exec(
        s,
        n,
        Action::OnchainSign {
            tip,
            prepare_request: prepare,
            review,
            key_file: key.to_string_lossy().into(),
            approved: true,
        },
        Some(PASSWORD),
        now,
    )
}
#[test]
fn separate_owner_reviews_combine_exact_existing_signatures_and_fund_native_value() {
    let deadline = Instant::now() + Duration::from_secs(180);
    let f = fixture();
    let chain = f.ledger.chain_id();
    let root = dir(chain, "joint");
    let a_path = root.join("a");
    let b_path = root.join("b");
    let (mut a, mut an) = funded(&f, &a_path);
    let (mut b, mut bn) = funded(&f, &b_path);
    let time = f.ledger.tip().timestamp() + 600;
    let proposal = a
        .opening_proposal(a.head(), terms(&f), time.to_string(), f.now)
        .unwrap();
    let raw = proposal["proposal_hex"].as_str().unwrap();
    let tip = Id(a.tip());
    let (ap, av) = exec(
        &mut a,
        &mut an,
        Action::OpenPrepare {
            tip,
            plan: request(raw, 0, time),
        },
        None,
        f.now,
    );
    assert!(av["diagnostic"].is_null(), "{av}");
    assert_eq!(av["review"]["own_index"], 0);
    assert_eq!(
        id(&av["review"], "chain_selected_tip"),
        Id(f.ledger.tip().id())
    );
    assert_eq!(av["review"]["evaluation_timestamp"], time.to_string());
    let ar = id(&av, "review_digest");
    // Reviewing owner0 reserves none of owner1's ordinary funds.
    let value = f.ledger.coins()[&out(f.channel, 1)].amount;
    let transfer = TransferRequest {
        owner: Id(f.owners[1].verifying_key().to_bytes()),
        inputs: vec![hex::encode(out(f.channel, 1))],
        outputs: vec![TransferOutput {
            owner: Id(f.owners[1].verifying_key().to_bytes()),
            amount: (value - 1).to_string(),
        }],
        fee: "1".into(),
        expiry: u128::MAX.to_string(),
        timestamp: time.to_string(),
    };
    let (_, v) = exec(
        &mut a,
        &mut an,
        Action::TransferPrepare {
            tip,
            plan: transfer,
        },
        None,
        f.now,
    );
    assert!(v["diagnostic"].is_null(), "{v}");
    let tip = Id(b.tip());
    let (bp, bv) = exec(
        &mut b,
        &mut bn,
        Action::OpenPrepare {
            tip,
            plan: request(raw, 1, time),
        },
        None,
        f.now,
    );
    assert!(bv["diagnostic"].is_null());
    let br = id(&bv, "review_digest");
    assert_ne!(ar, br);
    let keys = [root.join("owner-a.key"), root.join("owner-b.key")];
    for (i, key) in keys.iter().enumerate() {
        write(
            key,
            &keyfile::encrypt(&f.owners[i], chain, PASSWORD).unwrap(),
        );
    }
    let (asign, av) = sign(&mut a, &mut an, ap, ar, &keys[0], f.now);
    let (_, bv) = sign(&mut b, &mut bn, bp, br, &keys[1], f.now);
    assert!(av["diagnostic"].is_null(), "{av}");
    assert!(bv["diagnostic"].is_null(), "{bv}");
    assert!(av["operation_hex"].is_null());
    let own = hex::decode(av["opening_partial_hex"].as_str().unwrap()).unwrap();
    let partner = hex::decode(bv["opening_partial_hex"].as_str().unwrap()).unwrap();
    assert_eq!(own.len(), 65);
    assert!(fast::validate_operation(&own, chain).is_err());
    let h = a.head();
    let i = rid(&mut an);
    assert!(a
        .submit_authorized(h, i, asign, f.now)
        .unwrap_err()
        .contains("not a complete operation"));
    assert_eq!(a.head(), h);
    let tip = Id(a.tip());
    let (_, bad) = exec(
        &mut a,
        &mut an,
        Action::OpenCombine {
            tip,
            prepare_request: ap,
            sign_request: asign,
            review: ar,
            counterparty_partial: hex::encode(&own),
        },
        None,
        f.now,
    );
    assert!(bad["diagnostic"].is_string());
    assert!(bad["operation_hex"].is_null());
    let action = Action::OpenCombine {
        tip,
        prepare_request: ap,
        sign_request: asign,
        review: ar,
        counterparty_partial: hex::encode(partner),
    };
    let prior = a.head();
    let (combined, v) = exec(&mut a, &mut an, action.clone(), None, f.now);
    assert!(v["diagnostic"].is_null(), "{v}");
    let complete = hex::decode(v["operation_hex"].as_str().unwrap()).unwrap();
    fast::validate_operation(&complete, chain).unwrap();
    let channel = fast::operation_id(&complete);
    assert_eq!(id(&v, "operation_id").0, channel);
    let head = a.head();
    drop(a);
    drop(b);
    for (i, key) in keys.iter().enumerate() {
        fs::rename(key, root.join(format!("retained-key-{i}"))).unwrap();
    }
    let (mut a, recovered) = Session::recover(
        &a_path,
        &f.genesis,
        chain,
        prior,
        combined,
        action.digest().unwrap(),
        f.now,
    )
    .unwrap();
    assert_eq!(a.head(), head);
    assert_eq!(recovered["operation_hex"], v["operation_hex"]);
    assert_eq!(recovered["key_loaded_by_recovery"], false);
    let i = rid(&mut an);
    let v = a.submit_authorized(a.head(), i, combined, f.now).unwrap();
    assert_eq!(id(&v, "pool_operation").0, channel);
    let mut ledger = f.ledger.clone();
    let block = mine(
        &mut ledger,
        f.miner.verifying_key().to_bytes(),
        vec![complete],
        f.now,
    );
    let tip = Id(a.tip());
    let (_, v) = exec(
        &mut a,
        &mut an,
        Action::Native {
            tip,
            block: hex::encode(block),
        },
        None,
        f.now,
    );
    assert!(v["diagnostic"].is_null());
    let origin = ledger.funding_origin(channel).unwrap();
    assert_eq!(origin.initial(), [100, 100]);
    assert_eq!(origin.miner(), f.miner.verifying_key().to_bytes());
    assert_eq!(ledger.active_channels(), 2);
    let head = a.head();
    drop(a);
    Session::open(&a_path, &f.genesis, chain, head, f.now).unwrap();
    assert!(Instant::now() < deadline, "original180 joint opening");
}

#[test]
fn manual_public_opening_vectors_and_versioned_frames_require_exact_owner_proofs() {
    use rld_survivor_node::fast_peer::codec;
    let v: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/fast-native-opening-v1-vectors.json"
    ))
    .unwrap();
    assert_eq!(v["network_kind"], json!("NO_VALUE_ONLY"));
    let raw = |k: &str| hex::decode(v[k].as_str().unwrap()).unwrap();
    let chain: Hash = raw("chain_hex").try_into().unwrap();
    let proposal = raw("proposal_hex");
    let partial = hex::decode(v["partials_hex"][0].as_str().unwrap()).unwrap();
    assert_eq!(
        fast::opening::proposal_id(&proposal, chain)
            .unwrap()
            .as_slice(),
        raw("proposal_id_hex")
    );
    assert_eq!(
        fast::opening::verify_partial(&proposal, &partial, chain).unwrap(),
        0
    );
    let frame = codec::opening_payload(chain, &proposal, None).unwrap();
    assert_eq!(frame, raw("proposal_frame_hex"));
    assert_eq!(
        codec::opening_frame(&frame, chain, false).unwrap().0,
        proposal
    );
    let signed = codec::opening_payload(chain, &proposal, Some(&partial)).unwrap();
    assert_eq!(signed, raw("partial_frame_hex"));
    assert_eq!(
        codec::opening_frame(&signed, chain, true)
            .unwrap()
            .1
            .unwrap(),
        partial
    );
    let complete = raw("complete_operation_hex");
    fast::validate_operation(&complete, chain).unwrap();
    assert_eq!(
        fast::operation_id(&complete).as_slice(),
        raw("complete_operation_id_hex")
    );
    assert_eq!(complete.len(), 493);
    for (kind, data) in [(7, &frame), (8, &signed)] {
        codec::payload(kind, data, chain).unwrap();
        for pos in [0, 4, 36, 37] {
            let mut bad = data.clone();
            bad[pos] ^= 1;
            assert!(codec::payload(kind, &bad, chain).is_err());
        }
        let mut bad = data.clone();
        bad.push(0);
        assert!(codec::payload(kind, &bad, chain).is_err());
    }
    for pos in [38 + 37, signed.len() - 1] {
        let mut bad = signed.clone();
        bad[pos] ^= 1;
        assert!(codec::opening_frame(&bad, chain, true).is_err());
    }
    assert!(codec::payload(9, &signed, chain).is_err());
    assert!(codec::opening_frame(&signed, [1; 32], true).is_err());
    assert!(fast::validate_operation(&partial, chain).is_err());
}

#[test]
fn maximum_joint_opening_preserves_all_sixty_four_inputs_and_small_reply_recovery() {
    let deadline = Instant::now() + Duration::from_secs(180);
    let f = fixture();
    let chain = f.ledger.chain_id();
    let root = dir(chain, "maximum");
    let a_path = root.join("a");
    let b_path = root.join("b");
    let (mut a, mut an) = funded(&f, &a_path);
    let (mut b, mut bn) = funded(&f, &b_path);
    let mut ledger = f.ledger.clone();
    let mut large = [out(f.channel, 0), out(f.channel, 1)];
    let mut small = [Vec::new(), Vec::new()];
    for _ in 0..5 {
        let mut ops = vec![];
        for i in 0..2 {
            let owner = f.owners[i].verifying_key().to_bytes();
            let value = ledger.coins()[&large[i]].amount;
            let mut outputs = vec![(owner, 10); 7];
            outputs.push((owner, value - 71));
            let (op, tx) = ordinary(chain, &f.owners[i], &large[i], &outputs);
            for j in 0..7 {
                small[i].push(out(tx, j));
            }
            large[i] = out(tx, 7);
            ops.push(op);
        }
        let raw = mine(&mut ledger, f.miner.verifying_key().to_bytes(), ops, f.now);
        for (s, n) in [(&mut a, &mut an), (&mut b, &mut bn)] {
            let tip = Id(s.tip());
            let (_, v) = exec(
                s,
                n,
                Action::Native {
                    tip,
                    block: hex::encode(&raw),
                },
                None,
                f.now,
            );
            assert!(v["diagnostic"].is_null(), "{v}");
        }
    }
    let time = ledger.tip().timestamp() + 600;
    let mut input = terms(&f);
    for (i, v) in small.iter_mut().enumerate() {
        v.sort();
        v.truncate(32);
        input.inputs[i] = v.iter().map(hex::encode).collect();
    }
    let v = a
        .opening_proposal(a.head(), input, time.to_string(), f.now)
        .unwrap();
    let proposal = v["proposal_hex"].as_str().unwrap();
    assert_eq!(proposal.len(), 2473 * 2);
    let keys = [root.join("a.key"), root.join("b.key")];
    for (i, path) in keys.iter().enumerate() {
        write(
            path,
            &keyfile::encrypt(&f.owners[i], chain, PASSWORD).unwrap(),
        );
    }
    let tip = Id(a.tip());
    let (ap, av) = exec(
        &mut a,
        &mut an,
        Action::OpenPrepare {
            tip,
            plan: request(proposal, 0, time),
        },
        None,
        f.now,
    );
    assert!(av["diagnostic"].is_null());
    let ar = id(&av, "review_digest");
    let (asign, av) = sign(&mut a, &mut an, ap, ar, &keys[0], f.now);
    assert!(av["diagnostic"].is_null());
    let (bp, bv) = exec(
        &mut b,
        &mut bn,
        Action::OpenPrepare {
            tip,
            plan: request(proposal, 1, time),
        },
        None,
        f.now,
    );
    let br = id(&bv, "review_digest");
    let (_, bv) = sign(&mut b, &mut bn, bp, br, &keys[1], f.now);
    assert!(bv["diagnostic"].is_null());
    let action = Action::OpenCombine {
        tip,
        prepare_request: ap,
        sign_request: asign,
        review: ar,
        counterparty_partial: bv["opening_partial_hex"].as_str().unwrap().into(),
    };
    let prior = a.head();
    let (combined, v) = exec(&mut a, &mut an, action.clone(), None, f.now);
    assert!(v["diagnostic"].is_null(), "{v}");
    let raw = hex::decode(v["operation_hex"].as_str().unwrap()).unwrap();
    assert_eq!(raw.len(), 2601);
    let channel = fast::operation_id(&raw);
    let head = a.head();
    drop(a);
    drop(b);
    for (i, path) in keys.iter().enumerate() {
        fs::rename(path, root.join(format!("retained-key-{i}"))).unwrap();
    }
    let (mut a, recovered) = Session::recover(
        &a_path,
        &f.genesis,
        chain,
        prior,
        combined,
        action.digest().unwrap(),
        f.now,
    )
    .unwrap();
    assert_eq!(a.head(), head);
    assert_eq!(recovered["operation_hex"], v["operation_hex"]);
    assert_eq!(recovered["key_loaded_by_recovery"], false);
    let i = rid(&mut an);
    a.submit_authorized(a.head(), i, combined, f.now).unwrap();
    let block = mine(
        &mut ledger,
        f.miner.verifying_key().to_bytes(),
        vec![raw],
        f.now,
    );
    let tip = Id(a.tip());
    let (_, v) = exec(
        &mut a,
        &mut an,
        Action::Native {
            tip,
            block: hex::encode(block),
        },
        None,
        f.now,
    );
    assert!(v["diagnostic"].is_null());
    assert_eq!(
        ledger.funding_origin(channel).unwrap().initial(),
        [100, 100]
    );
    let head = a.head();
    drop(a);
    Session::open(&a_path, &f.genesis, chain, head, f.now).unwrap();
    assert!(
        Instant::now() < deadline,
        "original180 maximum joint opening"
    );
}

#[test]
fn invalid_joint_terms_partial_owners_and_cross_operation_reservations_refuse_without_signing() {
    let deadline = Instant::now() + Duration::from_secs(180);
    let f = fixture();
    let chain = f.ledger.chain_id();
    let root = dir(chain, "refusal");
    let (mut s, mut n) = funded(&f, &root.join("session"));
    let time = f.ledger.tip().timestamp() + 600;
    let good = terms(&f);
    let mut cases = vec![];
    let mut p = good.clone();
    p.owners[1] = p.owners[0];
    cases.push(p);
    let mut p = good.clone();
    p.inputs[1] = p.inputs[0].clone();
    cases.push(p);
    let mut p = good.clone();
    p.limits[0] = "0".into();
    cases.push(p);
    let mut p = good.clone();
    p.limits[0] = "1000001".into();
    cases.push(p);
    let mut p = good.clone();
    p.rates[0] = "0".into();
    cases.push(p);
    let mut p = good.clone();
    p.fees[0] = "0".into();
    cases.push(p);
    let mut p = good.clone();
    p.principal[0] = "1350".into();
    cases.push(p);
    let mut p = good.clone();
    p.principal[0] = "9999".into();
    cases.push(p);
    let mut p = good.clone();
    p.expiry = f.ledger.tip().height().to_string();
    cases.push(p);
    let mut p = good.clone();
    p.nonce = Id([0; 32]);
    cases.push(p);
    let head = s.head();
    for p in cases {
        assert!(s
            .opening_proposal(head, p, time.to_string(), f.now)
            .is_err());
        assert_eq!(s.head(), head);
    }
    let proposal = s
        .opening_proposal(head, good, time.to_string(), f.now)
        .unwrap();
    let raw = proposal["proposal_hex"].as_str().unwrap();
    let tip = Id(s.tip());
    let invalid = Action::OpenPrepare {
        tip,
        plan: request(raw, 2, time),
    };
    let i = rid(&mut n);
    assert!(s.execute(i, head, invalid, None, f.now).is_err());
    assert_eq!(s.head(), head);
    let (prepare, v) = exec(
        &mut s,
        &mut n,
        Action::OpenPrepare {
            tip,
            plan: request(raw, 0, time),
        },
        None,
        f.now,
    );
    assert!(v["diagnostic"].is_null());
    let review = id(&v, "review_digest");
    let value = f.ledger.coins()[&out(f.channel, 0)].amount;
    let transfer = TransferRequest {
        owner: Id(f.owners[0].verifying_key().to_bytes()),
        inputs: vec![hex::encode(out(f.channel, 0))],
        outputs: vec![TransferOutput {
            owner: Id(f.owners[0].verifying_key().to_bytes()),
            amount: (value - 1).to_string(),
        }],
        fee: "1".into(),
        expiry: u128::MAX.to_string(),
        timestamp: time.to_string(),
    };
    let head = s.head();
    let i = rid(&mut n);
    assert!(s
        .execute(
            i,
            head,
            Action::TransferPrepare {
                tip,
                plan: transfer.clone()
            },
            None,
            f.now
        )
        .unwrap_err()
        .contains("reserved"));
    assert_eq!(s.head(), head);
    let bad_sign = Action::OnchainSign {
        tip,
        prepare_request: prepare,
        review,
        key_file: root.join("absent.key").to_string_lossy().into(),
        approved: false,
    };
    let (_, v) = exec(&mut s, &mut n, bad_sign, None, f.now);
    assert!(v["diagnostic"].is_string());
    assert!(!v["diagnostic"].as_str().unwrap().contains("MISSING key"));
    assert!(v["opening_partial_hex"].is_null());
    let key = root.join("wrong-owner.key");
    write(
        &key,
        &keyfile::encrypt(&f.owners[1], chain, PASSWORD).unwrap(),
    );
    let (_, v) = sign(&mut s, &mut n, prepare, review, &key, f.now);
    assert!(v["diagnostic"].as_str().unwrap().contains("spending key"));
    assert!(v["opening_partial_hex"].is_null());
    let (mut reverse, mut rn) = funded(&f, &root.join("reverse"));
    let (_, v) = exec(
        &mut reverse,
        &mut rn,
        Action::TransferPrepare {
            tip,
            plan: transfer,
        },
        None,
        f.now,
    );
    assert!(v["diagnostic"].is_null());
    let head = reverse.head();
    let i = rid(&mut rn);
    assert!(reverse
        .execute(
            i,
            head,
            Action::OpenPrepare {
                tip,
                plan: request(raw, 0, time)
            },
            None,
            f.now
        )
        .unwrap_err()
        .contains("reserved"));
    assert_eq!(reverse.head(), head);
    // A changed native head cannot silently rebase the approved opening.
    let mut ledger = f.ledger.clone();
    let block = mine(
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
            block: hex::encode(block),
        },
        None,
        f.now,
    );
    let tip = Id(s.tip());
    let a = Action::OnchainSign {
        tip,
        prepare_request: prepare,
        review,
        key_file: root.join("missing.key").to_string_lossy().into(),
        approved: true,
    };
    let (_, v) = exec(&mut s, &mut n, a, None, f.now);
    assert!(v["diagnostic"]
        .as_str()
        .unwrap()
        .contains("changed review tip"));
    assert!(v["opening_partial_hex"].is_null());
    assert!(Instant::now() < deadline, "original180 opening refusal");
}

struct Launch {
    state: PathBuf,
    peer: PathBuf,
    head: Id,
    peer_head: Id,
}
struct Node {
    child: Option<std::process::Child>,
    input: Option<std::process::ChildStdin>,
    rx: std::sync::mpsc::Receiver<String>,
    head: Id,
    tip: Id,
    peer: Id,
    count: u64,
    deadline: Instant,
    terminal: PathBuf,
}
impl Node {
    fn start(
        root: &Path,
        label: &str,
        genesis: &Path,
        chain: Hash,
        launch: &Launch,
        deadline: Instant,
    ) -> Self {
        use std::{
            io::{BufRead, BufReader},
            process::{Command, Stdio},
        };
        let mut child = Command::new(env!("CARGO_BIN_EXE_rld-fast-payment-session"))
            .args([
                "serve",
                launch.state.to_str().unwrap(),
                genesis.to_str().unwrap(),
                &hex::encode(chain),
                &hex::encode(launch.head.0),
                "--peer-root",
                launch.peer.to_str().unwrap(),
                "--peer-head",
                &hex::encode(launch.peer_head.0),
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
            head: launch.head,
            tip: Id(chain),
            peer: launch.peer_head,
            count: 0,
            deadline,
            terminal: root.join(format!("{label}.terminal.json")),
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
                .expect("original180 opening process response"),
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
        if v["peer"]["peer_head"].is_string() {
            self.peer = id(&v["peer"], "peer_head");
        }
    }
    fn send(&mut self, mut v: Value) -> Value {
        assert!(
            Instant::now() < self.deadline,
            "original180 opening request"
        );
        v["head"] = serde_json::to_value(self.head).unwrap();
        writeln!(self.input.as_mut().unwrap(), "{v}").unwrap();
        self.input.as_mut().unwrap().flush().unwrap();
        let v = self.receive();
        self.update(&v);
        v
    }
    fn ok(&mut self, v: Value) -> Value {
        let v = self.send(v);
        assert!(v["diagnostic"].is_null(), "{v}");
        v
    }
    fn request(&mut self) -> Id {
        rid(&mut self.count)
    }
    fn execute(&mut self, action: Action, password: Option<&str>) -> (Id, Value) {
        let i = self.request();
        let v = self
            .ok(json!({"command":"execute","request_id":i,"action":action,"password":password}));
        (i, v)
    }
    fn wait(&mut self, packet: Id) {
        loop {
            let v = self.send(json!({"command":"peer_data","packet":packet}));
            if v["diagnostic"].is_null() {
                return;
            }
            assert!(Instant::now() < self.deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn import(&mut self, packet: Id) {
        self.wait(packet);
        let i = self.request();
        self.ok(json!({"command":"peer_import","packet":packet,"request_id":i}));
    }
    fn sign(&mut self, prepare: Id, review: Id, key: &Path) -> (Id, Value) {
        self.execute(
            Action::OnchainSign {
                tip: self.tip,
                prepare_request: prepare,
                review,
                key_file: key.to_string_lossy().into(),
                approved: true,
            },
            Some(std::str::from_utf8(PASSWORD).unwrap()),
        )
    }
    fn authorize(&mut self, action: Action, key: &Path) -> (Id, Value) {
        let (p, v) = self.execute(action, None);
        let (s, _) = self.sign(p, id(&v, "review_digest"), key);
        let i = self.request();
        let queued =
            self.ok(json!({"command":"submit_authorized","request_id":i,"sign_request":s}));
        (id(&queued, "pool_operation"), v)
    }
    fn mine(&mut self, miner: Id, time: u64) -> (Id, Vec<u8>) {
        let mut refresh = true;
        loop {
            let v=self.ok(json!({"command":"mine_pool","miner":miner,"timestamp":time.to_string(),"attempts":4096,"scan_limit":128,"refresh":refresh}));
            refresh = false;
            if v["candidate"].is_string() {
                let candidate = id(&v, "candidate");
                let raw = hex::decode(v["block_hex"].as_str().unwrap()).unwrap();
                let i = self.request();
                let v = self
                    .ok(json!({"command":"admit_candidate","request_id":i,"candidate":candidate}));
                assert_eq!(v["candidate_selected"], true);
                return (candidate, raw);
            }
        }
    }
    fn block(&mut self, block: Id, destination: Id) -> Id {
        let v = self.ok(json!({"command":"peer_block","block":block,"destination":destination}));
        id(&v, "packet")
    }
    fn drain(&mut self) {
        loop {
            let v = self.ok(json!({"command":"peer_inventory"}));
            if !v["packets"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["received"] == false && p["destination_transport_custody"] != true)
            {
                return;
            }
            assert!(Instant::now() < self.deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn finish(&mut self) {
        self.drain();
        self.ok(json!({"command":"peer_status"}));
        self.input.take();
        let c = self.child.as_mut().unwrap();
        let pid = c.id();
        let status = loop {
            if let Some(s) = c.try_wait().unwrap() {
                break s;
            }
            assert!(
                Instant::now() < self.deadline,
                "original180 opening process stop"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(status.success());
        write(
            &self.terminal,
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
            let pid = c.id();
            let _ = c.kill();
            let status = c.wait();
            if let Ok(mut file) = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&self.terminal)
            {
                let _ = writeln!(
                    file,
                    "{}",
                    json!({"pid":pid,"status":format!("{status:?}"),"success":false,"forced_stop":true,"reason":"OWNED_TEST_FAILURE_GUARD"})
                );
                let _ = file.sync_all();
            }
        }
    }
}

#[test]
fn actual_peers_jointly_fund_pay_onward_restart_and_submit_native_exit_challenges() {
    use ed25519_dalek::Signer;
    use rld_survivor_node::{
        fast_payment::{Delegation, Payment},
        fast_peer::{self, Config, PeerPin},
        fast_session::OnchainRequest,
    };
    use std::net::TcpListener;
    let deadline = Instant::now() + Duration::from_secs(180);
    let f = fixture();
    let chain = f.ledger.chain_id();
    let root = dir(chain, "peers");
    let genesis = root.join("genesis");
    write(&genesis, &f.genesis);
    let peer_roots = (0..3)
        .map(|i| root.join(format!("peer-{i}")))
        .collect::<Vec<_>>();
    let infos = peer_roots
        .iter()
        .map(|p| fast_peer::provision(p, chain).unwrap())
        .collect::<Vec<_>>();
    let listeners = (0..3)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect::<Vec<_>>();
    let addresses = listeners
        .iter()
        .map(|l| l.local_addr().unwrap())
        .collect::<Vec<_>>();
    let mut launches = vec![];
    for i in 0..3 {
        let config = Config {
            chain: Id(chain),
            identity: id(&infos[i], "identity"),
            listen: addresses[i],
            peers: (0..3)
                .filter(|j| *j != i)
                .map(|j| PeerPin {
                    key: id(&infos[j], "identity"),
                    endpoint: addresses[j],
                    certificate_sha256: id(&infos[j], "certificate_sha256"),
                })
                .collect(),
        };
        let peer_head = id(
            &fast_peer::bind(&peer_roots[i], &serde_json::to_vec(&config).unwrap(), f.now).unwrap(),
            "peer_head",
        );
        let state = root.join(format!("node-{i}"));
        let s = Session::create(&state, &f.genesis, chain, f.now).unwrap();
        launches.push(Launch {
            state,
            peer: peer_roots[i].clone(),
            head: Id(s.head()),
            peer_head,
        });
    }
    drop(listeners);
    let mut nodes = launches
        .iter()
        .enumerate()
        .map(|(i, l)| Node::start(&root, &format!("node-{i}"), &genesis, chain, l, deadline))
        .collect::<Vec<_>>();
    // Carry only the genuine ordinary funding history. The fixture's prebuilt
    // escrow opening is never imported into these three nodes.
    let mut at = 0;
    let mut height = 0;
    let mut packets = [vec![], vec![]];
    while height < f.before.tip().height() {
        let z = u32::from_be_bytes(f.history[at..at + 4].try_into().unwrap()) as usize;
        at += 4;
        let raw = &f.history[at..at + z];
        at += z;
        height += 1;
        let tip = nodes[0].tip;
        nodes[0].execute(
            Action::Native {
                tip,
                block: hex::encode(raw),
            },
            None,
        );
        let block = Id(fast::block_id(raw).unwrap());
        for i in 1..3 {
            packets[i - 1].push(nodes[0].block(block, id(&infos[i], "identity")));
        }
    }
    for i in 1..3 {
        for packet in &packets[i - 1] {
            nodes[i].import(*packet);
        }
        assert_eq!(nodes[i].tip.0, f.before.tip().id());
    }
    let time = f.before.tip().timestamp() + 600;
    let mut input = terms(&f);
    for i in 0..2 {
        let owner = f.owners[i].verifying_key().to_bytes();
        let coin = f
            .before
            .coins()
            .iter()
            .find(|(_, c)| c.owner == owner && c.amount == 2000)
            .unwrap()
            .0;
        input.inputs[i] = vec![hex::encode(coin)];
    }
    let proposal = nodes[0]
        .ok(json!({"command":"opening_proposal","terms":input,"timestamp":time.to_string()}));
    let proposal_hex = proposal["proposal_hex"].as_str().unwrap();
    let tip = nodes[0].tip;
    let (ap, av) = nodes[0].execute(
        Action::OpenPrepare {
            tip,
            plan: request(proposal_hex, 0, time),
        },
        None,
    );
    let ar = id(&av, "review_digest");
    let v=nodes[0].ok(json!({"command":"peer_opening","source_request":ap,"destination":id(&infos[1],"identity")}));
    let packet = id(&v, "packet");
    nodes[1].wait(packet);
    let bp = nodes[1].request();
    let bv=nodes[1].ok(json!({"command":"peer_open_prepare","packet":packet,"request_id":bp,"owner":1,"timestamp":time.to_string()}));
    let br = id(&bv, "review_digest");
    assert_ne!(ar, br);
    let keys = (0..3)
        .map(|i| root.join(format!("signing-{i}.key")))
        .collect::<Vec<_>>();
    for (i, path) in keys.iter().enumerate() {
        let key = if i < 2 { &f.owners[i] } else { &f.retainer };
        write(path, &keyfile::encrypt(key, chain, PASSWORD).unwrap());
    }
    let (asign, av) = nodes[0].sign(ap, ar, &keys[0]);
    let (bsign, bv) = nodes[1].sign(bp, br, &keys[1]);
    assert!(av["operation_hex"].is_null());
    assert!(bv["operation_hex"].is_null());
    let v=nodes[1].ok(json!({"command":"peer_opening","source_request":bsign,"destination":id(&infos[0],"identity")}));
    let partial_packet = id(&v, "packet");
    nodes[0].wait(partial_packet);
    let combined = nodes[0].request();
    let v=nodes[0].ok(json!({"command":"peer_open_combine","packet":partial_packet,"request_id":combined,"prepare_request":ap,"sign_request":asign,"review":ar}));
    let channel = id(&v, "operation_id");
    let i = nodes[0].request();
    nodes[0].ok(json!({"command":"submit_authorized","request_id":i,"sign_request":combined}));
    let miner = Id(f.miner.verifying_key().to_bytes());
    let (block, raw) = nodes[0].mine(miner, time);
    let mut verified = f.before.clone();
    verified.execute(&raw, f.now + 180).unwrap();
    assert_eq!(verified.active_channels(), 1);
    let origin = verified.funding_origin(channel.0).unwrap();
    for i in 1..3 {
        let packet = nodes[0].block(block, id(&infos[i], "identity"));
        nodes[i].import(packet);
    }
    // Restart with the owner key unavailable; retransmitting its retained
    // opening partial cannot first-sign or require that key.
    for n in &mut nodes {
        n.drain();
    }
    nodes[1].finish();
    launches[1].head = nodes[1].head;
    launches[1].peer_head = nodes[1].peer;
    fs::rename(&keys[1], root.join("temporarily-retained-owner.key")).unwrap();
    nodes[1] = Node::start(
        &root,
        "owner-restarted",
        &genesis,
        chain,
        &launches[1],
        deadline,
    );
    nodes[1].count = 10000;
    let v=nodes[1].ok(json!({"command":"peer_opening","source_request":bsign,"destination":id(&infos[0],"identity")}));
    assert_eq!(id(&v, "packet"), partial_packet);
    fs::rename(root.join("temporarily-retained-owner.key"), &keys[1]).unwrap();
    let mut delegation =
        Delegation::unsigned(&origin, f.retainer.verifying_key().to_bytes()).unwrap();
    let signature = f
        .miner
        .sign(&[tag("DELEGATION"), delegation.clone()].concat());
    delegation.extend(signature.to_bytes());
    let delegation = hex::encode(Delegation::verify(&origin, &delegation).unwrap().bytes());
    let mut actors = vec![];
    for (i, node) in nodes.iter_mut().enumerate() {
        let tip = node.tip;
        let action = if i < 2 {
            Action::OwnerCreate {
                tip,
                channel,
                owner: i as u8,
                delegation: delegation.clone(),
            }
        } else {
            Action::RetainerCreate {
                tip,
                channel,
                delegation: delegation.clone(),
            }
        };
        let (_, v) = node.execute(action, None);
        actors.push(id(&v, "actor"));
    }
    let mut last = vec![];
    for (payer, amount, nonce) in [(0usize, "7", 85u8), (1, "3", 86)] {
        let receiver = 1 - payer;
        let inv = Id([nonce; 32]);
        let v=nodes[payer].ok(json!({"command":"propose","actor":actors[payer],"payer":payer,"amount":amount,"invoice":inv}));
        let inv = id(&v, "invoice_id");
        let tip = nodes[payer].tip;
        let (pr, pv) = nodes[payer].execute(
            Action::OwnerPrepare {
                tip,
                actor: actors[payer],
                invoice: v["invoice_hex"].as_str().unwrap().into(),
            },
            None,
        );
        let v=nodes[payer].ok(json!({"command":"peer_invoice","actor":actors[payer],"invoice":inv,"destination":id(&infos[receiver],"identity")}));
        let packet = id(&v, "packet");
        nodes[receiver].wait(packet);
        let rr = nodes[receiver].request();
        let rv=nodes[receiver].ok(json!({"command":"peer_prepare","actor":actors[receiver],"packet":packet,"request_id":rr}));
        for (i, r, v) in [(payer, pr, &pv), (receiver, rr, &rv)] {
            let tip = nodes[i].tip;
            nodes[i].execute(
                Action::OwnerSign {
                    tip,
                    actor: actors[i],
                    invoice: inv,
                    review_request: r,
                    review: id(v, "review_digest"),
                    key_file: keys[i].to_string_lossy().into(),
                    approved: true,
                },
                Some(std::str::from_utf8(PASSWORD).unwrap()),
            );
        }
        let mut partials = vec![];
        for i in 0..2 {
            let v=nodes[i].ok(json!({"command":"peer_partial","actor":actors[i],"invoice":inv,"destination":id(&infos[1-i],"identity")}));
            partials.push(id(&v, "packet"));
        }
        nodes[0].wait(partials[1]);
        nodes[1].wait(partials[0]);
        let v=nodes[0].ok(json!({"command":"peer_combine_send","actor":actors[0],"invoice":inv,"partial":partials[1],"destinations":[id(&infos[2],"identity")]}));
        let packet = id(&v["sent"][0], "packet");
        nodes[2].wait(packet);
        let r = nodes[2].request();
        let v = nodes[2]
            .ok(json!({"command":"peer_prepare","actor":actors[2],"packet":packet,"request_id":r}));
        let receipt = id(&v["review"], "receipt_id");
        let tip = nodes[2].tip;
        nodes[2].execute(
            Action::RetainerSign {
                tip,
                actor: actors[2],
                receipt,
                review_request: r,
                review: id(&v, "review_digest"),
                key_file: keys[2].to_string_lossy().into(),
                approved: true,
            },
            Some(std::str::from_utf8(PASSWORD).unwrap()),
        );
        for i in 0..2 {
            let v=nodes[2].ok(json!({"command":"peer_ack","actor":actors[2],"receipt":receipt,"destination":id(&infos[i],"identity")}));
            let packet = id(&v, "packet");
            nodes[i].wait(packet);
            let r = nodes[i].request();
            let v=nodes[i].ok(json!({"command":"peer_complete","actor":actors[i],"invoice":inv,"partial":partials[1-i],"ack":packet,"request_id":r}));
            assert_eq!(v["fast_completion_authorized"], false);
            last = hex::decode(v["receipt_hex"].as_str().unwrap()).unwrap();
        }
    }
    let payment = Payment::verify(&origin, &last).unwrap();
    assert_eq!(
        origin
            .verify_certificate(payment.after_certificate())
            .unwrap()
            .balances,
        [96, 104]
    );
    let evidence = nodes[2].ok(json!({"command":"exit_evidence","actor":actors[2]}));
    assert_eq!(evidence["sequence"], "2");
    let certificate = evidence["certificate_hex"].as_str().unwrap().to_owned();
    let closing = OnchainRequest {
        kind: 2,
        channel,
        actor: Id(f.owners[0].verifying_key().to_bytes()),
        inputs: vec![hex::encode(out(channel.0, 0))],
        fee: "1".into(),
        expiry: u128::MAX.to_string(),
        nonce: Id([92; 32]),
        certificate: String::new(),
        timestamp: (time + 600).to_string(),
    };
    let tip = nodes[0].tip;
    let (close, _) = nodes[0].authorize(Action::OnchainPrepare { tip, plan: closing }, &keys[0]);
    let (close_block, _) = nodes[0].mine(miner, time + 600);
    let change = 1879u128 - 1;
    let funding = TransferRequest {
        owner: Id(f.owners[0].verifying_key().to_bytes()),
        inputs: vec![hex::encode(out(close.0, 0))],
        outputs: vec![
            TransferOutput {
                owner: Id(f.retainer.verifying_key().to_bytes()),
                amount: "100".into(),
            },
            TransferOutput {
                owner: Id(f.owners[0].verifying_key().to_bytes()),
                amount: (change - 101).to_string(),
            },
        ],
        fee: "1".into(),
        expiry: u128::MAX.to_string(),
        timestamp: (time + 1200).to_string(),
    };
    let tip = nodes[0].tip;
    let (_, v) = nodes[0].authorize(Action::TransferPrepare { tip, plan: funding }, &keys[0]);
    let funding_tx = id(&v["review"], "transaction_id");
    let (funding_block, _) = nodes[0].mine(miner, time + 1200);
    for i in 1..3 {
        for block in [close_block, funding_block] {
            let p = nodes[0].block(block, id(&infos[i], "identity"));
            nodes[i].import(p);
        }
    }
    let claim = OnchainRequest {
        kind: 4,
        channel,
        actor: Id(f.retainer.verifying_key().to_bytes()),
        inputs: vec![hex::encode(out(funding_tx.0, 0))],
        fee: "1".into(),
        expiry: u128::MAX.to_string(),
        nonce: Id([93; 32]),
        certificate: certificate.clone(),
        timestamp: (time + 1800).to_string(),
    };
    let tip = nodes[2].tip;
    let (claim, v) = nodes[2].authorize(Action::OnchainPrepare { tip, plan: claim }, &keys[2]);
    assert_eq!(v["review"]["known_miner_fee_ranges"], json!(["2", "3"]));
    let deadline_height = v["review"]["fixed_deadline_height"].clone();
    let (claim_block, _) = nodes[2].mine(miner, time + 1800);
    let principal = OnchainRequest {
        kind: 3,
        channel,
        actor: Id(f.retainer.verifying_key().to_bytes()),
        inputs: vec![hex::encode(out(claim.0, 0))],
        fee: "1".into(),
        expiry: u128::MAX.to_string(),
        nonce: Id([94; 32]),
        certificate,
        timestamp: (time + 2400).to_string(),
    };
    let tip = nodes[2].tip;
    let (_, v) = nodes[2].authorize(
        Action::OnchainPrepare {
            tip,
            plan: principal,
        },
        &keys[2],
    );
    assert_eq!(v["review"]["authorized_principal"], json!(["96", "104"]));
    assert_eq!(v["review"]["fixed_deadline_height"], deadline_height);
    let (principal_block, _) = nodes[2].mine(miner, time + 2400);
    for i in 0..2 {
        for block in [claim_block, principal_block] {
            let p = nodes[2].block(block, id(&infos[i], "identity"));
            nodes[i].import(p);
        }
    }
    for (i, key) in keys.iter().enumerate() {
        fs::rename(key, root.join(format!("retained-signing-{i}.key"))).unwrap();
    }
    for node in &mut nodes {
        node.drain();
        node.finish();
    }
    assert!(
        Instant::now() < deadline,
        "original180 actual joint opening and challenges"
    );
}

#[derive(serde::Serialize, serde::Deserialize)]
struct IntentMirror {
    id: Id,
    action: Action,
    at: u64,
}
#[derive(serde::Serialize, serde::Deserialize)]
struct DoneMirror {
    id: Id,
    request: Id,
    effect: Option<Id>,
    review: Option<Id>,
    diagnostic: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authorization: Option<String>,
}
fn corrupt_proof_and_rehash(path: &Path, old: &str, new: &str, bad_complete: Option<Hash>) -> Hash {
    use sha2::{Digest, Sha256};
    let source = fs::read(path).unwrap();
    let mut output = source[..197].to_vec();
    let mut head: Hash =
        Sha256::digest([b"RLD-FAST-SESSION-1/HEADER\0".as_slice(), output.as_slice()].concat())
            .into();
    let mut at = 197;
    let mut request = Id([0; 32]);
    let mut changed = false;
    let mut combine = false;
    while at < source.len() {
        let n = u32::from_be_bytes(source[at..at + 4].try_into().unwrap()) as usize;
        at += 4;
        let body = &source[at..at + n];
        at += n;
        let size = u32::from_be_bytes(body[33..37].try_into().unwrap()) as usize;
        let payload = &body[37..37 + size];
        let payload = if body[0] == 1 {
            let mut i: IntentMirror = serde_json::from_slice(payload).unwrap();
            combine = matches!(i.action, Action::OpenCombine { .. });
            if let Action::OpenCombine {
                counterparty_partial,
                ..
            } = &mut i.action
            {
                if bad_complete.is_some() && counterparty_partial == old {
                    *counterparty_partial = new.into();
                    changed = true;
                }
            }
            request = i.action.digest().unwrap();
            serde_json::to_vec(&i).unwrap()
        } else {
            let mut d: DoneMirror = serde_json::from_slice(payload).unwrap();
            d.request = request;
            if bad_complete.is_none() && d.authorization.as_deref() == Some(old) {
                d.authorization = Some(new.into());
                changed = true;
            }
            if combine {
                if let Some(id) = bad_complete {
                    d.review = Some(Id(id));
                }
            }
            serde_json::to_vec(&d).unwrap()
        };
        let mut record = vec![body[0]];
        record.extend(head);
        record.extend((payload.len() as u32).to_be_bytes());
        record.extend(payload);
        head =
            Sha256::digest([b"RLD-FAST-SESSION-1/RECORD\0".as_slice(), record.as_slice()].concat())
                .into();
        record.extend(head);
        output.extend((record.len() as u32).to_be_bytes());
        output.extend(record);
    }
    assert!(changed);
    fs::write(path, output).unwrap();
    head
}
#[test]
fn rehashed_caller_hashes_never_authenticate_changed_own_or_partner_opening_signatures() {
    let deadline = Instant::now() + Duration::from_secs(180);
    for own in [true, false] {
        let f = fixture();
        let chain = f.ledger.chain_id();
        let root = dir(chain, "rehash");
        let state = root.join("session");
        let (mut s, mut n) = funded(&f, &state);
        let time = f.ledger.tip().timestamp() + 600;
        let v = s
            .opening_proposal(s.head(), terms(&f), time.to_string(), f.now)
            .unwrap();
        let proposal = v["proposal_hex"].as_str().unwrap();
        let tip = Id(s.tip());
        let (p, v) = exec(
            &mut s,
            &mut n,
            Action::OpenPrepare {
                tip,
                plan: request(proposal, 0, time),
            },
            None,
            f.now,
        );
        let review = id(&v, "review_digest");
        let key = root.join("owner.key");
        write(
            &key,
            &keyfile::encrypt(&f.owners[0], chain, PASSWORD).unwrap(),
        );
        let (signed, v) = sign(&mut s, &mut n, p, review, &key, f.now);
        let own_proof = v["opening_partial_hex"].as_str().unwrap().to_owned();
        let native = f
            .ledger
            .plan_opening(tip.0, &hex::decode(proposal).unwrap(), time, f.now)
            .unwrap();
        let partner = native.sign(1, &f.owners[1]).unwrap();
        let partner_hex = hex::encode(&partner);
        let (_, v) = exec(
            &mut s,
            &mut n,
            Action::OpenCombine {
                tip,
                prepare_request: p,
                sign_request: signed,
                review,
                counterparty_partial: partner_hex.clone(),
            },
            None,
            f.now,
        );
        assert!(v["diagnostic"].is_null());
        let mut complete = hex::decode(v["operation_hex"].as_str().unwrap()).unwrap();
        drop(s);
        fs::rename(&key, root.join("retained-owner.key")).unwrap();
        let path = state.join("caller.journal");
        write(
            &root.join("original-caller.journal"),
            &fs::read(&path).unwrap(),
        );
        let original = if own { own_proof } else { partner_hex };
        let mut bad = hex::decode(&original).unwrap();
        let end = bad.len() - 1;
        bad[end] ^= 1;
        let bad_hex = hex::encode(bad);
        let bad_id = if own {
            None
        } else {
            let end = complete.len() - 1;
            complete[end] ^= 1;
            Some(fast::operation_id(&complete))
        };
        let head = corrupt_proof_and_rehash(&path, &original, &bad_hex, bad_id);
        let before = fs::read(&path).unwrap();
        let native_before = fs::read(state.join("native.journal")).unwrap();
        let error = Session::open(&state, &f.genesis, chain, head, f.now)
            .err()
            .expect("changed opening proof must refuse");
        assert!(error.contains("signature"), "{error}");
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(
            fs::read(state.join("native.journal")).unwrap(),
            native_before
        );
    }
    assert!(
        Instant::now() < deadline,
        "original180 opening cold authentication"
    );
}

#[test]
fn opening_cut_child() {
    let Some(path) = std::env::var_os("RLD_OPENING_CUT_FILE") else {
        return;
    };
    let v: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let state = Path::new(v["state"].as_str().unwrap());
    let g = hex::decode(v["genesis"].as_str().unwrap()).unwrap();
    let chain = id(&v, "chain");
    let head = id(&v, "head");
    let a: Action = serde_json::from_value(v["action"].clone()).unwrap();
    let now = v["now"].as_u64().unwrap();
    let mut s = Session::open(state, &g, chain.0, head.0, now).unwrap();
    let password = matches!(a, Action::OnchainSign { .. }).then_some(PASSWORD);
    s.execute_observed(id(&v, "request"), head.0, a, password, now, |b| {
        use rld_survivor_node::fast_session::Boundary;
        let label = match b {
            Boundary::IntentDurable => "intent",
            Boundary::NativeActionEvaluated => "evaluated",
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
    })
    .unwrap();
    panic!("required opening boundary not reached");
}
struct CutChild(Option<std::process::Child>);
impl Drop for CutChild {
    fn drop(&mut self) {
        if let Some(c) = &mut self.0 {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}
#[test]
fn actual_process_cuts_never_first_sign_and_reconstruct_only_exact_retained_joint_proofs() {
    use std::process::{Command, Stdio};
    let deadline = Instant::now() + Duration::from_secs(180);
    for combining in [false, true] {
        for cut in ["intent", "evaluated", "reply"] {
            let f = fixture();
            let chain = f.ledger.chain_id();
            let root = dir(chain, "cut");
            let state = root.join("session");
            let (mut s, mut n) = funded(&f, &state);
            let time = f.ledger.tip().timestamp() + 600;
            let v = s
                .opening_proposal(s.head(), terms(&f), time.to_string(), f.now)
                .unwrap();
            let proposal = v["proposal_hex"].as_str().unwrap();
            let tip = Id(s.tip());
            let (prepare, v) = exec(
                &mut s,
                &mut n,
                Action::OpenPrepare {
                    tip,
                    plan: request(proposal, 0, time),
                },
                None,
                f.now,
            );
            let review = id(&v, "review_digest");
            let key = root.join("owner.key");
            write(
                &key,
                &keyfile::encrypt(&f.owners[0], chain, PASSWORD).unwrap(),
            );
            let action = if combining {
                let (own, v) = sign(&mut s, &mut n, prepare, review, &key, f.now);
                assert!(v["diagnostic"].is_null());
                let native = f
                    .ledger
                    .plan_opening(tip.0, &hex::decode(proposal).unwrap(), time, f.now)
                    .unwrap();
                let partner = native.sign(1, &f.owners[1]).unwrap();
                fs::rename(&key, root.join("retained-owner.key")).unwrap();
                Action::OpenCombine {
                    tip,
                    prepare_request: prepare,
                    sign_request: own,
                    review,
                    counterparty_partial: hex::encode(partner),
                }
            } else {
                Action::OnchainSign {
                    tip,
                    prepare_request: prepare,
                    review,
                    key_file: key.to_string_lossy().into(),
                    approved: true,
                }
            };
            let prior = s.head();
            let native_head = s.native_head();
            let request = rid(&mut n);
            drop(s);
            let config = root.join("child.json");
            write(&config,json!({"state":state,"genesis":hex::encode(&f.genesis),"chain":Id(chain),"head":Id(prior),"action":action,"request":request,"cut":cut,"now":f.now}).to_string().as_bytes());
            let mut child = CutChild(Some(
                Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "opening_cut_child", "--nocapture"])
                    .env("RLD_OPENING_CUT_FILE", config)
                    .stdout(std::process::Stdio::from(
                        fs::File::create(root.join("child.stdout.log")).unwrap(),
                    ))
                    .stderr(Stdio::from(
                        fs::File::create(root.join("child.stderr.log")).unwrap(),
                    ))
                    .spawn()
                    .unwrap(),
            ));
            while !root.join("cut-reached").exists() {
                assert!(Instant::now() < deadline, "original180 opening cut");
                assert!(
                    child.0.as_mut().unwrap().try_wait().unwrap().is_none(),
                    "opening child exited before required cut"
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
            write(&root.join("terminal.json"),json!({"pid":pid,"intentional_sigkill":true,"boundary":cut,"combining":combining,"status":format!("{status:?}")}).to_string().as_bytes());
            if !combining {
                fs::rename(&key, root.join("retained-owner.key")).unwrap();
            }
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
            assert_eq!(s.native_head(), native_head);
            assert_eq!(s.tip(), tip.0);
            assert_eq!(v["key_loaded_by_recovery"], false);
            if combining {
                assert!(v["diagnostic"].is_null(), "{v}");
                let raw = hex::decode(v["operation_hex"].as_str().unwrap()).unwrap();
                fast::validate_operation(&raw, chain).unwrap();
                assert!(v["opening_partial_hex"].is_null());
            } else {
                assert_eq!(v["opening_partial_hex"].is_string(), cut == "reply");
                assert!(v["operation_hex"].is_null());
                if cut == "reply" {
                    fast::opening::verify_partial(
                        &hex::decode(proposal).unwrap(),
                        &hex::decode(v["opening_partial_hex"].as_str().unwrap()).unwrap(),
                        chain,
                    )
                    .unwrap();
                }
            }
            let mut changed = hex::decode(proposal).unwrap();
            changed[37] ^= 1;
            let h = s.head();
            let i = rid(&mut n);
            assert!(s
                .execute(
                    i,
                    h,
                    Action::OpenPrepare {
                        tip,
                        plan: OpeningRequest {
                            proposal: hex::encode(changed),
                            owner: 0,
                            timestamp: time.to_string()
                        }
                    },
                    None,
                    f.now
                )
                .unwrap_err()
                .contains("reserved"));
            assert_eq!(s.head(), h);
            let head = s.head();
            drop(s);
            let bytes = fs::read(state.join("caller.journal")).unwrap();
            let (s, _) = Session::recover(
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
            assert_eq!(fs::read(state.join("caller.journal")).unwrap(), bytes);
        }
    }
    assert!(
        Instant::now() < deadline,
        "original180 all opening process cuts"
    );
}
