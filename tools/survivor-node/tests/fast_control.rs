//! PUBLIC NO-VALUE fixture keys; fresh private state and interruption residue
//! remain local. No failed store is reopened as replacement qualification.
#[allow(dead_code)]
#[path = "support/fast_funding.rs"]
mod support;
use rld_survivor_node::{
    fast_session::{Action, Boundary, ControlBoundary, Id, Session},
    kernel::Hash,
};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn root(chain: Hash, label: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "rld-caller-control-{}-{}-{label}",
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
fn write(p: &Path, b: &[u8]) {
    let mut o = fs::OpenOptions::new();
    o.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(p).unwrap();
    f.write_all(b).unwrap();
    f.sync_all().unwrap();
}
fn first(f: &support::Fixture) -> Vec<u8> {
    let n = u32::from_be_bytes(f.history[..4].try_into().unwrap()) as usize;
    f.history[4..4 + n].to_vec()
}
fn action(chain: Hash, block: &[u8]) -> Action {
    Action::Native {
        tip: Id(chain),
        block: hex::encode(block),
    }
}
fn pause(marker: &Path) {
    write(marker, b"cut");
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
}
#[test]
fn caller_control_cut_child() {
    let Some(path) = std::env::var_os("RLD_CALLER_CONTROL_CUT") else {
        return;
    };
    let v: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let root = PathBuf::from(v["root"].as_str().unwrap());
    let g = fs::read(root.join("genesis")).unwrap();
    let chain = rld_survivor_node::kernel::fast::genesis_id(&g);
    let mut s =
        Session::open_controlled(&root.join("session"), &g, chain, &root.join("head"), now())
            .unwrap();
    let cut = v["cut"].as_u64().unwrap();
    let marker = root.join("marker");
    let control_marker = marker.clone();
    s.set_control_observer(move |b| {
        let selected = match b {
            ControlBoundary::PrepareNextDurable => 0,
            ControlBoundary::Prepared => 1,
            ControlBoundary::CommitNextDurable => 5,
            ControlBoundary::Committed => 6,
        };
        if cut == selected {
            pause(&control_marker);
        }
        Ok(())
    })
    .unwrap();
    let a: Action = serde_json::from_value(v["action"].clone()).unwrap();
    s.execute_observed(Id([1; 32]), s.head(), a, None, now(), move |b| {
        let selected = match b {
            Boundary::IntentDurable => 2,
            Boundary::ChildDurable => 3,
            Boundary::ReplyDurable => 4,
            Boundary::NativeActionEvaluated => 99,
        };
        if cut == selected {
            pause(&marker);
        }
    })
    .unwrap();
    panic!("missing requested caller-control boundary");
}
struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[test]
fn seven_actual_sigkill_boundaries_recover_only_retained_effect_or_audited_absence() {
    use std::process::{Command, Stdio};
    let deadline = Instant::now() + Duration::from_secs(180);
    for cut in 0..7 {
        let f = support::fixture();
        let chain = f.ledger.chain_id();
        let r = root(chain, &format!("cut-{cut}"));
        write(&r.join("genesis"), &f.genesis);
        let s = Session::create_controlled(
            &r.join("session"),
            &f.genesis,
            chain,
            &r.join("head"),
            now(),
        )
        .unwrap();
        let prior = s.head();
        drop(s);
        let config = r.join("cut.json");
        write(
            &config,
            json!({"root":r,"cut":cut,"action":action(chain,&first(&f))})
                .to_string()
                .as_bytes(),
        );
        let mut child = Child(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "caller_control_cut_child", "--nocapture"])
                .env("RLD_CALLER_CONTROL_CUT", config)
                .stdin(Stdio::null())
                .stdout(fs::File::create(r.join("stdout.log")).unwrap())
                .stderr(fs::File::create(r.join("stderr.log")).unwrap())
                .spawn()
                .unwrap(),
        );
        while !r.join("marker").exists() {
            assert!(Instant::now() < deadline, "original180 caller-control cuts");
            assert!(child.0.try_wait().unwrap().is_none(), "cut child exited");
            std::thread::sleep(Duration::from_millis(10));
        }
        child.0.kill().unwrap();
        let status = child.0.wait().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(status.signal(), Some(9));
        }
        let native = fs::read(r.join("session/native.journal")).unwrap();
        assert!(Session::open(&r.join("session"), &f.genesis, chain, prior, now()).is_err());
        if cut < 6 {
            assert!(Session::open_controlled(
                &r.join("session"),
                &f.genesis,
                chain,
                &r.join("head"),
                now()
            )
            .is_err());
        }
        let result = Command::new(env!("CARGO_BIN_EXE_rld-fast-payment-session"))
            .arg("recover-control")
            .arg(r.join("session"))
            .arg(r.join("genesis"))
            .arg(hex::encode(chain))
            .arg(r.join("head"))
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "cut{cut}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let v: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(v["recovery_key_loaded"], false);
        assert_eq!(v["recovery_first_execution"], false);
        assert_eq!(v["height"], if cut < 3 { "0" } else { "1" });
        assert_eq!(
            fs::read(r.join("session/native.journal")).unwrap(),
            native,
            "recovery must never first-accept a block"
        );
        let mut s = Session::open_controlled(
            &r.join("session"),
            &f.genesis,
            chain,
            &r.join("head"),
            now(),
        )
        .unwrap();
        assert_eq!(s.status(s.head(), now()).unwrap()["height"], v["height"]);
        assert_eq!(fs::read_dir(r.join("session/actors")).unwrap().count(), 0);
    }
}
fn hash(label: &str, raw: &[u8]) -> Hash {
    use sha2::{Digest, Sha256};
    Sha256::digest(
        [
            b"RLD-FAST-SESSION-1/".as_slice(),
            label.as_bytes(),
            &[0],
            raw,
        ]
        .concat(),
    )
    .into()
}
#[test]
fn rehashed_changed_pending_requests_candidates_and_partial_tails_refuse_unchanged() {
    for damage in 0..9 {
        let f = support::fixture();
        let chain = f.ledger.chain_id();
        let r = root(chain, &format!("damage-{damage}"));
        let file = r.join("head");
        let node = r.join("session");
        let mut s = Session::create_controlled(&node, &f.genesis, chain, &file, now()).unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            s.execute_observed(
                Id([2; 32]),
                s.head(),
                action(chain, &first(&f)),
                None,
                now(),
                |b| {
                    if b == Boundary::ChildDurable {
                        panic!("injected after durable native effect");
                    }
                },
            )
        }));
        assert!(result.is_err());
        drop(s);
        let mut snapshot = fs::read(&file).unwrap();
        if damage < 4 {
            let mut i: Value = serde_json::from_slice(&snapshot[112..snapshot.len() - 32]).unwrap();
            match damage {
                0 => i["id"] = hex::encode([3; 32]).into(),
                1 => i["at"] = (i["at"].as_u64().unwrap() + 1).into(),
                2 => i["action"]["block"] = "00".into(),
                3 => i["action"]["tip"] = hex::encode([4; 32]).into(),
                _ => unreachable!(),
            }
            // Typed canonical serialization is required even after rehashing.
            let typed: Value = i.clone();
            let action: Action = serde_json::from_value(i["action"].clone()).unwrap();
            let raw = format!(
                "{{\"id\":{},\"action\":{},\"at\":{}}}",
                typed["id"],
                serde_json::to_string(&action).unwrap(),
                typed["at"]
            )
            .into_bytes();
            snapshot.truncate(108);
            snapshot.extend((raw.len() as u32).to_be_bytes());
            snapshot.extend(raw);
            snapshot.extend(hash("CONTROL", &snapshot));
        } else {
            match damage {
                4 => {
                    let n = snapshot.len();
                    snapshot[n - 1] ^= 1;
                }
                5 => {
                    let mut next = snapshot[..112].to_vec();
                    next[44..76].copy_from_slice(&snapshot[snapshot.len() - 32..]);
                    next[76..108].fill(7);
                    next[108..112].fill(0);
                    next.extend(hash("CONTROL", &next));
                    write(&r.join("head.next"), &next);
                }
                6 => {
                    let mut b = fs::read(node.join("caller.journal")).unwrap();
                    b.push(0);
                    fs::write(node.join("caller.journal"), b).unwrap();
                }
                7 => {
                    let mut b = fs::read(node.join("native.journal")).unwrap();
                    b.push(0);
                    fs::write(node.join("native.journal"), b).unwrap();
                }
                8 => {
                    fs::write(r.join("head.lock"), [8; 32]).unwrap();
                }
                _ => unreachable!(),
            }
        }
        fs::write(&file, &snapshot).unwrap();
        let caller = fs::read(node.join("caller.journal")).unwrap();
        let native = fs::read(node.join("native.journal")).unwrap();
        let next = fs::read(r.join("head.next")).ok();
        assert!(
            Session::recover_controlled(&node, &f.genesis, chain, &file, now() + 2).is_err(),
            "damage{damage}"
        );
        assert_eq!(fs::read(&file).unwrap(), snapshot);
        assert_eq!(fs::read(node.join("caller.journal")).unwrap(), caller);
        assert_eq!(fs::read(node.join("native.journal")).unwrap(), native);
        assert_eq!(fs::read(r.join("head.next")).ok(), next);
    }
}
#[test]
fn exact_controlled_head_lease_and_legacy_versions_cannot_be_substituted() {
    let f = support::fixture();
    let chain = f.ledger.chain_id();
    let r = root(chain, "lease");
    let file = r.join("head");
    let node = r.join("session");
    let mut s = Session::create_controlled(&node, &f.genesis, chain, &file, now()).unwrap();
    assert!(Session::open_controlled(&node, &f.genesis, chain, &file, now()).is_err());
    assert!(Session::recover_controlled(&node, &f.genesis, chain, &file, now()).is_err());
    let key = fs::read(r.join("head.lock")).unwrap();
    fs::rename(r.join("head.lock"), r.join("old.lock")).unwrap();
    write(&r.join("head.lock"), &key);
    assert!(s.status(s.head(), now()).is_err());
    drop(s);
    let legacy = Session::create(&r.join("legacy"), &f.genesis, chain, now()).unwrap();
    drop(legacy);
    assert!(Session::open_controlled(&r.join("legacy"), &f.genesis, chain, &file, now()).is_err());
}
#[test]
fn same_clock_independent_controlled_roots_reject_each_others_head_files() {
    let f = support::fixture();
    let chain = f.ledger.chain_id();
    let r = root(chain, "same-clock-binding");
    let clock = now();
    let a = Session::create_controlled(&r.join("a"), &f.genesis, chain, &r.join("a.head"), clock)
        .unwrap();
    let b = Session::create_controlled(&r.join("b"), &f.genesis, chain, &r.join("b.head"), clock)
        .unwrap();
    drop(a);
    drop(b);
    assert!(
        Session::open_controlled(&r.join("a"), &f.genesis, chain, &r.join("b.head"), clock)
            .is_err(),
        "independent same-clock caller roots must not accept each other's control identity"
    );
}
#[test]
fn controlled_keyless_recovery_returns_original_signature_and_native_changes_cannot_rebase_review()
{
    use rld_survivor_node::{fast_session::OnchainRequest, keyfile};
    let deadline = Instant::now() + Duration::from_secs(180);
    let mut f = support::fixture();
    let chain = f.ledger.chain_id();
    let r = root(chain, "signed-recovery");
    let node = r.join("session");
    let file = r.join("head");
    let mut s = Session::create_controlled(&node, &f.genesis, chain, &file, now()).unwrap();
    let mut at = 0;
    let mut index = 0u64;
    let next = |index: &mut u64| {
        *index += 1;
        let mut b = [0; 32];
        b[..8].copy_from_slice(&index.to_be_bytes());
        Id(b)
    };
    while at < f.history.len() {
        let n = u32::from_be_bytes(f.history[at..at + 4].try_into().unwrap()) as usize;
        let b = &f.history[at + 4..at + 4 + n];
        at += 4 + n;
        let out = s
            .execute(
                next(&mut index),
                s.head(),
                Action::Native {
                    tip: Id(s.tip()),
                    block: hex::encode(b),
                },
                None,
                now(),
            )
            .unwrap();
        assert!(out["diagnostic"].is_null());
        assert!(Instant::now() < deadline);
    }
    let plan = |owner: usize| OnchainRequest {
        kind: 2,
        channel: Id(f.channel),
        actor: Id(f.owners[owner].verifying_key().to_bytes()),
        inputs: vec![hex::encode(support::out(f.channel, owner as u16))],
        fee: "1".into(),
        expiry: u128::MAX.to_string(),
        nonce: Id([110 + owner as u8; 32]),
        certificate: String::new(),
        timestamp: (f.ledger.tip().timestamp() + 600).to_string(),
    };
    let prepared = next(&mut index);
    let out = s
        .execute(
            prepared,
            s.head(),
            Action::OnchainPrepare {
                tip: Id(s.tip()),
                plan: plan(0),
            },
            None,
            now(),
        )
        .unwrap();
    assert!(out["diagnostic"].is_null());
    let review: Id = serde_json::from_value(out["review_digest"].clone()).unwrap();
    let key = r.join("owner.key");
    let password = b"public no-value controlled signing password";
    write(
        &key,
        &keyfile::encrypt(&f.owners[0], chain, password).unwrap(),
    );
    let signed = next(&mut index);
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        s.execute_observed(
            signed,
            s.head(),
            Action::OnchainSign {
                tip: Id(s.tip()),
                prepare_request: prepared,
                review,
                key_file: key.to_string_lossy().into(),
                approved: true,
            },
            Some(password),
            now(),
            |b| {
                if b == Boundary::ReplyDurable {
                    panic!("injected after retained original signature");
                }
            },
        )
    }));
    assert!(interrupted.is_err());
    drop(s);
    fs::rename(&key, r.join("owner-retained.key")).unwrap();
    let (mut s, recovered) =
        Session::recover_controlled(&node, &f.genesis, chain, &file, now()).unwrap();
    assert_eq!(
        recovered["request_id"],
        serde_json::to_value(signed).unwrap()
    );
    let operation = hex::decode(recovered["operation_hex"].as_str().unwrap()).unwrap();
    rld_survivor_node::kernel::fast::validate_operation(&operation, chain).unwrap();
    assert_eq!(recovered["recovery_key_loaded"], false);
    drop(s);
    let (reopened, again) =
        Session::recover_controlled(&node, &f.genesis, chain, &file, now()).unwrap();
    s = reopened;
    assert_eq!(again["operation_hex"], recovered["operation_hex"]);
    let other = next(&mut index);
    let out = s
        .execute(
            other,
            s.head(),
            Action::OnchainPrepare {
                tip: Id(s.tip()),
                plan: plan(1),
            },
            None,
            now(),
        )
        .unwrap();
    assert!(out["diagnostic"].is_null());
    let other_review = serde_json::from_value(out["review_digest"].clone()).unwrap();
    let miner = f.miner.verifying_key().to_bytes();
    let block = support::mine_until(&mut f.ledger, miner, vec![], f.now, deadline);
    let out = s
        .execute(
            next(&mut index),
            s.head(),
            Action::Native {
                tip: Id(s.tip()),
                block: hex::encode(block),
            },
            None,
            now(),
        )
        .unwrap();
    assert!(out["diagnostic"].is_null());
    let out = s
        .execute(
            next(&mut index),
            s.head(),
            Action::OnchainSign {
                tip: Id(s.tip()),
                prepare_request: other,
                review: other_review,
                key_file: r.join("missing-owner.key").to_string_lossy().into(),
                approved: true,
            },
            None,
            now(),
        )
        .unwrap();
    assert_eq!(
        out["diagnostic"],
        "INVALID native action changed review tip"
    );
    assert!(out["operation_hex"].is_null());
    assert!(Instant::now() < deadline);
}
