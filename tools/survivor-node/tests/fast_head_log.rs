//! PUBLIC NO-VALUE fixtures. Local metadata checks do not qualify independent
//! latest-state protection, monetary adoption or physical custody.
#[allow(dead_code)]
#[path = "support/fast_funding.rs"]
mod support;
use rld_survivor_node::{
    fast_session::{Action, Boundary, Id, Session},
    kernel::Hash,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, io::Write, path::PathBuf, time::SystemTime};
fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn root(chain: Hash, name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "rld-head-log-binding-{}-{}-{name}",
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
fn digest(raw: &[u8]) -> Hash {
    Sha256::digest([b"RLD-FAST-SESSION-1/RECORD\0".as_slice(), raw].concat()).into()
}
#[test]
fn changed_canonical_caller_request_cannot_replace_prepared_key_path_or_approval() {
    for damage in 0..4 {
        let f = support::fixture();
        let chain = f.ledger.chain_id();
        let r = root(chain, &format!("request-{damage}"));
        let node = r.join("node");
        let file = r.join("head");
        let mut s = Session::create_log_controlled(&node, &f.genesis, chain, &file, now()).unwrap();
        let prior = s.head();
        let action = Action::OnchainSign {
            tip: Id(chain),
            prepare_request: Id([73; 32]),
            review: Id([74; 32]),
            key_file: r.join("missing-key").to_string_lossy().into(),
            approved: true,
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            s.execute_observed(Id([75; 32]), prior, action, None, now(), |b| {
                if b == Boundary::IntentDurable {
                    panic!("retained intent before any key or child action");
                }
            })
        }));
        assert!(result.is_err());
        drop(s);
        let caller_path = node.join("caller.journal");
        let old = fs::read(&caller_path).unwrap();
        let size = u32::from_be_bytes(old[266..270].try_into().unwrap()) as usize;
        let mut intent: Value = serde_json::from_slice(&old[270..270 + size]).unwrap();
        match damage {
            0 => intent["action"]["key_file"] = "substituted-missing-key".into(),
            1 => intent["action"]["approved"] = false.into(),
            2 => intent["id"] = hex::encode([76; 32]).into(),
            3 => intent["at"] = (intent["at"].as_u64().unwrap() + 1).into(),
            _ => unreachable!(),
        }
        let action: Action = serde_json::from_value(intent["action"].clone()).unwrap();
        let payload = format!(
            "{{\"id\":{},\"action\":{},\"at\":{}}}",
            intent["id"],
            serde_json::to_string(&action).unwrap(),
            intent["at"]
        )
        .into_bytes();
        let mut record = vec![1];
        record.extend(prior);
        record.extend((payload.len() as u32).to_be_bytes());
        record.extend(payload);
        record.extend(digest(&record));
        let mut changed = old[..229].to_vec();
        changed.extend((record.len() as u32).to_be_bytes());
        changed.extend(record);
        let mut out = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&caller_path)
            .unwrap();
        out.write_all(&changed).unwrap();
        out.sync_all().unwrap();
        drop(out);
        let control = fs::read(&file).unwrap();
        let native = fs::read(node.join("native.journal")).unwrap();
        let e = Session::recover_log_controlled(&node, &f.genesis, chain, &file, now() + 2)
            .err()
            .expect("altered request must refuse");
        assert!(e.contains("exact canonical request"), "damage{damage}: {e}");
        assert_eq!(fs::read(&caller_path).unwrap(), changed);
        assert_eq!(fs::read(&file).unwrap(), control);
        assert_eq!(fs::read(node.join("native.journal")).unwrap(), native);
        assert!(!r.join("missing-key").exists());
    }
}
#[test]
fn explicit_profiles_refuse_format_fallback_and_independent_caller_substitution() {
    let f = support::fixture();
    let chain = f.ledger.chain_id();
    let r = root(chain, "profiles");
    let at = now();
    let a = Session::create_log_controlled(&r.join("a"), &f.genesis, chain, &r.join("a.head"), at)
        .unwrap();
    let b = Session::create_log_controlled(&r.join("b"), &f.genesis, chain, &r.join("b.head"), at)
        .unwrap();
    let c =
        Session::create_controlled(&r.join("c"), &f.genesis, chain, &r.join("c.head"), at).unwrap();
    drop((a, b, c));
    let a_head = fs::read(r.join("a.head")).unwrap();
    let c_head = fs::read(r.join("c.head")).unwrap();
    for recovering in [false, true] {
        if recovering {
            assert!(Session::recover_log_controlled(
                &r.join("a"),
                &f.genesis,
                chain,
                &r.join("b.head"),
                at
            )
            .is_err());
            assert!(Session::recover_controlled(
                &r.join("a"),
                &f.genesis,
                chain,
                &r.join("a.head"),
                at
            )
            .is_err());
            assert!(Session::recover_log_controlled(
                &r.join("c"),
                &f.genesis,
                chain,
                &r.join("c.head"),
                at
            )
            .is_err());
        } else {
            assert!(Session::open_log_controlled(
                &r.join("a"),
                &f.genesis,
                chain,
                &r.join("b.head"),
                at
            )
            .is_err());
            assert!(Session::open_controlled(
                &r.join("a"),
                &f.genesis,
                chain,
                &r.join("a.head"),
                at
            )
            .is_err());
            assert!(Session::open_log_controlled(
                &r.join("c"),
                &f.genesis,
                chain,
                &r.join("c.head"),
                at
            )
            .is_err());
        }
    }
    assert_eq!(fs::read(r.join("a.head")).unwrap(), a_head);
    assert_eq!(fs::read(r.join("c.head")).unwrap(), c_head);
}

#[test]
fn altered_control_after_retained_intent_refuses_before_any_signing_evaluation() {
    let f = support::fixture();
    let chain = f.ledger.chain_id();
    let r = root(chain, "warm-prepared-prefix");
    let node = r.join("node");
    let file = r.join("head");
    let mut s = Session::create_log_controlled(&node, &f.genesis, chain, &file, now()).unwrap();
    let before = fs::read(node.join("native.journal")).unwrap();
    let action = Action::OnchainSign {
        tip: Id(chain),
        prepare_request: Id([73; 32]),
        review: Id([74; 32]),
        key_file: r.join("missing-key").to_string_lossy().into(),
        approved: true,
    };
    let e = s
        .execute_observed(Id([75; 32]), s.head(), action, None, now(), |b| {
            assert_eq!(b, Boundary::IntentDurable);
            let mut bytes = fs::read(&file).unwrap();
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
            fs::write(&file, bytes).unwrap();
        })
        .unwrap_err();
    assert!(e.contains("changed head log prefix"), "{e}");
    assert_eq!(fs::read(node.join("native.journal")).unwrap(), before);
    assert_eq!(fs::read_dir(node.join("actors")).unwrap().count(), 0);
    drop(s);
    let damaged = fs::read(&file).unwrap();
    assert!(Session::recover_log_controlled(&node, &f.genesis, chain, &file, now()).is_err());
    assert_eq!(fs::read(&file).unwrap(), damaged);
}
