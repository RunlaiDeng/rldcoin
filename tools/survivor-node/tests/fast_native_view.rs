//! PUBLIC NO-VALUE fixture keys. Observations never authorize spending or
//! initialize a ledger; all current-state bytes still require native checks.
#[allow(dead_code)]
#[path = "support/fast_funding.rs"]
mod support;
use rld_survivor_node::{
    fast_session::{Action, Id, Session},
    kernel::{fast, Hash},
};
use serde_json::json;
use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};
fn root(chain: Hash, name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "rld-native-view-{}-{}-{name}",
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
#[test]
fn selected_native_output_observation_tracks_real_reorganization_and_full_cold_replay() {
    let f = support::fixture();
    let chain = f.ledger.chain_id();
    let r = root(chain, "selection");
    let path = r.join("node");
    let head = r.join("head");
    let mut s = Session::create_log_controlled(&path, &f.genesis, chain, &head, f.now).unwrap();
    let empty = s.head();
    let mut a = fast::Ledger::from_genesis(&f.genesis, chain, 100000).unwrap();
    let raw = support::mine(&mut a, f.miner.verifying_key().to_bytes(), vec![], f.now);
    let (reference, coin) = a.coins().first_key_value().unwrap();
    let reference = reference.clone();
    let coin = coin.clone();
    let out = s
        .execute(
            Id([81; 32]),
            s.head(),
            Action::Native {
                tip: Id(s.tip()),
                block: hex::encode(raw),
            },
            None,
            f.now,
        )
        .unwrap();
    assert!(out["diagnostic"].is_null());
    assert!(s.native_coin(empty, &reference, f.now).is_err());
    assert!(s.native_coin(s.head(), &reference[..33], f.now).is_err());
    let before = fs::read(path.join("caller.journal")).unwrap();
    let control = fs::read(&head).unwrap();
    let view = s.native_coin(s.head(), &reference, f.now).unwrap();
    assert_eq!(view["native_coin"]["owner"], json!(Id(coin.owner)));
    assert_eq!(view["native_coin"]["amount"], coin.amount.to_string());
    assert_eq!(view["native_coin"]["maturity_height"], "101");
    assert_eq!(view["native_coin"]["mature_for_next_block"], false);
    assert_eq!(view["selected_tip"], json!(Id(a.tip().id())));
    assert_eq!(view["selected_timestamp"], a.tip().timestamp().to_string());
    assert_eq!(view["owner_spend_authorized"], false);
    assert_eq!(view["reservation_review_required"], true);
    assert_eq!(view["independent_freshness"], false);
    assert_eq!(fs::read(path.join("caller.journal")).unwrap(), before);
    assert_eq!(fs::read(&head).unwrap(), control);
    let mut b = fast::Ledger::from_genesis(&f.genesis, chain, 100000).unwrap();
    for n in 82..84 {
        let raw = support::mine(&mut b, f.retainer.verifying_key().to_bytes(), vec![], f.now);
        let out = s
            .execute(
                Id([n; 32]),
                s.head(),
                Action::Native {
                    tip: Id(s.tip()),
                    block: hex::encode(raw),
                },
                None,
                f.now,
            )
            .unwrap();
        assert!(out["diagnostic"].is_null());
    }
    assert_eq!(s.tip(), b.tip().id());
    assert!(s.native_coin(s.head(), &reference, f.now).unwrap()["native_coin"].is_null());
    drop(s);
    let mut s = Session::open_log_controlled(&path, &f.genesis, chain, &head, f.now).unwrap();
    assert!(s.native_coin(s.head(), &reference, f.now).unwrap()["native_coin"].is_null());
    let (current, coin) = b.coins().first_key_value().unwrap();
    assert_eq!(
        s.native_coin(s.head(), current, f.now).unwrap()["native_coin"]["amount"],
        coin.amount.to_string()
    );
    let native = path.join("native.journal");
    let mut damaged = fs::read(&native).unwrap();
    let last = damaged.len() - 1;
    damaged[last] ^= 1;
    fs::write(&native, &damaged).unwrap();
    assert!(s.native_coin(s.head(), current, f.now).is_err());
    assert_eq!(fs::read(&native).unwrap(), damaged);
}
#[test]
fn private_cli_native_coin_is_a_keyless_nonmutating_current_head_observation() {
    let f = support::fixture();
    let chain = f.ledger.chain_id();
    let r = root(chain, "cli");
    let node = r.join("node");
    let file = r.join("head");
    let s = Session::create_log_controlled(&node, &f.genesis, chain, &file, f.now).unwrap();
    let head = s.head();
    drop(s);
    fs::write(r.join("genesis"), &f.genesis).unwrap();
    let caller = fs::read(node.join("caller.journal")).unwrap();
    let control = fs::read(&file).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_rld-fast-payment-session"))
        .arg("serve-log-control")
        .arg(&node)
        .arg(r.join("genesis"))
        .arg(hex::encode(chain))
        .arg(&file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    writeln!(
        stdin,
        "{}",
        json!({"command":"native_coin","head":Id(head),"reference":hex::encode([91;34])})
    )
    .unwrap();
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lines = String::from_utf8(out.stdout).unwrap();
    let response: serde_json::Value = serde_json::from_str(lines.lines().nth(1).unwrap()).unwrap();
    assert!(response["native_coin"].is_null());
    assert!(response["diagnostic"].is_null());
    assert_eq!(response["session_head"], json!(Id(head)));
    assert_eq!(response["observation_only"], true);
    assert_eq!(fs::read(node.join("caller.journal")).unwrap(), caller);
    assert_eq!(fs::read(&file).unwrap(), control);
}
