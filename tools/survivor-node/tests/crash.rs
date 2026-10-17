//! Actual process kills at native persistence boundaries. Not power-loss qualification.
use rld_survivor_node::{
    kernel::genesis_id,
    store::{CommitBoundary, Limits, Store},
};
use serde_json::Value;
use std::{
    io::{BufRead, BufReader, Write},
    process::{Command, Stdio},
    sync::mpsc,
    time::Duration,
};
fn fixture() -> (Vec<u8>, Vec<u8>) {
    let v: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/survivor-v1/vectors.json"
    ))
    .unwrap();
    (
        hex::decode(v["genesis"]["manifest_hex"].as_str().unwrap()).unwrap(),
        hex::decode(v["main_branch"][0]["block_hex"].as_str().unwrap()).unwrap(),
    )
}
#[test]
fn fault_child() {
    let Ok(root) = std::env::var("RLD_SURVIVOR_FAULT_ROOT") else {
        return;
    };
    let phase = std::env::var("RLD_SURVIVOR_FAULT_PHASE").unwrap();
    let (g, b) = fixture();
    let mut s = Store::open(
        std::path::Path::new(&root),
        &g,
        genesis_id(&g),
        Limits::default(),
    )
    .unwrap();
    let observer = |cut| {
        let name = match cut {
            CommitBoundary::Validated => "validated",
            CommitBoundary::IntentDurable => "intent",
            CommitBoundary::CommittedDurable => "committed",
        };
        if name == phase {
            println!("CUT {name}");
            std::io::stdout().flush().unwrap();
            loop {
                std::thread::park();
            }
        }
    };
    if std::env::var("RLD_SURVIVOR_FAULT_GROUP").is_ok() {
        let v: Value = serde_json::from_str(include_str!(
            "../../../docs/protocol/survivor-v1/vectors.json"
        ))
        .unwrap();
        let blocks: Vec<Vec<u8>> = v["main_branch"].as_array().unwrap()[..3]
            .iter()
            .map(|b| hex::decode(b["block_hex"].as_str().unwrap()).unwrap())
            .collect();
        s.accept_history_observed([1; 32], &blocks, 2_000_000_000, observer)
            .unwrap();
    } else {
        s.accept_observed([1; 32], &b, 2_000_000_000, observer)
            .unwrap();
    }
    panic!("requested boundary not observed");
}
#[test]
fn killed_history_group_never_exposes_an_intermediate_member() {
    let (g, _) = fixture();
    let pin = genesis_id(&g);
    let v: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/survivor-v1/vectors.json"
    ))
    .unwrap();
    let blocks: Vec<Vec<u8>> = v["main_branch"].as_array().unwrap()[..3]
        .iter()
        .map(|b| hex::decode(b["block_hex"].as_str().unwrap()).unwrap())
        .collect();
    for phase in ["validated", "intent", "committed"] {
        let root = std::env::temp_dir().join(format!(
            "rld-survivor-group-crash-{}-{phase}",
            std::process::id()
        ));
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "fault_child", "--nocapture"])
            .env("RLD_SURVIVOR_FAULT_ROOT", &root)
            .env("RLD_SURVIVOR_FAULT_PHASE", phase)
            .env("RLD_SURVIVOR_FAULT_GROUP", "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let out = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines() {
                let line = line.unwrap();
                if line.starts_with("CUT ") {
                    let _ = tx.send(line);
                    break;
                }
            }
        });
        let observed = rx.recv_timeout(Duration::from_secs(10));
        let _ = child.kill();
        child.wait().unwrap();
        assert_eq!(observed.unwrap(), format!("CUT {phase}"));
        let mut s = Store::open(&root, &g, pin, Limits::default()).unwrap();
        assert_eq!(
            s.ledger().tip().height(),
            if phase == "committed" { 3 } else { 0 }
        );
        if phase == "intent" {
            let pending = s.pending_operation([1; 32]).unwrap().unwrap();
            assert_eq!(pending["recovery_method"], "accept_history");
            assert_eq!(pending["history_members"].as_array().unwrap().len(), 3);
            assert_eq!(pending["first_signing"], false);
        }
        s.accept_history([1; 32], &blocks, 2_000_000_000).unwrap();
        assert_eq!(s.ledger().tip().height(), 3);
        assert_eq!(s.revision(), 1);
        assert_eq!(
            s.changes_since(0).unwrap()["changes"][0]["attached"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
    }
}
#[test]
fn killed_process_exposes_only_prior_or_complete_committed_successor() {
    let (g, b) = fixture();
    let pin = genesis_id(&g);
    for phase in ["validated", "intent", "committed"] {
        let root =
            std::env::temp_dir().join(format!("rld-survivor-crash-{}-{phase}", std::process::id()));
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "fault_child", "--nocapture"])
            .env("RLD_SURVIVOR_FAULT_ROOT", &root)
            .env("RLD_SURVIVOR_FAULT_PHASE", phase)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let out = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines() {
                let line = line.unwrap();
                if line.starts_with("CUT ") {
                    let _ = tx.send(line);
                    break;
                }
            }
        });
        let observed = rx.recv_timeout(Duration::from_secs(10));
        let _ = child.kill();
        child.wait().unwrap();
        assert_eq!(observed.unwrap(), format!("CUT {phase}"));
        let mut s = Store::open(&root, &g, pin, Limits::default()).unwrap();
        assert_eq!(s.ledger().tip().height(), u128::from(phase == "committed"));
        s.accept([1; 32], &b, 2_000_000_000).unwrap();
        assert_eq!(s.ledger().tip().height(), 1);
        assert_eq!(s.revision(), 1);
        let tip = s.ledger().tip().clone();
        drop(s);
        let s = Store::open(&root, &g, pin, Limits::default()).unwrap();
        assert_eq!(s.ledger().tip(), &tip);
    }
}
#[test]
fn full_database_refuses_without_losing_prior_head_then_explicit_capacity_recovers() {
    let v: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/survivor-v1/vectors.json"
    ))
    .unwrap();
    let (g, _) = fixture();
    let pin = genesis_id(&g);
    let root = std::env::temp_dir().join(format!("rld-survivor-capacity-{}", std::process::id()));
    let limits = Limits {
        database_bytes: 128 * 1024,
        ..Limits::default()
    };
    let mut s = Store::open(&root, &g, pin, limits).unwrap();
    let mut failed = None;
    for (i, b) in v["main_branch"].as_array().unwrap().iter().enumerate() {
        let raw = hex::decode(b["block_hex"].as_str().unwrap()).unwrap();
        let op = [i as u8 + 1; 32];
        let old = s.ledger().tip().clone();
        if let Err(e) = s.accept(op, &raw, 2_000_000_000) {
            assert!(e.starts_with("RESOURCE_WAIT"), "{e}");
            assert_eq!(s.ledger().tip(), &old);
            failed = Some((op, raw, old));
            break;
        }
    }
    let (op, raw, old) = failed.expect("bounded fixture fills the configured database");
    drop(s);
    let mut s = Store::open(&root, &g, pin, Limits::default()).unwrap();
    assert_eq!(s.ledger().tip(), &old);
    s.accept(op, &raw, 2_000_000_000).unwrap();
    assert_eq!(s.ledger().tip().height(), old.height() + 1);
}
