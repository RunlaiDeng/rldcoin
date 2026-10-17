//! Exercise the exact allowlisted archive through the system's independent tar
//! reader and start its extracted no-value executable from a fresh directory.
use std::{
    io::Write,
    process::{Command, Stdio},
};
#[test]
fn extracted_candidate_creates_zero_allocation_test_genesis_and_starts() {
    let root = std::env::temp_dir().join(format!("rld-survivor-package-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let tar = root.join("candidate.tar");
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_rld-survivor-package"))
        .arg(repo)
        .arg(env!("CARGO_BIN_EXE_rld-survivor-node"))
        .arg(&tar)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let listing = Command::new("tar").arg("-tf").arg(&tar).output().unwrap();
    assert!(listing.status.success());
    let listing = String::from_utf8(listing.stdout).unwrap();
    assert_eq!(listing.lines().count(), 10);
    assert!(!listing.contains("secret"));
    assert!(!listing.contains("sqlite"));
    let out = root.join("extracted");
    std::fs::create_dir(&out).unwrap();
    assert!(Command::new("tar")
        .arg("-xf")
        .arg(&tar)
        .arg("-C")
        .arg(&out)
        .status()
        .unwrap()
        .success());
    assert_eq!(
        std::fs::read(out.join("rld-survivor-node")).unwrap(),
        std::fs::read(env!("CARGO_BIN_EXE_rld-survivor-node")).unwrap()
    );
    let result = Command::new(out.join("rld-survivor-node"))
        .current_dir(&out)
        .args(["new-test-genesis", "fresh.genesis"])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(v["initial_allocation"], "0");
    assert_eq!(v["network_kind"], "NO_VALUE_ONLY");
    let mut child = Command::new(out.join("rld-survivor-node"))
        .current_dir(&out)
        .args([
            "serve",
            "private-node",
            "fresh.genesis",
            v["chain_id"].as_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(
        child.stdin.take().unwrap(),
        "{{\"method\":\"node_status\"}}"
    )
    .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let status: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(status["result"]["height"], "0");
    assert_eq!(status["result"]["mainnet"], false);
}
