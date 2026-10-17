//! Fresh NO-VALUE measurement scopes compose full native history with pending
//! wallet intent, encrypted whole-node backup, restore and ordinary cold startup.
//! Same-host fixture heads are not independent custody or physical power loss.
use std::process::Command;

#[test]
fn history_measurement_recovers_exact_pending_wallet_for_both_workloads() {
    for workload in ["growing-rewards", "consolidating-payments"] {
        let root = std::env::temp_dir().join(format!(
            "rld-survivor-history-backup-{}-{workload}",
            std::process::id()
        ));
        let result = Command::new(env!("CARGO_BIN_EXE_rld-survivor-history"))
            .arg(&root)
            .args(["160", "30", "32", workload, "with-backup"])
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{} {}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        let rows: Vec<serde_json::Value> = String::from_utf8(result.stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        for event in [
            "COLD_REPLAY_BEGIN",
            "BACKUP_ROUNDTRIP_BEGIN",
            "BACKUP_CREATED",
            "RESTORE_VALIDATED",
            "RESTORED_NODE_REOPENED",
        ] {
            assert!(rows.iter().any(|r| r["event"] == event));
        }
        let done = rows.last().unwrap();
        assert_eq!(done["event"], "COMPLETE");
        assert_eq!(done["height"], "160");
        assert_eq!(done["backup"]["status"], "COMPLETE");
        assert_eq!(done["backup"]["pending_signature_recovered"], true);
        assert_eq!(done["backup"]["reservation_preserved"], true);
        assert_eq!(done["backup"]["encrypted_key_restored"], true);
        assert_eq!(done["backup"]["state_head_match"], true);
        assert_eq!(done["backup"]["head_custody"], "SAME_HOST_PROVIDED_HEAD");
        assert_eq!(done["backup"]["independent_custody_qualification"], false);
        assert_eq!(done["backup"]["physical_power_loss_qualification"], false);
        assert_eq!(done["independent_qualification"], false);
        assert_eq!(done["physical_route_qualification"], false);
        assert!(!root.join("backup/BUILDING").exists());
        assert!(!root.join("restored-node/RESTORING").exists());
        assert!(root.join("restored-node/keys/wallet-0.key").is_file());
    }
}

#[test]
fn backup_measurement_requires_a_mature_input_before_creating_a_fixture() {
    let root = std::env::temp_dir().join(format!(
        "rld-survivor-history-backup-preflight-{}",
        std::process::id()
    ));
    let result = Command::new(env!("CARGO_BIN_EXE_rld-survivor-history"))
        .arg(&root)
        .args(["99", "30", "32", "consolidating-payments", "with-backup"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!root.exists());
    assert!(String::from_utf8(result.stdout)
        .unwrap()
        .contains("fewer than 100 blocks"));
}
