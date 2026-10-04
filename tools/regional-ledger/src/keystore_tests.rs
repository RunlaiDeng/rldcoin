use super::*;
use crate::{keystore, wallet, wallet_agent::Agent};
use std::{fs, path::Path};
const PASS: &[u8] = b"public-ground-test-passphrase-only";
fn private(root: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    }
}
fn request(owner: String) -> wallet::Request {
    wallet::Request {
        owner,
        participants: vec![],
        inputs: None,
        outputs: vec![Payment {
            owner: public(14),
            amount: Amount(30),
        }],
        remote: None,
        fee: Amount(1),
        valid_for_blocks: 8,
        valid_through: None,
    }
}
fn step(node: &mut Store, commands: Vec<Command>) {
    let mut block = node.template(commands, public(10)).unwrap();
    mine(&mut block).unwrap();
    node.accept(block).unwrap();
}
fn fund(node: &mut Store, root: &Path, owner: &str) {
    let key = root.join("fixture.json");
    keystore::private_create(
        &key,
        serde_json::to_string(&serde_json::json!({"secret_key":hex::encode([10;32])}))
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let mut payer = Agent::create(&root.join("payer"), node, public(10)).unwrap();
    let head = payer.journal.head().unwrap();
    let mut req = request(public(10));
    req.outputs = vec![Payment {
        owner: owner.into(),
        amount: Amount(60),
    }];
    let p = payer.prepare(node, req, head).unwrap();
    let s = payer
        .sign(node, p.draft, &key, p.review_commitment, head)
        .unwrap();
    step(node, s.commands);
    for _ in 0..3 {
        step(node, vec![]);
    }
}
#[test]
fn random_encrypted_keys_do_not_issue_value_and_reject_tampering_or_wrong_domain() {
    let f = Fixture::new();
    let (root, node) = stored_fixture(&f, &f.earth);
    private(&root);
    let key = root.join("key.enc");
    let before = node.chain.ledger.root().unwrap();
    let binding = keystore::create(&node, &key, PASS).unwrap();
    let other = keystore::create(&node, &root.join("second.enc"), PASS).unwrap();
    assert_ne!(binding.owner, other.owner);
    assert_eq!(before, node.chain.ledger.root().unwrap());
    assert_eq!(
        wallet::view(&node, &binding.owner).unwrap().spendable,
        Amount::ZERO
    );
    assert!(keystore::check(&node, &binding.owner, &key, b"wrong-test-passphrase").is_err());
    assert!(keystore::check(&node, &other.owner, &key, PASS).is_err());
    let raw = fs::read(&key).unwrap();
    let original: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    for field in ["format", "kind", "cipher", "kdf", "salt", "nonce"] {
        let mut damaged = original.clone();
        damaged["header"][field] = serde_json::json!("wrong");
        fs::write(&key, serde_json::to_vec(&damaged).unwrap()).unwrap();
        assert!(keystore::check(&node, &binding.owner, &key, PASS).is_err());
    }
    for field in ["memory_kib", "iterations", "lanes", "kdf_version"] {
        let mut damaged = original.clone();
        damaged["header"][field] = serde_json::json!(1);
        fs::write(&key, serde_json::to_vec(&damaged).unwrap()).unwrap();
        assert!(keystore::check(&node, &binding.owner, &key, PASS).is_err());
    }
    let mut damaged = original.clone();
    damaged["tag"] = serde_json::json!("00".repeat(16));
    fs::write(&key, serde_json::to_vec(&damaged).unwrap()).unwrap();
    assert!(keystore::check(&node, &binding.owner, &key, PASS).is_err());
    fs::write(&key, &raw).unwrap();
    assert!(keystore::create(&node, &key, PASS).is_err());
    assert_eq!(fs::read(&key).unwrap(), raw);
    assert!(keystore::validate_passphrase(b"short").is_err());
    drop(node);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn complete_backup_preserves_pending_inputs_keyless_retry_and_latest_head_refuses_old_backup() {
    let f = Fixture::new();
    let (root, mut node) = stored_fixture(&f, &f.earth);
    private(&root);
    let key = root.join("key.enc");
    let binding = keystore::create(&node, &key, PASS).unwrap();
    fund(&mut node, &root, &binding.owner);
    let mut agent = Agent::create(&root.join("wallet"), &node, binding.owner.clone()).unwrap();
    let old = agent.journal.head().unwrap();
    let old_backup = root.join("old.enc");
    keystore::backup(&node, &agent, old, &key, &old_backup, PASS).unwrap();
    let p = agent
        .prepare(&node, request(binding.owner.clone()), old)
        .unwrap();
    assert!(agent
        .sign_encrypted(
            &node,
            p.draft.clone(),
            &key,
            p.review_commitment,
            old,
            b"wrong-test-passphrase"
        )
        .is_err());
    assert_eq!(agent.journal.head().unwrap(), old);
    let signed = agent
        .sign_encrypted(&node, p.draft.clone(), &key, p.review_commitment, old, PASS)
        .unwrap();
    let latest = signed.wallet_head;
    let bytes = fs::read(&old_backup).unwrap();
    let reject = root.join("reject");
    assert!(keystore::restore(&node, &old_backup, &reject, latest, PASS).is_err());
    assert!(!reject.exists());
    assert_eq!(fs::read(&old_backup).unwrap(), bytes);
    let backup = root.join("complete.enc");
    keystore::backup(&node, &agent, latest, &key, &backup, PASS).unwrap();
    let fresh = root.join("restored");
    keystore::restore(&node, &backup, &fresh, latest, PASS).unwrap();
    let mut restored = Agent::open(&fresh, &node).unwrap();
    assert_eq!(restored.journal, agent.journal);
    assert_eq!(
        restored.view(&node, latest).unwrap().reserved_owned_outputs,
        Amount(60)
    );
    assert!(restored
        .prepare(&node, request(binding.owner.clone()), latest)
        .is_err());
    let retry = restored
        .sign_encrypted(
            &node,
            p.draft,
            &root.join("missing-key"),
            p.review_commitment,
            old,
            b"",
        )
        .unwrap();
    assert_eq!(retry.commands, signed.commands);
    assert_eq!(retry.wallet_head, latest);
    assert!(retry.recovered_exact_retry);
    assert!(keystore::restore(&node, &backup, &fresh, latest, PASS).is_err());
    drop(restored);
    step(&mut node, signed.commands);
    let restored = Agent::open(&fresh, &node).unwrap();
    assert_eq!(
        restored.view(&node, latest).unwrap().reserved_owned_outputs,
        Amount::ZERO
    );
    assert_eq!(
        restored.view(&node, latest).unwrap().signed[0].state,
        "INCLUDED_IN_LOCAL_LEDGER"
    );
    keystore::check(&node, &binding.owner, &fresh.join("key.enc.json"), PASS).unwrap();
    drop(restored);
    for _ in 0..3 {
        step(&mut node, vec![]);
    }
    let mut restored = Agent::open(&fresh, &node).unwrap();
    let mut next = request(binding.owner.clone());
    next.outputs[0].amount = Amount(10);
    let prepared = restored.prepare(&node, next, latest).unwrap();
    let signed = restored
        .sign_encrypted(
            &node,
            prepared.draft,
            &fresh.join("key.enc.json"),
            prepared.review_commitment,
            latest,
            PASS,
        )
        .unwrap();
    step(&mut node, signed.commands);
    assert_eq!(restored.journal.records.len(), 2);
    assert_eq!(
        wallet::view(&node, &binding.owner)
            .unwrap()
            .coins
            .iter()
            .map(|c| c.amount.0)
            .sum::<u128>(),
        18
    );
    drop(restored);
    drop(agent);
    drop(node);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn backup_observed_native_history_prevents_ledger_rollback_and_wrong_region_restore() {
    let f = Fixture::new();
    let (root, mut node) = stored_fixture(&f, &f.earth);
    private(&root);
    let key = root.join("key.enc");
    let binding = keystore::create(&node, &key, PASS).unwrap();
    let agent = Agent::create(&root.join("wallet"), &node, binding.owner).unwrap();
    let head = agent.journal.head().unwrap();
    step(&mut node, vec![]);
    let backup = root.join("backup.enc");
    keystore::backup(&node, &agent, head, &key, &backup, PASS).unwrap();
    let (oldroot, old) = stored_fixture(&f, &f.earth);
    assert!(keystore::restore(&old, &backup, &root.join("reject-height"), head, PASS).is_err());
    let (remote_root, remote) = stored_fixture(&f, &f.proxima);
    assert!(keystore::restore(&remote, &backup, &root.join("reject-region"), head, PASS).is_err());
    assert!(!root.join("reject-height").exists());
    assert!(!root.join("reject-region").exists());
    drop(agent);
    drop(node);
    drop(old);
    drop(remote);
    for p in [root, oldroot, remote_root] {
        fs::remove_dir_all(p).unwrap();
    }
}
#[test]
fn private_files_refuse_links_permissions_and_interrupted_restore_keeps_evidence() {
    let f = Fixture::new();
    let (root, node) = stored_fixture(&f, &f.earth);
    private(&root);
    let key = root.join("key.enc");
    let binding = keystore::create(&node, &key, PASS).unwrap();
    let original = fs::read(&key).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::{symlink, PermissionsExt};
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(keystore::check(&node, &binding.owner, &key, PASS).is_err());
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let link = root.join("link");
        symlink(&key, &link).unwrap();
        assert!(keystore::check(&node, &binding.owner, &link, PASS).is_err());
        let hard = root.join("hard");
        fs::hard_link(&key, &hard).unwrap();
        assert!(keystore::check(&node, &binding.owner, &key, PASS).is_err());
        fs::remove_file(hard).unwrap();
    }
    let agent = Agent::create(&root.join("wallet"), &node, binding.owner).unwrap();
    let head = agent.journal.head().unwrap();
    let backup = root.join("backup.enc");
    keystore::backup(&node, &agent, head, &key, &backup, PASS).unwrap();
    let restored = root.join("restore");
    keystore::restore(&node, &backup, &restored, head, PASS).unwrap();
    fs::write(restored.join("RESTORING"), b"fixture interruption").unwrap();
    let journal = fs::read(restored.join("wallet.json")).unwrap();
    assert!(Agent::open(&restored, &node).is_err());
    assert_eq!(fs::read(restored.join("wallet.json")).unwrap(), journal);
    assert_eq!(fs::read(&key).unwrap(), original);
    drop(agent);
    drop(node);
    fs::remove_dir_all(root).unwrap();
}
