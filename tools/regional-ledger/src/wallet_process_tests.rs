//! Fresh signed no-value wallet process boundaries; no independent custody claim.
use super::*;
use crate::{wallet, wallet_agent, wallet_client};
use std::os::unix::{fs::OpenOptionsExt, process::ExitStatusExt};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ChildConfig {
    root: PathBuf,
    currency: Hash,
    native_head: Hash,
    prepared: wallet_agent::Prepared,
    boundary: u8,
}

#[test]
fn wallet_sigkill_child() {
    let Some(path) = std::env::var_os("RLD_WALLET_CRASH_CHILD_CONFIG") else {
        return;
    };
    let config: ChildConfig = serde_json::from_slice(
        &wallet_client::private_read_with_limit(Path::new(&path), 8 * 1024 * 1024).unwrap(),
    )
    .unwrap();
    assert!(config.boundary < 3);
    let node = Store::open_pinned(
        &config.root.join("node"),
        &public(1),
        config.currency,
        config.native_head,
    )
    .unwrap();
    let dir = config.root.join("owner-wallet");
    let client =
        wallet_client::Client::lock(&config.root.join("owner-caller"), &dir, public(10), &node)
            .unwrap();
    let prior = client.read().unwrap();
    assert_eq!(prior.head, Some(config.prepared.wallet_head));
    assert!(prior.pending.is_none());
    let pending = wallet_client::State {
        pending: Some(wallet_client::Pending {
            prepared: config.prepared.clone(),
        }),
        ..prior.clone()
    };
    client
        .store(
            &node,
            wallet_client::Transition {
                previous: prior,
                proposed: pending,
            },
        )
        .unwrap();
    let mut owner = wallet_agent::Agent::open(&dir, &node).unwrap();
    owner.kill_publication_for_fixture(config.boundary);
    owner
        .sign(
            &node,
            config.prepared.draft,
            &config.root.join("public-owner-key.json"),
            config.prepared.review_commitment,
            config.prepared.wallet_head,
        )
        .unwrap();
    panic!("wallet SIGKILL boundary was not reached");
}

#[test]
fn real_wallet_sigkill_preserves_original_reservation_caller_and_single_native_debit() {
    let started = std::time::Instant::now();
    for boundary in 0..3 {
        let mut h = Harness::with_rules(crate::paged_bft::PACKED_RULES);
        h.retain = true;
        for _ in 0..4 {
            let p = h.proposal(0, None, h.node.bft_candidate(vec![], public(10)).unwrap());
            let q = h.prepare(&p, &[0, 1, 2, 3]);
            let certificate = h.commit(&p, &q, &[0, 1, 2, 3]);
            h.node.finalize(certificate).unwrap();
        }
        let root = h.root.clone();
        let dir = root.join("owner-wallet");
        let caller_dir = root.join("owner-caller");
        fs::create_dir(&caller_dir).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&caller_dir, fs::Permissions::from_mode(0o700)).unwrap();
        crate::keystore::private_create(
            &root.join("public-owner-key.json"),
            &serde_json::to_vec(&serde_json::json!({"secret_key":hex::encode([10;32])})).unwrap(),
        )
        .unwrap();
        let owner = wallet_agent::Agent::create(&dir, &h.node, public(10)).unwrap();
        let old = owner.journal.head().unwrap();
        let request = wallet::Request {
            owner: public(10),
            participants: vec![],
            inputs: None,
            outputs: vec![Payment {
                owner: public(14),
                amount: Amount(100),
            }],
            remote: None,
            fee: Amount(1),
            valid_for_blocks: 8,
            valid_through: None,
        };
        let prepared = owner.prepare(&h.node, request, old).unwrap();
        assert_eq!(prepared.draft.intent.inputs.len(), 1);
        let input = prepared.draft.intent.inputs[0];
        let amount = h.node.chain.ledger.coins[&input].payment.amount;
        drop(owner);
        let client = wallet_client::Client::lock(&caller_dir, &dir, public(10), &h.node).unwrap();
        let prior = client.open(&h.node, Some(old)).unwrap();
        drop(client);
        let config = ChildConfig {
            root: root.clone(),
            currency: h.node.trust.currency().unwrap(),
            native_head: h.node.storage_head().unwrap(),
            prepared: prepared.clone(),
            boundary,
        };
        let seeds = h.seeds.clone();
        let heads = h.heads.clone();
        let path = root.join("wallet-crash-request.json");
        crate::keystore::private_create(&path, &serde_json::to_vec(&config).unwrap()).unwrap();
        drop(h);
        let output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("wallet-child-output.log"))
            .unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "tests::regional_bft::wallet_process::wallet_sigkill_child",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("RLD_WALLET_CRASH_CHILD_CONFIG", &path)
            .stdout(std::process::Stdio::from(output.try_clone().unwrap()))
            .stderr(std::process::Stdio::from(output))
            .spawn()
            .unwrap();
        let child_started = std::time::Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if child_started.elapsed().as_secs_f64() >= 10.0 {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("wallet child exceeded declared ten-second boundary budget");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        let pending = wallet_client::State {
            pending: Some(wallet_client::Pending {
                prepared: prepared.clone(),
            }),
            ..prior.clone()
        };
        assert_eq!(
            fs::read(caller_dir.join("wallet-client.json")).unwrap(),
            wallet_client::canonical(&pending).unwrap()
        );
        let retained_path = if boundary == 0 {
            dir.join("wallet.next")
        } else {
            dir.join("wallet.json")
        };
        let observed: wallet_agent::Journal =
            serde_json::from_slice(&fs::read(retained_path).unwrap()).unwrap();
        assert_eq!(observed.records.len(), 1);
        assert_eq!(observed.records[0].draft, prepared.draft);
        let original_command = observed.records[0].command.clone();
        let node = Store::open_pinned(
            &root.join("node"),
            &public(1),
            config.currency,
            config.native_head,
        )
        .unwrap();
        let client = wallet_client::Client::lock(&caller_dir, &dir, public(10), &node).unwrap();
        let before = super::retained_native_replay::inventory(&root);
        let mut wrong_caller = pending.clone();
        wrong_caller.head = Some(Hash::ZERO);
        assert!(client.reconcile(&node, wrong_caller).is_err());
        assert_eq!(super::retained_native_replay::inventory(&root), before);
        let recovery = client.reconcile(&node, pending.clone()).unwrap();
        assert!(recovery.state.pending.is_none());
        assert_ne!(recovery.state.head, Some(old));
        assert_eq!(
            fs::read(caller_dir.join("wallet-client.json")).unwrap(),
            wallet_client::canonical(&pending).unwrap()
        );
        let mut owner = wallet_agent::Agent::open(&dir, &node).unwrap();
        let signed = owner.recover_prepared(&node, &prepared).unwrap();
        assert!(signed.recovered_exact_retry);
        assert_eq!(signed.commands, vec![original_command.clone()]);
        assert_eq!(recovery.state.head, Some(signed.wallet_head));
        assert_eq!(
            owner
                .view(&node, signed.wallet_head)
                .unwrap()
                .reserved_owned_outputs,
            amount
        );
        assert!(owner.view(&node, old).is_err());
        assert!(node.chain.ledger.coins.contains_key(&input));
        let stable = super::retained_native_replay::inventory(&root);
        let retry = owner
            .sign(
                &node,
                prepared.draft.clone(),
                &root.join("absent-key"),
                prepared.review_commitment,
                old,
            )
            .unwrap();
        assert!(retry.recovered_exact_retry);
        assert_eq!(retry.commands, signed.commands);
        let mut duplicate = prepared.draft.request.clone();
        duplicate.inputs = Some(vec![input]);
        assert!(owner.prepare(&node, duplicate, signed.wallet_head).is_err());
        assert_eq!(owner.journal.records.len(), 1);
        drop(owner);
        assert_eq!(super::retained_native_replay::inventory(&root), stable);
        client
            .store(
                &node,
                wallet_client::Transition {
                    previous: pending,
                    proposed: recovery.state.clone(),
                },
            )
            .unwrap();
        drop(client);
        let agents = seeds
            .iter()
            .map(|seed| Agent::open(&root.join(format!("signer-{seed}")), &node).unwrap())
            .collect();
        let mut h = Harness {
            root: root.clone(),
            node,
            agents,
            heads,
            seeds,
            retain: true,
        };
        let p = h.proposal(
            0,
            None,
            h.node.bft_candidate(signed.commands, public(10)).unwrap(),
        );
        let q = h.prepare(&p, &[0, 1, 2, 3]);
        let certificate = h.commit(&p, &q, &[0, 1, 2, 3]);
        h.node.finalize(certificate).unwrap();
        assert!(!h.node.chain.ledger.coins.contains_key(&input));
        assert!(h
            .node
            .chain
            .ledger
            .coins
            .values()
            .any(|coin| coin.payment.owner == public(14) && coin.payment.amount == Amount(100)));
        let owner = wallet_agent::Agent::open(&dir, &h.node).unwrap();
        let view = owner.view(&h.node, signed.wallet_head).unwrap();
        assert_eq!(view.reserved_owned_outputs, Amount::ZERO);
        assert_eq!(view.signed[0].state, "INCLUDED_IN_LOCAL_LEDGER");
        assert_eq!(owner.journal.records.len(), 1);
        assert_eq!(owner.journal.records[0].command, original_command);
        drop(owner);
        let native_head = h.node.storage_head().unwrap();
        let heads = h.heads.clone();
        let seeds = h.seeds.clone();
        drop(h);
        let stable = super::retained_native_replay::inventory(&root);
        let cold = Store::open_pinned(&root.join("node"), &public(1), config.currency, native_head)
            .unwrap();
        assert!(!cold.chain.ledger.coins.contains_key(&input));
        for (seed, head) in seeds.iter().zip(heads) {
            assert_eq!(
                Agent::open(&root.join(format!("signer-{seed}")), &cold)
                    .unwrap()
                    .head()
                    .unwrap(),
                head
            );
        }
        let owner = wallet_agent::Agent::open(&dir, &cold).unwrap();
        assert_eq!(
            owner
                .view(&cold, signed.wallet_head)
                .unwrap()
                .reserved_owned_outputs,
            Amount::ZERO
        );
        assert_eq!(owner.journal.records.len(), 1);
        drop(owner);
        let client = wallet_client::Client::lock(&caller_dir, &dir, public(10), &cold).unwrap();
        assert_eq!(client.read().unwrap(), recovery.state);
        assert_eq!(super::retained_native_replay::inventory(&root), stable);
        eprintln!("Wallet SIGKILL: boundary={boundary} original_reservation=true original_command=true native_debit_once=true caller_and_four_signers_cold=true power_loss=false independent_custody=false");
    }
    assert!(
        started.elapsed().as_secs_f64() < 60.0,
        "wallet SIGKILL custody budget"
    );
}
