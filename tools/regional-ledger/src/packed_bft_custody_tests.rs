//! Public no-value Native custody inputs; no independent control qualification.
use super::paged_integration::{certify, retain};
use super::retained_native_replay::inventory;
use super::*;
use std::process::Command as Process;

#[derive(Serialize, Deserialize)]
struct Pins {
    currency: Hash,
    native: Hash,
    signers: Vec<Hash>,
    seeds: Vec<u8>,
    owners: Vec<(u8, Hash)>,
}

fn payment(
    h: &Harness,
    owner: u8,
    recipient: u8,
    amount: Amount,
    input: Option<Hash>,
) -> (Vec<Command>, crate::wallet_agent::Agent, Hash) {
    let key = h.root.join(format!("owner-key-{owner}.json"));
    crate::keystore::private_create(
        &key,
        &serde_json::to_vec(&serde_json::json!({"secret_key":hex::encode([owner;32])})).unwrap(),
    )
    .unwrap();
    let mut wallet = crate::wallet_agent::Agent::create(
        &h.root.join(format!("owner-{owner}")),
        &h.node,
        public(owner),
    )
    .unwrap();
    let previous = wallet.journal.head().unwrap();
    retain(&h.root, usize::from(owner), previous);
    let prepared = wallet
        .prepare(
            &h.node,
            crate::wallet::Request {
                owner: public(owner),
                participants: vec![],
                inputs: input.map(|id| vec![id]),
                outputs: vec![Payment {
                    owner: public(recipient),
                    amount,
                }],
                remote: None,
                fee: Amount(1),
                valid_for_blocks: 8,
                valid_through: None,
            },
            previous,
        )
        .unwrap();
    let signed = wallet
        .sign(
            &h.node,
            prepared.draft,
            &key,
            prepared.review_commitment,
            previous,
        )
        .unwrap();
    retain(&h.root, usize::from(owner), signed.wallet_head);
    (signed.commands, wallet, signed.wallet_head)
}

#[test]
#[ignore = "bounded parent invokes a fresh pinned child explicitly"]
fn packed_original_custody_cold_child() {
    let root = PathBuf::from(
        std::env::var_os("RLD_PACKED_CUSTODY_COLD_ROOT").expect("bounded parent private path"),
    );
    let pins: Pins = crate::storage::read_json(&root.join("pins.json")).unwrap();
    let before = inventory(&root);
    let node =
        Store::open_pinned(&root.join("node"), &public(1), pins.currency, pins.native).unwrap();
    assert_eq!(node.chain.height(), 8);
    assert_eq!(node.blocks().unwrap().count(), 8);
    assert_eq!(
        node.history_layout().unwrap().0,
        "RLD-NATIVE-PACKED-BFT-STORE-FIXTURE-V1"
    );
    assert_eq!(
        fs::read(root.join("caller-native.head")).unwrap(),
        pins.native.0
    );
    for (n, seed) in pins.seeds.iter().enumerate() {
        let agent = Agent::open(&root.join(format!("signer-{seed}")), &node).unwrap();
        assert_eq!(agent.head().unwrap(), pins.signers[n]);
        assert_eq!(
            fs::read(root.join(format!("caller-{n}.head"))).unwrap(),
            pins.signers[n].0
        );
        assert!(agent.record_count() >= 16);
        assert_eq!(
            agent.retained_messages(&node).unwrap().len(),
            agent.record_count()
        );
    }
    for (owner, head) in &pins.owners {
        let wallet =
            crate::wallet_agent::Agent::open(&root.join(format!("owner-{owner}")), &node).unwrap();
        assert_eq!(wallet.journal.head().unwrap(), *head);
        assert_eq!(
            fs::read(root.join(format!("caller-{owner}.head"))).unwrap(),
            head.0
        );
        wallet.view(&node, *head).unwrap();
    }
    assert!(node.chain.ledger.coins.values().any(|coin| {
        coin.payment.owner == public(14)
            && coin.payment.amount == Amount(98)
            && coin.mature <= node.chain.height()
    }));
    assert_eq!(inventory(&root), before);
}

#[test]
fn packed_ledger_four_original_signer_journals_two_owner_payments_and_fresh_cold() {
    let started = std::time::Instant::now();
    let mut h = Harness::with_rules(crate::paged_bft::PACKED_RULES);
    h.retain = true;
    eprintln!("Fresh packed Native custody fixture: {}", h.root.display());
    for n in 0..4 {
        retain(&h.root, n, h.heads[n]);
    }
    let mut owners = Vec::new();
    for height in 1..=8 {
        assert!(
            started.elapsed().as_secs_f64() < 60.0,
            "packed custody deadline"
        );
        let commands = if height == 4 {
            let (commands, wallet, head) = payment(&h, 10, 11, Amount(99), None);
            owners.push((10, wallet, head));
            commands
        } else if height == 6 {
            let input = *h
                .node
                .chain
                .ledger
                .coins
                .iter()
                .find(|(_, coin)| {
                    coin.payment.owner == public(11)
                        && coin.payment.amount == Amount(99)
                        && coin.mature <= h.node.chain.height()
                })
                .unwrap()
                .0;
            let (commands, wallet, head) = payment(&h, 11, 14, Amount(98), Some(input));
            owners.push((11, wallet, head));
            commands
        } else {
            vec![]
        };
        let snapshot = certify(&mut h, commands);
        h.node.finalize(snapshot).unwrap();
        assert_eq!(h.node.chain.height(), height);
    }
    let before = inventory(&h.root);
    let request = Request::Timeout {
        context: Context::current(&h.node).unwrap(),
        round: 0,
    };
    assert!(h.agents[0]
        .sign(&h.node, request.clone(), None, h.heads[0])
        .is_err());
    assert!(h.agents[0]
        .sign(
            &h.node,
            request,
            Some(&h.root.join(format!("key-{}.json", h.seeds[0]))),
            Hash::ZERO,
        )
        .is_err());
    assert_eq!(inventory(&h.root), before);
    let pins = Pins {
        currency: h.node.trust.currency().unwrap(),
        native: h.node.storage_head().unwrap(),
        signers: h.heads.clone(),
        seeds: h.seeds.clone(),
        owners: owners
            .iter()
            .map(|(owner, _, head)| (*owner, *head))
            .collect(),
    };
    crate::keystore::private_create(&h.root.join("caller-native.head"), &pins.native.0).unwrap();
    crate::keystore::private_create(
        &h.root.join("pins.json"),
        &serde_json::to_vec(&pins).unwrap(),
    )
    .unwrap();
    let root = h.root.clone();
    drop(owners);
    drop(h);
    let output = Process::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tests::regional_bft::packed_custody::packed_original_custody_cold_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("RLD_PACKED_CUSTODY_COLD_ROOT", &root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fresh cold failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        started.elapsed().as_secs_f64() < 60.0,
        "packed custody cold deadline"
    );
    eprintln!("Complete Native custody cold replay, original heads and byte inventory verified");
}
