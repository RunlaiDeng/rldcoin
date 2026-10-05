use super::paged_integration::{certify, retain};
use super::retained_native_replay::inventory;
use super::*;
#[test]
fn paged_sign_cost_ten_native_heights_and_full_pinned_cold() {
    let started = std::time::Instant::now();
    let mut h = Harness::with_rules(crate::paged_bft::RULES);
    h.retain = true;
    for n in 0..4 {
        retain(&h.root, n, h.heads[n]);
    }
    bft::sign_cost::take();
    crate::keystore::private_create(
        &h.root.join("owner-key.json"),
        &serde_json::to_vec(&serde_json::json!({"secret_key":hex::encode([10;32])})).unwrap(),
    )
    .unwrap();
    let mut owner = None;
    let mut owner_head = Hash::ZERO;
    let mut certification_ns = 0u128;
    let mut finalize_ns = 0u128;
    for height in 1..=10 {
        let commands = if height == 4 {
            let mut wallet = crate::wallet_agent::Agent::create(
                &h.root.join("owner-wallet"),
                &h.node,
                public(10),
            )
            .unwrap();
            let old = wallet.journal.head().unwrap();
            retain(&h.root, 4, old);
            let prepared = wallet
                .prepare(
                    &h.node,
                    crate::wallet::Request {
                        owner: public(10),
                        participants: vec![],
                        inputs: None,
                        outputs: vec![Payment {
                            owner: public(11),
                            amount: Amount(99),
                        }],
                        remote: None,
                        fee: Amount(1),
                        valid_for_blocks: 8,
                        valid_through: None,
                    },
                    old,
                )
                .unwrap();
            let signed = wallet
                .sign(
                    &h.node,
                    prepared.draft,
                    &h.root.join("owner-key.json"),
                    prepared.review_commitment,
                    old,
                )
                .unwrap();
            owner_head = signed.wallet_head;
            // Retain the separate owner head before releasing commands.
            retain(&h.root, 4, owner_head);
            owner = Some(wallet);
            signed.commands
        } else {
            vec![]
        };
        let clock = std::time::Instant::now();
        let snapshot = certify(&mut h, commands);
        certification_ns += clock.elapsed().as_nanos();
        let clock = std::time::Instant::now();
        h.node.finalize(snapshot).unwrap();
        finalize_ns += clock.elapsed().as_nanos();
        println!(
            "paged-cost complete_height={height} records={:?} elapsed={:.3}",
            h.agents.iter().map(Agent::record_count).collect::<Vec<_>>(),
            started.elapsed().as_secs_f64()
        );
    }
    let cost = bft::sign_cost::take();
    assert_eq!(cost.completed_new_signatures, 90);
    let total_ns: u128 = cost.phases_ns.iter().sum();
    assert!(total_ns > 0);
    let replay_and_validation_fraction =
        (cost.phases_ns[0] + cost.phases_ns[3]) as f64 / total_ns as f64;
    owner.as_ref().unwrap().view(&h.node, owner_head).unwrap();
    let root = h.root.clone();
    let currency = h.node.trust.currency().unwrap();
    let native = h.node.storage_head().unwrap();
    crate::keystore::private_create(&root.join("caller-native.head"), &native.0).unwrap();
    let heads = h.heads.clone();
    let seeds = h.seeds.clone();
    drop(owner);
    drop(h);
    let before = inventory(&root);
    let separately_retained_native = Hash(
        fs::read(root.join("caller-native.head"))
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let node = Store::open_pinned(
        &root.join("node"),
        &public(1),
        currency,
        separately_retained_native,
    )
    .unwrap();
    assert_eq!(node.chain.height(), 10);
    for (n, seed) in seeds.iter().enumerate() {
        let agent = Agent::open(&root.join(format!("signer-{seed}")), &node).unwrap();
        assert_eq!(agent.head().unwrap(), heads[n]);
        assert_eq!(
            fs::read(root.join(format!("caller-{n}.head"))).unwrap(),
            heads[n].0
        );
    }
    let wallet = crate::wallet_agent::Agent::open(&root.join("owner-wallet"), &node).unwrap();
    assert_eq!(wallet.journal.head().unwrap(), owner_head);
    assert_eq!(fs::read(root.join("caller-4.head")).unwrap(), owner_head.0);
    wallet.view(&node, owner_head).unwrap();
    assert!(node
        .chain
        .ledger
        .coins
        .values()
        .any(|c| c.payment.owner == public(11)
            && c.payment.amount == Amount(99)
            && c.mature <= 10));
    assert_eq!(inventory(&root), before);
    println!(
        "paged-cost-result {}",
        serde_json::json!({
            "heights":10,"actual_signatures":cost.completed_new_signatures,
            "phase_names":["first_complete_replay","exact_request_scan","current_execution_and_sign","new_record_and_current_recheck","durable_append"],
            "phase_seconds":cost.phases_ns.map(|ns|ns as f64/1e9),"measured_sign_seconds":total_ns as f64/1e9,
            "replay_and_validation_fraction":replay_and_validation_fraction,
        "first_replay_fraction":cost.phases_ns[0] as f64/total_ns as f64,
        "post_sign_validation_fraction":cost.phases_ns[3] as f64/total_ns as f64,
        "second_complete_old_replay":false,
            "certification_seconds":certification_ns as f64/1e9,"store_finalize_seconds":finalize_ns as f64/1e9,
            "same_process_full_genesis_cold":true,"wallet99_mature":true,"private_inventory_unchanged":true,
            "actual_over128_or_height65":false,"full_fault":false,"independent_freshness":false,"total_test_seconds":started.elapsed().as_secs_f64()
        })
    );
}
