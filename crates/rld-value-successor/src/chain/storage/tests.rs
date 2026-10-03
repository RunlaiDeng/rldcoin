use super::*;
use crate::chain::finality::{FinalityCertificate, FinalityStatement};
use crate::chain::{mine_batch, Command, ObservationPolicy};
use rld_core::{generate_identity, sign_bytes, Amount, Identity};
use rld_cross_region::{
    value::{ExportCommand, ExportIntent},
    CourierStore,
};
use rld_pow::transition::Approval;
use rld_pow::{mine_batch as mine_v1, target_limit, Context, BLOCK_SECONDS};

#[test]
fn earth_finality_survives_restart_and_rejects_deep_source_fork() {
    let owner = generate_identity();
    let v1 = v1_chain(1, &owner);
    let root = directory();
    let adoption = Hash([44; 32]);
    let mut signers = (0..4).map(|_| generate_identity()).collect::<Vec<_>>();
    signers.sort_by(|a, b| a.public_key.cmp(&b.public_key));
    let keys = signers
        .iter()
        .map(|key| key.public_key.clone())
        .collect::<Vec<_>>();
    let (finalized, fork, certificate) = {
        let mut store =
            CandidateStore::open_finalized(&root, &v1, 2_000_000, adoption, keys.clone()).unwrap();
        let fork = branch_block(
            store.chain(),
            v1.tip(),
            &owner,
            1_000_000 + 2 * BLOCK_SECONDS + 1,
        );
        let mut first = None;
        for index in 0..12 {
            let time = 1_000_000 + (index + 2) * BLOCK_SECONDS;
            let mut block = store
                .chain()
                .template(owner.public_key.clone(), time, vec![])
                .unwrap();
            while !mine_batch(&mut block, 100_000).unwrap() {}
            if first.is_none() {
                first = Some(block.header.id().unwrap());
            }
            store.accept(block, 2_000_000).unwrap();
        }
        let finalized = first.unwrap();
        let statement =
            FinalityStatement::from_chain(store.chain(), adoption, finalized, None).unwrap();
        let bytes = statement.signing_bytes().unwrap();
        let approvals = signers
            .iter()
            .map(|key| Approval {
                public_key: key.public_key.clone(),
                signature: sign_bytes(&key.secret_key, &bytes).unwrap(),
            })
            .collect();
        let certificate = FinalityCertificate {
            statement,
            approvals,
        };
        store.install_finality(certificate.clone()).unwrap();
        assert!(store.accept(fork.clone(), 2_000_000).is_err());
        (finalized, fork, certificate)
    };
    {
        let mut reopened =
            CandidateStore::open_finalized(&root, &v1, 2_000_000, adoption, keys.clone()).unwrap();
        assert_eq!(
            reopened.chain().finalized(),
            Some((finalized, v1.height() + 1))
        );
        assert!(reopened.accept(fork, 2_000_000).is_err());
        assert_eq!(reopened.finality(), Some(&certificate));
    }
    let mut tampered = certificate;
    tampered.approvals[0].signature = "00".into();
    fs::write(
        root.join("FINALITY"),
        serde_json::to_vec(&tampered).unwrap(),
    )
    .unwrap();
    assert!(CandidateStore::open_finalized(&root, &v1, 2_000_000, adoption, keys).is_err());
    fs::remove_dir_all(root).unwrap();
}

fn v1_chain(blocks: u128, owner: &Identity) -> Chain {
    let mut chain = Chain::new(Context {
        network_domain: "fixture:durable-successor".into(),
        zone_id: "fixture-earth".into(),
        currency_genesis: Hash([1; 32]),
        manifest_pin: Hash([2; 32]),
        transition_id: Hash([3; 32]),
        legacy_height: 9,
        legacy_state_root: Hash([4; 32]),
        started_at: 1_000_000,
        initial_target: target_limit(),
    })
    .unwrap();
    for sequence in 1..=blocks {
        let timestamp = 1_000_000 + sequence as u64 * BLOCK_SECONDS;
        let mut block = chain
            .template(owner.public_key.clone(), timestamp, vec![])
            .unwrap();
        while !mine_v1(&mut block, 100_000).unwrap() {}
        chain.accept(block, timestamp).unwrap();
    }
    chain
}

fn directory() -> PathBuf {
    std::env::temp_dir().join(format!(
        "rld-successor-store-{}",
        generate_identity().public_key
    ))
}

fn export(v1: &Chain, owner: &Identity, recipient: &Identity) -> ExportCommand {
    let (input, coin) = v1
        .state()
        .coins
        .iter()
        .find(|(_, coin)| {
            coin.output.owner == owner.public_key && coin.spendable_height <= v1.height() + 1
        })
        .unwrap();
    let amount = Amount::from_rld_whole(1).unwrap();
    let source_fee = Amount(1);
    let intent = ExportIntent {
        source_chain_id: v1.context.chain_id().unwrap(),
        destination_chain_id: Hash([9; 32]),
        input: input.clone(),
        owner: owner.public_key.clone(),
        recipient: recipient.public_key.clone(),
        amount,
        source_fee,
        destination_fee: Amount(1),
        change: coin
            .output
            .amount
            .checked_sub(amount.checked_add(source_fee).unwrap())
            .unwrap(),
        valid_through_height: v1.height() + 10,
    };
    ExportCommand {
        owner_signature: sign_bytes(&owner.secret_key, &intent.signing_bytes().unwrap()).unwrap(),
        intent,
    }
}

fn branch_block(chain: &CandidateChain, parent: Hash, miner: &Identity, timestamp: u64) -> Block {
    let commands = vec![];
    let mut header = chain
        .next_header(parent, miner.public_key.clone(), timestamp, &commands)
        .unwrap();
    header.state_root = chain
        .execute(parent, &header, &commands)
        .unwrap()
        .root()
        .unwrap();
    let mut block = Block { header, commands };
    while !mine_batch(&mut block, 100_000).unwrap() {}
    block
}

#[test]
fn checkpoint_requires_replayed_block_and_rejects_tampered_state() {
    let owner = generate_identity();
    let miner = generate_identity();
    let v1 = v1_chain(1, &owner);
    let root = directory();
    let timestamp = 1_000_000 + 2 * BLOCK_SECONDS;
    let (tip, state_root) = {
        let mut store = CandidateStore::open(&root, &v1, timestamp).unwrap();
        assert!(store.write_replayed_checkpoint().is_err());
        let mut block = store
            .chain()
            .template(miner.public_key.clone(), timestamp, vec![])
            .unwrap();
        while !mine_batch(&mut block, 100_000).unwrap() {}
        assert!(store.accept(block, timestamp).unwrap());
        let tip = store.write_replayed_checkpoint().unwrap();
        (tip, store.chain().state().root().unwrap())
    };
    let checkpoint_path = root.join("CHECKPOINT");
    let original = fs::read(&checkpoint_path).unwrap();
    let checkpoint: Checkpoint = serde_json::from_slice(&original).unwrap();
    let reopened = CandidateStore::open(&root, &v1, timestamp).unwrap();
    assert_eq!(reopened.chain().tip(), tip);
    assert_eq!(reopened.chain().state().root().unwrap(), state_root);
    drop(reopened);

    let mut malformed = serde_json::to_value(&checkpoint).unwrap();
    malformed["state"]["coins"][0][1]["output"]["owner"] = serde_json::json!("00".repeat(32));
    let malformed: Checkpoint = serde_json::from_value(malformed).unwrap();
    fs::write(&checkpoint_path, serde_json::to_vec(&malformed).unwrap()).unwrap();
    assert!(CandidateStore::open(&root, &v1, timestamp).is_err());

    let mut duplicated = serde_json::to_value(&checkpoint).unwrap();
    let first_coin = duplicated["state"]["coins"][0].clone();
    duplicated["state"]["coins"]
        .as_array_mut()
        .unwrap()
        .push(first_coin);
    let duplicated: Checkpoint = serde_json::from_value(duplicated).unwrap();
    fs::write(&checkpoint_path, serde_json::to_vec(&duplicated).unwrap()).unwrap();
    assert!(CandidateStore::open(&root, &v1, timestamp).is_err());

    let mut wrong_root = serde_json::to_value(&checkpoint).unwrap();
    let original_owner = wrong_root["state"]["coins"][0][1]["output"]["owner"]
        .as_str()
        .unwrap();
    let other_owner = if original_owner == owner.public_key {
        &miner.public_key
    } else {
        &owner.public_key
    };
    wrong_root["state"]["coins"][0][1]["output"]["owner"] = serde_json::json!(other_owner);
    let wrong_root: Checkpoint = serde_json::from_value(wrong_root).unwrap();
    fs::write(&checkpoint_path, serde_json::to_vec(&wrong_root).unwrap()).unwrap();
    assert!(CandidateStore::open(&root, &v1, timestamp).is_err());

    fs::write(&checkpoint_path, original).unwrap();
    assert!(CandidateStore::open(&root, &v1, timestamp).is_ok());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn restart_replays_mined_export_checkpoint_and_retains_lock_exclusivity() {
    let owner = generate_identity();
    let recipient = generate_identity();
    let miner = generate_identity();
    let v1 = v1_chain(100, &owner);
    let root = directory();
    let courier_root = root.with_extension("courier");
    let first_time = 1_000_000 + 101 * BLOCK_SECONDS;
    let (expected_tip, expected_root, checkpoint, policy, proof, bundle) = {
        let mut store = CandidateStore::open(&root, &v1, first_time).unwrap();
        assert!(CandidateStore::open(&root, &v1, first_time).is_err());
        let export = export(&v1, &owner, &recipient);
        let export_id = export.intent.id().unwrap();
        let mut first = store
            .chain()
            .template(
                miner.public_key.clone(),
                first_time,
                vec![Command::Export(export)],
            )
            .unwrap();
        while !mine_batch(&mut first, 100_000).unwrap() {}
        let checkpoint = first.header.id().unwrap();
        assert!(store.accept(first.clone(), first_time).unwrap());
        assert!(!store.accept(first, first_time).unwrap());
        let proof = store.chain().state().membership_proof(export_id).unwrap();
        let policy = ObservationPolicy {
            source_chain_id: v1.context.chain_id().unwrap(),
            accepted_v1_tip: v1.tip(),
            minimum_confirmations: 2,
            minimum_cumulative_work: store.chain().chainwork(),
        };
        let second_time = first_time + BLOCK_SECONDS;
        let mut second = store
            .chain()
            .template(miner.public_key.clone(), second_time, vec![])
            .unwrap();
        while !mine_batch(&mut second, 100_000).unwrap() {}
        assert!(store.accept(second, second_time).unwrap());
        assert_eq!(
            store.write_replayed_checkpoint().unwrap(),
            store.chain().tip()
        );
        assert!(store.healthy());
        store
            .chain()
            .verify_export_on_best_chain(&proof, checkpoint, &policy)
            .unwrap();
        let bundle = store.chain().export_bundle(export_id, checkpoint).unwrap();
        store
            .chain()
            .observe_export_bundle(&bundle, &policy)
            .unwrap();
        (
            store.chain().tip(),
            store.chain().state().root().unwrap(),
            checkpoint,
            policy,
            proof,
            bundle,
        )
    };
    let mut courier = CourierStore::open(&courier_root).unwrap();
    assert!(courier.enqueue(bundle.clone()).unwrap());
    drop(courier);
    let courier = CourierStore::open(&courier_root).unwrap();
    let carried = courier
        .bundle_for_export(bundle.source_chain_id, bundle.export_id)
        .unwrap()
        .unwrap();
    assert_eq!(carried, bundle);
    let mut reopened = CandidateStore::open(&root, &v1, first_time + 2 * BLOCK_SECONDS).unwrap();
    assert_eq!(reopened.chain().tip(), expected_tip);
    assert_eq!(reopened.chain().state().root().unwrap(), expected_root);
    reopened
        .chain()
        .verify_export_on_best_chain(&proof, checkpoint, &policy)
        .unwrap();
    reopened
        .chain()
        .observe_export_bundle(&carried, &policy)
        .unwrap();
    let side1 = branch_block(reopened.chain(), v1.tip(), &miner, first_time + 1);
    let side1_id = side1.header.id().unwrap();
    assert!(!reopened.accept(side1, first_time + 1).unwrap());
    let side2 = branch_block(
        reopened.chain(),
        side1_id,
        &miner,
        first_time + BLOCK_SECONDS + 1,
    );
    let side2_id = side2.header.id().unwrap();
    assert!(!reopened
        .accept(side2, first_time + BLOCK_SECONDS + 1)
        .unwrap());
    drop(reopened);

    let mut tied = CandidateStore::open(&root, &v1, first_time + 2 * BLOCK_SECONDS).unwrap();
    assert_eq!(tied.chain().tip(), expected_tip);
    let side3 = branch_block(
        tied.chain(),
        side2_id,
        &miner,
        first_time + 2 * BLOCK_SECONDS + 1,
    );
    let side3_id = side3.header.id().unwrap();
    assert!(tied
        .accept(side3, first_time + 2 * BLOCK_SECONDS + 1)
        .unwrap());
    assert!(tied
        .chain()
        .verify_export_on_best_chain(&proof, checkpoint, &policy)
        .is_err());
    assert!(tied
        .chain()
        .observe_export_bundle(&bundle, &policy)
        .is_err());
    drop(tied);
    let reorganized = CandidateStore::open(&root, &v1, first_time + 3 * BLOCK_SECONDS).unwrap();
    assert_eq!(reorganized.chain().tip(), side3_id);
    assert!(reorganized
        .chain()
        .verify_export_on_best_chain(&proof, checkpoint, &policy)
        .is_err());
    assert!(reorganized
        .chain()
        .observe_export_bundle(&carried, &policy)
        .is_err());
    drop(reorganized);
    drop(courier);
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(courier_root).unwrap();
}

#[test]
fn wrong_anchor_invalid_block_and_tampered_disk_block_fail_closed() {
    let owner = generate_identity();
    let miner = generate_identity();
    let mut v1 = v1_chain(1, &owner);
    let root = directory();
    let timestamp = 1_000_000 + 2 * BLOCK_SECONDS;
    let block_id = {
        let mut store = CandidateStore::open(&root, &v1, timestamp).unwrap();
        let previous = store.chain().tip();
        let mut forged = store
            .chain()
            .template(miner.public_key.clone(), timestamp, vec![])
            .unwrap();
        forged.header.state_root = Hash([7; 32]);
        forged.header.nonce = 0;
        while !mine_batch(&mut forged, 100_000).unwrap() {}
        assert!(store.accept(forged, timestamp).is_err());
        assert_eq!(store.chain().tip(), previous);
        assert_eq!(fs::read_dir(root.join("blocks")).unwrap().count(), 0);
        let mut valid = store
            .chain()
            .template(miner.public_key.clone(), timestamp, vec![])
            .unwrap();
        while !mine_batch(&mut valid, 100_000).unwrap() {}
        let id = valid.header.id().unwrap();
        assert!(store.accept(valid, timestamp).unwrap());
        id
    };
    let anchor_path = root.join("anchor.json");
    let current_anchor = fs::read(&anchor_path).unwrap();
    let current_text = String::from_utf8(current_anchor.clone()).unwrap();
    let anchor: serde_json::Value = serde_json::from_slice(&current_anchor).unwrap();
    assert_eq!(anchor["format"], "RLD-EARTH-UNIFIED-SUCCESSOR-STORE");
    assert_eq!(
        anchor["v1_state_root"],
        serde_json::json!(v1.state().root().unwrap())
    );
    assert_ne!(anchor["v1_state_root"], anchor["successor_base_root"]);
    assert_eq!(
        anchor["v1_manifest_pin"],
        serde_json::json!(v1.context.manifest_pin)
    );
    assert_eq!(
        anchor["v1_adoption_id"],
        serde_json::json!(v1.context.transition_id)
    );
    assert_eq!(anchor["v1_chainwork"], serde_json::json!(v1.chainwork()));
    assert_eq!(anchor["v1_emitted"], serde_json::json!(v1.state().emitted));
    let source = anchor["successor_source_commitment"].as_str().unwrap();
    let changed_source = current_text.replacen(source, &Hash([0; 32]).to_hex(), 1);
    assert_ne!(changed_source, current_text);
    fs::write(&anchor_path, changed_source).unwrap();
    assert!(CandidateStore::open(&root, &v1, timestamp).is_err());
    let swapped_root = current_text.replacen(
        anchor["v1_state_root"].as_str().unwrap(),
        anchor["successor_base_root"].as_str().unwrap(),
        1,
    );
    assert_ne!(swapped_root, current_text);
    fs::write(&anchor_path, swapped_root).unwrap();
    assert!(CandidateStore::open(&root, &v1, timestamp).is_err());
    let old_format = current_text.replace(
        "RLD-EARTH-UNIFIED-SUCCESSOR-STORE",
        "RLD-RETIRED-UNIFIED-SUCCESSOR-STORE",
    );
    assert_ne!(old_format, current_text);
    fs::write(&anchor_path, old_format).unwrap();
    assert!(CandidateStore::open(&root, &v1, timestamp).is_err());
    fs::write(&anchor_path, current_anchor).unwrap();
    let mut v1_next = v1
        .template(owner.public_key.clone(), timestamp, vec![])
        .unwrap();
    while !mine_v1(&mut v1_next, 100_000).unwrap() {}
    v1.accept(v1_next, timestamp).unwrap();
    assert!(CandidateStore::open(&root, &v1, timestamp).is_err());

    fs::write(root.join("blocks").join("incomplete.pending"), b"partial").unwrap();
    let old_v1 = v1_chain(1, &owner);
    let replayed = CandidateStore::open(&root, &old_v1, timestamp).unwrap();
    assert_eq!(replayed.chain().tip(), block_id);
    drop(replayed);
    fs::write(
        root.join("blocks")
            .join(format!("{}.json", block_id.to_hex())),
        b"{}",
    )
    .unwrap();
    assert!(CandidateStore::open(&root, &old_v1, timestamp).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn failed_block_or_head_write_keeps_memory_unpublished_and_restart_replays_disk() {
    let owner = generate_identity();
    let miner = generate_identity();
    let v1 = v1_chain(1, &owner);
    let root = directory();
    let first_time = 1_000_000 + 2 * BLOCK_SECONDS;
    let mut store = CandidateStore::open(&root, &v1, first_time).unwrap();
    let old_tip = store.chain().tip();
    let old_root = store.chain().state().root().unwrap();
    let mut first = store
        .chain()
        .template(miner.public_key.clone(), first_time, vec![])
        .unwrap();
    while !mine_batch(&mut first, 100_000).unwrap() {}
    let first_id = first.header.id().unwrap();
    let block_pending = root
        .join("blocks")
        .join(format!("{}.pending", first_id.to_hex()));
    fs::create_dir(&block_pending).unwrap();
    assert!(store.accept(first.clone(), first_time).is_err());
    assert!(!store.healthy());
    assert_eq!(store.chain().tip(), old_tip);
    assert_eq!(store.chain().state().root().unwrap(), old_root);
    assert!(!root
        .join("blocks")
        .join(format!("{}.json", first_id.to_hex()))
        .exists());
    drop(store);
    fs::remove_dir(&block_pending).unwrap();

    let mut store = CandidateStore::open(&root, &v1, first_time).unwrap();
    assert_eq!(store.chain().tip(), old_tip);
    assert!(store.accept(first, first_time).unwrap());
    let first_root = store.chain().state().root().unwrap();
    let second_time = first_time + BLOCK_SECONDS;
    let mut second = store
        .chain()
        .template(miner.public_key, second_time, vec![])
        .unwrap();
    while !mine_batch(&mut second, 100_000).unwrap() {}
    let second_id = second.header.id().unwrap();
    let second_root = second.header.state_root;
    let head_pending = root.join("HEAD.pending");
    fs::create_dir(&head_pending).unwrap();
    assert!(store.accept(second, second_time).is_err());
    assert!(!store.healthy());
    assert_eq!(store.chain().tip(), first_id);
    assert_eq!(store.chain().state().root().unwrap(), first_root);
    assert!(root
        .join("blocks")
        .join(format!("{}.json", second_id.to_hex()))
        .exists());
    drop(store);
    fs::remove_dir(&head_pending).unwrap();

    let replayed = CandidateStore::open(&root, &v1, second_time).unwrap();
    assert_eq!(replayed.chain().tip(), second_id);
    assert_eq!(replayed.chain().state().root().unwrap(), second_root);
    drop(replayed);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn submitted_candidate_command_survives_restart_and_returns_after_reorg() {
    let owner = generate_identity();
    let recipient = generate_identity();
    let miner = generate_identity();
    let v1 = v1_chain(100, &owner);
    let root = directory();
    let t1 = 1_000_000 + 101 * BLOCK_SECONDS;
    let command = Command::Export(export(&v1, &owner, &recipient));
    let mut bad = command.clone();
    if let Command::Export(export) = &mut bad {
        export.owner_signature = "00".into();
    }
    let mut store = CandidateStore::open(&root, &v1, t1).unwrap();
    assert!(store.submit_command(bad, &miner.public_key, t1).is_err());
    assert_eq!(store.submitted_count(), 0);
    let pending_path = root.join("submissions").join("00000000.pending");
    fs::create_dir(&pending_path).unwrap();
    assert!(store
        .submit_command(command.clone(), &miner.public_key, t1)
        .is_err());
    assert!(!store.healthy());
    assert_eq!(store.submitted_count(), 0);
    drop(store);
    fs::remove_dir(pending_path).unwrap();
    let mut store = CandidateStore::open(&root, &v1, t1).unwrap();
    let (command_id, submitted) = store
        .submit_command(command.clone(), &miner.public_key, t1)
        .unwrap();
    assert!(submitted);
    assert!(store.has_submission(command_id).unwrap());
    assert_eq!(store.selected_inclusion(command_id).unwrap(), None);
    assert!(
        !store
            .submit_command(command.clone(), &miner.public_key, t1)
            .unwrap()
            .1
    );
    assert_eq!(
        store.mineable_commands(&miner.public_key, t1).unwrap(),
        vec![command.clone()]
    );
    drop(store);
    let mut reopened = CandidateStore::open(&root, &v1, t1).unwrap();
    assert_eq!(reopened.submitted_count(), 1);
    let main = reopened
        .chain()
        .template(
            miner.public_key.clone(),
            t1,
            reopened.mineable_commands(&miner.public_key, t1).unwrap(),
        )
        .unwrap();
    let mut main = main;
    while !mine_batch(&mut main, 100_000).unwrap() {}
    assert!(reopened.accept(main, t1).unwrap());
    assert_eq!(
        reopened.selected_inclusion(command_id).unwrap().unwrap().2,
        1
    );
    assert!(reopened
        .mineable_commands(&miner.public_key, t1 + BLOCK_SECONDS)
        .unwrap()
        .is_empty());
    let side1 = branch_block(reopened.chain(), v1.tip(), &miner, t1 + 1);
    let side1_id = side1.header.id().unwrap();
    assert!(!reopened.accept(side1, t1 + 1).unwrap());
    let side2 = branch_block(reopened.chain(), side1_id, &miner, t1 + BLOCK_SECONDS + 1);
    assert!(reopened.accept(side2, t1 + BLOCK_SECONDS + 1).unwrap());
    assert_eq!(reopened.selected_inclusion(command_id).unwrap(), None);
    assert_eq!(
        reopened
            .mineable_commands(&miner.public_key, t1 + 2 * BLOCK_SECONDS)
            .unwrap(),
        vec![command.clone()]
    );
    drop(reopened);
    let mut recovered = CandidateStore::open(&root, &v1, t1 + 2 * BLOCK_SECONDS).unwrap();
    assert_eq!(recovered.submitted_count(), 1);
    assert_eq!(
        recovered
            .mineable_commands(&miner.public_key, t1 + 2 * BLOCK_SECONDS)
            .unwrap()
            .len(),
        1
    );
    let return_time = t1 + 3 * BLOCK_SECONDS;
    let mut returned = recovered
        .chain()
        .template(miner.public_key.clone(), return_time, vec![command.clone()])
        .unwrap();
    while !mine_batch(&mut returned, 100_000).unwrap() {}
    let returned_id = returned.header.id().unwrap();
    assert!(recovered.accept(returned, return_time).unwrap());
    assert_eq!(
        recovered.selected_inclusion(command_id).unwrap(),
        Some((returned_id, v1.height() + 3, 1))
    );
    assert!(recovered.pending_commands().unwrap().is_empty());
    drop(recovered);
    let recovered = CandidateStore::open(&root, &v1, return_time).unwrap();
    assert_eq!(
        recovered.selected_inclusion(command_id).unwrap(),
        Some((returned_id, v1.height() + 3, 1))
    );
    drop(recovered);
    let submission_path = root.join("submissions").join("00000000.json");
    let original = fs::read(&submission_path).unwrap();
    fs::write(&submission_path, b"{}").unwrap();
    assert!(CandidateStore::open(&root, &v1, t1 + 2 * BLOCK_SECONDS).is_err());
    fs::write(&submission_path, original).unwrap();
    fs::write(root.join("submitted.json"), b"{}").unwrap();
    assert!(CandidateStore::open(&root, &v1, t1 + 2 * BLOCK_SECONDS).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn included_submission_history_can_exceed_old_128_command_limit() {
    let owner = generate_identity();
    let recipient = generate_identity();
    let miner = generate_identity();
    let v1 = v1_chain(229, &owner);
    let root = directory();
    let t1 = 1_000_000 + 230 * BLOCK_SECONDS;
    let mut store = CandidateStore::open(&root, &v1, t1).unwrap();
    let base = export(&v1, &owner, &recipient);
    let mut commands = Vec::new();
    for (input, coin) in v1
        .state()
        .coins
        .iter()
        .filter(|(_, coin)| coin.spendable_height <= v1.height() + 1)
        .take(129)
    {
        let mut export = base.clone();
        export.intent.input = input.clone();
        export.intent.change = coin
            .output
            .amount
            .checked_sub(
                export
                    .intent
                    .amount
                    .checked_add(export.intent.source_fee)
                    .unwrap(),
            )
            .unwrap();
        export.owner_signature =
            sign_bytes(&owner.secret_key, &export.intent.signing_bytes().unwrap()).unwrap();
        commands.push(Command::Export(export));
    }
    assert_eq!(commands.len(), 129);
    let mut block = store
        .chain()
        .template(miner.public_key.clone(), t1, commands[..128].to_vec())
        .unwrap();
    while !mine_batch(&mut block, 100_000).unwrap() {}
    assert!(store.accept(block, t1).unwrap());
    // Seed the old 128-command history as immutable files. Every command was
    // already validated by the accepted block; this avoids repeating the
    // expensive 128-signature block template for each journal insertion.
    for (index, command) in commands[..128].iter().enumerate() {
        fs::write(
            root.join("submissions").join(format!("{index:08}.json")),
            serde_json::to_vec(command).unwrap(),
        )
        .unwrap();
    }
    drop(store);
    let mut store = CandidateStore::open(&root, &v1, t1).unwrap();
    assert_eq!(store.submitted_count(), 128);
    assert!(store.pending_commands().unwrap().is_empty());
    assert!(
        store
            .submit_command(commands[128].clone(), &miner.public_key, t1 + BLOCK_SECONDS)
            .unwrap()
            .1
    );
    assert_eq!(store.submitted_count(), 129);
    assert_eq!(store.pending_commands().unwrap().len(), 1);
    drop(store);
    let reopened = CandidateStore::open(&root, &v1, t1 + BLOCK_SECONDS).unwrap();
    assert_eq!(reopened.submitted_count(), 129);
    assert_eq!(reopened.pending_commands().unwrap().len(), 1);
    assert_eq!(
        reopened
            .mineable_commands(&miner.public_key, t1 + BLOCK_SECONDS)
            .unwrap(),
        vec![commands[128].clone()]
    );
    drop(reopened);
    fs::remove_dir_all(root).unwrap();
}
