use super::*;
use crate::{
    chain::Command,
    destination::tests::{mine_source, signed_destination_payment, v1_chain},
};
use rld_core::{generate_identity, sign_bytes, Amount};
use rld_cross_region::value::{ExportCommand, ExportIntent};
use rld_pow::{OutPoint, BLOCK_SECONDS};

fn directory() -> PathBuf {
    std::env::temp_dir().join(format!(
        "rld-destination-simulation-{}",
        generate_identity().public_key
    ))
}

#[test]
fn import_log_replays_once_and_persists_halt_after_source_reorganization() {
    let owner = generate_identity();
    let recipient = generate_identity();
    let onward_recipient = generate_identity();
    let miner = generate_identity();
    let destination_operator = generate_identity();
    let wrong_operator = generate_identity();
    let v1 = v1_chain(100, &owner);
    let mut source = CandidateChain::from_replayed_pow_chain(&v1).unwrap();
    let mut alternate = source.clone();
    let destination_id = Hash([9; 32]);
    let (input, coin) = v1
        .state()
        .coins
        .iter()
        .find(|(_, coin)| coin.spendable_height <= v1.height() + 1)
        .unwrap();
    let amount = Amount::from_rld_whole(1).unwrap();
    let intent = ExportIntent {
        source_chain_id: v1.context.chain_id().unwrap(),
        destination_chain_id: destination_id,
        input: input.clone(),
        owner: owner.public_key.clone(),
        recipient: recipient.public_key.clone(),
        amount,
        source_fee: Amount(1),
        destination_fee: Amount(101),
        change: coin
            .output
            .amount
            .checked_sub(amount.checked_add(Amount(1)).unwrap())
            .unwrap(),
        valid_through_height: v1.height() + 10,
    };
    let export_id = intent.id().unwrap();
    let command = ExportCommand {
        owner_signature: sign_bytes(&owner.secret_key, &intent.signing_bytes().unwrap()).unwrap(),
        intent,
    };
    let first_time = 1_000_000 + 101 * BLOCK_SECONDS;
    let first = mine_source(
        &mut source,
        &miner,
        first_time,
        vec![Command::Export(command)],
    );
    let checkpoint = first.header.id().unwrap();
    let policy = ObservationPolicy {
        source_chain_id: v1.context.chain_id().unwrap(),
        accepted_v1_tip: v1.tip(),
        minimum_confirmations: 2,
        minimum_cumulative_work: source.chainwork(),
    };
    mine_source(&mut source, &miner, first_time + BLOCK_SECONDS, vec![]);
    let bundle = source.export_bundle(export_id, checkpoint).unwrap();
    let root = directory();
    let (expected_root, first_ack) = {
        let mut store =
            DestinationStore::open(&root, destination_id, policy.clone(), &source).unwrap();
        assert!(DestinationStore::open(&root, destination_id, policy.clone(), &source).is_err());
        assert!(store
            .attest_import(
                &source,
                &bundle,
                &destination_operator.public_key,
                &destination_operator.secret_key
            )
            .is_err());
        let mut wrong = bundle.clone();
        wrong.source_height += 1;
        assert!(store.import(&source, wrong, 1, &miner.public_key).is_err());
        assert_eq!(fs::read_dir(root.join("events")).unwrap().count(), 0);
        let receipt = store
            .import(&source, bundle.clone(), 1, &miner.public_key)
            .unwrap();
        assert_eq!(receipt.state_root, store.state().root().unwrap());
        let ack = store
            .attest_import(
                &source,
                &bundle,
                &destination_operator.public_key,
                &destination_operator.secret_key,
            )
            .unwrap();
        assert_eq!(
            fs::read(root.join("OPERATOR")).unwrap(),
            destination_operator.public_key.as_bytes()
        );
        assert!(store
            .attest_import(
                &source,
                &bundle,
                &wrong_operator.public_key,
                &wrong_operator.secret_key,
            )
            .is_err());
        assert_eq!(ack.receipt, receipt);
        ack.verify(&bundle, &destination_operator.public_key)
            .unwrap();
        assert_eq!(ack.source_policy, policy);
        let mut other_policy = policy.clone();
        other_policy.minimum_confirmations += 1;
        assert!(ack
            .verify_with_replayed_source(
                &source,
                &other_policy,
                &bundle,
                &destination_operator.public_key,
            )
            .unwrap_err()
            .contains("source policy differs"));
        assert!(ack.verify(&bundle, &wrong_operator.public_key).is_err());
        let mut forged = ack.clone();
        forged.receipt.state_root = Hash([88; 32]);
        assert!(forged
            .verify(&bundle, &destination_operator.public_key)
            .is_err());
        forged = ack.clone();
        forged.signature = "00".into();
        assert!(forged
            .verify(&bundle, &destination_operator.public_key)
            .is_err());
        let mut changed_bundle = bundle.clone();
        changed_bundle.source_height += 1;
        assert!(ack
            .verify(&changed_bundle, &destination_operator.public_key)
            .is_err());
        assert!(store.healthy());
        assert!(store
            .import(&source, bundle.clone(), 2, &miner.public_key)
            .is_err());
        let payment = signed_destination_payment(
            destination_id,
            &recipient,
            receipt.recipient_outpoint.clone(),
            amount.checked_sub(Amount(101)).unwrap(),
            &onward_recipient,
        );
        let transferred = store
            .transfer(&source, payment.clone(), 2, &miner.public_key)
            .unwrap();
        assert_eq!(transferred.transaction, payment.id().unwrap());
        assert!(store.state().coin(&receipt.recipient_outpoint).is_none());
        assert_eq!(
            store
                .state()
                .coin(&transferred.outputs[0])
                .unwrap()
                .output
                .owner,
            onward_recipient.public_key
        );
        assert!(store
            .transfer(&source, payment, 3, &miner.public_key)
            .is_err());
        assert_eq!(fs::read_dir(root.join("events")).unwrap().count(), 2);
        (transferred.state_root, ack)
    };

    let transfer_file = fs::read_dir(root.join("events"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("00000002-")
        })
        .unwrap();
    let transfer_bytes = fs::read(&transfer_file).unwrap();
    fs::write(&transfer_file, b"{}").unwrap();
    assert!(DestinationStore::open(&root, destination_id, policy.clone(), &source).is_err());
    fs::write(&transfer_file, transfer_bytes).unwrap();

    let prior_head = Head {
        sequence: 0,
        root: DestinationSimulation::new_empty(destination_id, policy.clone())
            .unwrap()
            .root()
            .unwrap(),
        halted: false,
    };
    fs::write(root.join("HEAD"), serde_json::to_vec(&prior_head).unwrap()).unwrap();
    fs::write(root.join("events").join("incomplete.pending"), b"partial").unwrap();
    let mut store = DestinationStore::open(&root, destination_id, policy.clone(), &source).unwrap();
    assert_eq!(store.state().root().unwrap(), expected_root);
    let recovered_head: Head =
        serde_json::from_slice(&fs::read(root.join("HEAD")).unwrap()).unwrap();
    assert_eq!(recovered_head.sequence, 2);
    assert_eq!(recovered_head.root, expected_root);
    assert_eq!(store.state().imported_total(), amount);
    assert!(!store.state().halted());
    assert_eq!(
        store
            .attest_import(
                &source,
                &bundle,
                &destination_operator.public_key,
                &destination_operator.secret_key
            )
            .unwrap(),
        first_ack
    );
    drop(store);
    let mut changed_policy = policy.clone();
    changed_policy.minimum_confirmations = 3;
    assert!(DestinationStore::open(&root, destination_id, changed_policy, &source).is_err());

    let original_source = source.clone();
    for offset in 1..=3 {
        let timestamp = first_time + (offset - 1) * BLOCK_SECONDS + 1;
        let branch_block = mine_source(&mut alternate, &miner, timestamp, vec![]);
        source.accept(branch_block, timestamp).unwrap();
    }
    assert!(source.observe_export_bundle(&bundle, &policy).is_err());
    store = DestinationStore::open(&root, destination_id, policy.clone(), &source).unwrap();
    assert!(store.state().halted());
    assert!(store
        .attest_import(
            &source,
            &bundle,
            &destination_operator.public_key,
            &destination_operator.secret_key
        )
        .is_err());
    assert_eq!(store.state().imported_total(), amount);
    assert!(store
        .import(&source, bundle.clone(), 2, &miner.public_key)
        .is_err());
    let halted_payment = signed_destination_payment(
        destination_id,
        &recipient,
        OutPoint {
            transaction: Hash([77; 32]),
            index: 0,
        },
        amount.checked_sub(Amount(101)).unwrap(),
        &onward_recipient,
    );
    assert!(store
        .transfer(&source, halted_payment, 3, &miner.public_key)
        .is_err());
    assert_eq!(fs::read(root.join("HALTED")).unwrap(), HALTED_MARKER);
    drop(store);

    let restored =
        DestinationStore::open(&root, destination_id, policy.clone(), &original_source).unwrap();
    assert!(restored.state().halted());
    assert_eq!(restored.state().imported_total(), amount);
    drop(restored);
    let event_file = fs::read_dir(root.join("events"))
        .unwrap()
        .filter_map(|entry| {
            let path = entry.unwrap().path();
            (path
                .extension()
                .is_some_and(|extension| extension == "json"))
            .then_some(path)
        })
        .next()
        .unwrap();
    let original_event = fs::read(&event_file).unwrap();
    fs::remove_file(&event_file).unwrap();
    assert!(
        DestinationStore::open(&root, destination_id, policy.clone(), &original_source).is_err()
    );
    fs::write(&event_file, original_event).unwrap();
    let head_path = root.join("HEAD");
    let original_head = fs::read(&head_path).unwrap();
    fs::remove_file(&head_path).unwrap();
    assert!(
        DestinationStore::open(&root, destination_id, policy.clone(), &original_source).is_err()
    );
    fs::write(&head_path, original_head).unwrap();
    fs::write(event_file, b"{}").unwrap();
    assert!(DestinationStore::open(&root, destination_id, policy, &original_source).is_err());
    fs::remove_dir_all(root).unwrap();
}
