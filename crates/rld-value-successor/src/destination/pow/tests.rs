use super::authorization::{
    DestinationGenesisAuthorization, DestinationGenesisAuthorizationStatement,
};
use super::receipt::InclusionPolicy;
use super::storage::DestinationPowStore;
use super::*;
use crate::chain::finality::{FinalityCertificate, FinalityStatement};
use crate::{
    chain::{Command as SourceCommand, ObservationPolicy},
    destination::tests::{mine_source, signed_destination_payment, v1_chain},
};
use rld_core::{generate_identity, sign_bytes, Amount, Identity};
use rld_cross_region::value::{ExportCommand, ExportIntent};
use rld_pow::transition::Approval;
use rld_pow::{OutPoint, Output, Transfer, BLOCK_SECONDS};

#[test]
fn cold_destination_branch_rebuilds_import_spend_and_reorg_balances() {
    let (source, _, bundle, source_policy, _, recipient, miner, amount) = source_export();
    let context = Context {
        chain_id: Hash([91; 32]),
        source_policy,
        started_at: 2_000_000,
        initial_target: target_limit(),
        source_finality: None,
    };
    let mut destination = DestinationPowChain::new(context.clone()).unwrap();
    let first = mine_destination(
        &mut destination,
        &source,
        &miner,
        2_000_001,
        vec![Command::Import(bundle.clone())],
    );
    let mut fork = destination.clone();
    let mut bytes = b"RLD-EARTH-DESTINATION-POW-IMPORT-OUTPUT\0".to_vec();
    bytes.extend(context.chain_id.0);
    bytes.extend(bundle.source_chain_id.0);
    bytes.extend(bundle.export_id.0);
    let input = OutPoint {
        transaction: hash(&bytes),
        index: 0,
    };
    for height in 2..=6 {
        mine_destination(
            &mut destination,
            &source,
            &miner,
            2_000_000 + height,
            vec![],
        );
    }
    let tx = signed_destination_payment(
        context.chain_id,
        &recipient,
        input.clone(),
        amount.checked_sub(Amount(10)).unwrap(),
        &generate_identity(),
    );
    mine_destination(
        &mut destination,
        &source,
        &miner,
        2_000_007,
        vec![Command::Transfer(tx)],
    );
    mine_destination(&mut destination, &source, &miner, 2_000_008, vec![]);
    assert!(destination.state().coin(&input).is_none());
    let cold = destination
        .state_at(first.header.id().unwrap(), &source)
        .unwrap();
    assert_eq!(cold.root().unwrap(), first.header.state_root);
    assert_eq!(cold.imported_total(), amount);
    assert!(cold.coin(&input).is_some());
    for height in 2..=9 {
        let block = mine_destination(&mut fork, &source, &miner, 2_000_100 + height, vec![]);
        destination
            .accept(&source, block, 2_000_100 + height)
            .unwrap();
    }
    assert_eq!(destination.tip(), fork.tip());
    assert_eq!(
        destination.state().root().unwrap(),
        fork.state().root().unwrap()
    );
    assert!(destination.state().coin(&input).is_some());
    assert_eq!(destination.state().imported_total(), amount);
    destination.side_state = None;
    destination
        .entries
        .get_mut(&first.header.id().unwrap())
        .unwrap()
        .block
        .header
        .state_root = Hash::ZERO;
    assert!(destination
        .state_at(first.header.id().unwrap(), &source)
        .unwrap_err()
        .contains("replayed destination state root mismatch"));
}

#[test]
fn destination_restart_restores_saved_equal_work_branch_and_its_assets() {
    let (source, _, bundle, source_policy, _, _, miner, _) = source_export();
    let context = Context {
        chain_id: Hash([91; 32]),
        source_policy,
        started_at: 2_000_000,
        initial_target: target_limit(),
        source_finality: None,
    };
    let mut branch_a = DestinationPowChain::new(context.clone()).unwrap();
    let mut branch_b = branch_a.clone();
    let a = mine_destination(
        &mut branch_a,
        &source,
        &miner,
        2_000_001,
        vec![Command::Import(bundle)],
    );
    let b = mine_destination(&mut branch_b, &source, &miner, 2_000_001, vec![]);
    // Recovery visits hash order. Persist the opposite tie winner to exercise
    // HEAD restoration after replay selected a different asset state.
    let (chosen, other) = if a.header.id().unwrap() > b.header.id().unwrap() {
        (a, b)
    } else {
        (b, a)
    };
    let root = std::env::temp_dir().join(format!(
        "rld-destination-tie-assets-{}",
        generate_identity().public_key
    ));
    let mut store = DestinationPowStore::open(&root, context.clone(), &source, 2_000_100).unwrap();
    store.accept(&source, chosen.clone(), 2_000_100).unwrap();
    store.accept(&source, other, 2_000_100).unwrap();
    let amount = store.chain().state().imported_total();
    drop(store);
    let restored = DestinationPowStore::open(&root, context, &source, 2_000_100).unwrap();
    assert_eq!(restored.chain().tip(), chosen.header.id().unwrap());
    assert_eq!(
        restored.chain().state().root().unwrap(),
        chosen.header.state_root
    );
    assert_eq!(restored.chain().state().imported_total(), amount);
    drop(restored);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn earth_import_requires_signed_source_finality_covering_export() {
    let (mut source, _, bundle, mut policy, _owner, _recipient, miner, _) = source_export();
    let adoption = Hash([44; 32]);
    let mut signers = (0..4).map(|_| generate_identity()).collect::<Vec<_>>();
    signers.sort_by(|a, b| a.public_key.cmp(&b.public_key));
    let keys = signers
        .iter()
        .map(|key| key.public_key.clone())
        .collect::<Vec<_>>();
    policy.minimum_confirmations = 12;
    for index in 0..10 {
        let time = 1_000_000 + (103 + index) * BLOCK_SECONDS;
        mine_source(&mut source, &miner, time, vec![]);
    }
    let statement =
        FinalityStatement::from_chain(&source, adoption, bundle.source_checkpoint, None).unwrap();
    let bytes = statement.signing_bytes().unwrap();
    let certificate = FinalityCertificate {
        approvals: signers
            .iter()
            .map(|key| Approval {
                public_key: key.public_key.clone(),
                signature: sign_bytes(&key.secret_key, &bytes).unwrap(),
            })
            .collect(),
        statement,
    };
    // Heap representation must preserve the complete authenticated command wire.
    let command = Command::FinalizedImport {
        bundle: bundle.clone(),
        certificate: Box::new(certificate.clone()),
    };
    #[derive(serde::Serialize)]
    enum OriginalCommandEncoding {
        FinalizedImport {
            bundle: ProofBundle,
            certificate: FinalityCertificate,
        },
    }
    let original = OriginalCommandEncoding::FinalizedImport {
        bundle: bundle.clone(),
        certificate: certificate.clone(),
    };
    let encoded = serde_json::to_vec(&command).unwrap();
    assert_eq!(encoded, serde_json::to_vec(&original).unwrap());
    assert_eq!(
        serde_json::from_slice::<Command>(&encoded).unwrap(),
        command
    );
    let context = Context {
        chain_id: bundle.destination_chain_id,
        source_policy: policy,
        started_at: 2_000_000,
        initial_target: target_limit(),
        source_finality: Some(SourceFinalityTrust {
            earth_adoption_id: adoption,
            validator_keys: keys,
        }),
    };
    let mut destination = DestinationPowChain::new(context).unwrap();
    assert!(destination
        .template(
            &source,
            miner.public_key.clone(),
            2_000_001,
            vec![Command::Import(bundle.clone())]
        )
        .is_err());
    assert!(destination
        .template(
            &source,
            miner.public_key.clone(),
            2_000_001,
            vec![Command::FinalizedImport {
                bundle: bundle.clone(),
                certificate: Box::new(certificate.clone())
            }]
        )
        .is_err());
    source.install_finality(bundle.source_checkpoint).unwrap();
    let mut forged = certificate.clone();
    forged.approvals[0].signature = "00".into();
    assert!(destination
        .template(
            &source,
            miner.public_key.clone(),
            2_000_001,
            vec![Command::FinalizedImport {
                bundle: bundle.clone(),
                certificate: Box::new(forged)
            }]
        )
        .is_err());
    let block = mine_destination(
        &mut destination,
        &source,
        &miner,
        2_000_001,
        vec![Command::FinalizedImport {
            bundle,
            certificate: Box::new(certificate),
        }],
    );
    assert_eq!(block.header.height, 1);
    assert!(!destination.state().imported_total().is_zero());
}

#[test]
fn destination_mining_batch_matches_full_header_hashing() {
    let miner = generate_identity();
    let mut fast = Block {
        header: Header {
            chain_id: Hash([5; 32]),
            parent: Hash([6; 32]),
            height: 1,
            timestamp: 1_600,
            target: target_limit(),
            miner: miner.public_key,
            commands_root: Hash([7; 32]),
            state_root: Hash([8; 32]),
            nonce: 0,
        },
        commands: vec![],
    };
    let mut reference = fast.clone();
    let mut expected = false;
    for _ in 0..128 {
        if reference.header.work_valid().unwrap() {
            expected = true;
            break;
        }
        reference.header.nonce += 1;
    }
    assert_eq!(mine_batch(&mut fast, 128).unwrap(), expected);
    assert_eq!(fast.header, reference.header);
}

#[test]
fn destination_authorization_binds_genesis_preview_and_signer() {
    let owner = generate_identity();
    let signer = generate_identity();
    let other = generate_identity();
    let v1 = v1_chain(1, &owner);
    let source = CandidateChain::from_replayed_pow_chain(&v1).unwrap();
    let preview =
        crate::transition::TransitionPreview::from_replayed_v1(&v1, Hash([9; 32])).unwrap();
    let context = Context {
        chain_id: Hash([91; 32]),
        source_policy: ObservationPolicy {
            source_chain_id: source.chain_id(),
            accepted_v1_tip: source.v1_tip(),
            minimum_confirmations: 2,
            minimum_cumulative_work: source.chainwork(),
        },
        started_at: 1_000,
        initial_target: target_limit(),
        source_finality: None,
    };
    let statement =
        DestinationGenesisAuthorizationStatement::from_context(&context, &preview).unwrap();
    let id = statement.id().unwrap();
    let authorization = DestinationGenesisAuthorization {
        signature: sign_bytes(&signer.secret_key, &statement.signing_bytes().unwrap()).unwrap(),
        signer_public_key: signer.public_key.clone(),
        statement,
    };
    authorization
        .verify_for_candidate(&context, &preview, id, &signer.public_key)
        .unwrap();
    assert!(authorization
        .verify_for_candidate(&context, &preview, Hash([7; 32]), &signer.public_key)
        .is_err());
    assert!(authorization
        .verify_for_candidate(&context, &preview, id, &other.public_key)
        .is_err());
    let mut changed_context = context.clone();
    changed_context.started_at += 1;
    assert!(authorization
        .verify_for_candidate(&changed_context, &preview, id, &signer.public_key)
        .is_err());
    let mut changed_preview = preview.clone();
    changed_preview.successor_source_sha256 = Hash([8; 32]);
    assert!(authorization
        .verify_for_candidate(&context, &changed_preview, id, &signer.public_key)
        .is_err());
    let mut bad_signature = authorization;
    bad_signature.signature = "00".into();
    assert!(bad_signature
        .verify_for_candidate(&context, &preview, id, &signer.public_key)
        .is_err());
}

fn mine_destination(
    destination: &mut DestinationPowChain,
    source: &CandidateChain,
    miner: &Identity,
    timestamp: u64,
    commands: Vec<Command>,
) -> Block {
    let mut block = destination
        .template(source, miner.public_key.clone(), timestamp, commands)
        .unwrap();
    while !mine_batch(&mut block, 100_000).unwrap() {}
    assert!(destination
        .accept(source, block.clone(), timestamp)
        .unwrap());
    block
}

fn source_export() -> (
    CandidateChain,
    CandidateChain,
    ProofBundle,
    ObservationPolicy,
    Identity,
    Identity,
    Identity,
    Amount,
) {
    let owner = generate_identity();
    let recipient = generate_identity();
    let miner = generate_identity();
    let v1 = v1_chain(100, &owner);
    let mut source = CandidateChain::from_replayed_pow_chain(&v1).unwrap();
    let alternate = source.clone();
    let destination_id = Hash([91; 32]);
    let (input, coin) = v1
        .state()
        .coins
        .iter()
        .find(|(_, coin)| coin.spendable_height <= v1.height() + 1)
        .unwrap();
    let amount = Amount(1_000);
    let intent = ExportIntent {
        source_chain_id: v1.context.chain_id().unwrap(),
        destination_chain_id: destination_id,
        input: input.clone(),
        owner: owner.public_key.clone(),
        recipient: recipient.public_key.clone(),
        amount,
        source_fee: Amount(1),
        destination_fee: Amount(10),
        change: coin.output.amount.checked_sub(Amount(1_001)).unwrap(),
        valid_through_height: v1.height() + 10,
    };
    let export_id = intent.id().unwrap();
    let command = SourceCommand::Export(ExportCommand {
        owner_signature: sign_bytes(&owner.secret_key, &intent.signing_bytes().unwrap()).unwrap(),
        intent,
    });
    let time = 1_000_000 + 101 * BLOCK_SECONDS;
    let first = mine_source(&mut source, &miner, time, vec![command]);
    let checkpoint = first.header.id().unwrap();
    let policy = ObservationPolicy {
        source_chain_id: v1.context.chain_id().unwrap(),
        accepted_v1_tip: v1.tip(),
        minimum_confirmations: 2,
        minimum_cumulative_work: source.chainwork(),
    };
    mine_source(&mut source, &miner, time + BLOCK_SECONDS, vec![]);
    let bundle = source.export_bundle(export_id, checkpoint).unwrap();
    (
        source, alternate, bundle, policy, owner, recipient, miner, amount,
    )
}

#[test]
fn import_receipt_requires_replayed_selected_branch_and_live_source_proof() {
    let (mut source, mut alternate_source, bundle, source_policy, owner, _recipient, miner, _) =
        source_export();
    let context = Context {
        chain_id: Hash([91; 32]),
        source_policy,
        started_at: 2_000_000,
        initial_target: target_limit(),
        source_finality: None,
    };
    let mut destination = DestinationPowChain::new(context.clone()).unwrap();
    let mut independent = DestinationPowChain::new(context).unwrap();
    let first = mine_destination(
        &mut destination,
        &source,
        &miner,
        2_000_001,
        vec![Command::Import(bundle.clone())],
    );
    let policy = InclusionPolicy {
        destination_chain_id: Hash([91; 32]),
        accepted_genesis: destination.genesis(),
        minimum_confirmations: 2,
        minimum_inclusion_work: destination.chainwork(),
    };
    assert!(destination
        .observe_import(&source, &bundle, &policy)
        .is_err());
    assert!(independent
        .accept(&source, first.clone(), 2_000_001)
        .unwrap());
    let second = mine_destination(&mut destination, &source, &miner, 2_000_002, vec![]);
    let receipt = destination
        .observe_import(&source, &bundle, &policy)
        .unwrap();
    assert!(!receipt.live_rld);
    assert_eq!(receipt.block, first.header.id().unwrap());
    assert_eq!(
        receipt.recipient_spendable_height,
        1 + MIN_IMPORT_CONFIRMATIONS
    );
    assert_eq!(receipt.command_index, 0);
    assert!(independent
        .verify_import_receipt(&source, &bundle, &policy, &receipt)
        .is_err());
    assert!(independent.accept(&source, second, 2_000_002).unwrap());
    let observed = independent
        .verify_import_receipt(&source, &bundle, &policy, &receipt)
        .unwrap();
    assert_eq!(observed.confirmations, 2);
    assert_eq!(observed.inclusion_work, policy.minimum_inclusion_work);
    let mut false_receipt = receipt.clone();
    false_receipt.state_root = Hash([7; 32]);
    assert!(independent
        .verify_import_receipt(&source, &bundle, &policy, &false_receipt)
        .is_err());
    false_receipt = receipt.clone();
    false_receipt.command_index = 1;
    assert!(independent
        .verify_import_receipt(&source, &bundle, &policy, &false_receipt)
        .is_err());
    false_receipt = receipt.clone();
    false_receipt.recipient_spendable_height -= 1;
    assert!(independent
        .verify_import_receipt(&source, &bundle, &policy, &false_receipt)
        .is_err());
    false_receipt = receipt.clone();
    false_receipt.live_rld = true;
    assert!(independent
        .verify_import_receipt(&source, &bundle, &policy, &false_receipt)
        .is_err());
    let stricter = InclusionPolicy {
        minimum_inclusion_work: observed.selected_work,
        ..policy.clone()
    };
    assert!(independent
        .verify_import_receipt(&source, &bundle, &stricter, &receipt)
        .is_err());
    let other_genesis = InclusionPolicy {
        accepted_genesis: Hash([8; 32]),
        ..policy.clone()
    };
    assert!(independent
        .verify_import_receipt(&source, &bundle, &other_genesis, &receipt)
        .is_err());

    let mut fork = DestinationPowChain::new(independent.context.clone()).unwrap();
    for height in 1..=3 {
        let block = mine_destination(&mut fork, &source, &miner, 2_000_000 + height, vec![]);
        independent
            .accept(&source, block, 2_000_000 + height)
            .unwrap();
    }
    assert_eq!(independent.tip(), fork.tip());
    assert!(independent
        .verify_import_receipt(&source, &bundle, &policy, &receipt)
        .is_err());

    // Even a destination branch that retained the import must reject its
    // receipt when a stronger source branch removes the export checkpoint.
    let source_time = 1_000_000 + 101 * BLOCK_SECONDS;
    for offset in 1..=3 {
        let block = mine_source(&mut alternate_source, &owner, source_time + offset, vec![]);
        source.accept(block, source_time + offset).unwrap();
    }
    assert!(destination
        .verify_import_receipt(&source, &bundle, &policy, &receipt)
        .is_err());
}

#[test]
fn destination_submitted_import_survives_restart_and_reorg() {
    let (source, _alternate, bundle, source_policy, _owner, _recipient, miner, _) = source_export();
    let context = Context {
        chain_id: Hash([91; 32]),
        source_policy,
        started_at: 2_000_000,
        initial_target: target_limit(),
        source_finality: None,
    };
    let root = std::env::temp_dir().join(format!(
        "rld-destination-queue-{}",
        generate_identity().public_key
    ));
    let mut store = DestinationPowStore::open(&root, context.clone(), &source, 2_000_100).unwrap();
    let command = Command::Import(bundle.clone());
    let (id, fresh) = store
        .submit_command(&source, command.clone(), &miner.public_key, 2_000_001)
        .unwrap();
    assert!(fresh);
    assert_eq!(
        store
            .submit_command(&source, command, &miner.public_key, 2_000_001)
            .unwrap(),
        (id, false)
    );
    assert_eq!(store.submitted_count(), 1);
    let chosen = store
        .mineable_commands(&source, &miner.public_key, 2_000_001)
        .unwrap();
    assert_eq!(chosen, vec![Command::Import(bundle.clone())]);
    let mut first = store
        .template(&source, miner.public_key.clone(), 2_000_001, chosen)
        .unwrap();
    while !mine_batch(&mut first, 100_000).unwrap() {}
    assert!(store.accept(&source, first, 2_000_001).unwrap());
    assert!(store
        .mineable_commands(&source, &miner.public_key, 2_000_002)
        .unwrap()
        .is_empty());
    assert!(store.selected_inclusion(id).unwrap().is_some());

    let mut rival = DestinationPowChain::new(context.clone()).unwrap();
    for height in 1..=2 {
        let block = mine_destination(&mut rival, &source, &miner, 2_000_000 + height, vec![]);
        store.accept(&source, block, 2_000_000 + height).unwrap();
    }
    assert_eq!(store.chain().tip(), rival.tip());
    assert!(store.selected_inclusion(id).unwrap().is_none());
    drop(store);
    let mut restored = DestinationPowStore::open(&root, context, &source, 2_000_100).unwrap();
    assert_eq!(restored.submitted_count(), 1);
    assert_eq!(
        restored
            .mineable_commands(&source, &miner.public_key, 2_000_003)
            .unwrap(),
        vec![Command::Import(bundle)]
    );
    drop(restored);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn destination_journal_accepts_command_33_and_rejects_replay_gap() {
    let (source, _alternate, bundle, policy, _owner, recipient, miner, amount) = source_export();
    let context = Context {
        chain_id: Hash([91; 32]),
        source_policy: policy,
        started_at: 2_000_000,
        initial_target: target_limit(),
        source_finality: None,
    };
    let root = std::env::temp_dir().join(format!(
        "rld-destination-long-journal-{}",
        generate_identity().public_key
    ));
    let mut store = DestinationPowStore::open(&root, context.clone(), &source, 2_000_100).unwrap();
    let imported = Command::Import(bundle.clone());
    store
        .submit_command(&source, imported.clone(), &miner.public_key, 2_000_001)
        .unwrap();
    let first = store
        .mineable_commands(&source, &miner.public_key, 2_000_001)
        .unwrap();
    let mut block = store
        .template(&source, miner.public_key.clone(), 2_000_001, first)
        .unwrap();
    while !mine_batch(&mut block, 100_000).unwrap() {}
    store.accept(&source, block, 2_000_001).unwrap();
    let mut empty = store
        .template(&source, miner.public_key.clone(), 2_000_002, vec![])
        .unwrap();
    while !mine_batch(&mut empty, 100_000).unwrap() {}
    store.accept(&source, empty, 2_000_002).unwrap();
    for height in 3..=6 {
        let timestamp = 2_000_000 + height;
        let mut empty = store
            .template(&source, miner.public_key.clone(), timestamp, vec![])
            .unwrap();
        while !mine_batch(&mut empty, 100_000).unwrap() {}
        store.accept(&source, empty, timestamp).unwrap();
    }

    let mut id_bytes = b"RLD-EARTH-DESTINATION-POW-IMPORT-OUTPUT\0".to_vec();
    id_bytes.extend(context.chain_id.0);
    id_bytes.extend(bundle.source_chain_id.0);
    id_bytes.extend(bundle.export_id.0);
    let mut input = OutPoint {
        transaction: crate::hash(&id_bytes),
        index: 0,
    };
    let mut balance = amount.checked_sub(Amount(10)).unwrap();
    let payee = generate_identity();
    for sequence in 0..33 {
        let timestamp = 2_000_007 + sequence;
        let mut tx = Transfer {
            chain_id: context.chain_id,
            owner: recipient.public_key.clone(),
            inputs: vec![input],
            outputs: vec![
                Output {
                    owner: payee.public_key.clone(),
                    amount: Amount(1),
                },
                Output {
                    owner: recipient.public_key.clone(),
                    amount: balance.checked_sub(Amount(2)).unwrap(),
                },
            ],
            fee: Amount(1),
            valid_through_height: 100,
            signature: String::new(),
        };
        tx.signature = sign_bytes(&recipient.secret_key, &tx.signing_bytes().unwrap()).unwrap();
        let next_input = OutPoint {
            transaction: tx.id().unwrap(),
            index: 1,
        };
        let command = Command::Transfer(tx);
        let (command_id, fresh) = store
            .submit_command(&source, command.clone(), &miner.public_key, timestamp)
            .unwrap();
        assert!(fresh);
        assert_eq!(
            store
                .mineable_commands(&source, &miner.public_key, timestamp)
                .unwrap(),
            vec![command.clone()]
        );
        let mut block = store
            .template(&source, miner.public_key.clone(), timestamp, vec![command])
            .unwrap();
        while !mine_batch(&mut block, 100_000).unwrap() {}
        store.accept(&source, block, timestamp).unwrap();
        assert!(store.selected_inclusion(command_id).unwrap().is_some());
        input = next_input;
        balance = balance.checked_sub(Amount(2)).unwrap();
    }
    assert_eq!(store.submitted_count(), 34);
    drop(store);
    let restored = DestinationPowStore::open(&root, context.clone(), &source, 2_000_100).unwrap();
    assert_eq!(restored.submitted_count(), 34);
    assert_eq!(restored.chain().height(), 39);
    drop(restored);
    let last = root.join("submissions/00000033.json");
    let skipped = root.join("submissions/00000034.json");
    std::fs::rename(&last, &skipped).unwrap();
    assert!(DestinationPowStore::open(&root, context.clone(), &source, 2_000_100).is_err());
    std::fs::rename(&skipped, &last).unwrap();
    assert!(DestinationPowStore::open(&root, context, &source, 2_000_100).is_ok());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn destination_journal_replays_legacy_prefix_before_new_files() {
    let (source, _alternate, bundle, policy, _owner, _recipient, miner, _) = source_export();
    let context = Context {
        chain_id: Hash([91; 32]),
        source_policy: policy,
        started_at: 2_000_000,
        initial_target: target_limit(),
        source_finality: None,
    };
    let root = std::env::temp_dir().join(format!(
        "rld-destination-legacy-journal-{}",
        generate_identity().public_key
    ));
    let store = DestinationPowStore::open(&root, context.clone(), &source, 2_000_100).unwrap();
    drop(store);
    let command = Command::Import(bundle);
    std::fs::write(
        root.join("submitted.json"),
        serde_json::to_vec(&vec![command.clone()]).unwrap(),
    )
    .unwrap();
    let mut restored = DestinationPowStore::open(&root, context, &source, 2_000_100).unwrap();
    assert_eq!(restored.submitted_count(), 1);
    assert!(
        !restored
            .submit_command(&source, command, &miner.public_key, 2_000_001)
            .unwrap()
            .1
    );
    drop(restored);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn destination_pow_import_transfer_forks_and_source_reorg_halt() {
    let (mut source, mut alternate_source, bundle, policy, owner, recipient, miner, amount) =
        source_export();
    let context = Context {
        chain_id: Hash([91; 32]),
        source_policy: policy,
        started_at: 2_000_000,
        initial_target: target_limit(),
        source_finality: None,
    };
    let mut destination = DestinationPowChain::new(context.clone()).unwrap();
    assert_eq!(destination.state().imported_total(), Amount::ZERO);
    let mut rival = destination.clone();
    let first = mine_destination(
        &mut destination,
        &source,
        &miner,
        2_000_001,
        vec![Command::Import(bundle.clone())],
    );
    assert_eq!(destination.height(), 1);
    assert_eq!(destination.state().imported_total(), amount);
    assert_eq!(destination.chainwork(), header_work(first.header.target));
    let import_point = OutPoint {
        transaction: {
            let mut bytes = b"RLD-EARTH-DESTINATION-POW-IMPORT-OUTPUT\0".to_vec();
            bytes.extend(context.chain_id.0);
            bytes.extend(bundle.source_chain_id.0);
            bytes.extend(bundle.export_id.0);
            hash(&bytes)
        },
        index: 0,
    };
    assert_eq!(
        destination
            .state()
            .coin(&import_point)
            .unwrap()
            .output
            .owner,
        recipient.public_key
    );
    assert_eq!(
        destination
            .state()
            .coin(&import_point)
            .unwrap()
            .spendable_height,
        1 + MIN_IMPORT_CONFIRMATIONS
    );
    assert_eq!(
        destination
            .state()
            .balance(&recipient.public_key, destination.height() + 1)
            .unwrap(),
        (Amount::ZERO, amount.checked_sub(Amount(10)).unwrap())
    );
    let mut forged = first.clone();
    forged.header.state_root = Hash([99; 32]);
    forged.header.nonce = 0;
    while !mine_batch(&mut forged, 100_000).unwrap() {}
    assert!(rival
        .accept(&source, forged, 2_000_001)
        .unwrap_err()
        .contains("state root mismatch"));
    assert_eq!(rival.height(), 0);
    assert!(destination
        .template(
            &source,
            miner.public_key.clone(),
            2_000_002,
            vec![Command::Import(bundle.clone())],
        )
        .is_err());
    let onward = generate_identity();
    let tx = signed_destination_payment(
        context.chain_id,
        &recipient,
        import_point.clone(),
        amount.checked_sub(Amount(10)).unwrap(),
        &onward,
    );
    assert!(rival
        .template(
            &source,
            miner.public_key.clone(),
            2_000_001,
            vec![
                Command::Import(bundle.clone()),
                Command::Transfer(tx.clone())
            ],
        )
        .is_err());
    assert!(destination
        .template(
            &source,
            miner.public_key.clone(),
            2_000_002,
            vec![Command::Transfer(tx.clone())],
        )
        .is_err());
    mine_destination(&mut destination, &source, &miner, 2_000_002, vec![]);
    assert_eq!(
        destination
            .state()
            .balance(&recipient.public_key, destination.height() + 1)
            .unwrap(),
        (Amount::ZERO, amount.checked_sub(Amount(10)).unwrap())
    );
    for height in 3..=6 {
        mine_destination(
            &mut destination,
            &source,
            &miner,
            2_000_000 + height,
            vec![],
        );
    }
    assert_eq!(
        destination
            .state()
            .balance(&recipient.public_key, destination.height() + 1)
            .unwrap(),
        (amount.checked_sub(Amount(10)).unwrap(), Amount::ZERO)
    );
    mine_destination(
        &mut destination,
        &source,
        &miner,
        2_000_007,
        vec![Command::Transfer(tx.clone())],
    );
    assert!(destination.state().coin(&import_point).is_none());
    assert_eq!(destination.state().imported_total(), amount);
    assert!(destination
        .template(
            &source,
            miner.public_key.clone(),
            2_000_008,
            vec![Command::Transfer(tx)],
        )
        .is_err());

    for height in 1..=8 {
        let block = mine_destination(&mut rival, &source, &miner, 2_000_000 + height, vec![]);
        destination
            .accept(&source, block, 2_000_000 + height)
            .unwrap();
    }
    assert_eq!(destination.tip(), rival.tip());
    assert_eq!(destination.state().imported_total(), Amount::ZERO);
    assert_eq!(
        destination.state().root().unwrap(),
        rival.state().root().unwrap()
    );
    mine_destination(
        &mut destination,
        &source,
        &miner,
        2_000_009,
        vec![Command::Import(bundle.clone())],
    );
    assert_eq!(destination.state().imported_total(), amount);

    let source_time = 1_000_000 + 101 * BLOCK_SECONDS;
    for offset in 1..=3 {
        let block = mine_source(&mut alternate_source, &owner, source_time + offset, vec![]);
        source.accept(block, source_time + offset).unwrap();
    }
    assert!(source
        .observe_export_bundle(&bundle, &context.source_policy)
        .is_err());
    assert!(destination.audit_source(&source).is_err());
    assert!(destination.halted());
    assert!(destination
        .template(&source, miner.public_key, 2_000_010, vec![])
        .is_err());
}

#[test]
fn destination_pow_retargets_without_native_issuance() {
    let owner = generate_identity();
    let miner = generate_identity();
    let v1 = v1_chain(1, &owner);
    let source = CandidateChain::from_replayed_pow_chain(&v1).unwrap();
    let context = Context {
        chain_id: Hash([92; 32]),
        source_policy: ObservationPolicy {
            source_chain_id: source.chain_id(),
            accepted_v1_tip: source.v1_tip(),
            minimum_confirmations: 2,
            minimum_cumulative_work: source.chainwork(),
        },
        started_at: 2_000_000,
        initial_target: target_limit(),
        source_finality: None,
    };
    let mut destination = DestinationPowChain::new(context).unwrap();
    for height in 1..=RETARGET_BLOCKS as u64 {
        mine_destination(
            &mut destination,
            &source,
            &miner,
            2_000_000 + height,
            vec![],
        );
    }
    assert_eq!(destination.state().imported_total(), Amount::ZERO);
    let next_time = 2_000_000 + RETARGET_BLOCKS as u64 + 1;
    let expected = (RETARGET_BLOCKS as u64 - 1) * BLOCK_SECONDS;
    let target = scale_target(target_limit(), expected / 4, expected).unwrap();
    let mut block = destination
        .template(&source, miner.public_key, next_time, vec![])
        .unwrap();
    assert_eq!(block.header.target, target);
    assert!(target < target_limit());
    let mut forged = block.clone();
    forged.header.target = target_limit();
    while !mine_batch(&mut forged, 100_000).unwrap() {}
    assert!(destination.accept(&source, forged, next_time).is_err());
    while !mine_batch(&mut block, 100_000).unwrap() {}
    assert!(destination.accept(&source, block, next_time).unwrap());
    assert_eq!(destination.height(), RETARGET_BLOCKS as u128 + 1);
    assert_eq!(destination.state().imported_total(), Amount::ZERO);
}

#[test]
fn destination_pow_store_replays_import_and_persists_source_halt() {
    let (mut source, mut alternate_source, bundle, policy, owner, recipient, miner, amount) =
        source_export();
    let context = Context {
        chain_id: Hash([91; 32]),
        source_policy: policy,
        started_at: 2_000_000,
        initial_target: target_limit(),
        source_finality: None,
    };
    let root = std::env::temp_dir().join(format!(
        "rld-destination-pow-{}",
        generate_identity().public_key
    ));
    let (selected_tip, receipt, inclusion_policy) = {
        let mut store =
            DestinationPowStore::open(&root, context.clone(), &source, 2_000_100).unwrap();
        assert!(DestinationPowStore::open(&root, context.clone(), &source, 2_000_100).is_err());
        let mut imported = store
            .template(
                &source,
                miner.public_key.clone(),
                2_000_001,
                vec![Command::Import(bundle.clone())],
            )
            .unwrap();
        while !mine_batch(&mut imported, 100_000).unwrap() {}
        assert!(store.accept(&source, imported, 2_000_001).unwrap());
        let inclusion_policy = InclusionPolicy {
            destination_chain_id: context.chain_id,
            accepted_genesis: store.chain().genesis(),
            minimum_confirmations: 2,
            minimum_inclusion_work: store.chain().chainwork(),
        };
        assert!(store
            .observe_import(&source, &bundle, &inclusion_policy)
            .is_err());
        let mut empty = store
            .template(&source, miner.public_key.clone(), 2_000_002, vec![])
            .unwrap();
        while !mine_batch(&mut empty, 100_000).unwrap() {}
        assert!(store.accept(&source, empty, 2_000_002).unwrap());
        for height in 3..=6 {
            let timestamp = 2_000_000 + height;
            let mut empty = store
                .template(&source, miner.public_key.clone(), timestamp, vec![])
                .unwrap();
            while !mine_batch(&mut empty, 100_000).unwrap() {}
            assert!(store.accept(&source, empty, timestamp).unwrap());
        }
        assert_eq!(store.chain().state().imported_total(), amount);
        assert!(store.healthy());
        let receipt = store
            .observe_import(&source, &bundle, &inclusion_policy)
            .unwrap();
        (store.chain().tip(), receipt, inclusion_policy)
    };
    let head_path = root.join("HEAD");
    std::fs::write(&head_path, context.genesis().unwrap().to_hex()).unwrap();
    let mut restored =
        DestinationPowStore::open(&root, context.clone(), &source, 2_000_100).unwrap();
    assert_eq!(restored.chain().tip(), selected_tip);
    assert_eq!(restored.chain().state().imported_total(), amount);
    let import_point = OutPoint {
        transaction: {
            let mut bytes = b"RLD-EARTH-DESTINATION-POW-IMPORT-OUTPUT\0".to_vec();
            bytes.extend(context.chain_id.0);
            bytes.extend(bundle.source_chain_id.0);
            bytes.extend(bundle.export_id.0);
            hash(&bytes)
        },
        index: 0,
    };
    assert_eq!(
        restored
            .chain()
            .state()
            .coin(&import_point)
            .unwrap()
            .spendable_height,
        1 + MIN_IMPORT_CONFIRMATIONS
    );
    let onward = generate_identity();
    let tx = signed_destination_payment(
        context.chain_id,
        &recipient,
        import_point,
        amount.checked_sub(Amount(10)).unwrap(),
        &onward,
    );
    assert!(restored
        .template(
            &source,
            miner.public_key.clone(),
            2_000_007,
            vec![Command::Transfer(tx)],
        )
        .is_ok());
    assert_eq!(
        restored
            .verify_import_receipt(&source, &bundle, &inclusion_policy, &receipt)
            .unwrap()
            .confirmations,
        6
    );
    assert_eq!(
        std::fs::read_to_string(&head_path).unwrap(),
        selected_tip.to_hex()
    );
    drop(restored);
    let identity_path = root.join("identity.json");
    let original_identity = std::fs::read(&identity_path).unwrap();
    let identity_text = String::from_utf8(original_identity.clone()).unwrap();
    let old_identity = identity_text.replace(
        "RLD-EARTH-DESTINATION-POW-STORE",
        "RLD-DESTINATION-POW-STORE-CANDIDATE-V1",
    );
    assert_ne!(old_identity, identity_text);
    std::fs::write(&identity_path, old_identity).unwrap();
    assert!(DestinationPowStore::open(&root, context.clone(), &source, 2_000_100).is_err());
    let wrong_source = identity_text.replace(
        &implementation_source_hash().unwrap().to_hex(),
        &Hash([45; 32]).to_hex(),
    );
    assert_ne!(wrong_source, identity_text);
    std::fs::write(&identity_path, wrong_source).unwrap();
    assert!(DestinationPowStore::open(&root, context.clone(), &source, 2_000_100).is_err());
    std::fs::write(&identity_path, original_identity).unwrap();
    let mut changed_context = context.clone();
    changed_context.started_at += 1;
    assert!(DestinationPowStore::open(&root, changed_context, &source, 2_000_100).is_err());

    let original_head = std::fs::read(&head_path).unwrap();
    std::fs::write(&head_path, Hash([88; 32]).to_hex()).unwrap();
    assert!(DestinationPowStore::open(&root, context.clone(), &source, 2_000_100).is_err());
    std::fs::write(&head_path, original_head).unwrap();
    let block_path = root
        .join("blocks")
        .join(format!("{}.json", selected_tip.to_hex()));
    let original_block = std::fs::read(&block_path).unwrap();
    std::fs::write(&block_path, b"{}").unwrap();
    assert!(DestinationPowStore::open(&root, context.clone(), &source, 2_000_100).is_err());
    std::fs::write(&block_path, &original_block).unwrap();
    std::fs::remove_file(&block_path).unwrap();
    assert!(DestinationPowStore::open(&root, context.clone(), &source, 2_000_100).is_err());
    std::fs::write(&block_path, original_block).unwrap();

    let original_source = source.clone();
    let source_time = 1_000_000 + 101 * BLOCK_SECONDS;
    for offset in 1..=3 {
        let block = mine_source(&mut alternate_source, &owner, source_time + offset, vec![]);
        source.accept(block, source_time + offset).unwrap();
    }
    assert!(source
        .observe_export_bundle(&bundle, &context.source_policy)
        .is_err());
    let mut halted = DestinationPowStore::open(&root, context.clone(), &source, 2_000_100).unwrap();
    assert!(halted.chain().halted());
    assert!(halted
        .verify_import_receipt(&source, &bundle, &inclusion_policy, &receipt)
        .is_err());
    assert_eq!(halted.chain().state().imported_total(), amount);
    assert!(root.join("HALTED").exists());
    drop(halted);
    let still_halted =
        DestinationPowStore::open(&root, context, &original_source, 2_000_100).unwrap();
    assert!(still_halted.chain().halted());
    drop(still_halted);
    std::fs::remove_dir_all(root).unwrap();
}
