use super::*;
use crate::chain::{mine_batch, Command};
use rld_core::{generate_identity, sign_bytes, Identity};
use rld_cross_region::value::{ExportCommand, ExportIntent};
use rld_pow::{mine_batch as mine_v1, target_limit, Context, Output, Transfer, BLOCK_SECONDS};

pub(super) fn signed_destination_payment(
    destination_id: Hash,
    owner: &Identity,
    input: OutPoint,
    balance: Amount,
    recipient: &Identity,
) -> Transfer {
    let payment = Amount(100);
    let fee = Amount(1);
    let mut tx = Transfer {
        chain_id: destination_id,
        owner: owner.public_key.clone(),
        inputs: vec![input],
        outputs: vec![
            Output {
                owner: recipient.public_key.clone(),
                amount: payment,
            },
            Output {
                owner: owner.public_key.clone(),
                amount: balance
                    .checked_sub(payment.checked_add(fee).unwrap())
                    .unwrap(),
            },
        ],
        fee,
        valid_through_height: 100,
        signature: String::new(),
    };
    tx.signature = sign_bytes(&owner.secret_key, &tx.signing_bytes().unwrap()).unwrap();
    tx
}

pub(super) fn v1_chain(blocks: u128, owner: &Identity) -> rld_pow::Chain {
    let mut chain = rld_pow::Chain::new(Context {
        network_domain: "fixture:destination-simulation".into(),
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

pub(super) fn mine_source(
    source: &mut CandidateChain,
    miner: &Identity,
    timestamp: u64,
    commands: Vec<Command>,
) -> crate::chain::Block {
    let mut block = source
        .template(miner.public_key.clone(), timestamp, commands)
        .unwrap();
    while !mine_batch(&mut block, 100_000).unwrap() {}
    source.accept(block.clone(), timestamp).unwrap();
    block
}

#[test]
fn verified_bundle_imports_once_and_source_reorg_halts_simulated_destination() {
    let owner = generate_identity();
    let recipient = generate_identity();
    let onward_recipient = generate_identity();
    let miner = generate_identity();
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
    let source_fee = Amount(1);
    let intent = ExportIntent {
        source_chain_id: v1.context.chain_id().unwrap(),
        destination_chain_id: destination_id,
        input: input.clone(),
        owner: owner.public_key.clone(),
        recipient: recipient.public_key.clone(),
        amount,
        source_fee,
        destination_fee: Amount(101),
        change: coin
            .output
            .amount
            .checked_sub(amount.checked_add(source_fee).unwrap())
            .unwrap(),
        valid_through_height: v1.height() + 10,
    };
    let export_id = intent.id().unwrap();
    let export = ExportCommand {
        owner_signature: sign_bytes(&owner.secret_key, &intent.signing_bytes().unwrap()).unwrap(),
        intent,
    };
    let first_time = 1_000_000 + 101 * BLOCK_SECONDS;
    let first = mine_source(
        &mut source,
        &miner,
        first_time,
        vec![Command::Export(export)],
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
    let mut destination = DestinationSimulation::new_empty(destination_id, policy.clone()).unwrap();
    let initial_root = destination.root().unwrap();
    let mut tampered = bundle.clone();
    tampered.source_height += 1;
    assert!(destination
        .import_from_replayed_source(&source, tampered, 1, &miner.public_key)
        .is_err());
    assert_eq!(destination.root().unwrap(), initial_root);
    let receipt = destination
        .import_from_replayed_source(&source, bundle.clone(), 1, &miner.public_key)
        .unwrap();
    assert_ne!(destination.root().unwrap(), initial_root);
    assert_eq!(receipt.state_root, destination.root().unwrap());
    assert_eq!(receipt.export_id, export_id);
    assert_eq!(destination.imported_total(), amount);
    assert_eq!(
        destination
            .coin(&receipt.recipient_outpoint)
            .unwrap()
            .output
            .amount,
        amount.checked_sub(Amount(101)).unwrap()
    );
    assert_eq!(
        destination
            .coin(&receipt.miner_fee_outpoint)
            .unwrap()
            .spendable_height,
        1 + COINBASE_MATURITY
    );
    let (_, locked, retired) = source.state().totals().unwrap();
    let (liquid, _, _) = source.state().totals().unwrap();
    assert_eq!(locked, Amount::ZERO);
    assert_eq!(retired, destination.imported_total());
    assert_eq!(
        liquid.checked_add(destination.imported_total()).unwrap(),
        source.state().commitment().unwrap().emitted
    );
    let root_after_import = destination.root().unwrap();
    assert!(destination
        .import_from_replayed_source(&source, bundle.clone(), 2, &miner.public_key)
        .is_err());
    assert_eq!(destination.root().unwrap(), root_after_import);
    destination.audit_source(&source).unwrap();
    let recipient_amount = amount.checked_sub(Amount(101)).unwrap();
    let payment = signed_destination_payment(
        destination_id,
        &recipient,
        receipt.recipient_outpoint.clone(),
        recipient_amount,
        &onward_recipient,
    );
    let mut forged = payment.clone();
    forged.signature = "00".into();
    assert!(destination
        .transfer_from_replayed_source(&source, forged, 2, &miner.public_key)
        .is_err());
    assert_eq!(destination.root().unwrap(), root_after_import);
    let mut overspend = payment.clone();
    overspend.outputs[0].amount = Amount(101);
    overspend.signature =
        sign_bytes(&recipient.secret_key, &overspend.signing_bytes().unwrap()).unwrap();
    assert!(destination
        .transfer_from_replayed_source(&source, overspend, 2, &miner.public_key)
        .is_err());
    let mut premature = Transfer {
        chain_id: destination_id,
        owner: miner.public_key.clone(),
        inputs: vec![receipt.miner_fee_outpoint.clone()],
        outputs: vec![Output {
            owner: miner.public_key.clone(),
            amount: Amount(100),
        }],
        fee: Amount(1),
        valid_through_height: 200,
        signature: String::new(),
    };
    premature.signature =
        sign_bytes(&miner.secret_key, &premature.signing_bytes().unwrap()).unwrap();
    assert!(destination
        .transfer_from_replayed_source(&source, premature, 2, &miner.public_key)
        .is_err());
    assert_eq!(destination.root().unwrap(), root_after_import);
    let transferred = destination
        .transfer_from_replayed_source(&source, payment.clone(), 2, &miner.public_key)
        .unwrap();
    assert_eq!(transferred.transaction, payment.id().unwrap());
    assert_eq!(transferred.state_root, destination.root().unwrap());
    assert!(destination.coin(&receipt.recipient_outpoint).is_none());
    assert_eq!(
        destination.coin(&transferred.outputs[0]).unwrap().output,
        Output {
            owner: onward_recipient.public_key.clone(),
            amount: Amount(100)
        }
    );
    assert_eq!(
        destination
            .coin(&transferred.miner_fee_outpoint)
            .unwrap()
            .spendable_height,
        2 + COINBASE_MATURITY
    );
    assert_eq!(destination.imported_total(), amount);
    let root_after_transfer = destination.root().unwrap();
    assert!(destination
        .transfer_from_replayed_source(&source, payment.clone(), 3, &miner.public_key)
        .is_err());
    assert_eq!(destination.root().unwrap(), root_after_transfer);

    let mut wrong_region = DestinationSimulation::new_empty(Hash([8; 32]), policy.clone()).unwrap();
    assert!(wrong_region
        .import_from_replayed_source(&source, bundle.clone(), 1, &miner.public_key)
        .is_err());
    assert_eq!(wrong_region.imported_total(), Amount::ZERO);
    let mut wrong_policy = policy.clone();
    wrong_policy.accepted_v1_tip = Hash([7; 32]);
    let mut wrong_anchor = DestinationSimulation::new_empty(destination_id, wrong_policy).unwrap();
    assert!(wrong_anchor
        .import_from_replayed_source(&source, bundle.clone(), 1, &miner.public_key)
        .is_err());
    assert_eq!(wrong_anchor.imported_total(), Amount::ZERO);

    for offset in 1..=3 {
        let branch_block = mine_source(
            &mut alternate,
            &miner,
            first_time + (offset - 1) * BLOCK_SECONDS + 1,
            vec![],
        );
        source
            .accept(branch_block, first_time + (offset - 1) * BLOCK_SECONDS + 1)
            .unwrap();
    }
    assert!(source
        .observe_export_bundle(&bundle, &destination.source_policy)
        .is_err());
    let mut after_reorg = DestinationSimulation::new_empty(destination_id, policy).unwrap();
    assert!(after_reorg
        .import_from_replayed_source(&source, bundle.clone(), 1, &miner.public_key)
        .is_err());
    assert_eq!(after_reorg.imported_total(), Amount::ZERO);
    assert!(destination.audit_source(&source).is_err());
    assert!(destination.halted());
    assert!(destination
        .import_from_replayed_source(&source, bundle, 3, &miner.public_key)
        .is_err());
    assert!(destination
        .transfer_from_replayed_source(&source, payment, 3, &miner.public_key)
        .is_err());
}
