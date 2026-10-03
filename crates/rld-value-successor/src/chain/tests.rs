use super::*;
use crate::{
    signed_state_hash, ActionFeeIntent, ChallengeFeeReserve, ChallengeFeeReserveIntent,
    DisputeAction,
};
use rld_core::{generate_identity, sign_bytes, verify_bytes, Identity};
use rld_cross_region::value::ExportIntent;
use rld_fast_payments::{
    successor::OpenIntent, ChannelState, ConfirmedEscrow, Registry, SignedState,
};
use rld_pow::{mine_batch as mine_v1, Context, OutPoint, Output};

#[test]
fn direct_empty_earth_genesis_mines_first_value_block_without_predecessor_reward() {
    let miner = generate_identity();
    let genesis = Chain::new(Context {
        network_domain: "fixture:direct-earth".into(),
        zone_id: "fixture-earth".into(),
        currency_genesis: Hash([1; 32]),
        manifest_pin: Hash([2; 32]),
        transition_id: Hash([3; 32]),
        legacy_height: 0,
        legacy_state_root: Hash([4; 32]),
        started_at: 1_000_000,
        initial_target: target_limit(),
    })
    .unwrap();
    let mut chain = CandidateChain::from_replayed_pow_chain(&genesis).unwrap();
    assert_eq!(chain.height(), 0);
    assert_eq!(chain.state().commitment().unwrap().emitted, Amount::ZERO);
    assert_eq!(chain.tip(), genesis.context.chain_id().unwrap());
    let mut block = chain
        .template(miner.public_key.clone(), 1_000_001, vec![])
        .unwrap();
    while !mine_batch(&mut block, 100_000).unwrap() {}
    let id = block.header.id().unwrap();
    let reward = OutPoint {
        transaction: coinbase_id(&block.header).unwrap(),
        index: 0,
    };
    assert!(chain.accept(block, 1_000_001).unwrap());
    assert_eq!(chain.height(), 1);
    assert_eq!(chain.tip(), id);
    assert_eq!(
        chain.state().commitment().unwrap().emitted,
        Amount::from_rld_whole(250_000).unwrap()
    );
    let first_coin = chain.state().coin(&reward).unwrap();
    assert_eq!(first_coin.output.owner, miner.public_key);
    assert_eq!(first_coin.spendable_height, 101);
}

#[test]
fn mining_batch_matches_full_header_hashing() {
    let miner = generate_identity();
    let mut fast = Block {
        header: Header {
            chain_id: Hash([1; 32]),
            parent: Hash([2; 32]),
            height: 10,
            timestamp: 1_000_600,
            target: target_limit(),
            miner: miner.public_key,
            commands_root: Hash([3; 32]),
            state_root: Hash([4; 32]),
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
    assert_eq!(fast.header.nonce, reference.header.nonce);
    assert_eq!(fast.header, reference.header);
}

fn v1_chain(blocks: u128, payer: &Identity) -> Chain {
    let mut chain = Chain::new(Context {
        network_domain: "fixture:unified-successor".into(),
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
            .template(payer.public_key.clone(), timestamp, vec![])
            .unwrap();
        while !mine_v1(&mut block, 100_000).unwrap() {}
        chain.accept(block, timestamp).unwrap();
    }
    chain
}

fn export(v1: &Chain, payer: &Identity, recipient: &Identity) -> ExportCommand {
    let input = v1
        .state()
        .coins
        .iter()
        .find(|(_, coin)| {
            coin.output.owner == payer.public_key && coin.spendable_height <= v1.height() + 1
        })
        .unwrap();
    let amount = Amount::from_rld_whole(1).unwrap();
    let source_fee = Amount(1);
    let change = input
        .1
        .output
        .amount
        .checked_sub(amount.checked_add(source_fee).unwrap())
        .unwrap();
    let intent = ExportIntent {
        source_chain_id: v1.context.chain_id().unwrap(),
        destination_chain_id: Hash([9; 32]),
        input: input.0.clone(),
        owner: payer.public_key.clone(),
        recipient: recipient.public_key.clone(),
        amount,
        source_fee,
        destination_fee: Amount(1),
        change,
        valid_through_height: v1.height() + 100,
    };
    ExportCommand {
        owner_signature: sign_bytes(&payer.secret_key, &intent.signing_bytes().unwrap()).unwrap(),
        intent,
    }
}

fn branch_block(
    chain: &CandidateChain,
    parent: Hash,
    miner: &Identity,
    timestamp: u64,
    commands: Vec<Command>,
) -> Block {
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

fn reserve_fee(
    chain_id: Hash,
    channel: Hash,
    input: OutPoint,
    owner: &Identity,
) -> ChallengeFeeReserve {
    let intent = ChallengeFeeReserveIntent {
        chain_id,
        channel,
        input,
        owner: owner.public_key.clone(),
    };
    ChallengeFeeReserve {
        owner_signature: sign_bytes(&owner.secret_key, &intent.signing_bytes().unwrap()).unwrap(),
        intent,
    }
}

#[test]
fn ordinary_payment_can_fund_later_export_but_cannot_double_spend_in_one_block() {
    let payer = generate_identity();
    let recipient = generate_identity();
    let destination = generate_identity();
    let miner = generate_identity();
    let v1 = v1_chain(100, &payer);
    let mut chain = CandidateChain::from_replayed_pow_chain(&v1).unwrap();
    let conflicting_export = export(&v1, &payer, &destination);
    let source_coin = v1
        .state()
        .coins
        .get(&conflicting_export.intent.input)
        .unwrap();
    let payment = Amount::from_rld_whole(2).unwrap();
    let fee = Amount(1);
    let mut tx = Transfer {
        chain_id: v1.context.chain_id().unwrap(),
        owner: payer.public_key.clone(),
        inputs: vec![conflicting_export.intent.input.clone()],
        outputs: vec![
            Output {
                owner: recipient.public_key.clone(),
                amount: payment,
            },
            Output {
                owner: payer.public_key.clone(),
                amount: source_coin
                    .output
                    .amount
                    .checked_sub(payment.checked_add(fee).unwrap())
                    .unwrap(),
            },
        ],
        fee,
        valid_through_height: v1.height() + 10,
        signature: String::new(),
    };
    tx.signature = sign_bytes(&payer.secret_key, &tx.signing_bytes().unwrap()).unwrap();
    let t1 = 1_000_000 + 101 * BLOCK_SECONDS;
    assert!(chain
        .template(
            miner.public_key.clone(),
            t1,
            vec![
                Command::Transfer(tx.clone()),
                Command::Export(conflicting_export),
            ],
        )
        .is_err());
    let payment_id = tx.id().unwrap();
    let first = branch_block(&chain, chain.tip(), &miner, t1, vec![Command::Transfer(tx)]);
    assert!(chain.accept(first, t1).unwrap());
    let payment_coin = OutPoint {
        transaction: payment_id,
        index: 0,
    };
    assert_eq!(
        chain.state().coin(&payment_coin).unwrap().output.amount,
        payment
    );

    let amount = Amount::from_rld_whole(1).unwrap();
    let intent = ExportIntent {
        source_chain_id: v1.context.chain_id().unwrap(),
        destination_chain_id: Hash([9; 32]),
        input: payment_coin,
        owner: recipient.public_key.clone(),
        recipient: destination.public_key.clone(),
        amount,
        source_fee: Amount(1),
        destination_fee: Amount(1),
        change: payment
            .checked_sub(amount.checked_add(Amount(1)).unwrap())
            .unwrap(),
        valid_through_height: v1.height() + 10,
    };
    let export = ExportCommand {
        owner_signature: sign_bytes(&recipient.secret_key, &intent.signing_bytes().unwrap())
            .unwrap(),
        intent,
    };
    let export_id = export.intent.id().unwrap();
    let second = branch_block(
        &chain,
        chain.tip(),
        &miner,
        t1 + BLOCK_SECONDS,
        vec![Command::Export(export)],
    );
    assert!(chain.accept(second, t1 + BLOCK_SECONDS).unwrap());
    let (liquid, locked, retired) = chain.state().totals().unwrap();
    assert_eq!(locked, Amount::ZERO);
    assert_eq!(retired, amount);
    assert_eq!(liquid.checked_add(retired).unwrap(), chain.state().emitted);
    assert!(chain.state().membership_proof(export_id).is_ok());
}

#[test]
fn mined_export_has_replayed_checkpoint_and_orphaned_branch_loses_authority() {
    let payer = generate_identity();
    let recipient = generate_identity();
    let miner = generate_identity();
    let v1 = v1_chain(100, &payer);
    let mut chain = CandidateChain::from_replayed_pow_chain(&v1).unwrap();
    let command = export(&v1, &payer, &recipient);
    let export_id = command.intent.id().unwrap();
    let base = chain.tip();
    let t1 = 1_000_000 + 101 * BLOCK_SECONDS;
    let first = branch_block(&chain, base, &miner, t1, vec![Command::Export(command)]);
    let checkpoint = first.header.id().unwrap();
    assert!(chain.accept(first, t1).unwrap());
    let first_work = chain.chainwork();
    let proof = chain.state().membership_proof(export_id).unwrap();
    let policy = ObservationPolicy {
        source_chain_id: v1.context.chain_id().unwrap(),
        accepted_v1_tip: base,
        minimum_confirmations: 2,
        minimum_cumulative_work: first_work,
    };
    assert!(chain
        .verify_export_on_best_chain(&proof, checkpoint, &policy)
        .is_err());
    let second = branch_block(&chain, checkpoint, &miner, t1 + BLOCK_SECONDS, vec![]);
    assert!(chain.accept(second, t1 + BLOCK_SECONDS).unwrap());
    chain
        .verify_export_on_best_chain(&proof, checkpoint, &policy)
        .unwrap();
    let bundle = chain.export_bundle(export_id, checkpoint).unwrap();
    let observed = chain.observe_export_bundle(&bundle, &policy).unwrap();
    assert_eq!(observed.record.id().unwrap(), export_id);
    assert_eq!(observed.checkpoint, checkpoint);
    assert_eq!(observed.confirmations, 2);
    assert_eq!(observed.checkpoint_height, v1.height() + 1);
    let mut wrong_bundle = bundle.clone();
    wrong_bundle.destination_chain_id = Hash([8; 32]);
    assert!(chain.observe_export_bundle(&wrong_bundle, &policy).is_err());
    wrong_bundle = bundle.clone();
    wrong_bundle.source_height += 1;
    assert!(chain.observe_export_bundle(&wrong_bundle, &policy).is_err());
    wrong_bundle = bundle.clone();
    wrong_bundle.export_id = Hash([8; 32]);
    assert!(chain.observe_export_bundle(&wrong_bundle, &policy).is_err());
    let pretty = serde_json::to_vec_pretty(&proof).unwrap();
    let pretty_bundle = ProofBundle::from_proof(
        bundle.source_chain_id,
        bundle.destination_chain_id,
        bundle.export_id,
        bundle.source_checkpoint,
        bundle.source_height,
        &pretty,
    )
    .unwrap();
    assert!(chain
        .observe_export_bundle(&pretty_bundle, &policy)
        .is_err());
    let mut wrong = proof.clone();
    wrong.record.command.intent.amount = Amount(2);
    assert!(chain
        .verify_export_on_best_chain(&wrong, checkpoint, &policy)
        .is_err());
    let mut bad_policy = policy.clone();
    bad_policy.accepted_v1_tip = Hash([7; 32]);
    assert!(chain
        .verify_export_on_best_chain(&proof, checkpoint, &bad_policy)
        .is_err());
    bad_policy = policy.clone();
    bad_policy.minimum_cumulative_work = Work::MAX;
    assert!(chain
        .verify_export_on_best_chain(&proof, checkpoint, &bad_policy)
        .is_err());

    let side1 = branch_block(&chain, base, &miner, t1 + 1, vec![]);
    let side1_id = side1.header.id().unwrap();
    assert!(!chain.accept(side1, t1 + 1).unwrap());
    let side2 = branch_block(&chain, side1_id, &miner, t1 + BLOCK_SECONDS + 1, vec![]);
    let side2_id = side2.header.id().unwrap();
    assert!(!chain.accept(side2, t1 + BLOCK_SECONDS + 1).unwrap());
    let side3 = branch_block(&chain, side2_id, &miner, t1 + 2 * BLOCK_SECONDS + 1, vec![]);
    let side3_id = side3.header.id().unwrap();
    assert!(chain.accept(side3, t1 + 2 * BLOCK_SECONDS + 1).unwrap());
    assert_eq!(chain.tip(), side3_id);
    assert!(chain.state().export_record(export_id).is_none());
    assert!(chain
        .verify_export_on_best_chain(&proof, checkpoint, &policy)
        .is_err());
    assert!(chain.observe_export_bundle(&bundle, &policy).is_err());
}

#[test]
fn forged_state_root_or_invalid_command_cannot_advance_candidate_chain() {
    let payer = generate_identity();
    let recipient = generate_identity();
    let miner = generate_identity();
    let v1 = v1_chain(100, &payer);
    let mut chain = CandidateChain::from_replayed_pow_chain(&v1).unwrap();
    let base = chain.tip();
    let root = chain.state().root().unwrap();
    let t1 = 1_000_000 + 101 * BLOCK_SECONDS;
    let mut invalid = export(&v1, &payer, &recipient);
    invalid.owner_signature = "00".into();
    assert!(chain
        .template(miner.public_key.clone(), t1, vec![Command::Export(invalid)])
        .is_err());
    let mut forged = branch_block(&chain, base, &miner, t1, vec![]);
    forged.header.state_root = Hash([7; 32]);
    forged.header.nonce = 0;
    while !mine_batch(&mut forged, 100_000).unwrap() {}
    assert!(chain.accept(forged, t1).is_err());
    assert_eq!(chain.tip(), base);
    assert_eq!(chain.state().root().unwrap(), root);
}

#[test]
fn retarget_continues_from_v1_history_without_a_difficulty_reset() {
    let payer = generate_identity();
    let miner = generate_identity();
    let v1 = v1_chain(144, &payer);
    let candidate = CandidateChain::from_replayed_pow_chain(&v1).unwrap();
    let timestamp = 1_000_000 + 145 * BLOCK_SECONDS;
    let expected = v1
        .template(miner.public_key.clone(), timestamp, vec![])
        .unwrap()
        .header
        .target;
    let actual = candidate
        .template(miner.public_key, timestamp, vec![])
        .unwrap()
        .header
        .target;
    assert_eq!(actual, expected);
}

#[test]
fn bounded_successor_history_matches_full_extension_across_retargets() {
    let miner = generate_identity();
    let v1 = v1_chain(1, &miner);
    let mut chain = CandidateChain::from_replayed_pow_chain(&v1).unwrap();
    let mut timestamp = 1_000_000 + BLOCK_SECONDS;
    for sequence in 1..=289u64 {
        timestamp += if sequence <= 143 { 600 } else { 300 };
        let header = chain
            .next_header(chain.tip(), miner.public_key.clone(), timestamp, &[])
            .unwrap();
        let id = header.id().unwrap();
        chain.entries.insert(
            id,
            Entry {
                block: Block {
                    header,
                    commands: vec![],
                },
                cumulative_work: chain.base_work,
            },
        );
        chain.tip = id;

        let mut extension = Vec::new();
        let mut cursor = chain.tip();
        while cursor != chain.v1_tip {
            let header = &chain.entries.get(&cursor).unwrap().block.header;
            extension.push(Predecessor {
                height: header.height,
                timestamp: header.timestamp,
                target: header.target,
            });
            cursor = header.parent;
        }
        extension.reverse();
        let mut full = chain.base_history.clone();
        full.extend(extension);
        if full.len() > RETARGET_BLOCKS {
            full.drain(..full.len() - RETARGET_BLOCKS);
        }
        let bounded = chain.history_at(chain.tip()).unwrap();
        assert_eq!(bounded.len(), full.len());
        for (got, expected) in bounded.iter().zip(&full) {
            assert_eq!(
                (got.height, got.timestamp, got.target),
                (expected.height, expected.timestamp, expected.target),
                "candidate block {sequence}"
            );
        }
    }
}

#[test]
fn candidate_escrow_observation_requires_confirmed_open_branch() {
    let payer = generate_identity();
    let payee = generate_identity();
    let miner = generate_identity();
    let v1 = v1_chain(100, &payer);
    let source = v1
        .state()
        .coins
        .iter()
        .find(|(_, coin)| {
            coin.output.owner == payer.public_key && coin.spendable_height <= v1.height() + 1
        })
        .unwrap();
    let capacity = Amount::from_rld_whole(1).unwrap();
    let intent = OpenIntent {
        chain_id: v1.context.chain_id().unwrap(),
        input: source.0.clone(),
        party_a: payer.public_key.clone(),
        party_b: payee.public_key.clone(),
        capacity,
        close_fee: Amount(1),
        opening_fee: Amount(1),
        change: source
            .1
            .output
            .amount
            .checked_sub(capacity.checked_add(Amount(1)).unwrap())
            .unwrap(),
        valid_through_height: v1.height() + 10,
    };
    let funding = intent.funding().unwrap();
    let opening_change = intent.change;
    let state = ChannelState::initial(&funding).unwrap();
    let message = state.signing_bytes(&funding).unwrap();
    let initial = SignedState {
        state,
        signature_a: sign_bytes(&payer.secret_key, &message).unwrap(),
        signature_b: sign_bytes(&payee.secret_key, &message).unwrap(),
    };
    let open = OpenChannel {
        signature_a: sign_bytes(&payer.secret_key, &intent.signing_bytes().unwrap()).unwrap(),
        intent,
        initial: initial.clone(),
    };
    let mut chain = CandidateChain::from_replayed_pow_chain(&v1).unwrap();
    let anchor = chain.tip();
    let t1 = 1_000_000 + 101 * BLOCK_SECONDS;
    let first = branch_block(&chain, anchor, &payee, t1, vec![Command::Open(open)]);
    let first_id = first.header.id().unwrap();
    let immature_fee_input = OutPoint {
        transaction: coinbase_id(&first.header).unwrap(),
        index: 0,
    };
    assert!(chain.accept(first, t1).unwrap());
    assert!(CandidateEscrowObservation::new(&chain, 1).is_err());
    let observed = CandidateEscrowObservation::new(&chain, 2).unwrap();
    assert!(observed.verify_confirmed_escrow(&funding).is_err());
    assert!(Registry::default()
        .open(&observed, funding.clone(), initial.clone())
        .is_err());
    let fee_input = OutPoint {
        transaction: funding.id().unwrap(),
        index: 1,
    };
    let reserve = reserve_fee(
        funding.chain_id,
        funding.id().unwrap(),
        fee_input.clone(),
        &payer,
    );
    let second = branch_block(
        &chain,
        first_id,
        &miner,
        t1 + BLOCK_SECONDS,
        vec![Command::ReserveChallengeFee(reserve)],
    );
    assert!(chain.accept(second, t1 + BLOCK_SECONDS).unwrap());
    assert!(CandidateEscrowObservation::new(&chain, 2)
        .unwrap()
        .verify_payment_readiness(
            &funding,
            &payer.public_key,
            &fee_input,
            opening_change,
            Amount(1),
            u128::MAX,
        )
        .is_err());
    let third = branch_block(&chain, chain.tip(), &miner, t1 + 2 * BLOCK_SECONDS, vec![]);
    assert!(chain.accept(third, t1 + 2 * BLOCK_SECONDS).unwrap());
    let observed = CandidateEscrowObservation::new(&chain, 2).unwrap();
    observed.verify_confirmed_escrow(&funding).unwrap();
    assert!(CandidateEscrowObservation::new_finalized(&chain, 2)
        .unwrap()
        .verify_confirmed_escrow(&funding)
        .is_err());
    observed
        .verify_payment_readiness(
            &funding,
            &payer.public_key,
            &fee_input,
            opening_change,
            Amount(1),
            u128::MAX,
        )
        .unwrap();
    let mut finalized_chain = chain.clone();
    finalized_chain.install_finality(first_id).unwrap();
    let finalized_open = CandidateEscrowObservation::new_finalized(&finalized_chain, 2).unwrap();
    finalized_open.verify_confirmed_escrow(&funding).unwrap();
    assert!(finalized_open
        .verify_payment_readiness(
            &funding,
            &payer.public_key,
            &fee_input,
            opening_change,
            Amount(1),
            u128::MAX,
        )
        .is_err());
    let mut fully_finalized_chain = chain.clone();
    fully_finalized_chain.install_finality(chain.tip()).unwrap();
    CandidateEscrowObservation::new_finalized(&fully_finalized_chain, 2)
        .unwrap()
        .verify_payment_readiness(
            &funding,
            &payer.public_key,
            &fee_input,
            opening_change,
            Amount(1),
            u128::MAX,
        )
        .unwrap();
    assert!(observed
        .verify_payment_readiness(
            &funding,
            &payer.public_key,
            &fee_input,
            opening_change,
            Amount(1),
            chain.height() + CONTEST_BLOCKS + 100,
        )
        .is_err());
    let immature = chain.state().coin(&immature_fee_input).unwrap();
    assert!(observed
        .verify_payment_readiness(
            &funding,
            &payee.public_key,
            &immature_fee_input,
            immature.output.amount,
            Amount(1),
            u128::MAX,
        )
        .is_err());
    assert!(observed
        .verify_payment_readiness(
            &funding,
            &payee.public_key,
            &OutPoint {
                transaction: Hash([99; 32]),
                index: 0,
            },
            Amount(10),
            Amount(1),
            u128::MAX,
        )
        .is_err());
    assert_eq!(
        Registry::default()
            .open(&observed, funding.clone(), initial)
            .unwrap(),
        funding.id().unwrap()
    );
    let mut wrong_network = funding.clone();
    wrong_network.chain_id = Hash([8; 32]);
    assert!(observed.verify_confirmed_escrow(&wrong_network).is_err());
    let side1 = branch_block(&chain, anchor, &miner, t1 + 1, vec![]);
    let side1_id = side1.header.id().unwrap();
    assert!(!chain.accept(side1, t1 + 1).unwrap());
    let side2 = branch_block(&chain, side1_id, &miner, t1 + BLOCK_SECONDS + 1, vec![]);
    let side2_id = side2.header.id().unwrap();
    assert!(!chain.accept(side2, t1 + BLOCK_SECONDS + 1).unwrap());
    let side3 = branch_block(&chain, side2_id, &miner, t1 + 2 * BLOCK_SECONDS + 1, vec![]);
    let side3_id = side3.header.id().unwrap();
    assert!(!chain.accept(side3, t1 + 2 * BLOCK_SECONDS + 1).unwrap());
    let side4 = branch_block(&chain, side3_id, &miner, t1 + 3 * BLOCK_SECONDS + 1, vec![]);
    assert!(chain.accept(side4, t1 + 3 * BLOCK_SECONDS + 1).unwrap());
    assert!(CandidateEscrowObservation::new(&chain, 2)
        .unwrap()
        .verify_confirmed_escrow(&funding)
        .is_err());
}

#[test]
fn close_and_challenge_require_action_bound_fee_spends() {
    let payer = generate_identity();
    let payee = generate_identity();
    let miner = generate_identity();
    let v1 = v1_chain(101, &payer);
    let source = v1
        .state()
        .coins
        .iter()
        .find(|(_, coin)| {
            coin.output.owner == payer.public_key && coin.spendable_height <= v1.height() + 1
        })
        .unwrap();
    // The payee's challenge uses its own funded coin, independent of the
    // closer's fee change and private key.
    let challenge_source = v1
        .state()
        .coins
        .iter()
        .filter(|(_, coin)| {
            coin.output.owner == payer.public_key && coin.spendable_height <= v1.height() + 1
        })
        .nth(1)
        .expect("second mature fee input");
    let challenge_amount = Amount(10);
    let mut challenge_funding = Transfer {
        chain_id: v1.context.chain_id().unwrap(),
        owner: payer.public_key.clone(),
        inputs: vec![challenge_source.0.clone()],
        outputs: vec![
            Output {
                owner: payee.public_key.clone(),
                amount: challenge_amount,
            },
            Output {
                owner: payer.public_key.clone(),
                amount: challenge_source
                    .1
                    .output
                    .amount
                    .checked_sub(challenge_amount.checked_add(Amount(1)).unwrap())
                    .unwrap(),
            },
        ],
        fee: Amount(1),
        valid_through_height: v1.height() + 10,
        signature: String::new(),
    };
    challenge_funding.signature = sign_bytes(
        &payer.secret_key,
        &challenge_funding.signing_bytes().unwrap(),
    )
    .unwrap();
    let challenge_input = OutPoint {
        transaction: challenge_funding.id().unwrap(),
        index: 0,
    };
    let capacity = Amount::from_rld_whole(1).unwrap();
    let intent = OpenIntent {
        chain_id: v1.context.chain_id().unwrap(),
        input: source.0.clone(),
        party_a: payer.public_key.clone(),
        party_b: payee.public_key.clone(),
        capacity,
        close_fee: Amount(1),
        opening_fee: Amount(1),
        change: source
            .1
            .output
            .amount
            .checked_sub(capacity.checked_add(Amount(1)).unwrap())
            .unwrap(),
        valid_through_height: v1.height() + 10,
    };
    let funding = intent.funding().unwrap();
    let sign_state = |state: ChannelState| {
        let message = state.signing_bytes(&funding).unwrap();
        SignedState {
            state,
            signature_a: sign_bytes(&payer.secret_key, &message).unwrap(),
            signature_b: sign_bytes(&payee.secret_key, &message).unwrap(),
        }
    };
    let initial = sign_state(ChannelState::initial(&funding).unwrap());
    let newer = sign_state(
        initial
            .state
            .propose_payment(&funding, &payer.public_key, Amount(100), Hash([7; 32]))
            .unwrap(),
    );
    let open = OpenChannel {
        signature_a: sign_bytes(&payer.secret_key, &intent.signing_bytes().unwrap()).unwrap(),
        intent,
        initial: initial.clone(),
    };
    let mut chain = CandidateChain::from_replayed_pow_chain(&v1).unwrap();
    let t1 = 1_000_000 + 102 * BLOCK_SECONDS;
    let first = chain
        .template(
            miner.public_key.clone(),
            t1,
            vec![Command::Open(open), Command::Transfer(challenge_funding)],
        )
        .unwrap();
    let mut first = first;
    while !mine_batch(&mut first, 100_000).unwrap() {}
    assert!(chain.accept(first, t1).unwrap());
    let channel = funding.id().unwrap();
    let fee_for = |owner: &Identity,
                   action: DisputeAction,
                   state: &SignedState,
                   input: OutPoint,
                   input_amount: Amount,
                   expiry: u128| {
        let intent = ActionFeeIntent {
            chain_id: funding.chain_id,
            action,
            channel,
            signed_state: signed_state_hash(state).unwrap(),
            input,
            owner: owner.public_key.clone(),
            fee: Amount(1),
            change: input_amount.checked_sub(Amount(1)).unwrap(),
            valid_through_height: expiry,
        };
        let owner_signature =
            sign_bytes(&owner.secret_key, &intent.signing_bytes().unwrap()).unwrap();
        ActionFee {
            intent,
            owner_signature,
        }
    };
    let close_fee_input = OutPoint {
        transaction: channel,
        index: 1,
    };
    let close_fee_amount = chain.state().coin(&close_fee_input).unwrap().output.amount;
    let close_fee = fee_for(
        &payer,
        DisputeAction::Close,
        &initial,
        close_fee_input.clone(),
        close_fee_amount,
        v1.height() + 10,
    );
    let close_fee_id = close_fee.intent.id().unwrap();
    let close_height = v1.height() + 2;
    let close_time = t1 + BLOCK_SECONDS;
    let root_before_close = chain.state().root().unwrap();
    let mut bad_state = initial.clone();
    bad_state.signature_b = "00".into();
    let bad_close = Command::Close {
        channel,
        state: bad_state,
        fee: fee_for(
            &payer,
            DisputeAction::Close,
            &initial,
            close_fee_input,
            close_fee_amount,
            v1.height() + 10,
        ),
    };
    assert!(chain
        .template(miner.public_key.clone(), close_time, vec![bad_close])
        .is_err());
    assert_eq!(chain.state().root().unwrap(), root_before_close);
    let close = Command::Close {
        channel,
        state: initial.clone(),
        fee: close_fee.clone(),
    };
    let mut forged_fee = close_fee.clone();
    forged_fee.owner_signature = "00".into();
    assert!(chain
        .template(
            miner.public_key.clone(),
            close_time,
            vec![Command::Close {
                channel,
                state: initial.clone(),
                fee: forged_fee,
            }],
        )
        .is_err());
    let reserve = reserve_fee(funding.chain_id, channel, challenge_input.clone(), &payee);
    let mut forged_reserve = reserve.clone();
    forged_reserve.owner_signature = "00".into();
    assert!(chain
        .template(
            miner.public_key.clone(),
            close_time,
            vec![Command::ReserveChallengeFee(forged_reserve)],
        )
        .is_err());
    let mut close_block = chain
        .template(
            miner.public_key.clone(),
            close_time,
            vec![Command::ReserveChallengeFee(reserve), close],
        )
        .unwrap();
    while !mine_batch(&mut close_block, 100_000).unwrap() {}
    assert!(chain.accept(close_block, close_time).unwrap());
    assert!(matches!(
        chain.state().escrow(channel).unwrap().phase,
        Phase::Closing { .. }
    ));
    assert!(chain.state().coin(&challenge_input).is_none());
    assert_eq!(
        chain
            .state()
            .reserved_challenge_fee(&challenge_input)
            .unwrap()
            .coin
            .output
            .amount,
        challenge_amount
    );
    let checkpoint = chain.replayed_checkpoint().unwrap();
    let checkpoint_bytes = serde_json::to_vec(&checkpoint).unwrap();
    let restored = serde_json::from_slice(&checkpoint_bytes).unwrap();
    chain.verify_replayed_checkpoint(&restored).unwrap();
    assert_eq!(
        chain
            .state()
            .coin(&OutPoint {
                transaction: close_fee_id,
                index: 1,
            })
            .unwrap()
            .spendable_height,
        close_height + COINBASE_MATURITY
    );
    let fee_change = OutPoint {
        transaction: close_fee_id,
        index: 0,
    };
    assert_eq!(
        chain.state().coin(&fee_change).unwrap().output.amount,
        close_fee_amount.checked_sub(Amount(1)).unwrap()
    );
    let challenge_fee = fee_for(
        &payee,
        DisputeAction::Challenge,
        &newer,
        challenge_input.clone(),
        challenge_amount,
        v1.height() + 10,
    );
    let root_before_challenge = chain.state().root().unwrap();
    let unreserved_fee = fee_for(
        &payer,
        DisputeAction::Challenge,
        &newer,
        fee_change,
        close_fee_amount.checked_sub(Amount(1)).unwrap(),
        v1.height() + 10,
    );
    assert!(chain
        .template(
            miner.public_key.clone(),
            close_time + BLOCK_SECONDS,
            vec![Command::Challenge {
                channel,
                state: newer.clone(),
                fee: unreserved_fee,
            }],
        )
        .is_err());
    let wrong_action_fee = fee_for(
        &payee,
        DisputeAction::Close,
        &newer,
        challenge_input.clone(),
        challenge_amount,
        v1.height() + 10,
    );
    assert!(chain
        .template(
            miner.public_key.clone(),
            close_time + BLOCK_SECONDS,
            vec![Command::Challenge {
                channel,
                state: newer.clone(),
                fee: wrong_action_fee,
            }],
        )
        .is_err());
    let wrong_state_fee = fee_for(
        &payee,
        DisputeAction::Challenge,
        &initial,
        challenge_input.clone(),
        challenge_amount,
        v1.height() + 10,
    );
    assert!(chain
        .template(
            miner.public_key.clone(),
            close_time + BLOCK_SECONDS,
            vec![Command::Challenge {
                channel,
                state: newer.clone(),
                fee: wrong_state_fee,
            }],
        )
        .is_err());
    let stolen_fee = Transfer {
        chain_id: funding.chain_id,
        owner: payee.public_key.clone(),
        inputs: vec![challenge_input],
        outputs: vec![Output {
            owner: payee.public_key.clone(),
            amount: challenge_fee.intent.change,
        }],
        fee: Amount(1),
        valid_through_height: v1.height() + 10,
        signature: challenge_fee.owner_signature.clone(),
    };
    assert!(verify_bytes(
        &payee.public_key,
        &stolen_fee.signing_bytes().unwrap(),
        &stolen_fee.signature
    )
    .is_err());
    assert!(chain
        .template(
            miner.public_key.clone(),
            close_time + BLOCK_SECONDS,
            vec![Command::Transfer(stolen_fee)]
        )
        .is_err());
    assert_eq!(chain.state().root().unwrap(), root_before_challenge);
    let fee_id = challenge_fee.intent.id().unwrap();
    let mut block = chain
        .template(
            miner.public_key.clone(),
            close_time + BLOCK_SECONDS,
            vec![Command::Challenge {
                channel,
                state: newer.clone(),
                fee: challenge_fee.clone(),
            }],
        )
        .unwrap();
    while !mine_batch(&mut block, 100_000).unwrap() {}
    assert!(chain.accept(block, close_time + BLOCK_SECONDS).unwrap());
    assert!(matches!(
        &chain.state().escrow(channel).unwrap().phase,
        Phase::Closing { best, .. } if best == &newer
    ));
    assert_eq!(
        chain
            .state()
            .coin(&OutPoint {
                transaction: fee_id,
                index: 1
            })
            .unwrap()
            .output
            .amount,
        Amount(1)
    );
    let stale_input = OutPoint {
        transaction: fee_id,
        index: 0,
    };
    let stale_amount = chain.state().coin(&stale_input).unwrap().output.amount;
    let stale_fee = fee_for(
        &payee,
        DisputeAction::Challenge,
        &initial,
        stale_input,
        stale_amount,
        v1.height() + 10,
    );
    let root = chain.state().root().unwrap();
    let mut direct_state = chain.state().clone();
    assert!(direct_state
        .challenge_with_fee(
            channel,
            initial.clone(),
            stale_fee.clone(),
            close_height + 2,
            &miner.public_key,
        )
        .is_err());
    assert_eq!(direct_state.root().unwrap(), root);
    assert!(chain
        .template(
            miner.public_key.clone(),
            close_time + 2 * BLOCK_SECONDS,
            vec![Command::Challenge {
                channel,
                state: initial,
                fee: stale_fee,
            }],
        )
        .is_err());
    assert_eq!(chain.state().root().unwrap(), root);
    assert_eq!(chain.state().totals().unwrap().1, capacity);
}
