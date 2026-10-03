use super::*;
use rld_core::{generate_identity, sign_bytes, Identity};
use rld_cross_region::value::ExportIntent;
use rld_fast_payments::{successor::OpenIntent, ChannelState, SignedState};

struct Fixture {
    ledger: Ledger,
    input: OutPoint,
    open: OpenChannel,
    export: ExportCommand,
    payer: Identity,
    payee: Identity,
    miner: Identity,
}

fn ordinary_transfer(f: &Fixture) -> Transfer {
    let mut tx = Transfer {
        chain_id: Hash([1; 32]),
        owner: f.payer.public_key.clone(),
        inputs: vec![f.input.clone()],
        outputs: vec![
            Output {
                owner: f.payee.public_key.clone(),
                amount: Amount(100),
            },
            Output {
                owner: f.payer.public_key.clone(),
                amount: Amount(4),
            },
        ],
        fee: Amount(1),
        valid_through_height: 30,
        signature: String::new(),
    };
    tx.signature = sign_bytes(&f.payer.secret_key, &tx.signing_bytes().unwrap()).unwrap();
    tx
}

fn signed(
    state: ChannelState,
    funding: &rld_fast_payments::Funding,
    a: &Identity,
    b: &Identity,
) -> SignedState {
    let bytes = state.signing_bytes(funding).unwrap();
    SignedState {
        state,
        signature_a: sign_bytes(&a.secret_key, &bytes).unwrap(),
        signature_b: sign_bytes(&b.secret_key, &bytes).unwrap(),
    }
}

fn fixture() -> Fixture {
    let payer = generate_identity();
    let payee = generate_identity();
    let miner = generate_identity();
    let input = OutPoint {
        transaction: Hash([2; 32]),
        index: 7,
    };
    let v1 = V1State {
        coins: BTreeMap::from([(
            input.clone(),
            Coin {
                output: Output {
                    owner: payer.public_key.clone(),
                    amount: Amount(105),
                },
                spendable_height: 10,
            },
        )]),
        emitted: Amount(105),
    };
    let chain_id = Hash([1; 32]);
    let open_intent = OpenIntent {
        chain_id,
        input: input.clone(),
        party_a: payer.public_key.clone(),
        party_b: payee.public_key.clone(),
        capacity: Amount(101),
        close_fee: Amount(1),
        opening_fee: Amount(1),
        change: Amount(3),
        valid_through_height: 30,
    };
    let funding = open_intent.funding().unwrap();
    let open = OpenChannel {
        signature_a: sign_bytes(&payer.secret_key, &open_intent.signing_bytes().unwrap()).unwrap(),
        initial: signed(
            ChannelState::initial(&funding).unwrap(),
            &funding,
            &payer,
            &payee,
        ),
        intent: open_intent,
    };
    let export_intent = ExportIntent {
        source_chain_id: chain_id,
        destination_chain_id: Hash([9; 32]),
        input: input.clone(),
        owner: payer.public_key.clone(),
        recipient: payee.public_key.clone(),
        amount: Amount(100),
        source_fee: Amount(1),
        destination_fee: Amount(1),
        change: Amount(4),
        valid_through_height: 30,
    };
    let export = ExportCommand {
        owner_signature: sign_bytes(&payer.secret_key, &export_intent.signing_bytes().unwrap())
            .unwrap(),
        intent: export_intent,
    };
    let ledger =
        Ledger::from_verified_anchor(chain_id, &v1, Hash([8; 32]), v1.root().unwrap(), 9).unwrap();
    Fixture {
        ledger,
        input,
        open,
        export,
        payer,
        payee,
        miner,
    }
}

#[test]
fn invalid_public_keys_cannot_enter_the_unified_coin_set() {
    let mut bad_v1 = V1State {
        coins: BTreeMap::from([(
            OutPoint {
                transaction: Hash([7; 32]),
                index: 0,
            },
            Coin {
                output: Output {
                    owner: "00".repeat(32),
                    amount: Amount(1),
                },
                spendable_height: 10,
            },
        )]),
        emitted: Amount(1),
    };
    assert!(bad_v1.root().is_err());
    assert!(
        Ledger::from_verified_anchor(Hash([1; 32]), &bad_v1, Hash([8; 32]), Hash([9; 32]), 9)
            .is_err()
    );
    let mut f = fixture();
    let before = f.ledger.clone();
    assert!(f
        .ledger
        .output(Hash([10; 32]), 0, "00".repeat(32), Amount(1), 10)
        .is_err());
    assert_eq!(f.ledger, before);
    bad_v1.coins.values_mut().next().unwrap().output.owner = f.payer.public_key;
    assert!(bad_v1.root().is_ok());
}

#[test]
fn channel_and_export_compete_for_the_same_mature_coin_in_both_orders() {
    let mut f = fixture();
    let id = f
        .ledger
        .open(f.open.clone(), 10, &f.miner.public_key)
        .unwrap();
    assert!(f.ledger.coin(&f.input).is_none());
    assert_eq!(
        f.ledger.totals().unwrap(),
        (Amount(4), Amount(101), Amount(0))
    );
    let root = f.ledger.root().unwrap();
    assert!(f
        .ledger
        .export(f.export.clone(), 10, &f.miner.public_key)
        .is_err());
    assert_eq!(f.ledger.root().unwrap(), root);
    assert!(f.ledger.escrow(id).is_some());

    let mut f = fixture();
    let record = f
        .ledger
        .export(f.export.clone(), 10, &f.miner.public_key)
        .unwrap();
    assert!(f.ledger.coin(&f.input).is_none());
    assert_eq!(
        f.ledger.totals().unwrap(),
        (Amount(5), Amount(0), Amount(100))
    );
    let root = f.ledger.root().unwrap();
    assert!(f
        .ledger
        .open(f.open.clone(), 10, &f.miner.public_key)
        .is_err());
    assert_eq!(f.ledger.root().unwrap(), root);
    assert!(f.ledger.export_record(record.id().unwrap()).is_some());
}

#[test]
fn ordinary_transfer_competes_with_channel_and_export_in_both_orders() {
    let mut f = fixture();
    let transfer = ordinary_transfer(&f);
    let id = f
        .ledger
        .transfer(transfer.clone(), 10, &f.miner.public_key)
        .unwrap();
    assert!(f.ledger.coin(&f.input).is_none());
    assert_eq!(
        f.ledger
            .coin(&OutPoint {
                transaction: id,
                index: 0
            })
            .unwrap()
            .output
            .amount,
        Amount(100)
    );
    assert_eq!(
        f.ledger
            .coin(&OutPoint {
                transaction: id,
                index: u16::MAX
            })
            .unwrap()
            .spendable_height,
        10 + COINBASE_MATURITY
    );
    assert_eq!(
        f.ledger.totals().unwrap(),
        (Amount(105), Amount::ZERO, Amount::ZERO)
    );
    let root = f.ledger.root().unwrap();
    assert!(f
        .ledger
        .open(f.open.clone(), 10, &f.miner.public_key)
        .is_err());
    assert!(f
        .ledger
        .export(f.export.clone(), 10, &f.miner.public_key)
        .is_err());
    assert_eq!(f.ledger.root().unwrap(), root);

    let mut f = fixture();
    let transfer = ordinary_transfer(&f);
    f.ledger
        .open(f.open.clone(), 10, &f.miner.public_key)
        .unwrap();
    let root = f.ledger.root().unwrap();
    assert!(f
        .ledger
        .transfer(transfer, 10, &f.miner.public_key)
        .is_err());
    assert_eq!(f.ledger.root().unwrap(), root);

    let mut f = fixture();
    let transfer = ordinary_transfer(&f);
    f.ledger
        .export(f.export.clone(), 10, &f.miner.public_key)
        .unwrap();
    let root = f.ledger.root().unwrap();
    assert!(f
        .ledger
        .transfer(transfer, 10, &f.miner.public_key)
        .is_err());
    assert_eq!(f.ledger.root().unwrap(), root);
}

#[test]
fn invalid_ordinary_transfer_is_failure_atomic() {
    let mut f = fixture();
    let root = f.ledger.root().unwrap();
    let mut tx = ordinary_transfer(&f);
    tx.outputs[0].amount = Amount(101);
    tx.signature = sign_bytes(&f.payer.secret_key, &tx.signing_bytes().unwrap()).unwrap();
    assert!(f.ledger.transfer(tx, 10, &f.miner.public_key).is_err());
    let mut tx = ordinary_transfer(&f);
    tx.signature = "00".into();
    assert!(f.ledger.transfer(tx, 10, &f.miner.public_key).is_err());
    let mut tx = ordinary_transfer(&f);
    tx.inputs.push(f.input.clone());
    assert!(f.ledger.transfer(tx, 10, &f.miner.public_key).is_err());
    assert!(f
        .ledger
        .transfer(ordinary_transfer(&f), 9, &f.miner.public_key)
        .is_err());
    assert_eq!(f.ledger.root().unwrap(), root);
}

#[test]
fn channel_challenge_and_finalization_preserve_supply() {
    let mut f = fixture();
    let id = f
        .ledger
        .open(f.open.clone(), 10, &f.miner.public_key)
        .unwrap();
    let funding = f.ledger.escrow(id).unwrap().funding.clone();
    let paid = f
        .open
        .initial
        .state
        .propose_payment(&funding, &f.payer.public_key, Amount(20), Hash([3; 32]))
        .unwrap();
    let newer = signed(paid, &funding, &f.payer, &f.payee);
    f.ledger
        .request_close(id, f.open.initial.clone(), 11)
        .unwrap();
    f.ledger.challenge(id, newer, 12).unwrap();
    assert!(f
        .ledger
        .finalize(id, 11 + CONTEST_BLOCKS, &f.miner.public_key)
        .is_err());
    let payout = f
        .ledger
        .finalize(id, 12 + CONTEST_BLOCKS, &f.miner.public_key)
        .unwrap();
    assert_eq!(payout.amount_b, Amount(20));
    assert_eq!(
        f.ledger.totals().unwrap(),
        (Amount(105), Amount(0), Amount(0))
    );
    assert!(f
        .ledger
        .finalize(id, 13 + CONTEST_BLOCKS, &f.miner.public_key)
        .is_err());
}

#[test]
fn reserved_challenge_fee_cannot_be_spent_and_is_refunded_at_settlement() {
    let mut f = fixture();
    let channel = f
        .ledger
        .open(f.open.clone(), 10, &f.miner.public_key)
        .unwrap();
    let input = OutPoint {
        transaction: channel,
        index: 1,
    };
    let intent = ChallengeFeeReserveIntent {
        chain_id: Hash([1; 32]),
        channel,
        input: input.clone(),
        owner: f.payer.public_key.clone(),
    };
    let command = ChallengeFeeReserve {
        owner_signature: sign_bytes(&f.payer.secret_key, &intent.signing_bytes().unwrap()).unwrap(),
        intent,
    };
    let mut forged = command.clone();
    forged.owner_signature = "00".into();
    let before = f.ledger.root().unwrap();
    assert!(f.ledger.reserve_challenge_fee(forged, 11).is_err());
    assert_eq!(f.ledger.root().unwrap(), before);
    f.ledger.reserve_challenge_fee(command, 11).unwrap();
    assert!(f.ledger.coin(&input).is_none());
    assert_eq!(
        f.ledger.totals().unwrap(),
        (Amount(1), Amount(104), Amount(0))
    );
    let mut transfer = Transfer {
        chain_id: Hash([1; 32]),
        owner: f.payer.public_key.clone(),
        inputs: vec![input.clone()],
        outputs: vec![Output {
            owner: f.payer.public_key.clone(),
            amount: Amount(2),
        }],
        fee: Amount(1),
        valid_through_height: 30,
        signature: String::new(),
    };
    transfer.signature =
        sign_bytes(&f.payer.secret_key, &transfer.signing_bytes().unwrap()).unwrap();
    let locked_root = f.ledger.root().unwrap();
    assert!(f
        .ledger
        .transfer(transfer, 12, &f.miner.public_key)
        .is_err());
    assert_eq!(f.ledger.root().unwrap(), locked_root);
    f.ledger
        .request_close(channel, f.open.initial.clone(), 12)
        .unwrap();
    f.ledger
        .finalize(channel, 13 + CONTEST_BLOCKS, &f.miner.public_key)
        .unwrap();
    assert!(f.ledger.reserved_challenge_fee(&input).is_none());
    assert_eq!(
        f.ledger.totals().unwrap(),
        (Amount(105), Amount(0), Amount(0))
    );
    assert!(f.ledger.coins.values().any(|coin| {
        coin.output.owner == f.payer.public_key && coin.output.amount == Amount(3)
    }));
}

#[test]
fn disjoint_channel_and_export_coexist_with_one_supply_commitment() {
    let mut f = fixture();
    let second = OutPoint {
        transaction: Hash([4; 32]),
        index: 0,
    };
    let mut coins = f.ledger.coins.clone();
    coins.insert(
        second.clone(),
        Coin {
            output: Output {
                owner: f.payer.public_key.clone(),
                amount: Amount(105),
            },
            spendable_height: 10,
        },
    );
    let v1 = V1State {
        coins,
        emitted: Amount(210),
    };
    f.ledger =
        Ledger::from_verified_anchor(Hash([1; 32]), &v1, Hash([8; 32]), v1.root().unwrap(), 9)
            .unwrap();
    f.export.intent.input = second;
    f.export.owner_signature = sign_bytes(
        &f.payer.secret_key,
        &f.export.intent.signing_bytes().unwrap(),
    )
    .unwrap();
    let channel_id = f
        .ledger
        .open(f.open.clone(), 10, &f.miner.public_key)
        .unwrap();
    let export_id = f
        .ledger
        .export(f.export.clone(), 10, &f.miner.public_key)
        .unwrap()
        .id()
        .unwrap();
    assert!(f.ledger.escrow(channel_id).is_some());
    assert!(f.ledger.export_record(export_id).is_some());
    let proof = f.ledger.membership_proof(export_id).unwrap();
    assert_eq!(
        proof
            .verify_in_claimed_state(f.ledger.root().unwrap())
            .unwrap()
            .id()
            .unwrap(),
        export_id
    );
    assert_eq!(
        f.ledger.totals().unwrap(),
        (Amount(9), Amount(101), Amount(100))
    );
    f.ledger
        .request_close(channel_id, f.open.initial.clone(), 11)
        .unwrap();
    f.ledger
        .finalize(channel_id, 12 + CONTEST_BLOCKS, &f.miner.public_key)
        .unwrap();
    assert_eq!(
        f.ledger.totals().unwrap(),
        (Amount(110), Amount(0), Amount(100))
    );
    assert!(proof
        .verify_in_claimed_state(f.ledger.root().unwrap())
        .is_err());
}

#[test]
fn unified_export_proof_rejects_record_path_and_claimed_root_changes() {
    let mut f = fixture();
    let mut coins = f.ledger.coins.clone();
    let inputs = [
        f.input.clone(),
        OutPoint {
            transaction: Hash([4; 32]),
            index: 0,
        },
        OutPoint {
            transaction: Hash([5; 32]),
            index: 0,
        },
    ];
    for point in inputs.iter().skip(1) {
        coins.insert(
            point.clone(),
            Coin {
                output: Output {
                    owner: f.payer.public_key.clone(),
                    amount: Amount(105),
                },
                spendable_height: 10,
            },
        );
    }
    let v1 = V1State {
        coins,
        emitted: Amount(315),
    };
    f.ledger =
        Ledger::from_verified_anchor(Hash([1; 32]), &v1, Hash([8; 32]), v1.root().unwrap(), 9)
            .unwrap();
    let mut ids = Vec::new();
    for point in inputs {
        let mut command = f.export.clone();
        command.intent.input = point;
        command.owner_signature = sign_bytes(
            &f.payer.secret_key,
            &command.intent.signing_bytes().unwrap(),
        )
        .unwrap();
        ids.push(
            f.ledger
                .export(command, 10, &f.miner.public_key)
                .unwrap()
                .id()
                .unwrap(),
        );
    }
    assert_eq!(
        f.ledger.totals().unwrap(),
        (Amount(15), Amount(0), Amount(300))
    );
    let root = f.ledger.root().unwrap();
    for id in ids {
        let proof = f.ledger.membership_proof(id).unwrap();
        assert_eq!(
            proof.verify_in_claimed_state(root).unwrap().id().unwrap(),
            id
        );
        assert!(proof.verify_in_claimed_state(Hash([7; 32])).is_err());
        let mut changed = proof.clone();
        changed.record.command.intent.amount = Amount(99);
        assert!(changed.verify_in_claimed_state(root).is_err());
        let mut changed = proof.clone();
        changed.siblings[0] = Hash([6; 32]);
        assert!(changed.verify_in_claimed_state(root).is_err());
    }
}

#[test]
fn malformed_signature_immature_input_and_wrong_anchor_do_not_mutate_state() {
    let mut f = fixture();
    let root = f.ledger.root().unwrap();
    assert!(f
        .ledger
        .open(f.open.clone(), 9, &f.miner.public_key)
        .is_err());
    let mut invalid = f.export.clone();
    invalid.owner_signature = "00".into();
    assert!(f.ledger.export(invalid, 10, &f.miner.public_key).is_err());
    assert_eq!(f.ledger.root().unwrap(), root);
    let v1 = V1State {
        coins: f.ledger.coins.clone(),
        emitted: Amount(105),
    };
    assert!(
        Ledger::from_verified_anchor(Hash([1; 32]), &v1, Hash([8; 32]), Hash([7; 32]), 9).is_err()
    );
}

#[test]
fn public_constructor_uses_the_replayed_pow_tip_and_rejects_no_block() {
    use rld_pow::{mine_batch, target_limit, Chain, Context};
    let payer = generate_identity();
    let context = Context {
        network_domain: "fixture:unified-anchor".into(),
        zone_id: "fixture-earth".into(),
        currency_genesis: Hash([1; 32]),
        manifest_pin: Hash([2; 32]),
        transition_id: Hash([3; 32]),
        legacy_height: 9,
        legacy_state_root: Hash([4; 32]),
        started_at: 1_000_000,
        initial_target: target_limit(),
    };
    let mut chain = Chain::new(context).unwrap();
    assert!(Ledger::from_replayed_pow_chain(&chain).is_err());
    let mut block = chain.template(payer.public_key, 1_000_600, vec![]).unwrap();
    while !mine_batch(&mut block, 100_000).unwrap() {}
    chain.accept(block, 1_000_600).unwrap();
    let ledger = Ledger::from_replayed_pow_chain(&chain).unwrap();
    assert_eq!(ledger.v1_tip, chain.tip());
    assert_eq!(ledger.v1_root, chain.state().root().unwrap());
    assert_eq!(
        ledger.totals().unwrap(),
        (chain.state().emitted, Amount::ZERO, Amount::ZERO)
    );
}
