use super::*;
use crate::ChannelState;
use rld_core::{generate_identity, sign_bytes, Identity};

#[test]
fn channel_open_starts_from_replayed_pow_reward_without_caller_supplied_root() {
    use rld_pow::{mine_batch, target_limit, Chain, Context};
    let payer = generate_identity();
    let payee = generate_identity();
    let miner = generate_identity();
    let mut chain = Chain::new(Context {
        network_domain: "fixture:channel-anchor".into(),
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
    for sequence in 1..=100 {
        let time = 1_000_000 + sequence * 600;
        let mut block = chain
            .template(payer.public_key.clone(), time, vec![])
            .unwrap();
        while !mine_batch(&mut block, 100_000).unwrap() {}
        chain.accept(block, time).unwrap();
    }
    let (input, coin) = chain
        .state()
        .coins
        .iter()
        .find(|(_, coin)| coin.spendable_height <= chain.height() + 1)
        .unwrap();
    let capacity = Amount::from_rld_whole(1).unwrap();
    let opening_fee = Amount(1);
    let change = coin
        .output
        .amount
        .checked_sub(capacity.checked_add(opening_fee).unwrap())
        .unwrap();
    let intent = OpenIntent {
        chain_id: chain.context.chain_id().unwrap(),
        input: input.clone(),
        party_a: payer.public_key.clone(),
        party_b: payee.public_key.clone(),
        capacity,
        close_fee: Amount(1),
        opening_fee,
        change,
        valid_through_height: chain.height() + 100,
    };
    let funding = intent.funding().unwrap();
    let open = OpenChannel {
        signature_a: sign_bytes(&payer.secret_key, &intent.signing_bytes().unwrap()).unwrap(),
        initial: signed(
            &funding,
            ChannelState::initial(&funding).unwrap(),
            &payer,
            &payee,
        ),
        intent,
    };
    let mut successor = Ledger::from_replayed_pow_chain(&chain).unwrap();
    let channel = successor
        .open(open, chain.height() + 1, &miner.public_key)
        .unwrap();
    assert!(successor.coin(input).is_none());
    assert_eq!(
        successor.escrow(channel).unwrap().funding.capacity,
        capacity
    );
    successor.root().unwrap();
}

struct Fixture {
    ledger: Ledger,
    open: OpenChannel,
    input: OutPoint,
    a: Identity,
    b: Identity,
    miner: Identity,
}

fn signed(funding: &Funding, state: ChannelState, a: &Identity, b: &Identity) -> SignedState {
    let message = state.signing_bytes(funding).unwrap();
    SignedState {
        state,
        signature_a: sign_bytes(&a.secret_key, &message).unwrap(),
        signature_b: sign_bytes(&b.secret_key, &message).unwrap(),
    }
}

fn fixture() -> Fixture {
    let a = generate_identity();
    let b = generate_identity();
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
                    owner: a.public_key.clone(),
                    amount: Amount(105),
                },
                spendable_height: 10,
            },
        )]),
        emitted: Amount(105),
    };
    let intent = OpenIntent {
        chain_id: Hash([1; 32]),
        input: input.clone(),
        party_a: a.public_key.clone(),
        party_b: b.public_key.clone(),
        capacity: Amount(101),
        close_fee: Amount(1),
        opening_fee: Amount(1),
        change: Amount(3),
        valid_through_height: 30,
    };
    let funding = intent.funding().unwrap();
    let initial = signed(&funding, ChannelState::initial(&funding).unwrap(), &a, &b);
    let open = OpenChannel {
        signature_a: sign_bytes(&a.secret_key, &intent.signing_bytes().unwrap()).unwrap(),
        intent,
        initial,
    };
    let ledger =
        Ledger::from_v1_snapshot(Hash([1; 32]), &v1, Hash([8; 32]), v1.root().unwrap(), 9).unwrap();
    Fixture {
        ledger,
        open,
        input,
        a,
        b,
        miner,
    }
}

#[test]
fn opening_consumes_one_mature_coin_and_settlement_preserves_all_value() {
    let mut f = fixture();
    let id = f
        .ledger
        .open(f.open.clone(), 10, &f.miner.public_key)
        .unwrap();
    assert!(f.ledger.coin(&f.input).is_none());
    let funding = &f.ledger.escrow(id).unwrap().funding;
    assert_eq!(funding.outpoint.transaction, f.open.intent.id().unwrap());
    let first = signed(
        funding,
        f.open
            .initial
            .state
            .propose_payment(funding, &f.a.public_key, Amount(10), Hash([3; 32]))
            .unwrap(),
        &f.a,
        &f.b,
    );
    let newer = signed(
        funding,
        first
            .state
            .propose_payment(funding, &f.a.public_key, Amount(20), Hash([4; 32]))
            .unwrap(),
        &f.a,
        &f.b,
    );
    assert!(f
        .ledger
        .request_close(id, f.open.initial.clone(), 10)
        .is_err());
    f.ledger.request_close(id, first, 11).unwrap();
    assert!(f
        .ledger
        .finalize(id, 11 + CONTEST_BLOCKS, &f.miner.public_key)
        .is_err());
    f.ledger.challenge(id, newer, 11 + CONTEST_BLOCKS).unwrap();
    let payout = f
        .ledger
        .finalize(id, 12 + CONTEST_BLOCKS, &f.miner.public_key)
        .unwrap();
    assert_eq!(
        (payout.amount_a, payout.amount_b, payout.miner_fee),
        (Amount(70), Amount(30), Amount(1))
    );
    assert_eq!(f.ledger.escrow(id).unwrap().phase, Phase::Settled);
    assert!(f
        .ledger
        .finalize(id, 13 + CONTEST_BLOCKS, &f.miner.public_key)
        .is_err());
    assert_eq!(
        f.ledger
            .coins
            .values()
            .map(|c| c.output.amount.0)
            .sum::<u128>(),
        105
    );
    f.ledger.root().unwrap();
}

#[test]
fn invalid_openings_fail_without_consuming_or_creating_value() {
    let mut f = fixture();
    let original = f.ledger.root().unwrap();
    let mut wrong_sig = f.open.clone();
    wrong_sig.signature_a =
        sign_bytes(&f.b.secret_key, &wrong_sig.intent.signing_bytes().unwrap()).unwrap();
    assert!(f.ledger.open(wrong_sig, 10, &f.miner.public_key).is_err());
    let mut wrong_amount = f.open.clone();
    wrong_amount.intent.change = Amount(4);
    wrong_amount.signature_a = sign_bytes(
        &f.a.secret_key,
        &wrong_amount.intent.signing_bytes().unwrap(),
    )
    .unwrap();
    let altered_funding = wrong_amount.intent.funding().unwrap();
    wrong_amount.initial = signed(
        &altered_funding,
        ChannelState::initial(&altered_funding).unwrap(),
        &f.a,
        &f.b,
    );
    assert!(f
        .ledger
        .open(wrong_amount, 10, &f.miner.public_key)
        .is_err());
    assert!(f
        .ledger
        .open(f.open.clone(), 9, &f.miner.public_key)
        .is_err());
    assert!(f
        .ledger
        .open(f.open.clone(), 31, &f.miner.public_key)
        .is_err());
    assert_eq!(f.ledger.root().unwrap(), original);
    assert!(f.ledger.coin(&f.input).is_some());
    let _ = f
        .ledger
        .open(f.open.clone(), 10, &f.miner.public_key)
        .unwrap();
    let after = f.ledger.root().unwrap();
    assert!(f.ledger.open(f.open, 11, &f.miner.public_key).is_err());
    assert_eq!(f.ledger.root().unwrap(), after);
}

#[test]
fn stale_challenges_fail_and_replay_produces_one_state_root() {
    let mut f = fixture();
    let mut replay = f.ledger.clone();
    let id = f
        .ledger
        .open(f.open.clone(), 10, &f.miner.public_key)
        .unwrap();
    replay
        .open(f.open.clone(), 10, &f.miner.public_key)
        .unwrap();
    f.ledger
        .request_close(id, f.open.initial.clone(), 11)
        .unwrap();
    replay
        .request_close(id, f.open.initial.clone(), 11)
        .unwrap();
    let funding = &f.ledger.escrow(id).unwrap().funding;
    let latest = signed(
        funding,
        f.open
            .initial
            .state
            .propose_payment(funding, &f.a.public_key, Amount(9), Hash([5; 32]))
            .unwrap(),
        &f.a,
        &f.b,
    );
    f.ledger.challenge(id, latest.clone(), 12).unwrap();
    replay.challenge(id, latest.clone(), 12).unwrap();
    let before = f.ledger.root().unwrap();
    assert!(f.ledger.challenge(id, f.open.initial.clone(), 13).is_err());
    assert!(f.ledger.challenge(id, latest, 12 + CONTEST_BLOCKS).is_err());
    assert_eq!(f.ledger.root().unwrap(), before);
    assert_eq!(f.ledger.root().unwrap(), replay.root().unwrap());
}

#[test]
fn snapshot_root_must_match_before_successor_state_exists() {
    let f = fixture();
    let v1 = V1State {
        coins: f.ledger.coins.clone(),
        emitted: f.ledger.emitted,
    };
    assert!(
        Ledger::from_v1_snapshot(Hash([1; 32]), &v1, Hash([8; 32]), Hash([9; 32]), 9,).is_err()
    );
}

#[test]
fn contest_deadline_overflow_keeps_channel_open() {
    let mut f = fixture();
    let id = f
        .ledger
        .open(f.open.clone(), 10, &f.miner.public_key)
        .unwrap();
    let root = f.ledger.root().unwrap();
    assert!(f
        .ledger
        .request_close(id, f.open.initial, u128::MAX)
        .is_err());
    assert_eq!(f.ledger.root().unwrap(), root);
    assert_eq!(f.ledger.escrow(id).unwrap().phase, Phase::Open);
}
