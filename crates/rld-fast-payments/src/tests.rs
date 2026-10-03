use super::*;
use rld_core::{generate_identity, sign_bytes, Identity};

fn fixture() -> (Funding, Identity, Identity) {
    let a = generate_identity();
    let b = generate_identity();
    let funding = Funding {
        chain_id: Hash([1; 32]),
        outpoint: FundingOutpoint {
            transaction: Hash([2; 32]),
            index: 0,
        },
        party_a: a.public_key.clone(),
        party_b: b.public_key.clone(),
        capacity: Amount(101),
        close_fee: Amount(1),
    };
    (funding, a, b)
}

fn signed(funding: &Funding, state: ChannelState, a: &Identity, b: &Identity) -> SignedState {
    let message = state.signing_bytes(funding).unwrap();
    SignedState {
        state,
        signature_a: sign_bytes(&a.secret_key, &message).unwrap(),
        signature_b: sign_bytes(&b.secret_key, &message).unwrap(),
    }
}

struct FixtureEscrow {
    expected: Funding,
    confirmed: bool,
}

impl ConfirmedEscrow for FixtureEscrow {
    fn verify_confirmed_escrow(&self, funding: &Funding) -> Result<()> {
        require(
            self.confirmed && funding == &self.expected,
            "escrow is not confirmed",
        )
    }
}

#[test]
fn receipt_requires_exact_two_party_payment_and_invoice() {
    let (funding, a, b) = fixture();
    let initial = signed(&funding, ChannelState::initial(&funding).unwrap(), &a, &b);
    let invoice = Hash([3; 32]);
    let update = signed(
        &funding,
        initial
            .state
            .propose_payment(&funding, &a.public_key, Amount(20), invoice)
            .unwrap(),
        &a,
        &b,
    );
    let receipt = PaymentReceipt {
        previous: initial,
        updated: update,
        sender: a.public_key.clone(),
        amount: Amount(20),
        payment_id: invoice,
    };
    receipt.verify(&funding, &b.public_key).unwrap();
    assert_eq!(receipt.updated.state.balance_a, Amount(80));
    assert_eq!(receipt.updated.state.balance_b, Amount(20));

    let mut wrong = receipt.clone();
    wrong.amount = Amount(21);
    assert!(wrong.verify(&funding, &b.public_key).is_err());
    wrong = receipt.clone();
    wrong.payment_id = Hash([4; 32]);
    assert!(wrong.verify(&funding, &b.public_key).is_err());
    assert!(receipt.verify(&funding, &a.public_key).is_err());
    wrong = receipt.clone();
    wrong.updated.signature_b = receipt.previous.signature_b.clone();
    assert!(wrong.verify(&funding, &b.public_key).is_err());
}

#[test]
fn proposals_fail_closed_on_liquidity_sequence_and_network() {
    let (funding, a, b) = fixture();
    let initial = ChannelState::initial(&funding).unwrap();
    assert!(initial
        .propose_payment(&funding, &a.public_key, Amount(101), Hash([3; 32]))
        .is_err());
    assert!(initial
        .propose_payment(&funding, &b.public_key, Amount(1), Hash([3; 32]))
        .is_err());
    assert!(initial
        .propose_payment(&funding, &a.public_key, Amount::ZERO, Hash([3; 32]))
        .is_err());
    assert!(initial
        .propose_payment(&funding, &a.public_key, Amount(1), Hash::ZERO)
        .is_err());
    assert!(initial
        .propose_payment(
            &funding,
            &generate_identity().public_key,
            Amount(1),
            Hash([3; 32])
        )
        .is_err());
    let mut other = funding.clone();
    other.chain_id = Hash([9; 32]);
    assert!(initial.validate(&other).is_err());
    let mut exhausted = initial;
    exhausted.sequence = u64::MAX;
    exhausted.payment_id = Hash([8; 32]);
    assert!(exhausted
        .propose_payment(&funding, &a.public_key, Amount(1), Hash([3; 32]))
        .is_err());
}

#[test]
fn opening_requires_confirmed_escrow_and_prevents_double_lock() {
    let (funding, a, b) = fixture();
    let initial = signed(&funding, ChannelState::initial(&funding).unwrap(), &a, &b);
    let mut registry = Registry::default();
    let mut verifier = FixtureEscrow {
        expected: funding.clone(),
        confirmed: false,
    };
    assert!(registry
        .open(&verifier, funding.clone(), initial.clone())
        .is_err());
    verifier.confirmed = true;
    let id = registry
        .open(&verifier, funding.clone(), initial.clone())
        .unwrap();
    assert_eq!(registry.phase(id), Some(&Phase::Open));
    assert!(registry.open(&verifier, funding, initial).is_err());
}

#[test]
fn old_state_can_be_replaced_during_contest_and_settlement_conserves_value() {
    let (funding, a, b) = fixture();
    let initial = signed(&funding, ChannelState::initial(&funding).unwrap(), &a, &b);
    let first = signed(
        &funding,
        initial
            .state
            .propose_payment(&funding, &a.public_key, Amount(10), Hash([3; 32]))
            .unwrap(),
        &a,
        &b,
    );
    let latest = signed(
        &funding,
        first
            .state
            .propose_payment(&funding, &a.public_key, Amount(20), Hash([4; 32]))
            .unwrap(),
        &a,
        &b,
    );
    let verifier = FixtureEscrow {
        expected: funding.clone(),
        confirmed: true,
    };
    let mut registry = Registry::default();
    let id = registry.open(&verifier, funding, initial.clone()).unwrap();
    registry.request_close(id, first.clone(), 100).unwrap();
    assert!(registry.finalize(id, 100 + CONTEST_BLOCKS).is_err());
    assert!(registry.challenge(id, latest.clone(), 99).is_err());
    assert!(registry.challenge(id, initial, 101).is_err());
    registry
        .challenge(id, latest.clone(), 100 + CONTEST_BLOCKS)
        .unwrap();
    assert!(registry.challenge(id, first, 101).is_err());
    let payout = registry.finalize(id, 101 + CONTEST_BLOCKS).unwrap();
    assert_eq!(payout.amount_a, Amount(70));
    assert_eq!(payout.amount_b, Amount(30));
    assert_eq!(payout.miner_fee, Amount(1));
    assert_eq!(registry.phase(id), Some(&Phase::Settled));
    assert!(registry.finalize(id, 102 + CONTEST_BLOCKS).is_err());
    assert!(registry
        .challenge(id, latest, 102 + CONTEST_BLOCKS)
        .is_err());
}

#[test]
fn late_challenge_fails_and_both_parties_must_monitor_closure() {
    let (funding, a, b) = fixture();
    let initial = signed(&funding, ChannelState::initial(&funding).unwrap(), &a, &b);
    let newest = signed(
        &funding,
        initial
            .state
            .propose_payment(&funding, &a.public_key, Amount(30), Hash([3; 32]))
            .unwrap(),
        &a,
        &b,
    );
    let verifier = FixtureEscrow {
        expected: funding.clone(),
        confirmed: true,
    };
    let mut registry = Registry::default();
    let id = registry.open(&verifier, funding, initial.clone()).unwrap();
    registry.request_close(id, initial, 100).unwrap();
    assert!(registry
        .challenge(id, newest, 101 + CONTEST_BLOCKS)
        .is_err());
    // This payout is unsafe for the offline recipient. The model intentionally
    // exposes the real watchtower/chain-availability requirement.
    let payout = registry.finalize(id, 101 + CONTEST_BLOCKS).unwrap();
    assert_eq!(payout.amount_b, Amount::ZERO);
}

#[test]
fn malformed_funding_and_json_are_rejected() {
    let (mut funding, a, b) = fixture();
    funding.party_b = a.public_key.clone();
    assert!(funding.validate().is_err());
    funding.party_b = b.public_key;
    funding.close_fee = funding.capacity;
    assert!(funding.validate().is_err());
    let mut json = serde_json::to_value(&funding).unwrap();
    json["unknown"] = serde_json::json!(true);
    assert!(serde_json::from_value::<Funding>(json).is_err());
}

#[test]
fn recipient_rejects_conflicting_sequence_and_reused_invoice() {
    let (funding, a, b) = fixture();
    let initial = signed(&funding, ChannelState::initial(&funding).unwrap(), &a, &b);
    let mut tracker =
        RecipientTracker::new(funding.clone(), b.public_key.clone(), initial.clone()).unwrap();
    let invoice = Hash([3; 32]);
    let first = signed(
        &funding,
        initial
            .state
            .propose_payment(&funding, &a.public_key, Amount(10), invoice)
            .unwrap(),
        &a,
        &b,
    );
    let receipt = PaymentReceipt {
        previous: initial.clone(),
        updated: first.clone(),
        sender: a.public_key.clone(),
        amount: Amount(10),
        payment_id: invoice,
    };
    tracker.apply_receipt(receipt.clone()).unwrap();
    assert!(tracker.apply_receipt(receipt).is_err());
    let conflicting = PaymentReceipt {
        previous: initial,
        updated: signed(
            &funding,
            ChannelState {
                channel_id: funding.id().unwrap(),
                sequence: 1,
                payment_id: Hash([4; 32]),
                balance_a: Amount(80),
                balance_b: Amount(20),
            },
            &a,
            &b,
        ),
        sender: a.public_key.clone(),
        amount: Amount(20),
        payment_id: Hash([4; 32]),
    };
    assert!(tracker.apply_receipt(conflicting).is_err());
    assert_eq!(tracker.latest(), &first);
    let reused = PaymentReceipt {
        previous: first.clone(),
        updated: signed(
            &funding,
            first
                .state
                .propose_payment(&funding, &a.public_key, Amount(1), invoice)
                .unwrap(),
            &a,
            &b,
        ),
        sender: a.public_key,
        amount: Amount(1),
        payment_id: invoice,
    };
    assert!(tracker.apply_receipt(reused).is_err());
    assert_eq!(tracker.latest(), &first);
}

#[test]
fn offer_rejects_wrong_payer_signature_and_modified_allocation() {
    let (funding, a, b) = fixture();
    let initial = signed(&funding, ChannelState::initial(&funding).unwrap(), &a, &b);
    assert!(PaymentOffer::new(
        &funding,
        initial.clone(),
        a.public_key.clone(),
        &b.secret_key,
        Amount(1),
        Hash([3; 32]),
    )
    .is_err());
    let mut offer = PaymentOffer::new(
        &funding,
        initial,
        a.public_key,
        &a.secret_key,
        Amount(1),
        Hash([3; 32]),
    )
    .unwrap();
    offer.proposed.balance_b = Amount(2);
    assert!(offer.verify(&funding).is_err());
}
