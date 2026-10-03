use super::*;
use rld_core::{generate_identity, sign_bytes, AdmissionHash32 as Hash, Identity};
use rld_fast_payments::{ChannelState, FundingOutpoint};

fn fixture() -> (Funding, Identity, Identity, SignedState) {
    let payer = generate_identity();
    let receiver = generate_identity();
    let funding = Funding {
        chain_id: Hash([1; 32]),
        outpoint: FundingOutpoint {
            transaction: Hash([2; 32]),
            index: 0,
        },
        party_a: payer.public_key.clone(),
        party_b: receiver.public_key.clone(),
        capacity: Amount(101),
        close_fee: Amount(1),
    };
    let state = ChannelState::initial(&funding).unwrap();
    let bytes = state.signing_bytes(&funding).unwrap();
    let initial = SignedState {
        state,
        signature_a: sign_bytes(&payer.secret_key, &bytes).unwrap(),
        signature_b: sign_bytes(&receiver.secret_key, &bytes).unwrap(),
    };
    (funding, payer, receiver, initial)
}

fn fee_funding() -> FeeFunding {
    FeeFunding {
        input: OutPoint {
            transaction: Hash([3; 32]),
            index: 0,
        },
        input_amount: Amount(10),
        fee: Amount(1),
        valid_through_height: 10_000,
    }
}

fn fee_for(funding: &Funding, state: &SignedState, receiver: &Identity) -> ActionFee {
    let source = fee_funding();
    let intent = ActionFeeIntent {
        chain_id: funding.chain_id,
        action: DisputeAction::Challenge,
        channel: funding.id().unwrap(),
        signed_state: signed_state_hash(state).unwrap(),
        input: source.input,
        owner: receiver.public_key.clone(),
        fee: source.fee,
        change: source.input_amount.checked_sub(source.fee).unwrap(),
        valid_through_height: source.valid_through_height,
    };
    ActionFee {
        owner_signature: sign_bytes(&receiver.secret_key, &intent.signing_bytes().unwrap())
            .unwrap(),
        intent,
    }
}

fn root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "rld-guarded-wallet-{}",
        generate_identity().public_key
    ))
}

#[test]
fn receipt_return_requires_durable_matching_watch_package_and_exact_retry() {
    let root = root();
    let (funding, payer, receiver, initial) = fixture();
    let mut guard = GuardedRecipient::open(
        &root,
        funding.clone(),
        receiver.public_key.clone(),
        initial.clone(),
        Some(fee_for(&funding, &initial, &receiver)),
    )
    .unwrap();
    assert!(GuardedRecipient::open(
        &root,
        funding.clone(),
        receiver.public_key.clone(),
        initial.clone(),
        None,
    )
    .is_err());
    let offer = PaymentOffer::new(
        &funding,
        initial.clone(),
        payer.public_key.clone(),
        &payer.secret_key,
        Amount(7),
        Hash([4; 32]),
    )
    .unwrap();
    assert!(guard
        .accept_offer_unchecked(offer.clone(), &payer.secret_key, fee_funding())
        .is_err());
    assert_eq!(guard.latest(), &initial);
    let receipt = guard
        .accept_offer_unchecked(offer.clone(), &receiver.secret_key, fee_funding())
        .unwrap();
    assert_eq!(guard.watch_package().state, receipt.updated);
    let bytes = fs::read(root.join("watch-package.json")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(root.join("watch-package.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
    }
    let published: WatchPackage = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(published.state, receipt.updated);
    published.validate().unwrap();
    drop(guard);
    let mut restored = GuardedRecipient::open(
        &root,
        funding.clone(),
        receiver.public_key.clone(),
        initial,
        None,
    )
    .unwrap();
    assert_eq!(
        restored
            .accept_offer_unchecked(offer.clone(), &receiver.secret_key, fee_funding())
            .unwrap(),
        receipt
    );
    assert_eq!(restored.watch_package().state, receipt.updated);
    let mut altered = offer;
    altered.amount = Amount(8);
    assert!(restored
        .accept_offer_unchecked(altered, &receiver.secret_key, fee_funding())
        .is_err());
    drop(restored);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn interrupted_publication_recovers_only_by_replaying_same_offer() {
    let root = root();
    let (funding, payer, receiver, initial) = fixture();
    let guard = GuardedRecipient::open(
        &root,
        funding.clone(),
        receiver.public_key.clone(),
        initial.clone(),
        Some(fee_for(&funding, &initial, &receiver)),
    )
    .unwrap();
    drop(guard);
    let offer = PaymentOffer::new(
        &funding,
        initial.clone(),
        payer.public_key.clone(),
        &payer.secret_key,
        Amount(7),
        Hash([4; 32]),
    )
    .unwrap();
    // Simulate a crash after the underlying receipt journal was fsynced but
    // before the guarded wrapper published the matching watch package.
    let mut recipient = RecipientStore::open(
        &root.join("recipient"),
        funding.clone(),
        receiver.public_key.clone(),
        initial.clone(),
    )
    .unwrap();
    let receipt = recipient
        .accept_offer(offer.clone(), &receiver.secret_key)
        .unwrap();
    drop(recipient);
    let mut guard = GuardedRecipient::open(
        &root,
        funding.clone(),
        receiver.public_key.clone(),
        initial,
        None,
    )
    .unwrap();
    let second = PaymentOffer::new(
        &funding,
        receipt.updated.clone(),
        payer.public_key.clone(),
        &payer.secret_key,
        Amount(1),
        Hash([5; 32]),
    )
    .unwrap();
    assert!(guard
        .accept_offer_unchecked(second, &receiver.secret_key, fee_funding())
        .is_err());
    assert_eq!(
        guard
            .accept_offer_unchecked(offer, &receiver.secret_key, fee_funding())
            .unwrap(),
        receipt
    );
    assert_eq!(guard.watch_package().state, receipt.updated);
    drop(guard);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn tampered_watch_package_fails_closed_on_reopen() {
    let root = root();
    let (funding, payer, receiver, initial) = fixture();
    let guard = GuardedRecipient::open(
        &root,
        funding.clone(),
        receiver.public_key.clone(),
        initial.clone(),
        Some(fee_for(&funding, &initial, &receiver)),
    )
    .unwrap();
    drop(guard);
    let original = fs::read(root.join("watch-package.json")).unwrap();
    let mut bad: WatchPackage = serde_json::from_slice(&original).unwrap();
    bad.fee.owner_signature = "00".into();
    fs::write(
        root.join("watch-package.json"),
        serde_json::to_vec(&bad).unwrap(),
    )
    .unwrap();
    assert!(GuardedRecipient::open(
        &root,
        funding.clone(),
        receiver.public_key.clone(),
        initial.clone(),
        None,
    )
    .is_err());
    fs::write(root.join("watch-package.json"), original).unwrap();
    let mut guard = GuardedRecipient::open(
        &root,
        funding.clone(),
        receiver.public_key.clone(),
        initial.clone(),
        None,
    )
    .unwrap();
    let offer = PaymentOffer::new(
        &funding,
        initial.clone(),
        payer.public_key.clone(),
        &payer.secret_key,
        Amount(3),
        Hash([6; 32]),
    )
    .unwrap();
    guard
        .accept_offer_unchecked(offer, &receiver.secret_key, fee_funding())
        .unwrap();
    drop(guard);
    fs::write(root.join("watch-package.json"), b"{}").unwrap();
    assert!(GuardedRecipient::open(&root, funding, receiver.public_key, initial, None,).is_err());
    fs::remove_dir_all(root).unwrap();
}
