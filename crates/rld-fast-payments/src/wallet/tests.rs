use super::*;
use rld_core::{generate_identity, sign_bytes, Identity as Keypair};

fn fixture() -> (Funding, Keypair, Keypair, SignedState) {
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
    let state = ChannelState::initial(&funding).unwrap();
    let bytes = state.signing_bytes(&funding).unwrap();
    let initial = SignedState {
        state,
        signature_a: sign_bytes(&a.secret_key, &bytes).unwrap(),
        signature_b: sign_bytes(&b.secret_key, &bytes).unwrap(),
    };
    (funding, a, b, initial)
}

fn receipt(
    funding: &Funding,
    a: &Keypair,
    b: &Keypair,
    previous: SignedState,
    amount: Amount,
    payment_id: Hash,
) -> PaymentReceipt {
    let state = previous
        .state
        .propose_payment(funding, &a.public_key, amount, payment_id)
        .unwrap();
    let bytes = state.signing_bytes(funding).unwrap();
    PaymentReceipt {
        previous,
        updated: SignedState {
            state,
            signature_a: sign_bytes(&a.secret_key, &bytes).unwrap(),
            signature_b: sign_bytes(&b.secret_key, &bytes).unwrap(),
        },
        sender: a.public_key.clone(),
        amount,
        payment_id,
    }
}

fn temp_dir() -> PathBuf {
    std::env::temp_dir().join(format!(
        "rld-fast-wallet-{}-{}",
        std::process::id(),
        generate_identity().public_key
    ))
}

#[test]
fn durable_receipt_replays_after_restart_and_keeps_exclusive_owner() {
    let root = temp_dir();
    let (funding, a, b, initial) = fixture();
    let mut store = RecipientStore::open(
        &root,
        funding.clone(),
        b.public_key.clone(),
        initial.clone(),
    )
    .unwrap();
    assert!(RecipientStore::open(
        &root,
        funding.clone(),
        b.public_key.clone(),
        initial.clone()
    )
    .is_err());
    let paid = receipt(&funding, &a, &b, initial.clone(), Amount(20), Hash([3; 32]));
    store.apply_receipt(paid.clone()).unwrap();
    assert_eq!(store.latest().state.balance_b, Amount(20));
    drop(store);

    let mut restored =
        RecipientStore::open(&root, funding.clone(), b.public_key.clone(), initial).unwrap();
    assert_eq!(restored.latest(), &paid.updated);
    assert!(restored.apply_receipt(paid.clone()).is_err());
    let next = receipt(&funding, &a, &b, paid.updated, Amount(5), Hash([4; 32]));
    restored.apply_receipt(next.clone()).unwrap();
    assert_eq!(restored.latest().state.balance_b, Amount(25));
    drop(restored);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn corrupt_or_wrong_channel_journal_fails_closed() {
    let root = temp_dir();
    let (funding, a, b, initial) = fixture();
    let mut store = RecipientStore::open(
        &root,
        funding.clone(),
        b.public_key.clone(),
        initial.clone(),
    )
    .unwrap();
    let paid = receipt(&funding, &a, &b, initial.clone(), Amount(1), Hash([3; 32]));
    store.apply_receipt(paid).unwrap();
    drop(store);
    let mut other = funding.clone();
    other.chain_id = Hash([9; 32]);
    assert!(RecipientStore::open(&root, other, b.public_key.clone(), initial.clone()).is_err());
    fs::write(root.join("receipts").join(receipt_name(1)), b"{}").unwrap();
    assert!(RecipientStore::open(&root, funding, b.public_key, initial).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn incomplete_pending_receipt_is_ignored_and_replaced() {
    let root = temp_dir();
    let (funding, a, b, initial) = fixture();
    let mut store = RecipientStore::open(
        &root,
        funding.clone(),
        b.public_key.clone(),
        initial.clone(),
    )
    .unwrap();
    fs::write(
        root.join("receipts").join("00000000000000000001.pending"),
        b"torn",
    )
    .unwrap();
    let paid = receipt(&funding, &a, &b, initial, Amount(2), Hash([3; 32]));
    store.apply_receipt(paid).unwrap();
    assert!(!root
        .join("receipts")
        .join("00000000000000000001.pending")
        .exists());
    drop(store);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn interrupted_initialization_with_only_pending_files_can_recover() {
    let root = temp_dir();
    fs::create_dir_all(root.join("receipts")).unwrap();
    fs::write(root.join("channel.pending"), b"torn").unwrap();
    fs::write(
        root.join("receipts").join("00000000000000000001.pending"),
        b"torn",
    )
    .unwrap();
    let (funding, _, b, initial) = fixture();
    let store = RecipientStore::open(&root, funding, b.public_key, initial).unwrap();
    assert_eq!(store.latest().state.sequence, 0);
    drop(store);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn signed_offer_is_persisted_before_reply_and_exact_retry_survives_restart() {
    let root = temp_dir();
    let (funding, a, b, initial) = fixture();
    let offer = PaymentOffer::new(
        &funding,
        initial.clone(),
        a.public_key.clone(),
        &a.secret_key,
        Amount(7),
        Hash([3; 32]),
    )
    .unwrap();
    let mut receiver = RecipientStore::open(
        &root,
        funding.clone(),
        b.public_key.clone(),
        initial.clone(),
    )
    .unwrap();
    assert!(receiver.accept_offer(offer.clone(), &a.secret_key).is_err());
    assert_eq!(receiver.latest(), &initial);
    let receipt = receiver.accept_offer(offer.clone(), &b.secret_key).unwrap();
    assert_eq!(receiver.latest().state.balance_b, Amount(7));
    assert_eq!(
        receiver.accept_offer(offer.clone(), &b.secret_key).unwrap(),
        receipt
    );
    drop(receiver);

    let mut restored = RecipientStore::open(&root, funding.clone(), b.public_key, initial).unwrap();
    assert_eq!(
        restored.accept_offer(offer.clone(), &b.secret_key).unwrap(),
        receipt
    );
    let mut conflicting = offer;
    conflicting.amount = Amount(8);
    assert!(restored.accept_offer(conflicting, &b.secret_key).is_err());
    drop(restored);
    fs::remove_dir_all(root).unwrap();
}
