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

fn temp_dir(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "rld-payer-{label}-{}-{}",
        std::process::id(),
        generate_identity().public_key
    ))
}

#[test]
fn two_wallet_handshake_is_durable_and_retry_safe() {
    let payer_dir = temp_dir("payer");
    let receiver_dir = temp_dir("receiver");
    let (funding, a, b, initial) = fixture();
    let mut payer = PayerStore::open(
        &payer_dir,
        funding.clone(),
        a.public_key.clone(),
        initial.clone(),
    )
    .unwrap();
    let mut receiver = RecipientStore::open(
        &receiver_dir,
        funding.clone(),
        b.public_key.clone(),
        initial.clone(),
    )
    .unwrap();
    let offer = payer
        .begin_payment(&a.secret_key, Amount(10), Hash([3; 32]))
        .unwrap();
    let receipt = receiver.accept_offer(offer.clone(), &b.secret_key).unwrap();
    assert_eq!(
        receiver.accept_offer(offer, &b.secret_key).unwrap(),
        receipt
    );
    assert!(payer.complete_payment(receipt.clone()).unwrap());
    assert!(!payer.complete_payment(receipt.clone()).unwrap());
    assert_eq!(payer.latest(), receiver.latest());
    assert_eq!(payer.latest().state.balance_b, Amount(10));
    drop(payer);
    drop(receiver);

    let mut payer = PayerStore::open(
        &payer_dir,
        funding.clone(),
        a.public_key.clone(),
        initial.clone(),
    )
    .unwrap();
    let mut receiver = RecipientStore::open(&receiver_dir, funding, b.public_key, initial).unwrap();
    assert!(payer.pending().is_none());
    assert_eq!(payer.latest(), receiver.latest());
    let offer = payer
        .begin_payment(&a.secret_key, Amount(5), Hash([4; 32]))
        .unwrap();
    let receipt = receiver.accept_offer(offer, &b.secret_key).unwrap();
    assert!(payer.complete_payment(receipt).unwrap());
    assert_eq!(payer.latest().state.balance_b, Amount(15));
    drop(payer);
    drop(receiver);
    fs::remove_dir_all(payer_dir).unwrap();
    fs::remove_dir_all(receiver_dir).unwrap();
}

#[test]
fn lost_reply_keeps_one_pending_offer_across_restart() {
    let root = temp_dir("pending");
    let (funding, a, b, initial) = fixture();
    let mut payer = PayerStore::open(
        &root,
        funding.clone(),
        a.public_key.clone(),
        initial.clone(),
    )
    .unwrap();
    let offer = payer
        .begin_payment(&a.secret_key, Amount(3), Hash([3; 32]))
        .unwrap();
    assert!(payer
        .begin_payment(&a.secret_key, Amount(4), Hash([4; 32]))
        .is_err());
    assert_eq!(payer.latest(), &initial);
    drop(payer);
    let mut restored =
        PayerStore::open(&root, funding.clone(), a.public_key.clone(), initial).unwrap();
    assert_eq!(restored.pending(), Some(&offer));
    assert_eq!(
        restored
            .begin_payment(&a.secret_key, Amount(3), Hash([3; 32]))
            .unwrap(),
        offer
    );
    let mut forged = offer.cosign(&funding, &b.secret_key).unwrap();
    forged.updated.signature_b = "00".repeat(64);
    assert!(restored.complete_payment(forged).is_err());
    assert_eq!(restored.pending(), Some(&offer));
    drop(restored);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn restart_finishes_receipt_written_before_pending_offer_cleanup() {
    let root = temp_dir("partial-complete");
    let (funding, a, b, initial) = fixture();
    let mut payer = PayerStore::open(
        &root,
        funding.clone(),
        a.public_key.clone(),
        initial.clone(),
    )
    .unwrap();
    let offer = payer
        .begin_payment(&a.secret_key, Amount(2), Hash([3; 32]))
        .unwrap();
    let receipt = offer.cosign(&funding, &b.secret_key).unwrap();
    let bytes = serde_json::to_vec(&receipt).unwrap();
    atomic_write(&root.join("receipts").join(receipt_name(1)), &bytes).unwrap();
    drop(payer);
    let restored = PayerStore::open(&root, funding, a.public_key, initial).unwrap();
    assert!(restored.pending().is_none());
    assert_eq!(restored.latest(), &receipt.updated);
    assert!(!root.join("offer.json").exists());
    drop(restored);
    fs::remove_dir_all(root).unwrap();
}
