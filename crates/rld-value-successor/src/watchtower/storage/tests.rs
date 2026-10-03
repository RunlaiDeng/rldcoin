use super::*;
use crate::{signed_state_hash, ActionFee, ActionFeeIntent, DisputeAction};
use rld_core::{generate_identity, sign_bytes, AdmissionHash32 as Hash, Amount, Identity};
use rld_fast_payments::{ChannelState, Funding, FundingOutpoint, SignedState};
use rld_pow::OutPoint;

fn package(funding: &Funding, a: &Identity, b: &Identity, state: ChannelState) -> WatchPackage {
    let bytes = state.signing_bytes(funding).unwrap();
    let state = SignedState {
        state,
        signature_a: sign_bytes(&a.secret_key, &bytes).unwrap(),
        signature_b: sign_bytes(&b.secret_key, &bytes).unwrap(),
    };
    let intent = ActionFeeIntent {
        chain_id: funding.chain_id,
        action: DisputeAction::Challenge,
        channel: funding.id().unwrap(),
        signed_state: signed_state_hash(&state).unwrap(),
        input: OutPoint {
            transaction: Hash([3; 32]),
            index: 0,
        },
        owner: b.public_key.clone(),
        fee: Amount(1),
        change: Amount(9),
        valid_through_height: 100,
    };
    WatchPackage {
        funding: funding.clone(),
        state,
        fee: ActionFee {
            owner_signature: sign_bytes(&b.secret_key, &intent.signing_bytes().unwrap()).unwrap(),
            intent,
        },
    }
}

#[test]
fn separate_watchtower_store_keeps_latest_after_restart_and_merchant_rollback() {
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
    let initial = ChannelState::initial(&funding).unwrap();
    let newer = initial
        .propose_payment(&funding, &a.public_key, Amount(7), Hash([4; 32]))
        .unwrap();
    let old = package(&funding, &a, &b, initial);
    let latest = package(&funding, &a, &b, newer);
    let root = std::env::temp_dir().join(format!(
        "rld-watchtower-state-{}",
        generate_identity().public_key
    ));
    let mut store = WatchStore::open(&root, Some(old.clone())).unwrap();
    assert!(WatchStore::open(&root, None).is_err());
    assert!(store.observe(latest.clone()).unwrap());
    assert!(!store.observe(latest.clone()).unwrap());
    drop(store);
    let mut store = WatchStore::open(&root, None).unwrap();
    assert_eq!(store.latest(), &latest);
    assert!(store.observe(old).is_err());
    let mut conflict = latest.clone();
    conflict.fee.intent.valid_through_height += 1;
    conflict.fee.owner_signature =
        sign_bytes(&b.secret_key, &conflict.fee.intent.signing_bytes().unwrap()).unwrap();
    assert!(store.observe(conflict).is_err());
    assert_eq!(store.latest(), &latest);
    drop(store);
    let mut other_funding = funding;
    other_funding.outpoint.transaction = Hash([8; 32]);
    let other = package(
        &other_funding,
        &a,
        &b,
        ChannelState::initial(&other_funding).unwrap(),
    );
    assert!(WatchStore::open(&root, Some(other)).is_err());
    let file = root.join("latest.json");
    let correct = fs::read(&file).unwrap();
    fs::write(&file, b"{}").unwrap();
    assert!(WatchStore::open(&root, None).is_err());
    fs::write(&file, correct).unwrap();
    fs::remove_dir_all(root).unwrap();
}
