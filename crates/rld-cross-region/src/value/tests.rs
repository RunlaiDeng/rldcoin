use super::*;
use rld_core::{generate_identity, sign_bytes, Identity};

#[test]
fn source_export_starts_from_replayed_pow_reward_without_caller_supplied_root() {
    use rld_pow::{mine_batch, target_limit, Chain, Context};
    let sender = generate_identity();
    let recipient = generate_identity();
    let miner = generate_identity();
    let mut chain = Chain::new(Context {
        network_domain: "fixture:export-anchor".into(),
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
            .template(sender.public_key.clone(), time, vec![])
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
    let amount = Amount::from_rld_whole(1).unwrap();
    let fee = Amount(1);
    let change = coin
        .output
        .amount
        .checked_sub(amount.checked_add(fee).unwrap())
        .unwrap();
    let source_chain_id = chain.context.chain_id().unwrap();
    let intent = ExportIntent {
        source_chain_id,
        destination_chain_id: Hash([9; 32]),
        input: input.clone(),
        owner: sender.public_key.clone(),
        recipient: recipient.public_key,
        amount,
        source_fee: fee,
        destination_fee: fee,
        change,
        valid_through_height: chain.height() + 100,
    };
    let command = ExportCommand {
        owner_signature: sign_bytes(&sender.secret_key, &intent.signing_bytes().unwrap()).unwrap(),
        intent,
    };
    let mut source = SourceLedger::from_replayed_pow_chain(&chain).unwrap();
    let record = source
        .export(command, chain.height() + 1, &miner.public_key)
        .unwrap();
    let proof = source.membership_proof(record.id().unwrap()).unwrap();
    assert_eq!(
        proof
            .verify_in_claimed_state(source.root().unwrap())
            .unwrap(),
        record
    );
    assert_eq!(source.retired().unwrap(), amount);
}

struct Fixture {
    source: SourceLedger,
    destination: DestinationLedger,
    command: ExportCommand,
    input: OutPoint,
    sender: Identity,
    receiver: Identity,
    miner: Identity,
}

fn fixture() -> Fixture {
    let sender = generate_identity();
    let receiver = generate_identity();
    let miner = generate_identity();
    let input = OutPoint {
        transaction: Hash([3; 32]),
        index: 0,
    };
    let source_v1 = V1State {
        coins: BTreeMap::from([(
            input.clone(),
            Coin {
                output: Output {
                    owner: sender.public_key.clone(),
                    amount: Amount(105),
                },
                spendable_height: 10,
            },
        )]),
        emitted: Amount(105),
    };
    let destination_v1 = V1State::default();
    let source = SourceLedger::from_v1_snapshot(
        Hash([1; 32]),
        &source_v1,
        Hash([4; 32]),
        source_v1.root().unwrap(),
        9,
    )
    .unwrap();
    let destination = DestinationLedger::from_v1_snapshot(
        Hash([2; 32]),
        &destination_v1,
        Hash([5; 32]),
        destination_v1.root().unwrap(),
        9,
    )
    .unwrap();
    let intent = ExportIntent {
        source_chain_id: Hash([1; 32]),
        destination_chain_id: Hash([2; 32]),
        input: input.clone(),
        owner: sender.public_key.clone(),
        recipient: receiver.public_key.clone(),
        amount: Amount(100),
        source_fee: Amount(1),
        destination_fee: Amount(2),
        change: Amount(4),
        valid_through_height: 30,
    };
    let command = ExportCommand {
        owner_signature: sign_bytes(&sender.secret_key, &intent.signing_bytes().unwrap()).unwrap(),
        intent,
    };
    Fixture {
        source,
        destination,
        command,
        input,
        sender,
        receiver,
        miner,
    }
}

fn simulated_certificate(
    source: &SourceLedger,
    record: ExportRecord,
) -> (ProofBundle, CertifiedExport) {
    let proof = source.membership_proof(record.id().unwrap()).unwrap();
    let payload = serde_json::to_vec(&proof).unwrap();
    let bundle = ProofBundle::from_proof(
        record.command.intent.source_chain_id,
        record.command.intent.destination_chain_id,
        record.id().unwrap(),
        Hash([9; 32]),
        20,
        &payload,
    )
    .unwrap();
    let certificate = CertifiedExport::from_membership(
        &proof,
        source.root().unwrap(),
        Hash([9; 32]),
        20,
        bundle.proof_sha256,
    )
    .unwrap();
    assert_eq!(certificate.record, record);
    (bundle, certificate)
}

#[test]
fn irreversible_export_and_single_import_conserve_combined_liquid_value() {
    let mut f = fixture();
    let record = f
        .source
        .export(f.command.clone(), 10, &f.miner.public_key)
        .unwrap();
    assert!(f.source.coin(&f.input).is_none());
    assert_eq!(f.source.retired().unwrap(), Amount(100));
    assert_eq!(f.source.liquid().unwrap(), Amount(5));
    let (bundle, certificate) = simulated_certificate(&f.source, record.clone());
    assert_eq!(f.destination.imported_total, Amount::ZERO);
    // This private test certificate is supplied by the fixture, not by PoW
    // proof verification. No production caller can invoke this import path.
    f.destination
        .import_certified(&bundle, certificate.clone(), 21, &f.miner.public_key)
        .unwrap();
    assert_eq!(f.destination.imported_total, Amount(100));
    let recipient: u128 = f
        .destination
        .coins
        .values()
        .filter(|coin| coin.output.owner == f.receiver.public_key)
        .map(|coin| coin.output.amount.0)
        .sum();
    assert_eq!(recipient, 98);
    let dest_liquid: u128 = f
        .destination
        .coins
        .values()
        .map(|coin| coin.output.amount.0)
        .sum();
    assert_eq!(f.source.liquid().unwrap().0 + dest_liquid, 105);
    let root = f.destination.root().unwrap();
    assert!(f
        .destination
        .import_certified(&bundle, certificate, 22, &f.miner.public_key)
        .is_err());
    assert_eq!(f.destination.root().unwrap(), root);
    assert!(f.source.export(f.command, 11, &f.miner.public_key).is_err());
    assert_eq!(f.source.export_record(record.id().unwrap()), Some(&record));
}

#[test]
fn forged_or_inconsistent_export_claim_cannot_change_destination_state() {
    let mut f = fixture();
    let record = f.source.export(f.command, 10, &f.miner.public_key).unwrap();
    let (bundle, certificate) = simulated_certificate(&f.source, record);
    let root = f.destination.root().unwrap();
    let mut forged_bundle = bundle.clone();
    forged_bundle.destination_chain_id = Hash([6; 32]);
    assert!(f
        .destination
        .import_certified(&forged_bundle, certificate.clone(), 21, &f.miner.public_key)
        .is_err());
    let mut forged_certificate = certificate.clone();
    forged_certificate.proof_sha256 = Hash([7; 32]);
    assert!(f
        .destination
        .import_certified(&bundle, forged_certificate, 21, &f.miner.public_key)
        .is_err());
    forged_certificate = certificate.clone();
    forged_certificate.record.command.intent.amount = Amount(101);
    assert!(f
        .destination
        .import_certified(&bundle, forged_certificate, 21, &f.miner.public_key)
        .is_err());
    let membership: ExportMembershipProof =
        serde_json::from_slice(&bundle.proof().unwrap()).unwrap();
    let padded = serde_json::to_vec_pretty(&membership).unwrap();
    let noncanonical = ProofBundle::from_proof(
        bundle.source_chain_id,
        bundle.destination_chain_id,
        bundle.export_id,
        bundle.source_checkpoint,
        bundle.source_height,
        &padded,
    )
    .unwrap();
    forged_certificate = certificate.clone();
    forged_certificate.proof_sha256 = noncanonical.proof_sha256;
    assert!(f
        .destination
        .import_certified(&noncanonical, forged_certificate, 21, &f.miner.public_key,)
        .is_err());
    forged_certificate = certificate;
    forged_certificate.checkpoint_height = 9;
    assert!(f
        .destination
        .import_certified(&bundle, forged_certificate, 21, &f.miner.public_key)
        .is_err());
    assert_eq!(f.destination.root().unwrap(), root);
    assert_eq!(f.destination.imported_total, Amount::ZERO);
}

#[test]
fn invalid_source_export_is_atomic_and_does_not_create_a_proof() {
    let mut f = fixture();
    let root = f.source.root().unwrap();
    let mut bad = f.command.clone();
    bad.owner_signature =
        sign_bytes(&f.miner.secret_key, &bad.intent.signing_bytes().unwrap()).unwrap();
    assert!(f.source.export(bad, 10, &f.miner.public_key).is_err());
    let mut bad = f.command.clone();
    bad.intent.change = Amount(5);
    bad.owner_signature =
        sign_bytes(&f.sender.secret_key, &bad.intent.signing_bytes().unwrap()).unwrap();
    assert!(f.source.export(bad, 10, &f.miner.public_key).is_err());
    assert!(f
        .source
        .export(f.command.clone(), 9, &f.miner.public_key)
        .is_err());
    assert!(f.source.export(f.command, 31, &f.miner.public_key).is_err());
    assert_eq!(f.source.root().unwrap(), root);
    assert!(f.source.coin(&f.input).is_some());
    assert_eq!(f.source.retired().unwrap(), Amount::ZERO);
}

#[test]
fn destination_cannot_start_with_a_second_native_issuance_reserve() {
    let f = fixture();
    let duplicate = V1State {
        coins: f.source.coins.clone(),
        emitted: f.source.native_emitted,
    };
    assert!(DestinationLedger::from_v1_snapshot(
        Hash([2; 32]),
        &duplicate,
        Hash([5; 32]),
        duplicate.root().unwrap(),
        9,
    )
    .is_err());
}

#[test]
fn export_membership_proofs_bind_sorted_records_and_state_root() {
    let f = fixture();
    let mut coins = BTreeMap::new();
    for marker in 11..=13 {
        coins.insert(
            OutPoint {
                transaction: Hash([marker; 32]),
                index: 0,
            },
            Coin {
                output: Output {
                    owner: f.sender.public_key.clone(),
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
    let mut source =
        SourceLedger::from_v1_snapshot(Hash([1; 32]), &v1, Hash([4; 32]), v1.root().unwrap(), 9)
            .unwrap();
    let mut ids = Vec::new();
    for marker in 11..=13 {
        let mut command = f.command.clone();
        command.intent.input = OutPoint {
            transaction: Hash([marker; 32]),
            index: 0,
        };
        command.owner_signature = sign_bytes(
            &f.sender.secret_key,
            &command.intent.signing_bytes().unwrap(),
        )
        .unwrap();
        ids.push(
            source
                .export(command, 10, &f.miner.public_key)
                .unwrap()
                .id()
                .unwrap(),
        );
    }
    let root = source.root().unwrap();
    assert_eq!(source.commitment().unwrap().export_count, 3);
    for id in &ids {
        let proof = source.membership_proof(*id).unwrap();
        assert_eq!(
            proof.verify_in_claimed_state(root).unwrap().id().unwrap(),
            *id
        );
        let encoded = serde_json::to_vec(&proof).unwrap();
        let bundle = ProofBundle::from_proof(
            Hash([1; 32]),
            Hash([2; 32]),
            *id,
            Hash([9; 32]),
            20,
            &encoded,
        )
        .unwrap();
        let delivered: ExportMembershipProof =
            serde_json::from_slice(&bundle.proof().unwrap()).unwrap();
        delivered.verify_in_claimed_state(root).unwrap();
        assert!(delivered.verify_in_claimed_state(Hash([7; 32])).is_err());
    }
    let last_id = *source.exports.keys().nth(2).unwrap();
    let mut odd = source.membership_proof(last_id).unwrap();
    assert_eq!(odd.siblings[0], export_leaf(last_id, &odd.record).unwrap());
    odd.siblings[0] = Hash([8; 32]);
    assert!(odd.verify_in_claimed_state(root).is_err());
    let mut wrong_record = source.membership_proof(ids[1]).unwrap();
    wrong_record.record.command.intent.amount = Amount(99);
    assert!(wrong_record.verify_in_claimed_state(root).is_err());
    let mut wrong_shape = source.membership_proof(ids[0]).unwrap();
    wrong_shape.leaf_index = 3;
    assert!(wrong_shape.verify_in_claimed_state(root).is_err());
    wrong_shape = source.membership_proof(ids[0]).unwrap();
    wrong_shape.siblings.pop();
    assert!(wrong_shape.verify_in_claimed_state(root).is_err());
}

#[test]
fn a_competing_source_history_does_not_authenticate_the_old_export() {
    let f = fixture();
    let mut first = f.source.clone();
    let mut competing = f.source;
    let first_record = first
        .export(f.command.clone(), 10, &f.miner.public_key)
        .unwrap();
    let proof = first.membership_proof(first_record.id().unwrap()).unwrap();

    let mut other_command = f.command;
    other_command.intent.recipient = f.miner.public_key.clone();
    other_command.owner_signature = sign_bytes(
        &f.sender.secret_key,
        &other_command.intent.signing_bytes().unwrap(),
    )
    .unwrap();
    competing
        .export(other_command, 10, &f.miner.public_key)
        .unwrap();

    assert_ne!(first.root().unwrap(), competing.root().unwrap());
    proof
        .verify_in_claimed_state(first.root().unwrap())
        .unwrap();
    assert!(proof
        .verify_in_claimed_state(competing.root().unwrap())
        .is_err());
}
