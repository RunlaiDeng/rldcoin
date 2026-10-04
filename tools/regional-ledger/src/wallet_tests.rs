use super::*;
use crate::wallet::{self, Draft, ReceiptExpectation, Request};
use std::fs;

fn request(owner: u8, amount: u128) -> Request {
    Request {
        owner: public(owner),
        participants: vec![],
        inputs: None,
        outputs: vec![Payment {
            owner: public(14),
            amount: Amount(amount),
        }],
        remote: None,
        fee: Amount(1),
        valid_for_blocks: 8,
        valid_through: None,
    }
}
fn key(root: &std::path::Path, seed: u8) -> PathBuf {
    let path = root.join(format!("key-{seed}.json"));
    fs::write(
        &path,
        serde_json::to_vec(&serde_json::json!({"secret_key":hex::encode([seed;32])})).unwrap(),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}
fn sign(store: &Store, draft: Draft, key: &std::path::Path) -> Result<Command> {
    let review = id("wallet-reviewed-draft", &draft)?;
    wallet::sign(store, draft, key, review)
}
fn step(store: &mut Store, commands: Vec<Command>) {
    let mut block = store.template(commands, public(10)).unwrap();
    mine(&mut block).unwrap();
    store.accept(block).unwrap();
}
fn expectation(f: &Fixture, export: Hash) -> ReceiptExpectation {
    ReceiptExpectation {
        currency: f.trust.currency().unwrap(),
        source: f.earth.region,
        destination: f.proxima.region,
        export,
        recipient: public(11),
        net_amount: Amount(78),
    }
}

#[test]
fn fresh_review_signs_real_payment_without_mutating_or_leaking_keys() {
    let f = Fixture::new();
    let (root, mut store) = stored_fixture(&f, &f.earth);
    let before = wallet::Pin::current(&store).unwrap();
    let view = wallet::view(&store, &public(10)).unwrap();
    assert_eq!(view.spendable, Amount(200));
    assert_eq!(view.immature, Amount(100));
    assert!(!view.local_observation_is_external_rollback_anchor);
    let draft = wallet::prepare(&store, request(10, 150)).unwrap();
    assert_eq!(draft.selected_input_total, Amount(200));
    assert_eq!(draft.change, Amount(49));
    let command = sign(&store, draft, &key(&root, 10)).unwrap();
    let encoded = serde_json::to_string(&command).unwrap();
    assert!(!encoded.contains(&hex::encode([10; 32])));
    assert_eq!(wallet::Pin::current(&store).unwrap(), before);
    step(&mut store, vec![command]);
    assert_eq!(
        wallet::view(&store, &public(14)).unwrap().spendable,
        Amount(150)
    );
    assert_eq!(store.chain.ledger.minted, Amount(300));
    drop(store);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn changed_review_intent_or_domain_never_returns_a_signature() {
    let f = Fixture::new();
    let (root, store) = stored_fixture(&f, &f.earth);
    let draft = wallet::prepare(&store, request(10, 30)).unwrap();
    let file = key(&root, 10);
    assert!(wallet::sign(&store, draft.clone(), &file, Hash([9; 32])).is_err());
    let mut bad = draft.clone();
    bad.intent.outputs[0].owner = public(13);
    assert!(sign(&store, bad, &file).is_err());
    let mut bad = draft.clone();
    bad.intent.currency = Hash([8; 32]);
    assert!(sign(&store, bad, &file).is_err());
    let mut bad = draft;
    bad.pin.region = f.proxima.region;
    assert!(sign(&store, bad, &file).is_err());
    assert!(sign(
        &store,
        wallet::prepare(&store, request(10, 30)).unwrap(),
        &key(&root, 11)
    )
    .is_err());
    drop(store);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn stale_draft_is_rejected_after_progress_and_restart() {
    let f = Fixture::new();
    let (root, mut store) = stored_fixture(&f, &f.earth);
    let draft = wallet::prepare(&store, request(10, 30)).unwrap();
    let file = key(&root, 10);
    step(&mut store, vec![]);
    let pin = store.trust.currency().unwrap();
    drop(store);
    let store = Store::open(&root, &public(1), pin).unwrap();
    assert!(sign(&store, draft, &file)
        .unwrap_err()
        .contains("state changed"));
    assert!(sign(
        &store,
        wallet::prepare(&store, request(10, 30)).unwrap(),
        &file
    )
    .is_ok());
    drop(store);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn immature_foreign_or_unfinalized_inputs_are_not_signed() {
    let mut f = Fixture::new();
    f.imported();
    let (root, mut store) = stored_fixture(&f, &f.proxima);
    assert!(wallet::prepare(&store, request(11, 30)).is_err());
    step(&mut store, vec![]);
    step(&mut store, vec![]);
    let mut remote = request(11, 30);
    remote.outputs.clear();
    remote.remote = Some(wallet::Remote {
        destination: f.andromeda.region,
        recipient: Payment {
            owner: public(14),
            amount: Amount(30),
        },
        destination_fee: Amount(1),
    });
    assert!(wallet::prepare(&store, remote.clone()).is_err());
    let mut snapshot = store.snapshot_request().unwrap();
    snapshot.approvals = f
        .trust
        .region(f.proxima.region)
        .unwrap()
        .validators
        .iter()
        .map(|k| {
            let seed = keys().into_iter().find(|s| public(*s) == *k).unwrap();
            Approval {
                key: k.clone(),
                signature: signature(seed, &snapshot.statement.bytes().unwrap()),
            }
        })
        .collect();
    store.finalize(snapshot).unwrap();
    assert!(sign(
        &store,
        wallet::prepare(&store, remote.clone()).unwrap(),
        &key(&root, 11)
    )
    .is_ok());
    remote.inputs = Some(vec![Hash([7; 32])]);
    assert!(wallet::prepare(&store, remote).is_err());
    drop(store);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn incident_knowledge_invalidates_review_and_quarantines_wallet_funds() {
    let mut f = Fixture::new();
    f.imported();
    for _ in 0..2 {
        advance(&mut f.proxima, &f.trust, &f.evidence, vec![]);
    }
    let (root, mut store) = stored_fixture(&f, &f.proxima);
    let draft = wallet::prepare(&store, request(11, 30)).unwrap();
    let file = key(&root, 11);
    let tip = store.chain.tip().unwrap();
    store.observe_conflict(conflict_proof(&f)).unwrap();
    assert_eq!(store.chain.tip().unwrap(), tip);
    assert!(sign(&store, draft, &file)
        .unwrap_err()
        .contains("state changed"));
    let view = wallet::view(&store, &public(11)).unwrap();
    assert_eq!(view.spendable, Amount::ZERO);
    assert_eq!(view.quarantined, Amount(78));
    assert!(wallet::prepare(&store, request(11, 30)).is_err());
    drop(store);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn recipient_checks_import_maturity_spent_output_and_exact_expectation() {
    let mut f = Fixture::new();
    let (_, export) = f.imported();
    let (root, mut store) = stored_fixture(&f, &f.proxima);
    let expected = expectation(&f, export);
    let receipt = wallet::receipt(&store, expected.clone()).unwrap();
    assert_eq!(receipt.state, "IMPORT_ACCEPTED_IMMATURE");
    assert!(!receipt.original_output_spendable_now);
    assert!(!receipt.transport_receipt_checked);
    assert!(!receipt.remote_current_state_known);
    for field in 0..6 {
        let mut wrong = expected.clone();
        match field {
            0 => wrong.currency = Hash([9; 32]),
            1 => wrong.source = f.andromeda.region,
            2 => wrong.destination = f.earth.region,
            3 => wrong.export = Hash([8; 32]),
            4 => wrong.recipient = public(14),
            _ => wrong.net_amount = Amount(80),
        }
        assert!(wallet::receipt(&store, wrong).is_err());
    }
    step(&mut store, vec![]);
    step(&mut store, vec![]);
    let receipt = wallet::receipt(&store, expected.clone()).unwrap();
    assert_eq!(receipt.state, "ORIGINAL_OUTPUT_SPENDABLE");
    assert!(receipt.original_output_spendable_now);
    assert!(!receipt.local_finality_covers_import);
    let command = sign(
        &store,
        wallet::prepare(&store, request(11, 30)).unwrap(),
        &key(&root, 11),
    )
    .unwrap();
    step(&mut store, vec![command]);
    let receipt = wallet::receipt(&store, expected).unwrap();
    assert_eq!(receipt.state, "ORIGINAL_OUTPUT_SPENT");
    assert!(receipt.import_accepted);
    assert!(!receipt.original_output_spendable_now);
    assert_eq!(receipt.original_output_remaining, Amount::ZERO);
    assert_eq!(
        wallet::view(&store, &public(11)).unwrap().spendable,
        Amount(47)
    );
    drop(store);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn independently_verified_transport_input_does_not_claim_import_or_spendability() {
    let mut f = Fixture::new();
    let (sid, export) = f.export_earth();
    let (root, mut source) = stored_fixture(&f, &f.earth);
    source
        .finalize(f.evidence.snapshot(sid).unwrap().clone())
        .unwrap();
    let frame = source.contact_export(export).unwrap();
    let mut target = Store::create(
        &root.join("target"),
        bootstrap(),
        f.proxima.region,
        &public(1),
        f.trust.currency().unwrap(),
    )
    .unwrap();
    assert!(wallet::receipt(&target, expectation(&f, export)).is_err());
    target.contact_apply(&frame, None).unwrap();
    let receipt = wallet::receipt(&target, expectation(&f, export)).unwrap();
    assert_eq!(receipt.state, "VERIFIED_EVIDENCE_PENDING_IMPORT");
    assert!(!receipt.import_accepted);
    assert!(!receipt.original_output_spendable_now);
    assert_eq!(
        wallet::view(&target, &public(11)).unwrap().spendable,
        Amount::ZERO
    );
    drop(target);
    drop(source);
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[cfg(unix)]
fn wallet_keys_require_private_regular_files() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let f = Fixture::new();
    let (root, store) = stored_fixture(&f, &f.earth);
    let draft = wallet::prepare(&store, request(10, 30)).unwrap();
    let file = key(&root, 10);
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(sign(&store, draft.clone(), &file).is_err());
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    let link = root.join("key-link.json");
    symlink(&file, &link).unwrap();
    assert!(sign(&store, draft, &link).is_err());
    drop(store);
    fs::remove_dir_all(root).unwrap();
}
