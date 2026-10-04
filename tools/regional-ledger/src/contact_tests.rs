use super::*;
use crate::contact::Frame;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::fs;
fn setup() -> (PathBuf, Store, Store, Vec<u8>) {
    let mut f = Fixture::new();
    let inputs = vec![coins(&f.earth, 10)[0]];
    let signed = intent(
        &f.earth,
        &f.trust,
        inputs,
        vec![],
        Some(f.proxima.region),
        Some(Payment {
            owner: public(11),
            amount: Amount(99),
        }),
        1,
        1,
        &[10],
    );
    let eid = signed.intent.id().unwrap();
    advance(
        &mut f.earth,
        &f.trust,
        &f.evidence,
        vec![Command::Spend(Box::new(signed))],
    );
    finalize(&mut f.earth, &f.trust, &mut f.evidence);
    let (root, mut source) = stored_fixture(&f, &f.earth);
    source
        .finalize(
            f.evidence
                .snapshot(f.earth.finalized.unwrap())
                .unwrap()
                .clone(),
        )
        .unwrap();
    let target = Store::create(
        &root.join("target"),
        bootstrap(),
        f.proxima.region,
        &public(1),
        f.trust.currency().unwrap(),
    )
    .unwrap();
    let frame = source.contact_export(eid).unwrap();
    (root, source, target, frame)
}
fn step(store: &mut Store) {
    let mut block = store.template(vec![], public(10)).unwrap();
    mine(&mut block).unwrap();
    store.accept(block).unwrap();
}
#[test]
fn export_carriage_stays_exact_after_unrelated_certified_growth_and_restart() {
    let (root, mut source, mut target, raw) = setup();
    let (_, bundle) = Frame::unpack(&raw).unwrap();
    let pin = source.trust.currency().unwrap();
    let before = bundle.evidence.snapshots.len();
    for _ in 0..3 {
        step(&mut source);
        let snapshot = checkpoint(&source.chain, &source.trust);
        source.finalize(snapshot).unwrap();
    }
    assert!(source.journal.evidence.snapshots.len() > before);
    assert_eq!(source.contact_export(bundle.export).unwrap(), raw);
    let independent = VerifiedEvidence::verify(&bundle.evidence, &source.trust).unwrap();
    assert_eq!(
        independent.export(bundle.snapshot, bundle.export).unwrap(),
        source.chain.ledger.exports.get(&bundle.export).unwrap()
    );
    drop(source);
    let source = Store::open(&root, &public(1), pin).unwrap();
    assert_eq!(source.contact_export(bundle.export).unwrap(), raw);
    let status = target.contact_apply(&raw, None).unwrap();
    assert!(status.evidence_verified && !status.import_accepted);
    assert_eq!(target.chain.height(), 0);
    fs::remove_dir_all(root).unwrap();
}
fn wrap(frame: &mut Frame, payload: Vec<u8>) -> Vec<u8> {
    frame.payload_b64 = STANDARD.encode(&payload);
    frame.payload_sha256 = Hash(Sha256::digest(payload).into());
    let mut body = serde_json::to_value(&frame).unwrap();
    body.as_object_mut().unwrap().remove("message_id");
    let mut bytes = format!("{}\0", contact::FRAME_FORMAT).into_bytes();
    bytes.extend(serde_json::to_vec(&body).unwrap());
    frame.message_id = Hash(Sha256::digest(bytes).into());
    serde_json::to_vec(&serde_json::to_value(frame).unwrap()).unwrap()
}
#[test]
fn transport_evidence_is_pending_until_native_import_and_survives_restart() {
    let (root, source, mut target, raw) = setup();
    let pin = source.trust.currency().unwrap();
    let status = target.contact_apply(&raw, None).unwrap();
    let ident = status.message_id;
    assert!(status.evidence_verified);
    assert!(!status.import_accepted);
    assert_eq!(target.chain.height(), 0);
    assert!(!status.original_recipient_output_spendable_now);
    drop(target);
    let mut target = Store::open(&root.join("target"), &public(1), pin).unwrap();
    let imported = target.contact_fulfill(ident, public(10)).unwrap();
    assert!(imported.import_accepted);
    assert_eq!(imported.import_height, Some(1));
    assert_eq!(imported.recipient_mature_height, Some(3));
    assert_eq!(imported.original_recipient_output_remaining, Amount(98));
    assert!(!imported.original_recipient_output_spendable_now);
    assert_eq!(target.chain.ledger.minted, Amount::ZERO);
    step(&mut target);
    step(&mut target);
    assert!(
        target
            .contact_status(ident)
            .unwrap()
            .original_recipient_output_spendable_now
    );
    let height = target.chain.height();
    let state = target.chain.ledger.root().unwrap();
    drop(target);
    let mut target = Store::open(&root.join("target"), &public(1), pin).unwrap();
    target.contact_apply(&raw, Some(public(10))).unwrap();
    assert_eq!(target.chain.height(), height);
    assert_eq!(target.chain.ledger.root().unwrap(), state);
    let third = Chain::new(target.trust.named("andromeda").unwrap(), &target.trust).unwrap();
    conservation(&[source.chain.clone(), target.chain.clone(), third]).unwrap();
    drop(target);
    drop(source);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn changed_payload_noncanonical_frame_and_transport_receipt_cannot_import() {
    let (root, source, mut target, raw) = setup();
    let before = fs::read(root.join("target/journal.json")).unwrap();
    let (mut frame, bundle) = Frame::unpack(&raw).unwrap();
    frame.payload_b64.push('A');
    let changed = serde_json::to_vec(&serde_json::to_value(frame).unwrap()).unwrap();
    assert!(target.contact_apply(&changed, Some(public(10))).is_err());
    let mut spaced = raw.clone();
    spaced.push(b' ');
    assert!(Frame::unpack(&spaced).is_err());
    let mut receipt: Frame = serde_json::from_slice(&raw).unwrap();
    receipt.kind = "destination-receipt".into();
    let fake = wrap(&mut receipt, serde_json::to_vec(&bundle).unwrap());
    assert!(target.contact_apply(&fake, Some(public(10))).is_err());
    assert_eq!(before, fs::read(root.join("target/journal.json")).unwrap());
    assert!(target.chain.ledger.imports.is_empty());
    drop(target);
    drop(source);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn wrong_native_destination_and_fake_export_are_rejected_atomically() {
    let (root, source, mut target, raw) = setup();
    let before = fs::read(root.join("target/journal.json")).unwrap();
    let (_, mut bundle) = Frame::unpack(&raw).unwrap();
    bundle.destination = source.trust.named("andromeda").unwrap();
    assert!(target
        .contact_apply(&Frame::pack(&bundle).unwrap(), Some(public(10)))
        .is_err());
    bundle.destination = target.chain.region;
    bundle.export = id("nonexistent-export", &0).unwrap();
    assert!(target
        .contact_apply(&Frame::pack(&bundle).unwrap(), Some(public(10)))
        .is_err());
    assert_eq!(before, fs::read(root.join("target/journal.json")).unwrap());
    assert!(target.journal.evidence.snapshots.is_empty());
    assert!(target.journal.contact_records.is_empty());
    drop(target);
    drop(source);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn incomplete_contact_dependencies_and_foreign_currency_leave_native_state_unchanged() {
    let (root, source, mut target, raw) = setup();
    let before = fs::read(root.join("target/journal.json")).unwrap();
    let (_, mut bundle) = Frame::unpack(&raw).unwrap();
    bundle
        .evidence
        .snapshots
        .retain(|s| s.statement.id().ok() == Some(bundle.snapshot));
    assert!(target
        .contact_apply(&Frame::pack(&bundle).unwrap(), Some(public(10)))
        .is_err());
    let (_, mut bundle) = Frame::unpack(&raw).unwrap();
    bundle.currency = id("foreign-currency", &0).unwrap();
    assert!(target
        .contact_apply(&Frame::pack(&bundle).unwrap(), Some(public(10)))
        .is_err());
    assert_eq!(before, fs::read(root.join("target/journal.json")).unwrap());
    assert!(target.chain.ledger.coins.is_empty());
    drop(target);
    drop(source);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn duplicate_carriage_of_the_same_export_never_mines_or_issues_twice() {
    let (root, source, mut target, raw) = setup();
    target.contact_apply(&raw, Some(public(10))).unwrap();
    let mut frame: Frame = serde_json::from_slice(&raw).unwrap();
    let mut payload = STANDARD.decode(&frame.payload_b64).unwrap();
    payload.push(b' ');
    let alias = wrap(&mut frame, payload);
    let before = target.chain.ledger.root().unwrap();
    let height = target.chain.height();
    let status = target.contact_apply(&alias, Some(public(10))).unwrap();
    assert!(status.import_accepted);
    assert_eq!(height, target.chain.height());
    assert_eq!(before, target.chain.ledger.root().unwrap());
    assert_eq!(target.journal.contact_records.len(), 2);
    assert_eq!(target.chain.ledger.imports.len(), 1);
    drop(target);
    drop(source);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn authenticated_incidents_in_contacts_are_retained_and_prevent_new_credit() {
    let (root, source, mut target, raw) = setup();
    let (_, mut bundle) = Frame::unpack(&raw).unwrap();
    let f = Fixture::new();
    let proof = conflict_proof(&f);
    bundle.incidents.push(proof.clone());
    let mut forged = bundle.clone();
    forged.incidents[0].left.approvals[0].signature = "00".into();
    assert!(target
        .contact_apply(&Frame::pack(&forged).unwrap(), Some(public(10)))
        .is_err());
    assert!(target.conflicts.is_empty());
    assert!(target
        .contact_apply(&Frame::pack(&bundle).unwrap(), Some(public(10)))
        .is_err());
    assert_eq!(target.conflicts.len(), 1);
    assert!(target.chain.ledger.imports.is_empty());
    assert_eq!(target.chain.height(), 0);
    assert_eq!(target.journal.contact_records.len(), 1);
    let ident = *target.journal.contact_records.keys().next().unwrap();
    assert!(target.contact_status(ident).unwrap().quarantined);
    let pin = target.trust.currency().unwrap();
    drop(target);
    let mut target = Store::open(&root.join("target"), &public(1), pin).unwrap();
    assert!(target.contact_fulfill(ident, public(10)).is_err());
    drop(target);
    drop(source);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn contact_capacity_and_byte_bounds_preserve_pending_value_evidence() {
    let (root, source, mut target, raw) = setup();
    let status = target.contact_apply(&raw, None).unwrap();
    let record = target.journal.contact_records[&status.message_id].clone();
    let mut journal = target.journal.clone();
    journal.contact_records.clear();
    for i in 0..contact::MAX_CONTACTS {
        let mut next = record.clone();
        next.message_id = id("contact-capacity-fixture", &i).unwrap();
        journal.contact_records.insert(next.message_id, next);
    }
    target.commit(journal).unwrap();
    let before = fs::read(root.join("target/journal.json")).unwrap();
    assert!(target
        .contact_apply(&raw, Some(public(10)))
        .unwrap_err()
        .contains("capacity"));
    assert_eq!(before, fs::read(root.join("target/journal.json")).unwrap());
    assert!(Frame::unpack(&vec![b'x'; contact::MAX_FRAME + 1]).is_err());
    assert!(target.chain.ledger.imports.is_empty());
    drop(target);
    drop(source);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn contact_index_corruption_cannot_turn_unverified_evidence_into_payment() {
    let (root, source, mut target, raw) = setup();
    let status = target.contact_apply(&raw, None).unwrap();
    let pin = target.trust.currency().unwrap();
    drop(target);
    let path = root.join("target/journal.json");
    let mut journal = crate::history::read_journal(&root.join("target")).unwrap();
    journal
        .contact_records
        .get_mut(&status.message_id)
        .unwrap()
        .snapshot = id("unknown-snapshot", &0).unwrap();
    fs::write(
        path,
        crate::history::prepare(&root.join("target"), &journal).unwrap(),
    )
    .unwrap();
    assert_eq!(
        Store::open(&root.join("target"), &public(1), pin)
            .err()
            .unwrap(),
        "missing verified source checkpoint"
    );
    drop(source);
    fs::remove_dir_all(root).unwrap();
}
