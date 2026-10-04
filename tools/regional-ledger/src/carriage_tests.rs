use super::*;
use crate::{
    carriage::{CarriedEvidence, Prefix},
    contact::Frame,
};

fn proofs(count: usize) -> (Fixture, Evidence) {
    let mut f = Fixture::new();
    let mut snapshots = vec![f
        .evidence
        .snapshot(f.earth.finalized.unwrap())
        .unwrap()
        .clone()];
    for _ in 1..count {
        advance(&mut f.earth, &f.trust, &f.evidence, vec![]);
        let sid = finalize(&mut f.earth, &f.trust, &mut f.evidence);
        snapshots.push(f.evidence.snapshot(sid).unwrap().clone());
    }
    (f, Evidence { snapshots })
}
#[test]
fn sixty_four_carried_checkpoints_expand_exactly_and_cold_native_replay_matches() {
    let (f, evidence) = proofs(MAX_SNAPSHOTS);
    let logical = serde_json::to_vec(&evidence).unwrap();
    let carried = CarriedEvidence::pack(&evidence).unwrap();
    let bytes = serde_json::to_vec(&carried).unwrap();
    assert!(bytes.len() * 4 < logical.len());
    assert!(carried.snapshots[0].prefix.is_none());
    assert!(carried.snapshots[1..]
        .iter()
        .all(|s| s.prefix.is_some() && s.snapshot.blocks.len() == 1));
    let cold: CarriedEvidence = serde_json::from_slice(&bytes).unwrap();
    let expanded = cold.expand().unwrap();
    assert_eq!(serde_json::to_vec(&expanded).unwrap(), logical);
    let native = VerifiedEvidence::verify(&expanded, &f.trust).unwrap();
    for snapshot in &evidence.snapshots {
        let sid = snapshot.statement.id().unwrap();
        assert_eq!(native.snapshots[&sid], f.evidence.snapshots[&sid]);
    }
    println!(
        "{}",
        serde_json::json!({"format":"RLD-NATIVE-CARRIAGE-PREFIX-SAMPLE-V1",
        "native_implementation":implementation().unwrap(),"fixture_only":true,"live_rld":false,
        "snapshots":MAX_SNAPSHOTS,"full_evidence_bytes":logical.len(),"carried_evidence_bytes":bytes.len(),
        "all_expanded_bytes_equal":true,"all_cold_native_ledgers_equal":true,
        "block_and_snapshot_bounds_unchanged":true,"long_history_qualified":false})
    );
}
#[test]
fn missing_forward_wrong_domain_and_bad_ranges_never_supply_a_prefix() {
    let (_, evidence) = proofs(3);
    let original = CarriedEvidence::pack(&evidence).unwrap();
    for mode in 0..7 {
        let mut changed = original.clone();
        let p = changed.snapshots[1].prefix.as_mut().unwrap();
        match mode {
            0 => p.checkpoint = Hash::ZERO,
            1 => p.checkpoint = evidence.snapshots[2].statement.id().unwrap(),
            2 => p.blocks += 1,
            3 => p.blocks = usize::MAX,
            4 => changed.snapshots[1].snapshot.statement.currency = Hash([2; 32]),
            5 => changed.snapshots[1].snapshot.statement.region = Hash([3; 32]),
            _ => changed.snapshots[1].snapshot.blocks.clear(),
        }
        assert!(changed.expand().is_err());
    }
    let mut absent = original.clone();
    absent.snapshots.remove(0);
    assert!(absent.expand().is_err());
    let mut reordered = original;
    reordered.snapshots.swap(0, 1);
    assert!(reordered.expand().is_err());
}
#[test]
fn self_consistent_carriage_and_duplicate_hashes_do_not_authorize_forged_certificates() {
    let (f, evidence) = proofs(3);
    let mut c = CarriedEvidence::pack(&evidence).unwrap();
    c.snapshots[2].snapshot.approvals[0].signature = "00".repeat(64);
    let raw = serde_json::to_vec(&c).unwrap();
    let decoded: CarriedEvidence = serde_json::from_slice(&raw).unwrap();
    let expanded = decoded.expand().unwrap();
    assert!(VerifiedEvidence::verify(&expanded, &f.trust).is_err());
    let mut repeated = evidence;
    repeated.snapshots.push(repeated.snapshots[2].clone());
    let packed = CarriedEvidence::pack(&repeated).unwrap();
    assert_eq!(
        serde_json::to_vec(&packed.expand().unwrap()).unwrap(),
        serde_json::to_vec(&repeated).unwrap()
    );
    VerifiedEvidence::verify(&packed.expand().unwrap(), &f.trust).unwrap();
}
#[test]
fn compressed_input_cannot_widen_native_count_block_or_expanded_byte_bounds() {
    let (_, evidence) = proofs(2);
    let mut c = CarriedEvidence::pack(&evidence).unwrap();
    c.snapshots = vec![c.snapshots[0].clone(); MAX_SNAPSHOTS + 1];
    assert!(c.expand().is_err());
    let mut c = CarriedEvidence::pack(&evidence).unwrap();
    c.snapshots[1].snapshot.statement.height = MAX_BLOCKS as u64 + 1;
    c.snapshots[1].snapshot.blocks = vec![c.snapshots[1].snapshot.blocks[0].clone(); MAX_BLOCKS];
    assert!(c.expand().is_err());
    let mut c = CarriedEvidence::pack(&evidence).unwrap();
    // One large, untrusted historical command fits the physical wire budget.
    // Reusing that block in many reconstructed snapshots must still account
    // every expanded byte before signature/command authentication begins.
    let intent = Intent {
        currency: c.snapshots[0].snapshot.statement.currency,
        region: c.snapshots[0].snapshot.statement.region,
        inputs: vec![Hash::ZERO],
        outputs: vec![],
        fee: Amount::ZERO,
        destination: None,
        remote: None,
        destination_fee: Amount::ZERO,
        valid_through: 100,
    };
    c.snapshots[0].snapshot.blocks[0].commands = vec![Command::Spend(Box::new(SignedIntent {
        intent,
        approvals: vec![Approval {
            key: public(10),
            signature: "x".repeat(MAX_BYTES / 16),
        }],
    }))];
    let base = c.snapshots[0].snapshot.clone();
    let mut prior = base.statement.id().unwrap();
    c.snapshots.truncate(1);
    for count in base.blocks.len()..base.blocks.len() + 20 {
        let mut tail = base.clone();
        tail.blocks = vec![base.blocks.last().unwrap().clone()];
        tail.statement.previous = Some(prior);
        tail.statement.height = (count + 1) as u64;
        let prefix = Prefix {
            checkpoint: prior,
            blocks: count,
        };
        prior = tail.statement.id().unwrap();
        c.snapshots.push(crate::carriage::CarriedSnapshot {
            prefix: Some(prefix),
            snapshot: tail,
        });
    }
    assert!(serde_json::to_vec(&c).unwrap().len() < crate::contact::MAX_PAYLOAD);
    assert!(c
        .expand()
        .unwrap_err()
        .contains("expanded evidence byte bound"));
}
#[test]
fn real_owner_export_compact_contact_imports_once_and_retains_spent_original_identity() {
    let (mut f, _) = proofs(12);
    let (_, eid) = f.export_earth();
    let (root, mut source) = stored_fixture(&f, &f.earth);
    let certificate = f
        .evidence
        .snapshot(f.earth.finalized.unwrap())
        .unwrap()
        .clone();
    source.finalize(certificate).unwrap();
    let mut target = Store::create(
        &root.join("target"),
        bootstrap(),
        f.proxima.region,
        &public(1),
        f.trust.currency().unwrap(),
    )
    .unwrap();
    let raw = source.contact_export(eid).unwrap();
    let (frame, bundle) = Frame::unpack(&raw).unwrap();
    let native = VerifiedEvidence::verify(&bundle.evidence, &f.trust).unwrap();
    assert_eq!(
        native.export(bundle.snapshot, eid).unwrap(),
        source.chain.ledger.exports.get(&eid).unwrap()
    );
    assert!(
        serde_json::to_vec(&bundle).unwrap().len()
            > base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &frame.payload_b64
            )
            .unwrap()
            .len()
                * 2
    );
    let accepted = target.contact_apply(&raw, Some(public(10))).unwrap();
    assert!(accepted.import_accepted);
    for _ in 0..2 {
        let mut b = target.template(vec![], public(10)).unwrap();
        mine(&mut b).unwrap();
        target.accept(b).unwrap();
    }
    let signed = intent(
        &target.chain,
        &target.trust,
        coins(&target.chain, 11),
        vec![Payment {
            owner: public(12),
            amount: Amount(78),
        }],
        None,
        None,
        0,
        0,
        &[11],
    );
    let mut b = target
        .template(vec![Command::Spend(Box::new(signed))], public(10))
        .unwrap();
    mine(&mut b).unwrap();
    target.accept(b).unwrap();
    let state = target.chain.ledger.clone();
    let height = target.chain.height();
    let pin = f.trust.currency().unwrap();
    drop(target);
    let mut target = Store::open(&root.join("target"), &public(1), pin).unwrap();
    let retry = target.contact_apply(&raw, Some(public(10))).unwrap();
    assert!(retry.import_accepted);
    assert_eq!(target.chain.ledger, state);
    assert_eq!(target.chain.height(), height);
    assert_eq!(target.chain.ledger.imports.len(), 1);
    assert!(!target
        .chain
        .ledger
        .coins
        .values()
        .any(|c| c.payment.owner == public(11)));
    drop(target);
    drop(source);
    std::fs::remove_dir_all(root).unwrap();
}
