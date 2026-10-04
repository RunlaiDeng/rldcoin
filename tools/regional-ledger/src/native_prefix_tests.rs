//! Compare prefix reuse against genesis replay, not against a cached balance.
use super::*;
use std::{cell::Cell, time::Instant};

thread_local! {
    static REPLAYED_BLOCKS: Cell<usize> = const { Cell::new(0) };
}
pub(crate) fn note_block_replay() {
    REPLAYED_BLOCKS.with(|count| count.set(count.get() + 1));
}
fn take_count() -> usize {
    REPLAYED_BLOCKS.with(|count| count.replace(0))
}
pub(super) fn from_genesis(
    snapshot: &Snapshot,
    trust: &Trust,
    evidence: &VerifiedEvidence,
) -> Chain {
    let mut chain = Chain::new(snapshot.statement.region, trust).unwrap();
    for block in &snapshot.blocks {
        chain.accept(block.clone(), trust, evidence).unwrap();
    }
    chain.epoch = snapshot.statement.epoch;
    assert_eq!(chain.statement(trust).unwrap(), snapshot.statement);
    chain
}

#[test]
fn cold_prefix_replay_matches_genesis_oracle_at_snapshot_capacity() {
    let package = bootstrap();
    let trust = Trust::verify(&package, &public(1), package.currency.id().unwrap()).unwrap();
    let mut chain = Chain::new(trust.named("earth").unwrap(), &trust).unwrap();
    let mut evidence = VerifiedEvidence::default();
    let mut snapshots = vec![];
    for _ in 0..MAX_SNAPSHOTS {
        advance(&mut chain, &trust, &evidence, vec![]);
        let snapshot = checkpoint(&chain, &trust);
        let ident = evidence.add(snapshot.clone(), &trust).unwrap();
        snapshots.push(snapshot);
        chain.install(ident, &evidence).unwrap();
    }
    // The disk/transport representation contains proofs, never a cached ledger.
    let bytes = serde_json::to_vec(&Evidence { snapshots }).unwrap();
    assert!(bytes.len() < MAX_BYTES);
    let input: Evidence = serde_json::from_slice(&bytes).unwrap();
    take_count();
    let started = Instant::now();
    let cold = VerifiedEvidence::verify(&input, &trust).unwrap();
    let cold_seconds = started.elapsed().as_secs_f64();
    let cold_blocks = take_count();
    assert_eq!(cold_blocks, MAX_SNAPSHOTS);
    let started = Instant::now();
    for snapshot in &input.snapshots {
        let replay = from_genesis(snapshot, &trust, &cold);
        let retained = &cold.snapshots[&snapshot.statement.id().unwrap()].1;
        assert_eq!(replay.ledger, *retained);
        assert_eq!(replay.ledger.root().unwrap(), snapshot.statement.state);
    }
    let genesis_seconds = started.elapsed().as_secs_f64();
    let genesis_blocks = take_count();
    assert_eq!(genesis_blocks, MAX_SNAPSHOTS * (MAX_SNAPSHOTS + 1) / 2);
    // Optimizing replay does not silently widen capacity or prune anything.
    advance(&mut chain, &trust, &evidence, vec![]);
    let extra = checkpoint(&chain, &trust);
    let before = evidence.snapshots.clone();
    assert!(evidence.add(extra, &trust).is_err());
    assert_eq!(evidence.snapshots, before);
    println!(
        "{}",
        serde_json::json!({
            "format":"RLD-NATIVE-PREFIX-REPLAY-SAMPLE-V1",
            "fixture_only":true,"live_rld":false,
            "native_implementation":implementation().unwrap(),
            "snapshots":MAX_SNAPSHOTS,"encoded_evidence_bytes":bytes.len(),
            "cold_verified_block_executions":cold_blocks,
            "genesis_oracle_block_executions":genesis_blocks,
            "cold_verification_seconds":cold_seconds,
            "genesis_oracle_seconds":genesis_seconds,
            "all_ledger_fields_equal":true,"all_native_roots_equal":true,
            "snapshot_capacity_unchanged":true,
            "long_term_history_qualified":false
        })
    );
}

#[test]
fn exact_trust_set_is_required_before_reusing_a_verified_prefix() {
    let mut fixture = Fixture::new();
    advance(
        &mut fixture.earth,
        &fixture.trust,
        &fixture.evidence,
        vec![],
    );
    let next = checkpoint(&fixture.earth, &fixture.trust);
    let mut package = bootstrap();
    package.admissions.retain(|a| a.region != "andromeda");
    let reduced = Trust::verify(&package, &public(1), package.currency.id().unwrap()).unwrap();
    // Same currency and exact Earth admission, but another admitted trust set.
    assert_eq!(
        reduced.currency().unwrap(),
        fixture.trust.currency().unwrap()
    );
    assert_eq!(reduced.named("earth").unwrap(), fixture.earth.region);
    let before = fixture.evidence.snapshots.clone();
    assert!(fixture.evidence.add(next.clone(), &reduced).is_err());
    assert_eq!(fixture.evidence.snapshots, before);
    fixture.evidence.add(next, &fixture.trust).unwrap();
}

#[test]
fn imported_value_and_onward_debit_match_full_replay_and_forged_tails_refuse() {
    let mut f = Fixture::new();
    let (_, export) = f.imported();
    for _ in 0..2 {
        advance(&mut f.proxima, &f.trust, &f.evidence, vec![]);
    }
    let parent = finalize(&mut f.proxima, &f.trust, &mut f.evidence);
    let signed = intent(
        &f.proxima,
        &f.trust,
        coins(&f.proxima, 11),
        vec![Payment {
            owner: public(11),
            amount: Amount(67),
        }],
        Some(f.andromeda.region),
        Some(Payment {
            owner: public(12),
            amount: Amount(10),
        }),
        1,
        1,
        &[11],
    );
    advance(
        &mut f.proxima,
        &f.trust,
        &f.evidence,
        vec![Command::Spend(Box::new(signed))],
    );
    let next = checkpoint(&f.proxima, &f.trust);
    let incremental = f.evidence.replay_extension(&next, &f.trust).unwrap();
    let complete = from_genesis(&next, &f.trust, &f.evidence);
    assert_eq!(incremental.ledger, complete.ledger);
    assert!(incremental.ledger.imports.contains_key(&export));
    assert_eq!(incremental.ledger.exports.len(), 1);
    let before = f.evidence.snapshots.clone();

    let mut bad = next.clone();
    bad.approvals[0].signature = "00".into();
    assert!(f.evidence.add(bad, &f.trust).is_err());

    let mut bad = next.clone();
    let block = bad.blocks.last_mut().unwrap();
    let Command::Spend(spend) = &mut block.commands[0] else {
        panic!()
    };
    spend.approvals[0].signature = "00".into();
    block.header.commands = id("commands", &block.commands).unwrap();
    mine(block).unwrap();
    bad.statement.block = block.header.id().unwrap();
    bad.approvals = keys()
        .into_iter()
        .map(|seed| Approval {
            key: public(seed),
            signature: signature(seed, &bad.statement.bytes().unwrap()),
        })
        .collect();
    // A genuine quorum signature cannot certify invalid owner authorization.
    assert!(f.evidence.add(bad, &f.trust).is_err());

    let mut bad = next.clone();
    bad.blocks[0].header.nonce ^= 1;
    assert!(f.evidence.add(bad, &f.trust).is_err());
    assert_eq!(f.evidence.snapshots, before);
    f.evidence.add(next, &f.trust).unwrap();
    assert_eq!(f.evidence.snapshot(parent).unwrap(), &before[&parent].0);
}

#[test]
fn failed_block_does_not_install_an_otherwise_valid_new_anchor() {
    let package = bootstrap();
    let trust = Trust::verify(&package, &public(1), package.currency.id().unwrap()).unwrap();
    let mut chain = Chain::new(trust.named("earth").unwrap(), &trust).unwrap();
    let mut evidence = VerifiedEvidence::default();
    advance(&mut chain, &trust, &evidence, vec![]);
    let old = chain.clone();
    finalize(&mut chain, &trust, &mut evidence);
    let mut next = chain
        .template(vec![], public(10), &trust, &evidence)
        .unwrap();
    next.header.state = Hash::ZERO;
    mine(&mut next).unwrap();
    let mut receiver = old.clone();
    assert!(receiver.accept(next, &trust, &evidence).is_err());
    assert_eq!(receiver.blocks, old.blocks);
    assert_eq!(receiver.ledger, old.ledger);
    assert_eq!(receiver.finalized, old.finalized);
}
