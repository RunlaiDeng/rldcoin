use super::*;
use crate::bft::{Certificate, Context, Phase, Quorum, Vote};
use crate::tests::{public, signature};

pub(super) fn header() -> Header {
    let mut currency = Currency {
        format: DOMAIN.into(),
        fixture_only: true,
        implementation: implementation().unwrap(),
        origin: "earth".into(),
        authority: public(1),
        cap: Amount::TOTAL_SUPPLY,
        block_reward: rld_pow::subsidy(1).unwrap(),
        maturity: 2,
        signature: String::new(),
    };
    currency.signature = signature(1, &currency.bytes().unwrap());
    let mut validators = [2, 3, 4, 5];
    validators.sort_by_key(|s| public(*s));
    let mut admission = Admission {
        currency: currency.id().unwrap(),
        region: "earth".into(),
        rules: crate::paged_bft::RULES.into(),
        value_rules: Some(crate::paged_bft::rules_hash().unwrap()),
        validators: validators.iter().map(|s| public(*s)).collect(),
        signature: String::new(),
    };
    admission.signature = signature(1, &admission.bytes().unwrap());
    Header {
        format: FORMAT.into(),
        region: admission.id().unwrap(),
        bootstrap: Bootstrap {
            currency,
            admissions: vec![admission],
        },
    }
}
pub(super) fn replay(h: &Header) -> Replay {
    Replay::new(h, &public(1), h.bootstrap.currency.id().unwrap()).unwrap()
}
pub(super) fn certified(r: &Replay) -> Snapshot {
    certified_with_commands(r, vec![])
}
pub(super) fn certified_with_commands(r: &Replay, commands: Vec<Command>) -> Snapshot {
    let mut chain = r.chain.clone();
    let context = Context {
        currency: r.trust.currency().unwrap(),
        region: chain.region,
        epoch: chain.epoch,
        previous: chain.finalized,
        parent_height: chain.height(),
        parent_block: chain.tip().unwrap(),
        parent_state: chain.ledger.root().unwrap(),
    };
    crate::paged_bft::prepare_parent(&mut chain, &r.evidence).unwrap();
    let mut block = chain
        .template(commands, public(10), &r.trust, &r.evidence)
        .unwrap();
    mine(&mut block).unwrap();
    chain.accept(block, &r.trust, &r.evidence).unwrap();
    let mut snapshot = Snapshot {
        base: chain.snapshot_base(),
        statement: chain.statement(&r.trust).unwrap(),
        blocks: chain.blocks.clone(),
        epochs: vec![],
        approvals: vec![],
        bft: None,
    };
    let value = snapshot.statement.id().unwrap();
    let mut seeds = [2, 3, 4, 5];
    seeds.sort_by_key(|s| public(*s));
    let qc = |phase| Quorum {
        context: context.clone(),
        round: 0,
        value,
        phase,
        votes: seeds[..3]
            .iter()
            .map(|seed| {
                let mut vote = Vote {
                    context: context.clone(),
                    round: 0,
                    value,
                    phase,
                    approval: Approval {
                        key: public(*seed),
                        signature: String::new(),
                    },
                };
                vote.approval.signature = signature(*seed, &vote.bytes().unwrap());
                vote
            })
            .collect(),
    };
    snapshot.bft = Some(Certificate {
        prepared: qc(Phase::Prepare),
        committed: qc(Phase::Commit),
    });
    snapshot
}
#[test]
fn fully_occupied_identity_cache_must_not_block_new_native_certificate() {
    let h = header();
    let mut r = replay(&h);
    let snapshot = certified(&r);
    crate::conflict::CertifiedHistory::from_snapshot(&snapshot)
        .verify(&r.trust)
        .unwrap();
    // Synthetic cache occupancy isolates the actual guard. These identities
    // confer no authority and do not represent4096 signed native checkpoints.
    for n in 0..MAX_COINS {
        r.bodies
            .remember(id("synthetic-cache-key", &n).unwrap(), Hash::ZERO)
            .unwrap();
    }
    assert_eq!(r.bodies.len(), MAX_COINS);
    let (_root, stream) = stream(&h, &r);
    r.apply(&Record::Certified(Box::new(snapshot)), &stream)
        .unwrap();
    assert_eq!(r.chain.height(), 1);
    assert!(r.bodies.len() <= MAX_COINS);
}

pub(super) fn stream(h: &Header, r: &Replay) -> (PathBuf, Stream<Record>) {
    let root = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "rld-executed-body-prefix-{}",
            rld_core::generate_identity().public_key
        ));
    private_root(&root).unwrap();
    let stream = Stream::create(&root.join("events"), h.scope(&r.trust).unwrap()).unwrap();
    (root, stream)
}
pub(super) fn evict_real_bodies(r: &mut Replay) {
    for n in 0..MAX_COINS {
        r.bodies
            .remember(id("synthetic-cache-key", &n).unwrap(), Hash::ZERO)
            .unwrap();
    }
    assert_eq!(r.bodies.len(), MAX_COINS);
}
#[test]
fn evicted_body_uses_only_this_invocations_executed_prefix_and_reauthenticates() {
    let h = header();
    let mut producing = replay(&h);
    let (_root, mut stream) = stream(&h, &producing);
    let first = certified(&producing);
    let record1 = Record::Certified(Box::new(first.clone()));
    producing.apply(&record1, &stream).unwrap();
    let second = certified(&producing);
    let record2 = Record::Certified(Box::new(second.clone()));
    stream
        .append(&[record1.clone(), record2.clone()], stream.storage_head())
        .unwrap();
    let mut r = replay(&h);
    let sid1 = first.statement.id().unwrap();
    let sid2 = second.statement.id().unwrap();
    // Even a hash-consistent, fully signed retained stream is not prior Native execution.
    assert_eq!(r.prior_body(sid1, &stream).unwrap(), None);
    r.apply_retained(&record1, &stream).unwrap();
    evict_real_bodies(&mut r);
    assert!(r.bodies.get(&sid1).is_none());
    assert_eq!(
        r.prior_body(sid2, &stream).unwrap(),
        None,
        "future record granted execution"
    );
    let ledger = r.chain.ledger.clone();
    r.apply(&record1, &stream).unwrap();
    assert_eq!(r.chain.ledger, ledger);
    assert_eq!(r.chain.height(), 1);
    evict_real_bodies(&mut r);
    let mut bad = first.clone();
    bad.bft.as_mut().unwrap().committed.votes[0]
        .approval
        .signature = "00".repeat(64);
    assert!(r.apply(&Record::Certified(Box::new(bad)), &stream).is_err());
    let mut bad = first.clone();
    bad.blocks[0].commands.push(Command::Import {
        snapshot: Hash([8; 32]),
        export: Hash([7; 32]),
    });
    assert!(r.apply(&Record::Certified(Box::new(bad)), &stream).is_err());
    assert_eq!(r.chain.ledger, ledger);
    r.apply_retained(&record2, &stream).unwrap();
    assert_eq!(r.chain.height(), 2);
    evict_real_bodies(&mut r);
    r.executed.corrupt_head_for_fixture();
    assert!(
        r.prior_body(sid1, &stream).is_err(),
        "wrong executed prefix accepted"
    );
    assert_eq!(r.chain.height(), 2);
}
#[test]
fn identity_fifo_never_exceeds_original_bound_and_rejects_changed_identity() {
    let mut b = body_witness::Bodies::default();
    for n in 0..=MAX_COINS {
        b.remember(id("bounded-cache-test", &n).unwrap(), Hash::ZERO)
            .unwrap();
        assert!(b.len() <= MAX_COINS);
    }
    assert_eq!(b.len(), MAX_COINS);
    assert!(b.get(&id("bounded-cache-test", &0usize).unwrap()).is_none());
    let latest = id("bounded-cache-test", &MAX_COINS).unwrap();
    assert!(b.remember(latest, Hash([9; 32])).is_err());
    assert_eq!(b.get(&latest), Some(&Hash::ZERO));
}
