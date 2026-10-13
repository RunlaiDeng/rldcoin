use super::*;
use crate::causal_cut::{inspect, Selection};

struct CutFixture {
    bootstrap: Bootstrap,
    fixture: Fixture,
    evidence: Evidence,
    older: Hash,
    imported: Hash,
    destination: Hash,
}

impl CutFixture {
    fn new() -> Self {
        // Public no-value fixture keys; current implementation identity is signed
        // anew. No prior Store, wallet or signer directory is opened or reused.
        let bootstrap = bootstrap();
        let mut fixture = Fixture::new();
        // The installed checkpoint's statement.previous changes on install;
        // retain the actual authenticated original bytes instead.
        let mut snapshots = vec![fixture
            .evidence
            .snapshot(fixture.earth.finalized.unwrap())
            .unwrap()
            .clone()];
        let (older, export) = fixture.export_earth();
        snapshots.push(fixture.evidence.snapshot(older).unwrap().clone());
        advance(
            &mut fixture.earth,
            &fixture.trust,
            &fixture.evidence,
            vec![],
        );
        let imported = finalize(&mut fixture.earth, &fixture.trust, &mut fixture.evidence);
        snapshots.push(fixture.evidence.snapshot(imported).unwrap().clone());
        // Explicitly bind the Native import to S2. Ordinary export carriage may
        // correctly choose S1, the earliest checkpoint containing this export.
        advance(
            &mut fixture.proxima,
            &fixture.trust,
            &fixture.evidence,
            vec![Command::Import {
                snapshot: imported,
                export,
            }],
        );
        for _ in 0..2 {
            advance(
                &mut fixture.proxima,
                &fixture.trust,
                &fixture.evidence,
                vec![],
            );
        }
        let spend = intent(
            &fixture.proxima,
            &fixture.trust,
            coins(&fixture.proxima, 11),
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
        advance(
            &mut fixture.proxima,
            &fixture.trust,
            &fixture.evidence,
            vec![Command::Spend(Box::new(spend))],
        );
        let destination = finalize(&mut fixture.proxima, &fixture.trust, &mut fixture.evidence);
        snapshots.push(fixture.evidence.snapshot(destination).unwrap().clone());
        Self {
            bootstrap,
            fixture,
            evidence: Evidence { snapshots },
            older,
            imported,
            destination,
        }
    }

    fn selection(&self, source: Hash) -> Vec<Selection> {
        vec![
            Selection {
                region: self.fixture.earth.region,
                checkpoint: source,
            },
            Selection {
                region: self.fixture.proxima.region,
                checkpoint: self.destination,
            },
        ]
    }

    fn check(
        &self,
        evidence: &Evidence,
        selection: &[Selection],
    ) -> Result<crate::causal_cut::Report> {
        inspect(
            &self.bootstrap,
            &public(1),
            self.bootstrap.currency.id().unwrap(),
            evidence,
            selection,
        )
    }
}

#[test]
fn authenticated_cut_refuses_amount_valid_nonclosed_history() {
    let f = CutFixture::new();
    let original = serde_json::to_vec(&(&f.bootstrap, &f.evidence)).unwrap();
    let old_chain = f
        .fixture
        .evidence
        .replay_extension(
            f.fixture.evidence.snapshot(f.older).unwrap(),
            &f.fixture.trust,
        )
        .unwrap();
    let expected = (Amount(300), Amount(300), Amount::ZERO, Amount::ZERO);
    assert_eq!(
        conservation_with_escrow(&[old_chain, f.fixture.proxima.clone()]).unwrap(),
        expected,
        "the counter must distinguish closure from the conditional amount helper"
    );
    assert_eq!(
        f.check(&f.evidence, &f.selection(f.older)).unwrap_err(),
        "selected history precedes required checkpoint"
    );
    let good = f.check(&f.evidence, &f.selection(f.imported)).unwrap();
    assert_eq!(
        (good.issued, good.liquid, good.escrow, good.pending_transfer),
        expected
    );
    assert_eq!(good.selected[0].id().unwrap(), f.imported);
    assert_eq!(good.selected[1].id().unwrap(), f.destination);
    assert!(!good.ledger_changed && !good.signing_authority);
    assert!(!good.current_spendability_authority && !good.incident_safety_verified);
    assert!(!good.independent_freshness_verified);
    // The imported recipient output was spent; the permanent dependency remains.
    assert!(coins(&f.fixture.proxima, 11).is_empty());
    assert_eq!(f.fixture.proxima.ledger.imports.len(), 1);
    let pending = f.check(&f.evidence, &f.selection(f.imported)[..1]).unwrap();
    assert_eq!(pending.pending_transfer, Amount(80));
    assert_eq!(pending.liquid, Amount(220));
    assert_ne!(pending.request_commitment, good.request_commitment);
    assert_eq!(
        serde_json::to_vec(&(&f.bootstrap, &f.evidence)).unwrap(),
        original
    );
    eprintln!("authenticated historical cut: amount-valid nonclosed refused; closed I=300 U=300 E=0 T=0; source-only T=80; spent import lineage retained");
}

#[test]
fn authenticated_cut_checks_every_later_certificate_and_complete_prefix() {
    let mut f = CutFixture::new();
    let choices = f.selection(f.imported);
    let good = f.check(&f.evidence, &choices).unwrap();
    advance(
        &mut f.fixture.earth,
        &f.fixture.trust,
        &f.fixture.evidence,
        vec![],
    );
    let later = finalize(
        &mut f.fixture.earth,
        &f.fixture.trust,
        &mut f.fixture.evidence,
    );
    let extra = f.fixture.evidence.snapshot(later).unwrap().clone();
    let mut evidence = f.evidence.clone();
    evidence.snapshots.push(extra.clone());
    let with_later = f.check(&evidence, &choices).unwrap();
    assert_eq!(good.selected, with_later.selected);
    assert_eq!(good.liquid, with_later.liquid);
    assert_ne!(good.request_commitment, with_later.request_commitment);
    evidence.snapshots.last_mut().unwrap().approvals[0].signature = "00".repeat(64);
    assert!(f.check(&evidence, &choices).is_err());
    evidence = f.evidence.clone();
    evidence.snapshots.push(evidence.snapshots[1].clone());
    f.check(&evidence, &choices).unwrap();
    evidence.snapshots.last_mut().unwrap().approvals[0].signature = "00".repeat(64);
    assert!(
        f.check(&evidence, &choices).is_err(),
        "duplicate body cannot hide bad signature"
    );
    for missing in [0, 1, 2] {
        let mut evidence = f.evidence.clone();
        evidence.snapshots.remove(missing);
        assert!(f.check(&evidence, &choices).is_err());
    }
}

#[test]
fn authenticated_cut_requires_explicit_source_and_independent_trust() {
    let f = CutFixture::new();
    let choices = f.selection(f.imported);
    assert_eq!(
        f.check(&f.evidence, &choices[1..]).unwrap_err(),
        "causal cut omits required source region"
    );
    assert_eq!(
        f.check(&f.evidence, &[choices[0].clone(), choices[0].clone()])
            .unwrap_err(),
        "causal cut duplicate selected region"
    );
    let mut unknown = choices.clone();
    unknown[0].checkpoint = Hash::ZERO;
    assert!(f.check(&f.evidence, &unknown).is_err());
    unknown[0].checkpoint = f.destination;
    assert_eq!(
        f.check(&f.evidence, &unknown).unwrap_err(),
        "causal cut selected checkpoint identity"
    );
    let pin = f.bootstrap.currency.id().unwrap();
    assert!(inspect(&f.bootstrap, &public(2), pin, &f.evidence, &choices).is_err());
    assert!(inspect(&f.bootstrap, &public(1), Hash::ZERO, &f.evidence, &choices).is_err());
    let mut other = f.bootstrap.clone();
    other.currency.maturity += 1;
    other.currency.signature = signature(1, &other.currency.bytes().unwrap());
    for admission in &mut other.admissions {
        admission.currency = other.currency.id().unwrap();
        admission.signature = signature(1, &admission.bytes().unwrap());
    }
    let other_pin = other.currency.id().unwrap();
    Trust::verify(&other, &public(1), other_pin).unwrap();
    assert!(inspect(&other, &public(1), other_pin, &f.evidence, &choices).is_err());
}

#[test]
fn authenticated_cut_refuses_unsupported_profiles_and_original_bounds() {
    let f = CutFixture::new();
    let choices = f.selection(f.imported);
    let mut bft_bootstrap = f.bootstrap.clone();
    for admission in &mut bft_bootstrap.admissions {
        admission.rules = bft::RULES.into();
        admission.signature = signature(1, &admission.bytes().unwrap());
    }
    let pin = bft_bootstrap.currency.id().unwrap();
    Trust::verify(&bft_bootstrap, &public(1), pin).unwrap();
    assert_eq!(
        inspect(&bft_bootstrap, &public(1), pin, &f.evidence, &choices).unwrap_err(),
        "causal cut unsupported history profile"
    );
    assert!(f.check(&f.evidence, &[]).is_err());
    assert!(f.check(&f.evidence, &vec![choices[0].clone(); 17]).is_err());
    assert!(f.check(&Evidence::default(), &choices).is_err());
    let oversized = Evidence {
        snapshots: vec![f.evidence.snapshots[0].clone(); MAX_SNAPSHOTS + 1],
    };
    assert!(f.check(&oversized, &choices).is_err());
    let mut evidence = f.evidence.clone();
    evidence.snapshots[0].base = Some(f.older);
    assert_eq!(
        f.check(&evidence, &choices).unwrap_err(),
        "causal cut unsupported history profile"
    );
    evidence = f.evidence.clone();
    evidence.snapshots[0].statement.epoch = Hash::ZERO;
    assert_eq!(
        f.check(&evidence, &choices).unwrap_err(),
        "causal cut unsupported history profile"
    );
    evidence = f.evidence.clone();
    evidence.snapshots[0].blocks = vec![evidence.snapshots[0].blocks[0].clone(); MAX_BLOCKS + 1];
    assert_eq!(
        f.check(&evidence, &choices).unwrap_err(),
        "causal cut unsupported history profile"
    );
    evidence = f.evidence.clone();
    evidence.snapshots[0].approvals[0].signature = "x".repeat(MAX_BYTES);
    assert_eq!(
        f.check(&evidence, &choices).unwrap_err(),
        "encoded evidence exceeds bound"
    );
}

// Public no-value fixture keys exercise Native certificate/value verification;
// this is not an Agent signing-custody, Store, transport or adoption fixture.
struct BftCutFixture {
    bootstrap: Bootstrap,
    trust: Trust,
    source: Chain,
    destination: Chain,
    verified: VerifiedEvidence,
    evidence: Evidence,
    s3: Hash,
    s4: Hash,
    d1: Hash,
    export: Hash,
}

fn bft_cut_advance(
    chain: &mut Chain,
    trust: &Trust,
    verified: &mut VerifiedEvidence,
    evidence: &mut Evidence,
    commands: Vec<Command>,
) -> Hash {
    let context = bft::Context {
        currency: trust.currency().unwrap(),
        region: chain.region,
        epoch: chain.epoch,
        previous: chain.finalized,
        parent_height: chain.height(),
        parent_block: chain.tip().unwrap(),
        parent_state: chain.ledger.root().unwrap(),
    };
    advance(chain, trust, verified, commands);
    let statement = chain.statement(trust).unwrap();
    let value = statement.id().unwrap();
    let quorum = |phase| {
        let votes = keys()
            .into_iter()
            .take(3)
            .map(|seed| {
                let mut vote = bft::Vote {
                    context: context.clone(),
                    round: 0,
                    value,
                    phase,
                    approval: Approval {
                        key: public(seed),
                        signature: String::new(),
                    },
                };
                vote.approval.signature = signature(seed, &vote.bytes().unwrap());
                vote
            })
            .collect();
        bft::Quorum::combine(votes, trust, verified).unwrap()
    };
    let snapshot = Snapshot {
        statement,
        approvals: vec![],
        blocks: chain.blocks.clone(),
        base: None,
        bft: Some(bft::Certificate {
            prepared: quorum(bft::Phase::Prepare),
            committed: quorum(bft::Phase::Commit),
        }),
        epochs: vec![],
    };
    let checkpoint = verified.add(snapshot.clone(), trust).unwrap();
    assert_eq!(checkpoint, value);
    // Preserve the complete original pre-install statement.previous and bytes.
    evidence.snapshots.push(snapshot);
    chain.install(checkpoint, verified).unwrap();
    checkpoint
}

impl BftCutFixture {
    fn new() -> Self {
        let mut bootstrap = bootstrap();
        for admission in &mut bootstrap.admissions {
            admission.rules = bft::RULES.into();
            admission.signature = signature(1, &admission.bytes().unwrap());
        }
        let trust =
            Trust::verify(&bootstrap, &public(1), bootstrap.currency.id().unwrap()).unwrap();
        let mut source = Chain::new(trust.named("earth").unwrap(), &trust).unwrap();
        let mut destination = Chain::new(trust.named("proxima").unwrap(), &trust).unwrap();
        let mut verified = VerifiedEvidence::default();
        let mut evidence = Evidence::default();
        for _ in 0..2 {
            bft_cut_advance(&mut source, &trust, &mut verified, &mut evidence, vec![]);
        }
        let inputs = source
            .ledger
            .coins
            .iter()
            .filter(|(_, coin)| coin.created == 1 && coin.payment.owner == public(10))
            .map(|(id, coin)| {
                assert_eq!(coin.payment.amount, Amount(100));
                assert_eq!(coin.mature, 3);
                *id
            })
            .collect::<Vec<_>>();
        assert_eq!(inputs.len(), 1);
        let spend = intent(
            &source,
            &trust,
            inputs,
            vec![Payment {
                owner: public(10),
                amount: Amount(19),
            }],
            Some(destination.region),
            Some(Payment {
                owner: public(11),
                amount: Amount(80),
            }),
            1,
            2,
            &[10],
        );
        let export = spend.intent.id().unwrap();
        let s3 = bft_cut_advance(
            &mut source,
            &trust,
            &mut verified,
            &mut evidence,
            vec![Command::Spend(Box::new(spend))],
        );
        let s4 = bft_cut_advance(&mut source, &trust, &mut verified, &mut evidence, vec![]);
        assert_eq!(
            verified.export(s3, export).unwrap(),
            verified.export(s4, export).unwrap()
        );
        let d1 = bft_cut_advance(
            &mut destination,
            &trust,
            &mut verified,
            &mut evidence,
            vec![Command::Import {
                snapshot: s4,
                export,
            }],
        );
        assert_eq!(evidence.snapshots.len(), 5);
        assert_eq!(source.height(), 4);
        assert_eq!(destination.height(), 1);
        assert_eq!(destination.ledger.imports[&export], s4);
        Self {
            bootstrap,
            trust,
            source,
            destination,
            verified,
            evidence,
            s3,
            s4,
            d1,
            export,
        }
    }

    fn selection(&self, source: Hash) -> Vec<Selection> {
        vec![
            Selection {
                region: self.source.region,
                checkpoint: source,
            },
            Selection {
                region: self.destination.region,
                checkpoint: self.d1,
            },
        ]
    }

    fn check(
        &self,
        evidence: &Evidence,
        selection: &[Selection],
    ) -> Result<crate::causal_cut::Report> {
        inspect(
            &self.bootstrap,
            &public(1),
            self.trust.currency().unwrap(),
            evidence,
            selection,
        )
    }
}

#[test]
fn original_bft_full_prefix_causal_cut_component_counter() {
    let mut f = BftCutFixture::new();
    let original = serde_json::to_vec(&(&f.bootstrap, &f.evidence)).unwrap();
    // Independently reauthenticate all complete evidence from the pinned genesis.
    let cold = VerifiedEvidence::verify(&f.evidence, &f.trust).unwrap();
    let replay = |checkpoint| {
        cold.replay_extension(cold.snapshot(checkpoint).unwrap(), &f.trust)
            .unwrap()
    };
    let expected = (Amount(300), Amount(300), Amount::ZERO, Amount::ZERO);
    assert_eq!(
        conservation_with_escrow(&[replay(f.s3), replay(f.d1)]).unwrap(),
        expected
    );
    eprintln!("original BFT Native construction complete: S1/S2/S3/S4/D1; complete cold evidence verified; S3+D1 amount helper returns I=300 U=300 E=0 T=0");
    let choices = f.selection(f.s4);
    // A complete closed BFT cut releases only historical accounting totals.
    let good = f.check(&f.evidence, &choices).unwrap();
    assert_eq!(
        (good.issued, good.liquid, good.escrow, good.pending_transfer),
        expected
    );
    assert_eq!(good.selected[0].id().unwrap(), f.s4);
    assert_eq!(good.selected[1].id().unwrap(), f.d1);
    assert!(!good.ledger_changed && !good.signing_authority);
    assert!(!good.current_spendability_authority && !good.independent_freshness_verified);
    assert!(!good.incident_safety_verified);
    assert_eq!(
        f.check(&f.evidence, &f.selection(f.s3)).unwrap_err(),
        "selected history precedes required checkpoint"
    );
    let pending = f.check(&f.evidence, &choices[..1]).unwrap();
    assert_eq!(
        (
            pending.issued,
            pending.liquid,
            pending.escrow,
            pending.pending_transfer
        ),
        (Amount(300), Amount(220), Amount::ZERO, Amount(80))
    );
    assert_eq!(f.destination.ledger.imports[&f.export], f.s4);
    assert!(f
        .destination
        .ledger
        .coins
        .values()
        .all(|coin| coin.mature == 3));
    assert_eq!(
        serde_json::to_vec(&(&f.bootstrap, &f.evidence)).unwrap(),
        original
    );

    // Later valid evidence authenticates but cannot advance the selected cut.
    let s5 = bft_cut_advance(
        &mut f.source,
        &f.trust,
        &mut f.verified,
        &mut f.evidence,
        vec![],
    );
    assert_ne!(s5, f.s4);
    let complete = serde_json::to_vec(&(&f.bootstrap, &f.evidence)).unwrap();
    let later = f.check(&f.evidence, &choices).unwrap();
    assert_eq!(later.selected, good.selected);
    assert_eq!(
        (
            later.issued,
            later.liquid,
            later.escrow,
            later.pending_transfer
        ),
        expected
    );
    assert_ne!(later.request_commitment, good.request_commitment);
    let mut bad = f.evidence.clone();
    bad.snapshots
        .last_mut()
        .unwrap()
        .bft
        .as_mut()
        .unwrap()
        .committed
        .votes[0]
        .approval
        .signature = "00".repeat(64);
    assert!(
        f.check(&bad, &choices).is_err(),
        "bad complete later certificate returned a report"
    );
    // Full Native authentication must precede even the known nonclosed-cut error.
    let native_error = VerifiedEvidence::verify(&bad, &f.trust).err().unwrap();
    assert_eq!(f.check(&bad, &f.selection(f.s3)).unwrap_err(), native_error);

    let mut duplicate = f.evidence.clone();
    duplicate.snapshots.push(duplicate.snapshots[3].clone());
    f.check(&duplicate, &choices).unwrap();
    let last = duplicate.snapshots.last_mut().unwrap();
    assert_eq!(last.statement.id().unwrap(), f.s4);
    last.bft.as_mut().unwrap().committed.votes[0]
        .approval
        .signature = "00".repeat(64);
    assert!(
        f.check(&duplicate, &choices).is_err(),
        "duplicate body hid an invalid certificate"
    );
    for missing in [1, 3] {
        let mut bad = f.evidence.clone();
        bad.snapshots.remove(missing); // S2 or the exact imported S4.
        assert!(f.check(&bad, &choices).is_err());
    }
    // No forged-signature positive: only negative copies mutate authority fields.
    for mutation in 0..5 {
        let mut bad = f.evidence.clone();
        let snapshot = &mut bad.snapshots[3];
        match mutation {
            0 => snapshot.bft = None,
            1 => snapshot.approvals.push(Approval {
                key: public(2),
                signature: "00".repeat(64),
            }),
            2 => {
                let q = &mut snapshot.bft.as_mut().unwrap().committed;
                q.votes[1] = q.votes[0].clone();
            }
            3 => snapshot.bft.as_mut().unwrap().committed.phase = bft::Phase::Prepare,
            4 => snapshot.bft.as_mut().unwrap().committed.round += 1,
            _ => unreachable!(),
        }
        assert!(
            f.check(&bad, &choices).is_err(),
            "authority mutation {mutation} accepted"
        );
    }
    let mut bad = f.evidence.clone();
    bad.snapshots[0].statement.height = 0;
    assert!(f.check(&bad, &choices).is_err());
    bad = f.evidence.clone();
    bad.snapshots[3].base = Some(f.s3);
    assert_eq!(
        f.check(&bad, &choices).unwrap_err(),
        "causal cut unsupported history profile"
    );
    bad = f.evidence.clone();
    bad.snapshots[3].statement.epoch = Hash::ZERO;
    assert_eq!(
        f.check(&bad, &choices).unwrap_err(),
        "causal cut unsupported history profile"
    );
    assert_eq!(
        f.check(&f.evidence, &choices[1..]).unwrap_err(),
        "causal cut omits required source region"
    );
    assert!(f
        .check(&f.evidence, &[choices[0].clone(), choices[0].clone()])
        .is_err());
    let mut mislabeled = choices.clone();
    mislabeled[0].region = f.destination.region;
    assert!(f.check(&f.evidence, &mislabeled).is_err());
    assert!(inspect(
        &f.bootstrap,
        &public(2),
        f.trust.currency().unwrap(),
        &f.evidence,
        &choices
    )
    .is_err());
    assert!(inspect(&f.bootstrap, &public(1), Hash::ZERO, &f.evidence, &choices).is_err());

    // These signed bootstrap variants independently pass Trust, then refuse at
    // the exact homogeneous-profile gate before mismatched evidence is examined.
    for rule in [
        DOMAIN,
        segmented::RULES,
        bft::EPOCH_RULES,
        bft::JOINT_RULES,
        bft::ROLE_RULES,
    ] {
        let mut other = f.bootstrap.clone();
        if rule == DOMAIN {
            other.admissions[0].rules = rule.into(); // Mixed unanimous/BFT.
        } else {
            for admission in &mut other.admissions {
                admission.rules = rule.into();
            }
        }
        for admission in &mut other.admissions {
            admission.signature = signature(1, &admission.bytes().unwrap());
        }
        let pin = other.currency.id().unwrap();
        Trust::verify(&other, &public(1), pin).unwrap();
        assert_eq!(
            inspect(&other, &public(1), pin, &f.evidence, &choices).unwrap_err(),
            "causal cut supports only homogeneous original unanimous or BFT admissions"
        );
    }
    // Valid current channel/paged bootstraps also reach the exact refusal gate;
    // their separate issuance/rule signatures are not replaced with legacy ones.
    for rule in [
        channels::BFT_RULES,
        channels::SEGMENTED_RULES,
        crate::paged_bft::RULES,
        crate::paged_bft::PACKED_RULES,
        crate::paged_bft::ORIGIN_HISTORY_RULES,
        crate::paged_bft::ORIGIN_NETWORK_RULES,
    ] {
        let mut other = super::channel_integration::package(rule);
        if crate::paged_bft::is_profile(rule) {
            for admission in &mut other.admissions {
                admission.value_rules = Some(crate::paged_bft::rules_hash_for(rule).unwrap());
                admission.signature = signature(1, &admission.bytes().unwrap());
            }
        }
        let pin = other.currency.id().unwrap();
        Trust::verify(&other, &public(1), pin).unwrap();
        assert_eq!(
            inspect(&other, &public(1), pin, &f.evidence, &choices).unwrap_err(),
            "causal cut supports only homogeneous original unanimous or BFT admissions"
        );
    }
    assert_eq!(
        serde_json::to_vec(&(&f.bootstrap, &f.evidence)).unwrap(),
        complete
    );
    eprintln!("original BFT historical cut: closed S4+D1 I=300 U=300 E=0 T=0; amount-valid S3+D1 refused; complete later/duplicate certificates and prefix/profile guards exercised; no custody, current spendability, incident or adoption qualification");
}
