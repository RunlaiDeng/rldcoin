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
        "causal cut supports only original unanimous admissions"
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
