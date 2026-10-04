use super::*;
use ed25519_dalek::SigningKey;
use rld_core::sign_bytes;
use std::path::PathBuf;
use storage::Store;
fn public(seed: u8) -> String {
    hex::encode(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
}
fn signature(seed: u8, bytes: &[u8]) -> String {
    sign_bytes(&hex::encode([seed; 32]), bytes).unwrap()
}
fn keys() -> Vec<u8> {
    let mut seeds = vec![2, 3, 4, 5];
    seeds.sort_by_key(|s| public(*s));
    seeds
}
fn bootstrap() -> Bootstrap {
    let mut currency = Currency {
        format: DOMAIN.into(),
        fixture_only: true,
        implementation: implementation().unwrap(),
        origin: "earth".into(),
        authority: public(1),
        cap: Amount(300),
        block_reward: Amount(100),
        maturity: 2,
        signature: String::new(),
    };
    currency.signature = signature(1, &currency.bytes().unwrap());
    let admissions = ["earth", "proxima", "andromeda"]
        .into_iter()
        .map(|region| {
            let mut a = Admission {
                currency: currency.id().unwrap(),
                region: region.into(),
                rules: DOMAIN.into(),
                validators: keys().into_iter().map(public).collect(),
                signature: String::new(),
            };
            a.signature = signature(1, &a.bytes().unwrap());
            a
        })
        .collect();
    Bootstrap {
        currency,
        admissions,
    }
}
fn checkpoint(chain: &Chain, trust: &Trust) -> Snapshot {
    let statement = chain.statement(trust).unwrap();
    let approvals = keys()
        .into_iter()
        .map(|seed| Approval {
            key: public(seed),
            signature: signature(seed, &statement.bytes().unwrap()),
        })
        .collect();
    Snapshot {
        base: chain.snapshot_base(),
        bft: None,
        statement,
        approvals,
        blocks: chain.blocks.clone(),
        epochs: vec![],
    }
}
fn advance(chain: &mut Chain, trust: &Trust, evidence: &VerifiedEvidence, commands: Vec<Command>) {
    let mut block = chain
        .template(commands, public(10), trust, evidence)
        .unwrap();
    mine(&mut block).unwrap();
    chain.accept(block, trust, evidence).unwrap();
}
fn finalize(chain: &mut Chain, trust: &Trust, evidence: &mut VerifiedEvidence) -> Hash {
    let sid = evidence.add(checkpoint(chain, trust), trust).unwrap();
    chain.install(sid, evidence).unwrap();
    sid
}
#[allow(clippy::too_many_arguments)] // Fixture builder mirrors the signed wire fields.
fn intent(
    chain: &Chain,
    trust: &Trust,
    inputs: Vec<Hash>,
    outputs: Vec<Payment>,
    destination: Option<Hash>,
    remote: Option<Payment>,
    fee: u128,
    destination_fee: u128,
    seeds: &[u8],
) -> SignedIntent {
    let mut inputs = inputs;
    inputs.sort();
    let intent = Intent {
        currency: trust.currency().unwrap(),
        region: chain.region,
        inputs,
        outputs,
        fee: Amount(fee),
        destination,
        remote,
        destination_fee: Amount(destination_fee),
        valid_through: if chain.is_segmented() {
            chain.height() + 32
        } else {
            100
        },
    };
    let mut approvals = seeds
        .iter()
        .map(|seed| Approval {
            key: public(*seed),
            signature: signature(*seed, &intent.bytes().unwrap()),
        })
        .collect::<Vec<_>>();
    approvals.sort_by(|a, b| a.key.cmp(&b.key));
    SignedIntent { intent, approvals }
}
fn coins(chain: &Chain, owner: u8) -> Vec<Hash> {
    chain
        .ledger
        .coins
        .iter()
        .filter(|(_, c)| c.payment.owner == public(owner) && c.mature <= chain.height() + 1)
        .map(|(id, _)| *id)
        .collect()
}
struct Fixture {
    trust: Trust,
    earth: Chain,
    proxima: Chain,
    andromeda: Chain,
    evidence: VerifiedEvidence,
}
#[path = "carriage_tests.rs"]
mod carriage;
#[path = "stream_archive_tests.rs"]
mod compact_stream_archives;
#[path = "segmented_tests.rs"]
mod segmented_histories;
#[path = "state_proof_tests.rs"]
mod state_proofs;
#[path = "stream_replay_tests.rs"]
mod stream_replays;
impl Fixture {
    fn new() -> Self {
        let b = bootstrap();
        let trust = Trust::verify(&b, &public(1), b.currency.id().unwrap()).unwrap();
        let mut earth = Chain::new(trust.named("earth").unwrap(), &trust).unwrap();
        let proxima = Chain::new(trust.named("proxima").unwrap(), &trust).unwrap();
        let andromeda = Chain::new(trust.named("andromeda").unwrap(), &trust).unwrap();
        let mut evidence = VerifiedEvidence::default();
        for _ in 0..4 {
            advance(&mut earth, &trust, &evidence, vec![]);
        }
        finalize(&mut earth, &trust, &mut evidence);
        Self {
            trust,
            earth,
            proxima,
            andromeda,
            evidence,
        }
    }
    fn audit(&self) {
        conservation(&[
            self.earth.clone(),
            self.proxima.clone(),
            self.andromeda.clone(),
        ])
        .unwrap();
    }
    fn export_earth(&mut self) -> (Hash, Hash) {
        let signed = intent(
            &self.earth,
            &self.trust,
            vec![coins(&self.earth, 10)[0]],
            vec![Payment {
                owner: public(10),
                amount: Amount(19),
            }],
            Some(self.proxima.region),
            Some(Payment {
                owner: public(11),
                amount: Amount(80),
            }),
            1,
            2,
            &[10],
        );
        let eid = signed.intent.id().unwrap();
        advance(
            &mut self.earth,
            &self.trust,
            &self.evidence,
            vec![Command::Spend(Box::new(signed))],
        );
        self.audit();
        let sid = finalize(&mut self.earth, &self.trust, &mut self.evidence);
        (sid, eid)
    }
    fn imported(&mut self) -> (Hash, Hash) {
        let (sid, eid) = self.export_earth();
        advance(
            &mut self.proxima,
            &self.trust,
            &self.evidence,
            vec![Command::Import {
                snapshot: sid,
                export: eid,
            }],
        );
        self.audit();
        (sid, eid)
    }
}
#[test]
fn currency_and_offline_admission_are_exact() {
    let b = bootstrap();
    let pin = b.currency.id().unwrap();
    Trust::verify(&b, &public(1), pin).unwrap();
    assert!(Trust::verify(&b, &public(2), pin).is_err());
    assert!(Trust::verify(&b, &public(1), Hash([9; 32])).is_err());
    let mut bad = b.clone();
    bad.currency.fixture_only = false;
    assert!(Trust::verify(&bad, &public(1), pin).is_err());
    bad = b.clone();
    bad.admissions[1].validators[0] = public(11);
    assert!(Trust::verify(&bad, &public(1), pin).is_err());
    bad = b;
    bad.admissions[1].rules = "unknown".into();
    assert!(Trust::verify(&bad, &public(1), pin).is_err());
}
#[test]
fn three_region_onward_and_value_return_preserve_supply() {
    let mut f = Fixture::new();
    let (_, first) = f.imported();
    for _ in 0..2 {
        advance(&mut f.proxima, &f.trust, &f.evidence, vec![]);
    }
    finalize(&mut f.proxima, &f.trust, &mut f.evidence);
    let pay = intent(
        &f.proxima,
        &f.trust,
        coins(&f.proxima, 11),
        vec![
            Payment {
                owner: public(12),
                amount: Amount(30),
            },
            Payment {
                owner: public(11),
                amount: Amount(47),
            },
        ],
        None,
        None,
        1,
        0,
        &[11],
    );
    advance(
        &mut f.proxima,
        &f.trust,
        &f.evidence,
        vec![Command::Spend(Box::new(pay))],
    );
    f.audit();
    finalize(&mut f.proxima, &f.trust, &mut f.evidence);
    let onward = intent(
        &f.proxima,
        &f.trust,
        coins(&f.proxima, 12),
        vec![],
        Some(f.andromeda.region),
        Some(Payment {
            owner: public(12),
            amount: Amount(29),
        }),
        1,
        1,
        &[12],
    );
    let second = onward.intent.id().unwrap();
    advance(
        &mut f.proxima,
        &f.trust,
        &f.evidence,
        vec![Command::Spend(Box::new(onward))],
    );
    f.audit();
    let sid = finalize(&mut f.proxima, &f.trust, &mut f.evidence);
    advance(
        &mut f.andromeda,
        &f.trust,
        &f.evidence,
        vec![Command::Import {
            snapshot: sid,
            export: second,
        }],
    );
    f.audit();
    for _ in 0..2 {
        advance(&mut f.andromeda, &f.trust, &f.evidence, vec![]);
    }
    finalize(&mut f.andromeda, &f.trust, &mut f.evidence);
    let back = intent(
        &f.andromeda,
        &f.trust,
        coins(&f.andromeda, 12),
        vec![],
        Some(f.earth.region),
        Some(Payment {
            owner: public(13),
            amount: Amount(27),
        }),
        1,
        1,
        &[12],
    );
    let third = back.intent.id().unwrap();
    advance(
        &mut f.andromeda,
        &f.trust,
        &f.evidence,
        vec![Command::Spend(Box::new(back))],
    );
    let sid = finalize(&mut f.andromeda, &f.trust, &mut f.evidence);
    f.audit();
    advance(
        &mut f.earth,
        &f.trust,
        &f.evidence,
        vec![Command::Import {
            snapshot: sid,
            export: third,
        }],
    );
    f.audit();
    assert!(f.earth.ledger.imports.contains_key(&third));
    assert!(f.earth.ledger.exports.contains_key(&first));
    assert_ne!(first, third);
    assert_eq!(
        conservation(&[f.earth, f.proxima, f.andromeda]).unwrap().0,
        Amount(300)
    );
}
#[test]
fn immature_or_unfinalized_onward_exports_are_rejected() {
    let mut f = Fixture::new();
    f.imported();
    let input = *f
        .proxima
        .ledger
        .coins
        .iter()
        .find(|(_, c)| c.payment.owner == public(11))
        .unwrap()
        .0;
    let export = intent(
        &f.proxima,
        &f.trust,
        vec![input],
        vec![],
        Some(f.andromeda.region),
        Some(Payment {
            owner: public(11),
            amount: Amount(78),
        }),
        0,
        0,
        &[11],
    );
    let root = f.proxima.ledger.root().unwrap();
    assert!(f
        .proxima
        .template(
            vec![Command::Spend(Box::new(export.clone()))],
            public(10),
            &f.trust,
            &f.evidence
        )
        .is_err());
    for _ in 0..2 {
        advance(&mut f.proxima, &f.trust, &f.evidence, vec![]);
    }
    assert!(f
        .proxima
        .template(
            vec![Command::Spend(Box::new(export))],
            public(10),
            &f.trust,
            &f.evidence
        )
        .is_err());
    assert_eq!(root, f.proxima.ledger.root().unwrap());
}
#[test]
fn wrong_destination_replay_and_incomplete_evidence_fail_atomically() {
    let mut f = Fixture::new();
    let (sid, eid) = f.imported();
    let replay = Command::Import {
        snapshot: sid,
        export: eid,
    };
    let root = f.proxima.ledger.root().unwrap();
    assert!(f
        .proxima
        .template(vec![replay.clone()], public(10), &f.trust, &f.evidence)
        .is_err());
    assert!(f
        .andromeda
        .template(vec![replay.clone()], public(10), &f.trust, &f.evidence)
        .is_err());
    let empty = VerifiedEvidence::default();
    assert!(f
        .andromeda
        .template(vec![replay], public(10), &f.trust, &empty)
        .is_err());
    assert_eq!(root, f.proxima.ledger.root().unwrap());
}
#[test]
fn source_certificate_forgery_fork_and_rollback_rejected() {
    let mut f = Fixture::new();
    let (sid, _) = f.export_earth();
    let s = f.evidence.snapshot(sid).unwrap().clone();
    let mut forged = s.clone();
    forged.approvals[0].signature = "00".into();
    assert!(VerifiedEvidence::default().add(forged, &f.trust).is_err());
    let mut missing = s;
    missing.statement.previous = None;
    assert!(f.evidence.add(missing, &f.trust).is_err());
    let initial = f
        .evidence
        .snapshots
        .values()
        .min_by_key(|(s, _)| s.statement.height)
        .unwrap()
        .0
        .clone();
    let old = initial.statement.id().unwrap();
    assert!(f.earth.install(old, &f.evidence).is_err());
}
#[test]
fn tampered_block_or_signature_never_changes_state() {
    let mut f = Fixture::new();
    let signed = intent(
        &f.earth,
        &f.trust,
        vec![coins(&f.earth, 10)[0]],
        vec![Payment {
            owner: public(11),
            amount: Amount(99),
        }],
        None,
        None,
        1,
        0,
        &[10],
    );
    let mut bad = signed.clone();
    bad.intent.outputs[0].amount = Amount(100);
    assert!(f
        .earth
        .template(
            vec![Command::Spend(Box::new(bad))],
            public(10),
            &f.trust,
            &f.evidence
        )
        .is_err());
    let mut block = f
        .earth
        .template(
            vec![Command::Spend(Box::new(signed))],
            public(10),
            &f.trust,
            &f.evidence,
        )
        .unwrap();
    block.header.state = Hash([9; 32]);
    mine(&mut block).unwrap();
    let root = f.earth.ledger.root().unwrap();
    assert!(f.earth.accept(block, &f.trust, &f.evidence).is_err());
    assert_eq!(root, f.earth.ledger.root().unwrap());
}
#[test]
fn split_merge_multiple_owners_and_fee_conserve() {
    let mut f = Fixture::new();
    let split = intent(
        &f.earth,
        &f.trust,
        vec![coins(&f.earth, 10)[0]],
        vec![
            Payment {
                owner: public(11),
                amount: Amount(40),
            },
            Payment {
                owner: public(12),
                amount: Amount(59),
            },
        ],
        None,
        None,
        1,
        0,
        &[10],
    );
    advance(
        &mut f.earth,
        &f.trust,
        &f.evidence,
        vec![Command::Spend(Box::new(split))],
    );
    let mut inputs = coins(&f.earth, 11);
    inputs.extend(coins(&f.earth, 12));
    let merge = intent(
        &f.earth,
        &f.trust,
        inputs,
        vec![Payment {
            owner: public(13),
            amount: Amount(97),
        }],
        None,
        None,
        2,
        0,
        &[11, 12],
    );
    let mut bad = merge.clone();
    bad.approvals.pop();
    assert!(f
        .earth
        .template(
            vec![Command::Spend(Box::new(bad))],
            public(10),
            &f.trust,
            &f.evidence
        )
        .is_err());
    advance(
        &mut f.earth,
        &f.trust,
        &f.evidence,
        vec![Command::Spend(Box::new(merge))],
    );
    f.audit();
}
#[test]
fn journal_lock_restart_tombstones_and_corruption() {
    let mut f = Fixture::new();
    let (sid, eid) = f.imported();
    let root = std::fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "rld-regional-{}",
            rld_core::generate_identity().public_key
        ));
    let b = bootstrap();
    let pin = b.currency.id().unwrap();
    let mut store = Store::create(&root, b, f.proxima.region, &public(1), pin).unwrap();
    let mut reversed = f
        .evidence
        .snapshots
        .values()
        .map(|(s, _)| s.clone())
        .collect::<Vec<_>>();
    reversed.sort_by_key(|s| std::cmp::Reverse(s.statement.height));
    store
        .add_evidence(Evidence {
            snapshots: reversed,
        })
        .unwrap_err(); // Dependency order must be complete before consumption.
    let mut list = f
        .evidence
        .snapshots
        .values()
        .map(|(s, _)| s.clone())
        .collect::<Vec<_>>();
    list.sort_by_key(|s| s.statement.height);
    store.add_evidence(Evidence { snapshots: list }).unwrap();
    for block in &f.proxima.blocks {
        store.accept(block.clone()).unwrap();
    }
    let state = store.chain.ledger.root().unwrap();
    assert!(Store::open(&root, &public(1), pin).is_err());
    drop(store);
    let store = Store::open(&root, &public(1), pin).unwrap();
    assert_eq!(state, store.chain.ledger.root().unwrap());
    assert!(store
        .chain
        .template(
            vec![Command::Import {
                snapshot: sid,
                export: eid
            }],
            public(10),
            &store.trust,
            &store.evidence
        )
        .is_err());
    drop(store);
    std::fs::write(root.join("journal.json"), b"{}").unwrap();
    assert!(Store::open(&root, &public(1), pin).is_err());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn duplicate_inputs_bad_amounts_wrong_currency_and_expiry_reject() {
    let f = Fixture::new();
    let signed = intent(
        &f.earth,
        &f.trust,
        vec![coins(&f.earth, 10)[0]],
        vec![Payment {
            owner: public(11),
            amount: Amount(99),
        }],
        None,
        None,
        1,
        0,
        &[10],
    );
    for case in 0..4 {
        let mut bad = signed.clone();
        match case {
            0 => bad.intent.inputs.push(bad.intent.inputs[0]),
            1 => bad.intent.outputs[0].amount = Amount(u128::MAX),
            2 => bad.intent.currency = Hash([9; 32]),
            _ => bad.intent.valid_through = 0,
        }
        bad.approvals[0].signature = signature(10, &bad.intent.bytes().unwrap());
        assert!(f
            .earth
            .template(
                vec![Command::Spend(Box::new(bad))],
                public(10),
                &f.trust,
                &f.evidence
            )
            .is_err());
    }
}
#[test]
fn a_later_invalid_command_rolls_back_the_entire_block() {
    let f = Fixture::new();
    let signed = intent(
        &f.earth,
        &f.trust,
        vec![coins(&f.earth, 10)[0]],
        vec![Payment {
            owner: public(11),
            amount: Amount(99),
        }],
        None,
        None,
        1,
        0,
        &[10],
    );
    let root = f.earth.ledger.root().unwrap();
    let command = Command::Spend(Box::new(signed));
    assert!(f
        .earth
        .template(
            vec![command.clone(), command],
            public(10),
            &f.trust,
            &f.evidence
        )
        .is_err());
    assert_eq!(root, f.earth.ledger.root().unwrap());
}
#[test]
fn zero_regional_issuance_and_no_time_or_receipt_refund() {
    let mut f = Fixture::new();
    let (_, export) = f.export_earth();
    let original = f.earth.ledger.exports[&export].clone();
    for _ in 0..12 {
        advance(&mut f.proxima, &f.trust, &f.evidence, vec![]);
        advance(&mut f.andromeda, &f.trust, &f.evidence, vec![]);
        f.audit();
    }
    assert_eq!(f.proxima.ledger.minted, Amount::ZERO);
    assert_eq!(f.andromeda.ledger.minted, Amount::ZERO);
    assert_eq!(original, f.earth.ledger.exports[&export]);
    assert_eq!(
        conservation(&[f.earth, f.proxima, f.andromeda]).unwrap().2,
        Amount(80)
    );
}
#[test]
fn signed_fork_below_finality_and_missing_checkpoint_dependency_fail() {
    let mut f = Fixture::new();
    let latest = f.earth.finalized.unwrap();
    let accepted = f.evidence.snapshot(latest).unwrap().clone();
    let mut fork = Chain::new(f.earth.region, &f.trust).unwrap();
    let mut block = fork
        .template(vec![], public(11), &f.trust, &VerifiedEvidence::default())
        .unwrap();
    mine(&mut block).unwrap();
    fork.accept(block, &f.trust, &VerifiedEvidence::default())
        .unwrap();
    let root = f.earth.ledger.root().unwrap();
    assert!(f
        .earth
        .accept(fork.blocks[0].clone(), &f.trust, &f.evidence)
        .is_err());
    let mut certificate = checkpoint(&fork, &f.trust);
    certificate.statement.previous = Some(latest);
    certificate.approvals = keys()
        .into_iter()
        .map(|seed| Approval {
            key: public(seed),
            signature: signature(seed, &certificate.statement.bytes().unwrap()),
        })
        .collect();
    assert!(f.evidence.add(certificate, &f.trust).is_err());
    assert_eq!(root, f.earth.ledger.root().unwrap());
    // Even correctly signed onward snapshots cannot bypass an absent source DAG.
    let (source, _) = f.export_earth();
    let snapshot = f.evidence.snapshot(source).unwrap().clone();
    assert!(VerifiedEvidence::default().add(snapshot, &f.trust).is_err());
    assert!(VerifiedEvidence::default().add(accepted, &f.trust).is_ok());
}
#[test]
fn disk_refusal_keeps_previous_journal_and_requires_restart() {
    let b = bootstrap();
    let pin = b.currency.id().unwrap();
    let trust = Trust::verify(&b, &public(1), pin).unwrap();
    let root = std::fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "rld-disk-refusal-{}",
            rld_core::generate_identity().public_key
        ));
    let mut store =
        Store::create(&root, b, trust.named("earth").unwrap(), &public(1), pin).unwrap();
    let before = std::fs::read(root.join("journal.json")).unwrap();
    std::fs::write(root.join("journal.next"), b"operator-inspect-residue").unwrap();
    let mut block = store
        .chain
        .template(vec![], public(10), &store.trust, &store.evidence)
        .unwrap();
    mine(&mut block).unwrap();
    assert!(store.accept(block.clone()).is_err());
    assert_eq!(before, std::fs::read(root.join("journal.json")).unwrap());
    std::fs::remove_file(root.join("journal.next")).unwrap();
    assert!(store.accept(block.clone()).is_err());
    drop(store);
    let mut reopened = Store::open(&root, &public(1), pin).unwrap();
    reopened.accept(block).unwrap();
    drop(reopened);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn resource_bounds_reject_without_destroying_evidence() {
    let mut f = Fixture::new();
    let (snapshot, export) = f.export_earth();
    let before = f.proxima.ledger.root().unwrap();
    let commands = vec![Command::Import { snapshot, export }; MAX_COMMANDS + 1];
    assert!(f
        .proxima
        .template(commands, public(10), &f.trust, &f.evidence)
        .is_err());
    assert_eq!(before, f.proxima.ledger.root().unwrap());
    let s = f.evidence.snapshot(snapshot).unwrap().clone();
    let oversized = Evidence {
        snapshots: vec![s; MAX_SNAPSHOTS + 1],
    };
    assert!(VerifiedEvidence::verify(&oversized, &f.trust).is_err());
    let file = std::fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "rld-oversize-{}",
            rld_core::generate_identity().public_key
        ));
    let opened = std::fs::File::create(&file).unwrap();
    opened.set_len(MAX_BYTES as u64 + 1).unwrap();
    assert!(storage::read_json::<Evidence>(&file).is_err());
    std::fs::remove_file(file).unwrap();
}
#[cfg(unix)]
#[test]
fn symlinked_store_and_evidence_are_rejected() {
    let dir = std::fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "rld-symlink-{}",
            rld_core::generate_identity().public_key
        ));
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("real"), b"{}").unwrap();
    std::os::unix::fs::symlink(dir.join("real"), dir.join("link")).unwrap();
    assert!(storage::read_json::<Evidence>(&dir.join("link")).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}

fn fork_snapshot(f: &Fixture, height: usize) -> Snapshot {
    let mut fork = Chain::new(f.earth.region, &f.trust).unwrap();
    let empty = VerifiedEvidence::default();
    for _ in 0..height {
        let mut block = fork.template(vec![], public(13), &f.trust, &empty).unwrap();
        mine(&mut block).unwrap();
        fork.accept(block, &f.trust, &empty).unwrap();
    }
    checkpoint(&fork, &f.trust)
}
fn conflict_proof(f: &Fixture) -> conflict::Conflict {
    let accepted = f.evidence.snapshot(f.earth.finalized.unwrap()).unwrap();
    conflict::Conflict::from_snapshots(accepted, &fork_snapshot(f, f.earth.height() as usize + 1))
        .unwrap()
}
fn evidence_archive(evidence: &VerifiedEvidence, trust: &Trust) -> Evidence {
    let mut pending = evidence
        .snapshots
        .values()
        .map(|(s, _)| s.clone())
        .collect::<Vec<_>>();
    let mut verified = VerifiedEvidence::default();
    let mut ordered = vec![];
    while !pending.is_empty() {
        let index = pending
            .iter()
            .position(|s| verified.add(s.clone(), trust).is_ok())
            .expect("acyclic verified archive");
        ordered.push(pending.remove(index));
    }
    Evidence { snapshots: ordered }
}
fn stored_fixture(f: &Fixture, chain: &Chain) -> (PathBuf, Store) {
    let root = std::fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "rld-incident-{}",
            rld_core::generate_identity().public_key
        ));
    let b = bootstrap();
    let mut store = Store::create(
        &root,
        b.clone(),
        chain.region,
        &public(1),
        b.currency.id().unwrap(),
    )
    .unwrap();
    store
        .add_evidence(evidence_archive(&f.evidence, &f.trust))
        .unwrap();
    for block in &chain.blocks {
        store.accept(block.clone()).unwrap();
    }
    (root, store)
}
#[test]
fn conflict_proof_authenticates_ancestry_at_different_heights() {
    let f = Fixture::new();
    let proof = conflict_proof(&f);
    proof.verify(&f.trust).unwrap();
    let mut forged = proof.clone();
    forged.left.headers[0].miner = public(14);
    assert!(forged.verify(&f.trust).is_err());
    forged = proof.clone();
    forged.right.approvals[0].signature = "00".into();
    assert!(forged.verify(&f.trust).is_err());
    forged = proof.clone();
    forged.right.approvals.pop();
    assert!(forged.verify(&f.trust).is_err());
    let old = f.evidence.snapshot(f.earth.finalized.unwrap()).unwrap();
    let compatible = conflict::Conflict::from_snapshots(old, old).unwrap();
    assert!(compatible.verify(&f.trust).is_err());
    let mut swapped = proof.clone();
    std::mem::swap(&mut swapped.left, &mut swapped.right);
    assert!(swapped.verify(&f.trust).is_err());
}
#[test]
fn compatible_incident_preflight_never_authenticates_or_retains_bad_evidence() {
    let mut f = Fixture::new();
    let old = f
        .evidence
        .snapshot(f.earth.finalized.unwrap())
        .unwrap()
        .clone();
    advance(&mut f.earth, &f.trust, &f.evidence, vec![]);
    let next = finalize(&mut f.earth, &f.trust, &mut f.evidence);
    let mut later = f.evidence.snapshot(next).unwrap().clone();
    // Distinct checkpoints share the exact certified block prefix. A bad
    // signature cannot turn that compatible structure into an incident.
    later.approvals[0].signature = "00".into();
    let compatible = conflict::Conflict::from_snapshots(&old, &later).unwrap();
    assert_eq!(
        compatible.verify(&f.trust).unwrap_err(),
        "compatible certificates are not conflict evidence"
    );
    assert!(conflict::CertifiedHistory::from_snapshot(&later)
        .verify(&f.trust)
        .is_err());
    let (root, mut store) = stored_fixture(&f, &f.earth);
    let before = std::fs::read(root.join("journal.json")).unwrap();
    let ledger = store.chain.ledger.root().unwrap();
    assert!(store
        .add_evidence(Evidence {
            snapshots: vec![later]
        })
        .is_err());
    assert_eq!(store.chain.ledger.root().unwrap(), ledger);
    assert_eq!(std::fs::read(root.join("journal.json")).unwrap(), before);
    assert!(store.conflicts.is_empty());
    // A potentially incompatible pair still needs both complete signatures.
    let mut actual = conflict_proof(&f);
    actual.verify(&f.trust).unwrap();
    actual.right.approvals[0].signature = "00".into();
    assert!(actual.verify(&f.trust).is_err());
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn automatic_conflict_preservation_survives_restart_without_refund() {
    let mut f = Fixture::new();
    f.imported();
    let (root, mut store) = stored_fixture(&f, &f.proxima);
    let before = store.chain.ledger.root().unwrap();
    let fork = fork_snapshot(&f, 6);
    assert!(store
        .add_evidence(Evidence {
            snapshots: vec![fork]
        })
        .is_err());
    assert_eq!(store.conflicts.len(), 1);
    assert_eq!(before, store.chain.ledger.root().unwrap());
    assert_eq!(
        store
            .safety
            .exposure(&store.chain, &store.evidence)
            .unwrap()
            .retained_coin_amount,
        Amount(80)
    );
    let proof = store.conflicts[0].clone();
    let iid = proof.id().unwrap();
    assert_eq!(store.observe_conflict(proof.clone()).unwrap(), iid);
    drop(store);
    let pin = bootstrap().currency.id().unwrap();
    let reopened = Store::open(&root, &public(1), pin).unwrap();
    assert_eq!(reopened.conflicts.len(), 1);
    assert_eq!(before, reopened.chain.ledger.root().unwrap());
    assert!(reopened.safety.regions.contains_key(&f.earth.region));
    drop(reopened);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn quarantine_is_dependency_scoped_and_cannot_be_bypassed_by_spend() {
    let mut f = Fixture::new();
    f.imported();
    for _ in 0..2 {
        advance(&mut f.proxima, &f.trust, &f.evidence, vec![]);
    }
    let (root, mut store) = stored_fixture(&f, &f.proxima);
    store.observe_conflict(conflict_proof(&f)).unwrap();
    let signed = intent(
        &store.chain,
        &f.trust,
        coins(&store.chain, 11),
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
    assert!(store
        .template(vec![Command::Spend(Box::new(signed.clone()))], public(10))
        .is_err());
    let mut bypass = store
        .chain
        .template(
            vec![Command::Spend(Box::new(signed))],
            public(10),
            &store.trust,
            &store.evidence,
        )
        .unwrap();
    mine(&mut bypass).unwrap();
    assert!(store.accept(bypass).is_err());
    let mut empty = store.template(vec![], public(10)).unwrap();
    mine(&mut empty).unwrap();
    store.accept(empty).unwrap(); // Unrelated local progress remains possible.
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
    let safety = conflict::Safety::from_conflicts(&[conflict_proof(&f)], &f.trust).unwrap();
    assert!(safety.check(&f.earth, &[], &f.evidence).is_err()); // The faulted region itself stops.
    assert!(safety.check(&f.andromeda, &[], &f.evidence).is_ok());
}
#[test]
fn propagated_faults_freeze_transitive_imports_but_leave_unrelated_region_free() {
    let mut f = Fixture::new();
    f.imported();
    for _ in 0..2 {
        advance(&mut f.proxima, &f.trust, &f.evidence, vec![]);
    }
    finalize(&mut f.proxima, &f.trust, &mut f.evidence);
    let export = intent(
        &f.proxima,
        &f.trust,
        coins(&f.proxima, 11),
        vec![],
        Some(f.andromeda.region),
        Some(Payment {
            owner: public(12),
            amount: Amount(78),
        }),
        0,
        0,
        &[11],
    );
    let eid = export.intent.id().unwrap();
    advance(
        &mut f.proxima,
        &f.trust,
        &f.evidence,
        vec![Command::Spend(Box::new(export))],
    );
    let sid = finalize(&mut f.proxima, &f.trust, &mut f.evidence);
    let safety = conflict::Safety::from_conflicts(&[conflict_proof(&f)], &f.trust).unwrap();
    assert!(safety
        .check(
            &f.andromeda,
            &[Command::Import {
                snapshot: sid,
                export: eid
            }],
            &f.evidence
        )
        .is_err());
    assert!(!safety.regions.contains_key(&f.proxima.region));
    assert!(!safety
        .exposure(&f.proxima, &f.evidence)
        .unwrap()
        .affected_historical_exports
        .is_empty());
}
#[test]
fn malformed_incident_never_freezes_or_changes_the_store() {
    let f = Fixture::new();
    let (root, mut store) = stored_fixture(&f, &f.andromeda);
    let before = store.chain.ledger.root().unwrap();
    let mut proof = conflict_proof(&f);
    proof.right.approvals[0].signature = "ff".into();
    assert!(store.observe_conflict(proof).is_err());
    assert!(store.conflicts.is_empty());
    assert_eq!(before, store.chain.ledger.root().unwrap());
    assert!(store.safety.regions.is_empty());
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn pending_guard_requires_the_exact_proof_and_recovery_keeps_quarantine() {
    let f = Fixture::new();
    let proof = conflict_proof(&f);
    let iid = proof.id().unwrap();
    let (root, store) = stored_fixture(&f, &f.andromeda);
    let pin = bootstrap().currency.id().unwrap();
    drop(store);
    std::fs::write(root.join("INCIDENT_GUARD"), iid.0).unwrap();
    assert!(Store::open(&root, &public(1), pin).is_err());
    let mut wrong = proof.clone();
    wrong.left.approvals[0].signature = "00".into();
    assert!(storage::recover_incident(&root, &public(1), pin, wrong).is_err());
    storage::recover_incident(&root, &public(1), pin, proof.clone()).unwrap();
    let store = Store::open(&root, &public(1), pin).unwrap();
    assert_eq!(store.conflicts.len(), 1);
    assert!(store.journal.incident_ids.contains(&iid));
    drop(store);
    std::fs::write(
        root.join("incidents")
            .join(format!("{}.json", iid.to_hex())),
        b"half-written",
    )
    .unwrap();
    assert!(Store::open(&root, &public(1), pin).is_err());
    storage::recover_incident(&root, &public(1), pin, proof).unwrap();
    let store = Store::open(&root, &public(1), pin).unwrap();
    assert!(store.safety.regions.contains_key(&f.earth.region));
    assert!(root
        .join(format!("damaged-incident-{}.bin", iid.to_hex()))
        .is_file());
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn simultaneous_competing_contacts_are_retained_without_accepting_a_branch() {
    let f = Fixture::new();
    let root = std::fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "rld-fresh-incidents-{}",
            rld_core::generate_identity().public_key
        ));
    let b = bootstrap();
    let mut store = Store::create(
        &root,
        b.clone(),
        f.andromeda.region,
        &public(1),
        b.currency.id().unwrap(),
    )
    .unwrap();
    let initial = store.chain.ledger.root().unwrap();
    let accepted = f
        .evidence
        .snapshot(f.earth.finalized.unwrap())
        .unwrap()
        .clone();
    let fork = fork_snapshot(&f, 5);
    assert!(store
        .add_evidence(Evidence {
            snapshots: vec![accepted, fork]
        })
        .is_err());
    assert_eq!(store.conflicts.len(), 1);
    assert_eq!(initial, store.chain.ledger.root().unwrap());
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn equivalent_signature_encoding_cannot_consume_more_incident_capacity() {
    let f = Fixture::new();
    let proof = conflict_proof(&f);
    let mut equivalent = proof.clone();
    for approval in &mut equivalent.left.approvals {
        approval.signature = approval.signature.to_uppercase();
    }
    equivalent.verify(&f.trust).unwrap();
    assert_eq!(proof.id().unwrap(), equivalent.id().unwrap());
    let (root, mut store) = stored_fixture(&f, &f.andromeda);
    store.observe_conflict(proof).unwrap();
    store.observe_conflict(equivalent).unwrap();
    assert_eq!(store.conflicts.len(), 1);
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn incident_capacity_failure_remains_closed_across_restart() {
    let f = Fixture::new();
    let (root, mut store) = stored_fixture(&f, &f.andromeda);
    let pin = bootstrap().currency.id().unwrap();
    let accepted = f.evidence.snapshot(f.earth.finalized.unwrap()).unwrap();
    for height in 5..5 + conflict::MAX_INCIDENTS {
        let proof =
            conflict::Conflict::from_snapshots(accepted, &fork_snapshot(&f, height)).unwrap();
        store.observe_conflict(proof).unwrap();
    }
    let extra = conflict::Conflict::from_snapshots(
        accepted,
        &fork_snapshot(&f, 5 + conflict::MAX_INCIDENTS),
    )
    .unwrap();
    assert!(store.observe_conflict(extra.clone()).is_err());
    drop(store);
    assert!(Store::open(&root, &public(1), pin).is_err());
    assert!(storage::recover_incident(&root, &public(1), pin, extra).is_err());
    assert_eq!(
        std::fs::read_dir(root.join("incidents")).unwrap().count(),
        conflict::MAX_INCIDENTS
    );
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn conflicting_finalization_is_preserved_before_rejection() {
    let f = Fixture::new();
    let (root, mut store) = stored_fixture(&f, &f.earth);
    let before = store.chain.ledger.root().unwrap();
    assert!(store.finalize(fork_snapshot(&f, 5)).is_err());
    assert_eq!(store.conflicts.len(), 1);
    assert_eq!(before, store.chain.ledger.root().unwrap());
    assert!(store.template(vec![], public(10)).is_err());
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn invalid_existing_incident_cannot_masquerade_as_persisted_proof() {
    let f = Fixture::new();
    let proof = conflict_proof(&f);
    let iid = proof.id().unwrap();
    let (root, mut store) = stored_fixture(&f, &f.andromeda);
    let mut damaged = proof.clone();
    damaged.right.approvals[0].signature = "00".into();
    std::fs::write(
        root.join("incidents")
            .join(format!("{}.json", iid.to_hex())),
        serde_json::to_vec(&damaged).unwrap(),
    )
    .unwrap();
    assert!(store.observe_conflict(proof.clone()).is_err());
    drop(store);
    let pin = bootstrap().currency.id().unwrap();
    assert!(Store::open(&root, &public(1), pin).is_err());
    storage::recover_incident(&root, &public(1), pin, proof).unwrap();
    let store = Store::open(&root, &public(1), pin).unwrap();
    assert_eq!(store.conflicts.len(), 1);
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[path = "epoch_tests.rs"]
mod epochs;

#[path = "contact_tests.rs"]
mod contacts;

#[path = "wallet_tests.rs"]
mod wallets;

#[path = "keystore_tests.rs"]
mod keystores;
#[path = "bft_tests.rs"]
mod regional_bft;
#[path = "wallet_agent_tests.rs"]
mod wallet_agents;

#[path = "native_prefix_tests.rs"]
pub(crate) mod native_prefix;

#[path = "history_archive_tests.rs"]
mod history_archives;

#[test]
fn pinned_history_refuses_unindexed_authenticated_incident_before_mutation() {
    let f = Fixture::new();
    let (root, store) = stored_fixture(&f, &f.proxima);
    let pin = store.trust.currency().unwrap();
    let head = crate::history::manifest(&root).unwrap().head().unwrap();
    let proof = conflict_proof(&f);
    proof.verify(&f.trust).unwrap();
    let iid = proof.id().unwrap();
    drop(store);
    std::fs::write(
        root.join("incidents")
            .join(format!("{}.json", iid.to_hex())),
        serde_json::to_vec(&proof).unwrap(),
    )
    .unwrap();
    let before = std::fs::read(root.join("journal.json")).unwrap();
    let unpinned = Store::open(&root, &public(1), pin).unwrap();
    assert!(unpinned.safety.regions.contains_key(&f.earth.region));
    drop(unpinned);
    let refusal = Store::open_pinned(&root, &public(1), pin, head)
        .err()
        .expect("an exact pinned head must cover every authenticated retained incident");
    assert!(refusal.contains("unindexed authenticated incidents"));
    assert_eq!(std::fs::read(root.join("journal.json")).unwrap(), before);
    assert!(root
        .join("incidents")
        .join(format!("{}.json", iid.to_hex()))
        .is_file());
    std::fs::remove_dir_all(root).unwrap();
}
