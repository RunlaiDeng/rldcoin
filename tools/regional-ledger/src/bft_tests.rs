use super::*;
use crate::bft::{
    self, Agent, Certificate, Context, Message, Phase, Proposal, Quorum, Request,
    TimeoutCertificate, TimeoutVote, Vote,
};
use std::{fs, path::Path};
struct Harness {
    root: PathBuf,
    node: Store,
    agents: Vec<Agent>,
    heads: Vec<Hash>,
    seeds: Vec<u8>,
}
impl Harness {
    fn new() -> Self {
        Self::with_rules(bft::RULES)
    }
    fn with_rules(rules: &str) -> Self {
        let mut package = bootstrap();
        for a in &mut package.admissions {
            a.rules = rules.into();
            a.signature = signature(1, &a.bytes().unwrap());
        }
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "rld-bft-{}",
                rld_core::generate_identity().public_key
            ));
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let currency = package.currency.id().unwrap();
        let region = package.admissions[0].id().unwrap();
        let node =
            Store::create(&root.join("node"), package, region, &public(1), currency).unwrap();
        let seeds = keys();
        let agents = seeds
            .iter()
            .map(|s| {
                crate::keystore::private_create(
                    &root.join(format!("key-{s}.json")),
                    serde_json::to_vec(&serde_json::json!({"secret_key":hex::encode([*s;32])}))
                        .unwrap()
                        .as_slice(),
                )
                .unwrap();
                Agent::create(&root.join(format!("signer-{s}")), &node, public(*s)).unwrap()
            })
            .collect::<Vec<_>>();
        let heads = agents.iter().map(|a| a.journal.head().unwrap()).collect();
        Self {
            root,
            node,
            agents,
            heads,
            seeds,
        }
    }
    fn sign(&mut self, n: usize, req: Request) -> bft::Signed {
        let result = self.agents[n]
            .sign(
                &self.node,
                req,
                Some(&self.root.join(format!("key-{}.json", self.seeds[n]))),
                self.heads[n],
            )
            .unwrap();
        self.heads[n] = result.head;
        result
    }
    fn proposal(
        &mut self,
        round: u64,
        timeout: Option<TimeoutCertificate>,
        snapshot: Snapshot,
    ) -> Proposal {
        let c = Context::current(&self.node).unwrap();
        let keys = self.seeds.iter().copied().map(public).collect::<Vec<_>>();
        let leader = bft::leader(&c, round, &keys).unwrap();
        let n = keys.iter().position(|k| k == &leader).unwrap();
        let Message::Proposal(p) = self
            .sign(
                n,
                Request::Propose {
                    round,
                    snapshot: Box::new(snapshot),
                    timeout,
                },
            )
            .message
        else {
            panic!()
        };
        *p
    }
    fn prepare(&mut self, p: &Proposal, indices: &[usize]) -> Quorum {
        let votes = indices
            .iter()
            .map(|n| {
                let Message::Vote(v) = self.sign(*n, Request::Prepare(Box::new(p.clone()))).message
                else {
                    panic!()
                };
                *v
            })
            .collect();
        Quorum::combine(votes, &self.node.trust, &self.node.evidence).unwrap()
    }
    fn commit(&mut self, p: &Proposal, q: &Quorum, indices: &[usize]) -> Snapshot {
        let votes = indices
            .iter()
            .map(|n| {
                let Message::Vote(v) = self
                    .sign(
                        *n,
                        Request::Commit {
                            proposal: Box::new(p.clone()),
                            prepared: q.clone(),
                        },
                    )
                    .message
                else {
                    panic!()
                };
                *v
            })
            .collect();
        let committed = Quorum::combine(votes, &self.node.trust, &self.node.evidence).unwrap();
        let mut snapshot = *p.snapshot.clone();
        snapshot.bft = Some(Certificate {
            prepared: q.clone(),
            committed,
        });
        snapshot
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        if std::thread::panicking() {
            return;
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}
#[path = "bft_epoch_tests.rs"]
mod epoch_activation;
#[path = "joint_epoch_tests.rs"]
mod joint_activation;
#[path = "joint_network_tests.rs"]
mod joint_network;
#[path = "joint_roles_tests.rs"]
mod joint_roles;
fn forged_proposal(h: &Harness, snapshot: Snapshot) -> Proposal {
    let mut p = Proposal {
        round: 0,
        snapshot: Box::new(snapshot),
        timeout: None,
        leader: Approval {
            key: public(h.seeds[0]),
            signature: String::new(),
        },
    };
    p.leader.signature = signature(h.seeds[0], &p.bytes().unwrap());
    p
}
fn forged_vote(seed: u8, c: Context, round: u64, value: Hash, phase: Phase) -> Vote {
    let mut v = Vote {
        context: c,
        round,
        value,
        phase,
        approval: Approval {
            key: public(seed),
            signature: String::new(),
        },
    };
    v.approval.signature = signature(seed, &v.bytes().unwrap());
    v
}
fn forged_certificate(h: &Harness, snapshot: Snapshot) -> Snapshot {
    let c = Context::current(&h.node).unwrap();
    let value = snapshot.statement.id().unwrap();
    let qc = |phase| Quorum {
        context: c.clone(),
        round: 0,
        value,
        phase,
        votes: h.seeds[..3]
            .iter()
            .map(|s| forged_vote(*s, c.clone(), 0, value, phase))
            .collect(),
    };
    Snapshot {
        base: None,
        bft: Some(Certificate {
            prepared: qc(Phase::Prepare),
            committed: qc(Phase::Commit),
        }),
        ..snapshot
    }
}
#[test]
fn two_phases_three_of_four_apply_one_atomic_native_block_and_exact_retry() {
    let mut h = Harness::new();
    let snapshot = h.node.bft_candidate(vec![], public(10)).unwrap();
    let p = h.proposal(0, None, snapshot);
    let q = h.prepare(&p, &[0, 1, 2]);
    let mut incomplete = *p.snapshot.clone();
    incomplete.bft = Some(Certificate {
        prepared: q.clone(),
        committed: q.clone(),
    });
    assert!(h.node.finalize(incomplete).is_err());
    assert_eq!(h.node.chain.height(), 0);
    let s = h.commit(&p, &q, &[0, 1, 2]);
    let sid = h.node.finalize(s.clone()).unwrap();
    assert_eq!(h.node.chain.height(), 1);
    assert_eq!(h.node.chain.finalized, Some(sid));
    assert_eq!(h.node.chain.ledger.minted, Amount(100));
    assert_eq!(h.node.finalize(s).unwrap(), sid);
    assert_eq!(h.node.chain.height(), 1);
    assert_eq!(h.agents[3].journal.records.len(), 0);
    let journal: storage::Journal = crate::history::read_journal(&h.root.join("node")).unwrap();
    let (_, _, chain) = journal
        .replay(&public(1), h.node.trust.currency().unwrap())
        .unwrap();
    assert_eq!(
        chain.ledger.root().unwrap(),
        h.node.chain.ledger.root().unwrap()
    );
    assert!(Agent::create(&h.root.join("blank-reset"), &h.node, public(h.seeds[1])).is_err());
}
#[test]
fn quorums_refuse_minority_duplicate_wrong_phase_domain_round_and_signatures() {
    let mut h = Harness::new();
    let s = h.node.bft_candidate(vec![], public(10)).unwrap();
    let p = h.proposal(0, None, s);
    let q = h.prepare(&p, &[0, 1, 2]);
    let keys = h.seeds.iter().copied().map(public).collect::<Vec<_>>();
    let mut bad_signature = q.clone();
    bad_signature.votes[0].approval.signature = "00".into();
    assert!(bad_signature.verify(&keys).is_err());
    let mut broken = q.clone();
    broken.votes.truncate(2);
    assert!(broken.verify(&keys).is_err());
    broken = q.clone();
    broken.votes[1] = broken.votes[0].clone();
    assert!(broken.verify(&keys).is_err());
    broken = q.clone();
    broken.votes.swap(0, 1);
    assert!(broken.verify(&keys).is_err());
    broken = q.clone();
    broken.votes[0].phase = Phase::Commit;
    assert!(broken.verify(&keys).is_err());
    broken = q.clone();
    broken.votes[0].round = 1;
    assert!(broken.verify(&keys).is_err());
    broken = q.clone();
    broken.votes[0].context.region = Hash::ZERO;
    assert!(broken.verify(&keys).is_err());
    let mut timeout = TimeoutVote {
        context: q.context,
        round: u64::MAX,
        high: None,
        approval: Approval {
            key: keys[0].clone(),
            signature: String::new(),
        },
    };
    timeout.approval.signature = signature(h.seeds[0], &timeout.bytes().unwrap());
    let tc = TimeoutCertificate {
        context: timeout.context.clone(),
        round: timeout.round,
        votes: vec![timeout.clone(), timeout.clone(), timeout],
    };
    assert!(std::panic::catch_unwind(|| tc.selected(&keys))
        .unwrap()
        .is_err());
}
#[test]
fn every_three_honest_prepare_partition_recovers_with_byzantine_leader_offline() {
    for mask in 0..8 {
        let mut h = Harness::new();
        let x = forged_proposal(&h, h.node.bft_candidate(vec![], public(10)).unwrap());
        let y = forged_proposal(&h, h.node.bft_candidate(vec![], public(14)).unwrap());
        let mut vx = vec![forged_vote(
            h.seeds[0],
            x.context().unwrap(),
            0,
            x.snapshot.statement.id().unwrap(),
            Phase::Prepare,
        )];
        let mut vy = vec![forged_vote(
            h.seeds[0],
            y.context().unwrap(),
            0,
            y.snapshot.statement.id().unwrap(),
            Phase::Prepare,
        )];
        let mut ix = vec![];
        let mut iy = vec![];
        for n in 1..4 {
            let p = if mask & (1 << (n - 1)) != 0 { &x } else { &y };
            let Message::Vote(v) = h.sign(n, Request::Prepare(Box::new(p.clone()))).message else {
                panic!()
            };
            if p == &x {
                vx.push(*v);
                ix.push(n);
            } else {
                vy.push(*v);
                iy.push(n);
            }
        }
        let (selected, mut votes, indices) = if vx.len() >= 3 {
            (&x, vx, ix)
        } else {
            (&y, vy, iy)
        };
        votes.truncate(3);
        let q = Quorum::combine(votes, &h.node.trust, &h.node.evidence).unwrap();
        for n in indices {
            h.sign(
                n,
                Request::Commit {
                    proposal: Box::new(selected.clone()),
                    prepared: q.clone(),
                },
            );
        }
        let c = Context::current(&h.node).unwrap();
        let timeouts = (1..4)
            .map(|n| {
                let Message::Timeout(t) = h
                    .sign(
                        n,
                        Request::Timeout {
                            context: c.clone(),
                            round: 0,
                        },
                    )
                    .message
                else {
                    panic!()
                };
                *t
            })
            .collect();
        let tc = TimeoutCertificate::combine(timeouts, &h.node.trust, &h.node.evidence).unwrap();
        assert_eq!(
            tc.selected(&h.seeds.iter().copied().map(public).collect::<Vec<_>>())
                .unwrap()
                .unwrap()
                .value,
            selected.snapshot.statement.id().unwrap()
        );
        let p = h.proposal(1, Some(tc), *selected.snapshot.clone());
        let q = h.prepare(&p, &[1, 2, 3]);
        let snapshot = h.commit(&p, &q, &[1, 2, 3]);
        h.node.finalize(snapshot).unwrap();
        assert_eq!(h.node.chain.ledger.minted, Amount(100));
        assert_eq!(h.node.chain.height(), 1);
        assert_eq!(h.agents[0].journal.records.len(), 0); // Byzantine fixtures bypass the protected path deliberately.
    }
}
#[test]
fn durable_qc_lock_sealed_round_old_backup_and_keyless_response_recovery() {
    let mut h = Harness::new();
    let p = h.proposal(0, None, h.node.bft_candidate(vec![], public(10)).unwrap());
    let q = h.prepare(&p, &[0, 1, 2]);
    let before = h.agents[1].journal.clone();
    let old = h.heads[1];
    let request = Request::Commit {
        proposal: Box::new(p.clone()),
        prepared: q.clone(),
    };
    let signed = h.sign(1, request.clone());
    assert!(h.agents[1].journal.state(&h.node).unwrap().lock.is_some());
    let retry = h.agents[1]
        .sign(&h.node, request.clone(), None, old)
        .unwrap();
    assert!(retry.recovered_exact_retry);
    assert_eq!(retry.message, signed.message);
    h.agents[1].journal = before;
    assert!(h.agents[1]
        .sign(&h.node, request, None, signed.head)
        .is_err());
    let path = h.root.join(format!("signer-{}/bft.json", h.seeds[1]));
    let current: bft::Journal = storage::read_json(&path).unwrap();
    h.agents[1].journal = current;
    let c = Context::current(&h.node).unwrap();
    h.sign(
        1,
        Request::Timeout {
            context: c,
            round: 0,
        },
    );
    // Returning an already retained signature is safe after a round is sealed.
    // A different, otherwise valid quorum must not authorize a new old-round vote.
    let sealed_head = h.heads[1];
    let recovered = h.agents[1]
        .sign(
            &h.node,
            Request::Commit {
                proposal: Box::new(p.clone()),
                prepared: q.clone(),
            },
            None,
            sealed_head,
        )
        .unwrap();
    assert!(recovered.recovered_exact_retry);
    assert_eq!(recovered.message, signed.message);
    assert_eq!(recovered.head, sealed_head);
    let mut alternate = q.clone();
    alternate.votes.push(forged_vote(
        h.seeds[3],
        q.context.clone(),
        q.round,
        q.value,
        Phase::Prepare,
    ));
    alternate
        .verify(&h.seeds.iter().copied().map(public).collect::<Vec<_>>())
        .unwrap();
    assert!(h.agents[1]
        .sign(
            &h.node,
            Request::Commit {
                proposal: Box::new(p),
                prepared: alternate,
            },
            Some(Path::new("/dev/null")),
            sealed_head,
        )
        .is_err());
    let state = h.agents[1].journal.state(&h.node).unwrap();
    assert_eq!(state.round, 1);
    assert!(state.lock.is_some());
}
#[test]
fn wrong_highest_qc_changed_value_unbound_round_and_invalid_native_state_never_vote() {
    let mut h = Harness::new();
    let x = h.node.bft_candidate(vec![], public(10)).unwrap();
    let p = h.proposal(0, None, x.clone());
    let q = h.prepare(&p, &[0, 1, 2]);
    for n in 0..3 {
        h.sign(
            n,
            Request::Commit {
                proposal: Box::new(p.clone()),
                prepared: q.clone(),
            },
        );
    }
    let c = Context::current(&h.node).unwrap();
    let tv = (0..3)
        .map(|n| {
            let Message::Timeout(t) = h
                .sign(
                    n,
                    Request::Timeout {
                        context: c.clone(),
                        round: 0,
                    },
                )
                .message
            else {
                panic!()
            };
            *t
        })
        .collect();
    let tc = TimeoutCertificate::combine(tv, &h.node.trust, &h.node.evidence).unwrap();
    let y = h.node.bft_candidate(vec![], public(14)).unwrap();
    let old = h.heads[1];
    assert!(h.agents[1]
        .sign(
            &h.node,
            Request::Propose {
                round: 1,
                snapshot: Box::new(y),
                timeout: Some(tc.clone())
            },
            Some(Path::new("/dev/null")),
            old
        )
        .is_err());
    assert!(h.agents[1]
        .sign(
            &h.node,
            Request::Propose {
                round: 1,
                snapshot: Box::new(x.clone()),
                timeout: None
            },
            Some(Path::new("/dev/null")),
            old
        )
        .is_err());
    let mut tampered = x;
    tampered.blocks[0]
        .commands
        .push(Command::Spend(Box::new(SignedIntent {
            intent: Intent {
                currency: c.currency,
                region: c.region,
                inputs: vec![],
                outputs: vec![],
                fee: Amount::ZERO,
                destination: None,
                remote: None,
                destination_fee: Amount::ZERO,
                valid_through: 4,
            },
            approvals: vec![],
        })));
    assert!(h.agents[1]
        .sign(
            &h.node,
            Request::Propose {
                round: 1,
                snapshot: Box::new(tampered),
                timeout: Some(tc)
            },
            Some(Path::new("/dev/null")),
            old
        )
        .is_err());
    assert_eq!(h.agents[1].journal.head().unwrap(), old);
}
#[test]
fn uncertified_blocks_legacy_signature_substitution_and_certificate_variants() {
    let mut h = Harness::new();
    let x = h.node.bft_candidate(vec![], public(10)).unwrap();
    assert!(h.node.accept(x.blocks[0].clone()).is_err());
    assert_eq!(h.node.chain.height(), 0);
    let mut legacy = x.clone();
    legacy.approvals = h
        .seeds
        .iter()
        .map(|s| Approval {
            key: public(*s),
            signature: signature(*s, &legacy.statement.bytes().unwrap()),
        })
        .collect();
    assert!(h.node.finalize(legacy).is_err());
    let p = h.proposal(0, None, x);
    let q = h.prepare(&p, &[0, 1, 2, 3]);
    let snapshot = h.commit(&p, &q, &[0, 1, 2, 3]);
    h.node.finalize(snapshot.clone()).unwrap();
    // Even a manually constructed, cryptographically complete legacy joint
    // handoff cannot activate an unimplemented BFT membership transition.
    let mut new_seeds = (62..66).collect::<Vec<u8>>();
    new_seeds.sort_by_key(|s| public(*s));
    let mut handoff = epoch::Transition {
        selection: None,
        statement: epoch::EpochStatement {
            activation: None,
            currency: snapshot.statement.currency,
            region: snapshot.statement.region,
            number: 1,
            previous_epoch: snapshot.statement.epoch,
            closing_checkpoint: snapshot.statement.id().unwrap(),
            closing_height: snapshot.statement.height,
            validators: new_seeds.iter().copied().map(public).collect(),
        },
        closing: epoch::Anchor::from_snapshot(&snapshot),
        old_approvals: vec![],
        new_approvals: vec![],
    };
    let bytes = handoff.statement.bytes().unwrap();
    let approvals = |seeds: &[u8]| {
        seeds
            .iter()
            .map(|s| Approval {
                key: public(*s),
                signature: signature(*s, &bytes),
            })
            .collect::<Vec<_>>()
    };
    handoff.old_approvals = approvals(&h.seeds);
    handoff.new_approvals = approvals(&new_seeds);
    epoch::approvals(
        &handoff.old_approvals,
        &h.seeds.iter().copied().map(public).collect::<Vec<_>>(),
        &bytes,
    )
    .unwrap();
    epoch::approvals(
        &handoff.new_approvals,
        &handoff.statement.validators,
        &bytes,
    )
    .unwrap();
    let before = fs::read(h.root.join("node/journal.json")).unwrap();
    assert!(h.node.install_epoch(handoff.clone()).is_err());
    assert!(epoch::Registry::verify_chain(&h.node.trust, h.node.chain.region, &[handoff]).is_err());
    assert_eq!(before, fs::read(h.root.join("node/journal.json")).unwrap());
    let mut different = snapshot.clone();
    different.bft.as_mut().unwrap().prepared.votes.remove(0);
    different.bft.as_mut().unwrap().committed.votes.remove(1);
    assert_eq!(
        h.node
            .evidence
            .add(different.clone(), &h.node.trust)
            .unwrap(),
        snapshot.statement.id().unwrap()
    );
    assert_eq!(
        h.node.finalize(different).unwrap(),
        snapshot.statement.id().unwrap()
    );
    let mut damaged: storage::Journal = crate::history::read_journal(&h.root.join("node")).unwrap();
    damaged.events.pop();
    assert!(damaged
        .replay(&public(1), h.node.trust.currency().unwrap())
        .is_err());
}
#[test]
fn compromised_quorum_conflict_is_retained_and_quarantines_without_refund() {
    let mut h = Harness::new();
    let x = forged_certificate(&h, h.node.bft_candidate(vec![], public(10)).unwrap());
    let y = forged_certificate(&h, h.node.bft_candidate(vec![], public(14)).unwrap());
    h.node.finalize(x).unwrap();
    let root = h.node.chain.ledger.root().unwrap();
    assert!(h.node.finalize(y).is_err());
    assert_eq!(h.node.conflicts.len(), 1);
    assert!(h.node.safety.regions.contains_key(&h.node.chain.region));
    assert_eq!(h.node.chain.ledger.root().unwrap(), root);
    assert_eq!(h.node.chain.ledger.minted, Amount(100));
    assert!(h.node.bft_candidate(vec![], public(10)).is_err());
    assert!(h.node.observed_installed_epochs().is_err());
}
#[test]
fn native_persistence_failure_and_exact_interrupted_signer_commit() {
    let mut h = Harness::new();
    let snapshot = h.node.bft_candidate(vec![], public(10)).unwrap();
    let req = Request::Propose {
        round: 0,
        snapshot: Box::new(snapshot),
        timeout: None,
    };
    let dir = h.root.join(format!("signer-{}", h.seeds[0]));
    let before = fs::read(dir.join("bft.json")).unwrap();
    let old = h.heads[0];
    fs::create_dir(dir.join("bft.next")).unwrap();
    assert!(h.agents[0]
        .sign(
            &h.node,
            req.clone(),
            Some(&h.root.join(format!("key-{}.json", h.seeds[0]))),
            old
        )
        .is_err());
    assert_eq!(fs::read(dir.join("bft.json")).unwrap(), before);
    fs::remove_dir(dir.join("bft.next")).unwrap();
    // Release only this owned signer lock, then recover/retry against native replay.
    let old_agent = h.agents.remove(0);
    drop(old_agent);
    let mut reopened = Agent::open(&dir, &h.node).unwrap();
    let signed = reopened
        .sign(
            &h.node,
            req.clone(),
            Some(&h.root.join(format!("key-{}.json", h.seeds[0]))),
            old,
        )
        .unwrap();
    let next = fs::read(dir.join("bft.json")).unwrap();
    drop(reopened);
    fs::write(dir.join("bft.json"), before).unwrap();
    crate::keystore::private_create(&dir.join("bft.next"), &next).unwrap();
    let mut reopened = Agent::open(&dir, &h.node).unwrap();
    assert_eq!(reopened.journal.head().unwrap(), signed.head);
    assert_eq!(
        reopened.sign(&h.node, req, None, old).unwrap().message,
        signed.message
    );
    h.agents.insert(0, reopened);
}

#[test]
fn locked_status_binds_full_native_lock_and_refuses_later_stale_head() {
    let mut h = Harness::new();
    let proposal = h.proposal(0, None, h.node.bft_candidate(vec![], public(10)).unwrap());
    let prepare = h.prepare(&proposal, &[0, 1, 2]);
    h.sign(
        1,
        Request::Commit {
            proposal: Box::new(proposal),
            prepared: prepare,
        },
    );
    let dir = h.root.join(format!("signer-{}", h.seeds[1]));
    let retained = fs::read(dir.join("bft.json")).unwrap();
    let expected = serde_json::json!({
        "head": h.agents[1].journal.head().unwrap(),
        "binding": h.agents[1].journal.binding,
        "state": h.agents[1].journal.state(&h.node).unwrap(),
        "records": h.agents[1].journal.records.len(),
        "creation": h.agents[1].journal.creation,
        "external_rollback_anchor_qualified": false,
    });
    drop(h.agents.remove(1));
    let (mut opened, status) = Agent::open_with_status(&dir, &h.node).unwrap();
    assert_eq!(
        serde_json::to_value(&status).unwrap().to_string(),
        expected.to_string()
    );
    assert!(expected["state"]["lock"].is_object());
    assert!(Agent::open_with_status(&dir, &h.node).is_err());
    assert_eq!(fs::read(dir.join("bft.json")).unwrap(), retained);
    let context = Context::current(&h.node).unwrap();
    let old = opened.journal.head().unwrap();
    let request = Request::Timeout {
        context: context.clone(),
        round: 0,
    };
    opened
        .sign(
            &h.node,
            request,
            Some(&h.root.join(format!("key-{}.json", h.seeds[1]))),
            old,
        )
        .unwrap();
    let advanced = fs::read(dir.join("bft.json")).unwrap();
    assert!(opened
        .sign(
            &h.node,
            Request::Timeout { context, round: 1 },
            Some(&h.root.join(format!("key-{}.json", h.seeds[1]))),
            old
        )
        .is_err());
    assert_eq!(fs::read(dir.join("bft.json")).unwrap(), advanced);
}

#[test]
fn locked_status_matches_exact_authenticated_interrupted_extension() {
    let mut h = Harness::new();
    let dir = h.root.join(format!("signer-{}", h.seeds[0]));
    let before = fs::read(dir.join("bft.json")).unwrap();
    let context = Context::current(&h.node).unwrap();
    h.sign(0, Request::Timeout { context, round: 0 });
    let next = fs::read(dir.join("bft.json")).unwrap();
    let expected = serde_json::json!({
        "head": h.agents[0].journal.head().unwrap(),
        "binding": h.agents[0].journal.binding,
        "state": h.agents[0].journal.state(&h.node).unwrap(),
        "records": h.agents[0].journal.records.len(),
        "creation": h.agents[0].journal.creation,
        "external_rollback_anchor_qualified": false,
    });
    drop(h.agents.remove(0));
    fs::write(dir.join("bft.json"), before).unwrap();
    crate::keystore::private_create(&dir.join("bft.next"), &next).unwrap();
    let (opened, status) = Agent::open_with_status(&dir, &h.node).unwrap();
    assert_eq!(
        serde_json::to_value(&status).unwrap().to_string(),
        expected.to_string()
    );
    assert_eq!(
        opened.journal.head().unwrap().to_hex(),
        expected["head"].as_str().unwrap()
    );
    assert_eq!(fs::read(dir.join("bft.json")).unwrap(), next);
    assert!(!dir.join("bft.next").exists());
}

#[test]
fn locked_status_rejects_changed_signature_and_invalid_interrupted_bytes_without_rewrite() {
    let mut h = Harness::new();
    let dir = h.root.join(format!("signer-{}", h.seeds[0]));
    let context = Context::current(&h.node).unwrap();
    h.sign(0, Request::Timeout { context, round: 0 });
    let original = fs::read(dir.join("bft.json")).unwrap();
    let mut altered: serde_json::Value = serde_json::from_slice(&original).unwrap();
    altered["records"][0]["message"]["Timeout"]["approval"]["signature"] =
        serde_json::json!("00".repeat(64));
    let damaged = serde_json::to_vec(&altered).unwrap();
    drop(h.agents.remove(0));
    fs::write(dir.join("bft.json"), &damaged).unwrap();
    assert!(Agent::open_with_status(&dir, &h.node).is_err());
    assert_eq!(fs::read(dir.join("bft.json")).unwrap(), damaged);
    fs::write(dir.join("bft.json"), &original).unwrap();
    crate::keystore::private_create(&dir.join("bft.next"), &damaged).unwrap();
    assert!(Agent::open_with_status(&dir, &h.node).is_err());
    assert_eq!(fs::read(dir.join("bft.json")).unwrap(), original);
    assert_eq!(fs::read(dir.join("bft.next")).unwrap(), damaged);
}

#[test]
fn typed_network_carriage_verifies_native_domain_parent_and_phase_without_mutation() {
    use crate::bft_network::{Body, Envelope, FORMAT};
    let mut h = Harness::new();
    let proposal = h.proposal(0, None, h.node.bft_candidate(vec![], public(10)).unwrap());
    let envelope = Envelope {
        format: FORMAT.into(),
        currency: h.node.trust.currency().unwrap(),
        region: h.node.chain.region,
        evidence: h.node.journal.evidence.clone(),
        body: Body::Signed(Box::new(Message::Proposal(Box::new(proposal.clone())))),
    };
    let before = fs::read(h.root.join("node/journal.json")).unwrap();
    envelope.verify(&h.node).unwrap();
    assert_eq!(
        envelope.value().unwrap(),
        Some(proposal.snapshot.statement.id().unwrap())
    );
    let mut wrong = envelope.clone();
    wrong.currency = Hash::ZERO;
    assert!(wrong.verify(&h.node).is_err());
    let mut context = Context::current(&h.node).unwrap();
    context.parent_state = Hash::ZERO;
    wrong = envelope.clone();
    wrong.body = Body::Signed(Box::new(Message::Vote(Box::new(forged_vote(
        h.seeds[1],
        context,
        0,
        proposal.snapshot.statement.id().unwrap(),
        Phase::Prepare,
    )))));
    assert!(wrong.verify(&h.node).is_err());
    wrong = envelope.clone();
    wrong.body = Body::Submission(vec![]);
    assert!(wrong.verify(&h.node).is_err());
    let prepared = h.prepare(&proposal, &[0, 1, 2]);
    let mut snapshot = h.commit(&proposal, &prepared, &[0, 1, 2]);
    snapshot.bft.as_mut().unwrap().committed.votes.pop();
    wrong.body = Body::Finalized(Box::new(snapshot));
    assert!(wrong.verify(&h.node).is_err());
    assert_eq!(before, fs::read(h.root.join("node/journal.json")).unwrap());
}

fn cold_batch_envelope(h: &mut Harness) -> crate::bft_network::WireEnvelope {
    use crate::bft_network::{Body, Envelope, FORMAT};
    let proposal = h.proposal(0, None, h.node.bft_candidate(vec![], public(10)).unwrap());
    Envelope {
        format: FORMAT.into(),
        currency: h.node.trust.currency().unwrap(),
        region: h.node.chain.region,
        evidence: h.node.journal.evidence.clone(),
        body: Body::Signed(Box::new(Message::Proposal(Box::new(proposal)))),
    }
    .pack()
    .unwrap()
}

#[test]
fn cold_network_batch_authenticates_all_ordered_envelopes_without_ledger_or_signer_changes() {
    let mut h = Harness::new();
    let wire = cold_batch_envelope(&mut h);
    let expected = wire.clone().expand().unwrap();
    let before = fs::read(h.root.join("node/journal.json")).unwrap();
    let heads = h.heads.clone();
    let rows = bft_network::check_cold_batch(vec![wire; 4], &h.node).unwrap();
    assert_eq!(rows.len(), 4);
    for row in rows {
        assert_eq!(row.message_id, expected.verify(&h.node).unwrap());
        assert_eq!(row.value, expected.value().unwrap());
    }
    assert_eq!(heads, h.heads);
    assert_eq!(before, fs::read(h.root.join("node/journal.json")).unwrap());
}

#[test]
fn cold_network_batch_never_deduplicates_a_later_bad_proof_on_the_same_body() {
    let mut h = Harness::new();
    let wire = cold_batch_envelope(&mut h);
    let mut bad = wire.clone();
    let bft_network::Body::Signed(message) = &wire.body else {
        panic!()
    };
    let Message::Proposal(proposal) = message.as_ref() else {
        panic!()
    };
    bad.evidence
        .snapshots
        .push(crate::carriage::CarriedSnapshot {
            prefix: None,
            snapshot: *proposal.snapshot.clone(),
        });
    let before = fs::read(h.root.join("node/journal.json")).unwrap();
    assert!(bft_network::check_cold_batch(vec![wire.clone(), bad], &h.node).is_err());
    let mut altered = wire.clone();
    altered.currency = Hash::ZERO;
    assert!(bft_network::check_cold_batch(vec![wire, altered], &h.node).is_err());
    assert_eq!(before, fs::read(h.root.join("node/journal.json")).unwrap());
}

#[test]
fn cold_network_batch_refuses_count_payload_and_total_capacity_without_state_changes() {
    let mut h = Harness::new();
    let wire = cold_batch_envelope(&mut h);
    let before = fs::read(h.root.join("node/journal.json")).unwrap();
    assert!(bft_network::check_cold_batch(vec![], &h.node).is_err());
    assert!(bft_network::check_cold_batch(vec![wire.clone(); 5], &h.node).is_err());
    let mut large = wire;
    let bft_network::Body::Signed(message) = &mut large.body else {
        panic!()
    };
    let Message::Proposal(proposal) = message.as_mut() else {
        panic!()
    };
    proposal.leader.signature = "0".repeat(crate::contact::MAX_PAYLOAD);
    assert!(bft_network::check_cold_batch(vec![large.clone()], &h.node)
        .unwrap_err()
        .contains("payload bound"));
    assert!(bft_network::check_cold_batch(vec![large; 4], &h.node)
        .unwrap_err()
        .contains("batch exceeds bound"));
    assert_eq!(before, fs::read(h.root.join("node/journal.json")).unwrap());
}

#[test]
fn cold_network_batch_inspection_refuses_pending_incident_before_replay_without_reconciliation() {
    let mut package = bootstrap();
    for admission in &mut package.admissions {
        admission.rules = bft::RULES.into();
        admission.signature = signature(1, &admission.bytes().unwrap());
    }
    let currency = package.currency.id().unwrap();
    let region = package.admissions[0].id().unwrap();
    let root = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "rld-cold-batch-inspection-{}",
            rld_core::generate_identity().public_key
        ));
    fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let node = Store::create(&root.join("node"), package, region, &public(1), currency).unwrap();
    drop(node);
    let path = root.join("node");
    let before = fs::read(path.join("journal.json")).unwrap();
    {
        let inspected = Store::open_inspection(&path, &public(1), currency).unwrap();
        assert_eq!(inspected.chain.height(), 0);
    }
    assert_eq!(before, fs::read(path.join("journal.json")).unwrap());
    fs::write(path.join("INCIDENT_GUARD"), [1u8; 32]).unwrap();
    fs::write(
        path.join("journal.json"),
        b"retained damaged fixture journal",
    )
    .unwrap();
    assert!(Store::open_inspection(&path, &public(1), currency)
        .err()
        .unwrap()
        .contains("pending incident"));
    assert_eq!(fs::read(path.join("INCIDENT_GUARD")).unwrap(), [1u8; 32]);
    assert_eq!(
        fs::read(path.join("journal.json")).unwrap(),
        b"retained damaged fixture journal"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn independently_verified_network_archive_catches_up_atomic_blocks_and_normalizes_quorum_variants()
{
    let mut h = Harness::new();
    for _ in 0..3 {
        let p = h.proposal(0, None, h.node.bft_candidate(vec![], public(10)).unwrap());
        let q = h.prepare(&p, &[0, 1, 2, 3]);
        let s = h.commit(&p, &q, &[0, 1, 2, 3]);
        h.node.finalize(s).unwrap();
    }
    let region = h.node.chain.region;
    let currency = h.node.trust.currency().unwrap();
    let path = h.root.join("replica");
    let mut replica = Store::create(
        &path,
        h.node.journal.bootstrap.clone(),
        region,
        &public(1),
        currency,
    )
    .unwrap();
    crate::bft_network::sync(&mut replica, h.node.journal.evidence.clone()).unwrap();
    assert_eq!(replica.chain.height(), 3);
    assert_eq!(replica.chain.ledger.minted, Amount(300));
    assert_eq!(
        replica.chain.ledger.root().unwrap(),
        h.node.chain.ledger.root().unwrap()
    );
    let before = fs::read(path.join("journal.json")).unwrap();
    let mut alternate = h.node.journal.evidence.clone();
    for snapshot in &mut alternate.snapshots {
        snapshot.bft.as_mut().unwrap().prepared.votes.remove(0);
        snapshot.bft.as_mut().unwrap().committed.votes.remove(1);
    }
    crate::bft_network::sync(&mut replica, alternate).unwrap();
    assert_eq!(before, fs::read(path.join("journal.json")).unwrap());
}

#[test]
fn compact_consensus_carriage_cold_authenticates_complete_history_and_refuses_forgery() {
    use crate::bft_network::{Body, Envelope, WireEnvelope, FORMAT};
    let mut h = Harness::new();
    for _ in 0..12 {
        let p = h.proposal(0, None, h.node.bft_candidate(vec![], public(10)).unwrap());
        let q = h.prepare(&p, &[0, 1, 2]);
        let s = h.commit(&p, &q, &[0, 1, 2]);
        h.node.finalize(s).unwrap();
    }
    let finality = h
        .node
        .evidence
        .snapshot(h.node.chain.finalized.unwrap())
        .unwrap()
        .clone();
    let logical = Envelope {
        format: FORMAT.into(),
        currency: h.node.trust.currency().unwrap(),
        region: h.node.chain.region,
        evidence: h.node.journal.evidence.clone(),
        body: Body::Finalized(Box::new(finality)),
    };
    let wire = logical.pack().unwrap();
    let bytes = serde_json::to_vec(&wire).unwrap();
    let full_bytes = serde_json::to_vec(&logical).unwrap().len();
    assert!(bytes.len() < full_bytes);
    assert!(wire.evidence.snapshots[1..]
        .iter()
        .all(|s| s.prefix.is_some() && s.snapshot.blocks.len() == 1));
    println!(
        "{}",
        serde_json::json!({"format":"RLD-NATIVE-BFT-CARRIAGE-PREFIX-SAMPLE-V1",
        "native_implementation":implementation().unwrap(),"fixture_only":true,"live_rld":false,
        "checkpoints":12,"full_envelope_bytes":full_bytes,"carried_envelope_bytes":bytes.len(),
        "signed_body_compressed":false,"long_history_qualified":false})
    );
    let cold: WireEnvelope = serde_json::from_slice(&bytes).unwrap();
    let expanded = cold.expand().unwrap();
    assert_eq!(
        serde_json::to_vec(&expanded).unwrap(),
        serde_json::to_vec(&logical).unwrap()
    );
    let path = h.root.join("cold-wire-replica");
    let mut target = Store::create(
        &path,
        h.node.journal.bootstrap.clone(),
        h.node.chain.region,
        &public(1),
        logical.currency,
    )
    .unwrap();
    expanded.verify(&target).unwrap();
    crate::bft_network::sync(&mut target, expanded.evidence).unwrap();
    assert_eq!(target.chain.blocks, h.node.chain.blocks);
    assert_eq!(target.chain.ledger, h.node.chain.ledger);
    let before = fs::read(path.join("journal.json")).unwrap();
    let mut forged = wire.clone();
    forged.evidence.snapshots[2]
        .snapshot
        .bft
        .as_mut()
        .unwrap()
        .committed
        .votes[0]
        .approval
        .signature = "00".repeat(64);
    assert!(forged.expand().unwrap().verify(&target).is_err());
    let mut legacy = wire;
    legacy.format = "RLD-REGIONAL-BFT-NETWORK-V1".into();
    assert!(legacy.expand().is_err());
    assert_eq!(fs::read(path.join("journal.json")).unwrap(), before);
}

#[test]
fn certified_prefix_proposals_and_cold_restart_match_complete_native_replay() {
    let mut h = Harness::new();
    for _ in 0..12 {
        let snapshot = h.node.bft_candidate(vec![], public(10)).unwrap();
        let complete =
            super::native_prefix::from_genesis(&snapshot, &h.node.trust, &h.node.evidence);
        let prefix = h
            .node
            .evidence
            .replay_extension(&snapshot, &h.node.trust)
            .unwrap();
        assert_eq!(prefix.ledger, complete.ledger);
        assert_eq!(prefix.statement(&h.node.trust).unwrap(), snapshot.statement);
        let proposal = h.proposal(0, None, snapshot);
        let prepared = h.prepare(&proposal, &[0, 1, 2]);
        let certified = h.commit(&proposal, &prepared, &[0, 1, 2]);
        h.node.finalize(certified).unwrap();
        assert_eq!(h.node.chain.ledger, complete.ledger);
    }
    let reopened = h
        .node
        .journal
        .replay(&public(1), h.node.trust.currency().unwrap())
        .unwrap();
    assert_eq!(reopened.2.blocks, h.node.chain.blocks);
    assert_eq!(reopened.2.ledger, h.node.chain.ledger);
    assert_eq!(reopened.2.finalized, h.node.chain.finalized);
}

#[test]
fn signed_submission_queues_without_debit_and_refuses_invalid_owner_amount() {
    let mut h = Harness::new();
    for _ in 0..3 {
        let p = h.proposal(0, None, h.node.bft_candidate(vec![], public(10)).unwrap());
        let q = h.prepare(&p, &[0, 1, 2]);
        let s = h.commit(&p, &q, &[0, 1, 2]);
        h.node.finalize(s).unwrap();
    }
    let input = *h
        .node
        .chain
        .ledger
        .coins
        .iter()
        .find(|(_, c)| c.mature <= 3)
        .unwrap()
        .0;
    let intent = Intent {
        currency: h.node.trust.currency().unwrap(),
        region: h.node.chain.region,
        inputs: vec![input],
        outputs: vec![Payment {
            owner: public(11),
            amount: Amount(99),
        }],
        fee: Amount(1),
        destination: None,
        remote: None,
        destination_fee: Amount::ZERO,
        valid_through: 20,
    };
    let command = Command::Spend(Box::new(SignedIntent {
        approvals: vec![Approval {
            key: public(10),
            signature: signature(10, &intent.bytes().unwrap()),
        }],
        intent,
    }));
    let before = fs::read(h.root.join("node/journal.json")).unwrap();
    let id = h.node.bft_submit(vec![command.clone()]).unwrap();
    assert_eq!(h.node.bft_submit(vec![command.clone()]).unwrap(), id);
    assert!(h
        .root
        .join(format!("node/bft-submissions/{}.json", id.to_hex()))
        .is_file());
    let mut invalid = command;
    if let Command::Spend(ref mut signed) = invalid {
        signed.intent.outputs[0].amount = Amount(100);
    }
    assert!(h.node.bft_submit(vec![invalid]).is_err());
    assert_eq!(before, fs::read(h.root.join("node/journal.json")).unwrap());
}

#[test]
fn live_network_batch_returns_complete_authenticated_evidence_in_order_without_changes() {
    let mut h = Harness::new();
    let wire = cold_batch_envelope(&mut h);
    let expected = wire.clone().expand().unwrap();
    let before = fs::read(h.root.join("node/journal.json")).unwrap();
    let heads = h.heads.clone();
    let rows = bft_network::inspect_live_batch(vec![wire; 4], &h.node).unwrap();
    assert_eq!(rows.len(), 4);
    for row in rows {
        assert_eq!(row.message_id, expected.verify(&h.node).unwrap());
        assert_eq!(row.value, expected.value().unwrap());
        assert_eq!(
            serde_json::to_vec(&row.evidence).unwrap(),
            serde_json::to_vec(&expected.evidence).unwrap()
        );
        assert_eq!(
            serde_json::to_vec(&row.epochs).unwrap(),
            serde_json::to_vec(expected.carried_epochs()).unwrap()
        );
    }
    assert_eq!(h.heads, heads);
    assert_eq!(fs::read(h.root.join("node/journal.json")).unwrap(), before);
}

#[test]
fn live_network_batch_later_invalid_signature_refuses_whole_batch_without_changes() {
    let mut h = Harness::new();
    let wire = cold_batch_envelope(&mut h);
    let mut bad = wire.clone();
    let bft_network::Body::Signed(message) = &mut bad.body else {
        panic!()
    };
    let Message::Proposal(proposal) = message.as_mut() else {
        panic!()
    };
    proposal.leader.signature = "0".repeat(128);
    let before = fs::read(h.root.join("node/journal.json")).unwrap();
    assert!(bft_network::inspect_live_batch(vec![wire.clone(), bad], &h.node).is_err());
    let mut foreign = wire.clone();
    foreign.currency = Hash::ZERO;
    assert!(bft_network::inspect_live_batch(vec![wire, foreign], &h.node).is_err());
    assert_eq!(fs::read(h.root.join("node/journal.json")).unwrap(), before);
}

#[test]
fn live_network_batch_refuses_count_and_wire_capacity_without_changes() {
    let mut h = Harness::new();
    let wire = cold_batch_envelope(&mut h);
    assert!(bft_network::inspect_live_batch(vec![], &h.node).is_err());
    assert!(bft_network::inspect_live_batch(vec![wire.clone(); 5], &h.node).is_err());
    let mut large = wire;
    let bft_network::Body::Signed(message) = &mut large.body else {
        panic!()
    };
    let Message::Proposal(proposal) = message.as_mut() else {
        panic!()
    };
    proposal.leader.signature = "0".repeat(crate::contact::MAX_PAYLOAD);
    let before = fs::read(h.root.join("node/journal.json")).unwrap();
    assert!(
        bft_network::inspect_live_batch(vec![large.clone()], &h.node)
            .unwrap_err()
            .contains("payload bound")
    );
    assert!(bft_network::inspect_live_batch(vec![large; 4], &h.node)
        .unwrap_err()
        .contains("batch exceeds bound"));
    assert_eq!(fs::read(h.root.join("node/journal.json")).unwrap(), before);
}
