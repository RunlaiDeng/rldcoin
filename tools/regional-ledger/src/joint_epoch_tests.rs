use super::epoch_activation::{append, candidates, request};
use super::*;
use crate::joint_epoch::Plan;

pub(super) fn plan(h: &Harness) -> Plan {
    let (previous_epoch, number, _, _) = h
        .node
        .evidence
        .epoch_state(&h.node.trust, h.node.chain.region)
        .unwrap();
    Plan {
        currency: h.node.trust.currency().unwrap(),
        region: h.node.chain.region,
        previous_epoch,
        number: number + 1,
        validators: candidates().into_iter().map(public).collect(),
    }
}
pub(super) fn selection(
    h: &mut Harness,
    commands: Vec<Command>,
    missing: Option<usize>,
) -> Snapshot {
    let snapshot = h.node.bft_candidate(commands, public(10)).unwrap();
    let c = Context::current(&h.node).unwrap();
    let leader = (c.parent_height % 4) as usize;
    let indices = (0..4).filter(|n| Some(*n) != missing).collect::<Vec<_>>();
    let (round, timeout) = if Some(leader) == missing {
        let votes = indices
            .iter()
            .map(|n| {
                let Message::Timeout(v) = h
                    .sign(
                        *n,
                        Request::Timeout {
                            context: c.clone(),
                            round: 0,
                        },
                    )
                    .message
                else {
                    panic!()
                };
                *v
            })
            .collect();
        (
            1,
            Some(TimeoutCertificate::combine(votes, &h.node.trust, &h.node.evidence).unwrap()),
        )
    } else {
        (0, None)
    };
    let p = h.proposal(round, timeout, snapshot);
    let q = h.prepare(&p, &indices[..3]);
    let s = h.commit(&p, &q, &indices[..3]);
    h.node.finalize(s.clone()).unwrap();
    s
}
pub(super) fn activate(
    h: &mut Harness,
    old_indices: &[usize],
    new_indices: &[usize],
) -> epoch::Transition {
    let mut proof = h
        .node
        .epoch_request(candidates().into_iter().map(public).collect())
        .unwrap();
    let unsigned = proof.clone();
    for n in old_indices {
        let Message::EpochApproval { approval, .. } = h.sign(*n, request(h, &unsigned)).message
        else {
            panic!()
        };
        proof.old_approvals.push(approval);
    }
    for n in new_indices {
        let seed = candidates()[*n];
        let mut agent = crate::signer::Agent::create(
            &h.root.join(format!("join-{seed}")),
            &h.node,
            public(seed),
        )
        .unwrap();
        let key = h.root.join(format!("key-{seed}.json"));
        crate::keystore::private_create(
            &key,
            &serde_json::to_vec(&serde_json::json!({"secret_key":hex::encode([seed;32])})).unwrap(),
        )
        .unwrap();
        let head = agent.journal.head().unwrap();
        proof.new_approvals.push(
            agent
                .handoff(&h.node, unsigned.clone(), &key, head)
                .unwrap()
                .approval,
        );
    }
    proof
}
pub(super) fn swap_new(h: &mut Harness) {
    drop(std::mem::take(&mut h.agents));
    h.seeds = candidates();
    h.agents = h
        .seeds
        .iter()
        .map(|s| Agent::create(&h.root.join(format!("signer-{s}")), &h.node, public(*s)).unwrap())
        .collect();
    h.heads = h.agents.iter().map(|a| a.journal.head().unwrap()).collect();
}

#[test]
fn installed_epoch_observation_excludes_known_proofs_and_refuses_missing_local_events() {
    let mut h = Harness::with_rules(bft::JOINT_RULES);
    let p = plan(&h);
    selection(&mut h, vec![Command::Reconfigure(Box::new(p))], None);
    let proof = activate(&mut h, &[0, 1, 2], &[0, 1, 2]);
    // Fully verify a known transition, without selecting it in local history.
    h.node
        .evidence
        .install_epoch(proof.clone(), &h.node.trust)
        .unwrap();
    h.node.journal.epoch_proofs.push(proof.clone());
    assert!(h.node.observed_installed_epochs().unwrap().is_empty());
    h.node.journal.epoch_proofs.clear();
    h.node.install_epoch(proof.clone()).unwrap();
    assert_eq!(
        serde_json::to_vec(&h.node.observed_installed_epochs().unwrap()).unwrap(),
        serde_json::to_vec(&vec![proof]).unwrap()
    );
    let events = h.node.journal.events.clone();
    h.node
        .journal
        .events
        .retain(|e| !matches!(e, crate::storage::Event::Epoch(_)));
    assert!(h.node.observed_installed_epochs().is_err());
    h.node.journal.events = events;
    h.node.journal.epoch_proofs.clear();
    assert!(h.node.observed_installed_epochs().is_err());
}

#[test]
fn joint_selected_plan_completes_with_missing_old_new_and_real_owner_value() {
    let mut h = Harness::with_rules(bft::JOINT_RULES);
    // No fourth validator participates, even when it would be round-zero leader.
    for _ in 0..3 {
        selection(&mut h, vec![], Some(3));
    }
    let input = *h
        .node
        .chain
        .ledger
        .coins
        .iter()
        .find(|(_, c)| c.created == 1)
        .unwrap()
        .0;
    let signed = intent(
        &h.node.chain,
        &h.node.trust,
        vec![input],
        vec![Payment {
            owner: public(11),
            amount: Amount(100),
        }],
        None,
        None,
        0,
        0,
        &[10],
    );
    let selected = plan(&h);
    let closing = selection(
        &mut h,
        vec![
            Command::Spend(Box::new(signed)),
            Command::Reconfigure(Box::new(selected)),
        ],
        Some(3),
    );
    assert_eq!(closing.bft.as_ref().unwrap().prepared.round, 1);
    let old = h.agents[0].journal.clone();
    let old_head = h.heads[0];
    let ledger = h.node.chain.ledger.clone();
    assert!(h.node.template(vec![], public(10)).is_err());
    let proof = activate(&mut h, &[0, 1, 2], &[0, 1, 2]);
    assert_eq!(proof.old_approvals.len(), 3);
    assert_eq!(proof.new_approvals.len(), 3);
    let fence = h.agents[0].journal.records.last().unwrap().clone();
    let eid = h.node.install_epoch(proof.clone()).unwrap();
    assert_eq!(h.node.chain.ledger, ledger);
    let replay = h.agents[0]
        .sign(&h.node, fence.request.clone(), None, fence.previous_head)
        .unwrap();
    assert!(replay.recovered_exact_retry);
    assert_eq!(replay.message, fence.message);
    let old_seed = h.seeds[0];
    let old_dir = h.root.join(format!("signer-{old_seed}"));
    let current_head = h.heads[0];
    swap_new(&mut h);
    let next = selection(&mut h, vec![], Some(3));
    assert_eq!(next.statement.epoch, eid);
    assert_eq!(h.node.chain.ledger, ledger);
    // Full cold evidence and disk journals derive their state from genesis.
    let cold = VerifiedEvidence::verify(&h.node.journal.evidence, &h.node.trust).unwrap();
    assert_eq!(cold.snapshot(next.statement.id().unwrap()).unwrap(), &next);
    let (_, _, reopened) = h
        .node
        .journal
        .replay(&public(1), h.node.trust.currency().unwrap())
        .unwrap();
    assert_eq!(reopened.ledger, ledger);
    assert_eq!(reopened.epoch, eid);
    let mut missing_epoch_event = h.node.journal.clone();
    missing_epoch_event
        .events
        .retain(|e| !matches!(e, crate::storage::Event::Epoch(_)));
    assert!(missing_epoch_event
        .replay(&public(1), h.node.trust.currency().unwrap())
        .is_err());
    // Restoring a pre-fence signer cannot override the separately retained head.
    fs::write(old_dir.join("bft.json"), serde_json::to_vec(&old).unwrap()).unwrap();
    let mut backup = Agent::open(&old_dir, &h.node).unwrap();
    assert_eq!(backup.journal.head().unwrap(), old_head);
    assert!(backup
        .sign(&h.node, fence.request, None, current_head)
        .is_err());
    println!(
        "{}",
        serde_json::json!({"format":"RLD-BFT-JOINT-EPOCH-NATIVE-SAMPLE-V1","fixture_only":true,"live_rld":false,"native_implementation":implementation().unwrap(),"height":5,"old_selection_prepare_commit_votes":3,"selection_round":1,"old_fences":3,"new_approvals":3,"one_old_and_one_new_absent":true,"signed_owner_payment_preserved":true,"minted":"300","full_cold_replay":true,"missing_local_epoch_event_refused":true,"old_exact_response_keyless_recovery":true,"stale_backup_refused_with_retained_head":true,"autonomous_reconfiguration":false,"independent_custody_qualified":false})
    );
}

#[test]
fn joint_unselected_changed_or_undersigned_activation_never_advances_native_state() {
    let mut h = Harness::with_rules(bft::JOINT_RULES);
    append(&mut h, vec![]);
    assert!(h
        .node
        .epoch_request(candidates().into_iter().map(public).collect())
        .is_err());
    let p = plan(&h);
    selection(&mut h, vec![Command::Reconfigure(Box::new(p))], None);
    let proof = activate(&mut h, &[0, 1, 2], &[0, 1, 2]);
    let before = serde_json::to_vec(&h.node.journal).unwrap();
    for mode in 0..8 {
        let mut bad = proof.clone();
        match mode {
            0 => {
                bad.old_approvals.pop();
            }
            1 => {
                bad.new_approvals.pop();
            }
            2 => {
                bad.old_approvals[0] = bad.old_approvals[1].clone();
            }
            3 => {
                bad.selection.as_mut().unwrap().commands.clear();
            }
            4 => {
                bad.statement.activation = None;
            }
            5 => {
                bad.statement.validators =
                    candidates().into_iter().map(|s| public(s + 40)).collect();
                bad.statement.validators.sort();
            }
            6 => {
                bad.selection = None;
            }
            _ => {
                bad.new_approvals[0].signature = "00".repeat(64);
            }
        }
        assert!(h.node.install_epoch(bad).is_err(), "mode {mode}");
        assert_eq!(serde_json::to_vec(&h.node.journal).unwrap(), before);
    }
    h.node.install_epoch(proof).unwrap();
}

#[test]
fn joint_selection_blocks_unfenced_old_timeout_and_wrong_plan_fence() {
    let mut h = Harness::with_rules(bft::JOINT_RULES);
    let p = plan(&h);
    selection(&mut h, vec![Command::Reconfigure(Box::new(p))], None);
    let context = Context::current(&h.node).unwrap();
    let mut wrong = h
        .node
        .epoch_request(candidates().into_iter().map(public).collect())
        .unwrap();
    wrong.statement.validators = (60..64).map(public).collect();
    wrong.statement.validators.sort();
    let before = h.agents[0].journal.clone();
    let key = h.root.join(format!("key-{}.json", h.seeds[0]));
    assert!(h.agents[0]
        .sign(
            &h.node,
            Request::Timeout { context, round: 0 },
            Some(&key),
            h.heads[0]
        )
        .is_err());
    let req = request(&h, &wrong);
    assert!(h.agents[0]
        .sign(&h.node, req, Some(&key), h.heads[0])
        .is_err());
    assert_eq!(h.agents[0].journal, before);
    assert!(h.node.bft_candidate(vec![], public(10)).is_err());
}

#[test]
fn joint_competing_plan_cannot_replace_the_durable_prepared_selection() {
    let mut h = Harness::with_rules(bft::JOINT_RULES);
    let a = plan(&h);
    let mut b = a.clone();
    b.validators = (60..64).map(public).collect();
    b.validators.sort();
    let selected = h
        .node
        .bft_candidate(vec![Command::Reconfigure(Box::new(a))], public(10))
        .unwrap();
    let competing = h
        .node
        .bft_candidate(vec![Command::Reconfigure(Box::new(b.clone()))], public(10))
        .unwrap();
    let p = h.proposal(0, None, selected.clone());
    let q = h.prepare(&p, &[0, 1, 2]);
    // One durable commit lock, but no finality certificate or fence yet.
    h.sign(
        0,
        Request::Commit {
            proposal: Box::new(p),
            prepared: q,
        },
    );
    assert!(h
        .node
        .epoch_request(candidates().into_iter().map(public).collect())
        .is_err());
    let context = Context::current(&h.node).unwrap();
    let votes = (0..3)
        .map(|n| {
            let Message::Timeout(v) = h
                .sign(
                    n,
                    Request::Timeout {
                        context: context.clone(),
                        round: 0,
                    },
                )
                .message
            else {
                panic!()
            };
            *v
        })
        .collect();
    let tc = TimeoutCertificate::combine(votes, &h.node.trust, &h.node.evidence).unwrap();
    let before = h.agents[1].journal.clone();
    let key = h.root.join(format!("key-{}.json", h.seeds[1]));
    assert!(h.agents[1]
        .sign(
            &h.node,
            Request::Propose {
                round: 1,
                snapshot: Box::new(competing),
                timeout: Some(tc.clone())
            },
            Some(&key),
            h.heads[1]
        )
        .is_err());
    assert_eq!(h.agents[1].journal, before);
    let p = h.proposal(1, Some(tc), selected);
    let q = h.prepare(&p, &[0, 1, 2]);
    let s = h.commit(&p, &q, &[0, 1, 2]);
    h.node.finalize(s).unwrap();
    assert!(h.node.epoch_request(b.validators).is_err());
    assert!(h
        .node
        .epoch_request(candidates().into_iter().map(public).collect())
        .is_ok());
}

#[test]
fn joint_invalid_new_epoch_tail_does_not_publish_staged_authority_or_state() {
    let mut h = Harness::with_rules(bft::JOINT_RULES);
    let p = plan(&h);
    selection(&mut h, vec![Command::Reconfigure(Box::new(p))], None);
    let proof = activate(&mut h, &[0, 1, 2], &[0, 1, 2]);
    let old_evidence = h.node.evidence.clone();
    h.node.install_epoch(proof).unwrap();
    swap_new(&mut h);
    let mut candidate = h.node.bft_candidate(vec![], public(10)).unwrap();
    let block = candidate.blocks.last_mut().unwrap();
    block.header.state = Hash::ZERO;
    mine(block).unwrap();
    candidate.statement.block = block.header.id().unwrap();
    candidate.statement.state = Hash::ZERO;
    let invalid = forged_certificate(&h, candidate);
    let mut cold = old_evidence.clone();
    assert!(cold.add(invalid, &h.node.trust).is_err());
    assert_eq!(
        cold.epoch_proofs(h.node.chain.region),
        old_evidence.epoch_proofs(h.node.chain.region)
    );
    assert_eq!(cold.snapshots, old_evidence.snapshots);
}

#[test]
fn joint_plan_is_separately_admitted_and_invalid_plans_do_not_debit() {
    let h = Harness::with_rules(bft::JOINT_RULES);
    let good = plan(&h);
    let before = serde_json::to_vec(&h.node.journal).unwrap();
    for mode in 0..6 {
        let mut p = good.clone();
        match mode {
            0 => p.previous_epoch = Hash::ZERO,
            1 => p.number += 1,
            2 => p.currency = Hash::ZERO,
            3 => p.region = Hash::ZERO,
            4 => p.validators = h.seeds.iter().copied().map(public).collect(),
            _ => p.validators.reverse(),
        }
        assert!(h
            .node
            .bft_candidate(vec![Command::Reconfigure(Box::new(p))], public(10))
            .is_err());
        assert_eq!(serde_json::to_vec(&h.node.journal).unwrap(), before);
    }
    assert!(h
        .node
        .bft_candidate(
            vec![
                Command::Reconfigure(Box::new(good.clone())),
                Command::Reconfigure(Box::new(good))
            ],
            public(10)
        )
        .is_err());
    for rules in [
        bft::RULES,
        bft::EPOCH_RULES,
        DOMAIN,
        crate::segmented::RULES,
    ] {
        let mut package = bootstrap();
        for a in &mut package.admissions {
            a.rules = rules.into();
            a.signature = signature(1, &a.bytes().unwrap());
        }
        let currency = package.currency.id().unwrap();
        let region = package.admissions[0].id().unwrap();
        let other = Store::create(
            &h.root.join(format!("legacy-{}", region.to_hex())),
            package,
            region,
            &public(1),
            currency,
        )
        .unwrap();
        let mut p = plan(&h);
        p.currency = currency;
        p.region = region;
        p.previous_epoch = other.chain.epoch;
        assert!(other
            .chain
            .template(
                vec![Command::Reconfigure(Box::new(p))],
                public(10),
                &other.trust,
                &other.evidence
            )
            .is_err());
    }
}
