use super::*;
use super::{
    epoch_activation::{candidates, request},
    joint_activation::selection,
};
use crate::{
    joint_epoch::{CarriedApproval, Plan, Role},
    joint_roles::{ReadyAgent, ReadyRequest},
};

#[test]
fn voter_origin_authenticates_distinct_closing_quorums_before_matching_complete_statement() {
    let mut h = Harness::with_rules(bft::ROLE_RULES);
    let mut next = vec![h.seeds[0], h.seeds[1], h.seeds[2], 6];
    next.sort_by_key(|s| public(*s));
    let plan = Plan {
        currency: h.node.trust.currency().unwrap(),
        region: h.node.chain.region,
        previous_epoch: h.node.chain.epoch,
        number: 1,
        validators: next.iter().copied().map(public).collect(),
    };
    let snapshot = h
        .node
        .bft_candidate(vec![Command::Reconfigure(Box::new(plan))], public(10))
        .unwrap();
    let proposal = h.proposal(0, None, snapshot);
    let quorum = h.prepare(&proposal, &[0, 1, 2, 3]);
    let closing = h.commit(&proposal, &quorum, &[0, 1, 2, 3]);
    h.node.finalize(closing).unwrap();
    let selected = h
        .node
        .epoch_request(next.into_iter().map(public).collect())
        .unwrap();
    let (mut proof, ready) = approve(&mut h, &selected);
    let qc = proof.closing.bft.as_mut().unwrap();
    qc.prepared.votes.truncate(3);
    qc.committed.votes.truncate(3);
    assert_eq!(proof.statement, selected.statement);
    assert_ne!(proof.closing, selected.closing);
    let old_seeds = h.seeds.clone();
    let old_bytes = old_seeds
        .iter()
        .map(|s| fs::read(h.root.join(format!("signer-{s}/bft.json"))).unwrap())
        .collect::<Vec<_>>();
    let dirs = rollover(&mut h, &proof, ready);
    for (n, agent) in h.agents.iter().enumerate() {
        let origin = agent.journal.origin.as_ref().unwrap();
        assert_eq!(*origin.proof, proof);
        assert_eq!(*origin.ready.scope.proposal, selected);
        assert!(agent.journal.state(&h.node).is_ok());
        let mut invalid = agent.journal.clone();
        invalid
            .origin
            .as_mut()
            .unwrap()
            .proof
            .closing
            .bft
            .as_mut()
            .unwrap()
            .committed
            .votes[0]
            .approval
            .signature = "00".into();
        assert!(invalid.state(&h.node).is_err());
        let mut invalid = agent.journal.clone();
        invalid
            .origin
            .as_mut()
            .unwrap()
            .ready
            .scope
            .proposal
            .closing
            .bft
            .as_mut()
            .unwrap()
            .prepared
            .votes[0]
            .approval
            .signature = "00".into();
        assert!(invalid.state(&h.node).is_err());
        assert_eq!(
            fs::read(dirs[n].join("bft.json")).unwrap(),
            serde_json::to_vec(&agent.journal).unwrap()
        );
    }
    for (n, seed) in old_seeds.iter().enumerate() {
        assert_eq!(
            fs::read(h.root.join(format!("signer-{seed}/bft.json"))).unwrap(),
            old_bytes[n]
        );
    }
    drop(std::mem::take(&mut h.agents));
    let (_, _, cold) = h
        .node
        .journal
        .replay(&public(1), h.node.trust.currency().unwrap())
        .unwrap();
    assert_eq!(cold.ledger, h.node.chain.ledger);
    assert_eq!(cold.epoch, h.node.chain.epoch);
    for dir in dirs {
        let reopened = Agent::open(&dir, &h.node).unwrap();
        assert!(reopened.journal.state(&h.node).is_ok());
    }
}

#[test]
fn unsigned_readiness_initialization_preview_and_exact_recovery_never_sign_or_adopt_wrong_heads() {
    let mut h = Harness::with_rules(bft::ROLE_RULES);
    let proposal = selected(&mut h, candidates(), vec![]);
    let request = ReadyRequest {
        proposal: Box::new(proposal),
        previous_epochs: vec![],
    };
    let preview = crate::joint_roles::ReadyCreation::observe(
        &ReadyAgent::initial_journal(&h.node, public(6), request.clone()).unwrap(),
    )
    .unwrap();
    let dir = h.root.join("initial-ready");
    assert!(!dir.exists());
    let agent = ReadyAgent::create(&dir, &h.node, public(6), request).unwrap();
    assert_eq!(
        crate::joint_roles::ReadyCreation::observe(&agent.journal).unwrap(),
        preview
    );
    drop(agent);
    fs::rename(dir.join("ready.json"), dir.join("ready.next")).unwrap();
    let before = fs::read(dir.join("ready.next")).unwrap();
    let mut wrong = preview.clone();
    wrong.head = Hash([18; 32]);
    assert!(ReadyAgent::recover_creation(&dir, &h.node, &wrong).is_err());
    assert_eq!(fs::read(dir.join("ready.next")).unwrap(), before);
    assert!(!dir.join("ready.json").exists());
    let mut recovered = ReadyAgent::recover_creation(&dir, &h.node, &preview).unwrap();
    assert_eq!(recovered.journal.head().unwrap(), preview.head);
    assert!(recovered.sign(&h.node, None, preview.head, true).is_err());
    assert!(recovered.journal.approval.is_none());
    let key = h.root.join("initial-ready-key.json");
    crate::keystore::private_create(
        &key,
        &serde_json::to_vec(&serde_json::json!({"secret_key":hex::encode([6;32])})).unwrap(),
    )
    .unwrap();
    let signed = recovered
        .sign(&h.node, Some(&key), preview.head, false)
        .unwrap();
    drop(recovered);
    let before = fs::read(dir.join("ready.json")).unwrap();
    assert!(ReadyAgent::recover_creation(&dir, &h.node, &preview).is_err());
    assert_eq!(fs::read(dir.join("ready.json")).unwrap(), before);
    assert_eq!(
        ReadyAgent::open(&dir, &h.node)
            .unwrap()
            .journal
            .head()
            .unwrap(),
        signed.head
    );
}

#[test]
fn exact_empty_voter_initialization_recovers_after_progress_but_never_resets_a_used_voter() {
    let mut h = Harness::with_rules(bft::ROLE_RULES);
    let proposal = selected(&mut h, candidates(), vec![]);
    let (proof, ready) = approve(&mut h, &proposal);
    let dirs = rollover(&mut h, &proof, ready);
    let marker = crate::joint_roles::VoterCreation::observe(&h.agents[3].journal).unwrap();
    let used_marker = crate::joint_roles::VoterCreation::observe(&h.agents[0].journal).unwrap();
    selection(&mut h, vec![], None);
    assert!(h.agents[3].journal.records.is_empty());
    drop(std::mem::take(&mut h.agents));
    let dir = &dirs[3];
    fs::rename(dir.join("bft.json"), dir.join("bft.next")).unwrap();
    let before = fs::read(dir.join("bft.next")).unwrap();
    let mut wrong = marker.clone();
    wrong.creation.pin.height += 1;
    assert!(Agent::recover_role_creation(dir, &h.node, &wrong).is_err());
    assert_eq!(fs::read(dir.join("bft.next")).unwrap(), before);
    assert!(!dir.join("bft.json").exists());
    let recovered = Agent::recover_role_creation(dir, &h.node, &marker).unwrap();
    assert_eq!(recovered.journal.head().unwrap(), marker.head);
    assert!(recovered.journal.records.is_empty());
    assert_eq!(recovered.journal.creation.pin.height, 1);
    drop(recovered);
    let used = fs::read(dirs[0].join("bft.json")).unwrap();
    assert!(Agent::recover_role_creation(&dirs[0], &h.node, &used_marker).is_err());
    assert_eq!(fs::read(dirs[0].join("bft.json")).unwrap(), used);
}

fn selected(h: &mut Harness, mut seeds: Vec<u8>, commands: Vec<Command>) -> epoch::Transition {
    seeds.sort_by_key(|s| public(*s));
    let (previous_epoch, number, _, _) = h
        .node
        .evidence
        .epoch_state(&h.node.trust, h.node.chain.region)
        .unwrap();
    let plan = Plan {
        currency: h.node.trust.currency().unwrap(),
        region: h.node.chain.region,
        previous_epoch,
        number: number + 1,
        validators: seeds.iter().map(|s| public(*s)).collect(),
    };
    let mut commands = commands;
    commands.push(Command::Reconfigure(Box::new(plan)));
    selection(h, commands, None);
    h.node
        .epoch_request(seeds.into_iter().map(public).collect())
        .unwrap()
}

fn approve(
    h: &mut Harness,
    proposal: &epoch::Transition,
) -> (epoch::Transition, Vec<(u8, ReadyAgent, Hash)>) {
    approve_with_missing_fence(h, proposal, None)
}
fn approve_with_missing_fence(
    h: &mut Harness,
    proposal: &epoch::Transition,
    missing: Option<usize>,
) -> (epoch::Transition, Vec<(u8, ReadyAgent, Hash)>) {
    let previous_epochs = h.node.evidence.epoch_proofs(h.node.chain.region);
    let mut votes = vec![];
    // Four retained local fences; only the first three are needed by this QC.
    for n in 0..4 {
        if Some(n) == missing {
            continue;
        }
        let Message::EpochApproval { approval, .. } = h.sign(n, request(h, proposal)).message
        else {
            panic!()
        };
        if n < 3 {
            votes.push(CarriedApproval {
                format: "RLD-JOINT-EPOCH-APPROVAL-V2".into(),
                proposal: Box::new(proposal.clone()),
                previous_epochs: previous_epochs.clone(),
                role: Role::Old,
                approval,
            });
        }
    }
    let mut ready = vec![];
    for (n, key) in proposal.statement.validators.iter().enumerate() {
        let seed = (2..64).find(|s| public(*s) == *key).unwrap();
        let keyfile = h.root.join(format!("key-{seed}.json"));
        if !keyfile.exists() {
            crate::keystore::private_create(
                &keyfile,
                &serde_json::to_vec(&serde_json::json!({"secret_key":hex::encode([seed;32])}))
                    .unwrap(),
            )
            .unwrap();
        }
        let mut agent = ReadyAgent::create(
            &h.root
                .join(format!("ready-{}-{seed}", proposal.statement.number)),
            &h.node,
            key.clone(),
            ReadyRequest {
                proposal: Box::new(proposal.clone()),
                previous_epochs: previous_epochs.clone(),
            },
        )
        .unwrap();
        let before = agent.journal.head().unwrap();
        assert!(agent.sign(&h.node, None, before, true).is_err());
        let signed = agent.sign(&h.node, Some(&keyfile), before, false).unwrap();
        assert!(!signed.recovered_exact_retry);
        let retry = agent
            .sign(
                &h.node,
                Some(Path::new("/absent-private-key")),
                before,
                true,
            )
            .unwrap();
        assert!(retry.recovered_exact_retry);
        assert_eq!(signed.approval, retry.approval);
        assert_eq!(signed.head, retry.head);
        if n < 3 {
            votes.push(signed.approval);
        }
        ready.push((seed, agent, signed.head));
    }
    let proof = crate::joint_epoch::combine(&votes, &h.node.trust, &h.node.evidence).unwrap();
    assert_eq!(proof.old_approvals.len(), 3);
    assert_eq!(proof.new_approvals.len(), 3);
    (proof, ready)
}

#[test]
fn continuing_key_without_its_local_fence_cannot_create_or_first_sign_in_next_era() {
    let mut h = Harness::with_rules(bft::ROLE_RULES);
    let unsealed = h.seeds[3];
    let successor = vec![h.seeds[0], h.seeds[1], unsealed, 6];
    let proposal = selected(&mut h, successor, vec![]);
    let (proof, ready) = approve_with_missing_fence(&mut h, &proposal, Some(3));
    let old_head = h.heads[3];
    let old_bytes = fs::read(h.root.join(format!("signer-{unsealed}/bft.json"))).unwrap();
    h.node.install_epoch(proof.clone()).unwrap();
    let (_, readiness, ready_head) = ready.iter().find(|(seed, _, _)| *seed == unsealed).unwrap();
    let dir = h.root.join("unsealed-voter");
    assert!(Agent::create_role(
        &dir,
        &h.node,
        public(unsealed),
        Some((&h.agents[3], old_head)),
        readiness,
        *ready_head,
        proof
    )
    .err()
    .unwrap()
    .contains("fenced custody"));
    assert!(!dir.exists());
    let request = Request::Timeout {
        context: Context::current(&h.node).unwrap(),
        round: 0,
    };
    let error = h.agents[3]
        .sign(
            &h.node,
            request,
            Some(Path::new("/absent-private-key")),
            old_head,
        )
        .unwrap_err();
    assert!(error.contains("cannot change era")); // Refusal before opening a signing key.
    assert_eq!(h.agents[3].journal.head().unwrap(), old_head);
    assert_eq!(
        fs::read(h.root.join(format!("signer-{unsealed}/bft.json"))).unwrap(),
        old_bytes
    );
}

fn rollover(
    h: &mut Harness,
    proof: &epoch::Transition,
    ready: Vec<(u8, ReadyAgent, Hash)>,
) -> Vec<PathBuf> {
    h.node.install_epoch(proof.clone()).unwrap();
    let old_agents = std::mem::take(&mut h.agents);
    let old_seeds = h.seeds.clone();
    let old_heads = h.heads.clone();
    let mut dirs = vec![];
    h.seeds.clear();
    h.heads.clear();
    for (seed, readiness, ready_head) in ready {
        let old = old_seeds
            .iter()
            .position(|s| *s == seed)
            .map(|n| (&old_agents[n], old_heads[n]));
        let denied = h
            .root
            .join(format!("denied-{}-{seed}", proof.statement.number));
        assert!(Agent::create(&denied, &h.node, public(seed)).is_err());
        assert!(!denied.exists());
        if let Some((agent, head)) = old {
            assert!(Agent::create_role(
                &denied,
                &h.node,
                public(seed),
                None,
                &readiness,
                ready_head,
                proof.clone()
            )
            .is_err());
            assert!(Agent::create_role(
                &denied,
                &h.node,
                public(seed),
                Some((agent, Hash([91; 32]))),
                &readiness,
                ready_head,
                proof.clone()
            )
            .is_err());
            assert_eq!(agent.journal.head().unwrap(), head);
            assert!(!denied.exists());
        }
        assert!(Agent::create_role(
            &denied,
            &h.node,
            public(seed),
            old,
            &readiness,
            Hash([92; 32]),
            proof.clone()
        )
        .is_err());
        assert!(!denied.exists());
        let dir = h
            .root
            .join(format!("voter-{}-{seed}", proof.statement.number));
        let agent = Agent::create_role(
            &dir,
            &h.node,
            public(seed),
            old,
            &readiness,
            ready_head,
            proof.clone(),
        )
        .unwrap();
        let mut stripped = agent.journal.clone();
        stripped.origin = None;
        assert!(stripped.state(&h.node).is_err());
        h.heads.push(agent.journal.head().unwrap());
        h.agents.push(agent);
        h.seeds.push(seed);
        dirs.push(dir);
    }
    dirs
}

#[test]
fn role_scoped_zero_through_three_continuing_keys_replay_native_value_and_two_handoffs() {
    for overlap in 0..4 {
        let mut h = Harness::with_rules(bft::ROLE_RULES);
        for _ in 0..3 {
            selection(&mut h, vec![], None);
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
        let pay = intent(
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
        let successor = h
            .seeds
            .iter()
            .take(overlap)
            .copied()
            .chain(candidates().into_iter().take(4 - overlap))
            .collect();
        let proposal = selected(&mut h, successor, vec![Command::Spend(Box::new(pay))]);
        assert_eq!(
            proposal.statement.activation.as_deref(),
            Some(crate::joint_epoch::ROLE_ACTIVATION)
        );
        let (proof, ready) = approve(&mut h, &proposal);
        let ledger = h.node.chain.ledger.clone();
        rollover(&mut h, &proof, ready);
        assert_eq!(h.node.chain.ledger, ledger);
        for _ in 0..2 {
            selection(&mut h, vec![], None);
        }
        let input = coins(&h.node.chain, 11)[0];
        let destination = h
            .node
            .trust
            .regions
            .iter()
            .find(|(id, _)| **id != h.node.chain.region)
            .unwrap()
            .0;
        let export = intent(
            &h.node.chain,
            &h.node.trust,
            vec![input],
            vec![],
            Some(*destination),
            Some(Payment {
                owner: public(12),
                amount: Amount(100),
            }),
            0,
            0,
            &[11],
        );
        let second = h.seeds.iter().take(2).copied().chain([50, 51]).collect();
        let proposal = selected(&mut h, second, vec![Command::Spend(Box::new(export))]);
        let (proof, ready) = approve(&mut h, &proposal);
        let ledger = h.node.chain.ledger.clone();
        let dirs = rollover(&mut h, &proof, ready);
        let next = selection(&mut h, vec![], None);
        assert_eq!(h.node.chain.ledger, ledger);
        assert_eq!(ledger.minted, Amount(300));
        assert_eq!(ledger.exports.len(), 1);
        assert_eq!(next.statement.epoch, proof.statement.id().unwrap());
        assert_eq!(h.node.evidence.epoch_proofs(h.node.chain.region).len(), 2);
        let evidence = VerifiedEvidence::verify(&h.node.journal.evidence, &h.node.trust).unwrap();
        assert_eq!(
            evidence.snapshot(next.statement.id().unwrap()).unwrap(),
            &next
        );
        let (_, _, replayed) = h
            .node
            .journal
            .replay(&public(1), h.node.trust.currency().unwrap())
            .unwrap();
        assert_eq!(replayed.ledger, ledger);
        assert_eq!(replayed.epoch, proof.statement.id().unwrap());
        drop(std::mem::take(&mut h.agents));
        for (n, dir) in dirs.iter().enumerate() {
            let agent = Agent::open(dir, &h.node).unwrap();
            assert_eq!(agent.journal.head().unwrap(), h.heads[n]);
            assert!(agent
                .journal
                .origin
                .as_ref()
                .unwrap()
                .ready
                .approval
                .is_some());
        }
    }
}

#[test]
fn overlapping_role_relabelling_changed_readiness_and_retired_key_rejoining_refuse() {
    let mut h = Harness::with_rules(bft::ROLE_RULES);
    let successor: Vec<_> = h.seeds.iter().take(3).copied().chain([6]).collect();
    let proposal = selected(&mut h, successor, vec![]);
    let (proof, ready) = approve(&mut h, &proposal);
    let shared = proof
        .old_approvals
        .iter()
        .find(|a| proof.statement.validators.contains(&a.key))
        .unwrap();
    let old = CarriedApproval {
        format: "RLD-JOINT-EPOCH-APPROVAL-V2".into(),
        proposal: Box::new(proposal.clone()),
        previous_epochs: vec![],
        role: Role::Old,
        approval: shared.clone(),
    };
    old.verify(&h.node.trust, &h.node.evidence).unwrap();
    let mut wrong = old.clone();
    wrong.role = Role::New;
    assert!(wrong.verify(&h.node.trust, &h.node.evidence).is_err());
    let new = ready
        .iter()
        .find(|(_, r, _)| r.journal.binding.key == shared.key)
        .unwrap()
        .1
        .journal
        .carried()
        .unwrap();
    let mut wrong = new.clone();
    wrong.role = Role::Old;
    assert!(wrong.verify(&h.node.trust, &h.node.evidence).is_err());
    let mut wrong = new.clone();
    wrong.format = "RLD-JOINT-EPOCH-APPROVAL-V1".into();
    assert!(wrong.verify(&h.node.trust, &h.node.evidence).is_err());
    let before = serde_json::to_vec(&h.node.journal).unwrap();
    for mode in 0..3 {
        let mut bad = proof.clone();
        match mode {
            0 => bad.new_approvals = bad.old_approvals.clone(),
            1 => bad.old_approvals = bad.new_approvals.clone(),
            _ => bad.statement.activation = Some(crate::joint_epoch::ACTIVATION.into()),
        }
        assert!(h.node.install_epoch(bad).is_err());
        assert_eq!(serde_json::to_vec(&h.node.journal).unwrap(), before);
    }
    let r = &ready[0].1;
    let head = r.journal.head().unwrap();
    let mut bad = r.journal.clone();
    bad.approval = ready[1].1.journal.approval.clone();
    assert!(bad.validate(&h.node).is_err());
    let mut bad = r.journal.clone();
    bad.binding.role = Role::Old;
    assert!(bad.validate(&h.node).is_err());
    assert_eq!(r.journal.head().unwrap(), head);
    let removed = *h
        .seeds
        .iter()
        .find(|s| !proof.statement.validators.contains(&public(**s)))
        .unwrap();
    rollover(&mut h, &proof, ready);
    selection(&mut h, vec![], None);
    let (previous_epoch, number, _, _) = h
        .node
        .evidence
        .epoch_state(&h.node.trust, h.node.chain.region)
        .unwrap();
    let mut validators: Vec<_> = h
        .seeds
        .iter()
        .take(3)
        .map(|s| public(*s))
        .chain([public(removed)])
        .collect();
    validators.sort();
    let plan = Plan {
        currency: h.node.trust.currency().unwrap(),
        region: h.node.chain.region,
        previous_epoch,
        number: number + 1,
        validators,
    };
    assert!(h
        .node
        .bft_candidate(vec![Command::Reconfigure(Box::new(plan))], public(10))
        .is_err());
}

#[test]
fn readiness_interrupted_signed_extension_recovers_without_key_and_refuses_unsigned_or_changed_tail(
) {
    let mut h = Harness::with_rules(bft::ROLE_RULES);
    let proposal = selected(&mut h, candidates(), vec![]);
    let dir = h.root.join("crash-ready");
    let key = h.root.join("crash-key.json");
    crate::keystore::private_create(
        &key,
        &serde_json::to_vec(&serde_json::json!({"secret_key":hex::encode([6;32])})).unwrap(),
    )
    .unwrap();
    let mut agent = ReadyAgent::create(
        &dir,
        &h.node,
        public(6),
        ReadyRequest {
            proposal: Box::new(proposal),
            previous_epochs: vec![],
        },
    )
    .unwrap();
    let unsigned = agent.journal.clone();
    let head = unsigned.head().unwrap();
    assert!(agent
        .sign(&h.node, Some(Path::new("/absent")), Hash([9; 32]), false)
        .is_err());
    assert_eq!(agent.journal, unsigned);
    let signed = agent.sign(&h.node, Some(&key), head, false).unwrap();
    let complete = agent.journal.clone();
    drop(agent);
    // Exact pre-response persistence boundary: retained old + signed next.
    fs::write(
        dir.join("ready.json"),
        serde_json::to_vec(&unsigned).unwrap(),
    )
    .unwrap();
    crate::keystore::private_create(
        &dir.join("ready.next"),
        &serde_json::to_vec(&complete).unwrap(),
    )
    .unwrap();
    let mut agent = ReadyAgent::open(&dir, &h.node).unwrap();
    assert!(!dir.join("ready.next").exists());
    let retry = agent.sign(&h.node, None, head, true).unwrap();
    assert_eq!(retry.approval, signed.approval);
    assert_eq!(retry.head, signed.head);
    drop(agent);
    let retained = fs::read(dir.join("ready.json")).unwrap();
    let mut bad = complete;
    bad.binding.role = Role::Old;
    crate::keystore::private_create(&dir.join("ready.next"), &serde_json::to_vec(&bad).unwrap())
        .unwrap();
    assert!(ReadyAgent::open(&dir, &h.node).is_err());
    assert_eq!(fs::read(dir.join("ready.json")).unwrap(), retained);
    assert!(dir.join("ready.next").exists());
}
