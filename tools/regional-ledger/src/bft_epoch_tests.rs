use super::*;

pub(super) fn append(h: &mut Harness, commands: Vec<Command>) -> Snapshot {
    let b = h.node.template(commands, public(10)).unwrap();
    let mut b = b;
    mine(&mut b).unwrap();
    let mut snapshot = h.node.snapshot_request().unwrap();
    snapshot.blocks.push(b);
    snapshot.statement = h.node.chain.statement(&h.node.trust).unwrap();
    let terminal = snapshot.blocks.last().unwrap();
    snapshot.statement.height = terminal.header.height;
    snapshot.statement.block = terminal.header.id().unwrap();
    snapshot.statement.state = terminal.header.state;
    let p = h.proposal(0, None, snapshot);
    let q = h.prepare(&p, &[0, 1, 2]);
    let s = h.commit(&p, &q, &[0, 1, 2]);
    h.node.finalize(s.clone()).unwrap();
    s
}
pub(super) fn candidates() -> Vec<u8> {
    let mut seeds = vec![6, 7, 8, 9];
    seeds.sort_by_key(|s| public(*s));
    seeds
}
pub(super) fn request(h: &Harness, proposal: &epoch::Transition) -> Request {
    Request::EpochFence {
        context: Context::current(&h.node).unwrap(),
        proposal: Box::new(proposal.clone()),
        previous_epochs: h.node.evidence.epoch_proofs(h.node.chain.region),
    }
}
fn activate(h: &mut Harness) -> (epoch::Transition, Vec<(crate::signer::Agent, Hash)>) {
    let mut proof = h
        .node
        .epoch_request(candidates().into_iter().map(public).collect())
        .unwrap();
    let unsigned = proof.clone();
    for n in 0..4 {
        let Message::EpochApproval {
            statement,
            approval,
        } = h.sign(n, request(h, &unsigned)).message
        else {
            panic!()
        };
        assert_eq!(*statement, proof.statement);
        proof.old_approvals.push(approval);
    }
    let mut fresh = vec![];
    for seed in candidates() {
        let mut agent = crate::signer::Agent::create(
            &h.root.join(format!("activation-{seed}")),
            &h.node,
            public(seed),
        )
        .unwrap();
        let path = h.root.join(format!("key-{seed}.json"));
        crate::keystore::private_create(
            &path,
            &serde_json::to_vec(&serde_json::json!({"secret_key":hex::encode([seed;32])})).unwrap(),
        )
        .unwrap();
        let head = agent.journal.head().unwrap();
        let result = agent
            .handoff(&h.node, unsigned.clone(), &path, head)
            .unwrap();
        proof.new_approvals.push(result.approval);
        fresh.push((agent, result.lock_head));
    }
    (proof, fresh)
}

#[test]
fn complete_epoch_activation_preserves_native_value_and_restarts_both_journals() {
    let mut h = Harness::with_rules(bft::EPOCH_RULES);
    for _ in 0..3 {
        append(&mut h, vec![]);
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
    let payment = intent(
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
    append(&mut h, vec![Command::Spend(Box::new(payment))]);
    let ledger = h.node.chain.ledger.clone();
    let closing = h.node.chain.finalized.unwrap();
    let (proof, fresh) = activate(&mut h);
    let retained = h
        .agents
        .iter()
        .map(|a| a.journal.clone())
        .collect::<Vec<_>>();
    let eid = h.node.install_epoch(proof.clone()).unwrap();
    assert_eq!(h.node.chain.ledger, ledger);
    assert_eq!(h.node.chain.finalized, Some(closing));
    assert_eq!(h.node.chain.epoch, eid);
    for (n, old) in retained.iter().enumerate() {
        let state = old.state(&h.node).unwrap();
        assert_eq!(state.epoch_fence, Some(eid));
        assert!(h.agents[n]
            .sign(
                &h.node,
                Request::Timeout {
                    context: Context::current(&h.node).unwrap(),
                    round: 0
                },
                Some(&h.root.join(format!("key-{}.json", h.seeds[n]))),
                h.heads[n]
            )
            .is_err());
    }
    let old_agents = std::mem::take(&mut h.agents);
    drop(old_agents);
    for (n, seed) in h.seeds.iter().enumerate() {
        let mut old = Agent::open(&h.root.join(format!("signer-{seed}")), &h.node).unwrap();
        assert_eq!(old.journal.head().unwrap(), h.heads[n]);
        let last = old.journal.records.last().unwrap().clone();
        let recovered = old
            .sign(&h.node, last.request.clone(), None, last.previous_head)
            .unwrap();
        assert!(recovered.recovered_exact_retry);
        assert_eq!(recovered.message, last.message);
    }
    drop(fresh);
    h.seeds = candidates();
    h.agents = h
        .seeds
        .iter()
        .map(|seed| {
            Agent::create(
                &h.root.join(format!("signer-{seed}")),
                &h.node,
                public(*seed),
            )
            .unwrap()
        })
        .collect();
    h.heads = h.agents.iter().map(|a| a.journal.head().unwrap()).collect();
    let next = append(&mut h, vec![]);
    assert_eq!(next.statement.epoch, eid);
    assert_eq!(h.node.chain.height(), 5);
    assert_eq!(h.node.chain.ledger, ledger);
    assert!(h
        .node
        .epoch_request(retained.iter().map(|j| j.binding.key.clone()).collect())
        .is_err());
    assert!(Agent::create(&h.root.join("late-new-signer"), &h.node, public(h.seeds[0])).is_err());
    let pin = h.node.trust.currency().unwrap();
    let dir = h.root.join("node");
    let placeholder = Store::create(
        &h.root.join("placeholder"),
        h.node.journal.bootstrap.clone(),
        h.node.trust.named("proxima").unwrap(),
        &public(1),
        pin,
    )
    .unwrap();
    drop(std::mem::replace(&mut h.node, placeholder));
    h.node = Store::open(&dir, &public(1), pin).unwrap();
    assert_eq!(h.node.chain.ledger, ledger);
    assert_eq!(h.node.chain.epoch, eid);
    for (n, agent) in h.agents.iter().enumerate() {
        assert_eq!(agent.journal.head().unwrap(), h.heads[n]);
        assert!(agent.journal.state(&h.node).is_ok());
    }
    let cold = VerifiedEvidence::verify(&h.node.journal.evidence, &h.node.trust).unwrap();
    assert_eq!(cold.snapshot(next.statement.id().unwrap()).unwrap(), &next);
    println!(
        "{}",
        serde_json::json!({"format":"RLD-BFT-UNANIMOUS-EPOCH-SAMPLE-V1","native_implementation":implementation().unwrap(),"fixture_only":true,"live_rld":false,"height":5,"old_fences":4,"new_approvals":4,"regular_prepare_votes":3,"regular_commit_votes":3,"signed_owner_payment_preserved":true,"all_state_replayed_from_genesis":true,"old_exact_response_recovered_without_key":true,"late_new_signer_refused":true,"fault_tolerant_reconfiguration_qualified":false,"independent_custody_qualified":false})
    );
}

#[test]
fn missing_or_changed_approval_and_legacy_profile_cannot_activate_epoch() {
    let mut legacy = Harness::new();
    append(&mut legacy, vec![]);
    assert!(legacy
        .node
        .epoch_request(candidates().into_iter().map(public).collect())
        .is_err());
    let mut h = Harness::with_rules(bft::EPOCH_RULES);
    append(&mut h, vec![]);
    let (proof, _fresh) = activate(&mut h);
    let before = serde_json::to_vec(&h.node.journal).unwrap();
    for mode in 0..6 {
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
                bad.statement.closing_height += 1;
            }
            4 => {
                bad.new_approvals[0].signature = "00".repeat(64);
            }
            _ => {
                bad.statement.previous_epoch = Hash::ZERO;
            }
        }
        assert!(h.node.install_epoch(bad).is_err());
        assert_eq!(serde_json::to_vec(&h.node.journal).unwrap(), before);
    }
    assert!(h
        .node
        .epoch_request(h.seeds.iter().copied().map(public).collect())
        .is_err());
    let mut overlap = candidates().into_iter().map(public).collect::<Vec<_>>();
    overlap[0] = public(h.seeds[0]);
    overlap.sort();
    assert!(h.node.epoch_request(overlap).is_err());
    h.node.install_epoch(proof).unwrap();
}

#[test]
fn already_prepared_successor_refuses_fence_and_cannot_use_legacy_signer() {
    let mut h = Harness::with_rules(bft::EPOCH_RULES);
    let mut legacy = crate::signer::Agent::create(
        &h.root.join("old-key-at-genesis"),
        &h.node,
        public(h.seeds[0]),
    )
    .unwrap();
    append(&mut h, vec![]);
    let unsigned = h
        .node
        .epoch_request(candidates().into_iter().map(public).collect())
        .unwrap();
    let mut block = h.node.template(vec![], public(10)).unwrap();
    mine(&mut block).unwrap();
    let mut snapshot = h.node.snapshot_request().unwrap();
    snapshot.blocks.push(block.clone());
    snapshot.statement.height = block.header.height;
    snapshot.statement.block = block.header.id().unwrap();
    snapshot.statement.state = block.header.state;
    let p = h.proposal(0, None, snapshot);
    h.sign(0, Request::Prepare(Box::new(p)));
    let before = h.heads[0];
    let req = request(&h, &unsigned);
    assert!(h.agents[0]
        .sign(
            &h.node,
            req,
            Some(&h.root.join(format!("key-{}.json", h.seeds[0]))),
            before
        )
        .is_err());
    assert_eq!(h.agents[0].journal.head().unwrap(), before);
    let legacy_head = legacy.journal.head().unwrap();
    assert!(legacy
        .handoff(
            &h.node,
            unsigned,
            &h.root.join(format!("key-{}.json", h.seeds[0])),
            legacy_head
        )
        .is_err());
    assert_eq!(legacy.journal.head().unwrap(), legacy_head);
    let binding = crate::signer::Binding {
        currency: h.node.trust.currency().unwrap(),
        region: h.node.chain.region,
        key: public(h.seeds[0]),
    };
    let fake = crate::signer::Journal {
        binding,
        records: vec![],
    };
    // A separate late old-key signer directory cannot bypass the BFT lock.
    assert!(crate::signer::Agent::create(
        &h.root.join("old-key-legacy"),
        &h.node,
        fake.binding.key
    )
    .is_err());
}

#[test]
fn interrupted_fence_recovers_exactly_and_external_head_rejects_old_backup() {
    let mut h = Harness::with_rules(bft::EPOCH_RULES);
    append(&mut h, vec![]);
    let proposal = h
        .node
        .epoch_request(candidates().into_iter().map(public).collect())
        .unwrap();
    let req = request(&h, &proposal);
    let old = h.agents[0].journal.clone();
    let old_head = h.heads[0];
    assert!(h.agents[0]
        .sign(&h.node, req.clone(), None, old_head)
        .is_err());
    assert_eq!(h.agents[0].journal, old);
    let response = h.sign(0, req.clone());
    let sealed = h.agents[0].journal.clone();
    let seed = h.seeds[0];
    let dir = h.root.join(format!("signer-{seed}"));
    drop(std::mem::take(&mut h.agents));
    fs::write(dir.join("bft.json"), serde_json::to_vec(&old).unwrap()).unwrap();
    crate::keystore::private_create(&dir.join("bft.next"), &serde_json::to_vec(&sealed).unwrap())
        .unwrap();
    let mut recovered = Agent::open(&dir, &h.node).unwrap();
    let exact = recovered
        .sign(&h.node, req.clone(), None, old_head)
        .unwrap();
    assert!(exact.recovered_exact_retry);
    assert_eq!(exact.message, response.message);
    assert_eq!(exact.head, response.head);
    assert!(recovered
        .journal
        .state(&h.node)
        .unwrap()
        .epoch_fence
        .is_some());
    assert!(!dir.join("bft.next").exists());
    drop(recovered);
    fs::write(dir.join("bft.json"), serde_json::to_vec(&old).unwrap()).unwrap();
    let mut rolled_back = Agent::open(&dir, &h.node).unwrap();
    assert!(rolled_back
        .sign(
            &h.node,
            req,
            Some(&h.root.join(format!("key-{seed}.json"))),
            response.head
        )
        .is_err());
    assert_eq!(rolled_back.journal, old);
}
