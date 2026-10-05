use super::retained_native_replay::inventory;
use super::*;
fn certified(node: &Store, mut snapshot: Snapshot) -> Snapshot {
    let context = Context::current(node).unwrap();
    let value = snapshot.statement.id().unwrap();
    let qc = |phase| Quorum {
        context: context.clone(),
        round: 0,
        value,
        phase,
        votes: keys()[..3]
            .iter()
            .map(|s| forged_vote(*s, context.clone(), 0, value, phase))
            .collect(),
    };
    snapshot.bft = Some(Certificate {
        prepared: qc(Phase::Prepare),
        committed: qc(Phase::Commit),
    });
    snapshot
}
#[test]
fn ordinary_paged_store_crosses_64_with_native_wallet_history_and_rejects_complete_bad_tails() {
    let started = std::time::Instant::now();
    let mut package = super::super::channel_integration::package(crate::paged_bft::RULES);
    for a in &mut package.admissions {
        a.rules = crate::paged_bft::RULES.into();
        a.value_rules = Some(crate::paged_bft::rules_hash().unwrap());
        a.signature = signature(1, &a.bytes().unwrap());
    }
    let root = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "rld-paged-bft-{}",
            rld_core::generate_identity().public_key
        ));
    fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let pin = package.currency.id().unwrap();
    let region = package.admissions[0].id().unwrap();
    let mut node = Store::create(&root.join("node"), package, region, &public(1), pin).unwrap();
    let original_genesis_head = node.storage_head().unwrap();
    let mut wallet = None;
    let mut wallet_head = Hash::ZERO;
    let mut complete_first = None;
    let mut complete_latest = None;
    for height in 1..=65 {
        let commands = if height == 4 {
            crate::keystore::private_create(
                &root.join("owner.json"),
                &serde_json::to_vec(&serde_json::json!({"secret_key":hex::encode([10;32])}))
                    .unwrap(),
            )
            .unwrap();
            let mut owner =
                crate::wallet_agent::Agent::create(&root.join("owner"), &node, public(10)).unwrap();
            let old = owner.journal.head().unwrap();
            let prepared = owner
                .prepare(
                    &node,
                    crate::wallet::Request {
                        owner: public(10),
                        participants: vec![],
                        inputs: None,
                        outputs: vec![Payment {
                            owner: public(11),
                            amount: Amount(99),
                        }],
                        remote: None,
                        fee: Amount(1),
                        valid_for_blocks: 8,
                        valid_through: None,
                    },
                    old,
                )
                .unwrap();
            let signed = owner
                .sign(
                    &node,
                    prepared.draft,
                    &root.join("owner.json"),
                    prepared.review_commitment,
                    old,
                )
                .unwrap();
            wallet_head = signed.wallet_head;
            wallet = Some(owner);
            signed.commands
        } else {
            vec![]
        };
        let snapshot = certified(&node, node.bft_candidate(commands, public(10)).unwrap());
        if height == 1 {
            complete_first = Some(snapshot.clone());
        }
        node.finalize(snapshot.clone()).unwrap();
        complete_latest = Some(snapshot);
        assert_eq!(node.chain.height(), height);
        assert!(node.evidence.snapshots.len() <= MAX_SNAPSHOTS);
        assert!(node.chain.blocks.is_empty());
        if height % 16 == 0 || height == 65 {
            println!(
                "paged-store phase=certified height={height} active={} elapsed={:.3}",
                node.evidence.snapshots.len(),
                started.elapsed().as_secs_f64()
            );
        }
    }
    assert_eq!(node.evidence.snapshots.len(), 64);
    assert!(node
        .evidence
        .snapshot(complete_first.as_ref().unwrap().statement.id().unwrap())
        .is_err());
    assert_eq!(
        node.chain.ledger.minted,
        Amount(rld_pow::cumulative_emission(65))
    );
    assert!(node
        .chain
        .ledger
        .coins
        .values()
        .any(|c| c.payment.owner == public(11)
            && c.payment.amount == Amount(99)
            && c.mature <= 65));
    assert!(node.journal.replay(&public(1), pin).is_err());
    assert_eq!(node.blocks().unwrap().count(), 65);
    let head = node.storage_head().unwrap();
    let ledger = node.chain.ledger.clone();
    // Every invalid complete tail must refuse without chain/heads or disk mutation.
    let before = inventory(&root);
    let mut bad = complete_first.clone().unwrap();
    bad.bft.as_mut().unwrap().committed.votes[0]
        .approval
        .signature = "00".repeat(64);
    assert!(node.finalize(bad).is_err());
    let mut bad = node.bft_candidate(vec![], public(10)).unwrap();
    let block = bad.blocks.last_mut().unwrap();
    block.commands.push(Command::Import {
        snapshot: Hash([8; 32]),
        export: Hash([7; 32]),
    });
    block.header.commands = id("commands", &block.commands).unwrap();
    mine(block).unwrap();
    bad.statement.block = block.header.id().unwrap();
    let bad = certified(&node, bad);
    crate::conflict::CertifiedHistory::from_snapshot(&bad)
        .verify(&node.trust)
        .unwrap();
    assert!(node.finalize(bad).is_err());
    let mut bad = certified(&node, node.bft_candidate(vec![], public(10)).unwrap());
    bad.blocks.last_mut().unwrap().header.state = Hash([9; 32]);
    assert!(node.finalize(bad).is_err());
    let mut bad = certified(&node, node.bft_candidate(vec![], public(10)).unwrap());
    bad.blocks
        .first_mut()
        .unwrap()
        .commands
        .push(Command::Import {
            snapshot: Hash([8; 32]),
            export: Hash([7; 32]),
        });
    assert!(node.finalize(bad).is_err());
    assert_eq!(node.chain.ledger, ledger);
    assert_eq!(node.storage_head().unwrap(), head);
    assert_eq!(inventory(&root), before);
    // Exact old full certificate is authenticated and retained again; it never
    // selects historical state. A changed proof on that body still refuses.
    node.finalize(complete_first.unwrap()).unwrap();
    assert_eq!(node.chain.height(), 65);
    assert_eq!(node.chain.ledger, ledger);
    wallet.as_ref().unwrap().view(&node, wallet_head).unwrap();
    assert_eq!(
        wallet.as_ref().unwrap().journal.head().unwrap(),
        wallet_head
    );
    let native_head = node.storage_head().unwrap();
    let after = inventory(&root);
    drop(wallet);
    drop(node);
    assert!(
        Store::open_pinned(&root.join("node"), &public(1), pin, original_genesis_head).is_err()
    );
    let node = Store::open_pinned(&root.join("node"), &public(1), pin, native_head).unwrap();
    assert_eq!(node.chain.ledger, ledger);
    assert_eq!(node.chain.height(), 65);
    let owner = crate::wallet_agent::Agent::open(&root.join("owner"), &node).unwrap();
    assert_eq!(owner.journal.head().unwrap(), wallet_head);
    assert_eq!(node.block_at(4).unwrap().commands.len(), 1);
    assert_eq!(inventory(&root), after);
    println!("paged-store phase=complete fixture={} height=65 wallet99_mature=true actual_bft_signer_custody=false elapsed={:.3}",root.display(),started.elapsed().as_secs_f64());
    assert!(complete_latest.is_some());
}

#[test]
fn paged_store_reauthenticates_retained_legacy_region_envelopes_without_format_adoption() {
    let mut package = super::super::channel_integration::package(crate::paged_bft::RULES);
    for a in &mut package.admissions {
        a.rules = if a.region == "proxima" {
            channels::BFT_RULES
        } else {
            crate::paged_bft::RULES
        }
        .into();
        a.value_rules = Some(if a.region == "proxima" {
            channels::profile_hash().unwrap()
        } else {
            crate::paged_bft::rules_hash().unwrap()
        });
        a.signature = signature(1, &a.bytes().unwrap());
    }
    let root = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "rld-paged-mixed-{}",
            rld_core::generate_identity().public_key
        ));
    fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let pin = package.currency.id().unwrap();
    let trust = Trust::verify(&package, &public(1), pin).unwrap();
    let mut source = Store::create(
        &root.join("source"),
        package.clone(),
        trust.named("proxima").unwrap(),
        &public(1),
        pin,
    )
    .unwrap();
    let snapshot = certified(&source, source.bft_candidate(vec![], public(10)).unwrap());
    source.finalize(snapshot.clone()).unwrap();
    let mut target = Store::create(
        &root.join("target"),
        package,
        trust.named("earth").unwrap(),
        &public(1),
        pin,
    )
    .unwrap();
    let evidence = Evidence {
        snapshots: vec![snapshot.clone()],
    };
    target.add_evidence(evidence.clone()).unwrap();
    target.add_evidence(evidence).expect(
        "fully authenticated exact legacy-region envelope must not be forced into paged format",
    );
    let before = inventory(&root);
    let head = target.storage_head().unwrap();
    let mut bad = snapshot;
    bad.bft.as_mut().unwrap().committed.votes[0]
        .approval
        .signature = "00".repeat(64);
    assert!(target
        .add_evidence(Evidence {
            snapshots: vec![bad]
        })
        .is_err());
    assert_eq!(target.storage_head().unwrap(), head);
    assert_eq!(inventory(&root), before);
    assert_eq!(target.chain.height(), 0);
    assert!(source.journal.evidence.snapshots[0].base.is_none());
    println!("paged-mixed phase=complete legacy-envelope-authenticated-again=true malformed-later-refused=true no-format-conversion=true");
}

#[test]
fn ordinary_paged_agents_write_full_votes_and_replay_historical_native_locks() {
    let started = std::time::Instant::now();
    let mut h = Harness::with_rules(crate::paged_bft::RULES);
    h.retain = true;
    let initial = h.heads.clone();
    let mut last = None;
    for height in 1..=8 {
        let commands = if height == 4 {
            let (input, coin) = h
                .node
                .chain
                .ledger
                .coins
                .iter()
                .find(|(_, c)| c.mature <= 3 && c.payment.owner == public(10))
                .unwrap();
            vec![Command::Spend(Box::new(intent(
                &h.node.chain,
                &h.node.trust,
                vec![*input],
                vec![
                    Payment {
                        owner: public(11),
                        amount: Amount(99),
                    },
                    Payment {
                        owner: public(10),
                        amount: Amount(coin.payment.amount.0 - 100),
                    },
                ],
                None,
                None,
                1,
                0,
                &[10],
            )))]
        } else {
            vec![]
        };
        let candidate = h.node.bft_candidate(commands, public(10)).unwrap();
        let p = h.proposal(0, None, candidate);
        let q = h.prepare(&p, &[0, 1, 2, 3]);
        let s = h.commit(&p, &q, &[0, 1, 2, 3]);
        last = Some((p, q));
        h.node.finalize(s).unwrap();
    }
    assert!(h
        .node
        .chain
        .ledger
        .coins
        .values()
        .any(|c| c.payment.owner == public(11) && c.payment.amount == Amount(99) && c.mature <= 8));
    let (p, q) = last.unwrap();
    let request = Request::Commit {
        proposal: Box::new(p),
        prepared: q,
    };
    for (n, agent) in h.agents.iter_mut().enumerate() {
        assert!(agent.journal.records.is_empty());
        assert!(agent.journal.state(&h.node).is_err());
        assert!(agent.record_count() >= 16);
        let before = inventory(&h.root);
        let recovered = agent
            .sign(&h.node, request.clone(), None, h.heads[n])
            .unwrap();
        assert!(recovered.recovered_exact_retry);
        assert_eq!(recovered.head, h.heads[n]);
        assert!(agent
            .sign(&h.node, request.clone(), None, initial[n])
            .is_err());
        let next = Request::Timeout {
            context: Context::current(&h.node).unwrap(),
            round: 0,
        };
        assert!(!agent.contains_request(&h.node, &next).unwrap());
        assert!(agent.sign(&h.node, next, None, h.heads[n]).is_err());
        assert_eq!(agent.head().unwrap(), h.heads[n]);
        assert_eq!(inventory(&h.root), before);
        crate::keystore::private_create(&h.root.join(format!("caller-{n}.head")), &h.heads[n].0)
            .unwrap();
    }
    let native_head = h.node.storage_head().unwrap();
    let counts: Vec<_> = h.agents.iter().map(Agent::record_count).collect();
    let heads = h.heads.clone();
    let package = h.node.journal.bootstrap.clone();
    let pin = package.currency.id().unwrap();
    let before = inventory(&h.root);
    h.agents.clear();
    let node = Store::create(
        &h.root.join("empty-unused-native"),
        package.clone(),
        h.node.chain.region,
        &public(1),
        pin,
    )
    .unwrap();
    // Complete non-genesis custody cannot open against a rolled-back native view.
    for seed in &h.seeds {
        assert!(Agent::open(&h.root.join(format!("signer-{seed}")), &node).is_err());
    }
    drop(node);
    // Exclude the deliberately added empty counterexample directory from the
    // original immutable signer/native inventory comparison below.
    let stable = inventory(&h.root);
    for (n, seed) in h.seeds.iter().enumerate() {
        let (mut agent, status) =
            Agent::open_with_status(&h.root.join(format!("signer-{seed}")), &h.node).unwrap();
        assert_eq!(
            serde_json::to_value(status).unwrap()["head"],
            serde_json::to_value(heads[n]).unwrap()
        );
        assert_eq!(agent.head().unwrap(), heads[n]);
        assert_eq!(agent.record_count(), counts[n]);
        let caller =
            crate::keystore::private_read(&h.root.join(format!("caller-{n}.head")), 32).unwrap();
        assert_eq!(*caller, heads[n].0);
        assert!(
            agent
                .sign(&h.node, request.clone(), None, heads[n])
                .unwrap()
                .recovered_exact_retry
        );
    }
    assert_eq!(h.node.storage_head().unwrap(), native_head);
    assert_eq!(inventory(&h.root), stable);
    assert!(before
        .iter()
        .all(|(path, row)| stable.get(path) == Some(row)));
    println!("paged-agent complete native_height=8 signatures=72 native_owner99_mature=true same_process_cold=true records={counts:?} elapsed={:.3} fixture={}",started.elapsed().as_secs_f64(),h.root.display());
}

#[test]
fn paged_signer_replays_absent_active_parents_and_refuses_hash_consistent_bad_vote() {
    let mut h = Harness::with_rules(crate::paged_bft::RULES);
    h.retain = true;
    for _ in 0..3 {
        let p = h.proposal(0, None, h.node.bft_candidate(vec![], public(10)).unwrap());
        let q = h.prepare(&p, &[0, 1, 2, 3]);
        let s = h.commit(&p, &q, &[0, 1, 2, 3]);
        h.node.finalize(s).unwrap();
    }
    let agent = h.agents.remove(0);
    let dir = h.root.join(format!("signer-{}", h.seeds[0]));
    let header = crate::keystore::private_read(&dir.join("bft-header.json"), MAX_BYTES).unwrap();
    let manifest =
        crate::keystore::private_read(&dir.join("bft-records/stream.json"), MAX_BYTES).unwrap();
    let scope: crate::retained_pages::Scope = serde_json::from_value(
        serde_json::from_slice::<serde_json::Value>(&manifest).unwrap()["scope"].clone(),
    )
    .unwrap();
    let count = agent.record_count();
    let head = agent.head().unwrap();
    drop(agent);
    // Remove ONLY the process-local working set. Full signed native records and
    // the authoritative current ledger/selection remain in the original store.
    h.node.evidence.snapshots.clear();
    let before = inventory(&h.root);
    let reopened = Agent::open(&dir, &h.node).unwrap();
    assert_eq!(reopened.head().unwrap(), head);
    assert_eq!(reopened.record_count(), count);
    assert_eq!(inventory(&h.root), before);
    drop(reopened);
    let original =
        crate::retained_pages::Stream::<bft::Record>::open(&dir.join("bft-records"), &scope, head)
            .unwrap();
    let mut records = vec![];
    original
        .visit(head, |r| {
            records.push(r.clone());
            Ok(())
        })
        .unwrap();
    drop(original);
    let Message::Vote(vote) = &mut records.last_mut().unwrap().message else {
        panic!("last native response must be the retained commit vote");
    };
    vote.approval.signature = "00".repeat(64);
    let damaged = h.root.join("hash-consistent-bad-signer");
    fs::create_dir(&damaged).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&damaged, fs::Permissions::from_mode(0o700)).unwrap();
    }
    crate::keystore::private_create(&damaged.join("LOCK"), b"").unwrap();
    crate::keystore::private_create(&damaged.join("bft-header.json"), &header).unwrap();
    let mut stream =
        crate::retained_pages::Stream::<bft::Record>::create(&damaged.join("bft-records"), scope)
            .unwrap();
    stream.append(&records, stream.storage_head()).unwrap();
    // Integrity checks are satisfied. Native signatures must still reject.
    stream.visit(stream.storage_head(), |_| Ok(())).unwrap();
    drop(stream);
    let before = inventory(&h.root);
    assert!(Agent::open(&damaged, &h.node).is_err());
    assert_eq!(inventory(&h.root), before);
    println!("paged-signer full-native-history-without-active-parent=true hash-consistent-bad-signature-refused=true native_height=3 actual_archive_capacity=false");
}

#[test]
fn paged_signer_refuses_new_pending_native_incident_on_already_open_store() {
    let mut h = Harness::with_rules(crate::paged_bft::RULES);
    h.retain = true;
    h.agents.clear();
    // Simulate a newly durable incident publication marker while the native
    // Store lock stays held. It grants no incident/ledger authority.
    fs::write(h.root.join("node/INCIDENT_GUARD"), Hash([7; 32]).0).unwrap();
    let before = inventory(&h.root);
    assert!(
        Agent::open(&h.root.join(format!("signer-{}", h.seeds[0])), &h.node).is_err(),
        "paged signer accepted native history with a new pending incident marker"
    );
    assert_eq!(inventory(&h.root), before);
    println!("paged signer pending native incident refuses held-open Store; no votes or authority");
}
