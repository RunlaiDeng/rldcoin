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
