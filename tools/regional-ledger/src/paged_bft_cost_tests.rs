use super::paged_integration::{certify, retain};
use super::retained_native_replay::inventory;
use super::*;
#[test]
fn paged_sign_cost_ten_native_heights_and_full_pinned_cold() {
    let started = std::time::Instant::now();
    let mut h = Harness::with_rules(crate::paged_bft::RULES);
    h.retain = true;
    for n in 0..4 {
        retain(&h.root, n, h.heads[n]);
    }
    bft::sign_cost::take();
    crate::verification_keys::cost::take();
    crate::keystore::private_create(
        &h.root.join("owner-key.json"),
        &serde_json::to_vec(&serde_json::json!({"secret_key":hex::encode([10;32])})).unwrap(),
    )
    .unwrap();
    let mut owner = None;
    let mut owner_head = Hash::ZERO;
    let mut certification_ns = 0u128;
    let mut finalize_ns = 0u128;
    for height in 1..=10 {
        let commands = if height == 4 {
            let mut wallet = crate::wallet_agent::Agent::create(
                &h.root.join("owner-wallet"),
                &h.node,
                public(10),
            )
            .unwrap();
            let old = wallet.journal.head().unwrap();
            retain(&h.root, 4, old);
            let prepared = wallet
                .prepare(
                    &h.node,
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
            let signed = wallet
                .sign(
                    &h.node,
                    prepared.draft,
                    &h.root.join("owner-key.json"),
                    prepared.review_commitment,
                    old,
                )
                .unwrap();
            owner_head = signed.wallet_head;
            // Retain the separate owner head before releasing commands.
            retain(&h.root, 4, owner_head);
            owner = Some(wallet);
            signed.commands
        } else {
            vec![]
        };
        let clock = std::time::Instant::now();
        let snapshot = certify(&mut h, commands);
        certification_ns += clock.elapsed().as_nanos();
        let clock = std::time::Instant::now();
        h.node.finalize(snapshot).unwrap();
        finalize_ns += clock.elapsed().as_nanos();
        println!(
            "paged-cost complete_height={height} records={:?} elapsed={:.3}",
            h.agents.iter().map(Agent::record_count).collect::<Vec<_>>(),
            started.elapsed().as_secs_f64()
        );
    }
    let cost = bft::sign_cost::take();
    let material = crate::verification_keys::cost::take();
    assert!(material.material_hits > 90 && material.strict_attempts > 90);
    assert_eq!(
        material.material_requests,
        material.material_hits + material.material_validations
    );
    assert_eq!(cost.completed_new_signatures, 90);
    let total_ns: u128 = cost.phases_ns.iter().sum();
    assert!(total_ns > 0);
    assert!(material.key_admission_requests > 90);
    assert_eq!(
        material.material_requests,
        material.strict_attempts + material.key_admission_requests
    );
    // The original Core predicate still runs on misses; this exact fresh
    // fixture already admitted every replay key before preflight begins.
    assert_eq!(cost.original_key_admission_calls, 0);
    assert_eq!(cost.original_key_admission_ns, 0);
    let preflight_ns: u128 = cost.preflight_ns.iter().sum();
    assert!(preflight_ns > 0 && preflight_ns <= cost.phases_ns[0]);
    let publication_ns: u128 = cost.publication_ns.iter().sum();
    assert!(publication_ns > 0 && publication_ns <= cost.phases_ns[4]);
    assert_eq!(cost.completed_stream_appends, 90);
    assert!(cost.completed_old_records > 90);
    let replay_ns: u128 = cost.replay_ns.iter().sum();
    assert!(replay_ns > 0 && replay_ns <= cost.phases_ns[0]);
    let native_ns: u128 = cost.native_record_ns.iter().sum();
    assert!(native_ns > 0 && native_ns <= cost.phases_ns[0]);
    assert!(cost.native_records > 90 && cost.active_evidence_serialized_bytes > 0);
    assert!(cost.original_proposal_checks > 90 && cost.repeated_exact_proposal_checks > 90);
    assert!(cost.full_proposal_proofs > 90 && cost.reused_proposal_proofs > 90);
    assert_eq!(
        cost.full_proposal_proofs + cost.reused_proposal_proofs,
        cost.original_proposal_checks
    );
    assert_eq!(
        cost.reused_proposal_proofs,
        cost.repeated_exact_proposal_checks
    );
    let append_ns: u128 = cost.append_ns.iter().sum();
    assert!(append_ns > 0 && append_ns <= cost.publication_ns[0]);
    let replay_and_validation_fraction =
        (cost.phases_ns[0] + cost.phases_ns[3]) as f64 / total_ns as f64;
    owner.as_ref().unwrap().view(&h.node, owner_head).unwrap();
    let root = h.root.clone();
    let currency = h.node.trust.currency().unwrap();
    let native = h.node.storage_head().unwrap();
    crate::keystore::private_create(&root.join("caller-native.head"), &native.0).unwrap();
    let heads = h.heads.clone();
    let seeds = h.seeds.clone();
    drop(owner);
    drop(h);
    let before = inventory(&root);
    let separately_retained_native = Hash(
        fs::read(root.join("caller-native.head"))
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let node = Store::open_pinned(
        &root.join("node"),
        &public(1),
        currency,
        separately_retained_native,
    )
    .unwrap();
    assert_eq!(node.chain.height(), 10);
    for (n, seed) in seeds.iter().enumerate() {
        let agent = Agent::open(&root.join(format!("signer-{seed}")), &node).unwrap();
        assert_eq!(agent.head().unwrap(), heads[n]);
        assert_eq!(
            fs::read(root.join(format!("caller-{n}.head"))).unwrap(),
            heads[n].0
        );
    }
    let wallet = crate::wallet_agent::Agent::open(&root.join("owner-wallet"), &node).unwrap();
    assert_eq!(wallet.journal.head().unwrap(), owner_head);
    assert_eq!(fs::read(root.join("caller-4.head")).unwrap(), owner_head.0);
    wallet.view(&node, owner_head).unwrap();
    assert!(node
        .chain
        .ledger
        .coins
        .values()
        .any(|c| c.payment.owner == public(11)
            && c.payment.amount == Amount(99)
            && c.mature <= 10));
    assert_eq!(inventory(&root), before);
    println!(
        "paged-cost-result {}",
        serde_json::json!({
            "public_key_material_hits":material.material_hits,
            "public_key_material_full_validations":material.material_validations,
            "actual_strict_message_verification_attempts":material.strict_attempts,
            "heights":10,"actual_signatures":cost.completed_new_signatures,
            "Core_key_material_requests_admission_first_replay_misses_seconds":(material.material_requests,material.key_admission_requests,cost.original_key_admission_calls,cost.original_key_admission_ns as f64/1e9),
            "actual_full_nested_proposal_proofs":cost.full_proposal_proofs,
            "actual_reused_nested_proposal_proofs_this_invocation":cost.reused_proposal_proofs,
            "actual_original_proposal_checks":cost.original_proposal_checks,
            "actual_repeated_exact_proposal_checks_same_executed_native_and_trust":cost.repeated_exact_proposal_checks,
            "preflight_phase_names":["original_header_and_native_cursor_initialization","full_retained_signer_record_visit_and_native_history_replay","complete_current_native_cursor_and_byte_guard"],
            "preflight_phase_seconds":cost.preflight_ns.map(|ns|ns as f64/1e9),
            "phase_names":["first_complete_replay","exact_request_scan","current_execution_and_sign","new_record_and_current_recheck","durable_append"],
            "publication_phase_names":["original_durable_stream_append","postpublication_header_and_signer_stream_read","final_native_history_guard_and_response_head"],
            "native_record_phase_names":["full_native_record_authentication_and_execution","canonical_current_ledger_capacity_serialization","clone_and_canonical_whole_active_evidence_capacity_serialization"],
            "native_record_phase_seconds":cost.native_record_ns.map(|ns|ns as f64/1e9),
            "actual_native_history_records":cost.native_records,
            "actual_whole_active_evidence_bytes_serialized":cost.active_evidence_serialized_bytes,
            "old_record_replay_phase_names":["native_history_context_and_observation","original_request_proof_lock_and_deterministic_response","own_response_signature_and_stream_head"],
            "old_record_replay_phase_seconds":cost.replay_ns.map(|ns|ns as f64/1e9),
            "actual_old_record_replays":cost.completed_old_records,
            "append_phase_names":["old_structural_stream_visit","stage_complete_records_and_shared_capacity","original_durable_pending_pages_manifest_and_cleanup"],
            "append_phase_seconds":cost.append_ns.map(|ns|ns as f64/1e9),
            "actual_observed_stream_appends":cost.completed_stream_appends,
            "publication_phase_seconds":cost.publication_ns.map(|ns|ns as f64/1e9),
            "phase_seconds":cost.phases_ns.map(|ns|ns as f64/1e9),"measured_sign_seconds":total_ns as f64/1e9,
            "replay_and_validation_fraction":replay_and_validation_fraction,
        "first_replay_fraction":cost.phases_ns[0] as f64/total_ns as f64,
        "post_sign_validation_fraction":cost.phases_ns[3] as f64/total_ns as f64,
        "second_complete_old_replay":false,
            "certification_seconds":certification_ns as f64/1e9,"store_finalize_seconds":finalize_ns as f64/1e9,
            "same_process_full_genesis_cold":true,"wallet99_mature":true,"private_inventory_unchanged":true,
            "actual_over128_or_height65":false,"full_fault":false,"independent_freshness":false,"total_test_seconds":started.elapsed().as_secs_f64()
        })
    );
}

#[test]
fn scoped_proposal_proof_matches_reference_and_warm_bad_quorum_still_refuses() {
    // Fresh signed no-value Native inputs; the shadow kernels grant no custody.
    let mut h = Harness::with_rules(crate::paged_bft::RULES);
    h.retain = true;
    let candidate = h.node.bft_candidate(vec![], public(10)).unwrap();
    let proposal = h.proposal(0, None, candidate);
    let prepared = h.prepare(&proposal, &[0, 1, 2]);
    let boundary = h.node.storage_head().unwrap();
    let mut proof = bft::ProposalProof::default();
    let reference = proposal.verify(&h.node.trust, &h.node.evidence).unwrap();
    assert_eq!(
        proof
            .verify(&proposal, &h.node.trust, &h.node.evidence, boundary)
            .unwrap(),
        reference
    );
    assert_eq!(
        proof
            .verify(&proposal, &h.node.trust, &h.node.evidence, boundary)
            .unwrap(),
        reference
    );
    assert_eq!((proof.full_checks, proof.reused_checks), (1, 1));
    let mut altered = proposal.clone();
    let mut signature = hex::decode(&altered.leader.signature).unwrap();
    signature[0] ^= 1;
    altered.leader.signature = hex::encode(signature);
    assert!(proposal.verify(&h.node.trust, &h.node.evidence).is_ok());
    assert_eq!(
        proof.verify(&altered, &h.node.trust, &h.node.evidence, boundary),
        altered.verify(&h.node.trust, &h.node.evidence)
    );
    assert!(altered.verify(&h.node.trust, &h.node.evidence).is_err());
    // A failed replacement leaves only the old exact proof, never the bad one.
    assert_eq!(
        proof
            .verify(&proposal, &h.node.trust, &h.node.evidence, boundary)
            .unwrap(),
        reference
    );
    let mut changed_trust = h.node.trust.clone();
    changed_trust.binding = Hash([9; 32]);
    assert_eq!(
        proof.verify(&proposal, &changed_trust, &h.node.evidence, boundary),
        proposal.verify(&changed_trust, &h.node.evidence)
    );
    assert!(proposal.verify(&changed_trust, &h.node.evidence).is_err());
    // Changed execution metadata forces a new full proof; this synthetic token
    // test never initializes a Native ledger or signer history.
    let full = proof.full_checks;
    assert_eq!(
        proof
            .verify(&proposal, &h.node.trust, &h.node.evidence, Hash([8; 32]))
            .unwrap(),
        reference
    );
    assert_eq!(proof.full_checks, full + 1);

    let before = inventory(&h.root);
    let signing_key = public(h.seeds[0]);
    let mut oracle = bft::State::default();
    let mut scoped = bft::State::default();
    let mut scoped_proof = bft::ProposalProof::default();
    let prepare = Request::Prepare(Box::new(proposal.clone()));
    assert_eq!(
        oracle.reference_proposal_apply(&prepare, &signing_key, &h.node.trust, &h.node.evidence),
        scoped.scoped_proposal_apply(
            &prepare,
            &signing_key,
            &h.node.trust,
            &h.node.evidence,
            boundary,
            &mut scoped_proof
        )
    );
    assert_eq!(
        serde_json::to_vec(&oracle).unwrap(),
        serde_json::to_vec(&scoped).unwrap()
    );
    let previous = serde_json::to_vec(&scoped).unwrap();
    let mut bad_quorum = prepared.clone();
    let mut signature = hex::decode(&bad_quorum.votes[0].approval.signature).unwrap();
    signature[0] ^= 1;
    bad_quorum.votes[0].approval.signature = hex::encode(signature);
    let bad = Request::Commit {
        proposal: Box::new(proposal.clone()),
        prepared: bad_quorum,
    };
    let refused =
        oracle.reference_proposal_apply(&bad, &signing_key, &h.node.trust, &h.node.evidence);
    assert!(refused.is_err());
    assert_eq!(
        refused,
        scoped.scoped_proposal_apply(
            &bad,
            &signing_key,
            &h.node.trust,
            &h.node.evidence,
            boundary,
            &mut scoped_proof
        )
    );
    assert_eq!(serde_json::to_vec(&scoped).unwrap(), previous);
    assert_eq!(serde_json::to_vec(&oracle).unwrap(), previous);
    let commit = Request::Commit {
        proposal: Box::new(proposal.clone()),
        prepared: prepared.clone(),
    };
    assert_eq!(
        oracle.reference_proposal_apply(&commit, &signing_key, &h.node.trust, &h.node.evidence),
        scoped.scoped_proposal_apply(
            &commit,
            &signing_key,
            &h.node.trust,
            &h.node.evidence,
            boundary,
            &mut scoped_proof
        )
    );
    assert_eq!(
        serde_json::to_vec(&oracle).unwrap(),
        serde_json::to_vec(&scoped).unwrap()
    );
    assert_eq!(scoped_proof.full_checks, 1);
    assert_eq!(scoped_proof.reused_checks, 2);
    assert_eq!(inventory(&h.root), before);
    let certified = h.commit(&proposal, &prepared, &[0, 1, 2]);
    h.node.finalize(certified).unwrap();
    for n in 0..4 {
        retain(&h.root, n, h.heads[n]);
    }
    let root = h.root.clone();
    let head = h.node.storage_head().unwrap();
    let currency = h.node.trust.currency().unwrap();
    let ledger = h.node.chain.ledger.clone();
    let heads = h.heads.clone();
    let seeds = h.seeds.clone();
    drop(h);
    let before = inventory(&root);
    let cold = Store::open_pinned(&root.join("node"), &public(1), currency, head).unwrap();
    assert_eq!(cold.chain.height(), 1);
    assert_eq!(cold.chain.ledger, ledger);
    for (n, seed) in seeds.iter().enumerate() {
        let signer = Agent::open(&root.join(format!("signer-{seed}")), &cold).unwrap();
        assert_eq!(signer.head().unwrap(), heads[n]);
        assert_eq!(
            fs::read(root.join(format!("caller-{n}.head"))).unwrap(),
            heads[n].0
        );
    }
    assert_eq!(inventory(&root), before);
    println!("same-invocation nested proof exact Native/trust/input binding, reference states equal, warm changedproof/wrongtrust/badquorum refuses, all outer and QC signatures remain, fullNative1 all4signer cold unchanged");
}
