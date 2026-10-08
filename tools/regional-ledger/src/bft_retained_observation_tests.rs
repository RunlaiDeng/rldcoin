//! Fresh real-signature paired reads; no failed fixture or recovered custody.
use super::retained_native_replay::inventory;
use super::*;

fn paired(mut h: Harness, heights: usize, rounds: u64) {
    h.retain = true;
    for _ in 0..heights {
        let p = h.proposal(0, None, h.node.bft_candidate(vec![], public(10)).unwrap());
        let q = h.prepare(&p, &[0, 1, 2]);
        let certified = h.commit(&p, &q, &[0, 1, 2]);
        h.node.finalize(certified).unwrap();
    }
    let context = Context::current(&h.node).unwrap();
    for round in 0..rounds {
        h.sign(
            0,
            Request::Timeout {
                context: context.clone(),
                round,
            },
        );
    }
    let heads = h.heads.clone();
    h.agents.clear();
    let before = inventory(&h.root);
    let mut original_ns = 0;
    let mut combined_ns = 0;
    for (n, seed) in h.seeds.iter().enumerate() {
        let dir = h.root.join(format!("signer-{seed}"));
        crate::verification_keys::cost::take();
        let start = std::time::Instant::now();
        let (agent, status) = Agent::inspect_with_status(&dir, &h.node).unwrap();
        let original = serde_json::to_vec(&agent.retained_messages(&h.node).unwrap()).unwrap();
        original_ns += start.elapsed().as_nanos();
        let old_cost = crate::verification_keys::cost::take();
        let status_bytes = serde_json::to_vec(&status).unwrap();
        assert_eq!(agent.head().unwrap(), heads[n]);
        drop(agent);
        crate::verification_keys::cost::take();
        let (reference, reference_status) = Agent::inspect_with_status(&dir, &h.node).unwrap();
        let reference_cost = crate::verification_keys::cost::take();
        assert_eq!(serde_json::to_vec(&reference_status).unwrap(), status_bytes);
        drop(reference);
        crate::verification_keys::cost::take();
        let start = std::time::Instant::now();
        let (agent, status, messages) = Agent::inspect_with_retained_status(&dir, &h.node).unwrap();
        let combined = serde_json::to_vec(&messages).unwrap();
        combined_ns += start.elapsed().as_nanos();
        let new_cost = crate::verification_keys::cost::take();
        assert_eq!(combined, original);
        assert_eq!(serde_json::to_vec(&status).unwrap(), status_bytes);
        assert_eq!(agent.head().unwrap(), heads[n]);
        assert_eq!(messages.len(), agent.record_count());
        assert!(new_cost.strict_attempts >= messages.len());
        assert_eq!(new_cost.strict_attempts, reference_cost.strict_attempts);
        assert_eq!(new_cost.material_requests, reference_cost.material_requests);
        assert_eq!(
            new_cost.key_admission_requests,
            reference_cost.key_admission_requests
        );
        assert_eq!(
            new_cost.native_history_reused,
            reference_cost.native_history_reused
        );
        assert_eq!(old_cost.strict_attempts, 2 * new_cost.strict_attempts);
        // The combined observation still owns custody; a concurrent read must
        // refuse rather than adopt telemetry or silently retry without locks.
        assert!(Agent::inspect_with_retained_status(&dir, &h.node).is_err());
        drop(agent);
        assert_eq!(inventory(&h.root), before);
        println!("retained-paired signer={n} strict_old={} strict_combined={} exact_output=true exact_status=true retained_records={} locks_preserved=true", old_cost.strict_attempts, new_cost.strict_attempts, messages.len());
    }
    println!("retained-paired heights={heights} extra_timeouts={rounds} original_ns={original_ns} combined_ns={combined_ns} inventory_unchanged=true fixture={}", h.root.display());
}

#[test]
fn retained_observation_classic_exact_state_messages_and_one_full_authentication() {
    paired(Harness::new(), 1, 0);
}

#[test]
fn retained_observation_paged_complete_page_tail_history_and_one_full_authentication() {
    paired(Harness::with_rules(crate::paged_bft::RULES), 3, 19);
}

#[test]
fn retained_observation_refuses_bad_signature_header_and_pending_without_output_or_mutation() {
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Manifest {
        format: String,
        scope: crate::retained_pages::Scope,
        pages: Vec<crate::history::Reference>,
        tail: Vec<bft::Record>,
        count: u64,
        head: Hash,
    }
    for attack in ["signature", "header", "pending"] {
        let mut h = Harness::with_rules(crate::paged_bft::RULES);
        h.retain = true;
        let context = Context::current(&h.node).unwrap();
        for round in 0..if attack == "signature" { 18 } else { 1 } {
            h.sign(
                0,
                Request::Timeout {
                    context: context.clone(),
                    round,
                },
            );
        }
        h.agents.clear();
        let dir = h.root.join(format!("signer-{}", h.seeds[0]));
        if attack == "signature" {
            let path = dir.join("bft-records/stream.json");
            let mut manifest: Manifest = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            assert_eq!(manifest.pages.len(), 1);
            let last = manifest.tail.last_mut().unwrap();
            let Message::Timeout(timeout) = &mut last.message else {
                panic!("actual timeout")
            };
            timeout.approval.signature = "00".repeat(64);
            manifest.head =
                crate::retained_pages::next_head(last.previous_head, manifest.count - 1, last)
                    .unwrap();
            fs::write(path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        } else if attack == "header" {
            let path = dir.join("bft-header.json");
            let mut header: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            header["journal"]["binding"]["key"] = serde_json::json!(public(90));
            fs::write(path, serde_json::to_vec(&header).unwrap()).unwrap();
        } else {
            crate::keystore::private_create(&dir.join("bft-records/stream.next"), b"{}").unwrap();
        }
        let before = inventory(&h.root);
        let original = Agent::inspect_with_status(&dir, &h.node)
            .err()
            .expect("old strict refusal");
        let combined = Agent::inspect_with_retained_status(&dir, &h.node)
            .err()
            .expect("combined strict refusal");
        assert_eq!(combined, original);
        if attack == "signature" {
            assert!(
                combined.contains("signature"),
                "hash-consistent full replay: {combined}"
            );
        }
        assert_eq!(inventory(&h.root), before);
        println!("retained-refusal attack={attack} exact_error=true no_output=true unchanged=true fixture={}", h.root.display());
    }
}
