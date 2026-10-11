//! Public no-value fixtures for receive/observation composition; no custody upgrade.
use super::*;
use crate::bft_network::{self, receive_origin_phase};

fn fixture() -> Harness {
    let rules = crate::paged_bft::ORIGIN_NETWORK_RULES;
    let mut package = crate::tests::channel_integration::package(rules);
    for a in &mut package.admissions {
        a.rules = rules.into();
        a.value_rules = Some(crate::paged_bft::rules_hash_for(rules).unwrap());
        a.signature = signature(1, &a.bytes().unwrap());
    }
    let root = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "rld-receive-phase-{}",
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
    let node = Store::create(&root.join("node"), package, region, &public(1), pin).unwrap();
    let seeds = keys();
    let agents = seeds
        .iter()
        .map(|s| {
            crate::keystore::private_create(
                &root.join(format!("key-{s}.json")),
                &serde_json::to_vec(&serde_json::json!({"secret_key":hex::encode([*s;32])}))
                    .unwrap(),
            )
            .unwrap();
            Agent::create(&root.join(format!("signer-{s}")), &node, public(*s)).unwrap()
        })
        .collect::<Vec<_>>();
    let heads = agents.iter().map(|a| a.head().unwrap()).collect();
    Harness {
        root,
        node,
        agents,
        heads,
        seeds,
        retain: false,
    }
}
fn receiver(h: &Harness, name: &str) -> (Store, PathBuf, Hash) {
    let node = Store::create(
        &h.root.join(name),
        h.node.journal.bootstrap.clone(),
        h.node.chain.region,
        &public(1),
        h.node.trust.currency().unwrap(),
    )
    .unwrap();
    let dir = h.root.join(format!("{name}-signer"));
    let agent = Agent::create(&dir, &node, public(h.seeds[0])).unwrap();
    let head = agent.head().unwrap();
    drop(agent);
    (node, dir, head)
}
fn proposal(h: &mut Harness) -> bft_network::WireEnvelope {
    let s = h.node.bft_candidate(vec![], public(10)).unwrap();
    let p = h.proposal(0, None, s);
    bft_network::local_envelope(
        bft_network::Body::Signed(Box::new(Message::Proposal(Box::new(p)))),
        &h.node,
    )
    .unwrap()
    .envelope
}
#[test]
fn phase_matches_separate_receive_and_locked_status_without_signing() {
    let mut h = fixture();
    let wire = proposal(&mut h);
    let (mut old, old_dir, _) = receiver(&h, "old");
    let (mut new, dir, head) = receiver(&h, "new");
    let before = head;
    let checked = bft_network::receive_origin_batch(&mut old, vec![wire.clone()]).unwrap();
    let (_, status) = Agent::inspect_with_status(&old_dir, &old).unwrap();
    let result =
        receive_origin_phase(&mut new, vec![wire], &dir, head, &public(h.seeds[0])).unwrap();
    assert_eq!(
        serde_json::to_value(checked).unwrap(),
        serde_json::to_value(&result.checked).unwrap()
    );
    assert_eq!(
        serde_json::to_value(status).unwrap(),
        serde_json::to_value(&result.signer).unwrap()
    );
    assert_eq!(new.storage_head().unwrap(), old.storage_head().unwrap());
    assert_eq!(result.history_head, new.storage_head().unwrap());
    assert_eq!(
        serde_json::to_value(&result.signer).unwrap()["head"],
        serde_json::json!(before)
    );
    assert_eq!(new.chain.ledger.minted, Amount::ZERO);
}
#[test]
fn stale_signer_head_and_shared_signer_lock_refuse_without_signature() {
    let mut h = fixture();
    let wire = proposal(&mut h);
    let (mut node, dir, head) = receiver(&h, "target");
    let old = node.storage_head().unwrap();
    assert!(receive_origin_phase(
        &mut node,
        vec![wire.clone()],
        &dir,
        Hash::ZERO,
        &public(h.seeds[0])
    )
    .is_err());
    assert!(receive_origin_phase(&mut node, vec![wire.clone()], &dir, head, &public(99)).is_err());
    let agent = Agent::open(&dir, &node).unwrap();
    assert!(receive_origin_phase(&mut node, vec![wire], &dir, head, &public(h.seeds[0])).is_err());
    assert_eq!(node.storage_head().unwrap(), old);
    assert_eq!(agent.head().unwrap(), head);
}
#[test]
fn invalid_later_signature_cannot_receive_or_manufacture_incident() {
    let mut h = fixture();
    let wire = proposal(&mut h);
    let (mut node, dir, head) = receiver(&h, "target");
    let old = node.storage_head().unwrap();
    let mut bad = wire.clone();
    let bft_network::Body::Signed(m) = &mut bad.body else {
        panic!()
    };
    let Message::Proposal(p) = m.as_mut() else {
        panic!()
    };
    p.leader.signature = "00".repeat(64);
    assert!(
        receive_origin_phase(&mut node, vec![wire, bad], &dir, head, &public(h.seeds[0])).is_err()
    );
    assert_eq!(node.storage_head().unwrap(), old);
    assert!(node.journal.incident_ids.is_empty());
    assert_eq!(
        serde_json::to_value(Agent::inspect_with_status(&dir, &node).unwrap().1).unwrap()["head"],
        serde_json::json!(head)
    );
}
#[test]
fn duplicate_replay_and_cold_open_preserve_exact_heads_and_value() {
    let mut h = fixture();
    let wire = proposal(&mut h);
    let (mut node, dir, head) = receiver(&h, "target");
    for _ in 0..2 {
        let r = receive_origin_phase(
            &mut node,
            vec![wire.clone(); 4],
            &dir,
            head,
            &public(h.seeds[0]),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(&r.signer).unwrap()["head"],
            serde_json::json!(head)
        );
    }
    let native_head = node.storage_head().unwrap();
    let currency = node.trust.currency().unwrap();
    let ledger = node.chain.ledger.clone();
    drop(node);
    let cold =
        Store::open_pinned_inspection(&h.root.join("target"), &public(1), currency, native_head)
            .unwrap();
    assert_eq!(
        serde_json::to_value(&cold.chain.ledger).unwrap(),
        serde_json::to_value(ledger).unwrap()
    );
    assert_eq!(
        serde_json::to_value(Agent::inspect_with_status(&dir, &cold).unwrap().1).unwrap()["head"],
        serde_json::json!(head)
    );
}
#[test]
fn failed_postreceive_observation_keeps_certified_prefix_for_cold_recovery() {
    let mut h = fixture();
    let s = h.node.bft_candidate(vec![], public(10)).unwrap();
    let p = h.proposal(0, None, s);
    let q = h.prepare(&p, &[0, 1, 2]);
    let s = h.commit(&p, &q, &[0, 1, 2]);
    let wire = bft_network::local_envelope(bft_network::Body::Finalized(Box::new(s)), &h.node)
        .unwrap()
        .envelope;
    let (mut node, dir, head) = receiver(&h, "target");
    assert!(bft_network::receive_origin_phase_failure_for_test(
        &mut node,
        vec![wire],
        &dir,
        head,
        &public(h.seeds[0])
    )
    .is_err());
    assert_eq!(node.chain.height(), 1);
    let native_head = node.storage_head().unwrap();
    let pin = node.trust.currency().unwrap();
    drop(node);
    let cold = Store::open_pinned_inspection(&h.root.join("target"), &public(1), pin, native_head)
        .unwrap();
    assert_eq!(cold.chain.height(), 1);
    cold.chain.ledger.audit().unwrap();
    assert_eq!(
        serde_json::to_value(Agent::inspect_with_status(&dir, &cold).unwrap().1).unwrap()["head"],
        serde_json::json!(head)
    );
}

#[test]
fn certified_sync_precedes_single_current_observation_or_custody_refusal() {
    let mut h = fixture();
    let s = h.node.bft_candidate(vec![], public(10)).unwrap();
    let p = h.proposal(0, None, s);
    let q = h.prepare(&p, &[0, 1, 2]);
    let s = h.commit(&p, &q, &[0, 1, 2]);
    let wire = bft_network::local_envelope(bft_network::Body::Finalized(Box::new(s)), &h.node)
        .unwrap()
        .envelope;
    for mode in ["current", "stale", "locked"] {
        let (mut node, dir, head) = receiver(&h, mode);
        let held = if mode == "locked" {
            Some(Agent::inspect_with_status(&dir, &node).unwrap().0)
        } else {
            None
        };
        let result = receive_origin_phase(
            &mut node,
            vec![wire.clone()],
            &dir,
            if mode == "stale" { Hash([0; 32]) } else { head },
            &public(h.seeds[0]),
        );
        assert_eq!(node.chain.height(), 1);
        if mode == "current" {
            let received = result.unwrap();
            assert_eq!(received.context.parent_height, 1);
            drop(received);
        } else {
            assert!(result.is_err());
        }
        drop(held);
        let native_head = node.storage_head().unwrap();
        let pin = node.trust.currency().unwrap();
        drop(node);
        let cold = Store::open_pinned_inspection(&h.root.join(mode), &public(1), pin, native_head)
            .unwrap();
        assert_eq!(cold.chain.height(), 1);
        cold.chain.ledger.audit().unwrap();
        let (_, current) = Agent::inspect_with_status(&dir, &cold).unwrap();
        assert_eq!(
            serde_json::to_value(current).unwrap()["head"],
            serde_json::json!(head)
        );
    }
}

#[test]
fn authentic_conflict_survives_bad_later_envelope_without_credit() {
    let mut h = fixture();
    let mut wire = proposal(&mut h);
    let c = Context::current(&h.node).unwrap();
    let branch = |miner| {
        let mut s = h.node.bft_candidate(vec![], public(miner)).unwrap();
        let value = s.statement.id().unwrap();
        let qc = |phase| Quorum {
            context: c.clone(),
            round: 0,
            value,
            phase,
            votes: h.seeds[..3]
                .iter()
                .map(|seed| forged_vote(*seed, c.clone(), 0, value, phase))
                .collect(),
        };
        s.bft = Some(Certificate {
            prepared: qc(Phase::Prepare),
            committed: qc(Phase::Commit),
        });
        bft_network::local_envelope(bft_network::Body::Finalized(Box::new(s)), &h.node)
            .unwrap()
            .envelope
    };
    let a = branch(10);
    let b = branch(11);
    let bft_network::Body::Signed(m) = &mut wire.body else {
        panic!()
    };
    let Message::Proposal(p) = m.as_mut() else {
        panic!()
    };
    p.leader.signature = "00".repeat(64);
    let (mut node, dir, head) = receiver(&h, "target");
    assert!(
        receive_origin_phase(&mut node, vec![a, b, wire], &dir, head, &public(h.seeds[0])).is_err()
    );
    assert_eq!(node.chain.height(), 0);
    assert_eq!(node.chain.ledger.minted, Amount::ZERO);
    assert!(node.safety.check_region(node.chain.region).is_err());
    let pin = node.trust.currency().unwrap();
    drop(node);
    let cold = Store::open(&h.root.join("target"), &public(1), pin).unwrap();
    assert!(cold.safety.check_region(cold.chain.region).is_err());
    assert_eq!(cold.chain.height(), 0);
}
