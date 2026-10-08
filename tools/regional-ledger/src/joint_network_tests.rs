use super::joint_activation::{activate, plan, selection, swap_new};
use super::*;
use crate::{
    bft_network::{Body, Envelope, FORMAT},
    joint_epoch::{CarriedApproval, Role},
};

fn approvals(p: &epoch::Transition) -> Vec<CarriedApproval> {
    let mut unsigned = p.clone();
    unsigned.old_approvals.clear();
    unsigned.new_approvals.clear();
    let mut out = vec![];
    for (role, list) in [(Role::Old, &p.old_approvals), (Role::New, &p.new_approvals)] {
        for approval in list {
            out.push(CarriedApproval {
                format: "RLD-JOINT-EPOCH-APPROVAL-V1".into(),
                proposal: Box::new(unsigned.clone()),
                previous_epochs: vec![],
                role,
                approval: approval.clone(),
            });
        }
    }
    out
}
fn envelope(h: &Harness, body: Body) -> Envelope {
    Envelope {
        format: FORMAT.into(),
        origins: None,
        currency: h.node.trust.currency().unwrap(),
        region: h.node.chain.region,
        evidence: h.node.journal.evidence.clone(),
        body,
    }
}
fn selected() -> (Harness, epoch::Transition) {
    let mut h = Harness::with_rules(bft::JOINT_RULES);
    let p = plan(&h);
    selection(&mut h, vec![Command::Reconfigure(Box::new(p))], None);
    let proof = activate(&mut h, &[0, 1, 2, 3], &[0, 1, 2, 3]);
    (h, proof)
}

#[test]
fn joint_carried_approvals_bind_exact_native_selection_and_old_new_roles() {
    let (h, proof) = selected();
    let votes = approvals(&proof);
    for vote in &votes {
        envelope(&h, Body::EpochApproval(Box::new(vote.clone())))
            .verify(&h.node)
            .unwrap();
    }
    assert_eq!(
        crate::joint_epoch::combine(&votes, &h.node.trust, &h.node.evidence).unwrap(),
        proof
    );
    for mode in 0..4 {
        let mut bad = votes[0].clone();
        match mode {
            0 => bad.role = Role::New,
            1 => bad.approval.signature = "00".repeat(64),
            2 => bad.proposal.selection.as_mut().unwrap().commands.clear(),
            _ => bad.format = "unknown".into(),
        }
        assert!(envelope(&h, Body::EpochApproval(Box::new(bad)))
            .verify(&h.node)
            .is_err());
    }
    assert!(crate::joint_epoch::combine(&votes[..4], &h.node.trust, &h.node.evidence).is_err());
}

#[test]
fn joint_complete_quorum_variants_authenticate_without_rewriting_original_authority() {
    let (mut h, proof) = selected();
    let mut a = proof.clone();
    a.old_approvals.pop();
    a.new_approvals.pop();
    let mut b = proof;
    b.old_approvals.remove(0);
    b.new_approvals.remove(0);
    let eid = h.node.install_epoch(a.clone()).unwrap();
    let before = serde_json::to_vec(&h.node.journal).unwrap();
    crate::bft_network::activate(&mut h.node, b.clone(), envelope_evidence(&before)).unwrap();
    assert_eq!(serde_json::to_vec(&h.node.journal).unwrap(), before);
    assert_eq!(h.node.evidence.epoch_proofs(h.node.chain.region), vec![a]);
    let mut bad = b;
    bad.old_approvals[0].signature = "00".repeat(64);
    let evidence = h.node.journal.evidence.clone();
    assert!(crate::bft_network::activate(&mut h.node, bad, evidence).is_err());
    assert_eq!(h.node.chain.epoch, eid);
    assert_eq!(serde_json::to_vec(&h.node.journal).unwrap(), before);
}
fn envelope_evidence(raw: &[u8]) -> Evidence {
    serde_json::from_slice::<crate::storage::Journal>(raw)
        .unwrap()
        .evidence
}

#[test]
fn activation_observation_authenticates_variants_and_retains_original_selected_bytes() {
    let (mut h, proof) = selected();
    let mut original = proof.clone();
    original.old_approvals.pop();
    original.new_approvals.pop();
    let eid = h.node.install_epoch(original.clone()).unwrap();
    let before = serde_json::to_vec(&h.node.journal).unwrap();
    let wire = envelope(&h, Body::EpochActivation(Box::new(proof.clone())));
    let request = Hash([17; 32]);
    let observed = crate::bft_network::activate_observed(&mut h.node, wire, None, request).unwrap();
    assert_eq!(
        observed.format,
        crate::bft_network::ACTIVATION_OBSERVATION_FORMAT
    );
    assert_eq!(observed.request_sha256, request);
    assert_eq!(observed.carried_index, None);
    assert_eq!(observed.epoch, eid);
    assert_eq!(observed.activated_epoch, eid);
    assert_eq!(observed.proofs, vec![original]);
    assert!(observed.fixture_only);
    assert!(!observed.independent_freshness_qualified);
    assert!(!observed.signing_authority);
    assert_eq!(serde_json::to_vec(&h.node.journal).unwrap(), before);
    let mut bad = proof;
    bad.new_approvals[0].signature = "00".repeat(64);
    let bad = envelope(&h, Body::EpochActivation(Box::new(bad)));
    assert!(crate::bft_network::activate_observed(&mut h.node, bad, None, request).is_err());
    assert_eq!(serde_json::to_vec(&h.node.journal).unwrap(), before);
}

#[test]
fn activation_observation_selects_exact_carried_index_after_complete_authentication() {
    let (mut h, proof) = selected();
    h.node.install_epoch(proof.clone()).unwrap();
    swap_new(&mut h);
    let context = Context::current(&h.node).unwrap();
    let message = h.sign(0, Request::Timeout { context, round: 0 }).message;
    let good = envelope(
        &h,
        Body::EpochSigned {
            message: Box::new(message),
            epochs: vec![proof.clone()],
        },
    );
    let before = serde_json::to_vec(&h.node.journal).unwrap();
    for index in [None, Some(1), Some(usize::MAX)] {
        assert!(crate::bft_network::activate_observed(
            &mut h.node,
            good.clone(),
            index,
            Hash([18; 32])
        )
        .is_err());
        assert_eq!(serde_json::to_vec(&h.node.journal).unwrap(), before);
    }
    let observed =
        crate::bft_network::activate_observed(&mut h.node, good.clone(), Some(0), Hash([18; 32]))
            .unwrap();
    assert_eq!(observed.carried_index, Some(0));
    assert_eq!(observed.proofs, vec![proof]);
    for mode in 0..3 {
        let mut bad = good.clone();
        match mode {
            0 => bad.currency = Hash([255; 32]),
            1 => bad.region = Hash([255; 32]),
            _ => {
                if let Body::EpochSigned { epochs, .. } = &mut bad.body {
                    let mut forged = epochs[0].clone();
                    forged.old_approvals[0].signature = "00".repeat(64);
                    epochs.push(forged);
                }
            }
        }
        assert!(
            crate::bft_network::activate_observed(&mut h.node, bad, Some(0), Hash([18; 32]))
                .is_err()
        );
        assert_eq!(serde_json::to_vec(&h.node.journal).unwrap(), before);
    }
}

#[test]
fn joint_scoped_first_proposal_and_keyless_sync_cross_epoch_from_genesis() {
    let (mut h, proof) = selected();
    let mut a = proof.clone();
    a.old_approvals.pop();
    a.new_approvals.pop();
    let mut b = proof;
    b.old_approvals.remove(0);
    b.new_approvals.remove(0);
    h.node.install_epoch(a).unwrap();
    swap_new(&mut h);
    let candidate = h.node.bft_candidate(vec![], public(10)).unwrap();
    let proposal = h.proposal(0, None, candidate);
    let mut foreign = proposal.clone();
    foreign.snapshot.epochs = vec![b.clone()];
    foreign.leader.signature = signature(h.seeds[1], &foreign.bytes().unwrap());
    let scoped = envelope(
        &h,
        Body::EpochSigned {
            message: Box::new(Message::Proposal(Box::new(foreign.clone()))),
            epochs: vec![b.clone()],
        },
    );
    // Raw closing snapshots alone intentionally carry no future epoch authority.
    assert!(envelope(
        &h,
        Body::Signed(Box::new(Message::Proposal(Box::new(foreign.clone()))))
    )
    .verify(&h.node)
    .is_err());
    scoped.verify(&h.node).unwrap();
    let q = h.prepare(&foreign, &[0, 1, 2]);
    let s = h.commit(&foreign, &q, &[0, 1, 2]);
    h.node.finalize(s.clone()).unwrap();
    // Duplicate checkpoint variants authenticate every complete carried proof.
    let mut alternate = s.clone();
    alternate.epochs[0] = h.node.journal.epoch_proofs[0].clone();
    let original = h
        .node
        .evidence
        .snapshot(s.statement.id().unwrap())
        .unwrap()
        .clone();
    h.node
        .add_evidence(Evidence {
            snapshots: vec![alternate],
        })
        .unwrap();
    assert_eq!(
        h.node.evidence.snapshot(s.statement.id().unwrap()).unwrap(),
        &original
    );
    let mut replica = Store::create(
        &h.root.join("cold-replica"),
        h.node.journal.bootstrap.clone(),
        h.node.chain.region,
        &public(1),
        h.node.trust.currency().unwrap(),
    )
    .unwrap();
    crate::bft_network::sync(&mut replica, h.node.journal.evidence.clone()).unwrap();
    assert_eq!(replica.chain.epoch, h.node.chain.epoch);
    assert_eq!(replica.chain.ledger, h.node.chain.ledger);
    assert_eq!(replica.chain.height(), 2);
    assert!(replica
        .journal
        .events
        .iter()
        .any(|e| matches!(e, crate::storage::Event::Epoch(_))));
}
