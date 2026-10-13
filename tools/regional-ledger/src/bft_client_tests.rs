//! Fresh public no-value native custody fixtures, not independent/latest-state qualification.
use super::*;
use crate::bft_client::{Client, State, Transition, FORMAT, ORIGIN_FORMAT};
use crate::wallet_client::canonical;
fn transition(previous: State, proposed: State) -> Transition {
    use sha2::{Digest, Sha256};
    Transition {
        previous_sha256: Hash(Sha256::digest(canonical(&previous).unwrap()).into()),
        proposed,
    }
}

fn custody(mut h: Harness, format: &str, interrupted: bool) {
    h.retain = true;
    let parent = h.root.join("caller");
    fs::create_dir(&parent).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let file = parent.join("head.json");
    let signer = h.root.join(format!("signer-{}", h.seeds[0]));
    let state = State {
        format: format.into(),
        binding: h.agents[0].journal.binding.clone(),
        head: h.heads[0],
        pending: None,
        outbox: None,
    };
    crate::keystore::private_create(&file, &canonical(&state).unwrap()).unwrap();
    h.agents.clear();
    let client = Client::lock(&file, &signer, public(h.seeds[0]), format.into(), &h.node).unwrap();
    assert!(Client::lock(&file, &signer, public(h.seeds[0]), format.into(), &h.node).is_err());
    assert_eq!(client.read().unwrap(), state);
    let request = Request::Timeout {
        context: Context::current(&h.node).unwrap(),
        round: 0,
    };
    let pending = State {
        pending: Some(request.clone()),
        ..state.clone()
    };
    client
        .store(&h.node, transition(state.clone(), pending.clone()))
        .unwrap();
    let before = fs::read(&file).unwrap();
    let cleared = client.reconcile(&h.node, pending.clone()).unwrap();
    assert_eq!(cleared, state); // Keyless recovery cannot first-sign.
    assert_eq!(fs::read(&file).unwrap(), before); // Calculation has no caller publication rights.
    assert_eq!(Agent::open(&signer, &h.node).unwrap().record_count(), 0);
    client
        .store(&h.node, transition(pending.clone(), state.clone()))
        .unwrap();
    client
        .store(&h.node, transition(state.clone(), pending.clone()))
        .unwrap();
    let mut agent = Agent::open(&signer, &h.node).unwrap();
    if interrupted {
        agent.interrupt_publication(0);
    }
    let signed = agent.sign(
        &h.node,
        request,
        Some(&h.root.join(format!("key-{}.json", h.seeds[0]))),
        state.head,
    );
    if interrupted {
        assert!(signed.is_err());
    } else {
        assert!(signed.is_ok());
    }
    drop(agent);
    let before = fs::read(&file).unwrap();
    let recovered = client.reconcile(&h.node, pending.clone()).unwrap();
    assert!(recovered.pending.is_none() && recovered.outbox.is_some());
    assert_eq!(fs::read(&file).unwrap(), before);
    let mut forged = recovered.clone();
    forged.head = Hash([7; 32]);
    assert!(client
        .store(&h.node, transition(pending.clone(), forged))
        .is_err());
    assert_eq!(fs::read(&file).unwrap(), before);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o500)).unwrap();
        let failed = client.store(&h.node, transition(pending.clone(), recovered.clone()));
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(failed.is_err());
        assert_eq!(fs::read(&file).unwrap(), before);
    }
    client
        .store(&h.node, transition(pending, recovered.clone()))
        .unwrap();
    assert_eq!(fs::read(&file).unwrap(), canonical(&recovered).unwrap());
    let mut invalid = recovered.clone();
    invalid.pending = Some(Request::Timeout {
        context: Context::current(&h.node).unwrap(),
        round: 1,
    });
    assert!(client
        .store(&h.node, transition(recovered.clone(), invalid))
        .is_err());
    let cleared = State {
        outbox: None,
        ..recovered.clone()
    };
    client
        .store(&h.node, transition(recovered, cleared.clone()))
        .unwrap();
    drop(client);
    let cold = Client::lock(&file, &signer, public(h.seeds[0]), format.into(), &h.node).unwrap();
    assert_eq!(cold.read().unwrap(), cleared);
    assert_eq!(Agent::open(&signer, &h.node).unwrap().record_count(), 1);
    println!(
        "fresh-native-bft-caller fixture={} interrupted={interrupted}",
        h.root.display()
    );
}
#[test]
fn native_bft_caller_preserves_legacy_and_paged_exact_custody() {
    custody(Harness::new(), FORMAT, false);
    custody(Harness::with_rules(crate::paged_bft::RULES), FORMAT, false);
}
#[test]
fn native_bft_caller_origin_recovers_exact_pending_publication_and_cold_state() {
    custody(super::receive_phase::fixture(), ORIGIN_FORMAT, true);
}

#[test]
fn complete_response_inspection_matches_original_retry_and_refuses_stale_heads() {
    for rules in [bft::RULES, crate::paged_bft::PACKED_RULES] {
        let mut h = Harness::with_rules(rules);
        h.retain = true;
        let request = Request::Timeout {
            context: Context::current(&h.node).unwrap(),
            round: 0,
        };
        let previous = h.heads[0];
        let signed = h.sign(0, request.clone());
        h.agents.clear();
        let dir = h.root.join(format!("signer-{}", h.seeds[0]));
        let before = super::retained_native_replay::inventory(&h.root);
        let (agent, status, response) =
            Agent::inspect_with_response_status(&dir, &h.node, &request, previous).unwrap();
        let observed = response.unwrap();
        assert_eq!(status.head, signed.head);
        assert_eq!(observed.head, signed.head);
        assert_eq!(observed.previous_head, previous);
        assert_eq!(observed.message, signed.message);
        assert!(observed.recovered_exact_retry);
        assert!(Agent::open(&dir, &h.node).is_err());
        drop(agent);
        let mut reference = Agent::open(&dir, &h.node).unwrap();
        assert!(reference.contains_request(&h.node, &request).unwrap());
        let original = reference
            .sign(&h.node, request.clone(), None, previous)
            .unwrap();
        assert_eq!(
            serde_json::to_value(&observed).unwrap(),
            serde_json::to_value(&original).unwrap()
        );
        drop(reference);
        assert!(Agent::inspect_with_response_status(&dir, &h.node, &request, Hash::ZERO).is_err());
        let absent = Request::Timeout {
            context: Context::current(&h.node).unwrap(),
            round: 1,
        };
        let (agent, status, response) =
            Agent::inspect_with_response_status(&dir, &h.node, &absent, signed.head).unwrap();
        assert_eq!(status.head, signed.head);
        assert!(response.is_none());
        drop(agent);
        assert_eq!(super::retained_native_replay::inventory(&h.root), before);
    }
}
