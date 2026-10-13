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

fn custody(mut h: Harness, format: &str, interrupted: bool, handoff: bool) {
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
    if handoff {
        let before = super::retained_native_replay::inventory(&h.root);
        let mut stale = transition(state.clone(), pending.clone());
        stale.previous_sha256 = Hash::ZERO;
        assert!(client.store_pending_for_sign(&h.node, stale).is_err());
        let mut wrong = pending.clone();
        wrong.head = Hash::ZERO;
        assert!(client
            .store_pending_for_sign(&h.node, transition(state.clone(), wrong))
            .is_err());
        assert_eq!(super::retained_native_replay::inventory(&h.root), before);
        let (saved, mut agent) = client
            .store_pending_for_sign(&h.node, transition(state.clone(), pending.clone()))
            .unwrap();
        assert_eq!(saved, pending);
        assert_eq!(fs::read(&file).unwrap(), canonical(&pending).unwrap());
        assert!(Agent::open(&signer, &h.node).is_err());
        assert!(agent
            .sign(&h.node, request.clone(), None, state.head)
            .is_err());
        assert_eq!(agent.record_count(), 0);
        drop(agent);
    } else {
        client
            .store(&h.node, transition(state.clone(), pending.clone()))
            .unwrap();
    }
    let before = fs::read(&file).unwrap();
    let cleared = client.reconcile(&h.node, pending.clone()).unwrap();
    assert_eq!(cleared, state); // Keyless recovery cannot first-sign.
    assert_eq!(fs::read(&file).unwrap(), before); // Calculation has no caller publication rights.
    assert_eq!(Agent::open(&signer, &h.node).unwrap().record_count(), 0);
    client
        .store(&h.node, transition(pending.clone(), state.clone()))
        .unwrap();
    let mut agent = if handoff {
        let (saved, agent) = client
            .store_pending_for_sign(&h.node, transition(state.clone(), pending.clone()))
            .unwrap();
        assert_eq!(saved, pending);
        assert!(Agent::open(&signer, &h.node).is_err());
        agent
    } else {
        client
            .store(&h.node, transition(state.clone(), pending.clone()))
            .unwrap();
        Agent::open(&signer, &h.node).unwrap()
    };
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
    custody(Harness::new(), FORMAT, false, false);
    custody(
        Harness::with_rules(crate::paged_bft::RULES),
        FORMAT,
        false,
        false,
    );
}
#[test]
fn native_bft_caller_origin_recovers_exact_pending_publication_and_cold_state() {
    custody(super::receive_phase::fixture(), ORIGIN_FORMAT, true, false);
}

#[test]
fn pending_signer_handoff_preserves_durable_consent_lock_and_keyless_refusal() {
    custody(Harness::new(), FORMAT, false, true);
    custody(
        Harness::with_rules(crate::paged_bft::PACKED_RULES),
        FORMAT,
        false,
        true,
    );
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CrashRequest {
    root: PathBuf,
    currency: Hash,
    native_head: Hash,
    key: String,
    key_file: PathBuf,
    signer: PathBuf,
    caller: PathBuf,
    previous: Hash,
    request: Request,
    boundary: u8,
}

#[test]
fn sigkill_paged_signer_child() {
    let Some(path) = std::env::var_os("RLD_BFT_CRASH_CHILD_CONFIG") else {
        return;
    };
    let raw = crate::wallet_client::private_read_with_limit(Path::new(&path), 1024 * 1024).unwrap();
    let config: CrashRequest = serde_json::from_slice(&raw).unwrap();
    assert!(config.boundary < 3);
    let node = Store::open_pinned(
        &config.root.join("node"),
        &public(1),
        config.currency,
        config.native_head,
    )
    .unwrap();
    let client = Client::lock(
        &config.caller,
        &config.signer,
        config.key,
        FORMAT.into(),
        &node,
    )
    .unwrap();
    let state = client.read().unwrap();
    assert_eq!(state.head, config.previous);
    assert!(state.pending.is_none() && state.outbox.is_none());
    let pending = State {
        pending: Some(config.request.clone()),
        ..state.clone()
    };
    let (_, mut agent) = client
        .store_pending_for_sign(&node, transition(state, pending))
        .unwrap();
    agent.kill_publication_for_fixture(config.boundary);
    agent
        .sign(
            &node,
            config.request,
            Some(&config.key_file),
            config.previous,
        )
        .unwrap();
    panic!("expected fixture SIGKILL boundary was not reached");
}

#[test]
fn real_sigkill_paged_response_recovers_exact_caller_and_prepare_lock_at_three_boundaries() {
    use std::os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        process::ExitStatusExt,
    };
    let started = std::time::Instant::now();
    for boundary in 0..3 {
        let mut h = Harness::with_rules(crate::paged_bft::PACKED_RULES);
        h.retain = true;
        let proposal = h.proposal(0, None, h.node.bft_candidate(vec![], public(10)).unwrap());
        let prepared = h.prepare(&proposal, &[0, 1, 2, 3]);
        h.commit(&proposal, &prepared, &[0, 1, 2, 3]);
        let context = Context::current(&h.node).unwrap();
        let mut round = 0;
        while h.agents[0].record_count() < 15 {
            h.sign(
                0,
                Request::Timeout {
                    context: context.clone(),
                    round,
                },
            );
            round += 1;
        }
        let previous = h.heads[0];
        let root = h.root.clone();
        let signer = root.join(format!("signer-{}", h.seeds[0]));
        let caller_dir = root.join("crash-caller");
        fs::create_dir(&caller_dir).unwrap();
        fs::set_permissions(&caller_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let caller = caller_dir.join("head.json");
        let state = State {
            format: FORMAT.into(),
            binding: h.agents[0].journal.binding.clone(),
            head: previous,
            pending: None,
            outbox: None,
        };
        crate::keystore::private_create(&caller, &canonical(&state).unwrap()).unwrap();
        let request = Request::Timeout {
            context: context.clone(),
            round,
        };
        let config = CrashRequest {
            root: root.clone(),
            currency: h.node.trust.currency().unwrap(),
            native_head: h.node.storage_head().unwrap(),
            key: public(h.seeds[0]),
            key_file: root.join(format!("key-{}.json", h.seeds[0])),
            signer: signer.clone(),
            caller: caller.clone(),
            previous,
            request: request.clone(),
            boundary,
        };
        let config_path = root.join("crash-request.json");
        crate::keystore::private_create(&config_path, &serde_json::to_vec(&config).unwrap())
            .unwrap();
        drop(h); // Only the new child owns the Native/signer/caller locks.
        let output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("child-output.log"))
            .unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "tests::regional_bft::bft_client_tests::sigkill_paged_signer_child",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("RLD_BFT_CRASH_CHILD_CONFIG", &config_path)
            .stdout(std::process::Stdio::from(output.try_clone().unwrap()))
            .stderr(std::process::Stdio::from(output))
            .spawn()
            .unwrap();
        let child_started = std::time::Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if child_started.elapsed().as_secs_f64() >= 10.0 {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("native signer child exceeded declared ten-second boundary budget");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "child did not reach the declared publication boundary"
        );
        let pending_path = signer.join("bft-records/stream.next");
        let publication: serde_json::Value =
            serde_json::from_slice(&fs::read(&pending_path).unwrap()).unwrap();
        assert_eq!(publication["manifest"]["count"], 16);
        assert_eq!(publication["pages"].as_array().unwrap().len(), 1);
        let exact: bft::Record =
            serde_json::from_value(publication["pages"][0]["records"][15].clone()).unwrap();
        assert_eq!(exact.request, request);
        assert_eq!(exact.previous_head, previous);
        let Message::Timeout(timeout) = &exact.message else {
            panic!("retained response is not Timeout");
        };
        assert_eq!(timeout.high.as_ref(), Some(&prepared));
        let proposed: Hash =
            serde_json::from_value(publication["manifest"]["head"].clone()).unwrap();
        let pending = State {
            pending: Some(request.clone()),
            ..state.clone()
        };
        assert_eq!(fs::read(&caller).unwrap(), canonical(&pending).unwrap());
        let node = Store::open_pinned(
            &root.join("node"),
            &public(1),
            config.currency,
            config.native_head,
        )
        .unwrap();
        assert!(Agent::open(&signer, &node).is_err());
        let client =
            Client::lock(&caller, &signer, config.key.clone(), FORMAT.into(), &node).unwrap();
        let before = super::retained_native_replay::inventory(&root);
        let wrong = Request::Timeout {
            context: context.clone(),
            round: round + 1,
        };
        assert!(Agent::recover_response(&signer, &node, wrong.clone(), previous).is_err());
        assert!(Agent::recover_response(&signer, &node, request.clone(), Hash::ZERO).is_err());
        assert_eq!(super::retained_native_replay::inventory(&root), before);
        let recovered = client.reconcile(&node, pending.clone()).unwrap();
        assert_eq!(recovered.head, proposed);
        assert_eq!(recovered.outbox.as_ref(), Some(&exact.message));
        assert!(recovered.pending.is_none());
        assert_eq!(fs::read(&caller).unwrap(), canonical(&pending).unwrap());
        client
            .store(&node, transition(pending, recovered.clone()))
            .unwrap();
        let closed = State {
            outbox: None,
            ..recovered
        };
        client
            .store(&node, transition(client.read().unwrap(), closed.clone()))
            .unwrap();
        drop(client);
        let mut agent = Agent::open(&signer, &node).unwrap();
        assert_eq!(agent.record_count(), 16);
        assert_eq!(agent.head().unwrap(), proposed);
        let stable = super::retained_native_replay::inventory(&root);
        assert!(
            agent.sign(&node, wrong.clone(), None, proposed).is_err(),
            "keyless recovery first-signed a new request"
        );
        drop(agent);
        assert_eq!(super::retained_native_replay::inventory(&root), stable);
        let (agent, status) = Agent::open_with_status(&signer, &node).unwrap();
        let status = serde_json::to_value(status).unwrap();
        assert_eq!(
            status["state"]["lock"],
            serde_json::to_value(&prepared).unwrap()
        );
        assert_eq!(status["state"]["round"], round + 1);
        drop(agent);
        assert!(Agent::recover_response(&signer, &node, wrong, previous).is_err());
        assert_eq!(
            Agent::recover_response(&signer, &node, request, previous)
                .unwrap()
                .message,
            exact.message
        );
        let cold = Client::lock(&caller, &signer, config.key, FORMAT.into(), &node).unwrap();
        assert_eq!(cold.read().unwrap(), closed);
        assert_eq!(node.storage_head().unwrap(), config.native_head);
        assert_eq!(super::retained_native_replay::inventory(&root), stable);
        assert!(!pending_path.exists());
        eprintln!("Native signer SIGKILL: boundary={boundary} exact_response=true original_lock=true caller_cold=true first_sign=false power_loss=false independent_custody=false");
    }
    assert!(
        started.elapsed().as_secs_f64() < 60.0,
        "native SIGKILL custody budget"
    );
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
