//! A finite scheduling regression, never a payment or liveness qualification.
//! Fresh public no-value fixture keys sign only through the original Agent.
use super::*;
use crate::tests::{public, signature};
use crate::{Amount, Bootstrap};
use std::time::Duration;

fn clock() -> f64 {
    super::super::service::monotonic().unwrap()
}

fn within(deadline: f64) {
    assert!(
        clock() < deadline,
        "original ten-second Mesh gate regression exhausted"
    );
}

fn create_json(path: &Path, value: &impl serde::Serialize) {
    crate::keystore::private_create(path, &files::canonical(value).unwrap()).unwrap();
}

fn fresh_bootstrap() -> Bootstrap {
    let mut bootstrap = crate::tests::bootstrap();
    bootstrap.currency.origin = format!("mesh-regression-{}", &random().unwrap()[..16]);
    bootstrap.currency.cap = Amount::TOTAL_SUPPLY;
    bootstrap.currency.block_reward = rld_pow::subsidy(1).unwrap();
    bootstrap.currency.signature = signature(1, &bootstrap.currency.bytes().unwrap());
    let mut seeds = [2u8, 3, 4, 5];
    seeds.sort_by_key(|seed| public(*seed));
    for (i, rules) in [
        crate::paged_bft::RULES,
        crate::paged_bft::ORIGIN_NETWORK_RULES,
        crate::paged_bft::ONWARD_NETWORK_RULES,
    ]
    .into_iter()
    .enumerate()
    {
        let admission = &mut bootstrap.admissions[i];
        if i == 0 {
            admission.region = bootstrap.currency.origin.clone();
        }
        admission.currency = bootstrap.currency.id().unwrap();
        admission.rules = rules.into();
        admission.value_rules = Some(crate::paged_bft::rules_hash_for(rules).unwrap());
        admission.validators = seeds.iter().map(|seed| public(*seed)).collect();
        admission.signature = signature(1, &admission.bytes().unwrap());
    }
    bootstrap
}

// Byte and mtime comparison detects writes; it grants no Native authority.
fn inventory(root: &Path) -> BTreeMap<PathBuf, (Hash, u64, std::time::SystemTime)> {
    fn visit(path: &Path, result: &mut BTreeMap<PathBuf, (Hash, u64, std::time::SystemTime)>) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            assert!(!metadata.file_type().is_symlink());
            if metadata.is_dir() {
                visit(&path, result);
            } else {
                assert!(metadata.is_file());
                result.insert(
                    path.clone(),
                    (
                        Hash(Sha256::digest(fs::read(&path).unwrap()).into()),
                        metadata.len(),
                        metadata.modified().unwrap(),
                    ),
                );
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(root, &mut result);
    result
}

#[test]
#[ignore = "one fresh ten-second real Onward proposal regression; no payment or consensus completion"]
fn mesh_lease_preserves_ready_onward_work_and_native_refusals() {
    let started = clock();
    let deadline = started + 10.0;
    let root = directory(
        &fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("rld-onward-mesh-gate-{}", random().unwrap())),
    )
    .unwrap();
    eprintln!(
        "\nonward_mesh_gate_regression_scope={}",
        json!({"root":root,"started":started,"deadline":deadline,"pid":std::process::id(),"fixture_only":true})
    );
    let bootstrap = fresh_bootstrap();
    let currency = bootstrap.currency.id().unwrap();
    let region = bootstrap.admissions[2].id().unwrap();
    let ledger = root.join("ledger");
    let node = Store::create(&ledger, bootstrap, region, &public(1), currency).unwrap();
    node.require_onward_network_state().unwrap();
    let native_head = node.storage_head().unwrap();
    let mut seeds = [2u8, 3, 4, 5];
    seeds.sort_by_key(|seed| public(*seed));
    let mut ids = Vec::new();
    for i in 0..4 {
        let identity = initialize(
            &root.join(format!("transport-{i}")),
            &currency.to_hex(),
            &region.to_hex(),
            "public-no-value-onward-mesh-gate",
        )
        .unwrap();
        ids.push(identity["node_id"].as_str().unwrap().to_owned());
    }
    let transport =
        json!({"format":MESH,"network":currency,"state":root.join("transport-0"),"contacts":[]});
    let signer = root.join("signer");
    let agent = consensus::Agent::create(&signer, &node, public(seeds[0])).unwrap();
    assert_eq!(agent.record_count(), 0);
    let initial_head = agent.head().unwrap();
    let caller_path = directory(&root.join("caller")).unwrap().join("head.json");
    let initial_caller = bft_client::State {
        format: bft_client::ONWARD_FORMAT.into(),
        binding: agent.journal.binding.clone(),
        head: initial_head,
        pending: None,
        outbox: None,
    };
    create_json(&caller_path, &initial_caller);
    // A separate invalid input never rewrites the actual retained caller head.
    let bad_caller_path = directory(&root.join("bad-caller"))
        .unwrap()
        .join("head.json");
    let mut bad_caller = initial_caller.clone();
    bad_caller.head = Hash::ZERO;
    create_json(&bad_caller_path, &bad_caller);
    drop(
        bft_client::Client::lock(
            &bad_caller_path,
            &signer,
            public(seeds[0]),
            bft_client::ONWARD_FORMAT.into(),
            &node,
        )
        .unwrap(),
    );
    drop(agent);
    let key_file = root.join("key.json");
    create_json(&key_file, &json!({"secret_key":hex::encode([seeds[0];32])}));
    let archive = directory(&root.join("runtime")).unwrap();
    let path = root.join("runtime-config.json");
    create_json(
        &path,
        &json!({"format":bft_client::ONWARD_FORMAT,"state":archive,"signer_dir":signer,
        "head_file":caller_path,"key_file":key_file,"key":public(seeds[0]),"miner":public(12),
        "validators":seeds.iter().enumerate().map(|(i,s)|json!({"key":public(*s),"node_id":ids[i]})).collect::<Vec<_>>(),
        "block_interval":0.5,"round_timeout":5.0,"stop_height":1,"startup_native_history_head":native_head}),
    );
    let mut runtime = Some(Runtime::open(&path, &node, &transport).unwrap());
    drop(node);
    let options = super::super::service::Options {
        ledger: ledger.clone(),
        authority: public(1),
        currency,
        mesh_config: None,
        bft_config: None,
        listen: "127.0.0.1:0".parse().unwrap(),
        miner: None,
        interval: 0.5,
        insecure_tcp: false,
    };
    let mut cursor = None;
    let mut seen = Vec::new();
    let priming = super::super::service::tick_ledger(
        &options,
        &transport,
        &mut runtime,
        &mut cursor,
        &mut seen,
    )
    .unwrap();
    assert_eq!(priming["local_height"], 0);
    assert_eq!(runtime.as_ref().unwrap().last_decision, Some("idle"));
    let entered = runtime.as_ref().unwrap().entered;
    while clock() < entered + 0.5 {
        within(deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    within(deadline);
    let held = Node::open(&transport).unwrap();
    let before = inventory(&root);
    let native = Store::open_inspection(&ledger, &public(1), currency).unwrap();
    let r = runtime.as_ref().unwrap();
    let context = consensus::Context::current(&native).unwrap();
    let slot = r.slot.clone();
    assert_eq!(slot, Some((context.clone(), 0)));
    let archive_head = r.head.unwrap();
    let archive_bytes = files::canonical_with_limit(&r.archive, retention::MAX_STATE).unwrap();
    let caller = bft_client::Client::lock(
        &caller_path,
        &signer,
        public(seeds[0]),
        bft_client::ONWARD_FORMAT.into(),
        &native,
    )
    .unwrap();
    let caller_state = caller.read().unwrap();
    assert_eq!(caller_state.head, initial_head);
    assert!(caller_state.pending.is_none() && caller_state.outbox.is_none());
    drop(caller);
    let ready = tick::observe(
        &native,
        proposal::Pins {
            signer: &signer,
            archive: &archive,
            key: public(seeds[0]),
            runtime_format: bft_client::ONWARD_FORMAT.into(),
            head: initial_head,
            archive_head,
            context: context.clone(),
            round: 0,
        },
        tick::Input {
            context: context.clone(),
            order: r.archive.runtime.messages.keys().copied().collect(),
            stage: tick::Stage::Begin,
            proposed: None,
            entered_at: entered,
            interval: 0.5,
            timeout: 5.0,
            stopped: false,
            initial_wait: false,
            timeout_refresh: true,
        },
    )
    .unwrap();
    assert!(matches!(
        ready.action,
        tick::Decision::Propose {
            round: 0,
            timeout: None,
            high: None
        }
    ));
    assert!(ready.monotonic_now >= entered + 0.5 && ready.monotonic_now < entered + 5.0);
    assert_eq!(native.storage_head().unwrap(), native_head);
    let (agent, status) = consensus::Agent::inspect_with_status(&signer, &native).unwrap();
    assert_eq!(agent.record_count(), 0);
    assert_eq!(status.head, initial_head);
    drop(agent);
    // The Mesh deferral must still reach and obey the original Native lock.
    let native_refusal = super::super::service::tick_ledger(
        &options,
        &transport,
        &mut runtime,
        &mut cursor,
        &mut seen,
    )
    .unwrap_err();
    assert_eq!(
        native_refusal,
        std::fs::TryLockError::WouldBlock.to_string()
    );
    drop(native);
    assert_eq!(inventory(&root), before);
    // It must likewise obey the separately retained caller binding before signing.
    runtime.as_mut().unwrap().config.head_file = bad_caller_path;
    let caller_refusal = super::super::service::tick_ledger(
        &options,
        &transport,
        &mut runtime,
        &mut cursor,
        &mut seen,
    )
    .unwrap_err();
    runtime.as_mut().unwrap().config.head_file = caller_path.clone();
    assert_eq!(caller_refusal, "BFT external caller-head binding differs");
    let r = runtime.as_ref().unwrap();
    assert_eq!(r.slot, slot);
    assert_eq!(r.entered, entered);
    assert_eq!(r.head, Some(archive_head));
    assert_eq!(
        files::canonical_with_limit(&r.archive, retention::MAX_STATE).unwrap(),
        archive_bytes
    );
    assert!(cursor.is_none() && seen.is_empty());
    assert_eq!(inventory(&root), before);
    within(deadline);
    assert!(
        clock() < entered + 5.0,
        "original proposal clock reached timeout"
    );
    let transport_before = inventory(&root.join("transport-0"));
    let post_native_busy = super::super::service::tick_ledger(
        &options,
        &transport,
        &mut runtime,
        &mut cursor,
        &mut seen,
    )
    .unwrap_err();
    assert!(post_native_busy.starts_with(&format!("CONTACT_STORAGE_IO:{}:", libc::EWOULDBLOCK)));
    assert_eq!(runtime.as_ref().unwrap().last_decision, Some("propose"));
    assert!(cursor.is_none() && seen.is_empty());
    assert_eq!(inventory(&root.join("transport-0")), transport_before);
    // Inspect the actual original signer while Mesh is STILL held: local
    // work is durable, but the post-Native error granted no transport custody.
    let node = Store::open_pinned(&ledger, &public(1), currency, native_head).unwrap();
    let (agent, status) = consensus::Agent::inspect_with_status(&signer, &node).unwrap();
    assert_eq!(agent.record_count(), 2);
    let messages = agent.retained_messages(&node).unwrap();
    let consensus::Message::Proposal(proposal) = &messages[0] else {
        panic!("original proposal missing")
    };
    let consensus::Message::Vote(vote) = &messages[1] else {
        panic!("original Prepare missing")
    };
    assert_eq!(proposal.context().unwrap(), context);
    assert_eq!(proposal.round, 0);
    assert!(proposal.timeout.is_none());
    assert_eq!(proposal.leader.key, public(seeds[0]));
    assert_eq!(vote.context, context);
    assert_eq!(vote.round, 0);
    assert_eq!(vote.phase, consensus::Phase::Prepare);
    assert_eq!(vote.value, proposal.snapshot.statement.id().unwrap());
    assert_eq!(vote.approval.key, public(seeds[0]));
    let final_head = status.head;
    assert_ne!(final_head, initial_head);
    drop(agent);
    let caller = bft_client::Client::lock(
        &caller_path,
        &signer,
        public(seeds[0]),
        bft_client::ONWARD_FORMAT.into(),
        &node,
    )
    .unwrap();
    let caller_state = caller.read().unwrap();
    assert_eq!(caller_state.head, final_head);
    assert!(caller_state.pending.is_none() && caller_state.outbox.is_none());
    drop(caller);
    assert_eq!(node.chain.height(), 0);
    assert_eq!(node.chain.finalized, None);
    assert_eq!(node.chain.ledger.minted, Amount::ZERO);
    assert!(
        node.chain.ledger.coins.is_empty()
            && node.chain.ledger.imports.is_empty()
            && node.chain.ledger.exports.is_empty()
    );
    drop(node);
    drop(held);
    within(deadline);
    assert!(
        clock() < entered + 5.0,
        "original proposal clock reached timeout"
    );
    let released = super::super::service::tick_ledger(
        &options,
        &transport,
        &mut runtime,
        &mut cursor,
        &mut seen,
    )
    .unwrap();
    assert_eq!(released["local_height"], 0);
    assert_eq!(released["transport_receive_deferred"], false);
    assert!(cursor.is_none() && seen.is_empty());
    drop(runtime);
    let stopped = inventory(&root);
    let cold = Store::open_pinned(&ledger, &public(1), currency, native_head).unwrap();
    let (agent, status) = consensus::Agent::inspect_with_status(&signer, &cold).unwrap();
    assert_eq!(status.head, final_head);
    assert_eq!(agent.retained_messages(&cold).unwrap(), messages);
    drop(agent);
    let reopened = Runtime::open(&path, &cold, &transport).unwrap();
    assert_eq!(reopened.archive.runtime.messages.len(), 2);
    for record in reopened.archive.runtime.messages.values() {
        Wire::decode(
            reopened.archive.envelope(record).unwrap(),
            bft_client::ONWARD_FORMAT,
        )
        .unwrap()
        .verify(&cold)
        .unwrap();
    }
    drop(reopened);
    drop(cold);
    assert_eq!(inventory(&root), stopped);
    // A post-acquisition storage error must never become deferred input.
    // This separate fresh corrupt fixture is retained, not repaired or reused.
    let corrupt_transport = json!({"format":MESH,"network":currency,
        "state":root.join("transport-1"),"contacts":[]});
    drop(Node::open(&corrupt_transport).unwrap());
    let damaged = root.join("transport-1/native-mesh-state.json");
    fs::write(&damaged, b"invalid retained Mesh state").unwrap();
    let corrupt_before = inventory(&root.join("transport-1"));
    assert!(Node::open_or_defer_mesh(&corrupt_transport).is_err());
    assert_eq!(inventory(&root.join("transport-1")), corrupt_before);
    within(deadline);
    let ended = clock();
    eprintln!(
        "\nonward_mesh_gate_regression_result={}",
        json!({"root":root,"started":started,"deadline":deadline,"ended":ended,
        "elapsed_seconds":ended-started,"pid":std::process::id(),"currency":currency,"region":region,
        "passed":true,"real_onward_proposal_ready":true,"native_available_during_mesh_lease":true,
        "native_lock_refused_before_signing":true,"bad_caller_refused_before_signing":true,
        "refused_state_and_clocks_unchanged":true,"held_mesh_original_agent_proposal_prepare":true,
        "post_native_mesh_error_retained":true,"no_mesh_custody_or_cursor_advance":true,
        "release_restores_transport_turn":true,"post_acquisition_corruption_refused":true,
        "same_process_cold_reauthenticated":true,
        "cold_inventory_unchanged":true,"native_height":0,"agent_records":2,"native_value_unchanged":true,
        "payment_qualified":false,"bft_liveness_qualified":false,"independent_cold_process":false,
        "old_payment_cause_established":false,"mainnet":false})
    );
}

#[path = "bft_timeout_observation_tests.rs"]
mod timeout_observation_tests;
