//! Public no-value Native custody inputs; no independent control qualification.
use super::paged_integration::{certify, retain};
use super::retained_native_replay::inventory;
use super::*;
use std::process::Command as Process;

#[derive(Serialize, Deserialize)]
struct Pins {
    currency: Hash,
    native: Hash,
    signers: Vec<Hash>,
    seeds: Vec<u8>,
    owners: Vec<(u8, Hash)>,
}

fn payment(
    h: &Harness,
    owner: u8,
    recipient: u8,
    amount: Amount,
    input: Option<Hash>,
) -> (Vec<Command>, crate::wallet_agent::Agent, Hash) {
    let key = h.root.join(format!("owner-key-{owner}.json"));
    crate::keystore::private_create(
        &key,
        &serde_json::to_vec(&serde_json::json!({"secret_key":hex::encode([owner;32])})).unwrap(),
    )
    .unwrap();
    let mut wallet = crate::wallet_agent::Agent::create(
        &h.root.join(format!("owner-{owner}")),
        &h.node,
        public(owner),
    )
    .unwrap();
    let previous = wallet.journal.head().unwrap();
    retain(&h.root, usize::from(owner), previous);
    let prepared = wallet
        .prepare(
            &h.node,
            crate::wallet::Request {
                owner: public(owner),
                participants: vec![],
                inputs: input.map(|id| vec![id]),
                outputs: vec![Payment {
                    owner: public(recipient),
                    amount,
                }],
                remote: None,
                fee: Amount(1),
                valid_for_blocks: 8,
                valid_through: None,
            },
            previous,
        )
        .unwrap();
    let signed = wallet
        .sign(
            &h.node,
            prepared.draft,
            &key,
            prepared.review_commitment,
            previous,
        )
        .unwrap();
    retain(&h.root, usize::from(owner), signed.wallet_head);
    (signed.commands, wallet, signed.wallet_head)
}

#[test]
#[ignore = "bounded parent invokes a fresh pinned child explicitly"]
fn packed_original_custody_cold_child() {
    let root = PathBuf::from(
        std::env::var_os("RLD_PACKED_CUSTODY_COLD_ROOT").expect("bounded parent private path"),
    );
    let pins: Pins = crate::storage::read_json(&root.join("pins.json")).unwrap();
    let before = inventory(&root);
    let node =
        Store::open_pinned(&root.join("node"), &public(1), pins.currency, pins.native).unwrap();
    assert_eq!(node.chain.height(), 8);
    assert_eq!(node.blocks().unwrap().count(), 8);
    assert_eq!(
        node.history_layout().unwrap().0,
        "RLD-NATIVE-PACKED-BFT-STORE-FIXTURE-V1"
    );
    assert_eq!(
        fs::read(root.join("caller-native.head")).unwrap(),
        pins.native.0
    );
    for (n, seed) in pins.seeds.iter().enumerate() {
        let agent = Agent::open(&root.join(format!("signer-{seed}")), &node).unwrap();
        assert_eq!(agent.head().unwrap(), pins.signers[n]);
        assert_eq!(
            fs::read(root.join(format!("caller-{n}.head"))).unwrap(),
            pins.signers[n].0
        );
        assert!(agent.record_count() >= 16);
        assert_eq!(
            agent.retained_messages(&node).unwrap().len(),
            agent.record_count()
        );
    }
    for (owner, head) in &pins.owners {
        let wallet =
            crate::wallet_agent::Agent::open(&root.join(format!("owner-{owner}")), &node).unwrap();
        assert_eq!(wallet.journal.head().unwrap(), *head);
        assert_eq!(
            fs::read(root.join(format!("caller-{owner}.head"))).unwrap(),
            head.0
        );
        wallet.view(&node, *head).unwrap();
    }
    assert!(node.chain.ledger.coins.values().any(|coin| {
        coin.payment.owner == public(14)
            && coin.payment.amount == Amount(98)
            && coin.mature <= node.chain.height()
    }));
    assert_eq!(inventory(&root), before);
}

#[test]
fn packed_ledger_four_original_signer_journals_two_owner_payments_and_fresh_cold() {
    let started = std::time::Instant::now();
    let mut h = Harness::with_rules(crate::paged_bft::PACKED_RULES);
    h.retain = true;
    eprintln!("Fresh packed Native custody fixture: {}", h.root.display());
    for n in 0..4 {
        retain(&h.root, n, h.heads[n]);
    }
    let mut owners = Vec::new();
    for height in 1..=8 {
        assert!(
            started.elapsed().as_secs_f64() < 60.0,
            "packed custody deadline"
        );
        let commands = if height == 4 {
            let (commands, wallet, head) = payment(&h, 10, 11, Amount(99), None);
            owners.push((10, wallet, head));
            commands
        } else if height == 6 {
            let input = *h
                .node
                .chain
                .ledger
                .coins
                .iter()
                .find(|(_, coin)| {
                    coin.payment.owner == public(11)
                        && coin.payment.amount == Amount(99)
                        && coin.mature <= h.node.chain.height()
                })
                .unwrap()
                .0;
            let (commands, wallet, head) = payment(&h, 11, 14, Amount(98), Some(input));
            owners.push((11, wallet, head));
            commands
        } else {
            vec![]
        };
        let snapshot = certify(&mut h, commands);
        h.node.finalize(snapshot).unwrap();
        assert_eq!(h.node.chain.height(), height);
    }
    let before = inventory(&h.root);
    let request = Request::Timeout {
        context: Context::current(&h.node).unwrap(),
        round: 0,
    };
    assert!(h.agents[0]
        .sign(&h.node, request.clone(), None, h.heads[0])
        .is_err());
    assert!(h.agents[0]
        .sign(
            &h.node,
            request,
            Some(&h.root.join(format!("key-{}.json", h.seeds[0]))),
            Hash::ZERO,
        )
        .is_err());
    assert_eq!(inventory(&h.root), before);
    let pins = Pins {
        currency: h.node.trust.currency().unwrap(),
        native: h.node.storage_head().unwrap(),
        signers: h.heads.clone(),
        seeds: h.seeds.clone(),
        owners: owners
            .iter()
            .map(|(owner, _, head)| (*owner, *head))
            .collect(),
    };
    crate::keystore::private_create(&h.root.join("caller-native.head"), &pins.native.0).unwrap();
    crate::keystore::private_create(
        &h.root.join("pins.json"),
        &serde_json::to_vec(&pins).unwrap(),
    )
    .unwrap();
    let root = h.root.clone();
    drop(owners);
    drop(h);
    let output = Process::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tests::regional_bft::packed_custody::packed_original_custody_cold_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("RLD_PACKED_CUSTODY_COLD_ROOT", &root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fresh cold failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        started.elapsed().as_secs_f64() < 60.0,
        "packed custody cold deadline"
    );
    eprintln!("Complete Native custody cold replay, original heads and byte inventory verified");
}

#[test]
fn packed_height_four_runtime_tick_measures_complete_authentication_without_new_signature() {
    packed_runtime_work(false, false, false);
}

#[test]
fn packed_current_prepare_measures_original_runtime_sign_and_caller_publication() {
    packed_runtime_work(true, false, false);
}

#[test]
fn ordinary_proposer_retains_own_prepare_without_another_contact_turn() {
    packed_runtime_work(false, true, false);
}

#[test]
fn packed_receive_retains_exact_evidence_event_and_measures_post_sync_retention() {
    packed_runtime_work(false, false, true);
}

fn packed_runtime_work(measure_sign: bool, compose_proposal: bool, measure_receive: bool) {
    let started = std::time::Instant::now();
    let mut h = Harness::with_rules(crate::paged_bft::PACKED_RULES);
    h.retain = true;
    eprintln!("Fresh packed Runtime work fixture: {}", h.root.display());
    h.agents.clear();
    let currency = h.node.trust.currency().unwrap();
    let region = h.node.chain.region;
    let mut ids = Vec::new();
    for n in 0..4 {
        let identity = crate::contact_runtime::initialize(
            &h.root.join(format!("transport-{n}")),
            &currency.to_hex(),
            &region.to_hex(),
            "public-no-value-packed-work",
        )
        .unwrap();
        ids.push(identity["node_id"].as_str().unwrap().to_owned());
    }
    let mut actors = Vec::new();
    for n in 0..4 {
        let caller_dir = h.root.join(format!("runtime-caller-{n}"));
        fs::create_dir(&caller_dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&caller_dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let caller = caller_dir.join("head.json");
        let signer = h.root.join(format!("signer-{}", h.seeds[n]));
        let state = crate::bft_client::State {
            format: crate::bft_client::FORMAT.into(),
            binding: Agent::open(&signer, &h.node)
                .unwrap()
                .journal
                .binding
                .clone(),
            head: h.heads[n],
            pending: None,
            outbox: None,
        };
        crate::keystore::private_create(&caller, &crate::wallet_client::canonical(&state).unwrap())
            .unwrap();
        let archive = h.root.join(format!("runtime-work-{n}"));
        fs::create_dir(&archive).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&archive, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let config = serde_json::json!({
            "format":crate::bft_client::FORMAT,"state":archive,"signer_dir":signer,
            "head_file":caller,"key_file":h.root.join(format!("key-{}.json",h.seeds[n])),
            "key":public(h.seeds[n]),"miner":public(10),
            "validators":h.seeds.iter().enumerate().map(|(n,seed)|
                serde_json::json!({"key":public(*seed),"node_id":ids[n]})).collect::<Vec<_>>(),
            "block_interval":0.5,"round_timeout":5.0,"stop_height":4
        });
        let path = h.root.join(format!("runtime-config-{n}.json"));
        crate::keystore::private_create(&path, &crate::wallet_client::canonical(&config).unwrap())
            .unwrap();
        let transport = serde_json::json!({"format":crate::contact_runtime::MESH,
            "network":currency,"state":h.root.join(format!("transport-{n}")),"contacts":[]});
        actors.push(crate::contact_runtime::TestRuntime::open(&path, &h.node, &transport).unwrap());
    }
    if compose_proposal {
        let context = Context::current(&h.node).unwrap();
        let keys = h.seeds.iter().copied().map(public).collect::<Vec<_>>();
        let leader = bft::leader(&context, 0, &keys).unwrap();
        let n = keys.iter().position(|key| key == &leader).unwrap();
        let head = h.node.storage_head().unwrap();
        let ledger = h.node.chain.ledger.clone();
        assert_eq!(
            actors[n].probe_tick(&mut h.node).unwrap()["decision"],
            "idle"
        );
        std::thread::sleep(std::time::Duration::from_millis(550));
        let result = actors[n].probe_tick(&mut h.node).unwrap();
        assert!(
            result["error"].is_null(),
            "ordinary proposal refused: {result}"
        );
        let controls = actors[n].fixture_controls().unwrap();
        assert_eq!(
            controls
                .iter()
                .filter(|message| matches!(message, Message::Proposal(_)))
                .count(),
            1
        );
        assert_eq!(
            controls
                .iter()
                .filter(
                    |message| matches!(message,Message::Vote(vote) if vote.phase == Phase::Prepare)
                )
                .count(),
            1,
            "ordinary proposer deferred its own native-verified Prepare to another contact turn"
        );
        assert_eq!(h.node.storage_head().unwrap(), head);
        assert_eq!(h.node.chain.ledger, ledger);
        drop(actors);
        let root = h.root.clone();
        let seeds = h.seeds.clone();
        drop(h);
        let before = inventory(&root);
        let cold = Store::open_pinned(&root.join("node"), &public(1), currency, head).unwrap();
        assert_eq!(cold.chain.height(), 0);
        assert_eq!(cold.chain.ledger, ledger);
        let caller = crate::bft_client::Client::lock(
            &root.join(format!("runtime-caller-{n}/head.json")),
            &root.join(format!("signer-{}", seeds[n])),
            public(seeds[n]),
            crate::bft_client::FORMAT.into(),
            &cold,
        )
        .unwrap();
        let state = caller.read().unwrap();
        assert!(state.pending.is_none() && state.outbox.is_none());
        let agent = Agent::open(&root.join(format!("signer-{}", seeds[n])), &cold).unwrap();
        assert_eq!(agent.head().unwrap(), state.head);
        assert_eq!(agent.record_count(), 2);
        assert_eq!(inventory(&root), before);
        assert!(
            started.elapsed().as_secs_f64() < 60.0,
            "ordinary proposal component deadline"
        );
        return;
    }
    for height in 1..=5 {
        assert!(
            started.elapsed().as_secs_f64() < 60.0,
            "Runtime fixture deadline"
        );
        let context = Context::current(&h.node).unwrap();
        let keys = h.seeds.iter().copied().map(public).collect::<Vec<_>>();
        let leader = bft::leader(&context, 0, &keys).unwrap();
        let n = keys.iter().position(|key| key == &leader).unwrap();
        let Message::Proposal(proposal) = actors[n]
            .sign_fixture_control(
                &h.node,
                Request::Propose {
                    round: 0,
                    timeout: None,
                    snapshot: Box::new(h.node.bft_candidate(vec![], public(10)).unwrap()),
                },
            )
            .unwrap()
        else {
            panic!("original proposal response")
        };
        let mut votes = Vec::new();
        for (n, actor) in actors.iter_mut().enumerate() {
            let request = Request::Prepare(proposal.clone());
            let message = if measure_sign && height == 5 && n == 0 {
                let head = h.node.storage_head().unwrap();
                let ledger = h.node.chain.ledger.clone();
                let (message, report) = actor.probe_fixture_sign_control(&h.node, request).unwrap();
                assert!(report["error"].is_null());
                assert_eq!(report["new_signatures"], 1);
                assert!(report["strict_signature_checks"].as_u64().unwrap() > 0);
                assert_eq!(h.node.storage_head().unwrap(), head);
                assert_eq!(h.node.chain.ledger, ledger);
                eprintln!("Packed original Runtime signature work: {report}");
                message
            } else {
                actor.sign_fixture_control(&h.node, request).unwrap()
            };
            let Message::Vote(vote) = message else {
                panic!("original prepare response")
            };
            votes.push(*vote);
        }
        let prepared = Quorum::combine(votes, &h.node.trust, &h.node.evidence).unwrap();
        if height == 5 {
            break;
        }
        let mut votes = Vec::new();
        for actor in &mut actors {
            let Message::Vote(vote) = actor
                .sign_fixture_control(
                    &h.node,
                    Request::Commit {
                        proposal: proposal.clone(),
                        prepared: prepared.clone(),
                    },
                )
                .unwrap()
            else {
                panic!("original commit response")
            };
            votes.push(*vote);
        }
        let committed = Quorum::combine(votes, &h.node.trust, &h.node.evidence).unwrap();
        let mut snapshot = *proposal.snapshot;
        snapshot.bft = Some(Certificate {
            prepared,
            committed,
        });
        h.node.finalize(snapshot).unwrap();
        assert_eq!(h.node.chain.height(), height);
    }
    let messages = actors
        .iter()
        .flat_map(|actor| actor.fixture_controls().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(messages.len(), 41);
    if measure_receive {
        let target = messages
            .iter()
            .find(|message| {
                matches!(message, Message::Proposal(proposal)
                if proposal.context().unwrap().parent_height == 4)
            })
            .unwrap();
        let Message::Proposal(proposal) = target else {
            unreachable!()
        };
        let source = h
            .seeds
            .iter()
            .position(|seed| public(*seed) == proposal.leader.key)
            .unwrap();
        let recipient = if source == 0 { 1 } else { 0 };
        let others = messages
            .iter()
            .filter(|message| *message != target)
            .cloned()
            .collect::<Vec<_>>();
        actors[recipient]
            .retain_fixture_controls(&h.node, &others)
            .unwrap();
        let raw = actors[source].fixture_control_frame(target).unwrap();
        let (_, payload) = crate::contact_frame::inspect_bytes(
            &raw,
            None,
            None,
            crate::contact::MAX_PAYLOAD,
            crate::contact::MAX_FRAME,
        )
        .unwrap();
        let wire: crate::bft_network::WireEnvelope = crate::bft_client::decode(&payload).unwrap();
        // This is the expected original byte image, not an authorization witness.
        // The ordinary receive path below still authenticates the entire input.
        let incoming = wire.expand().unwrap().evidence;
        let head = h.node.storage_head().unwrap();
        let ledger = h.node.chain.ledger.clone();
        let prefix = h
            .node
            .blocks()
            .unwrap()
            .collect::<Result<Vec<_>>>()
            .unwrap();
        let finality = h.node.chain.finalized;
        let records = h.node.fixture_paged_records().unwrap();
        let archive_path = h.root.join(format!("runtime-work-{recipient}/state.json"));
        let manifest_path = h.root.join("node/ledger-events/live.json");
        let mut before = inventory(&h.root);
        before.remove(&archive_path);
        before.remove(&manifest_path);
        let report = actors[recipient]
            .probe_fixture_receive(&mut h.node, &raw)
            .unwrap();
        assert!(
            report["error"].is_null(),
            "ordinary Native receive refused: {report}"
        );
        assert_eq!(report["retained_messages"], 41);
        assert!(report["strict_signature_checks"].as_u64().unwrap() > 0);
        let post_sync_head = h.node.storage_head().unwrap();
        assert_ne!(
            post_sync_head, head,
            "ordinary sync must durably append the complete Evidence event"
        );
        assert_eq!(h.node.chain.ledger, ledger);
        assert_eq!(h.node.chain.finalized, finality);
        assert_eq!(
            h.node
                .blocks()
                .unwrap()
                .collect::<Result<Vec<_>>>()
                .unwrap(),
            prefix
        );
        let retained = h.node.fixture_paged_records().unwrap();
        assert_eq!(retained.len(), records.len() + 1);
        assert_eq!(
            serde_json::to_vec(&retained[..records.len()]).unwrap(),
            serde_json::to_vec(&records).unwrap()
        );
        let crate::storage::PagedRecord::Evidence(evidence) = retained.last().unwrap() else {
            panic!("receive appended a record other than complete authenticated Evidence")
        };
        assert_eq!(
            serde_json::to_vec(evidence).unwrap(),
            serde_json::to_vec(&incoming).unwrap()
        );
        let mut after = inventory(&h.root);
        after.remove(&archive_path);
        after.remove(&manifest_path);
        for (path, bytes) in &before {
            assert_eq!(after.get(path), Some(bytes));
        }
        for path in after.keys().filter(|path| !before.contains_key(*path)) {
            assert!(
                path.starts_with(h.root.join("node/ledger-events")),
                "receive changed unrelated private custody bytes"
            );
        }
        let mut retention = None;
        let mut measured = 0.0;
        for row in report["trace"].as_array().unwrap() {
            let phase = row["phase"].as_str().unwrap();
            let seconds = row["seconds"].as_f64().unwrap();
            if phase.starts_with("receive-") {
                measured += seconds;
            }
            if phase == "receive-retention" {
                retention = Some(seconds);
            }
        }
        let total = report["seconds"].as_f64().unwrap();
        let retention = retention.unwrap();
        assert!(retention > 0.0 && measured <= total);
        let archive_ns = report["archive_phase_ns"].as_array().unwrap();
        let archive_total = archive_ns
            .iter()
            .map(|ns| ns.as_u64().unwrap() as f64)
            .sum::<f64>();
        let graph_ns = (archive_ns[1].as_u64().unwrap() + archive_ns[2].as_u64().unwrap()) as f64;
        assert!(archive_total > 0.0 && archive_total / 1e9 <= retention);
        eprintln!(
            "Packed original Native receive work: {}",
            serde_json::json!({
            "report":report,"retention_fraction":retention/total,
            "retention_dominates_half_receive":retention/total>=0.5,
            "archive_retained_and_proposed_checks_fraction":graph_ns/archive_total,
            "archive_retained_and_proposed_checks_dominate_half":graph_ns/archive_total>=0.5,
            "ledger_prefix_caller_and_signer_bytes_unchanged":true,
            "exact_original_evidence_event_appended":true,"pre_sync_witness_invalidated":true,
            "network_or_payment_qualification":false})
        );
        drop(actors);
        let root = h.root.clone();
        let seeds = h.seeds.clone();
        drop(h);
        let before = inventory(&root);
        let cold =
            Store::open_pinned(&root.join("node"), &public(1), currency, post_sync_head).unwrap();
        assert_eq!(cold.chain.ledger, ledger);
        assert_eq!(cold.chain.finalized, finality);
        assert_eq!(
            cold.blocks().unwrap().collect::<Result<Vec<_>>>().unwrap(),
            prefix
        );
        assert_eq!(
            serde_json::to_vec(&cold.fixture_paged_records().unwrap()).unwrap(),
            serde_json::to_vec(&retained).unwrap()
        );
        let archive = crate::bft_runtime_archive::Client::lock(
            &root.join(format!("runtime-work-{recipient}")),
            public(seeds[recipient]),
            crate::bft_client::FORMAT.into(),
            &cold,
        )
        .unwrap();
        let archive_receipt = archive.read(&cold).unwrap();
        assert_eq!(archive_receipt.message_count, 41);
        drop(archive);
        let complete_archive = crate::bft_runtime_archive::Archive::decode(
            &fs::read(root.join(format!("runtime-work-{recipient}/state.json"))).unwrap(),
        )
        .unwrap();
        let entries = complete_archive
            .runtime
            .messages
            .values()
            .collect::<Vec<_>>();
        let mut authenticated = 0;
        for records in entries.chunks(crate::bft_network::MAX_COLD_BATCH) {
            let wires = records
                .iter()
                .map(|record| {
                    let value = complete_archive.envelope(record).unwrap();
                    let wire: crate::bft_network::WireEnvelope =
                        serde_json::from_value(value.clone()).unwrap();
                    assert_eq!(serde_json::to_value(&wire).unwrap(), value);
                    wire
                })
                .collect::<Vec<_>>();
            let checked = crate::bft_network::check_cold_batch(wires, &cold).unwrap();
            assert_eq!(checked.len(), records.len());
            for (record, checked) in records.iter().zip(checked) {
                assert_eq!(checked.value, record.value);
                authenticated += 1;
            }
        }
        assert_eq!(authenticated, 41);
        for (n, seed) in seeds.iter().enumerate() {
            let caller = crate::bft_client::Client::lock(
                &root.join(format!("runtime-caller-{n}/head.json")),
                &root.join(format!("signer-{seed}")),
                public(*seed),
                crate::bft_client::FORMAT.into(),
                &cold,
            )
            .unwrap();
            let state = caller.read().unwrap();
            assert!(state.pending.is_none() && state.outbox.is_none());
            if n == recipient {
                let context = Context::current(&cold).unwrap();
                let observation = crate::bft_phase_schedule::observe(
                    &cold,
                    crate::bft_proposal_schedule::Pins {
                        signer: &root.join(format!("signer-{seed}")),
                        archive: &root.join(format!("runtime-work-{recipient}")),
                        key: public(*seed),
                        runtime_format: crate::bft_client::FORMAT.into(),
                        head: state.head,
                        archive_head: archive_receipt.state_sha256,
                        context: context.clone(),
                        round: 0,
                    },
                    crate::bft_phase_schedule::Mode::Start,
                    crate::bft_phase_schedule::Input {
                        context,
                        order: complete_archive.runtime.messages.keys().copied().collect(),
                    },
                )
                .unwrap();
                // This separate scheduler count names only current-context
                // controls. Whole-archive authentication is checked above.
                assert_eq!(observation.authenticated_messages, 5);
            }
            let agent = Agent::open(&root.join(format!("signer-{seed}")), &cold).unwrap();
            assert_eq!(agent.head().unwrap(), state.head);
        }
        assert_eq!(inventory(&root), before);
        assert!(
            started.elapsed().as_secs_f64() < 60.0,
            "original receive component deadline"
        );
        return;
    }
    actors[0]
        .retain_fixture_controls(&h.node, &messages)
        .unwrap();
    let head = h.node.storage_head().unwrap();
    let ledger = h.node.chain.ledger.clone();
    let archive_path = h.root.join("runtime-work-0/state.json");
    let old_archive =
        crate::bft_runtime_archive::Archive::decode(&fs::read(&archive_path).unwrap()).unwrap();
    let mut before = inventory(&h.root);
    before.remove(&archive_path);
    let report = actors[0].probe_tick(&mut h.node).unwrap();
    assert!(report["error"].is_null(), "Runtime tick refused: {report}");
    assert_eq!(report["decision"], "idle");
    assert_eq!(report["retained_messages"], 41);
    assert_eq!(h.node.storage_head().unwrap(), head);
    assert_eq!(h.node.chain.ledger, ledger);
    let mut after = inventory(&h.root);
    after.remove(&archive_path);
    assert_eq!(after, before);
    let mut observed_archive =
        crate::bft_runtime_archive::Archive::decode(&fs::read(&archive_path).unwrap()).unwrap();
    assert_eq!(observed_archive.runtime.height, h.node.chain.height());
    assert_eq!(observed_archive.runtime.tip, h.node.chain.tip().unwrap());
    // Only a native-checked current observation may advance. Every original
    // retained body, envelope reference, local flag and remaining byte is exact.
    observed_archive.runtime.height = old_archive.runtime.height;
    observed_archive.runtime.tip = old_archive.runtime.tip;
    assert_eq!(observed_archive, old_archive);
    let mut measured = 0.0;
    let mut observed = 0.0;
    for row in report["trace"].as_array().unwrap() {
        let seconds = row["seconds"].as_f64().unwrap();
        measured += seconds;
        if row["phase"] == "consensus-complete-observe" {
            observed += seconds;
        }
    }
    let total = report["seconds"].as_f64().unwrap();
    assert!(observed > 0.0 && measured <= total);
    eprintln!(
        "Packed Native Runtime work: {}",
        serde_json::json!({
            "report":report,"complete_observe_fraction":observed/total,
            "dominates_half_tick":observed/total>=0.5,
            "unchanged_native_and_caller_inventory":true,
            "network_or_ordinary_payment_qualification":false
        })
    );
    assert_eq!(report["complete_archive_byte_checks"], 2,
        "metadata-only publication must inherit exact graph checks from its retained input in this call");
    assert_eq!(report["complete_envelope_byte_checks"], 82);
    drop(actors);
    let client = crate::bft_runtime_archive::Client::lock(
        &h.root.join("runtime-work-0"),
        public(h.seeds[0]),
        crate::bft_client::FORMAT.into(),
        &h.node,
    )
    .unwrap();
    let current =
        crate::bft_runtime_archive::Archive::decode(&fs::read(&archive_path).unwrap()).unwrap();
    let receipt = client.read(&h.node).unwrap();
    let before_guards = inventory(&h.root);
    for attack in 0..7 {
        let mut changed = current.clone();
        match attack {
            0 => changed.runtime.cursor = u64::MAX,
            1 => changed.runtime.snapshot_cache = vec![Hash::ZERO; 65],
            2 => {
                changed.runtime.height = 3;
                changed.runtime.tip = h.node.block_at(3).unwrap().header.id().unwrap();
            }
            3 => changed.runtime.tip = Hash::ZERO,
            4 => changed.runtime.binding.key = public(127),
            5 => {
                changed.runtime.messages.pop_first();
            }
            _ => {
                changed
                    .runtime
                    .messages
                    .values_mut()
                    .next()
                    .unwrap()
                    .refs
                    .push(Hash::ZERO);
            }
        }
        let raw = crate::wallet_client::canonical_with_limit(
            &changed,
            crate::bft_runtime_archive::MAX_STATE,
        )
        .unwrap();
        assert!(
            client
                .store(&h.node, &raw, Some(receipt.state_sha256))
                .is_err(),
            "archive guard attack {attack} passed"
        );
        assert_eq!(inventory(&h.root), before_guards);
    }
    let raw = fs::read(&archive_path).unwrap();
    assert!(client.store(&h.node, &raw, Some(Hash::ZERO)).is_err());
    assert_eq!(inventory(&h.root), before_guards);
    let mut changed = current.clone();
    let mut record = current
        .runtime
        .messages
        .values()
        .find(|record| {
            let body: crate::bft_network::Body =
                serde_json::from_value(record.body.clone()).unwrap();
            matches!(body, crate::bft_network::Body::Signed(message)
            if matches!(*message, Message::Vote(ref vote) if vote.context.parent_height == 4))
        })
        .unwrap()
        .clone();
    let crate::bft_network::Body::Signed(mut message) =
        serde_json::from_value(record.body.clone()).unwrap()
    else {
        panic!("original signed vote")
    };
    let Message::Vote(ref mut vote) = *message else {
        panic!("original vote")
    };
    vote.approval.signature = "00".repeat(64);
    record.body = serde_json::to_value(crate::bft_network::Body::Signed(message)).unwrap();
    let envelope = crate::wallet_client::canonical(&changed.envelope(&record).unwrap()).unwrap();
    record.sha256 = Hash(Sha256::digest(&envelope).into());
    record.size_bytes = envelope.len();
    let ident = Hash(Sha256::digest(crate::wallet_client::canonical(&record.body).unwrap()).into());
    changed.runtime.messages.insert(ident, record);
    let raw =
        crate::wallet_client::canonical_with_limit(&changed, crate::bft_runtime_archive::MAX_STATE)
            .unwrap();
    assert!(crate::bft_runtime_archive::Archive::decode(&raw).is_ok());
    let error = client
        .store(&h.node, &raw, Some(receipt.state_sha256))
        .err()
        .expect("hash-consistent bad envelope must refuse");
    assert!(
        error.contains("signature"),
        "changed envelope was not natively authenticated: {error}"
    );
    assert_eq!(inventory(&h.root), before_guards);
    let mut local = current.clone();
    local
        .runtime
        .messages
        .values_mut()
        .find(|record| !record.local)
        .unwrap()
        .local = true;
    let raw =
        crate::wallet_client::canonical_with_limit(&local, crate::bft_runtime_archive::MAX_STATE)
            .unwrap();
    let accepted = client
        .store(&h.node, &raw, Some(receipt.state_sha256))
        .unwrap();
    assert_eq!(accepted.new_envelopes_authenticated, 1);
    assert!(
        accepted.full_cold_authentication_required
            && !accepted.ledger_changed
            && !accepted.signing_authority
    );
    assert_eq!(h.node.storage_head().unwrap(), head);
    assert_eq!(h.node.chain.ledger, ledger);
    drop(client);
    let root = h.root.clone();
    let seeds = h.seeds.clone();
    drop(h);
    let before = inventory(&root);
    let cold = Store::open_pinned(&root.join("node"), &public(1), currency, head).unwrap();
    assert_eq!(cold.chain.ledger, ledger);
    for (n, seed) in seeds.iter().enumerate() {
        let caller = crate::bft_client::Client::lock(
            &root.join(format!("runtime-caller-{n}/head.json")),
            &root.join(format!("signer-{seed}")),
            public(*seed),
            crate::bft_client::FORMAT.into(),
            &cold,
        )
        .unwrap();
        let state = caller.read().unwrap();
        assert!(state.pending.is_none() && state.outbox.is_none());
        let agent = Agent::open(&root.join(format!("signer-{seed}")), &cold).unwrap();
        assert_eq!(agent.head().unwrap(), state.head);
    }
    assert_eq!(inventory(&root), before);
    assert!(
        started.elapsed().as_secs_f64() < 60.0,
        "Runtime work component deadline"
    );
}
