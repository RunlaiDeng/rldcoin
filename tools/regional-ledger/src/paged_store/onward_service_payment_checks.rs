//! Native-derived prefix/accounting and original-custody checks for service_payment.
use super::*;

pub(super) fn import_receipt(node: &Store, setup: &Setup) -> wallet::Receipt {
    let value = wallet::receipt(
        node,
        wallet::ReceiptExpectation {
            currency: setup.currency,
            source: setup.proof.history.source,
            destination: setup.proof.history.destination,
            export: setup.export,
            recipient: public(12),
            net_amount: Amount(89),
        },
    )
    .unwrap();
    assert_eq!(value.verified_source_checkpoint, setup.b4);
    assert!(value.evidence_verified && value.import_accepted && value.local_finality_covers_import);
    assert!(!value.quarantined);
    assert_eq!(
        value.mature_height,
        Some(value.import_height.unwrap() + node.trust.currency.maturity)
    );
    value
}
fn prefix(node: &Store) -> Vec<Snapshot> {
    let mut next = node.chain.finalized;
    let mut height = node.chain.height();
    let mut result = vec![];
    while let Some(key) = next {
        assert!(height > 0 && result.len() < STOP_HEIGHT as usize);
        let snapshot = node.evidence.snapshot(key).unwrap().clone();
        assert_eq!(snapshot.statement.id().unwrap(), key);
        assert_eq!(snapshot.statement.height, height);
        assert_eq!(snapshot.statement.currency, node.trust.currency().unwrap());
        assert_eq!(snapshot.statement.region, node.chain.region);
        let block = snapshot.blocks.last().unwrap();
        assert_eq!(block.header.height, height);
        assert_eq!(block.header.id().unwrap(), snapshot.statement.block);
        next = snapshot.statement.previous;
        height -= 1;
        result.push(snapshot);
    }
    assert_eq!(height, 0);
    result.reverse();
    result
}
pub(super) fn payment_checkpoint(node: &Store, payment: &PaymentPins) -> Option<Hash> {
    let found = prefix(node)
        .into_iter()
        .filter(|s| s.blocks.last().unwrap().commands == payment.commands)
        .collect::<Vec<_>>();
    assert!(found.len() <= 1, "same declared payment appeared twice");
    found.first().map(|s| s.statement.id().unwrap())
}
fn coin(
    node: &Store,
    key: Hash,
    owner: u8,
    amount: u128,
    created: u64,
    mature: u64,
    setup: &Setup,
) {
    assert_eq!(
        node.chain.ledger.coins[&key],
        Coin {
            payment: Payment {
                owner: public(owner),
                amount: Amount(amount)
            },
            created,
            mature,
            dependencies: BTreeSet::from([setup.a80, setup.b4]),
            channel_dependencies: BTreeSet::new()
        }
    );
}
pub(super) fn first_recipient(
    node: &Store,
    setup: &Setup,
    payment: &PaymentPins,
    checkpoint: Hash,
) {
    node.require_onward_network_state().unwrap();
    assert_eq!(payment_checkpoint(node, payment), Some(checkpoint));
    assert_eq!(payment.number, 1);
    assert_eq!(payment.owner, 12);
    assert_eq!(payment.recipient, 13);
    let height = node.evidence.snapshot(checkpoint).unwrap().statement.height;
    assert!(node
        .evidence
        .descends_from(node.chain.finalized.unwrap(), checkpoint)
        .unwrap());
    assert!(!node.chain.ledger.coins.contains_key(&payment.input));
    coin(node, payment.output, 13, 88, height, height, setup);
    assert!(ready_coin(node, 13, payment.output, Amount(88)));
    let receipt = import_receipt(node, setup);
    assert!(receipt.maturity_reached);
    assert_eq!(receipt.original_output_remaining, Amount::ZERO);
    assert!(node.journal.incident_ids.is_empty());
}
pub(super) fn completed(node: &Store, setup: &Setup, payments: &[PaymentPins], s2: Hash) {
    assert_eq!(payments.len(), 2);
    node.require_onward_network_state().unwrap();
    node.require_retained_onward_material(Some(&setup.proof), &[])
        .unwrap();
    assert!(node
        .evidence
        .descends_from(node.chain.finalized.unwrap(), s2)
        .unwrap());
    assert_eq!(payment_checkpoint(node, &payments[1]), Some(s2));
    let p1 = payment_checkpoint(node, &payments[0]).unwrap();
    let h1 = node.evidence.snapshot(p1).unwrap().statement.height;
    let h2 = node.evidence.snapshot(s2).unwrap().statement.height;
    assert!(h1 < h2);
    assert_eq!(
        payments[0].input,
        id("output", &(setup.export, 0u32)).unwrap()
    );
    assert_eq!(payments[1].input, payments[0].output);
    assert_eq!(
        payments[0].output,
        id("output", &(payments[0].intent, 0u32)).unwrap()
    );
    assert_eq!(
        payments[1].output,
        id("output", &(payments[1].intent, 0u32)).unwrap()
    );
    assert!(payments[0].submitted_at < payments[1].submitted_at);
    let receipt = import_receipt(node, setup);
    let import_height = receipt.import_height.unwrap();
    assert!(import_height + node.trust.currency.maturity <= h1 && h1 < h2);
    assert_eq!(receipt.original_output_remaining, Amount::ZERO);
    assert!(receipt.maturity_reached);
    let history = prefix(node);
    let mut nonempty = vec![];
    for s in &history {
        let commands = &s.blocks.last().unwrap().commands;
        if !commands.is_empty() {
            nonempty.push((s.statement.height, commands.clone()));
        }
        if s.statement.height > h2 {
            assert!(
                commands.is_empty(),
                "unexpected command in final empty tail"
            );
        }
    }
    assert_eq!(
        nonempty,
        vec![
            (
                import_height,
                vec![Command::Import {
                    snapshot: setup.b4,
                    export: setup.export
                }]
            ),
            (h1, payments[0].commands.clone()),
            (h2, payments[1].commands.clone())
        ]
    );
    assert_eq!(node.chain.ledger, node.evidence.snapshots[&s2].1);
    let ledger = &node.chain.ledger;
    assert_eq!(ledger.coins.len(), 4);
    assert!(!ledger.coins.contains_key(&payments[0].input));
    assert!(!ledger.coins.contains_key(&payments[1].input));
    coin(node, payments[1].output, 14, 87, h2, h2, setup);
    assert!(ready_coin(node, 14, payments[1].output, Amount(87)));
    let maturity = node.trust.currency.maturity;
    for (intent, created) in [
        (setup.export, import_height),
        (payments[0].intent, h1),
        (payments[1].intent, h2),
    ] {
        coin(
            node,
            id("output", &(intent, 16u32)).unwrap(),
            12,
            1,
            created,
            created + maturity,
            setup,
        );
    }
    assert_eq!(ledger.imports, BTreeMap::from([(setup.export, setup.b4)]));
    assert!(ledger.exports.is_empty() && ledger.channel_state.is_none());
    assert_eq!(ledger.minted, Amount::ZERO);
    assert_eq!(ledger.received, Amount(90));
    assert_eq!(
        ledger
            .coins
            .values()
            .map(|c| c.payment.amount.0)
            .sum::<u128>(),
        90
    );
    assert!(node
        .complete_onward_network_pending_imports()
        .unwrap()
        .is_empty());
    assert!(node.journal.incident_ids.is_empty());
    ledger.audit().unwrap();
    // These ledgers were derived by the complete current Native replay, not read from test JSON.
    let a = &node.evidence.snapshots[&setup.a80].1;
    let b = &node.evidence.snapshots[&setup.b4].1;
    let a_export = setup.proof.history.origin.export;
    let ax = &a.exports[&a_export];
    let bx = &b.exports[&setup.export];
    assert_eq!(ax.destination, setup.proof.history.source);
    assert_eq!(ax.recipient.amount, Amount(100));
    assert_eq!(b.imports.get(&a_export), Some(&setup.a80));
    assert_eq!(bx.destination, setup.proof.history.destination);
    assert_eq!(bx.recipient.amount, Amount(90));
    assert_eq!(bx.destination_fee, Amount(1));
    assert_eq!(bx.dependencies, BTreeSet::from([setup.a80]));
    assert_eq!(b, &setup.b_ledger);
    assert_eq!(a.exports.len(), 1);
    assert_eq!(b.exports.len(), 1);
    assert_eq!(b.minted, Amount::ZERO);
    assert_eq!(
        b.coins.values().map(|c| c.payment.amount.0).sum::<u128>(),
        10
    );
    let liquid = |l: &Ledger| l.coins.values().map(|c| c.payment.amount.0).sum::<u128>();
    assert_eq!(liquid(a) + liquid(b) + liquid(ledger), a.minted.0);
    a.audit().unwrap();
    b.audit().unwrap();
}
pub(super) fn observe(node: &Store, actor: usize) -> NativeObservation {
    NativeObservation {
        actor,
        checked_at: now(),
        head: node.storage_head().unwrap(),
        height: node.chain.height(),
        finality: node.chain.finalized.unwrap(),
        prefix: prefix(node),
        ledger: node.chain.ledger.clone(),
    }
}
pub(super) fn brief(o: &NativeObservation) -> Value {
    json!({"actor":o.actor,"checked_at":o.checked_at,"head":o.head,"height":o.height,"finality":o.finality,
        "ledger_root":o.ledger.root().unwrap(),"prefix":o.prefix.iter().map(|s|s.statement.id().unwrap()).collect::<Vec<_>>(),
        "fee_maturity":o.ledger.coins.iter().filter(|(_,c)|c.payment.amount==Amount(1)).map(|(id,c)|
            json!({"id":id,"created":c.created,"mature":c.mature,"height_mature":o.height>=c.mature})).collect::<Vec<_>>()})
}
pub(super) fn compatible(nodes: &[NativeObservation]) {
    assert_eq!(nodes.len(), 4);
    assert_eq!(
        nodes.iter().map(|n| n.actor).collect::<Vec<_>>(),
        vec![0, 1, 2, 3]
    );
    for a in nodes {
        for b in nodes {
            for (left, right) in a.prefix.iter().zip(&b.prefix) {
                assert_eq!(
                    left.statement.id().unwrap(),
                    right.statement.id().unwrap(),
                    "incompatible certified empty prefix"
                );
            }
            assert_eq!(a.ledger, b.ledger);
        }
    }
}
fn original_caller(root: &Path, node: &Store, setup: &Setup, actor: usize) -> bft_client::State {
    let caller = bft_client::Client::lock(
        &root.join(format!("caller-{actor}/head.json")),
        &root.join(format!("signer-{actor}")),
        public(setup.seeds[actor]),
        bft_client::ONWARD_FORMAT.into(),
        node,
    )
    .unwrap();
    let state = caller.read().unwrap();
    assert!(state.pending.is_none() && state.outbox.is_none());
    state
}
fn original_messages(
    root: &Path,
    node: &Store,
    setup: &Setup,
    actor: usize,
    caller: &bft_client::State,
) -> (usize, Vec<Message>) {
    let agent = Agent::inspect_with_status(&root.join(format!("signer-{actor}")), node)
        .unwrap()
        .0;
    assert_eq!(agent.journal.creation.pin.height, 0);
    assert_eq!(agent.head().unwrap(), caller.head);
    assert_ne!(caller.head, setup.initial_bft_heads[actor]);
    assert_eq!(agent.journal.binding.key, public(setup.seeds[actor]));
    (agent.record_count(), agent.retained_messages(node).unwrap())
}
fn archive_presence(
    root: &Path,
    node: &Store,
    actor: usize,
    messages: &[Message],
) -> (Hash, usize) {
    let raw = fs::read(root.join(format!("runtime-{actor}/state.json"))).unwrap();
    let archive = crate::bft_runtime_archive::Archive::decode(&raw).unwrap();
    assert_eq!(archive.format, crate::bft_runtime_archive::ONWARD_FORMAT);
    let mut required = messages
        .iter()
        .cloned()
        .map(|m| Body::Signed(Box::new(m)))
        .collect::<Vec<_>>();
    required.push(Body::Finalized(Box::new(
        node.evidence
            .snapshot(node.chain.finalized.unwrap())
            .unwrap()
            .clone(),
    )));
    for body in required {
        let typed = serde_json::to_value(body).unwrap();
        assert!(archive.runtime.messages.values().any(|r|r.body==typed),
            "cold closure missing exact original signed/current Finalized body; do not repair or reopen");
    }
    // Byte/body membership is only a precondition. Fresh Runtime open does complete authentication.
    (sha(&raw), raw.len())
}
fn vote_custody(nodes: &[NativeObservation], setup: &Setup, messages: &[Vec<Message>]) {
    let keys = setup.seeds.iter().map(|s| public(*s)).collect::<Vec<_>>();
    for node in nodes {
        for (index, snapshot) in node.prefix.iter().enumerate() {
            let cert = snapshot.bft.as_ref().unwrap();
            let value = snapshot.statement.id().unwrap();
            let (parent_height, parent_block, parent_state) = if index == 0 {
                (
                    0,
                    setup.proof.history.destination,
                    Ledger::default().root().unwrap(),
                )
            } else {
                let previous = &node.prefix[index - 1].statement;
                assert_eq!(snapshot.statement.previous, Some(previous.id().unwrap()));
                (previous.height, previous.block, previous.state)
            };
            let context = crate::bft::Context {
                currency: setup.currency,
                region: setup.proof.history.destination,
                epoch: snapshot.statement.epoch,
                previous: snapshot.statement.previous,
                parent_height,
                parent_block,
                parent_state,
            };
            cert.verify(&context, value, &keys).unwrap();
            assert_eq!(cert.prepared.round, cert.committed.round);
            assert_eq!(cert.prepared.context, cert.committed.context);
            for (q, phase) in [
                (&cert.prepared, Phase::Prepare),
                (&cert.committed, Phase::Commit),
            ] {
                assert_eq!(q.votes.len(), 3);
                assert_eq!(q.phase, phase);
                assert_eq!(q.value, value);
                assert_eq!(q.context.currency, setup.currency);
                assert_eq!(q.context.region, setup.proof.history.destination);
                assert_eq!(q.context.parent_height + 1, snapshot.statement.height);
                assert_eq!(q.context.previous, snapshot.statement.previous);
                for vote in &q.votes {
                    let actor = keys.iter().position(|k| k == &vote.approval.key).unwrap();
                    assert!(
                        messages[actor]
                            .iter()
                            .any(|m| matches!(m,Message::Vote(v) if v.as_ref()==vote)),
                        "certificate vote missing from its original C0 Agent response journal"
                    );
                }
            }
        }
    }
}
fn owner_cold(root: &Path, node: &Store, p: &PaymentPins) {
    let caller = owner_client(root, p.owner, node);
    assert_eq!(caller.read().unwrap(), p.caller);
    assert_eq!(caller.open(node, Some(p.head)).unwrap(), p.caller);
    assert!(p.caller.pending.is_none());
    drop(caller);
    let agent = wallet_agent::Agent::open(&owner_root(root, p.owner).join("wallet"), node).unwrap();
    assert_eq!(agent.journal.creation.pin.height, 0);
    assert_eq!(agent.journal.head().unwrap(), p.head);
    assert_ne!(p.head, p.initial_head);
    assert_eq!(agent.journal.records.len(), 1);
    let record = &agent.journal.records[0];
    assert_eq!(record.previous_head, p.initial_head);
    assert_eq!(record.observation.pin, p.prepared.draft.pin);
    assert_eq!(record.draft, p.prepared.draft);
    assert_eq!(record.review_commitment, p.prepared.review_commitment);
    assert_eq!(record.command, p.commands[0]);
    let recovered = agent.recover_prepared(node, &p.prepared).unwrap();
    assert!(recovered.recovered_exact_retry && recovered.retained_approvals_complete);
    assert_eq!(recovered.commands, p.commands);
    assert_eq!(recovered.wallet_head, p.head);
    assert_eq!(
        agent.view(node, p.head).unwrap().reserved_owned_outputs,
        Amount::ZERO
    );
}
fn source(root: &Path, setup: &Setup) {
    let b = Store::open_pinned_inspection(
        &root.join("intermediate"),
        &public(1),
        setup.currency,
        setup.b_head,
    )
    .unwrap();
    assert_eq!(b.chain.height(), 5);
    assert_eq!(b.chain.ledger, setup.b_ledger);
    assert_eq!(
        b.complete_onward_network_export(setup.export).unwrap(),
        setup.proof
    );
    assert_eq!(
        b.chain
            .ledger
            .imports
            .get(&setup.proof.history.origin.export),
        Some(&setup.a80)
    );
    assert!(!b
        .chain
        .ledger
        .coins
        .contains_key(&id("output", &(setup.proof.history.origin.export, 0u32)).unwrap()));
    assert!(b.journal.incident_ids.is_empty());
}
pub(super) fn capture(
    root: &Path,
    setup: Setup,
    payments: Vec<PaymentPins>,
    s2: Hash,
    completion: Completion,
) -> ColdPins {
    let Completion {
        before_stop,
        recipient_observations,
        normal_stops,
    } = completion;
    within(setup.deadline);
    source(root, &setup);
    assert_eq!(immutable_files(root), setup.original_files);
    let mut nodes = vec![];
    let mut originals = vec![];
    let mut s2_ledger = None;
    assert_eq!(before_stop.len(), 4);
    for (actor, previous) in before_stop.iter().enumerate() {
        within(setup.deadline);
        let node =
            Store::open_inspection(&ledger_path(root, actor), &public(1), setup.currency).unwrap();
        completed(&node, &setup, &payments, s2);
        let observed = observe(&node, actor);
        assert!(node
            .evidence
            .descends_from(observed.finality, previous.finality)
            .unwrap());
        assert!(observed.height <= STOP_HEIGHT);
        let current_s2 = node.evidence.snapshots[&s2].1.clone();
        if let Some(l) = &s2_ledger {
            assert_eq!(l, &current_s2);
        } else {
            s2_ledger = Some(current_s2);
        }
        let caller = original_caller(root, &node, &setup, actor);
        let (signer_records, messages) = original_messages(root, &node, &setup, actor, &caller);
        let original_messages = id("onward-service-original-messages", &messages).unwrap();
        let (archive_hash, archive_bytes) = archive_presence(root, &node, actor, &messages);
        originals.push(messages);
        for payment in payments.iter().filter(|p| p.actor == actor) {
            owner_cold(root, &node, payment);
        }
        let mut cold: Value = serde_json::from_slice(
            &fs::read(root.join(format!("payment-runtime-{actor}.json"))).unwrap(),
        )
        .unwrap();
        let absent = root.join(format!("payment-cold-key-{actor}-must-remain-absent.json"));
        assert!(!absent.exists());
        cold["startup_native_history_head"] = json!(observed.head);
        cold["key_file"] = json!(absent);
        let cold_config = root.join(format!("payment-cold-runtime-{actor}.json"));
        new_json(&cold_config, &cold);
        nodes.push(NodePins {
            observed,
            caller,
            signer_records,
            original_messages,
            archive_hash,
            archive_bytes,
            cold_config,
        });
    }
    let observations = nodes.iter().map(|p| p.observed.clone()).collect::<Vec<_>>();
    compatible(&observations);
    vote_custody(&observations, &setup, &originals);
    within(setup.deadline);
    ColdPins {
        format: "RLD-ONWARD-ORDINARY-SERVICE-PAYMENT-COLD-V1".into(),
        mode: "two-original-owner-payments".into(),
        setup,
        payments,
        s2,
        s2_ledger: s2_ledger.unwrap(),
        before_stop,
        nodes,
        recipient_observations,
        normal_stops,
    }
}
pub(super) fn cold(root: &Path) {
    let pins: ColdPins =
        serde_json::from_slice(&fs::read(root.join("payment-cold-pins.json")).unwrap()).unwrap();
    assert_eq!(pins.format, "RLD-ONWARD-ORDINARY-SERVICE-PAYMENT-COLD-V1");
    assert_eq!(pins.mode, "two-original-owner-payments");
    let setup = &pins.setup;
    within(setup.deadline);
    assert_ne!(std::process::id(), setup.parent_pid);
    assert_eq!(unsafe { libc::getppid() } as u32, setup.parent_pid);
    assert_eq!(sha(&fs::read(&setup.cli).unwrap()), setup.cli_sha256);
    assert_eq!(std::env::current_exe().unwrap(), setup.test_binary);
    assert_eq!(
        sha(&fs::read(&setup.test_binary).unwrap()),
        setup.test_binary_sha256
    );
    let before = inventory(root);
    assert_eq!(immutable_files(root), setup.original_files);
    source(root, setup);
    let mut observations = vec![];
    let mut originals = vec![];
    for actor in 0..4 {
        within(setup.deadline);
        let expected = &pins.nodes[actor];
        let node = Store::open_pinned_inspection(
            &ledger_path(root, actor),
            &public(1),
            setup.currency,
            expected.observed.head,
        )
        .unwrap();
        completed(&node, setup, &pins.payments, pins.s2);
        let actual = observe(&node, actor);
        assert_eq!(actual.head, expected.observed.head);
        assert_eq!(actual.height, expected.observed.height);
        assert_eq!(actual.finality, expected.observed.finality);
        assert_eq!(actual.prefix, expected.observed.prefix);
        assert_eq!(actual.ledger, expected.observed.ledger);
        assert_eq!(actual.ledger, pins.s2_ledger);
        assert!(node
            .evidence
            .descends_from(actual.finality, pins.before_stop[actor].finality)
            .unwrap());
        let runtime =
            TestRuntime::open(&expected.cold_config, &node, &setup.transports[actor + 1]).unwrap();
        let caller = original_caller(root, &node, setup, actor);
        assert_eq!(caller, expected.caller);
        let (records, messages) = original_messages(root, &node, setup, actor, &caller);
        assert_eq!(records, expected.signer_records);
        assert_eq!(
            id("onward-service-original-messages", &messages).unwrap(),
            expected.original_messages
        );
        assert_eq!(
            archive_presence(root, &node, actor, &messages),
            (expected.archive_hash, expected.archive_bytes)
        );
        for payment in pins.payments.iter().filter(|p| p.actor == actor) {
            owner_cold(root, &node, payment);
        }
        assert!(!root
            .join(format!("payment-cold-key-{actor}-must-remain-absent.json"))
            .exists());
        originals.push(messages);
        observations.push(actual);
        drop(runtime);
        drop(node);
    }
    compatible(&observations);
    vote_custody(&observations, setup, &originals);
    let mut actual_complete_frames = 0usize;
    for i in 0..5 {
        within(setup.deadline);
        let transport = Node::open(&setup.transports[i]).unwrap();
        if i == 0 {
            assert!(
                transport.observation()["retained_receipts"]
                    .as_u64()
                    .unwrap()
                    >= 1
            );
        } else {
            for (_, raw) in transport.received_frames().unwrap() {
                let (frame, _) = crate::contact_frame::inspect_bytes(
                    &raw,
                    None,
                    None,
                    crate::contact::MAX_PAYLOAD,
                    crate::contact::MAX_FRAME,
                )
                .unwrap();
                if frame.kind == "onward-source-finality" {
                    let (f, proof) = crate::contact::Frame::unpack_onward(&raw).unwrap();
                    assert_eq!(proof, setup.proof);
                    assert_eq!(f.export_id, setup.export);
                    assert_eq!(f.source_chain_id, setup.proof.history.source);
                    assert_eq!(f.destination_chain_id, setup.proof.history.destination);
                    actual_complete_frames += 1;
                }
            }
        }
        drop(transport);
        assert_eq!(tls_identity(&setup.transports[i]).unwrap(), setup.tls[i]);
    }
    assert!(
        actual_complete_frames >= 1,
        "ordinary B carriage not observed at any C transport"
    );
    assert_eq!(immutable_files(root), setup.original_files);
    assert_eq!(
        inventory(root),
        before,
        "fresh-process full Native/Runtime/owner cold replay changed bytes"
    );
    within(setup.deadline);
    // The libtest preamble preceded the before-inventory; no output was written during checks.
    eprintln!(
        "onward_service_payment_cold_result={}",
        json!({"root":root,"pid":std::process::id(),
        "parent_pid":setup.parent_pid,"started":setup.started,"deadline":setup.deadline,"ended":now(),
        "mode":pins.mode,"test_binary_sha256":setup.test_binary_sha256,"cli_sha256":setup.cli_sha256,
        "passed":true,"four_native_runtime_cold":true,"both_original_owners_cold":true,
        "inventory_unchanged":true,"actual_complete_frames":actual_complete_frames,
        "keyless_startup":true,"original_agent_prepare_commit_custody":true})
    );
}
