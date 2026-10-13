//! Original C0 owner custody through an actual mature Runtime payment.
//! Direct component carriage only; no ordinary Service or latency-cohort claim.
use super::*;
use crate::{wallet, wallet_agent};

pub(super) const TEST: &str = "storage::paged::onward_runtime_tests::owner_spend::original_onward_owner_matures_import_spends_and_cold_replays";
pub(super) const COVERAGE: &str =
    "every tick and receive in the five original-owner C1 through C5 direct-drive loops only";
pub(super) const EXCLUDED: &str = "setup, keyless-recovery loop, explicit wrapper receipts/retries, owner prepare/sign/queue and cold child";

#[derive(Serialize, Deserialize)]
pub(super) struct Pins {
    initial_head: Hash,
    head: Hash,
    caller: files::State,
    prepared: wallet_agent::Prepared,
    commands: Vec<Command>,
    input: Hash,
    output: Hash,
    intent: Hash,
    queue: Hash,
    submitted_at: f64,
    queue_returned_at: f64,
    recipient_observations: Vec<Value>,
}
impl Pins {
    pub(super) fn report(&self) -> Value {
        json!({"submitted_at":self.submitted_at,"queue_returned_at":self.queue_returned_at,
            "input":self.input,"output":self.output,"intent":self.intent,"queue":self.queue,
            "requested_owner":public(12),"recipient":public(13),"input_amount":"89",
            "recipient_amount":"88","fee":"1","status":"completed",
            "recipient_observations":self.recipient_observations,"displayed_recipient_actor":2,
            "completion_clock":"upper-bound observation after Native finality and eligibility checks",
            "normal_latency_cohort_qualified":false})
    }
}
pub(super) struct Owner {
    root: PathBuf,
    initial_head: Hash,
    pins: Option<Pins>,
    immature: Vec<u64>,
}
fn request(export: Hash) -> wallet::Request {
    wallet::Request {
        owner: public(12),
        participants: vec![],
        inputs: Some(vec![id("output", &(export, 0u32)).unwrap()]),
        outputs: vec![Payment {
            owner: public(13),
            amount: Amount(88),
        }],
        remote: None,
        fee: Amount(1),
        valid_for_blocks: 8,
        valid_through: None,
    }
}
fn client(root: &Path, node: &Store) -> files::Client {
    files::Client::lock(
        &root.join("owner-caller"),
        &root.join("owner-wallet"),
        public(12),
        node,
    )
    .unwrap()
}
fn receipt(node: &Store, b4: Hash, export: Hash) -> wallet::Receipt {
    let value = wallet::receipt(
        node,
        wallet::ReceiptExpectation {
            currency: node.trust.currency().unwrap(),
            source: node.trust.named("proxima").unwrap(),
            destination: node.chain.region,
            export,
            recipient: public(12),
            net_amount: Amount(89),
        },
    )
    .unwrap();
    assert_eq!(value.verified_source_checkpoint, b4);
    assert!(value.evidence_verified && value.import_accepted && value.local_finality_covers_import);
    assert_eq!(value.import_height, Some(2));
    assert_eq!(value.mature_height, Some(4));
    assert!(!value.quarantined);
    value
}
impl Owner {
    pub(super) fn create(root: &Path, node: &Store) -> Self {
        assert_eq!(node.chain.height(), 0);
        let agent =
            wallet_agent::Agent::create(&root.join("owner-wallet"), node, public(12)).unwrap();
        assert_eq!(agent.journal.creation.pin.height, 0);
        assert!(agent.journal.records.is_empty());
        let initial_head = agent.journal.head().unwrap();
        drop(agent);
        dir(&root.join("owner-caller"));
        let state = client(root, node).open(node, Some(initial_head)).unwrap();
        assert_eq!(state.head, Some(initial_head));
        assert!(state.pending.is_none());
        new_json(
            &root.join("owner-key.json"),
            &json!({"secret_key":hex::encode([12u8;32])}),
        );
        Self {
            root: root.to_owned(),
            initial_head,
            pins: None,
            immature: vec![],
        }
    }
    pub(super) fn immature(&mut self, node: &Store, b4: Hash, export: Hash) {
        let height = node.chain.height();
        assert!(height == 2 || height == 3);
        let before = inventory(&self.root);
        let native_head = node.storage_head().unwrap();
        let value = receipt(node, b4, export);
        assert!(!value.maturity_reached && !value.original_output_spendable_now);
        assert_eq!(value.state, "IMPORT_ACCEPTED_IMMATURE");
        let agent = wallet_agent::Agent::open(&self.root.join("owner-wallet"), node).unwrap();
        assert_eq!(agent.journal.head().unwrap(), self.initial_head);
        assert!(agent.journal.records.is_empty());
        let error = agent
            .prepare(node, request(export), self.initial_head)
            .unwrap_err();
        assert_eq!(
            error,
            "wallet input is not owned, mature, finalized or safe"
        );
        drop(agent);
        let state = client(&self.root, node).read().unwrap();
        assert_eq!(state.head, Some(self.initial_head));
        assert!(state.pending.is_none());
        assert_eq!(node.storage_head().unwrap(), native_head);
        assert_eq!(inventory(&self.root), before);
        self.immature.push(height);
        new_json(
            &self.root.join(format!("owner-immature-{height}.json")),
            &json!({"height":height,"error":error,"unchanged":true}),
        );
    }
    pub(super) fn queue(&mut self, node: &Store, a80: Hash, b4: Hash, export: Hash, deadline: f64) {
        budget(deadline);
        assert_eq!(node.chain.height(), 4);
        assert_eq!(self.immature, [2, 3]);
        let native_head = node.storage_head().unwrap();
        let ledger = node.chain.ledger.clone();
        let value = receipt(node, b4, export);
        assert!(value.maturity_reached && value.original_output_spendable_now);
        assert_eq!(value.state, "ORIGINAL_OUTPUT_SPENDABLE");
        assert_eq!(value.original_output_remaining, Amount(89));
        let mut agent = wallet_agent::Agent::open(&self.root.join("owner-wallet"), node).unwrap();
        let prepared = agent
            .prepare(node, request(export), self.initial_head)
            .unwrap();
        assert_eq!(prepared.draft.pin.height, 4);
        assert_eq!(prepared.draft.selected_input_total, Amount(89));
        assert_eq!(prepared.draft.change, Amount::ZERO);
        assert!(agent.journal.records.is_empty());
        drop(agent);
        budget(deadline);
        let caller = client(&self.root, node);
        let previous = caller.read().unwrap();
        let mut proposed = previous.clone();
        proposed.pending = Some(files::Pending {
            prepared: prepared.clone(),
        });
        let pending = caller
            .store(node, files::Transition { previous, proposed })
            .unwrap();
        assert_eq!(pending.head, Some(self.initial_head));
        assert_eq!(pending.pending.as_ref().unwrap().prepared, prepared);
        drop(caller);
        budget(deadline);
        agent = wallet_agent::Agent::open(&self.root.join("owner-wallet"), node).unwrap();
        let signed = agent
            .sign(
                node,
                prepared.draft.clone(),
                &self.root.join("owner-key.json"),
                prepared.review_commitment,
                self.initial_head,
            )
            .unwrap();
        assert!(!signed.recovered_exact_retry && signed.retained_approvals_complete);
        assert_eq!(signed.required_owners, vec![public(12)]);
        assert_eq!(signed.previous_wallet_head, self.initial_head);
        assert_eq!(signed.intent_id, prepared.draft.intent_id);
        assert_eq!(agent.journal.records.len(), 1);
        assert_eq!(
            agent
                .view(node, signed.wallet_head)
                .unwrap()
                .reserved_owned_outputs,
            Amount(89)
        );
        assert_eq!(signed.commands.len(), 1);
        assert!(
            matches!(&signed.commands[0], Command::Spend(s) if s.intent == prepared.draft.intent
            && s.approvals.len()==1 && s.approvals[0].key==public(12))
        );
        drop(agent);
        let caller = client(&self.root, node);
        assert_eq!(caller.read().unwrap(), pending);
        let mut proposed = pending.clone();
        proposed.head = Some(signed.wallet_head);
        proposed.pending = None;
        let state = caller
            .store(
                node,
                files::Transition {
                    previous: pending,
                    proposed,
                },
            )
            .unwrap();
        drop(caller);
        assert_eq!(state.head, Some(signed.wallet_head));
        assert!(state.pending.is_none());
        assert_eq!(node.storage_head().unwrap(), native_head);
        assert_eq!(node.chain.ledger, ledger);
        let input = id("output", &(export, 0u32)).unwrap();
        let output = id("output", &(signed.intent_id, 0u32)).unwrap();
        budget(deadline);
        // Preserve one original clock before the first admission; never rebase on retry.
        let submitted_at = now();
        new_json(
            &self.root.join("owner-submission.json"),
            &json!({"submitted_at":submitted_at,
            "status":"pending","input":input,"output":output,"intent":signed.intent_id,
            "requested":prepared.draft.request,"commands":signed.commands,"owner_head":signed.wallet_head}),
        );
        let result = node.bft_submit(signed.commands.clone());
        let queue_returned_at = now();
        new_json(
            &self.root.join("owner-queue-response.json"),
            &json!({"submitted_at":submitted_at,
            "returned_at":queue_returned_at,"result":result}),
        );
        let queue = result.unwrap();
        let raw = fs::read(
            node.dir
                .join("bft-submissions")
                .join(format!("{}.json", queue.to_hex())),
        )
        .unwrap();
        let wire: net::WireEnvelope = bft_client::decode(&raw).unwrap();
        let envelope = wire.expand().unwrap();
        assert_eq!(envelope.verify(node).unwrap(), queue);
        assert!(envelope.history.is_some());
        assert_eq!(
            envelope
                .history
                .as_ref()
                .unwrap()
                .history
                .snapshots
                .last()
                .unwrap()
                .statement
                .id()
                .unwrap(),
            b4
        );
        assert_eq!(
            envelope
                .history
                .as_ref()
                .unwrap()
                .history
                .origin
                .snapshots
                .last()
                .unwrap()
                .statement
                .id()
                .unwrap(),
            a80
        );
        assert_eq!(
            envelope.evidence.snapshots.last().unwrap().statement.height,
            4
        );
        assert!(matches!(&envelope.body, Body::Submission(c) if c==&signed.commands));
        assert_eq!(node.storage_head().unwrap(), native_head);
        assert_eq!(node.chain.ledger, ledger);
        let before = inventory(&self.root);
        assert_eq!(node.bft_submit(signed.commands.clone()).unwrap(), queue);
        assert_eq!(
            inventory(&self.root),
            before,
            "exact queue retry changed custody or bytes"
        );
        assert_eq!(node.chain.ledger, ledger);
        self.pins = Some(Pins {
            initial_head: self.initial_head,
            head: signed.wallet_head,
            caller: state,
            prepared,
            commands: signed.commands,
            input,
            output,
            intent: signed.intent_id,
            queue,
            submitted_at,
            queue_returned_at,
            recipient_observations: vec![],
        });
    }
    pub(super) fn complete(mut self, nodes: &[Store], a80: Hash, b4: Hash, export: Hash) -> Pins {
        let mut pins = self.pins.take().unwrap();
        for (actor, node) in nodes.iter().enumerate() {
            verify_spend(node, &pins, a80, b4, export);
            let checked_at = now();
            pins.recipient_observations
                .push(json!({"actor":actor,"height":5,
                "checked_at":checked_at,"latency_upper_bound_seconds":checked_at-pins.submitted_at,
                "finality":node.chain.finalized.unwrap(),"output":pins.output,
                "recipient":public(13),"amount":"88","eligible":true,"quarantined":false}));
        }
        new_json(&self.root.join("owner-completion.json"), &pins.report());
        pins
    }
}
pub(super) fn verify_spend(node: &Store, pins: &Pins, a80: Hash, b4: Hash, export: Hash) {
    assert_eq!(node.chain.height(), 5);
    assert_eq!(
        node.evidence
            .snapshot(node.chain.finalized.unwrap())
            .unwrap()
            .blocks
            .last()
            .unwrap()
            .commands,
        pins.commands
    );
    assert!(!node.chain.ledger.coins.contains_key(&pins.input));
    let coin = &node.chain.ledger.coins[&pins.output];
    assert_eq!(
        coin.payment,
        Payment {
            owner: public(13),
            amount: Amount(88)
        }
    );
    assert_eq!(coin.created, 5);
    assert_eq!(coin.mature, 5);
    assert_eq!(coin.dependencies, BTreeSet::from([a80, b4]));
    let fee = &node.chain.ledger.coins[&id("output", &(pins.intent, 16u32)).unwrap()];
    assert_eq!(
        fee.payment,
        Payment {
            owner: public(12),
            amount: Amount(1)
        }
    );
    assert_eq!(fee.created, 5);
    assert_eq!(fee.mature, 7);
    assert_eq!(fee.dependencies, BTreeSet::from([a80, b4]));
    let import_fee = &node.chain.ledger.coins[&id("output", &(export, 16u32)).unwrap()];
    assert_eq!(
        import_fee.payment,
        Payment {
            owner: public(12),
            amount: Amount(1)
        }
    );
    assert_eq!((import_fee.created, import_fee.mature), (2, 4));
    assert_eq!(import_fee.dependencies, BTreeSet::from([a80, b4]));
    assert_eq!(node.chain.ledger.coins.len(), 3);
    assert!(
        coin.channel_dependencies.is_empty()
            && fee.channel_dependencies.is_empty()
            && import_fee.channel_dependencies.is_empty()
    );
    assert_eq!(node.chain.ledger.imports, BTreeMap::from([(export, b4)]));
    assert!(node.chain.ledger.exports.is_empty());
    assert_eq!(node.chain.ledger.minted, Amount::ZERO);
    assert_eq!(node.chain.ledger.received, Amount(90));
    assert_eq!(
        node.chain
            .ledger
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
    node.chain.ledger.audit().unwrap();
    let value = receipt(node, b4, export);
    assert_eq!(value.state, "ORIGINAL_OUTPUT_SPENT");
    assert_eq!(value.original_output_remaining, Amount::ZERO);
    let view = wallet::view(node, &public(13)).unwrap();
    let recipient = view.coins.iter().find(|c| c.id == pins.output).unwrap();
    assert_eq!(recipient.amount, Amount(88));
    assert!(
        recipient.spendable_now && recipient.eligible_for_onward_export && !recipient.quarantined
    );
    assert_eq!(view.pin.height, 5);
}
pub(super) fn cold_owner(root: &Path, node: &Store, pins: &Pins) {
    let caller = client(root, node);
    assert_eq!(caller.read().unwrap(), pins.caller);
    assert_eq!(caller.open(node, Some(pins.head)).unwrap(), pins.caller);
    assert!(pins.caller.pending.is_none());
    drop(caller);
    let agent = wallet_agent::Agent::open(&root.join("owner-wallet"), node).unwrap();
    assert_eq!(agent.journal.creation.pin.height, 0);
    assert_eq!(agent.journal.head().unwrap(), pins.head);
    assert_ne!(pins.head, pins.initial_head);
    assert_eq!(agent.journal.records.len(), 1);
    let record = &agent.journal.records[0];
    assert_eq!(record.previous_head, pins.initial_head);
    assert_eq!(record.observation.pin.height, 4);
    assert_eq!(record.draft, pins.prepared.draft);
    assert_eq!(record.review_commitment, pins.prepared.review_commitment);
    assert_eq!(record.command, pins.commands[0]);
    let recovered = agent.recover_prepared(node, &pins.prepared).unwrap();
    assert!(recovered.recovered_exact_retry && recovered.retained_approvals_complete);
    assert_eq!(recovered.commands, pins.commands);
    assert_eq!(recovered.wallet_head, pins.head);
    assert_eq!(
        agent.view(node, pins.head).unwrap().reserved_owned_outputs,
        Amount::ZERO
    );
}
#[test]
#[ignore = "one fresh original-owner C0 through C5 Runtime payment and complete cold component, original 120 seconds"]
fn original_onward_owner_matures_import_spends_and_cold_replays() {
    super::run(Mode::OwnerSpend);
}
