//! One ordinary CLI/TLS two-payment sample, not latency qualification.
//! Nested under onward_runtime_tests; no test-controlled frames, votes, or C blocks.
use super::*;
use crate::contact_runtime::{tls_identity, Node};
use crate::{wallet, wallet_agent};
use std::net::TcpListener;

#[path = "onward_service_carriage_tests.rs"]
mod carriage_boundary;
#[path = "onward_service_payment_checks.rs"]
mod checks;
#[path = "onward_service_payment_process.rs"]
mod processes;

const TEST: &str = "storage::paged::onward_runtime_tests::service_payment::ordinary_onward_service_two_original_owner_payments_and_cold_replay";
const CHILD: &str = "RLD_ONWARD_SERVICE_PAYMENT_COLD_CHILD";
const CLI_ENV: &str = "RLD_ONWARD_SERVICE_CLI";
const CLI_SHA_ENV: &str = "RLD_ONWARD_SERVICE_CLI_SHA256";
const STOP_HEIGHT: u64 = 12;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Setup {
    parent_pid: u32,
    started: f64,
    deadline: f64,
    currency: Hash,
    proof: CompleteOnwardNetworkHistory,
    a80: Hash,
    b4: Hash,
    export: Hash,
    b_head: Hash,
    b_ledger: Ledger,
    seeds: Vec<u8>,
    transports: Vec<Value>,
    tls: Vec<Value>,
    initial_bft_heads: Vec<Hash>,
    initial_owner_heads: Vec<Hash>,
    original_files: BTreeMap<PathBuf, Hash>,
    cli: PathBuf,
    cli_sha256: Hash,
    test_binary: PathBuf,
    test_binary_sha256: Hash,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PaymentPins {
    number: usize,
    actor: usize,
    owner: u8,
    recipient: u8,
    amount: Amount,
    input: Hash,
    output: Hash,
    intent: Hash,
    prepared: wallet_agent::Prepared,
    commands: Vec<Command>,
    initial_head: Hash,
    head: Hash,
    caller: files::State,
    queue: Hash,
    submitted_at: f64,
    queue_returned_at: f64,
    signature_returned_at: f64,
    caller_published_at: f64,
    retry: Value,
    native_lease: Option<Value>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeObservation {
    actor: usize,
    checked_at: f64,
    head: Hash,
    height: u64,
    finality: Hash,
    prefix: Vec<Snapshot>,
    ledger: Ledger,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodePins {
    observed: NativeObservation,
    caller: bft_client::State,
    signer_records: usize,
    original_messages: Hash,
    archive_hash: Hash,
    archive_bytes: usize,
    cold_config: PathBuf,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ColdPins {
    format: String,
    mode: String,
    setup: Setup,
    payments: Vec<PaymentPins>,
    s2: Hash,
    s2_ledger: Ledger,
    before_stop: Vec<NativeObservation>,
    nodes: Vec<NodePins>,
    recipient_observations: Vec<Value>,
    normal_stops: Vec<Value>,
}
struct OwnerSubmission {
    number: usize,
    actor: usize,
    owner: u8,
    recipient: u8,
    input: Hash,
    amount: Amount,
    open_dispatched_at: f64,
    open_returned_at: f64,
}
struct Completion {
    before_stop: Vec<NativeObservation>,
    recipient_observations: Vec<Value>,
    normal_stops: Vec<Value>,
}
fn within(deadline: f64) {
    assert!(
        now() < deadline,
        "original 120-second ordinary Onward Service payment scope exhausted"
    );
}
fn ledger_path(root: &Path, actor: usize) -> PathBuf {
    root.join(format!("payment-ledger-{actor}"))
}
fn owner_root(root: &Path, owner: u8) -> PathBuf {
    root.join(format!("owner-{owner}"))
}
fn owner_client(root: &Path, owner: u8, node: &Store) -> files::Client {
    let home = owner_root(root, owner);
    files::Client::lock(
        &home.join("caller"),
        &home.join("wallet"),
        public(owner),
        node,
    )
    .unwrap()
}
fn create_owner(root: &Path, owner: u8, node: &Store) -> Hash {
    assert_eq!(node.chain.height(), 0);
    let home = dir(&owner_root(root, owner));
    let agent = wallet_agent::Agent::create(&home.join("wallet"), node, public(owner)).unwrap();
    assert_eq!(agent.journal.creation.pin.height, 0);
    assert!(agent.journal.records.is_empty());
    let head = agent.journal.head().unwrap();
    drop(agent);
    dir(&home.join("caller"));
    let state = owner_client(root, owner, node)
        .open(node, Some(head))
        .unwrap();
    assert_eq!(state.head, Some(head));
    assert!(state.pending.is_none());
    new_json(
        &home.join("key.json"),
        &json!({"secret_key":hex::encode([owner;32])}),
    );
    head
}
fn ready_coin(node: &Store, owner: u8, input: Hash, expected: Amount) -> bool {
    let view = wallet::view(node, &public(owner)).unwrap();
    if let Some(coin) = view.coins.iter().find(|coin| coin.id == input) {
        assert_eq!(coin.amount, expected);
        assert!(!coin.quarantined, "selected payment input quarantined");
        coin.spendable_now && coin.eligible_for_onward_export
    } else {
        false
    }
}
fn submit_owner(root: &Path, setup: &Setup, node: &Store, request: OwnerSubmission) -> PaymentPins {
    let OwnerSubmission {
        number,
        actor,
        owner,
        recipient,
        input,
        amount,
        open_dispatched_at,
        open_returned_at,
    } = request;
    within(setup.deadline);
    // The caller owns this one original Native OS lease throughout review/sign/queue/retry.
    // No wait, Service stop, frame movement, or second Native open occurs under it.
    node.require_onward_network_state().unwrap();
    assert!(ready_coin(node, owner, input, Amount(amount.0 + 1)));
    let home = owner_root(root, owner);
    let initial_head = setup.initial_owner_heads[number - 1];
    let native_head = node.storage_head().unwrap();
    let ledger = node.chain.ledger.clone();
    new_json(
        &home.join("request-start.json"),
        &json!({"number":number,"actor":actor,
        "review_started_at":now(),"original_submission_at":null,"input":input,"amount":amount,
        "owner":public(owner),"recipient":public(recipient),"native_head":native_head,
        "native_open_dispatched_at":open_dispatched_at,"native_open_returned_at":open_returned_at,
        "native_lock_acquired_at":"unknown inside Store::open_inspection",
        "native_lease_release_observed_at":null}),
    );
    let agent = wallet_agent::Agent::open(&home.join("wallet"), node).unwrap();
    assert_eq!(agent.journal.creation.pin.height, 0);
    assert_eq!(agent.journal.head().unwrap(), initial_head);
    assert!(agent.journal.records.is_empty());
    let prepared = agent
        .prepare(
            node,
            wallet::Request {
                owner: public(owner),
                participants: vec![],
                inputs: Some(vec![input]),
                outputs: vec![Payment {
                    owner: public(recipient),
                    amount,
                }],
                remote: None,
                fee: Amount(1),
                valid_for_blocks: 8,
                valid_through: None,
            },
            initial_head,
        )
        .unwrap();
    assert_eq!(prepared.draft.pin.height, node.chain.height());
    assert_eq!(prepared.draft.selected_input_total, Amount(amount.0 + 1));
    assert_eq!(prepared.draft.change, Amount::ZERO);
    drop(agent);
    let caller = owner_client(root, owner, node);
    let previous = caller.read().unwrap();
    assert_eq!(previous.head, Some(initial_head));
    assert!(previous.pending.is_none());
    let mut proposed = previous.clone();
    proposed.pending = Some(files::Pending {
        prepared: prepared.clone(),
    });
    let pending = caller
        .store(node, files::Transition { previous, proposed })
        .unwrap();
    assert_eq!(pending.pending.as_ref().unwrap().prepared, prepared);
    drop(caller);
    within(setup.deadline);
    let mut agent = wallet_agent::Agent::open(&home.join("wallet"), node).unwrap();
    let sign_result = agent.sign(
        node,
        prepared.draft.clone(),
        &home.join("key.json"),
        prepared.review_commitment,
        initial_head,
    );
    let signature_returned_at = now();
    new_json(
        &home.join("sign-response.json"),
        &json!({"returned_at":signature_returned_at,"result":sign_result}),
    );
    let signed = sign_result.unwrap();
    assert!(!signed.recovered_exact_retry && signed.retained_approvals_complete);
    assert_eq!(signed.required_owners, vec![public(owner)]);
    assert_eq!(signed.previous_wallet_head, initial_head);
    assert_eq!(signed.intent_id, prepared.draft.intent_id);
    assert_eq!(agent.journal.records.len(), 1);
    assert_eq!(
        agent
            .view(node, signed.wallet_head)
            .unwrap()
            .reserved_owned_outputs,
        Amount(amount.0 + 1)
    );
    assert_eq!(signed.commands.len(), 1);
    assert!(
        matches!(&signed.commands[0], Command::Spend(s) if s.intent == prepared.draft.intent
        && s.approvals.len() == 1 && s.approvals[0].key == public(owner))
    );
    drop(agent);
    // Preserve the real response before publication or queue errors can occur.
    new_json(&home.join("signed-response.json"), &signed);
    let caller = owner_client(root, owner, node);
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
    assert_eq!(state.head, Some(signed.wallet_head));
    assert!(state.pending.is_none());
    drop(caller);
    let caller_published_at = now();
    assert_eq!(node.storage_head().unwrap(), native_head);
    assert_eq!(node.chain.ledger, ledger);
    within(setup.deadline);
    let submitted_at = now();
    let output = id("output", &(signed.intent_id, 0u32)).unwrap();
    new_json(
        &home.join("submission.json"),
        &json!({"number":number,"submitted_at":submitted_at,
        "status":"pending","actor":actor,"owner":public(owner),"recipient":public(recipient),
        "input":input,"output":output,"intent":signed.intent_id,"commands":signed.commands,
        "review_commitment":prepared.review_commitment,
        "commands_sha256":sha(&files::canonical_with_limit(&signed.commands,crate::MAX_BYTES).unwrap()),
        "initial_owner_head":initial_head,"owner_head":signed.wallet_head,
        "signature_returned_at":signature_returned_at,"caller_published_at":caller_published_at}),
    );
    let result = node.bft_submit(signed.commands.clone());
    let queue_returned_at = now();
    new_json(
        &home.join("queue-response.json"),
        &json!({"submitted_at":submitted_at,
        "returned_at":queue_returned_at,"result":result}),
    );
    let queue = result.unwrap();
    let queue_dir = node.dir.join("bft-submissions");
    let raw = fs::read(queue_dir.join(format!("{}.json", queue.to_hex()))).unwrap();
    let wire: net::WireEnvelope = bft_client::decode(&raw).unwrap();
    let envelope = wire.expand().unwrap();
    assert_eq!(envelope.verify(node).unwrap(), queue);
    assert_eq!(envelope.history, Some(setup.proof.clone()));
    assert!(matches!(&envelope.body, Body::Submission(c) if c == &signed.commands));
    assert_eq!(
        envelope
            .evidence
            .snapshots
            .last()
            .unwrap()
            .statement
            .id()
            .unwrap(),
        node.chain.finalized.unwrap()
    );
    let queue_before = inventory(&queue_dir);
    let owner_before = inventory(&home);
    let retry_started_at = now();
    let retry_result = node.bft_submit(signed.commands.clone());
    let retry_returned_at = now();
    let queue_unchanged = inventory(&queue_dir) == queue_before;
    let owner_unchanged = inventory(&home) == owner_before;
    let retry = json!({"original_submitted_at":submitted_at,"started_at":retry_started_at,
        "returned_at":retry_returned_at,"result":retry_result,"queue_unchanged":queue_unchanged,
        "owner_unchanged":owner_unchanged,"metadata_written_after_inventory_comparison":true});
    // Outside the compared owner/queue directories, after both before/after reads.
    new_json(&root.join(format!("payment-{number}-retry.json")), &retry);
    assert_eq!(retry_result.unwrap(), queue);
    assert!(queue_unchanged && owner_unchanged);
    assert_eq!(node.storage_head().unwrap(), native_head);
    assert_eq!(node.chain.ledger, ledger);
    within(setup.deadline);
    PaymentPins {
        number,
        actor,
        owner,
        recipient,
        amount,
        input,
        output,
        intent: signed.intent_id,
        prepared,
        commands: signed.commands,
        initial_head,
        head: signed.wallet_head,
        caller: state,
        queue,
        submitted_at,
        queue_returned_at,
        signature_returned_at,
        caller_published_at,
        retry,
        native_lease: None,
    }
}

// Public metadata only; every unsuccessful lock observation remains unknown.
struct Progress {
    file: fs::File,
    rows: usize,
    bytes: usize,
}
impl Progress {
    fn new(root: &Path) -> Self {
        let path = root.join("payment-progress.jsonl");
        crate::keystore::private_create(&path, b"").unwrap();
        Self {
            file: fs::OpenOptions::new().append(true).open(path).unwrap(),
            rows: 0,
            bytes: 0,
        }
    }
    fn row(&mut self, value: Value) {
        use std::io::Write;
        let mut raw = serde_json::to_vec(&value).unwrap();
        raw.push(b'\n');
        assert!(self.rows < 4096 && self.bytes + raw.len() <= 8 * 1024 * 1024);
        self.file.write_all(&raw).unwrap();
        self.file.flush().unwrap();
        self.rows += 1;
        self.bytes += raw.len();
    }
}
struct FailureReport {
    root: PathBuf,
    started: f64,
    deadline: f64,
    completed: bool,
}
impl Drop for FailureReport {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        // Best-effort retained diagnostic only; no Native/caller recovery or inferred success.
        let observed = crate::bft_tick_schedule::monotonic().ok();
        let owners=[12,13].into_iter().enumerate().map(|(index,owner)| {
            let home=owner_root(&self.root,owner);
            let read=|name:&str|fs::read(home.join(name)).ok().and_then(|b|serde_json::from_slice::<Value>(&b).ok());
            let submission=read("submission.json");
            let original=submission.as_ref().and_then(|v|v["submitted_at"].as_f64());
            let recipient=fs::read(self.root.join(format!("payment-{}-recipient.json",index+1))).ok()
                .and_then(|b|serde_json::from_slice::<Value>(&b).ok());
            let verified=recipient.as_ref().and_then(|v|v["checked_at"].as_f64());
            json!({"owner":public(owner),"request_started":read("request-start.json"),
                "submission":submission,"queue_response":read("queue-response.json"),
                "original_submitted_at":original,"observed_submission_age_seconds":original.zip(observed).map(|(s,a)|a-s),
                "unconfirmed_age_seconds":if verified.is_none() {original.zip(observed).map(|(s,a)|a-s)} else {None},
                "fixed_recipient_verification":recipient,
                "native_inclusion":if verified.is_some() {"verified at the retained fixed-recipient observation"} else {"unknown; no retained fixed-recipient verification"}})
        }).collect::<Vec<_>>();
        let value = json!({"passed":false,"started":self.started,"deadline":self.deadline,
            "observed_at":observed,"before_remaining_service_cleanup_diagnostic_only":true,
            "services_may_still_be_running":true,"owners":owners});
        if let Ok(raw) = serde_json::to_vec(&value) {
            let _ = crate::keystore::private_create(&self.root.join("payment-failure.json"), &raw);
        }
        eprintln!("onward_service_payment_failure={value}");
    }
}
fn immutable_files(root: &Path) -> BTreeMap<PathBuf, Hash> {
    let mut paths = Vec::new();
    for i in 0..4 {
        paths.push(root.join(format!("key-{i}.json")));
        paths.push(root.join(format!("payment-runtime-{i}.json")));
    }
    for i in 0..5 {
        paths.push(root.join(format!("payment-transport-{i}.json")));
    }
    for owner in [12, 13] {
        paths.push(owner_root(root, owner).join("key.json"));
    }
    paths
        .into_iter()
        .map(|p| {
            let h = sha(&fs::read(&p).unwrap());
            (p, h)
        })
        .collect()
}
fn setup(started: f64, deadline: f64) -> (PathBuf, Setup, Vec<TcpListener>, Vec<String>) {
    let cli = PathBuf::from(
        std::env::var_os(CLI_ENV).expect("source-bound ordinary Service CLI required"),
    );
    assert!(cli.is_absolute());
    let cli_sha256 =
        Hash::from_hex(&std::env::var(CLI_SHA_ENV).expect("source-bound CLI SHA256 required"))
            .unwrap();
    assert_eq!(sha(&fs::read(&cli).unwrap()), cli_sha256);
    let test_binary = std::env::current_exe().unwrap();
    let test_binary_sha256 = sha(&fs::read(&test_binary).unwrap());
    let (root, bootstrap, proof, a80, b4, export) = ancestors();
    within(deadline);
    let currency = bootstrap.currency.id().unwrap();
    let b = Store::open_inspection(&root.join("intermediate"), &public(1), currency).unwrap();
    let b_head = b.storage_head().unwrap();
    let b_ledger = b.chain.ledger.clone();
    drop(b);
    let mut seeds = (2u8..6).collect::<Vec<_>>();
    seeds.sort_by_key(|seed| public(*seed));
    let mut transports = vec![];
    let mut ids = vec![];
    for i in 0..5 {
        let state = root.join(format!("payment-transport-state-{i}"));
        let region = if i == 0 {
            proof.history.source
        } else {
            proof.history.destination
        };
        let identity = initialize(
            &state,
            &currency.to_hex(),
            &region.to_hex(),
            "public-no-value-onward-service-payments",
        )
        .unwrap();
        ids.push(identity["node_id"].as_str().unwrap().to_owned());
        transports.push(json!({"format":MESH,"network":currency,"state":state,"contacts":[]}));
    }
    let tls = transports
        .iter()
        .map(|c| tls_identity(c).unwrap())
        .collect::<Vec<_>>();
    let sockets = (0..5)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect::<Vec<_>>();
    let endpoints = sockets
        .iter()
        .map(|s| s.local_addr().unwrap())
        .collect::<Vec<_>>();
    let addresses = endpoints.iter().map(ToString::to_string).collect();
    for (i, transport) in transports.iter_mut().enumerate() {
        transport["contacts"] = json!((0..5)
            .filter(|j| *j != i)
            .map(|j| json!({"peer":ids[j],
            "host":"127.0.0.1","port":endpoints[j].port(),"tls_cert_sha256":tls[j]["fingerprint"]}))
            .collect::<Vec<_>>());
        new_json(&root.join(format!("payment-transport-{i}.json")), transport);
        drop(Node::open(transport).unwrap());
    }
    let mut initial_bft_heads = vec![];
    let mut initial_owner_heads = vec![];
    for i in 0..4 {
        within(deadline);
        let node = Store::create(
            &ledger_path(&root, i),
            bootstrap.clone(),
            proof.history.destination,
            &public(1),
            currency,
        )
        .unwrap();
        let agent =
            Agent::create(&root.join(format!("signer-{i}")), &node, public(seeds[i])).unwrap();
        assert_eq!(agent.journal.creation.pin.height, 0);
        assert_eq!(agent.record_count(), 0);
        let state = bft_client::State {
            format: bft_client::ONWARD_FORMAT.into(),
            binding: agent.journal.binding.clone(),
            head: agent.head().unwrap(),
            pending: None,
            outbox: None,
        };
        initial_bft_heads.push(state.head);
        drop(agent);
        new_json(
            &dir(&root.join(format!("caller-{i}"))).join("head.json"),
            &state,
        );
        new_json(
            &root.join(format!("key-{i}.json")),
            &json!({"secret_key":hex::encode([seeds[i];32])}),
        );
        dir(&root.join(format!("runtime-{i}")));
        new_json(
            &root.join(format!("payment-runtime-{i}.json")),
            &config(
                &root,
                i,
                &seeds,
                &ids[1..],
                STOP_HEIGHT,
                node.storage_head().unwrap(),
            ),
        );
        if i == 0 {
            initial_owner_heads.push(create_owner(&root, 12, &node));
        }
        if i == 2 {
            initial_owner_heads.push(create_owner(&root, 13, &node));
        }
        drop(node);
    }
    let setup = Setup {
        parent_pid: std::process::id(),
        started,
        deadline,
        currency,
        proof,
        a80,
        b4,
        export,
        b_head,
        b_ledger,
        seeds,
        transports,
        tls,
        initial_bft_heads,
        initial_owner_heads,
        original_files: immutable_files(&root),
        cli,
        cli_sha256,
        test_binary,
        test_binary_sha256,
    };
    new_json(&root.join("payment-setup.json"), &setup);
    new_json(
        &root.join("payment-topology.json"),
        &json!({"transport_node_ids":ids,"addresses":addresses,
        "ordinary_full_configured_neighbors":true,"stop_height_upper_bound":STOP_HEIGHT,
        "required_equal_terminal_heights":false,"started":started,"deadline":deadline}),
    );
    within(deadline);
    (root, setup, sockets, addresses)
}

fn run_parent() {
    let started = now();
    let deadline = started + 120.0;
    let (root, setup, sockets, addresses) = setup(started, deadline);
    // Reverse drop order retains the failure before potentially slow process
    // cleanup, including a panic partway through launch or readiness.
    let mut services = processes::Services::new(started + 125.0);
    let mut failure = FailureReport {
        root: root.clone(),
        started,
        deadline,
        completed: false,
    };
    eprintln!(
        "onward_service_payment_scope={}",
        json!({"root":root,"started":started,"deadline":deadline,"passed":false})
    );
    let mut progress = Progress::new(&root);
    drop(sockets);
    services.launch(&root, &setup, &addresses);
    let mut payments = Vec::<PaymentPins>::new();
    let mut recipient_observations = vec![];
    let mut s2 = None;
    let mut last_heads = [Hash::ZERO; 4];
    let mut unknown = [0u64; 4];
    let before_stop = loop {
        within(deadline);
        services.running();
        let mut covered = vec![];
        for actor in 0..4 {
            within(deadline);
            services.running();
            let open_dispatched_at = now();
            let node = match Store::open_inspection(
                &ledger_path(&root, actor),
                &public(1),
                setup.currency,
            ) {
                Ok(node) => node,
                Err(e) if e == std::fs::TryLockError::WouldBlock.to_string() => {
                    unknown[actor] += 1;
                    continue;
                }
                Err(e) => panic!("ordinary Native observation refused for actor {actor}: {e}"),
            };
            let open_returned_at = now();
            let requests_before = payments.len();
            node.require_onward_network_state().unwrap();
            assert!(node.chain.height() <= STOP_HEIGHT);
            let current_head = node.storage_head().unwrap();
            if last_heads[actor] != current_head {
                progress.row(json!({"kind":"native-observation","actor":actor,"at":now(),
                    "height":node.chain.height(),"head":current_head,"finality":node.chain.finalized,
                    "unknown_lock_observations":unknown[actor]}));
                last_heads[actor] = current_head;
            }
            if actor == 0
                && payments.is_empty()
                && node.chain.ledger.imports.contains_key(&setup.export)
            {
                let receipt = checks::import_receipt(&node, &setup);
                if receipt.maturity_reached && receipt.original_output_spendable_now {
                    let p = submit_owner(
                        &root,
                        &setup,
                        &node,
                        OwnerSubmission {
                            number: 1,
                            actor: 0,
                            owner: 12,
                            recipient: 13,
                            input: id("output", &(setup.export, 0u32)).unwrap(),
                            amount: Amount(88),
                            open_dispatched_at,
                            open_returned_at,
                        },
                    );
                    progress.row(json!({"kind":"owner-submitted","number":1,"at":p.submitted_at,"intent":p.intent,
                        "queue_returned_at":p.queue_returned_at,"original_clock":true}));
                    payments.push(p);
                }
            }
            if actor == 2 && payments.len() == 1 {
                if let Some(checkpoint) = checks::payment_checkpoint(&node, &payments[0]) {
                    checks::first_recipient(&node, &setup, &payments[0], checkpoint);
                    let checked_at = now();
                    recipient_observations.push(json!({"number":1,"actor":2,"checked_at":checked_at,
                        "submitted_at":payments[0].submitted_at,"latency_upper_bound_seconds":checked_at-payments[0].submitted_at,
                        "checkpoint":checkpoint,"intent":payments[0].intent,"output":payments[0].output,
                        "amount":"88","native_finality":true,"mature":true,"eligible":true,"quarantined":false}));
                    new_json(
                        &root.join("payment-1-recipient.json"),
                        recipient_observations.last().unwrap(),
                    );
                    let input = payments[0].output;
                    let p = submit_owner(
                        &root,
                        &setup,
                        &node,
                        OwnerSubmission {
                            number: 2,
                            actor: 2,
                            owner: 13,
                            recipient: 14,
                            input,
                            amount: Amount(87),
                            open_dispatched_at,
                            open_returned_at,
                        },
                    );
                    progress.row(json!({"kind":"owner-submitted","number":2,"at":p.submitted_at,"intent":p.intent,
                        "queue_returned_at":p.queue_returned_at,"original_clock":true}));
                    payments.push(p);
                }
            }
            if actor == 3 && payments.len() == 2 && s2.is_none() {
                if let Some(checkpoint) = checks::payment_checkpoint(&node, &payments[1]) {
                    checks::completed(&node, &setup, &payments, checkpoint);
                    let checked_at = now();
                    recipient_observations.push(json!({"number":2,"actor":3,"checked_at":checked_at,
                        "submitted_at":payments[1].submitted_at,"latency_upper_bound_seconds":checked_at-payments[1].submitted_at,
                        "checkpoint":checkpoint,"intent":payments[1].intent,"output":payments[1].output,
                        "amount":"87","native_finality":true,"mature":true,"eligible":true,"quarantined":false}));
                    new_json(
                        &root.join("payment-2-recipient.json"),
                        recipient_observations.last().unwrap(),
                    );
                    s2 = Some(checkpoint);
                }
            }
            if let Some(checkpoint) = s2 {
                if node.evidence.snapshot(checkpoint).is_ok()
                    && node
                        .chain
                        .finalized
                        .is_some_and(|f| node.evidence.descends_from(f, checkpoint).unwrap())
                {
                    checks::completed(&node, &setup, &payments, checkpoint);
                    covered.push(checks::observe(&node, actor));
                }
            }
            drop(node);
            if payments.len() > requests_before {
                let released_at = now();
                let payment = payments.last_mut().unwrap();
                let lease = json!({"actor":actor,"native_open_dispatched_at":open_dispatched_at,
                    "native_open_returned_at":open_returned_at,"release_observed_after_drop_at":released_at,
                    "observed_held_interval_seconds":released_at-open_returned_at,
                    "native_open_including_lock_and_replay_seconds":open_returned_at-open_dispatched_at,
                    "internal_lock_acquired_at":null,"clock_semantics":"open-return acquisition upper bound; release clock immediately after actual Store drop"});
                new_json(
                    &root.join(format!("payment-{}-native-lease.json", payment.number)),
                    &lease,
                );
                payment.native_lease = Some(lease);
            }
        }
        if covered.len() == 4 {
            checks::compatible(&covered);
            break covered;
        }
        progress.row(json!({"kind":"waiting","at":now(),"owner_requests":payments.len(),
            "s2":s2,"all_four_covered_this_round":covered.len(),"unknown_lock_observations":unknown,
            "submission_ages_seconds":payments.iter().map(|p|now()-p.submitted_at).collect::<Vec<_>>(),
            "fixed_recipient_verifications":recipient_observations }));
        std::thread::sleep(Duration::from_millis(50));
    };
    within(deadline);
    let normal_stops = services.stop(&root, deadline);
    drop(services);
    let s2 = s2.unwrap();
    assert_eq!(payments.len(), 2);
    assert_eq!(recipient_observations.len(), 2);
    let pins = checks::capture(
        &root,
        setup,
        payments,
        s2,
        Completion {
            before_stop,
            recipient_observations,
            normal_stops,
        },
    );
    new_json(&root.join("payment-cold-pins.json"), &pins);
    progress.row(json!({"kind":"normal-stopped-cold-start","at":now(),"s2":s2}));
    drop(progress); // Parent writes nothing under the root during the child's inventory comparison.
    processes::cold_join(&root, &pins.setup);
    within(deadline);
    let ended = now();
    let report = json!({"root":root,"passed":true,"started":started,"deadline":deadline,"ended":ended,
        "elapsed_seconds":ended-started,"parent_pid":std::process::id(),"cli_sha256":pins.setup.cli_sha256,
        "test_binary_sha256":pins.setup.test_binary_sha256,"mode":"two-original-owner-payments",
        "stop_height_upper_bound":STOP_HEIGHT,"required_equal_terminal_heights":false,
        "payments":pins.payments,"recipient_observations":pins.recipient_observations,
        "s2":s2,"s2_ledger_root":pins.s2_ledger.root().unwrap(),"before_stop":pins.before_stop.iter().map(checks::brief).collect::<Vec<_>>(),
        "s2_checkpoint":pins.nodes[3].observed.prefix.iter().find(|s|s.statement.id().unwrap()==s2).unwrap(),
        "terminal":pins.nodes.iter().map(|n|checks::brief(&n.observed)).collect::<Vec<_>>(),
        "normal_stops":pins.normal_stops,"unknown_lock_observations":unknown,
        "all_four_live_second_payment":true,"compatible_empty_tails":true,
        "four_native_runtime_cold":true,"both_original_owners_cold":true,
        "original_agent_prepare_commit_custody":true,"complete_causal_accounting":true,
        "normal_child_join":true,"child_complete":true,"full_cold_inventory_unchanged":true,
        "controller_value_delivery":false,"normal_latency_cohort_qualified":false,"independent_qualification":false});
    new_json(&root.join("payment-result.json"), &report);
    within(deadline);
    failure.completed = true;
    eprintln!("onward_service_payment_result={report}");
}

#[test]
#[ignore = "one fresh ordinary five-Service pinned-TLS two-payment scope; original120 including full cold child"]
fn ordinary_onward_service_two_original_owner_payments_and_cold_replay() {
    if let Some(root) = std::env::var_os(CHILD) {
        checks::cold(&PathBuf::from(root));
    } else {
        run_parent();
    }
}
