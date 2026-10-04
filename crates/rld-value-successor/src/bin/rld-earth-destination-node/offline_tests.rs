//! Actual destination HTTP handlers, durable stores and signed fixture funds.
//! No adopted network, production keys or external services are used.
use super::*;
use rld_core::{generate_identity, sign_bytes, Amount, Identity};
use rld_cross_region::value::{ExportCommand, ExportIntent};
use rld_pow::{transition::Approval, OutPoint, Output, Transfer, BLOCK_SECONDS};
use rld_value_successor::chain::{
    finality::FinalityStatement, Command as SourceCommand, ObservationPolicy,
};
use rld_value_successor::destination::pow::SourceFinalityTrust;
use sha2::{Digest, Sha256};

struct Fixture {
    root: PathBuf,
    v1: rld_pow::Chain,
    context: DestinationContext,
    certificate: rld_value_successor::chain::finality::FinalityCertificate,
    bundle: ProofBundle,
    recipient: Identity,
    miner: Identity,
    source: Option<CandidateStore>,
}
impl Fixture {
    fn new() -> Self {
        let time = now().unwrap();
        let owner = generate_identity();
        let recipient = generate_identity();
        let miner = generate_identity();
        let root = std::env::temp_dir().join(format!("rld-offline-{}", owner.public_key));
        let mut v1 = rld_pow::Chain::new(rld_pow::Context {
            network_domain: "fixture-only:disconnected-destination".into(),
            zone_id: "fixture-source".into(),
            currency_genesis: Hash([1; 32]),
            manifest_pin: Hash([2; 32]),
            transition_id: Hash([3; 32]),
            legacy_height: 0,
            legacy_state_root: Hash([4; 32]),
            started_at: time - 100_000,
            initial_target: rld_pow::target_limit(),
        })
        .unwrap();
        for sequence in 1..=100 {
            let timestamp = time - 100_000 + sequence * BLOCK_SECONDS;
            let mut block = v1
                .template(owner.public_key.clone(), timestamp, vec![])
                .unwrap();
            while !rld_pow::mine_batch(&mut block, 100_000).unwrap() {}
            v1.accept(block, time).unwrap();
        }
        let adoption = Hash([44; 32]);
        let mut keys = (0..4).map(|_| generate_identity()).collect::<Vec<_>>();
        keys.sort_by(|a, b| a.public_key.cmp(&b.public_key));
        let validators = keys
            .iter()
            .map(|k| k.public_key.clone())
            .collect::<Vec<_>>();
        let mut source = CandidateStore::open_finalized(
            &root.join("source"),
            &v1,
            time,
            adoption,
            validators.clone(),
        )
        .unwrap();
        let (input, coin) = v1
            .state()
            .coins
            .iter()
            .find(|(_, c)| c.spendable_height <= 101)
            .unwrap();
        let input = input.clone();
        let intent = ExportIntent {
            source_chain_id: source.chain().chain_id(),
            destination_chain_id: Hash([91; 32]),
            input: input.clone(),
            owner: owner.public_key.clone(),
            recipient: recipient.public_key.clone(),
            amount: Amount(1000),
            source_fee: Amount(1),
            destination_fee: Amount(10),
            change: coin.output.amount.checked_sub(Amount(1001)).unwrap(),
            valid_through_height: 110,
        };
        let export_id = intent.id().unwrap();
        let export = SourceCommand::Export(ExportCommand {
            owner_signature: sign_bytes(&owner.secret_key, &intent.signing_bytes().unwrap())
                .unwrap(),
            intent,
        });
        let mut checkpoint = Hash::ZERO;
        for sequence in 101..=112 {
            let timestamp = time - 100_000 + sequence * BLOCK_SECONDS;
            let commands = if sequence == 101 {
                vec![export.clone()]
            } else {
                vec![]
            };
            let mut block = source
                .chain()
                .template(miner.public_key.clone(), timestamp, commands)
                .unwrap();
            while !rld_value_successor::chain::mine_batch(&mut block, 100_000).unwrap() {}
            if sequence == 101 {
                checkpoint = block.header.id().unwrap();
            }
            source.accept(block, time).unwrap();
        }
        assert!(
            source.chain().state().coin(&input).is_none(),
            "export debits source before communication"
        );
        let bundle = source.chain().export_bundle(export_id, checkpoint).unwrap();
        let statement =
            FinalityStatement::from_chain(source.chain(), adoption, checkpoint, None).unwrap();
        let bytes = statement.signing_bytes().unwrap();
        let certificate = rld_value_successor::chain::finality::FinalityCertificate {
            approvals: keys
                .iter()
                .map(|k| Approval {
                    public_key: k.public_key.clone(),
                    signature: sign_bytes(&k.secret_key, &bytes).unwrap(),
                })
                .collect(),
            statement,
        };
        source.install_finality(certificate.clone()).unwrap();
        let context = DestinationContext {
            chain_id: Hash([91; 32]),
            source_policy: ObservationPolicy {
                source_chain_id: source.chain().chain_id(),
                accepted_v1_tip: v1.tip(),
                minimum_confirmations: 12,
                minimum_cumulative_work: certificate.statement.cumulative_work,
            },
            started_at: time - 1000,
            initial_target: rld_pow::target_limit(),
            source_finality: Some(SourceFinalityTrust {
                earth_adoption_id: adoption,
                validator_keys: validators,
            }),
        };
        Self {
            root,
            v1,
            context,
            certificate,
            bundle,
            recipient,
            miner,
            source: Some(source),
        }
    }
    fn pin(&self) -> Hash {
        self.certificate.statement.id().unwrap()
    }
    fn app(&mut self, offline: bool) -> App {
        let source = self.source.take().unwrap_or_else(|| {
            let trust = self.context.source_finality.as_ref().unwrap();
            CandidateStore::open_finalized(
                &self.root.join("source"),
                &self.v1,
                now().unwrap(),
                trust.earth_adoption_id,
                trust.validator_keys.clone(),
            )
            .unwrap()
        });
        if offline {
            verify_disconnected_source(&source, &self.context, self.pin()).unwrap();
        }
        let destination = DestinationPowStore::open(
            &self.root.join("destination"),
            self.context.clone(),
            source.chain(),
            now().unwrap(),
        )
        .unwrap();
        App(Arc::new(Runtime {
            source: Mutex::new(source),
            destination: Mutex::new(destination),
            context: self.context.clone(),
            fresh: AtomicBool::new(false),
            last_source_ok: AtomicU64::new(0),
            running: AtomicBool::new(true),
            miner: Some(self.miner.public_key.clone()),
            submissions: AtomicU64::new(0),
            transition_preview_id: Hash([55; 32]),
            destination_authorization_id: Hash([66; 32]),
            permits: Arc::new(Semaphore::new(2)),
            mode: NodeMode::Candidate,
            disconnected_source_certificate: offline.then(|| self.pin()),
        }))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        drop(self.source.take());
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}

async fn server(
    app: App,
) -> (
    String,
    tokio::task::JoinHandle<()>,
    tokio::sync::oneshot::Sender<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}{}", listener.local_addr().unwrap(), BASE);
    let router = Router::new()
        .route("/status", get(status))
        .route("/balance/{owner}", get(balance))
        .route("/template", post(template))
        .route("/blocks", post(submit_block))
        .route("/commands", post(submit_command))
        .route("/receipts", post(receipt))
        .route("/verify-receipt", post(verify_receipt));
    let router = Router::new().nest(BASE, router).with_state(app);
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    (url, task, stop)
}
async fn block(http: &reqwest::Client, url: &str, miner: &str, commands: Vec<Command>) -> Block {
    let response = http
        .post(format!("{url}/template"))
        .json(&serde_json::json!({"miner":miner,"commands":commands}))
        .send()
        .await
        .unwrap();
    let code = response.status();
    let bytes = response.bytes().await.unwrap();
    assert_eq!(code, StatusCode::OK, "{}", String::from_utf8_lossy(&bytes));
    let mut block: Block = serde_json::from_slice(&bytes).unwrap();
    while !mine_batch(&mut block, 100_000).unwrap() {}
    http.post(format!("{url}/blocks"))
        .json(&block)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    block
}

#[test]
fn offline_requires_exact_durable_finality_and_trust() {
    let fixture = Fixture::new();
    let source = fixture.source.as_ref().unwrap();
    verify_disconnected_source(source, &fixture.context, fixture.pin()).unwrap();
    assert!(verify_disconnected_source(source, &fixture.context, Hash::ZERO).is_err());
    assert!(verify_disconnected_source(source, &fixture.context, Hash([90; 32])).is_err());
    let mut context = fixture.context.clone();
    context.source_finality = None;
    assert!(verify_disconnected_source(source, &context, fixture.pin()).is_err());
    context = fixture.context.clone();
    context.source_policy.source_chain_id = Hash([90; 32]);
    assert!(verify_disconnected_source(source, &context, fixture.pin()).is_err());
    context = fixture.context.clone();
    context.source_finality.as_mut().unwrap().earth_adoption_id = Hash([90; 32]);
    assert!(verify_disconnected_source(source, &context, fixture.pin()).is_err());
    let trust = fixture.context.source_finality.as_ref().unwrap();
    let empty = CandidateStore::open_finalized(
        &fixture.root.join("missing-finality"),
        &fixture.v1,
        now().unwrap(),
        trust.earth_adoption_id,
        trust.validator_keys.clone(),
    )
    .unwrap();
    assert!(verify_disconnected_source(&empty, &fixture.context, fixture.pin()).is_err());
    drop(empty);
}

#[test]
fn corrupted_durable_source_certificate_cannot_restart_offline() {
    let mut fixture = Fixture::new();
    drop(fixture.source.take());
    let mut forged = fixture.certificate.clone();
    forged.approvals[0].signature = "00".into();
    std::fs::write(
        fixture.root.join("source/FINALITY"),
        serde_json::to_vec(&forged).unwrap(),
    )
    .unwrap();
    let trust = fixture.context.source_finality.as_ref().unwrap();
    assert!(CandidateStore::open_finalized(
        &fixture.root.join("source"),
        &fixture.v1,
        now().unwrap(),
        trust.earth_adoption_id,
        trust.validator_keys.clone()
    )
    .is_err());
}

#[tokio::test]
async fn default_still_stops_without_source_contact() {
    let mut fixture = Fixture::new();
    let app = fixture.app(false);
    assert!(!app.0.source_available());
    assert_eq!(
        balance(
            State(app.clone()),
            RoutePath(fixture.recipient.public_key.clone())
        )
        .await
        .unwrap_err()
        .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    app.0.fresh.store(true, Ordering::Release);
    app.0
        .last_source_ok
        .store(now().unwrap() - 6, Ordering::Release);
    assert!(!app.0.source_available());
    app.0
        .last_source_ok
        .store(now().unwrap(), Ordering::Release);
    assert!(app.0.source_fresh());
    drop(app);
}

#[tokio::test]
async fn disconnected_http_import_mature_spend_and_restart_without_source_server() {
    let mut fixture = Fixture::new();
    let app = fixture.app(true);
    let (url, task, stop) = server(app.clone()).await;
    let http = reqwest::Client::builder()
        .no_proxy()
        .pool_max_idle_per_host(0)
        .build()
        .unwrap();
    let state: serde_json::Value = http
        .get(format!("{url}/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(state["source_fresh"], false);
    assert_eq!(state["source_available"], true);
    assert_eq!(state["live_rld"], false);
    assert_eq!(state["source_view"], "PINNED_FINALIZED_OFFLINE_SNAPSHOT");
    let import = Command::FinalizedImport {
        bundle: fixture.bundle.clone(),
        certificate: fixture.certificate.clone(),
    };
    let uncovered = {
        let source = app.0.source.lock().await;
        source
            .chain()
            .export_bundle(fixture.bundle.export_id, source.chain().tip())
            .unwrap()
    };
    let mut forged = fixture.certificate.clone();
    forged.approvals[0].signature = "00".into();
    for command in [
        Command::Import(fixture.bundle.clone()),
        Command::FinalizedImport {
            bundle: fixture.bundle.clone(),
            certificate: forged,
        },
        Command::FinalizedImport {
            bundle: uncovered,
            certificate: fixture.certificate.clone(),
        },
    ] {
        let response = http
            .post(format!("{url}/template"))
            .json(&serde_json::json!({"miner":fixture.miner.public_key,"commands":[command]}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let first = block(&http, &url, &fixture.miner.public_key, vec![import.clone()]).await;
    assert_eq!(
        http.post(format!("{url}/commands"))
            .json(&import)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST,
        "duplicate cannot create credit"
    );
    let mut id_bytes = b"RLD-EARTH-DESTINATION-POW-IMPORT-OUTPUT\0".to_vec();
    id_bytes.extend(fixture.context.chain_id.0);
    id_bytes.extend(fixture.bundle.source_chain_id.0);
    id_bytes.extend(fixture.bundle.export_id.0);
    let mut tx = Transfer {
        chain_id: fixture.context.chain_id,
        owner: fixture.recipient.public_key.clone(),
        inputs: vec![OutPoint {
            transaction: Hash(Sha256::digest(id_bytes).into()),
            index: 0,
        }],
        outputs: vec![
            Output {
                owner: fixture.miner.public_key.clone(),
                amount: Amount(100),
            },
            Output {
                owner: fixture.recipient.public_key.clone(),
                amount: Amount(889),
            },
        ],
        fee: Amount(1),
        valid_through_height: 100,
        signature: String::new(),
    };
    tx.signature = sign_bytes(&fixture.recipient.secret_key, &tx.signing_bytes().unwrap()).unwrap();
    let command = Command::Transfer(tx);
    assert_eq!(
        http.post(format!("{url}/commands"))
            .json(&command)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST,
        "immature funds cannot be spent"
    );
    for _ in 2..=6 {
        block(&http, &url, &fixture.miner.public_key, vec![]).await;
    }
    block(
        &http,
        &url,
        &fixture.miner.public_key,
        vec![command.clone()],
    )
    .await;
    assert_eq!(
        http.post(format!("{url}/commands"))
            .json(&command)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST,
        "spent input cannot be spent twice"
    );
    let state: serde_json::Value = http
        .get(format!("{url}/balance/{}", fixture.recipient.public_key))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(state["spendable_runlai"], "889");
    let policy = InclusionPolicy {
        destination_chain_id: fixture.context.chain_id,
        accepted_genesis: app.0.destination.lock().await.chain().genesis(),
        minimum_confirmations: 2,
        minimum_inclusion_work: rld_core::header_work(first.header.target),
    };
    let observed: ImportInclusionReceipt = http
        .post(format!("{url}/receipts"))
        .json(&serde_json::json!({"bundle":fixture.bundle,"policy":policy}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!observed.live_rld);
    let verified: serde_json::Value = http
        .post(format!("{url}/verify-receipt"))
        .json(&serde_json::json!({"bundle":fixture.bundle,"policy":policy,"receipt":observed}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(verified["valid_on_selected_branches"], true);
    let mut false_live = observed;
    false_live.live_rld = true;
    assert_eq!(
        http.post(format!("{url}/verify-receipt"))
            .json(
                &serde_json::json!({"bundle":fixture.bundle,"policy":policy,"receipt":false_live})
            )
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let (tip, root) = {
        let store = app.0.destination.lock().await;
        (store.chain().tip(), store.chain().state().root().unwrap())
    };
    drop(http);
    stop.send(()).unwrap();
    task.await.unwrap();
    drop(app);
    let recovered = fixture.app(true);
    assert!(!recovered.0.source_fresh());
    assert!(recovered.0.source_available());
    let store = recovered.0.destination.lock().await;
    assert_eq!(store.chain().tip(), tip);
    assert_eq!(store.chain().state().root().unwrap(), root);
    assert_eq!(store.chain().state().imported_total(), Amount(1000));
    assert_eq!(
        store
            .chain()
            .state()
            .balance(&fixture.recipient.public_key, 8)
            .unwrap(),
        (Amount(889), Amount::ZERO)
    );
    drop(store);
    drop(recovered);
}
