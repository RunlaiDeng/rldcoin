//! Disposable real-process interoperability test; no production state or port.
use ed25519_dalek::SigningKey;
use rld_core::{generate_identity, header_work, sign_bytes, AdmissionHash32 as Hash, Amount};
use rld_cross_region::value::{ExportCommand, ExportIntent};
use rld_fast_payments::{
    successor::{OpenChannel, OpenIntent},
    ChannelState, PaymentOffer, PaymentReceipt, SignedState,
};
use rld_pow::{
    mine_batch as mine_v1,
    storage::Store as V1Store,
    target_limit,
    transition::{rules_hash, Adoption, AdoptionStatement, Approval, FORMAT},
    OutPoint, Output, Transfer,
};
use rld_value_successor::adoption::{EarthSuccessorAdoption, EarthSuccessorAdoptionStatement};
use rld_value_successor::chain::{
    finality::{FinalityCertificate, FinalityStatement},
    mine_batch, Block, CandidateChain, Command as CandidateCommand, ObservationPolicy,
};
use rld_value_successor::transition::{
    TransitionAuthorization, TransitionAuthorizationStatement, TransitionPreview,
};
use rld_value_successor::{
    destination::ack::CandidateImportAck,
    destination::pow::{
        authorization::{
            DestinationGenesisAuthorization, DestinationGenesisAuthorizationStatement,
        },
        receipt::{ImportInclusionReceipt, InclusionPolicy},
        Command as DestinationCommand, Context as DestinationContext, SourceFinalityTrust,
    },
    signed_state_hash,
    wallet_guard::{FeeFunding, GuardedRecipient},
    wallet_payer::WatchedPayer,
    watchtower::{WatchAck, WatchedReceipt},
    ActionFee, ActionFeeIntent, ChallengeFeeReserve, ChallengeFeeReserveIntent, DisputeAction,
};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn hash(bytes: &[u8]) -> Hash {
    Hash(Sha256::digest(bytes).into())
}
struct Fixture {
    dir: PathBuf,
    pin: Hash,
    adoption: Hash,
    source: Hash,
    transition_preview: Hash,
    transition_authorization: Hash,
    earth_adoption: Option<Hash>,
    transition_signer: String,
    destination_authorization: Option<Hash>,
    destination_signer: Option<String>,
    owner: String,
    owner_secret: String,
    chain_id: Hash,
    mature_input: Option<(OutPoint, Amount)>,
    mature_fee_input: Option<(OutPoint, Amount)>,
    v1_height: u128,
    v1_chain: rld_pow::Chain,
    children: Vec<Child>,
}
impl Fixture {
    fn new() -> Self {
        Self::with_v1_blocks(1)
    }
    fn with_v1_blocks(v1_blocks: u128) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "rld-successor-process-{}",
            generate_identity().public_key
        ));
        std::fs::create_dir(&dir).unwrap();
        let genesis = include_bytes!("../../../vectors/m0-genesis-v3/manifest.json");
        let history = b"[]";
        let manifest = rld_core::M0GenesisManifestFile::decode_json(genesis).unwrap();
        let descriptor = manifest.descriptor();
        let pin = Hash::from_hex(manifest.manifest_sha256()).unwrap();
        let source =
            Hash::from_hex(rld_core::implementation_source::IMPLEMENTATION_SOURCE_COMMITMENT)
                .unwrap();
        let statement = AdoptionStatement {
            format: FORMAT.into(),
            manifest_pin: pin,
            network_domain: descriptor.network_domain.clone(),
            zone_id: descriptor.zone_id.clone(),
            currency_genesis: Hash::from_hex(&descriptor.currency_genesis_root).unwrap(),
            legacy_height: 0,
            legacy_state_root: Hash::from_hex(manifest.genesis_state_root()).unwrap(),
            legacy_history_sha256: hash(history),
            rules_sha256: rules_hash(),
            implementation_source_sha256: source,
            started_at: now() - 100_000,
            initial_target: target_limit(),
            old_service_reserves_reassigned: Amount::TOTAL_SUPPLY,
            personal_allocation: Amount::ZERO,
            incompatible_with_m0_constitution: true,
        };
        let adoption = statement.id().unwrap();
        let mut approvals = Vec::new();
        for seed in 2..=5 {
            let key = SigningKey::from_bytes(&[seed; 32]);
            approvals.push(Approval {
                public_key: hex::encode(key.verifying_key().to_bytes()),
                signature: sign_bytes(
                    &hex::encode([seed; 32]),
                    &statement.signing_bytes().unwrap(),
                )
                .unwrap(),
            });
        }
        approvals.sort_by(|a, b| a.public_key.cmp(&b.public_key));
        let signed = Adoption {
            statement,
            approvals,
        };
        let context = signed.verify(genesis, history, pin, adoption).unwrap();
        std::fs::write(dir.join("genesis.json"), genesis).unwrap();
        std::fs::write(dir.join("history.json"), history).unwrap();
        std::fs::write(
            dir.join("adoption.json"),
            serde_json::to_vec(&signed).unwrap(),
        )
        .unwrap();
        let identity = generate_identity();
        let owner = identity.public_key;
        let owner_secret = identity.secret_key;
        let mut chain = rld_pow::Chain::new(context.clone()).unwrap();
        let mut blocks = Vec::new();
        for sequence in 1..=v1_blocks {
            let mut block = chain
                .template(
                    owner.clone(),
                    context.started_at + sequence as u64 * 600,
                    vec![],
                )
                .unwrap();
            while !mine_v1(&mut block, 100_000).unwrap() {}
            chain.accept(block.clone(), now()).unwrap();
            blocks.push(block);
        }
        let mature_input = chain
            .state()
            .coins
            .iter()
            .find(|(_, coin)| {
                coin.output.owner == owner && coin.spendable_height <= chain.height() + 1
            })
            .map(|(point, coin)| (point.clone(), coin.output.amount));
        let mature_fee_input = chain
            .state()
            .coins
            .iter()
            .filter(|(_, coin)| {
                coin.output.owner == owner && coin.spendable_height <= chain.height() + 1
            })
            .nth(1)
            .map(|(point, coin)| (point.clone(), coin.output.amount));
        for name in ["a", "b", "receiver", "payer", "importer"] {
            let mut store =
                V1Store::open(&dir.join(format!("{name}-v1")), context.clone(), now()).unwrap();
            for block in &blocks {
                store.accept(block.clone(), now()).unwrap();
            }
        }
        let preview = TransitionPreview::from_replayed_v1(&chain, source).unwrap();
        let transition_preview = preview.id().unwrap();
        std::fs::write(
            dir.join("transition-preview.json"),
            preview.canonical_bytes().unwrap(),
        )
        .unwrap();
        let signer = generate_identity();
        let authorization_statement =
            TransitionAuthorizationStatement::from_preview(&preview).unwrap();
        let transition_authorization = authorization_statement.id().unwrap();
        let authorization = TransitionAuthorization {
            signature: sign_bytes(
                &signer.secret_key,
                &authorization_statement.signing_bytes().unwrap(),
            )
            .unwrap(),
            signer_public_key: signer.public_key.clone(),
            statement: authorization_statement,
        };
        std::fs::write(
            dir.join("transition-authorization.json"),
            authorization.canonical_bytes().unwrap(),
        )
        .unwrap();
        Self {
            dir,
            pin,
            adoption,
            source,
            transition_preview,
            transition_authorization,
            earth_adoption: None,
            transition_signer: signer.public_key,
            destination_authorization: None,
            destination_signer: None,
            owner,
            owner_secret,
            chain_id: context.chain_id().unwrap(),
            mature_input,
            mature_fee_input,
            v1_height: chain.height(),
            v1_chain: chain,
            children: Vec::new(),
        }
    }
    fn enable_earth(&mut self) {
        let preview: TransitionPreview = serde_json::from_slice(
            &std::fs::read(self.dir.join("transition-preview.json")).unwrap(),
        )
        .unwrap();
        let statement =
            EarthSuccessorAdoptionStatement::from_replayed_fresh_chain(&self.v1_chain, &preview)
                .unwrap();
        let id = statement.id().unwrap();
        let bytes = statement.signing_bytes().unwrap();
        let mut approvals = Vec::new();
        for seed in 2..=5 {
            let key = SigningKey::from_bytes(&[seed; 32]);
            approvals.push(Approval {
                public_key: hex::encode(key.verifying_key().to_bytes()),
                signature: sign_bytes(&hex::encode([seed; 32]), &bytes).unwrap(),
            });
        }
        approvals.sort_by(|a, b| a.public_key.cmp(&b.public_key));
        let signed = EarthSuccessorAdoption {
            statement,
            approvals,
        };
        let pow: Adoption =
            serde_json::from_slice(&std::fs::read(self.dir.join("adoption.json")).unwrap())
                .unwrap();
        signed
            .verify(
                &std::fs::read(self.dir.join("genesis.json")).unwrap(),
                b"[]",
                &pow,
                &self.v1_chain,
                &preview,
                id,
            )
            .unwrap();
        std::fs::write(
            self.dir.join("earth-adoption.json"),
            serde_json::to_vec(&signed).unwrap(),
        )
        .unwrap();
        self.earth_adoption = Some(id);
    }
    fn authorize_destination(&mut self, context: &DestinationContext) {
        let preview: TransitionPreview = serde_json::from_slice(
            &std::fs::read(self.dir.join("transition-preview.json")).unwrap(),
        )
        .unwrap();
        let signer = generate_identity();
        let statement =
            DestinationGenesisAuthorizationStatement::from_context(context, &preview).unwrap();
        let id = statement.id().unwrap();
        let authorization = DestinationGenesisAuthorization {
            signature: sign_bytes(&signer.secret_key, &statement.signing_bytes().unwrap()).unwrap(),
            signer_public_key: signer.public_key.clone(),
            statement,
        };
        std::fs::write(
            self.dir.join("destination-authorization.json"),
            authorization.canonical_bytes().unwrap(),
        )
        .unwrap();
        self.destination_authorization = Some(id);
        self.destination_signer = Some(signer.public_key);
    }
    fn launch(&mut self, name: &str, peer: Option<&str>, miner: bool) -> String {
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        drop(socket);
        self.launch_at(name, peer, miner, addr)
    }
    fn launch_at(
        &mut self,
        name: &str,
        peer: Option<&str>,
        miner: bool,
        addr: SocketAddr,
    ) -> String {
        let log = std::fs::File::create(self.dir.join(format!("{name}.log"))).unwrap();
        let mut process = Command::new(env!("CARGO_BIN_EXE_rld-earth-node"));
        process
            .arg("run")
            .arg("--genesis")
            .arg(self.dir.join("genesis.json"))
            .arg("--history")
            .arg(self.dir.join("history.json"))
            .arg("--adoption")
            .arg(self.dir.join("adoption.json"))
            .arg("--manifest-pin")
            .arg(self.pin.to_hex())
            .arg("--accept-adoption")
            .arg(self.adoption.to_hex())
            .arg("--pinned-v1-source")
            .arg(self.source.to_hex())
            .arg("--v1-data-dir")
            .arg(self.dir.join(format!("{name}-v1")))
            .arg("--transition-preview")
            .arg(self.dir.join("transition-preview.json"))
            .arg("--accept-transition-preview")
            .arg(self.transition_preview.to_hex())
            .arg("--transition-authorization")
            .arg(self.dir.join("transition-authorization.json"))
            .arg("--accept-transition-authorization")
            .arg(self.transition_authorization.to_hex())
            .arg("--transition-signer")
            .arg(&self.transition_signer)
            .arg("--candidate-dir")
            .arg(self.dir.join(format!("{name}-candidate")))
            .arg("--listen")
            .arg(addr.to_string())
            .arg("--offline-v1-copy")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log);
        if let Some(peer) = peer {
            process.arg("--peer").arg(peer);
        }
        if miner {
            process
                .arg("--mine-to")
                .arg(&self.owner)
                .args(["--mine-interval-ms", "2000"]);
        }
        self.children.push(process.spawn().unwrap());
        format!("http://{addr}")
    }
    fn launch_destination(
        &mut self,
        name: &str,
        source_node: &str,
        peer: Option<&str>,
        miner: bool,
    ) -> String {
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        drop(socket);
        let log = std::fs::File::create(self.dir.join(format!("{name}-destination.log"))).unwrap();
        let mut process = Command::new(env!("CARGO_BIN_EXE_rld-earth-destination-node"));
        process
            .arg("--genesis")
            .arg(self.dir.join("genesis.json"))
            .arg("--history")
            .arg(self.dir.join("history.json"))
            .arg("--adoption")
            .arg(self.dir.join("adoption.json"))
            .args(["--manifest-pin", &self.pin.to_hex()])
            .args(["--accept-adoption", &self.adoption.to_hex()])
            .args(["--pinned-v1-source", &self.source.to_hex()])
            .arg("--v1-data-dir")
            .arg(self.dir.join(format!("{name}-v1")))
            .arg("--transition-preview")
            .arg(self.dir.join("transition-preview.json"))
            .args([
                "--accept-transition-preview",
                &self.transition_preview.to_hex(),
            ])
            .arg("--source-candidate-dir")
            .arg(self.dir.join(format!("{name}-source-candidate")))
            .args(["--source-node", source_node])
            .arg("--destination-context")
            .arg(self.dir.join("destination-context.json"))
            .arg("--destination-authorization")
            .arg(self.dir.join("destination-authorization.json"))
            .args([
                "--accept-destination-authorization",
                &self.destination_authorization.unwrap().to_hex(),
            ])
            .args([
                "--destination-signer",
                self.destination_signer.as_ref().unwrap(),
            ])
            .arg("--destination-dir")
            .arg(self.dir.join(format!("{name}-destination-store")))
            .args(["--listen", &addr.to_string()])
            .arg("--offline-v1-copy")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log);
        if let Some(peer) = peer {
            process.args(["--peer", peer]);
        }
        if miner {
            process.args(["--mine-to", &self.owner]);
            process.args(["--mine-interval-ms", "1500"]);
        }
        self.children.push(process.spawn().unwrap());
        format!("http://{addr}")
    }
    fn launch_receiver(
        &mut self,
        node: &str,
        watcher: (&str, &str),
        wallet: &Path,
        key: &Path,
        config: &Path,
        addr: SocketAddr,
    ) -> String {
        let receiver_log = std::fs::File::create(self.dir.join("receiver.log")).unwrap();
        self.children.push(
            Command::new(env!(
                "CARGO_BIN_EXE_rldsuccessor-payment-receiver-candidate"
            ))
            .arg("--genesis")
            .arg(self.dir.join("genesis.json"))
            .arg("--history")
            .arg(self.dir.join("history.json"))
            .arg("--adoption")
            .arg(self.dir.join("adoption.json"))
            .args(["--manifest-pin", &self.pin.to_hex()])
            .args(["--accept-adoption", &self.adoption.to_hex()])
            .args(["--pinned-v1-source", &self.source.to_hex()])
            .arg("--v1-data-dir")
            .arg(self.dir.join("receiver-v1"))
            .arg("--transition-preview")
            .arg(self.dir.join("transition-preview.json"))
            .args([
                "--accept-transition-preview",
                &self.transition_preview.to_hex(),
            ])
            .arg("--candidate-dir")
            .arg(self.dir.join("receiver-candidate"))
            .arg("--wallet-dir")
            .arg(wallet)
            .arg("--receiver-key")
            .arg(key)
            .arg("--funding-config")
            .arg(config)
            .args(["--node", node, "--listen", &addr.to_string()])
            .args(["--watchtower", watcher.0])
            .args(["--watcher-public-key", watcher.1])
            .arg("--offline-v1-copy")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(receiver_log)
            .spawn()
            .unwrap(),
        );
        format!("http://{addr}")
    }
    fn launch_watcher(
        &mut self,
        node: &str,
        package: &Path,
        state: &Path,
        key: &Path,
        addr: SocketAddr,
    ) {
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("watchtower.log"))
            .unwrap();
        self.children.push(
            Command::new(env!("CARGO_BIN_EXE_rld-earth-watchtower"))
                .args(["--node", node])
                .args([
                    "--accept-transition-preview",
                    &self.transition_preview.to_hex(),
                ])
                .arg("--package")
                .arg(package)
                .arg("--watch-state-dir")
                .arg(state)
                .arg("--ack-key")
                .arg(key)
                .args(["--listen", &addr.to_string(), "--poll-ms", "100"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(log)
                .spawn()
                .unwrap(),
        );
    }
    fn stop(&mut self, index: usize) {
        let id = self.children[index].id();
        assert!(Command::new("kill")
            .args(["-TERM", &id.to_string()])
            .status()
            .unwrap()
            .success());
        assert!(self.children[index].wait().unwrap().success());
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for process in &mut self.children {
            let _ = process.kill();
            let _ = process.wait();
        }
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.dir);
        } else {
            eprintln!("candidate process fixture retained: {}", self.dir.display());
        }
    }
}
async fn status(client: &reqwest::Client, url: &str, height: u128) -> serde_json::Value {
    for _ in 0..100 {
        if let Ok(response) = client
            .get(format!("{url}/v1/successor-candidate/status"))
            .send()
            .await
        {
            if let Ok(value) = response.json::<serde_json::Value>().await {
                if value["height"]
                    .as_str()
                    .and_then(|s| s.parse::<u128>().ok())
                    .is_some_and(|n| n >= height)
                {
                    return value;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("candidate process did not reach height {height}");
}

async fn destination_status(
    client: &reqwest::Client,
    url: &str,
    minimum_height: u128,
) -> serde_json::Value {
    for _ in 0..200 {
        if let Ok(response) = client
            .get(format!("{url}/v1/destination-pow-candidate/status"))
            .send()
            .await
        {
            if let Ok(value) = response.json::<serde_json::Value>().await {
                if value["height"]
                    .as_str()
                    .and_then(|s| s.parse::<u128>().ok())
                    .is_some_and(|height| height >= minimum_height)
                    && value["source_fresh"] == true
                {
                    return value;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("destination candidate did not reach height {minimum_height}");
}

/// Replay the local candidate peer's block stream against our own pinned v1
/// anchor. A JSON status or escrow response alone is not a funding proof.
async fn observed_candidate_chain(
    fixture: &Fixture,
    client: &reqwest::Client,
    url: &str,
) -> CandidateChain {
    let mut chain = CandidateChain::from_replayed_pow_chain(&fixture.v1_chain).unwrap();
    for _ in 0..100 {
        let response: serde_json::Value = client
            .post(format!("{url}/v1/successor-candidate/sync"))
            .json(&serde_json::json!({"locator":[chain.tip()]}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            response["chain_id"],
            serde_json::to_value(fixture.chain_id).unwrap()
        );
        assert_eq!(
            response["v1_tip"],
            serde_json::to_value(chain.v1_tip()).unwrap()
        );
        let blocks: Vec<Block> = serde_json::from_value(response["blocks"].clone()).unwrap();
        for block in blocks {
            chain.accept(block, now()).unwrap();
        }
        if response["tip"] == serde_json::to_value(chain.tip()).unwrap() {
            return chain;
        }
    }
    panic!("candidate peer did not yield a replayable selected branch");
}
async fn escrow(client: &reqwest::Client, url: &str, id: Hash) -> serde_json::Value {
    for _ in 0..120 {
        if let Ok(response) = client
            .get(format!(
                "{url}/v1/successor-candidate/escrows/{}",
                id.to_hex()
            ))
            .send()
            .await
        {
            if response.status().is_success() {
                return response.json().await.unwrap();
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("candidate process did not include escrow {}", id.to_hex());
}
async fn included_command(client: &reqwest::Client, url: &str, id: &str) {
    for _ in 0..120 {
        if let Ok(response) = client
            .get(format!("{url}/v1/successor-candidate/commands/{id}"))
            .send()
            .await
        {
            if let Ok(value) = response.json::<serde_json::Value>().await {
                if value["candidate_included"] == true {
                    return;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("candidate did not include command {id}");
}
async fn closing_state(
    client: &reqwest::Client,
    url: &str,
    id: Hash,
    sequence: u64,
) -> serde_json::Value {
    for _ in 0..120 {
        let value = escrow(client, url, id).await;
        if value["escrow"]["phase"]["Closing"]["best"]["state"]["sequence"] == sequence {
            return value;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("candidate channel did not reach closing sequence {sequence}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_processes_sync_replay_and_reject_unmined_block() {
    let mut f = Fixture::new();
    let client = reqwest::Client::new();
    let a = f.launch("a", None, false);
    let b = f.launch("b", Some(&a), false);
    let initial = status(&client, &a, f.v1_height).await;
    assert_eq!(initial["live_rld"], false);
    assert_eq!(initial["cross_region_imports_enabled"], false);
    status(&client, &b, f.v1_height).await;
    let continuity_url = |node: &str| format!("{node}/v1/successor-candidate/continuity");
    let handoff: serde_json::Value = client
        .get(continuity_url(&a))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(handoff["live_rld"], false);
    assert_eq!(
        handoff["v1_tip"],
        serde_json::to_value(f.v1_chain.tip()).unwrap()
    );
    assert_eq!(
        handoff["v1_state_root"],
        serde_json::to_value(f.v1_chain.state().root().unwrap()).unwrap()
    );
    assert_eq!(
        handoff["commitment"]["emitted"],
        serde_json::to_value(f.v1_chain.state().emitted).unwrap()
    );
    assert_eq!(
        handoff["commitment"]["liquid"],
        handoff["commitment"]["emitted"]
    );
    assert_eq!(handoff["commitment"]["locked"], "0");
    assert_eq!(handoff["commitment"]["retired"], "0");
    let peer_handoff: serde_json::Value = client
        .get(continuity_url(&b))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(peer_handoff, handoff);
    let template: Block = client
        .post(format!("{a}/v1/successor-candidate/template"))
        .json(&serde_json::json!({"miner":f.owner,"commands":[]}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let mut invalid = template.clone();
    invalid.header.state_root = Hash([7; 32]);
    assert!(!client
        .post(format!("{a}/v1/successor-candidate/blocks"))
        .json(&invalid)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
    assert_eq!(
        status(&client, &a, f.v1_height).await["height"],
        f.v1_height.to_string()
    );
    let mut block = template;
    while !mine_batch(&mut block, 100_000).unwrap() {}
    assert!(client
        .post(format!("{a}/v1/successor-candidate/blocks"))
        .json(&block)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
    let expected_tip = block.header.id().unwrap().to_hex();
    let synced = status(&client, &b, f.v1_height + 1).await;
    assert_eq!(synced["tip"], expected_tip);
    assert_eq!(
        synced["state_root"],
        status(&client, &a, f.v1_height + 1).await["state_root"]
    );
    let post_mining_handoff: serde_json::Value = client
        .get(continuity_url(&a))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(post_mining_handoff, handoff);
    f.stop(1);
    let b_restarted = f.launch("b", Some(&a), false);
    let replayed = status(&client, &b_restarted, f.v1_height + 1).await;
    assert_eq!(replayed["tip"], expected_tip);
    assert_eq!(replayed["storage_healthy"], true);
    let restarted_handoff: serde_json::Value = client
        .get(continuity_url(&b_restarted))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(restarted_handoff, handoff);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn source_candidate_holds_v1_cut_lock_until_shutdown() {
    let mut f = Fixture::new();
    let client = reqwest::Client::new();
    let source = f.launch("a", None, false);
    status(&client, &source, f.v1_height).await;
    let v1_dir = f.dir.join("a-v1");
    let locked = V1Store::open(&v1_dir, f.v1_chain.context.clone(), now());
    assert!(
        locked.is_err(),
        "v1 writer must not reopen a candidate's fixed source cut"
    );
    assert!(locked.err().unwrap().contains("already owned"));

    f.stop(0);
    let reopened = V1Store::open(&v1_dir, f.v1_chain.context.clone(), now()).unwrap();
    assert_eq!(reopened.chain().tip(), f.v1_chain.tip());
    drop(reopened);
    let restarted = f.launch("a", None, false);
    let state = status(&client, &restarted, f.v1_height).await;
    assert_eq!(state["v1_tip"], f.v1_chain.tip().to_hex());
    f.stop(1);

    // If the old chain advances after the candidate stops, the previous
    // signed cut must not authorize another candidate launch.
    let mut reopened = V1Store::open(&v1_dir, f.v1_chain.context.clone(), now()).unwrap();
    let mut next = reopened
        .chain()
        .template(
            f.owner.clone(),
            f.v1_chain.context.started_at + 1_200,
            vec![],
        )
        .unwrap();
    while !mine_v1(&mut next, 100_000).unwrap() {}
    reopened.accept(next, now()).unwrap();
    drop(reopened);
    f.launch("a", None, false);
    let mut failure = None;
    for _ in 0..100 {
        if let Some(exit) = f.children[2].try_wait().unwrap() {
            failure = Some(exit);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let failure = failure.expect("stale signed cut was incorrectly allowed to keep running");
    assert!(!failure.success());
    assert!(std::fs::read_to_string(f.dir.join("a.log"))
        .unwrap()
        .contains("transition preview"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn destination_import_process_returns_signed_ack_and_halts_on_source_reorg() {
    let mut f = Fixture::with_v1_blocks(101);
    let client = reqwest::Client::new();
    let node = f.launch("a", None, false);
    status(&client, &node, f.v1_height).await;
    let destination_id = Hash([91; 32]);
    let recipient = generate_identity();
    let operator = generate_identity();
    let (input, balance) = f.mature_input.clone().unwrap();
    let intent = ExportIntent {
        source_chain_id: f.chain_id,
        destination_chain_id: destination_id,
        input,
        owner: f.owner.clone(),
        recipient: recipient.public_key.clone(),
        amount: Amount(1_000),
        source_fee: Amount(1),
        destination_fee: Amount(10),
        change: balance.checked_sub(Amount(1_001)).unwrap(),
        valid_through_height: f.v1_height + 10,
    };
    let export_id = intent.id().unwrap();
    let command = CandidateCommand::Export(ExportCommand {
        owner_signature: sign_bytes(&f.owner_secret, &intent.signing_bytes().unwrap()).unwrap(),
        intent,
    });
    let mut source = CandidateChain::from_replayed_pow_chain(&f.v1_chain).unwrap();
    let mut alternate = source.clone();
    let first_time = now() - 20;
    let mut first = source
        .template(f.owner.clone(), first_time, vec![command])
        .unwrap();
    while !mine_batch(&mut first, 100_000).unwrap() {}
    source.accept(first.clone(), now()).unwrap();
    let checkpoint_work = source.chainwork();
    assert!(client
        .post(format!("{node}/v1/successor-candidate/blocks"))
        .json(&first)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
    let checkpoint = first.header.id().unwrap();
    let mut confirming = source
        .template(f.owner.clone(), first_time + 1, vec![])
        .unwrap();
    while !mine_batch(&mut confirming, 100_000).unwrap() {}
    source.accept(confirming.clone(), now()).unwrap();
    assert!(client
        .post(format!("{node}/v1/successor-candidate/blocks"))
        .json(&confirming)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
    let bundle = source.export_bundle(export_id, checkpoint).unwrap();
    let bundle_file = f.dir.join("source-export-bundle.json");
    std::fs::write(&bundle_file, serde_json::to_vec(&bundle).unwrap()).unwrap();
    let operator_key = f.dir.join("destination-operator-key.json");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut key = options.open(&operator_key).unwrap();
    key.write_all(&serde_json::to_vec(&operator).unwrap())
        .unwrap();
    key.sync_all().unwrap();
    let ack_file = f.dir.join("destination-ack.json");
    let store_dir = f.dir.join("destination-store");
    let run_import = |ack_target: &Path| {
        Command::new(env!(
            "CARGO_BIN_EXE_rldsuccessor-destination-import-candidate"
        ))
        .arg("--genesis")
        .arg(f.dir.join("genesis.json"))
        .arg("--history")
        .arg(f.dir.join("history.json"))
        .arg("--adoption")
        .arg(f.dir.join("adoption.json"))
        .args(["--manifest-pin", &f.pin.to_hex()])
        .args(["--accept-adoption", &f.adoption.to_hex()])
        .args(["--pinned-v1-source", &f.source.to_hex()])
        .arg("--v1-data-dir")
        .arg(f.dir.join("importer-v1"))
        .arg("--transition-preview")
        .arg(f.dir.join("transition-preview.json"))
        .args([
            "--accept-transition-preview",
            &f.transition_preview.to_hex(),
        ])
        .arg("--candidate-dir")
        .arg(f.dir.join("importer-candidate"))
        .arg("--destination-dir")
        .arg(&store_dir)
        .args(["--destination-chain-id", &destination_id.to_hex()])
        .args(["--source-work-pin", &checkpoint_work.to_hex()])
        .args(["--minimum-confirmations", "2"])
        .arg("--bundle-file")
        .arg(&bundle_file)
        .arg("--operator-key")
        .arg(&operator_key)
        .args(["--miner-fee-to", &f.owner])
        .arg("--ack-output")
        .arg(ack_target)
        .args(["--node", &node])
        .arg("--offline-v1-copy")
        .output()
        .unwrap()
    };
    let missing_parent = f.dir.join("missing-parent").join("ack.json");
    let interrupted = run_import(&missing_parent);
    assert!(!interrupted.status.success());
    assert_eq!(
        std::fs::read_dir(store_dir.join("events")).unwrap().count(),
        1
    );
    let result = run_import(&ack_file);
    assert!(
        result.status.success(),
        "candidate import failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let ack_bytes = std::fs::read(&ack_file).unwrap();
    let ack: CandidateImportAck = serde_json::from_slice(&ack_bytes).unwrap();
    ack.verify(&bundle, &operator.public_key).unwrap();
    let source_policy = ObservationPolicy {
        source_chain_id: f.chain_id,
        accepted_v1_tip: f.v1_chain.tip(),
        minimum_confirmations: 2,
        minimum_cumulative_work: checkpoint_work,
    };
    let sender_replay = observed_candidate_chain(&f, &client, &node).await;
    ack.verify_with_replayed_source(
        &sender_replay,
        &source_policy,
        &bundle,
        &operator.public_key,
    )
    .unwrap();
    assert_eq!(ack.receipt.export_id, export_id);
    assert!(!ack.live_rld);
    assert!(run_import(&ack_file).status.success());
    assert_eq!(std::fs::read(&ack_file).unwrap(), ack_bytes);
    assert_eq!(
        std::fs::read_dir(store_dir.join("events")).unwrap().count(),
        1
    );

    for offset in 0..3 {
        let mut block = alternate
            .template(f.owner.clone(), first_time + 2 + offset, vec![])
            .unwrap();
        while !mine_batch(&mut block, 100_000).unwrap() {}
        alternate.accept(block.clone(), now()).unwrap();
        assert!(client
            .post(format!("{node}/v1/successor-candidate/blocks"))
            .json(&block)
            .send()
            .await
            .unwrap()
            .status()
            .is_success());
    }
    assert_eq!(
        status(&client, &node, f.v1_height + 3).await["tip"],
        alternate.tip().to_hex()
    );
    assert!(!run_import(&ack_file).status.success());
    assert!(store_dir.join("HALTED").exists());
    let reorganized = observed_candidate_chain(&f, &client, &node).await;
    assert!(ack
        .verify_with_replayed_source(&reorganized, &source_policy, &bundle, &operator.public_key,)
        .is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn destination_pow_processes_sync_import_receipt_and_halt_after_source_reorg() {
    let mut f = Fixture::with_v1_blocks(101);
    let client = reqwest::Client::new();
    let source_node = f.launch("a", None, false);
    status(&client, &source_node, f.v1_height).await;
    let destination_id = Hash([91; 32]);
    let recipient = generate_identity();
    let (input, balance) = f.mature_input.clone().unwrap();
    let intent = ExportIntent {
        source_chain_id: f.chain_id,
        destination_chain_id: destination_id,
        input,
        owner: f.owner.clone(),
        recipient: recipient.public_key.clone(),
        amount: Amount(1_000),
        source_fee: Amount(1),
        destination_fee: Amount(10),
        change: balance.checked_sub(Amount(1_001)).unwrap(),
        valid_through_height: f.v1_height + 10,
    };
    let export_id = intent.id().unwrap();
    let export = CandidateCommand::Export(ExportCommand {
        owner_signature: sign_bytes(&f.owner_secret, &intent.signing_bytes().unwrap()).unwrap(),
        intent,
    });
    let mut source = CandidateChain::from_replayed_pow_chain(&f.v1_chain).unwrap();
    let mut alternate = source.clone();
    let first_time = now() - 20;
    let mut first = source
        .template(f.owner.clone(), first_time, vec![export])
        .unwrap();
    while !mine_batch(&mut first, 100_000).unwrap() {}
    source.accept(first.clone(), now()).unwrap();
    let checkpoint = first.header.id().unwrap();
    let checkpoint_work = source.chainwork();
    assert!(client
        .post(format!("{source_node}/v1/successor-candidate/blocks"))
        .json(&first)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
    let mut confirming = source
        .template(f.owner.clone(), first_time + 1, vec![])
        .unwrap();
    while !mine_batch(&mut confirming, 100_000).unwrap() {}
    source.accept(confirming.clone(), now()).unwrap();
    assert!(client
        .post(format!("{source_node}/v1/successor-candidate/blocks"))
        .json(&confirming)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
    let bundle = source.export_bundle(export_id, checkpoint).unwrap();
    let context = DestinationContext {
        chain_id: destination_id,
        source_policy: ObservationPolicy {
            source_chain_id: f.chain_id,
            accepted_v1_tip: f.v1_chain.tip(),
            minimum_confirmations: 2,
            minimum_cumulative_work: checkpoint_work,
        },
        started_at: now() - 10,
        initial_target: target_limit(),
        source_finality: None,
    };
    std::fs::write(
        f.dir.join("destination-context.json"),
        serde_json::to_vec(&context).unwrap(),
    )
    .unwrap();
    f.authorize_destination(&context);
    let a = f.launch_destination("receiver", &source_node, None, true);
    let b = f.launch_destination("payer", &source_node, Some(&a), false);
    destination_status(&client, &a, 0).await;
    destination_status(&client, &b, 0).await;
    let submitted = client
        .post(format!("{a}/v1/destination-pow-candidate/commands"))
        .json(&DestinationCommand::Import(bundle.clone()))
        .send()
        .await
        .unwrap();
    assert!(submitted.status().is_success(), "{submitted:?}");
    let policy = InclusionPolicy {
        destination_chain_id: destination_id,
        accepted_genesis: context.genesis().unwrap(),
        minimum_confirmations: 2,
        minimum_inclusion_work: header_work(target_limit()),
    };
    let request = serde_json::json!({"bundle":bundle,"policy":policy});
    let mut receipt = None;
    for _ in 0..200 {
        let response = client
            .post(format!("{a}/v1/destination-pow-candidate/receipts"))
            .json(&request)
            .send()
            .await
            .unwrap();
        if response.status().is_success() {
            receipt = Some(response.json::<ImportInclusionReceipt>().await.unwrap());
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let receipt = receipt.expect("mined destination import never reached two confirmations");
    assert!(!receipt.live_rld);
    assert_eq!(receipt.recipient_spendable_height, receipt.block_height + 2);
    let recipient_balance: serde_json::Value = client
        .get(format!(
            "{a}/v1/destination-pow-candidate/balance/{}",
            recipient.public_key
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(recipient_balance["live_rld"], false);
    assert_eq!(recipient_balance["candidate_spendable_runlai"], "990");
    assert_eq!(recipient_balance["candidate_pending_runlai"], "0");
    assert_eq!(recipient_balance["minimum_import_confirmations"], "2");
    let verify_request = serde_json::json!({"bundle":bundle,"policy":policy,"receipt":receipt});
    let mut verified = false;
    for _ in 0..200 {
        let response = client
            .post(format!("{b}/v1/destination-pow-candidate/verify-receipt"))
            .json(&verify_request)
            .send()
            .await
            .unwrap();
        if response.status().is_success() {
            let result = response.json::<serde_json::Value>().await.unwrap();
            assert_eq!(result["live_rld"], false);
            assert_eq!(result["valid_on_selected_branches"], true);
            verified = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(verified, "second destination process never verified import");
    f.stop(2);
    let b_restarted = f.launch_destination("payer", &source_node, Some(&a), false);
    destination_status(&client, &b_restarted, 2).await;
    assert!(client
        .post(format!(
            "{b_restarted}/v1/destination-pow-candidate/verify-receipt"
        ))
        .json(&verify_request)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());

    let source_addr: SocketAddr = source_node.trim_start_matches("http://").parse().unwrap();
    f.stop(0);
    let mut paused = false;
    for _ in 0..100 {
        let response = client
            .get(format!("{a}/v1/destination-pow-candidate/status"))
            .send()
            .await
            .unwrap();
        let value = response.json::<serde_json::Value>().await.unwrap();
        if value["source_fresh"] == false {
            paused = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        paused,
        "destination mining did not pause when source disappeared"
    );
    let paused_height: serde_json::Value = client
        .get(format!("{a}/v1/destination-pow-candidate/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(2200)).await;
    let still_paused: serde_json::Value = client
        .get(format!("{a}/v1/destination-pow-candidate/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(paused_height["height"], still_paused["height"]);
    assert_eq!(
        client
            .get(format!(
                "{a}/v1/destination-pow-candidate/balance/{}",
                recipient.public_key
            ))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        client
            .post(format!("{a}/v1/destination-pow-candidate/template"))
            .json(&serde_json::json!({"miner":f.owner,"include_submitted":true}))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
    let revived = f.launch_at("a", None, false, source_addr);
    assert_eq!(revived, source_node);
    status(&client, &revived, f.v1_height + 2).await;
    destination_status(&client, &a, 2).await;
    assert!(client
        .post(format!("{a}/v1/destination-pow-candidate/verify-receipt"))
        .json(&verify_request)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());

    for offset in 0..3 {
        let mut block = alternate
            .template(f.owner.clone(), first_time + 2 + offset, vec![])
            .unwrap();
        while !mine_batch(&mut block, 100_000).unwrap() {}
        alternate.accept(block.clone(), now()).unwrap();
        assert!(client
            .post(format!("{source_node}/v1/successor-candidate/blocks"))
            .json(&block)
            .send()
            .await
            .unwrap()
            .status()
            .is_success());
    }
    assert_eq!(
        status(&client, &source_node, f.v1_height + 3).await["tip"],
        alternate.tip().to_hex()
    );
    let mut halted = false;
    for _ in 0..200 {
        let response = client
            .get(format!("{a}/v1/destination-pow-candidate/status"))
            .send()
            .await
            .unwrap();
        let value = response.json::<serde_json::Value>().await.unwrap();
        if value["halted"] == true {
            halted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(halted, "source reorganization did not halt destination");
    assert_eq!(
        client
            .get(format!(
                "{a}/v1/destination-pow-candidate/balance/{}",
                recipient.public_key
            ))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(!client
        .post(format!("{a}/v1/destination-pow-candidate/verify-receipt"))
        .json(&verify_request)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
    assert!(f.dir.join("receiver-destination-store/HALTED").exists());
}

#[test]
fn destination_authorization_cli_and_process_gate_fail_closed() {
    let mut f = Fixture::new();
    let context = DestinationContext {
        chain_id: Hash([91; 32]),
        source_policy: ObservationPolicy {
            source_chain_id: f.chain_id,
            accepted_v1_tip: f.v1_chain.tip(),
            minimum_confirmations: 2,
            minimum_cumulative_work: header_work(target_limit()),
        },
        started_at: now() - 10,
        initial_target: target_limit(),
        source_finality: None,
    };
    let context_file = f.dir.join("destination-context.json");
    std::fs::write(&context_file, serde_json::to_vec(&context).unwrap()).unwrap();
    f.authorize_destination(&context);
    let authorization_file = f.dir.join("destination-authorization.json");
    let authorization: DestinationGenesisAuthorization =
        serde_json::from_slice(&std::fs::read(&authorization_file).unwrap()).unwrap();
    let command = env!("CARGO_BIN_EXE_rld-earth-destination-authorization");
    let draft = Command::new(command)
        .args(["draft", "--destination-context"])
        .arg(&context_file)
        .arg("--transition-preview")
        .arg(f.dir.join("transition-preview.json"))
        .output()
        .unwrap();
    assert!(draft.status.success());
    let drafted: serde_json::Value = serde_json::from_slice(&draft.stdout).unwrap();
    assert_eq!(
        drafted["statement_id"],
        f.destination_authorization.unwrap().to_hex()
    );
    assert_eq!(
        drafted["signing_bytes_hex"],
        hex::encode(authorization.statement.signing_bytes().unwrap())
    );
    let assembled = Command::new(command)
        .args(["assemble", "--destination-context"])
        .arg(&context_file)
        .arg("--transition-preview")
        .arg(f.dir.join("transition-preview.json"))
        .args([
            "--accept-destination-authorization",
            &f.destination_authorization.unwrap().to_hex(),
        ])
        .args([
            "--signer-public-key",
            f.destination_signer.as_ref().unwrap(),
        ])
        .args(["--signature", &authorization.signature])
        .output()
        .unwrap();
    assert!(assembled.status.success());
    assert_eq!(
        assembled.stdout,
        std::fs::read(&authorization_file).unwrap()
    );

    let bad_context_file = f.dir.join("changed-destination-context.json");
    let mut bad_context = context.clone();
    bad_context.started_at += 1;
    std::fs::write(&bad_context_file, serde_json::to_vec(&bad_context).unwrap()).unwrap();
    let bad_signature_file = f.dir.join("bad-destination-signature.json");
    let mut bad_signature = authorization.clone();
    bad_signature.signature = "00".into();
    std::fs::write(
        &bad_signature_file,
        bad_signature.canonical_bytes().unwrap(),
    )
    .unwrap();
    let noncanonical_file = f.dir.join("noncanonical-destination-authorization.json");
    let mut noncanonical = authorization.canonical_bytes().unwrap();
    noncanonical.push(b'\n');
    std::fs::write(&noncanonical_file, noncanonical).unwrap();
    let other_signer = generate_identity();
    let cases = [
        (
            "wrong-id",
            context_file.as_path(),
            authorization_file.as_path(),
            Hash([7; 32]),
            f.destination_signer.as_ref().unwrap().as_str(),
        ),
        (
            "wrong-signer",
            context_file.as_path(),
            authorization_file.as_path(),
            f.destination_authorization.unwrap(),
            other_signer.public_key.as_str(),
        ),
        (
            "changed-context",
            bad_context_file.as_path(),
            authorization_file.as_path(),
            f.destination_authorization.unwrap(),
            f.destination_signer.as_ref().unwrap().as_str(),
        ),
        (
            "bad-signature",
            context_file.as_path(),
            bad_signature_file.as_path(),
            f.destination_authorization.unwrap(),
            f.destination_signer.as_ref().unwrap().as_str(),
        ),
        (
            "noncanonical",
            context_file.as_path(),
            noncanonical_file.as_path(),
            f.destination_authorization.unwrap(),
            f.destination_signer.as_ref().unwrap().as_str(),
        ),
    ];
    for (name, context, authorization, id, signer) in cases {
        let source_dir = f.dir.join(format!("{name}-source"));
        let destination_dir = f.dir.join(format!("{name}-destination"));
        let result = Command::new(env!("CARGO_BIN_EXE_rld-earth-destination-node"))
            .arg("--genesis")
            .arg(f.dir.join("genesis.json"))
            .arg("--history")
            .arg(f.dir.join("history.json"))
            .arg("--adoption")
            .arg(f.dir.join("adoption.json"))
            .args(["--manifest-pin", &f.pin.to_hex()])
            .args(["--accept-adoption", &f.adoption.to_hex()])
            .args(["--pinned-v1-source", &f.source.to_hex()])
            .arg("--v1-data-dir")
            .arg(f.dir.join("b-v1"))
            .arg("--transition-preview")
            .arg(f.dir.join("transition-preview.json"))
            .args([
                "--accept-transition-preview",
                &f.transition_preview.to_hex(),
            ])
            .arg("--source-candidate-dir")
            .arg(&source_dir)
            .args(["--source-node", "http://127.0.0.1:9/"])
            .arg("--destination-context")
            .arg(context)
            .arg("--destination-authorization")
            .arg(authorization)
            .args(["--accept-destination-authorization", &id.to_hex()])
            .args(["--destination-signer", signer])
            .arg("--destination-dir")
            .arg(&destination_dir)
            .args(["--listen", "127.0.0.1:0", "--offline-v1-copy"])
            .output()
            .unwrap();
        assert!(
            !result.status.success(),
            "{name} unexpectedly accepted destination authorization"
        );
        assert!(!source_dir.exists(), "{name} opened source value store");
        assert!(
            !destination_dir.exists(),
            "{name} opened destination value store"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn candidate_auto_miner_replays_after_restart() {
    let mut f = Fixture::new();
    let client = reqwest::Client::new();
    let a = f.launch("a", None, true);
    let first = status(&client, &a, f.v1_height + 1).await;
    assert_eq!(first["live_rld"], false);
    let checkpoint: serde_json::Value = client
        .post(format!("{a}/v1/successor-candidate/checkpoint"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(checkpoint["blocks_pruned"], false);
    let checkpoint_path = f.dir.join("a-candidate").join("CHECKPOINT");
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&checkpoint_path).unwrap()).unwrap();
    assert_eq!(saved["tip"], checkpoint["checkpoint"]);
    assert_eq!(saved["state_root"], checkpoint["state_root"]);
    f.stop(0);
    let restarted = f.launch("a", None, false);
    let replayed = status(&client, &restarted, f.v1_height + 1).await;
    assert!(
        replayed["height"]
            .as_str()
            .unwrap()
            .parse::<u128>()
            .unwrap()
            >= first["height"].as_str().unwrap().parse::<u128>().unwrap()
    );
    assert_eq!(replayed["storage_healthy"], true);
    assert!(
        replayed["height"]
            .as_str()
            .unwrap()
            .parse::<u128>()
            .unwrap()
            >= checkpoint["height"]
                .as_str()
                .unwrap()
                .parse::<u128>()
                .unwrap()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_channel_commands_relay_both_ways_and_survive_restart() {
    let mut f = Fixture::with_v1_blocks(109);
    let open = |(input, coin_amount): (OutPoint, Amount)| {
        let receiver = generate_identity();
        let capacity = Amount::from_rld_whole(1).unwrap();
        let intent = OpenIntent {
            chain_id: f.chain_id,
            input,
            party_a: f.owner.clone(),
            party_b: receiver.public_key.clone(),
            capacity,
            close_fee: Amount(1),
            opening_fee: Amount(1),
            change: coin_amount
                .checked_sub(capacity.checked_add(Amount(1)).unwrap())
                .unwrap(),
            valid_through_height: u128::MAX,
        };
        let funding = intent.funding().unwrap();
        let state = ChannelState::initial(&funding).unwrap();
        let signing_bytes = state.signing_bytes(&funding).unwrap();
        let initial = SignedState {
            state,
            signature_a: sign_bytes(&f.owner_secret, &signing_bytes).unwrap(),
            signature_b: sign_bytes(&receiver.secret_key, &signing_bytes).unwrap(),
        };
        (
            CandidateCommand::Open(OpenChannel {
                signature_a: sign_bytes(&f.owner_secret, &intent.signing_bytes().unwrap()).unwrap(),
                intent,
                initial,
            }),
            funding.id().unwrap(),
        )
    };
    let (first, first_channel) = open(f.mature_input.clone().unwrap());
    let (second, second_channel) = open(f.mature_fee_input.clone().unwrap());
    let recipient = generate_identity();
    let extra_transfers = f
        .v1_chain
        .state()
        .coins
        .iter()
        .filter(|(point, coin)| {
            coin.output.owner == f.owner
                && coin.spendable_height <= f.v1_height + 1
                && *point != &f.mature_input.as_ref().unwrap().0
                && *point != &f.mature_fee_input.as_ref().unwrap().0
        })
        .take(7)
        .map(|(point, coin)| {
            let mut transfer = Transfer {
                chain_id: f.chain_id,
                owner: f.owner.clone(),
                inputs: vec![point.clone()],
                outputs: vec![Output {
                    owner: recipient.public_key.clone(),
                    amount: coin.output.amount.checked_sub(Amount(1)).unwrap(),
                }],
                fee: Amount(1),
                valid_through_height: u128::MAX,
                signature: String::new(),
            };
            transfer.signature =
                sign_bytes(&f.owner_secret, &transfer.signing_bytes().unwrap()).unwrap();
            CandidateCommand::Transfer(transfer)
        })
        .collect::<Vec<_>>();
    assert_eq!(extra_transfers.len(), 7);
    let a_socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let a_addr = a_socket.local_addr().unwrap();
    let b_socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let b_addr = b_socket.local_addr().unwrap();
    drop(a_socket);
    drop(b_socket);
    let a_url = format!("http://{a_addr}");
    let b_url = format!("http://{b_addr}");
    f.launch_at("a", Some(&b_url), false, a_addr);
    f.launch_at("b", Some(&a_url), false, b_addr);
    let client = reqwest::Client::new();
    let a_ready = status(&client, &a_url, f.v1_height).await;
    assert_eq!(
        a_ready["transition_authorization_id"],
        f.transition_authorization.to_hex()
    );
    status(&client, &b_url, f.v1_height).await;
    let mut invalid = first.clone();
    if let CandidateCommand::Open(opening) = &mut invalid {
        opening.signature_a = "00".into();
    }
    assert!(!client
        .post(format!("{a_url}/v1/successor-candidate/commands"))
        .json(&invalid)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
    let first_result: serde_json::Value = client
        .post(format!("{a_url}/v1/successor-candidate/commands"))
        .json(&first)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let second_result: serde_json::Value = client
        .post(format!("{b_url}/v1/successor-candidate/commands"))
        .json(&second)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(first_result["newly_submitted"], true);
    assert_eq!(second_result["newly_submitted"], true);
    let first_id = first_result["command"].as_str().unwrap();
    let second_id = second_result["command"].as_str().unwrap();
    let mut extra_ids = Vec::new();
    for command in &extra_transfers {
        let result: serde_json::Value = client
            .post(format!("{a_url}/v1/successor-candidate/commands"))
            .json(command)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(result["newly_submitted"], true);
        extra_ids.push(result["command"].as_str().unwrap().to_owned());
    }
    let mut propagated = false;
    for _ in 0..200 {
        let a = status(&client, &a_url, f.v1_height).await;
        let b = status(&client, &b_url, f.v1_height).await;
        if a["submitted_candidate_commands"] == 9 && b["submitted_candidate_commands"] == 9 {
            propagated = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(propagated, "pending commands did not propagate both ways");
    for url in [&a_url, &b_url] {
        let page: serde_json::Value = client
            .post(format!("{url}/v1/successor-candidate/pending"))
            .json(&serde_json::json!({"offset":0}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(page["transition_preview_id"], f.transition_preview.to_hex());
        assert_eq!(page["commands"].as_array().unwrap().len(), 8);
        assert_eq!(page["next_offset"], 8);
        let next: serde_json::Value = client
            .post(format!("{url}/v1/successor-candidate/pending"))
            .json(&serde_json::json!({"offset":8}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(next["commands"].as_array().unwrap().len(), 1);
        assert!(next["next_offset"].is_null());
        assert!(!client
            .post(format!("{url}/v1/successor-candidate/pending"))
            .json(&serde_json::json!({"offset":129}))
            .send()
            .await
            .unwrap()
            .status()
            .is_success());
    }
    f.stop(0);
    f.launch_at("a", Some(&b_url), false, a_addr);
    let replayed = status(&client, &a_url, f.v1_height).await;
    assert_eq!(replayed["submitted_candidate_commands"], 9);
    f.stop(1);
    f.launch_at("b", Some(&a_url), true, b_addr);
    included_command(&client, &b_url, first_id).await;
    included_command(&client, &b_url, second_id).await;
    included_command(&client, &a_url, first_id).await;
    included_command(&client, &a_url, second_id).await;
    for id in &extra_ids {
        included_command(&client, &b_url, id).await;
        included_command(&client, &a_url, id).await;
    }
    let first_a = escrow(&client, &a_url, first_channel).await;
    let second_a = escrow(&client, &a_url, second_channel).await;
    assert_eq!(first_a["live_rld"], false);
    assert_eq!(second_a["live_rld"], false);
    let isolated = f.launch("receiver", None, false);
    status(&client, &isolated, f.v1_height).await;
    assert_eq!(
        client
            .post(format!("{isolated}/v1/successor-candidate/commands"))
            .json(&first)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_channel_dispute_is_durably_mined_and_synced() {
    let mut f = Fixture::with_v1_blocks(101);
    let receiver = generate_identity();
    let (input, coin_amount) = f.mature_input.clone().expect("mature v1 reward");
    let capacity = Amount::from_rld_whole(1).unwrap();
    let intent = OpenIntent {
        chain_id: f.chain_id,
        input,
        party_a: f.owner.clone(),
        party_b: receiver.public_key.clone(),
        capacity,
        close_fee: Amount(1),
        opening_fee: Amount(1),
        change: coin_amount
            .checked_sub(capacity.checked_add(Amount(1)).unwrap())
            .unwrap(),
        valid_through_height: u128::MAX,
    };
    let opening_change = intent.change;
    let funding = intent.funding().unwrap();
    let state = ChannelState::initial(&funding).unwrap();
    let signing_bytes = state.signing_bytes(&funding).unwrap();
    let initial = SignedState {
        state,
        signature_a: sign_bytes(&f.owner_secret, &signing_bytes).unwrap(),
        signature_b: sign_bytes(&receiver.secret_key, &signing_bytes).unwrap(),
    };
    let command = CandidateCommand::Open(OpenChannel {
        signature_a: sign_bytes(&f.owner_secret, &intent.signing_bytes().unwrap()).unwrap(),
        intent,
        initial: initial.clone(),
    });
    let client = reqwest::Client::new();
    let a = f.launch("a", None, true);
    let b = f.launch("b", Some(&a), false);
    status(&client, &a, f.v1_height).await;
    status(&client, &b, f.v1_height).await;
    let mut invalid = command.clone();
    if let CandidateCommand::Open(open) = &mut invalid {
        open.signature_a = "00".into();
    }
    assert!(!client
        .post(format!("{a}/v1/successor-candidate/commands"))
        .json(&invalid)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
    let submitted: serde_json::Value = client
        .post(format!("{a}/v1/successor-candidate/commands"))
        .json(&command)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(submitted["newly_submitted"], true);
    assert_eq!(submitted["confirmed"], false);
    let command_id = submitted["command"].as_str().unwrap();
    let duplicate: serde_json::Value = client
        .post(format!("{a}/v1/successor-candidate/commands"))
        .json(&command)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(duplicate["newly_submitted"], false);
    assert_eq!(duplicate["command"], command_id);
    let id = funding.id().unwrap();
    let opened_a = escrow(&client, &a, id).await;
    let included: serde_json::Value = client
        .get(format!("{a}/v1/successor-candidate/commands/{command_id}"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(included["candidate_included"], true);
    assert_eq!(included["live_rld"], false);
    assert_eq!(
        opened_a["escrow"]["funding"],
        serde_json::to_value(&funding).unwrap()
    );
    assert_eq!(opened_a["live_rld"], false);
    let opened_b = escrow(&client, &b, id).await;
    assert_eq!(opened_b["escrow"]["funding"], opened_a["escrow"]["funding"]);
    let (fee_input, fee_source_amount) =
        f.mature_fee_input.clone().expect("second mature v1 reward");
    let fee_balance = Amount(10);
    let mut fee_funding_tx = Transfer {
        chain_id: f.chain_id,
        owner: f.owner.clone(),
        inputs: vec![fee_input],
        outputs: vec![
            Output {
                owner: receiver.public_key.clone(),
                amount: fee_balance,
            },
            Output {
                owner: f.owner.clone(),
                amount: fee_source_amount
                    .checked_sub(fee_balance.checked_add(Amount(1)).unwrap())
                    .unwrap(),
            },
        ],
        fee: Amount(1),
        valid_through_height: u128::MAX,
        signature: String::new(),
    };
    fee_funding_tx.signature =
        sign_bytes(&f.owner_secret, &fee_funding_tx.signing_bytes().unwrap()).unwrap();
    let receiver_fee_input = OutPoint {
        transaction: fee_funding_tx.id().unwrap(),
        index: 0,
    };
    let submitted_fee: serde_json::Value = client
        .post(format!("{a}/v1/successor-candidate/commands"))
        .json(&CandidateCommand::Transfer(fee_funding_tx))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    included_command(&client, &a, submitted_fee["command"].as_str().unwrap()).await;
    let reserve_intent = ChallengeFeeReserveIntent {
        chain_id: f.chain_id,
        channel: id,
        input: receiver_fee_input.clone(),
        owner: receiver.public_key.clone(),
    };
    let reserve = CandidateCommand::ReserveChallengeFee(ChallengeFeeReserve {
        owner_signature: sign_bytes(
            &receiver.secret_key,
            &reserve_intent.signing_bytes().unwrap(),
        )
        .unwrap(),
        intent: reserve_intent,
    });
    let submitted_reserve: serde_json::Value = client
        .post(format!("{a}/v1/successor-candidate/commands"))
        .json(&reserve)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let reserve_id = submitted_reserve["command"].as_str().unwrap();
    included_command(&client, &a, reserve_id).await;
    let mut confirmed_reserve = false;
    for _ in 0..120 {
        let value: serde_json::Value = client
            .get(format!("{a}/v1/successor-candidate/commands/{reserve_id}"))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        if value["candidate_confirmations"]
            .as_str()
            .and_then(|s| s.parse::<u128>().ok())
            .is_some_and(|n| n >= 2)
        {
            confirmed_reserve = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(confirmed_reserve, "challenge fee reservation not confirmed");
    let receiver_fee = |state: &SignedState| {
        let intent = ActionFeeIntent {
            chain_id: f.chain_id,
            action: DisputeAction::Challenge,
            channel: id,
            signed_state: signed_state_hash(state).unwrap(),
            input: receiver_fee_input.clone(),
            owner: receiver.public_key.clone(),
            fee: Amount(1),
            change: fee_balance.checked_sub(Amount(1)).unwrap(),
            valid_through_height: u128::MAX,
        };
        ActionFee {
            owner_signature: sign_bytes(&receiver.secret_key, &intent.signing_bytes().unwrap())
                .unwrap(),
            intent,
        }
    };
    let guarded_root = f.dir.join("guarded-recipient");
    let mut guarded = GuardedRecipient::open(
        &guarded_root,
        funding.clone(),
        receiver.public_key.clone(),
        initial.clone(),
        Some(receiver_fee(&initial)),
    )
    .unwrap();
    let watch_path = guarded_root.join("watch-package.json");
    let initial_watch_bytes = std::fs::read(&watch_path).unwrap();
    let watch_state = f.dir.join("watch-state");
    let watcher = generate_identity();
    let watcher_key = f.dir.join("watcher-key.json");
    let mut watch_key_options = OpenOptions::new();
    watch_key_options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        watch_key_options.mode(0o600);
    }
    let mut watch_key_file = watch_key_options.open(&watcher_key).unwrap();
    watch_key_file
        .write_all(&serde_json::to_vec(&watcher).unwrap())
        .unwrap();
    watch_key_file.sync_all().unwrap();
    let watcher_socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let watcher_addr = watcher_socket.local_addr().unwrap();
    drop(watcher_socket);
    let watcher_url = format!("http://{watcher_addr}");
    f.launch_watcher(&a, &watch_path, &watch_state, &watcher_key, watcher_addr);
    for _ in 0..100 {
        if std::fs::read_to_string(f.dir.join("watchtower.log"))
            .unwrap()
            .contains("watchtower loaded sequence 0")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(std::fs::read_to_string(f.dir.join("watchtower.log"))
        .unwrap()
        .contains("watchtower loaded sequence 0"));
    let offer = PaymentOffer::new(
        &funding,
        initial.clone(),
        f.owner.clone(),
        &f.owner_secret,
        Amount(100),
        Hash([7; 32]),
    )
    .unwrap();
    let observed = observed_candidate_chain(&f, &client, &a).await;
    let fee_funding = FeeFunding {
        input: receiver_fee_input.clone(),
        input_amount: fee_balance,
        fee: Amount(1),
        valid_through_height: u128::MAX,
    };
    let mut wrong_amount = fee_funding.clone();
    wrong_amount.input_amount = Amount(11);
    assert!(guarded
        .accept_offer(
            &observed,
            2,
            false,
            offer.clone(),
            &receiver.secret_key,
            wrong_amount
        )
        .is_err());
    assert_eq!(guarded.latest(), &initial);
    let mut expired = fee_funding.clone();
    expired.valid_through_height = observed.height() + 1;
    assert!(guarded
        .accept_offer(
            &observed,
            2,
            false,
            offer.clone(),
            &receiver.secret_key,
            expired
        )
        .is_err());
    assert_eq!(guarded.latest(), &initial);
    let mut absent = fee_funding.clone();
    absent.input.transaction = Hash([99; 32]);
    assert!(guarded
        .accept_offer(
            &observed,
            2,
            false,
            offer.clone(),
            &receiver.secret_key,
            absent
        )
        .is_err());
    assert_eq!(guarded.latest(), &initial);
    let receipt = guarded
        .accept_offer(
            &observed,
            2,
            false,
            offer,
            &receiver.secret_key,
            fee_funding,
        )
        .unwrap();
    assert_eq!(guarded.watch_package().state, receipt.updated);
    let first_package = guarded.watch_package().clone();
    let mut first_ack = None;
    for _ in 0..100 {
        if let Ok(response) = client
            .post(format!("{watcher_url}/v1/candidate-watchtower/packages"))
            .json(&first_package)
            .send()
            .await
        {
            if response.status().is_success() {
                first_ack = Some(response.json::<WatchAck>().await.unwrap());
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let first_delivery = WatchedReceipt {
        status: "UNADOPTED_LOCAL_CANDIDATE_ONLY".into(),
        live_rld: false,
        receipt: receipt.clone(),
        watch_package: first_package,
        watch_ack: first_ack.expect("watchtower did not acknowledge first receipt"),
    };
    let payer_root = f.dir.join("payer-wallet");
    let mut payer = WatchedPayer::open(
        &payer_root,
        funding.clone(),
        f.owner.clone(),
        initial.clone(),
        watcher.public_key.clone(),
    )
    .unwrap();
    let first_offer = payer
        .begin_payment(&f.owner_secret, Amount(100), Hash([7; 32]))
        .unwrap();
    assert_eq!(first_offer.proposed, receipt.updated.state);
    assert!(payer.complete_payment(&observed, first_delivery).unwrap());
    drop(guarded);

    let receiver_key = f.dir.join("receiver-key.json");
    let mut key_options = OpenOptions::new();
    key_options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        key_options.mode(0o600);
    }
    let mut key_file = key_options.open(&receiver_key).unwrap();
    key_file
        .write_all(&serde_json::to_vec(&receiver).unwrap())
        .unwrap();
    key_file.sync_all().unwrap();
    let config_path = f.dir.join("receiver-config.json");
    std::fs::write(
        &config_path,
        serde_json::to_vec(&serde_json::json!({
            "funding":funding,
            "initial":initial,
            "fee_input":receiver_fee_input,
            "fee_input_amount":fee_balance,
            "fee":Amount(1),
            "valid_through_height":u128::MAX.to_string()
        }))
        .unwrap(),
    )
    .unwrap();
    let payer_key = f.dir.join("payer-key.json");
    let mut payer_key_options = OpenOptions::new();
    payer_key_options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        payer_key_options.mode(0o600);
    }
    let mut payer_key_file = payer_key_options.open(&payer_key).unwrap();
    payer_key_file
        .write_all(
            &serde_json::to_vec(&rld_core::Identity {
                public_key: f.owner.clone(),
                secret_key: f.owner_secret.clone(),
            })
            .unwrap(),
        )
        .unwrap();
    payer_key_file.sync_all().unwrap();
    let payer_config = f.dir.join("payer-config.json");
    std::fs::write(
        &payer_config,
        serde_json::to_vec(&serde_json::json!({"funding":funding,"initial":initial})).unwrap(),
    )
    .unwrap();
    let receiver_socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let receiver_addr = receiver_socket.local_addr().unwrap();
    drop(receiver_socket);
    let receiver_url = f.launch_receiver(
        &a,
        (&watcher_url, &watcher.public_key),
        &guarded_root,
        &receiver_key,
        &config_path,
        receiver_addr,
    );
    let mut server_ready = false;
    for _ in 0..300 {
        if let Ok(response) = client
            .get(format!("{receiver_url}/v1/candidate-payment/status"))
            .send()
            .await
        {
            if response.status().is_success() {
                let value: serde_json::Value = response.json().await.unwrap();
                assert_eq!(value["receipt_sequence"], 1);
                assert_eq!(value["live_rld"], false);
                server_ready = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        server_ready,
        "candidate receiver failed: {}",
        std::fs::read_to_string(f.dir.join("receiver.log")).unwrap()
    );
    let payer_dir = f.dir.clone();
    let payer_pin = f.pin.to_hex();
    let payer_adoption = f.adoption.to_hex();
    let payer_source = f.source.to_hex();
    let payer_preview = f.transition_preview.to_hex();
    let second_payment_id = Hash([8; 32]).to_hex();
    let run_payer = |session: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rldsuccessor-payment-payer-candidate"));
        command
            .arg("--genesis")
            .arg(payer_dir.join("genesis.json"))
            .arg("--history")
            .arg(payer_dir.join("history.json"))
            .arg("--adoption")
            .arg(payer_dir.join("adoption.json"))
            .args(["--manifest-pin", &payer_pin])
            .args(["--accept-adoption", &payer_adoption])
            .args(["--pinned-v1-source", &payer_source])
            .arg("--v1-data-dir")
            .arg(payer_dir.join("payer-v1"))
            .arg("--transition-preview")
            .arg(payer_dir.join("transition-preview.json"))
            .args(["--accept-transition-preview", &payer_preview])
            .arg("--candidate-dir")
            .arg(payer_dir.join("payer-candidate"))
            .arg("--wallet-dir")
            .arg(&payer_root)
            .arg("--payer-key")
            .arg(&payer_key)
            .arg("--funding-config")
            .arg(&payer_config)
            .args(["--node", &a])
            .args(["--receiver", &receiver_url])
            .args(["--watcher-public-key", &watcher.public_key])
            .arg("--offline-v1-copy");
        if session {
            let mut child = command
                .arg("--session-stdin")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let mut requests = String::new();
            for byte in 8..28 {
                let id = Hash([byte; 32]).to_hex();
                requests.push_str(&format!(
                    "{{\"amount_runlai\":\"50\",\"payment_id\":\"{id}\"}}\n"
                ));
            }
            let last_id = Hash([27; 32]).to_hex();
            requests.push_str(&format!(
                "{{\"amount_runlai\":\"50\",\"payment_id\":\"{last_id}\"}}\n"
            ));
            child
                .stdin
                .take()
                .unwrap()
                .write_all(requests.as_bytes())
                .unwrap();
            child.wait_with_output().unwrap()
        } else {
            command
                .args(["--amount-runlai", "50"])
                .args(["--payment-id", &second_payment_id])
                .output()
                .unwrap()
        }
    };
    let second_offer = payer
        .begin_payment(&f.owner_secret, Amount(50), Hash([8; 32]))
        .unwrap();
    let mut invalid_offer = second_offer.clone();
    invalid_offer.amount = Amount(51);
    assert_eq!(
        client
            .post(format!("{receiver_url}/v1/candidate-payment/offers"))
            .json(&invalid_offer)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::CONFLICT
    );
    let send = || {
        client
            .post(format!("{receiver_url}/v1/candidate-payment/offers"))
            .json(&second_offer)
            .send()
    };
    drop(payer);
    f.stop(2);
    let failed_payer = run_payer(false);
    assert!(!failed_payer.status.success());
    assert!(
        String::from_utf8_lossy(&failed_payer.stderr).contains("signed offer remains pending"),
        "candidate payer failed before sending the pending offer: {}",
        String::from_utf8_lossy(&failed_payer.stderr)
    );
    let pending = WatchedPayer::open(
        &payer_root,
        funding.clone(),
        f.owner.clone(),
        initial.clone(),
        watcher.public_key.clone(),
    )
    .unwrap();
    assert_eq!(pending.pending(), Some(&second_offer));
    drop(pending);
    let without_watch = send().await.unwrap();
    assert_eq!(
        without_watch.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(!without_watch.text().await.unwrap().contains("receipt"));
    f.stop(3);
    f.launch_receiver(
        &a,
        (&watcher_url, &watcher.public_key),
        &guarded_root,
        &receiver_key,
        &config_path,
        receiver_addr,
    );
    let mut restarted_ready = false;
    for _ in 0..300 {
        if let Ok(response) = client
            .get(format!("{receiver_url}/v1/candidate-payment/status"))
            .send()
            .await
        {
            if response.status().is_success() {
                let value: serde_json::Value = response.json().await.unwrap();
                assert_eq!(value["receipt_sequence"], 2);
                restarted_ready = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        restarted_ready,
        "candidate receiver did not replay receipt after restart"
    );
    f.launch_watcher(&a, &watch_path, &watch_state, &watcher_key, watcher_addr);
    let mut watcher_ready = false;
    for _ in 0..100 {
        if let Ok(response) = client
            .get(format!("{watcher_url}/v1/candidate-watchtower/status"))
            .send()
            .await
        {
            if response.status().is_success() {
                watcher_ready = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(watcher_ready, "candidate watchtower did not restart");
    let successful_payer = run_payer(true);
    assert!(
        successful_payer.status.success(),
        "candidate payer failed: {}",
        String::from_utf8_lossy(&successful_payer.stderr)
    );
    let payer_lines: Vec<serde_json::Value> = successful_payer
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    assert_eq!(payer_lines.len(), 21);
    let payer_output = &payer_lines[0];
    assert_eq!(payer_output["previously_recorded"], false);
    assert_eq!(payer_output["sequence"], 2);
    assert_eq!(payer_output["live_rld"], false);
    assert!(payer_output["payer_request_to_record_ms"].is_number());
    let mut durations = Vec::new();
    for (index, line) in payer_lines.iter().take(20).enumerate() {
        assert_eq!(line["previously_recorded"], false);
        assert_eq!(line["sequence"], index + 2);
        durations.push(line["payer_request_to_record_ms"].as_u64().unwrap());
    }
    durations.sort_unstable();
    eprintln!(
        "isolated candidate payer request-to-record sample: n=20, p95={} ms, max={} ms",
        durations[18], durations[19]
    );
    assert_eq!(payer_lines[20]["previously_recorded"], true);
    assert_eq!(payer_lines[20]["sequence"], 21);
    let replay_payer = run_payer(false);
    assert!(replay_payer.status.success());
    let replay_output: serde_json::Value = serde_json::from_slice(&replay_payer.stdout).unwrap();
    assert_eq!(replay_output["previously_recorded"], true);
    let evidence_file = payer_lines[19]["evidence_file"].as_str().unwrap();
    let watched: WatchedReceipt =
        serde_json::from_slice(&std::fs::read(evidence_file).unwrap()).unwrap();
    watched
        .verify(&funding, &f.owner, &watcher.public_key)
        .unwrap();
    let mut forged = watched.clone();
    forged.watch_ack.signature = "00".into();
    assert!(forged
        .verify(&funding, &f.owner, &watcher.public_key)
        .is_err());
    let latest_receipt: PaymentReceipt = watched.receipt.clone();
    assert_eq!(latest_receipt.updated.state.sequence, 21);
    let payer = WatchedPayer::open(
        &payer_root,
        funding.clone(),
        f.owner.clone(),
        initial.clone(),
        watcher.public_key.clone(),
    )
    .unwrap();
    assert_eq!(payer.latest(), &latest_receipt.updated);
    assert_eq!(payer.recorded(Hash([27; 32])), Some(&watched));
    assert!(payer.recorded(Hash([8; 32])).is_some());
    drop(payer);
    let mut watch_saved = false;
    for _ in 0..100 {
        if std::fs::read(watch_state.join("latest.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .is_some_and(|value| value["state"]["state"]["sequence"] == 21)
        {
            watch_saved = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        watch_saved,
        "watchtower did not durably observe latest receipt"
    );
    let latest_watch_bytes = std::fs::read(&watch_path).unwrap();
    f.stop(5);
    // The merchant copy moves backward while the watchtower is down. Its
    // independent persisted package must still protect the newer receipt.
    std::fs::write(&watch_path, &initial_watch_bytes).unwrap();
    f.launch_watcher(&a, &watch_path, &watch_state, &watcher_key, watcher_addr);
    let mut watch_restarted = false;
    for _ in 0..100 {
        if std::fs::read_to_string(f.dir.join("watchtower.log"))
            .unwrap()
            .contains("watchtower loaded sequence 21")
        {
            watch_restarted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(watch_restarted, "watchtower did not resume latest state");
    let fee_for = |action: DisputeAction, state: &SignedState, input: OutPoint, amount: Amount| {
        let intent = ActionFeeIntent {
            chain_id: f.chain_id,
            action,
            channel: id,
            signed_state: signed_state_hash(state).unwrap(),
            input,
            owner: f.owner.clone(),
            fee: Amount(1),
            change: amount.checked_sub(Amount(1)).unwrap(),
            valid_through_height: u128::MAX,
        };
        ActionFee {
            owner_signature: sign_bytes(&f.owner_secret, &intent.signing_bytes().unwrap()).unwrap(),
            intent,
        }
    };
    let close_fee = fee_for(
        DisputeAction::Close,
        &initial,
        OutPoint {
            transaction: id,
            index: 1,
        },
        opening_change,
    );
    let close = CandidateCommand::Close {
        channel: id,
        state: initial.clone(),
        fee: close_fee,
    };
    let submitted_close: serde_json::Value = client
        .post(format!("{a}/v1/successor-candidate/commands"))
        .json(&close)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    included_command(&client, &a, submitted_close["command"].as_str().unwrap()).await;
    closing_state(&client, &a, id, 21).await;
    closing_state(&client, &b, id, 21).await;
    assert!(std::fs::read_to_string(f.dir.join("watchtower.log"))
        .unwrap()
        .contains("candidate watchtower challenge submitted"));
    f.stop(6);
    std::fs::write(&watch_path, latest_watch_bytes).unwrap();
    f.stop(4);
    let restored_guard =
        GuardedRecipient::open(&guarded_root, funding, receiver.public_key, initial, None).unwrap();
    assert_eq!(restored_guard.latest(), &latest_receipt.updated);
    drop(restored_guard);
    f.stop(0);
    let restarted = f.launch("a", None, false);
    let mut restart_ready = false;
    for _ in 0..600 {
        if let Ok(response) = client
            .get(format!("{restarted}/v1/successor-candidate/status"))
            .send()
            .await
        {
            if response.status().is_success() {
                restart_ready = true;
                break;
            }
        }
        if let Some(exit) = f.children.last_mut().unwrap().try_wait().unwrap() {
            panic!(
                "candidate node exited during replay ({exit}): {}",
                std::fs::read_to_string(f.dir.join("a.log")).unwrap()
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        restart_ready,
        "candidate node replay exceeded restart budget"
    );
    let replayed = closing_state(&client, &restarted, id, 21).await;
    assert_eq!(replayed["escrow"]["funding"], opened_a["escrow"]["funding"]);
    assert_eq!(
        status(&client, &restarted, f.v1_height + 1).await["submitted_candidate_commands"],
        5
    );
}

#[test]
fn process_rejects_wrong_v1_release_pin_and_public_listener() {
    let f = Fixture::new();
    let run = |source: Hash, listener: &str| {
        Command::new(env!("CARGO_BIN_EXE_rld-earth-node"))
            .arg("run")
            .arg("--genesis")
            .arg(f.dir.join("genesis.json"))
            .arg("--history")
            .arg(f.dir.join("history.json"))
            .arg("--adoption")
            .arg(f.dir.join("adoption.json"))
            .arg("--manifest-pin")
            .arg(f.pin.to_hex())
            .arg("--accept-adoption")
            .arg(f.adoption.to_hex())
            .arg("--pinned-v1-source")
            .arg(source.to_hex())
            .arg("--v1-data-dir")
            .arg(f.dir.join("a-v1"))
            .arg("--transition-preview")
            .arg(f.dir.join("transition-preview.json"))
            .arg("--accept-transition-preview")
            .arg(f.transition_preview.to_hex())
            .arg("--transition-authorization")
            .arg(f.dir.join("transition-authorization.json"))
            .arg("--accept-transition-authorization")
            .arg(f.transition_authorization.to_hex())
            .arg("--transition-signer")
            .arg(&f.transition_signer)
            .arg("--candidate-dir")
            .arg(f.dir.join("rejected-candidate"))
            .arg("--listen")
            .arg(listener)
            .arg("--offline-v1-copy")
            .output()
            .unwrap()
    };
    let wrong_source = run(Hash([9; 32]), "127.0.0.1:0");
    assert!(!wrong_source.status.success());
    assert!(String::from_utf8_lossy(&wrong_source.stderr)
        .contains("transition does not bind the pinned release source"));
    let public = run(f.source, "0.0.0.0:0");
    assert!(!public.status.success());
    assert!(String::from_utf8_lossy(&public.stderr).contains("loopback only"));
    assert!(!f.dir.join("rejected-candidate").exists());
}

#[test]
fn transition_preview_cli_roundtrip_and_candidate_refuses_changed_acceptance() {
    let f = Fixture::new();
    let preview = Command::new(env!(
        "CARGO_BIN_EXE_rldsuccessor-transition-preview-candidate"
    ))
    .arg("--genesis")
    .arg(f.dir.join("genesis.json"))
    .arg("--history")
    .arg(f.dir.join("history.json"))
    .arg("--adoption")
    .arg(f.dir.join("adoption.json"))
    .arg("--manifest-pin")
    .arg(f.pin.to_hex())
    .arg("--accept-adoption")
    .arg(f.adoption.to_hex())
    .arg("--pinned-v1-source")
    .arg(f.source.to_hex())
    .arg("--v1-data-dir")
    .arg(f.dir.join("a-v1"))
    .arg("--offline-v1-copy")
    .output()
    .unwrap();
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stderr)
    );
    assert_eq!(
        preview.stdout,
        std::fs::read(f.dir.join("transition-preview.json")).unwrap()
    );
    assert!(String::from_utf8_lossy(&preview.stderr).contains(&f.transition_preview.to_hex()));
    let authorization_path = f.dir.join("transition-authorization.json");
    let authorization: TransitionAuthorization =
        serde_json::from_slice(&std::fs::read(&authorization_path).unwrap()).unwrap();
    let draft = Command::new(env!(
        "CARGO_BIN_EXE_rldsuccessor-transition-authorization-candidate"
    ))
    .arg("draft")
    .arg("--transition-preview")
    .arg(f.dir.join("transition-preview.json"))
    .output()
    .unwrap();
    assert!(draft.status.success());
    let draft: serde_json::Value = serde_json::from_slice(&draft.stdout).unwrap();
    assert_eq!(draft["statement_id"], f.transition_authorization.to_hex());
    assert_eq!(
        draft["signing_bytes_hex"],
        hex::encode(authorization.statement.signing_bytes().unwrap())
    );
    let assembled = Command::new(env!(
        "CARGO_BIN_EXE_rldsuccessor-transition-authorization-candidate"
    ))
    .arg("assemble")
    .arg("--transition-preview")
    .arg(f.dir.join("transition-preview.json"))
    .arg("--accept-transition-authorization")
    .arg(f.transition_authorization.to_hex())
    .arg("--signer-public-key")
    .arg(&f.transition_signer)
    .arg("--signature")
    .arg(&authorization.signature)
    .output()
    .unwrap();
    assert!(assembled.status.success());
    assert_eq!(assembled.stdout, std::fs::read(authorization_path).unwrap());

    let bad_path = f.dir.join("bad-transition-preview.json");
    let run = |path: &Path, id: Hash, target: &str| {
        Command::new(env!("CARGO_BIN_EXE_rld-earth-node"))
            .arg("run")
            .arg("--genesis")
            .arg(f.dir.join("genesis.json"))
            .arg("--history")
            .arg(f.dir.join("history.json"))
            .arg("--adoption")
            .arg(f.dir.join("adoption.json"))
            .arg("--manifest-pin")
            .arg(f.pin.to_hex())
            .arg("--accept-adoption")
            .arg(f.adoption.to_hex())
            .arg("--pinned-v1-source")
            .arg(f.source.to_hex())
            .arg("--v1-data-dir")
            .arg(f.dir.join("a-v1"))
            .arg("--transition-preview")
            .arg(path)
            .arg("--accept-transition-preview")
            .arg(id.to_hex())
            .arg("--transition-authorization")
            .arg(f.dir.join("transition-authorization.json"))
            .arg("--accept-transition-authorization")
            .arg(f.transition_authorization.to_hex())
            .arg("--transition-signer")
            .arg(&f.transition_signer)
            .arg("--candidate-dir")
            .arg(f.dir.join(target))
            .arg("--listen")
            .arg("127.0.0.1:0")
            .arg("--offline-v1-copy")
            .output()
            .unwrap()
    };
    let good_path = f.dir.join("transition-preview.json");
    let wrong_id = run(&good_path, Hash([7; 32]), "wrong-id-candidate");
    assert!(!wrong_id.status.success());
    assert!(String::from_utf8_lossy(&wrong_id.stderr).contains("transition preview"));
    assert!(!f.dir.join("wrong-id-candidate").exists());

    let mut changed: TransitionPreview = serde_json::from_slice(&preview.stdout).unwrap();
    changed.v1_emitted = Amount::ZERO;
    std::fs::write(&bad_path, changed.canonical_bytes().unwrap()).unwrap();
    let changed_result = run(&bad_path, changed.id().unwrap(), "changed-candidate");
    assert!(!changed_result.status.success());
    assert!(String::from_utf8_lossy(&changed_result.stderr).contains("transition preview"));
    assert!(!f.dir.join("changed-candidate").exists());

    let mut noncanonical = preview.stdout.clone();
    noncanonical.push(b'\n');
    std::fs::write(&bad_path, noncanonical).unwrap();
    let changed_result = run(&bad_path, f.transition_preview, "noncanonical-candidate");
    assert!(!changed_result.status.success());
    assert!(String::from_utf8_lossy(&changed_result.stderr).contains("canonical bytes"));
    assert!(!f.dir.join("noncanonical-candidate").exists());
}

#[test]
fn candidate_rejects_unpinned_or_corrupt_transition_authorization_before_value_store() {
    let f = Fixture::new();
    let original_path = f.dir.join("transition-authorization.json");
    let original: TransitionAuthorization =
        serde_json::from_slice(&std::fs::read(&original_path).unwrap()).unwrap();
    let run = |path: &Path, id: Hash, signer: &str, name: &str| {
        Command::new(env!("CARGO_BIN_EXE_rld-earth-node"))
            .arg("run")
            .arg("--genesis")
            .arg(f.dir.join("genesis.json"))
            .arg("--history")
            .arg(f.dir.join("history.json"))
            .arg("--adoption")
            .arg(f.dir.join("adoption.json"))
            .arg("--manifest-pin")
            .arg(f.pin.to_hex())
            .arg("--accept-adoption")
            .arg(f.adoption.to_hex())
            .arg("--pinned-v1-source")
            .arg(f.source.to_hex())
            .arg("--v1-data-dir")
            .arg(f.dir.join("a-v1"))
            .arg("--transition-preview")
            .arg(f.dir.join("transition-preview.json"))
            .arg("--accept-transition-preview")
            .arg(f.transition_preview.to_hex())
            .arg("--transition-authorization")
            .arg(path)
            .arg("--accept-transition-authorization")
            .arg(id.to_hex())
            .arg("--transition-signer")
            .arg(signer)
            .arg("--candidate-dir")
            .arg(f.dir.join(name))
            .arg("--listen")
            .arg("127.0.0.1:0")
            .arg("--offline-v1-copy")
            .output()
            .unwrap()
    };
    let wrong_id = run(
        &original_path,
        Hash([7; 32]),
        &f.transition_signer,
        "wrong-auth-id",
    );
    assert!(!wrong_id.status.success());
    assert!(String::from_utf8_lossy(&wrong_id.stderr).contains("authorization statement"));
    assert!(!f.dir.join("wrong-auth-id").exists());

    let other = generate_identity();
    let wrong_signer = run(
        &original_path,
        f.transition_authorization,
        &other.public_key,
        "wrong-auth-signer",
    );
    assert!(!wrong_signer.status.success());
    assert!(String::from_utf8_lossy(&wrong_signer.stderr).contains("signer differs"));
    assert!(!f.dir.join("wrong-auth-signer").exists());

    let mut forged = original.clone();
    forged.signature = "00".into();
    let forged_path = f.dir.join("forged-transition-authorization.json");
    std::fs::write(&forged_path, forged.canonical_bytes().unwrap()).unwrap();
    let forged_result = run(
        &forged_path,
        f.transition_authorization,
        &f.transition_signer,
        "forged-auth",
    );
    assert!(!forged_result.status.success());
    assert!(!f.dir.join("forged-auth").exists());

    let mut changed = original;
    changed.statement.v1_tip = Hash([8; 32]);
    let changed_path = f.dir.join("changed-transition-authorization.json");
    std::fs::write(&changed_path, changed.canonical_bytes().unwrap()).unwrap();
    let changed_result = run(
        &changed_path,
        changed.statement.id().unwrap(),
        &f.transition_signer,
        "changed-auth",
    );
    assert!(!changed_result.status.success());
    assert!(!f.dir.join("changed-auth").exists());

    let mut noncanonical = std::fs::read(original_path).unwrap();
    noncanonical.push(b'\n');
    std::fs::write(&changed_path, noncanonical).unwrap();
    let noncanonical_result = run(
        &changed_path,
        f.transition_authorization,
        &f.transition_signer,
        "noncanonical-auth",
    );
    assert!(!noncanonical_result.status.success());
    assert!(String::from_utf8_lossy(&noncanonical_result.stderr).contains("canonical bytes"));
    assert!(!f.dir.join("noncanonical-auth").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn candidate_value_clients_reject_wrong_transition_preview_before_opening_stores() {
    let mut f = Fixture::new();
    let node = f.launch("a", None, false);
    let client = reqwest::Client::new();
    status(&client, &node, f.v1_height).await;
    let wrong = Hash([7; 32]).to_hex();
    let watcher = generate_identity();
    let common = |binary: &str, v1_name: &str, candidate_name: &str| {
        let mut command = Command::new(binary);
        command
            .arg("--genesis")
            .arg(f.dir.join("genesis.json"))
            .arg("--history")
            .arg(f.dir.join("history.json"))
            .arg("--adoption")
            .arg(f.dir.join("adoption.json"))
            .args(["--manifest-pin", &f.pin.to_hex()])
            .args(["--accept-adoption", &f.adoption.to_hex()])
            .args(["--pinned-v1-source", &f.source.to_hex()])
            .arg("--v1-data-dir")
            .arg(f.dir.join(v1_name))
            .arg("--transition-preview")
            .arg(f.dir.join("transition-preview.json"))
            .args(["--accept-transition-preview", &wrong])
            .arg("--offline-v1-copy");
        assert!(!f.dir.join(candidate_name).exists());
        command
    };

    let mut payer = common(
        env!("CARGO_BIN_EXE_rldsuccessor-payment-payer-candidate"),
        "payer-v1",
        "wrong-payer-candidate",
    );
    let payer_result = payer
        .args(["--node", &node, "--receiver", &node])
        .args(["--watcher-public-key", &watcher.public_key])
        .args([
            "--amount-runlai",
            "1",
            "--payment-id",
            &Hash([8; 32]).to_hex(),
        ])
        .arg("--candidate-dir")
        .arg(f.dir.join("wrong-payer-candidate"))
        .arg("--wallet-dir")
        .arg(f.dir.join("wrong-payer-wallet"))
        .args([
            "--payer-key",
            "/missing/key",
            "--funding-config",
            "/missing/config",
        ])
        .output()
        .unwrap();
    assert!(!payer_result.status.success());
    assert!(String::from_utf8_lossy(&payer_result.stderr).contains("transition preview"));
    assert!(!f.dir.join("wrong-payer-candidate").exists());
    assert!(!f.dir.join("wrong-payer-wallet").exists());

    let mut receiver = common(
        env!("CARGO_BIN_EXE_rldsuccessor-payment-receiver-candidate"),
        "receiver-v1",
        "wrong-receiver-candidate",
    );
    let receiver_result = receiver
        .args(["--node", &node, "--watchtower", &node])
        .args(["--watcher-public-key", &watcher.public_key])
        .args(["--listen", "127.0.0.1:0"])
        .arg("--candidate-dir")
        .arg(f.dir.join("wrong-receiver-candidate"))
        .arg("--wallet-dir")
        .arg(f.dir.join("wrong-receiver-wallet"))
        .args([
            "--receiver-key",
            "/missing/key",
            "--funding-config",
            "/missing/config",
        ])
        .output()
        .unwrap();
    assert!(!receiver_result.status.success());
    assert!(String::from_utf8_lossy(&receiver_result.stderr).contains("transition preview"));
    assert!(!f.dir.join("wrong-receiver-candidate").exists());
    assert!(!f.dir.join("wrong-receiver-wallet").exists());

    let mut destination = common(
        env!("CARGO_BIN_EXE_rld-earth-destination-node"),
        "b-v1",
        "wrong-destination-source",
    );
    let destination_result = destination
        .args(["--source-node", &node])
        .arg("--source-candidate-dir")
        .arg(f.dir.join("wrong-destination-source"))
        .args(["--destination-context", "/missing/context"])
        .args(["--destination-authorization", "/missing/authorization"])
        .args(["--accept-destination-authorization", "00"])
        .args(["--destination-signer", "00"])
        .arg("--destination-dir")
        .arg(f.dir.join("wrong-destination-store"))
        .args(["--listen", "127.0.0.1:0"])
        .output()
        .unwrap();
    assert!(!destination_result.status.success());
    assert!(String::from_utf8_lossy(&destination_result.stderr).contains("transition preview"));
    assert!(!f.dir.join("wrong-destination-source").exists());
    assert!(!f.dir.join("wrong-destination-store").exists());

    let watcher_result = Command::new(env!("CARGO_BIN_EXE_rld-earth-watchtower"))
        .args(["--node", &node, "--accept-transition-preview", &wrong])
        .args([
            "--package",
            "/missing/package",
            "--watch-state-dir",
            "/missing/watch",
        ])
        .args(["--ack-key", "/missing/key", "--listen", "127.0.0.1:0"])
        .output()
        .unwrap();
    assert!(!watcher_result.status.success());
    assert!(String::from_utf8_lossy(&watcher_result.stderr).contains("transition preview"));
}

#[test]
fn candidate_receiver_refuses_public_listener_and_remote_node_before_reading_keys() {
    let run = |listener: &str, node: &str, offline: bool| {
        let mut command = Command::new(env!(
            "CARGO_BIN_EXE_rldsuccessor-payment-receiver-candidate"
        ));
        command
            .args(["--genesis", "/missing/genesis"])
            .args(["--history", "/missing/history"])
            .args(["--adoption", "/missing/adoption"])
            .args(["--manifest-pin", "00"])
            .args(["--accept-adoption", "00"])
            .args(["--pinned-v1-source", "00"])
            .args(["--v1-data-dir", "/missing/v1"])
            .args(["--transition-preview", "/missing/preview"])
            .args(["--accept-transition-preview", "00"])
            .args(["--candidate-dir", "/missing/candidate"])
            .args(["--wallet-dir", "/missing/wallet"])
            .args(["--receiver-key", "/missing/key"])
            .args(["--funding-config", "/missing/config"])
            .args(["--watchtower", "http://127.0.0.1:48302"])
            .args(["--watcher-public-key", &generate_identity().public_key])
            .args(["--node", node, "--listen", listener]);
        if offline {
            command.arg("--offline-v1-copy");
        }
        command.output().unwrap()
    };
    let public = run("0.0.0.0:0", "http://127.0.0.1:48300", true);
    assert!(!public.status.success());
    assert!(String::from_utf8_lossy(&public.stderr).contains("loopback listener"));
    let remote = run("127.0.0.1:0", "http://192.0.2.1:48300", true);
    assert!(!remote.status.success());
    assert!(String::from_utf8_lossy(&remote.stderr).contains("loopback HTTP origin"));
    let missing_offline = run("127.0.0.1:0", "http://127.0.0.1:48300", false);
    assert!(!missing_offline.status.success());
    assert!(String::from_utf8_lossy(&missing_offline.stderr).contains("disposable v1 copy"));
}

#[tokio::test]
async fn adopted_earth_source_and_destination_require_exact_signed_chain_and_cut() {
    let mut f = Fixture::with_v1_blocks(101);
    f.enable_earth();
    let earth_id = f.earth_adoption.unwrap();
    let free_addr = || {
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        drop(socket);
        addr
    };
    let source_addr = free_addr();
    let mut source = Command::new(env!("CARGO_BIN_EXE_rld-earth-node"));
    source
        .arg("run-adopted")
        .arg("--genesis")
        .arg(f.dir.join("genesis.json"))
        .arg("--history")
        .arg(f.dir.join("history.json"))
        .arg("--adoption")
        .arg(f.dir.join("adoption.json"))
        .args(["--manifest-pin", &f.pin.to_hex()])
        .args(["--accept-adoption", &f.adoption.to_hex()])
        .args(["--pinned-v1-source", &f.source.to_hex()])
        .arg("--v1-data-dir")
        .arg(f.dir.join("a-v1"))
        .arg("--transition-preview")
        .arg(f.dir.join("transition-preview.json"))
        .args([
            "--accept-transition-preview",
            &f.transition_preview.to_hex(),
        ])
        .arg("--earth-adoption")
        .arg(f.dir.join("earth-adoption.json"))
        .args(["--accept-earth-adoption", &earth_id.to_hex()])
        .arg("--data-dir")
        .arg(f.dir.join("adopted-source"))
        .args(["--listen", &source_addr.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(f.dir.join("adopted-source.log")).unwrap());
    f.children.push(source.spawn().unwrap());
    let client = reqwest::Client::new();
    let source_url = format!("http://{source_addr}");
    let mut source_status = None;
    for _ in 0..100 {
        if let Ok(reply) = client
            .get(format!("{source_url}/v1/earth/status"))
            .send()
            .await
        {
            if reply.status().is_success() {
                source_status = Some(reply.json::<serde_json::Value>().await.unwrap());
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let source_status = source_status.expect("adopted source did not start");
    assert_eq!(source_status["chain_id"], f.chain_id.to_hex());
    assert_eq!(source_status["earth_adoption_id"], earth_id.to_hex());
    assert_eq!(source_status["live_rld"], true);

    let adopted: EarthSuccessorAdoption =
        serde_json::from_slice(&std::fs::read(f.dir.join("earth-adoption.json")).unwrap()).unwrap();
    let destination_context = DestinationContext {
        chain_id: Hash([81; 32]),
        source_policy: ObservationPolicy {
            source_chain_id: f.chain_id,
            accepted_v1_tip: f.v1_chain.tip(),
            minimum_confirmations: 12,
            minimum_cumulative_work: f
                .v1_chain
                .chainwork()
                .checked_add(header_work(target_limit()))
                .unwrap(),
        },
        started_at: now() - 10,
        initial_target: target_limit(),
        source_finality: Some(SourceFinalityTrust {
            earth_adoption_id: earth_id,
            validator_keys: adopted
                .approvals
                .iter()
                .map(|a| a.public_key.clone())
                .collect(),
        }),
    };
    std::fs::write(
        f.dir.join("earth-destination-context.json"),
        serde_json::to_vec(&destination_context).unwrap(),
    )
    .unwrap();
    f.authorize_destination(&destination_context);
    let destination_addr = free_addr();
    let mut destination = Command::new(env!("CARGO_BIN_EXE_rld-earth-destination-node"));
    destination
        .arg("--genesis")
        .arg(f.dir.join("genesis.json"))
        .arg("--history")
        .arg(f.dir.join("history.json"))
        .arg("--adoption")
        .arg(f.dir.join("adoption.json"))
        .args(["--manifest-pin", &f.pin.to_hex()])
        .args(["--accept-adoption", &f.adoption.to_hex()])
        .args(["--pinned-v1-source", &f.source.to_hex()])
        .arg("--v1-data-dir")
        .arg(f.dir.join("receiver-v1"))
        .arg("--transition-preview")
        .arg(f.dir.join("transition-preview.json"))
        .args([
            "--accept-transition-preview",
            &f.transition_preview.to_hex(),
        ])
        .arg("--earth-adoption")
        .arg(f.dir.join("earth-adoption.json"))
        .args(["--accept-earth-adoption", &earth_id.to_hex()])
        .arg("--source-candidate-dir")
        .arg(f.dir.join("adopted-destination-source"))
        .args(["--source-node", &source_url])
        .arg("--destination-context")
        .arg(f.dir.join("earth-destination-context.json"))
        .arg("--destination-authorization")
        .arg(f.dir.join("destination-authorization.json"))
        .args([
            "--accept-destination-authorization",
            &f.destination_authorization.unwrap().to_hex(),
        ])
        .args([
            "--destination-signer",
            f.destination_signer.as_ref().unwrap(),
        ])
        .arg("--destination-dir")
        .arg(f.dir.join("adopted-destination"))
        .args(["--listen", &destination_addr.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(f.dir.join("adopted-destination.log")).unwrap());
    f.children.push(destination.spawn().unwrap());
    let destination_url = format!("http://{destination_addr}");
    let mut destination_status = None;
    for _ in 0..100 {
        if let Ok(reply) = client
            .get(format!("{destination_url}/v1/earth-destination/status"))
            .send()
            .await
        {
            if reply.status().is_success() {
                destination_status = Some(reply.json::<serde_json::Value>().await.unwrap());
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let destination_status = destination_status.expect("adopted destination did not start");
    assert_eq!(
        destination_status["source_transition_preview_id"],
        f.transition_preview.to_hex()
    );
    assert_eq!(destination_status["earth_adoption_id"], earth_id.to_hex());
    assert_eq!(destination_status["live_rld"], true);
    assert_eq!(destination_status["source_fresh"], true);

    let (export_input, export_coin) = f.mature_input.clone().unwrap();
    let recipient = generate_identity();
    let export_intent = ExportIntent {
        source_chain_id: f.chain_id,
        destination_chain_id: destination_context.chain_id,
        input: export_input,
        owner: f.owner.clone(),
        recipient: recipient.public_key.clone(),
        amount: Amount(1_000),
        source_fee: Amount(1),
        destination_fee: Amount(10),
        change: export_coin.checked_sub(Amount(1_001)).unwrap(),
        valid_through_height: f.v1_height + 50,
    };
    let export_id = export_intent.id().unwrap();
    let export = CandidateCommand::Export(ExportCommand {
        owner_signature: sign_bytes(&f.owner_secret, &export_intent.signing_bytes().unwrap())
            .unwrap(),
        intent: export_intent,
    });
    let mut local_source = CandidateChain::from_replayed_pow_chain(&f.v1_chain).unwrap();
    let mut export_checkpoint = None;
    for index in 0..12_u64 {
        let commands = if index == 0 {
            vec![export.clone()]
        } else {
            vec![]
        };
        let mut block = local_source
            .template(f.owner.clone(), now() - 30 + index, commands)
            .unwrap();
        while !mine_batch(&mut block, 100_000).unwrap() {}
        local_source.accept(block.clone(), now()).unwrap();
        if index == 0 {
            export_checkpoint = Some(block.header.id().unwrap());
        }
        let reply = client
            .post(format!("{source_url}/v1/earth/blocks"))
            .json(&block)
            .send()
            .await
            .unwrap();
        assert!(
            reply.status().is_success(),
            "adopted source rejected export block: {reply:?}"
        );
    }
    let bundle = local_source
        .export_bundle(export_id, export_checkpoint.unwrap())
        .unwrap();
    let draft: FinalityStatement = client
        .get(format!(
            "{source_url}/v1/earth/finality-draft/{}",
            export_checkpoint.unwrap().to_hex()
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    std::fs::write(
        f.dir.join("finality-statement.json"),
        serde_json::to_vec(&draft).unwrap(),
    )
    .unwrap();
    let key_paths = (2..=5)
        .map(|seed| {
            let key = SigningKey::from_bytes(&[seed; 32]);
            let path = f.dir.join(format!("finality-validator-{seed}.json"));
            std::fs::write(
                &path,
                serde_json::to_vec(&serde_json::json!({
                    "public_key":hex::encode(key.verifying_key().to_bytes()),
                    "secret_key":hex::encode([seed; 32])
                }))
                .unwrap(),
            )
            .unwrap();
            path
        })
        .collect::<Vec<_>>();
    let mut signing = Command::new(env!("CARGO_BIN_EXE_rld-earth-finality"));
    signing
        .arg("--statement")
        .arg(f.dir.join("finality-statement.json"))
        .arg("--pow-adoption")
        .arg(f.dir.join("adoption.json"))
        .arg("--earth-adoption")
        .arg(f.dir.join("earth-adoption.json"))
        .arg("--lock-dir")
        .arg(f.dir.join("finality-locks"))
        .arg("--output")
        .arg(f.dir.join("finality-certificate.json"))
        .arg("--confirm-reviewed-source");
    signing.arg("--validator-key");
    for path in &key_paths {
        signing.arg(path);
    }
    let result = signing.output().unwrap();
    assert!(
        result.status.success(),
        "finality signing failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let certificate: FinalityCertificate =
        serde_json::from_slice(&std::fs::read(f.dir.join("finality-certificate.json")).unwrap())
            .unwrap();
    let installed = client
        .post(format!("{source_url}/v1/earth/finality"))
        .body(serde_json::to_vec(&certificate).unwrap())
        .send()
        .await
        .unwrap();
    assert!(
        installed.status().is_success(),
        "source finality rejected: {}",
        installed.text().await.unwrap()
    );
    let mut conflicting = draft.clone();
    conflicting.block = Hash([90; 32]);
    std::fs::write(
        f.dir.join("finality-statement.json"),
        serde_json::to_vec(&conflicting).unwrap(),
    )
    .unwrap();
    std::fs::remove_file(f.dir.join("finality-certificate.json")).unwrap();
    let rejected = signing.output().unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("validator finality lock"));
    let mut synchronized = false;
    for _ in 0..100 {
        let status: serde_json::Value = client
            .get(format!("{destination_url}/v1/earth-destination/status"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if status["source_fresh"] == true
            && status["source_tip"] == local_source.tip().to_hex()
            && status["source_finality_block"] == export_checkpoint.unwrap().to_hex()
        {
            synchronized = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        synchronized,
        "adopted destination did not replay 12 source confirmations"
    );
    for commands in [
        vec![DestinationCommand::FinalizedImport {
            bundle: bundle.clone(),
            certificate: certificate.clone(),
        }],
        vec![],
    ] {
        let response = client
            .post(format!("{destination_url}/v1/earth-destination/template"))
            .json(&serde_json::json!({"miner":f.owner,"commands":commands}))
            .send()
            .await
            .unwrap();
        assert!(
            response.status().is_success(),
            "adopted destination template rejected: {}",
            response.text().await.unwrap()
        );
        let mut block: rld_value_successor::destination::pow::Block =
            response.json().await.unwrap();
        while !rld_value_successor::destination::pow::mine_batch(&mut block, 100_000).unwrap() {}
        let reply = client
            .post(format!("{destination_url}/v1/earth-destination/blocks"))
            .json(&block)
            .send()
            .await
            .unwrap();
        assert!(
            reply.status().is_success(),
            "adopted destination rejected block: {reply:?}"
        );
    }
    let receipt_policy = InclusionPolicy {
        destination_chain_id: destination_context.chain_id,
        accepted_genesis: destination_context.genesis().unwrap(),
        minimum_confirmations: 2,
        minimum_inclusion_work: header_work(target_limit()),
    };
    let receipt_request = serde_json::json!({"bundle":bundle,"policy":receipt_policy});
    let receipt: ImportInclusionReceipt = client
        .post(format!("{destination_url}/v1/earth-destination/receipts"))
        .json(&receipt_request)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(receipt.live_rld);
    let verified: serde_json::Value = client
        .post(format!(
            "{destination_url}/v1/earth-destination/verify-receipt"
        ))
        .json(&serde_json::json!({"bundle":bundle,"policy":receipt_policy,"receipt":receipt}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(verified["valid_on_selected_branches"], true);
    assert_eq!(verified["live_rld"], true);
    let balance_url = format!(
        "{destination_url}/v1/earth-destination/balance/{}",
        recipient.public_key
    );
    let pending: serde_json::Value = client
        .get(&balance_url)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(pending["spendable_runlai"], "0");
    assert_eq!(pending["pending_runlai"], "990");
    for _ in 0..4 {
        let response = client
            .post(format!("{destination_url}/v1/earth-destination/template"))
            .json(&serde_json::json!({"miner":f.owner,"commands":[]}))
            .send()
            .await
            .unwrap();
        assert!(
            response.status().is_success(),
            "destination maturity template rejected: {}",
            response.text().await.unwrap()
        );
        let mut block: rld_value_successor::destination::pow::Block =
            response.json().await.unwrap();
        while !rld_value_successor::destination::pow::mine_batch(&mut block, 100_000).unwrap() {}
        let reply = client
            .post(format!("{destination_url}/v1/earth-destination/blocks"))
            .json(&block)
            .send()
            .await
            .unwrap();
        assert!(reply.status().is_success());
    }
    let matured: serde_json::Value = client
        .get(&balance_url)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(matured["spendable_runlai"], "990");
    assert_eq!(matured["pending_runlai"], "0");
    f.stop(1);
    let mut resumed = Command::new(destination.get_program());
    resumed
        .args(destination.get_args())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(f.dir.join("adopted-destination-restart.log")).unwrap());
    f.children.push(resumed.spawn().unwrap());
    let mut replayed = false;
    for _ in 0..100 {
        if let Ok(reply) = client.get(&balance_url).send().await {
            if let Ok(value) = reply.error_for_status() {
                let value: serde_json::Value = value.json().await.unwrap();
                if value["spendable_runlai"] == "990" && value["pending_runlai"] == "0" {
                    replayed = true;
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        replayed,
        "adopted destination did not replay finalized import after restart"
    );

    let mut wrong = Command::new(env!("CARGO_BIN_EXE_rld-earth-node"));
    wrong
        .arg("run-adopted")
        .arg("--genesis")
        .arg(f.dir.join("genesis.json"))
        .arg("--history")
        .arg(f.dir.join("history.json"))
        .arg("--adoption")
        .arg(f.dir.join("adoption.json"))
        .args(["--manifest-pin", &f.pin.to_hex()])
        .args(["--accept-adoption", &f.adoption.to_hex()])
        .args(["--pinned-v1-source", &f.source.to_hex()])
        .arg("--v1-data-dir")
        .arg(f.dir.join("b-v1"))
        .arg("--transition-preview")
        .arg(f.dir.join("transition-preview.json"))
        .args([
            "--accept-transition-preview",
            &f.transition_preview.to_hex(),
        ])
        .arg("--earth-adoption")
        .arg(f.dir.join("earth-adoption.json"))
        .args(["--accept-earth-adoption", &Hash([99; 32]).to_hex()])
        .arg("--data-dir")
        .arg(f.dir.join("wrong-adoption-store"))
        .args(["--listen", &free_addr().to_string()]);
    let rejected = wrong.output().unwrap();
    assert!(!rejected.status.success());
    assert!(!f.dir.join("wrong-adoption-store").exists());
}
