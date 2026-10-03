//! Loopback-only candidate destination node. No adopted value or public peer.

use anyhow::{anyhow, bail, Context as _, Result};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path as RoutePath, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use rld_core::AdmissionHash32 as Hash;
use rld_cross_region::ProofBundle;
use rld_pow::{storage::Store as V1Store, transition::Adoption, MAX_TRACKED_BLOCKS};
use rld_value_successor::{
    candidate_client::{
        load_verified_transition_preview_file, loopback_origin, now, refresh_mode,
        verify_earth_adoption_file, NodeMode,
    },
    chain::storage::CandidateStore,
    destination::pow::{
        authorization::DestinationGenesisAuthorization,
        mine_batch,
        receipt::{ImportInclusionReceipt, InclusionPolicy},
        storage::DestinationPowStore,
        Block, Command, Context as DestinationContext, DestinationPowChain,
        MAX_DESTINATION_BLOCK_BYTES,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::{Mutex, Semaphore};

const BASE: &str = "/v1/destination-pow-candidate";
const STATUS: &str = "UNADOPTED_LOCAL_DESTINATION_POW_CANDIDATE_ONLY";
const SYNC_BATCH: usize = 2;

fn api_base(mode: NodeMode) -> &'static str {
    if matches!(mode, NodeMode::Adopted(_)) {
        "/v1/earth-destination"
    } else {
        BASE
    }
}
fn network_status(mode: NodeMode) -> &'static str {
    if matches!(mode, NodeMode::Adopted(_)) {
        "ADOPTED_EARTH_DESTINATION_POW_V1"
    } else {
        STATUS
    }
}

#[derive(Parser)]
struct Args {
    #[arg(long)]
    genesis: PathBuf,
    #[arg(long)]
    history: PathBuf,
    #[arg(long)]
    adoption: PathBuf,
    #[arg(long)]
    manifest_pin: String,
    #[arg(long)]
    accept_adoption: String,
    #[arg(long)]
    pinned_v1_source: String,
    #[arg(long)]
    v1_data_dir: PathBuf,
    #[arg(long)]
    transition_preview: PathBuf,
    #[arg(long)]
    accept_transition_preview: String,
    #[arg(long)]
    source_candidate_dir: PathBuf,
    #[arg(
        long,
        required_unless_present = "disconnected_source_certificate",
        conflicts_with = "disconnected_source_certificate"
    )]
    source_node: Option<String>,
    /// Research only: use an immutable, fully replayed source snapshot with
    /// this exact installed finality statement ID. No source HTTP is used.
    #[arg(long)]
    disconnected_source_certificate: Option<String>,
    #[arg(long)]
    destination_context: PathBuf,
    #[arg(long)]
    destination_authorization: PathBuf,
    #[arg(long)]
    accept_destination_authorization: String,
    #[arg(long)]
    destination_signer: String,
    #[arg(long)]
    destination_dir: PathBuf,
    #[arg(long, default_value = "127.0.0.1:48310")]
    listen: SocketAddr,
    #[arg(long)]
    peer: Vec<String>,
    #[arg(long)]
    mine_to: Option<String>,
    #[arg(long, default_value_t = 0)]
    mine_interval_ms: u64,
    #[arg(long)]
    offline_v1_copy: bool,
    #[arg(long, requires = "accept_earth_adoption")]
    earth_adoption: Option<PathBuf>,
    #[arg(long, requires = "earth_adoption")]
    accept_earth_adoption: Option<String>,
}

struct Runtime {
    source: Mutex<CandidateStore>,
    destination: Mutex<DestinationPowStore>,
    context: DestinationContext,
    fresh: AtomicBool,
    last_source_ok: AtomicU64,
    running: AtomicBool,
    miner: Option<String>,
    submissions: AtomicU64,
    transition_preview_id: Hash,
    destination_authorization_id: Hash,
    permits: Arc<Semaphore>,
    mode: NodeMode,
    disconnected_source_certificate: Option<Hash>,
}
#[derive(Clone)]
struct App(Arc<Runtime>);
type Api<T> = std::result::Result<Json<T>, (StatusCode, String)>;

impl Runtime {
    fn source_fresh(&self) -> bool {
        self.disconnected_source_certificate.is_none()
            && self.fresh.load(Ordering::Acquire)
            && now().ok().is_some_and(|time| {
                time.saturating_sub(self.last_source_ok.load(Ordering::Acquire)) <= 5
            })
    }

    fn source_available(&self) -> bool {
        // The offline source store is verified once before serving and never
        // mutated. Every operation still audits its source proofs and ledger.
        self.disconnected_source_certificate.is_some() || self.source_fresh()
    }

    fn live_rld(&self) -> bool {
        matches!(self.mode, NodeMode::Adopted(_)) && self.disconnected_source_certificate.is_none()
    }
}

fn verify_disconnected_source(
    source: &CandidateStore,
    context: &DestinationContext,
    pin: Hash,
) -> Result<()> {
    context.validate().map_err(|error| anyhow!(error))?;
    let trust = context
        .source_finality
        .as_ref()
        .ok_or_else(|| anyhow!("disconnected source requires pinned signed finality trust"))?;
    if pin.is_zero()
        || !source.healthy()
        || source.chain().chain_id() != context.source_policy.source_chain_id
        || source.chain().v1_tip() != context.source_policy.accepted_v1_tip
    {
        bail!("disconnected source identity, health or certificate pin mismatch");
    }
    let certificate = source
        .finality()
        .ok_or_else(|| anyhow!("disconnected source lacks durable finality certificate"))?;
    certificate
        .verify(
            source.chain(),
            trust.earth_adoption_id,
            &trust.validator_keys,
        )
        .map_err(|error| anyhow!(error))?;
    if certificate.statement.id().map_err(|error| anyhow!(error))? != pin
        || source.chain().finalized()
            != Some((certificate.statement.block, certificate.statement.height))
    {
        bail!("disconnected source does not match exact installed finality pin");
    }
    Ok(())
}

fn bad(error: impl ToString) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, error.to_string())
}
fn unavailable(error: impl ToString) -> (StatusCode, String) {
    (StatusCode::SERVICE_UNAVAILABLE, error.to_string())
}
fn require_source(app: &App) -> std::result::Result<(), (StatusCode, String)> {
    if app.0.source_available() {
        Ok(())
    } else {
        Err(unavailable("candidate source synchronization unavailable"))
    }
}
fn parse_hash(input: &str) -> Result<Hash> {
    Hash::from_hex(input).map_err(|error| anyhow!(error))
}
fn read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit as u64 {
        bail!("unsafe or oversized destination candidate input");
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        bail!("destination candidate input exceeded bound");
    }
    Ok(bytes)
}

async fn source_copy(app: &App) -> rld_value_successor::chain::CandidateChain {
    app.0.source.lock().await.chain().clone()
}

async fn status(State(app): State<App>) -> Api<serde_json::Value> {
    let source_snapshot = app.0.source.try_lock().ok().map(|source| {
        (
            source.chain().tip(),
            source.finality().map(|cert| cert.statement.block),
        )
    });
    let source_tip = source_snapshot.map(|(tip, _)| tip);
    let source_finality = source_snapshot.and_then(|(_, block)| block);
    let store = app.0.destination.lock().await;
    let chain = store.chain();
    Ok(Json(serde_json::json!({
        "status":network_status(app.0.mode),
        "live_rld":app.0.live_rld() && !chain.halted() && app.0.source_fresh(),
        "earth_adoption_id":if let NodeMode::Adopted(id) = app.0.mode { Some(id) } else { None },
        "source_fresh":app.0.source_fresh(),
        "source_available":app.0.source_available() && store.healthy() && !chain.halted(),
        "source_view":if app.0.disconnected_source_certificate.is_some() {"PINNED_FINALIZED_OFFLINE_SNAPSHOT"} else {"LOCAL_SOURCE_REFRESH_REQUIRED"},
        "disconnected_source_certificate":app.0.disconnected_source_certificate,
        "experimental_disconnected_mode":app.0.disconnected_source_certificate.is_some(),
        "source_refreshing":source_tip.is_none(),
        "source_tip":source_tip,
        "destination_chain_id":app.0.context.chain_id,
        "destination_genesis":chain.genesis(),
        "tip":chain.tip(),
        "height":chain.height().to_string(),
        "chainwork":chain.chainwork(),
        "state_root":chain.state().root().map_err(bad)?,
        "imported_total":chain.state().imported_total(),
        "halted":chain.halted(),
        "storage_healthy":store.healthy(),
        "submitted_candidate_commands":store.submitted_count(),
        "native_issuance":false,
        "source_transition_preview_id":app.0.transition_preview_id,
        "destination_authorization_id":app.0.destination_authorization_id,
        "minimum_source_confirmations":app.0.context.source_policy.minimum_confirmations.to_string(),
        "minimum_import_confirmations":rld_value_successor::destination::pow::MIN_IMPORT_CONFIRMATIONS.to_string(),
        "probabilistic_finality":true,
        "source_finality_block":source_finality,
        "source_reorganization_policy":if app.0.context.source_finality.is_some() {"SIGNED_SOURCE_CHECKPOINT_REQUIRED_FOR_IMPORT"} else {"PERMANENT_HALT_NO_AUTOMATIC_CLAWBACK"}
    })))
}

async fn balance(
    State(app): State<App>,
    RoutePath(owner): RoutePath<String>,
) -> Api<serde_json::Value> {
    require_source(&app)?;
    rld_core::validate_ed25519_public_key(&owner).map_err(bad)?;
    let source = source_copy(&app).await;
    let mut store = app.0.destination.lock().await;
    require_source(&app)?;
    store.audit_source(&source).map_err(unavailable)?;
    let chain = store.chain();
    let next_height = chain
        .height()
        .checked_add(1)
        .ok_or_else(|| bad("destination height overflow"))?;
    let (spendable, pending) = chain.state().balance(&owner, next_height).map_err(bad)?;
    Ok(Json(serde_json::json!({
        "status":network_status(app.0.mode),
        "live_rld":app.0.live_rld(),
        "owner":owner,
        "height":chain.height().to_string(),
        "next_height":next_height.to_string(),
        "tip":chain.tip(),
        "source_tip":source.tip(),
        "candidate_spendable_runlai":spendable,
        "candidate_pending_runlai":pending,
        "spendable_runlai":spendable,
        "pending_runlai":pending,
        "minimum_import_confirmations":rld_value_successor::destination::pow::MIN_IMPORT_CONFIRMATIONS.to_string(),
        "probabilistic":true
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TemplateRequest {
    miner: String,
    #[serde(default)]
    commands: Vec<Command>,
    #[serde(default)]
    include_submitted: bool,
}

async fn template(State(app): State<App>, body: Bytes) -> Api<Block> {
    require_source(&app)?;
    if body.len() > MAX_DESTINATION_BLOCK_BYTES {
        return Err(bad("destination template request byte bound"));
    }
    let request: TemplateRequest = serde_json::from_slice(&body).map_err(bad)?;
    let source = source_copy(&app).await;
    let mut store = app.0.destination.lock().await;
    require_source(&app)?;
    if !store.healthy() {
        return Err(unavailable("destination store unhealthy"));
    }
    let timestamp = store
        .chain()
        .template_time(now().map_err(bad)?)
        .map_err(bad)?;
    if timestamp > now().map_err(bad)?.saturating_add(7200) {
        return Err(bad("clock behind destination median"));
    }
    let mut commands = if request.include_submitted {
        store
            .mineable_commands(&source, &request.miner, timestamp)
            .map_err(bad)?
    } else {
        Vec::new()
    };
    commands.extend(request.commands);
    Ok(Json(
        store
            .template(&source, request.miner, timestamp, commands)
            .map_err(bad)?,
    ))
}

async fn submit_command(State(app): State<App>, body: Bytes) -> Api<serde_json::Value> {
    require_source(&app)?;
    if body.len() > MAX_DESTINATION_BLOCK_BYTES {
        return Err(bad("destination command byte bound"));
    }
    let miner = app
        .0
        .miner
        .clone()
        .ok_or_else(|| unavailable("destination command intake requires local miner"))?;
    let _permit = app
        .0
        .permits
        .clone()
        .try_acquire_owned()
        .map_err(unavailable)?;
    let command: Command = serde_json::from_slice(&body).map_err(bad)?;
    let source = source_copy(&app).await;
    let mut store = app.0.destination.lock().await;
    require_source(&app)?;
    let timestamp = store
        .chain()
        .template_time(now().map_err(bad)?)
        .map_err(bad)?;
    let (id, newly_submitted) = store
        .submit_command(&source, command, &miner, timestamp)
        .map_err(bad)?;
    if newly_submitted {
        app.0.submissions.fetch_add(1, Ordering::Release);
    }
    Ok(Json(serde_json::json!({
        "status":network_status(app.0.mode),
        "live_rld":app.0.live_rld(),
        "command":id,
        "newly_submitted":newly_submitted,
        "candidate_included":store.selected_inclusion(id).map_err(bad)?.is_some(),
        "submitted_candidate_commands":store.submitted_count()
    })))
}

async fn submit_block(State(app): State<App>, body: Bytes) -> Api<serde_json::Value> {
    require_source(&app)?;
    if body.len() > MAX_DESTINATION_BLOCK_BYTES {
        return Err(bad("destination block byte bound"));
    }
    let _permit = app
        .0
        .permits
        .clone()
        .try_acquire_owned()
        .map_err(unavailable)?;
    let block: Block = serde_json::from_slice(&body).map_err(bad)?;
    let source = source_copy(&app).await;
    let mut store = app.0.destination.lock().await;
    require_source(&app)?;
    let selected = store
        .accept(&source, block, now().map_err(bad)?)
        .map_err(bad)?;
    Ok(Json(serde_json::json!({
        "status":network_status(app.0.mode),
        "live_rld":app.0.live_rld(),
        "selected":selected,
        "tip":store.chain().tip(),
        "height":store.chain().height().to_string()
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptRequest {
    bundle: ProofBundle,
    policy: InclusionPolicy,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyReceiptRequest {
    bundle: ProofBundle,
    policy: InclusionPolicy,
    receipt: ImportInclusionReceipt,
}

async fn receipt(State(app): State<App>, body: Bytes) -> Api<ImportInclusionReceipt> {
    require_source(&app)?;
    if body.len() > MAX_DESTINATION_BLOCK_BYTES {
        return Err(bad("destination receipt request byte bound"));
    }
    let request: ReceiptRequest = serde_json::from_slice(&body).map_err(bad)?;
    let source = source_copy(&app).await;
    let mut store = app.0.destination.lock().await;
    require_source(&app)?;
    let mut receipt = store
        .observe_import(&source, &request.bundle, &request.policy)
        .map_err(bad)?;
    receipt.live_rld = app.0.live_rld();
    Ok(Json(receipt))
}

async fn verify_receipt(State(app): State<App>, body: Bytes) -> Api<serde_json::Value> {
    require_source(&app)?;
    if body.len() > MAX_DESTINATION_BLOCK_BYTES {
        return Err(bad("destination verification request byte bound"));
    }
    let request: VerifyReceiptRequest = serde_json::from_slice(&body).map_err(bad)?;
    if request.receipt.live_rld != app.0.live_rld() {
        return Err(bad("destination receipt adoption mode mismatch"));
    }
    let mut core_receipt = request.receipt.clone();
    core_receipt.live_rld = false;
    let source = source_copy(&app).await;
    let mut store = app.0.destination.lock().await;
    require_source(&app)?;
    let observed = store
        .verify_import_receipt(&source, &request.bundle, &request.policy, &core_receipt)
        .map_err(bad)?;
    Ok(Json(serde_json::json!({
        "status":network_status(app.0.mode),
        "live_rld":app.0.live_rld(),
        "valid_on_selected_branches":true,
        "selected_tip":observed.selected_tip,
        "confirmations":observed.confirmations.to_string(),
        "inclusion_work":observed.inclusion_work,
        "selected_work":observed.selected_work
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncRequest {
    locator: Vec<Hash>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncResponse {
    chain_id: Hash,
    genesis: Hash,
    common: Hash,
    tip: Hash,
    blocks: Vec<Block>,
}

fn sync_response(chain: &DestinationPowChain, locator: &[Hash]) -> Result<SyncResponse> {
    if locator.is_empty() || locator.len() > 64 {
        bail!("destination locator bound");
    }
    let path = chain.best_blocks().map_err(|error| anyhow!(error))?;
    let ids = path
        .iter()
        .map(|block| block.header.id())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| anyhow!(error))?;
    let known: BTreeSet<_> = locator.iter().copied().collect();
    let start = match ids.iter().rposition(|id| known.contains(id)) {
        Some(index) => index + 1,
        None if known.contains(&chain.genesis()) => 0,
        None => bail!("no shared destination candidate ancestry"),
    };
    Ok(SyncResponse {
        chain_id: chain.chain_id(),
        genesis: chain.genesis(),
        common: if start == 0 {
            chain.genesis()
        } else {
            ids[start - 1]
        },
        tip: chain.tip(),
        blocks: path
            .into_iter()
            .skip(start)
            .take(SYNC_BATCH)
            .cloned()
            .collect(),
    })
}

async fn sync(State(app): State<App>, body: Bytes) -> Api<SyncResponse> {
    if body.len() > 8192 {
        return Err(bad("destination sync request byte bound"));
    }
    let request: SyncRequest = serde_json::from_slice(&body).map_err(bad)?;
    let store = app.0.destination.lock().await;
    Ok(Json(
        sync_response(store.chain(), &request.locator).map_err(bad)?,
    ))
}

fn locator(chain: &DestinationPowChain, cursor: Option<Hash>) -> Result<Vec<Hash>> {
    let path = chain.best_blocks().map_err(|error| anyhow!(error))?;
    let mut ids = Vec::new();
    if let Some(id) = cursor.filter(|id| chain.block(*id).is_some()) {
        ids.push(id);
    }
    let mut back = 0usize;
    let mut step = 1usize;
    while back < path.len() && ids.len() < 63 {
        let id = path[path.len() - 1 - back]
            .header
            .id()
            .map_err(|error| anyhow!(error))?;
        if !ids.contains(&id) {
            ids.push(id);
        }
        if ids.len() > 10 {
            step = step.saturating_mul(2);
        }
        back = back.saturating_add(step);
    }
    ids.push(chain.genesis());
    Ok(ids)
}

async fn pull_peer(app: &App, client: &reqwest::Client, peer: &str) -> Result<()> {
    if !app.0.source_available() {
        bail!("destination candidate source is not synchronized");
    }
    let mut cursor = None;
    for _ in 0..MAX_TRACKED_BLOCKS.div_ceil(SYNC_BATCH) {
        let request = {
            let store = app.0.destination.lock().await;
            serde_json::json!({"locator":locator(store.chain(), cursor)?})
        };
        let mut response = client
            .post(format!("{peer}{}/sync", api_base(app.0.mode)))
            .json(&request)
            .send()
            .await?
            .error_for_status()?;
        let limit = MAX_DESTINATION_BLOCK_BYTES * SYNC_BATCH + 8192;
        if response
            .content_length()
            .is_some_and(|length| length > limit as u64)
        {
            bail!("oversized destination peer response");
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if bytes.len().saturating_add(chunk.len()) > limit {
                bail!("destination peer response exceeded bound");
            }
            bytes.extend_from_slice(&chunk);
        }
        let batch: SyncResponse = serde_json::from_slice(&bytes)?;
        if batch.blocks.len() > SYNC_BATCH {
            bail!("destination peer block count bound");
        }
        let source = source_copy(app).await;
        let mut store = app.0.destination.lock().await;
        if !app.0.source_available()
            || batch.chain_id != app.0.context.chain_id
            || batch.genesis != store.chain().genesis()
        {
            bail!("destination peer network or source mismatch");
        }
        if batch.common != store.chain().genesis() && store.chain().block(batch.common).is_none() {
            bail!("destination peer supplied unknown common parent");
        }
        let terminal = batch.blocks.is_empty();
        let mut parent = batch.common;
        for block in batch.blocks {
            if block.header.parent != parent {
                bail!("discontinuous destination peer response");
            }
            parent = block.header.id().map_err(|error| anyhow!(error))?;
            store
                .accept(&source, block, now()?)
                .map_err(|error| anyhow!(error))?;
        }
        if terminal || parent == batch.tip {
            return Ok(());
        }
        if cursor == Some(parent) {
            bail!("destination peer made no sync progress");
        }
        cursor = Some(parent);
    }
    bail!("destination peer sync page budget reached")
}

fn mine_loop(app: App, miner: String, interval_ms: u64) {
    while app.0.running.load(Ordering::Acquire) {
        if !app.0.source_available() {
            std::thread::sleep(Duration::from_millis(250));
            continue;
        }
        let source = app.0.source.blocking_lock().chain().clone();
        let candidate = (|| -> Result<(Block, u64)> {
            let mut store = app.0.destination.blocking_lock();
            if !store.healthy() {
                bail!("destination candidate store unhealthy");
            }
            let timestamp = store
                .chain()
                .template_time(now()?)
                .map_err(|e| anyhow!(e))?;
            if timestamp > now()?.saturating_add(7200) {
                bail!("clock behind destination median");
            }
            let commands = store
                .mineable_commands(&source, &miner, timestamp)
                .map_err(|error| anyhow!(error))?;
            let epoch = app.0.submissions.load(Ordering::Acquire);
            let block = store
                .template(&source, miner.clone(), timestamp, commands)
                .map_err(|error| anyhow!(error))?;
            Ok((block, epoch))
        })();
        let (mut block, epoch) = match candidate {
            Ok(candidate) => candidate,
            Err(error) => {
                eprintln!("destination candidate mining paused: {error}");
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
        };
        loop {
            if !app.0.running.load(Ordering::Acquire) {
                return;
            }
            match mine_batch(&mut block, 10_000) {
                Ok(true) => {
                    if !app.0.source_available() {
                        break;
                    }
                    let latest_source = app.0.source.blocking_lock().chain().clone();
                    let mut store = app.0.destination.blocking_lock();
                    if store.chain().tip() == block.header.parent
                        && app.0.submissions.load(Ordering::Acquire) == epoch
                        && app.0.source_available()
                    {
                        match now() {
                            Ok(time) => {
                                if let Err(error) = store.accept(&latest_source, block, time) {
                                    eprintln!(
                                        "destination candidate mined block rejected: {error}"
                                    );
                                }
                            }
                            Err(error) => eprintln!("destination candidate clock failed: {error}"),
                        }
                    }
                    drop(store);
                    let mut remaining = interval_ms;
                    while remaining > 0 && app.0.running.load(Ordering::Acquire) {
                        let step = remaining.min(100);
                        std::thread::sleep(Duration::from_millis(step));
                        remaining -= step;
                    }
                    break;
                }
                Ok(false) => {
                    if !app.0.source_available()
                        || app.0.submissions.load(Ordering::Acquire) != epoch
                        || app.0.destination.blocking_lock().chain().tip() != block.header.parent
                    {
                        break;
                    }
                }
                Err(error) => {
                    eprintln!("destination candidate mining failed: {error}");
                    break;
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let mode = if let (Some(_), Some(id)) = (&args.earth_adoption, &args.accept_earth_adoption) {
        NodeMode::Adopted(parse_hash(id)?)
    } else {
        if !args.offline_v1_copy {
            bail!("destination candidate requires a disposable offline v1 copy");
        }
        NodeMode::Candidate
    };
    if !args.listen.ip().is_loopback() {
        bail!("unadopted destination candidate must listen on loopback only");
    }
    if args.peer.len() > 16 || args.mine_interval_ms > 60_000 {
        bail!("destination candidate peer or mining interval bound");
    }
    let disconnected_pin = args
        .disconnected_source_certificate
        .as_deref()
        .map(parse_hash)
        .transpose()?;
    let source_node = args
        .source_node
        .as_deref()
        .map(loopback_origin)
        .transpose()?;
    let peers = args
        .peer
        .iter()
        .map(|peer| loopback_origin(peer))
        .collect::<Result<Vec<_>>>()?;
    if let Some(miner) = &args.mine_to {
        rld_core::validate_ed25519_public_key(miner).map_err(|error| anyhow!(error))?;
    }
    let genesis = read(&args.genesis, 65_536)?;
    let history = read(&args.history, 32 * 1024 * 1024)?;
    let adoption: Adoption = serde_json::from_slice(&read(&args.adoption, 65_536)?)?;
    let v1_context = adoption
        .verify_with_pinned_release_source(
            &genesis,
            &history,
            parse_hash(&args.manifest_pin)?,
            parse_hash(&args.accept_adoption)?,
            parse_hash(&args.pinned_v1_source)?,
        )
        .map_err(|error| anyhow!(error))?;
    let v1 = V1Store::open(&args.v1_data_dir, v1_context, now()?).map_err(|e| anyhow!(e))?;
    let fresh_earth = matches!(mode, NodeMode::Adopted(_))
        && v1.chain().context.legacy_height == 0
        && v1.chain().height() == 0
        && v1.chain().best_blocks().map_err(|e| anyhow!(e))?.is_empty();
    if !fresh_earth && v1.chain().height() <= v1.chain().context.legacy_height {
        bail!("destination source copy lacks replayed PoW history");
    }
    let preview = load_verified_transition_preview_file(
        &args.transition_preview,
        v1.chain(),
        adoption.statement.implementation_source_sha256,
        parse_hash(&args.accept_transition_preview)?,
    )?;
    let preview_id = preview.id().map_err(|error| anyhow!(error))?;
    if let NodeMode::Adopted(id) = mode {
        verify_earth_adoption_file(
            args.earth_adoption.as_ref().expect("checked adoption path"),
            &genesis,
            &history,
            &adoption,
            v1.chain(),
            &preview,
            id,
        )?;
    }
    let context_bytes = read(&args.destination_context, 8192)?;
    let context: DestinationContext = serde_json::from_slice(&context_bytes)?;
    if context_bytes != serde_json::to_vec(&context)? {
        bail!("noncanonical destination candidate context");
    }
    if matches!(mode, NodeMode::Adopted(_)) && context.source_policy.minimum_confirmations < 12 {
        bail!("adopted destination requires at least 12 source confirmations");
    }
    if let NodeMode::Adopted(id) = mode {
        let trust = context
            .source_finality
            .as_ref()
            .ok_or_else(|| anyhow!("adopted destination requires signed source finality"))?;
        let keys = adoption
            .approvals
            .iter()
            .map(|approval| approval.public_key.clone())
            .collect::<Vec<_>>();
        if trust.earth_adoption_id != id || trust.validator_keys != keys {
            bail!("destination finality trust differs from Earth adoption validators");
        }
    }
    let authorization_bytes = read(&args.destination_authorization, 2048)?;
    let authorization: DestinationGenesisAuthorization =
        serde_json::from_slice(&authorization_bytes)?;
    if authorization
        .canonical_bytes()
        .map_err(|error| anyhow!(error))?
        != authorization_bytes
    {
        bail!("destination authorization must have exact canonical bytes");
    }
    let destination_authorization_id = parse_hash(&args.accept_destination_authorization)?;
    authorization
        .verify_for_candidate(
            &context,
            &preview,
            destination_authorization_id,
            &args.destination_signer,
        )
        .map_err(|error| anyhow!(error))?;
    let mut source = if let Some(trust) = &context.source_finality {
        CandidateStore::open_finalized(
            &args.source_candidate_dir,
            v1.chain(),
            now()?,
            trust.earth_adoption_id,
            trust.validator_keys.clone(),
        )
        .map_err(|error| anyhow!(error))?
    } else {
        CandidateStore::open(&args.source_candidate_dir, v1.chain(), now()?)
            .map_err(|error| anyhow!(error))?
    };
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()?;
    if let Some(pin) = disconnected_pin {
        verify_disconnected_source(&source, &context, pin)?;
    } else {
        refresh_mode(
            &mut source,
            &client,
            source_node
                .as_deref()
                .ok_or_else(|| anyhow!("missing local source endpoint"))?,
            preview_id,
            mode,
        )
        .await?;
    }
    let destination = DestinationPowStore::open(
        &args.destination_dir,
        context.clone(),
        source.chain(),
        now()?,
    )
    .map_err(|error| anyhow!(error))?;
    let app = App(Arc::new(Runtime {
        source: Mutex::new(source),
        destination: Mutex::new(destination),
        context,
        fresh: AtomicBool::new(disconnected_pin.is_none()),
        last_source_ok: AtomicU64::new(now()?),
        running: AtomicBool::new(true),
        miner: args.mine_to.clone(),
        submissions: AtomicU64::new(0),
        transition_preview_id: preview_id,
        destination_authorization_id,
        permits: Arc::new(Semaphore::new(2)),
        mode,
        disconnected_source_certificate: disconnected_pin,
    }));
    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .context("bind destination candidate loopback")?;
    let base = api_base(mode);
    let router = Router::new()
        .route(&format!("{base}/status"), get(status))
        .route(&format!("{base}/balance/{{owner}}"), get(balance))
        .route(&format!("{base}/template"), post(template))
        .route(&format!("{base}/commands"), post(submit_command))
        .route(&format!("{base}/blocks"), post(submit_block))
        .route(&format!("{base}/sync"), post(sync))
        .route(&format!("{base}/receipts"), post(receipt))
        .route(&format!("{base}/verify-receipt"), post(verify_receipt))
        .layer(DefaultBodyLimit::max(MAX_DESTINATION_BLOCK_BYTES))
        .with_state(app.clone());

    let source_app = app.clone();
    let source_client = client.clone();
    let source_task = source_node.map(|source_node| {
        tokio::spawn(async move {
            while source_app.0.running.load(Ordering::Acquire) {
                let (result, changed) = {
                    let mut source = source_app.0.source.lock().await;
                    let prior = source.chain().tip();
                    let result = refresh_mode(
                        &mut source,
                        &source_client,
                        &source_node,
                        source_app.0.transition_preview_id,
                        source_app.0.mode,
                    )
                    .await;
                    (result, prior != source.chain().tip())
                };
                if let Err(error) = result {
                    source_app.0.fresh.store(false, Ordering::Release);
                    eprintln!("destination candidate source sync unavailable: {error}");
                } else {
                    if changed {
                        source_app.0.submissions.fetch_add(1, Ordering::Release);
                    }
                    let source = source_copy(&source_app).await;
                    let mut destination = source_app.0.destination.lock().await;
                    if let Err(error) = destination.audit_source(&source) {
                        source_app.0.fresh.store(false, Ordering::Release);
                        eprintln!("destination candidate source audit failed: {error}");
                    } else {
                        if let Ok(time) = now() {
                            source_app.0.last_source_ok.store(time, Ordering::Release);
                        }
                        source_app.0.fresh.store(true, Ordering::Release);
                    }
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        })
    });
    let peer_app = app.clone();
    let peer_task = tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .expect("destination candidate HTTP client");
        while peer_app.0.running.load(Ordering::Acquire) {
            for peer in &peers {
                if let Err(error) = pull_peer(&peer_app, &client, peer).await {
                    eprintln!("destination candidate peer sync unavailable: {error}");
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
    let miner = args.mine_to.map(|key| {
        let runtime = app.clone();
        std::thread::spawn(move || mine_loop(runtime, key, args.mine_interval_ms))
    });
    let shutdown_app = app.clone();
    let shutdown = async move {
        #[cfg(unix)]
        {
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("destination SIGTERM handler");
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
        }
        #[cfg(not(unix))]
        tokio::signal::ctrl_c()
            .await
            .expect("destination CTRL-C handler");
        shutdown_app.0.running.store(false, Ordering::Release);
    };
    eprintln!("{} listening on {}", network_status(mode), args.listen);
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await?;
    app.0.running.store(false, Ordering::Release);
    if let Some(source_task) = source_task {
        source_task.abort();
    }
    peer_task.abort();
    if let Some(miner) = miner {
        miner
            .join()
            .map_err(|_| anyhow!("destination miner thread panicked"))?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "rld-earth-destination-node/offline_tests.rs"]
mod offline_tests;
