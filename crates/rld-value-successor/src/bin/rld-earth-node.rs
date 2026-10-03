//! Loopback-only process harness and signed-adoption Earth successor node.
//! The candidate mode remains isolated; adopted mode requires a distinct new
//! Earth genesis and unanimous rule adoption before it can report live RLD.
use anyhow::{anyhow, bail, Context as _, Result};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path as RoutePath, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use clap::{Args as ClapArgs, Parser, Subcommand};
use rld_core::AdmissionHash32 as Hash;
use rld_pow::{
    storage::{DirectoryLease, Store as V1Store},
    transition::Adoption,
    MAX_BLOCK_BYTES,
};
use rld_value_successor::adoption::EarthSuccessorAdoption;
use rld_value_successor::chain::{
    finality::{FinalityCertificate, FinalityStatement},
    mine_batch,
    storage::{command_id, CandidateStore},
    Block, CandidateChain, Command,
};
use rld_value_successor::transition::{TransitionAuthorization, TransitionPreview};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    Run {
        #[command(flatten)]
        common: Common,
        /// Signed, purpose-specific statement for the exact replayed preview.
        #[arg(long)]
        transition_authorization: PathBuf,
        /// Locally accepted authorization statement ID; a signature alone is not consent.
        #[arg(long)]
        accept_transition_authorization: String,
        /// Public key independently pinned by this candidate operator.
        #[arg(long)]
        transition_signer: String,
        /// Confirm that the v1 directory is a disposable offline copy, not a live node.
        #[arg(long)]
        offline_v1_copy: bool,
    },
    RunAdopted {
        #[command(flatten)]
        common: Common,
        /// Unanimous signed adoption of the exact new Earth chain and cut.
        #[arg(long)]
        earth_adoption: PathBuf,
        #[arg(long)]
        accept_earth_adoption: String,
    },
}

#[derive(ClapArgs)]
struct Common {
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
    #[arg(long = "candidate-dir", alias = "data-dir")]
    candidate_dir: PathBuf,
    #[arg(long, default_value = "127.0.0.1:48300")]
    listen: SocketAddr,
    #[arg(long)]
    peer: Vec<String>,
    #[arg(long)]
    mine_to: Option<String>,
    #[arg(long, default_value_t = 0)]
    mine_interval_ms: u64,
}

enum Mode {
    Candidate {
        transition_authorization: PathBuf,
        accept_transition_authorization: String,
        transition_signer: String,
        offline_v1_copy: bool,
    },
    Adopted {
        earth_adoption: PathBuf,
        accept_earth_adoption: String,
    },
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before UNIX epoch")
        .as_secs()
}
fn read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > limit as u64 {
        bail!("unsafe or oversized transition input");
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        bail!("transition input exceeded bound");
    }
    Ok(bytes)
}
fn parse_hash(input: &str) -> Result<Hash> {
    Hash::from_hex(input).map_err(|error| anyhow!(error))
}
fn validate_peer(peer: &str) -> Result<String> {
    let url = reqwest::Url::parse(peer)?;
    let host = url.host_str().ok_or_else(|| anyhow!("missing peer host"))?;
    let ip: IpAddr = host
        .parse()
        .context("candidate peers must use loopback IP addresses")?;
    if url.scheme() != "http"
        || !ip.is_loopback()
        || url.port().is_none()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        bail!("candidate peer must be an explicit loopback HTTP origin");
    }
    Ok(peer.trim_end_matches('/').to_owned())
}

struct Runtime {
    store: Mutex<CandidateStore>,
    // Keep the replayed v1 directory locked for the entire candidate lifetime.
    // Otherwise a local v1 miner can extend the supposedly fixed cut after
    // CandidateStore has copied its state into the successor anchor.
    _v1_lease: DirectoryLease,
    transition_preview_id: Hash,
    transition_authorization_id: Hash,
    adopted: bool,
    permits: Arc<Semaphore>,
    running: AtomicBool,
    miner: Option<String>,
    relay_configured: bool,
    validation_miner: String,
    submissions: AtomicU64,
    pending_cursors: Mutex<BTreeMap<String, usize>>,
    pending_push: Mutex<BTreeMap<String, (Instant, BTreeSet<Hash>)>>,
}

fn network_status(adopted: bool) -> &'static str {
    if adopted {
        "ADOPTED_EARTH_SUCCESSOR_V1"
    } else {
        "UNADOPTED_LOCAL_CANDIDATE_ONLY"
    }
}

fn api_base(adopted: bool) -> &'static str {
    if adopted {
        "/v1/earth"
    } else {
        "/v1/successor-candidate"
    }
}
#[derive(Clone)]
struct App(Arc<Runtime>);
type Api<T> = std::result::Result<Json<T>, (StatusCode, String)>;
fn bad(error: impl ToString) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, error.to_string())
}
fn busy() -> (StatusCode, String) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "candidate verification unavailable".into(),
    )
}

async fn status(State(app): State<App>) -> Api<serde_json::Value> {
    let store = app.0.store.lock().map_err(|_| busy())?;
    let chain = store.chain();
    Ok(Json(serde_json::json!({
        "status": network_status(app.0.adopted),
        "chain_id": chain.chain_id(),
        "v1_tip": chain.v1_tip(),
        "tip": chain.tip(),
        "height": chain.height().to_string(),
        "chainwork": chain.chainwork(),
        "state_root": chain.state().root().map_err(bad)?,
        "storage_healthy": store.healthy(),
        "transition_preview_id": app.0.transition_preview_id,
        "transition_authorization_id": (!app.0.adopted).then_some(app.0.transition_authorization_id),
        "earth_adoption_id": app.0.adopted.then_some(app.0.transition_authorization_id),
        "submitted_candidate_commands": store.submitted_count(),
        "live_rld": app.0.adopted,
        "finalized_source": chain.finalized().map(|(block, height)| serde_json::json!({"block":block,"height":height.to_string()})),
        "cross_region_imports_enabled": app.0.adopted && store.finality().is_some()
    })))
}
async fn continuity(State(app): State<App>) -> Api<serde_json::Value> {
    let store = app.0.store.lock().map_err(|_| busy())?;
    let commitment = store.chain().anchor_commitment().map_err(bad)?;
    let successor_base_root = commitment.root().map_err(bad)?;
    Ok(Json(serde_json::json!({
        "status": network_status(app.0.adopted),
        "v1_chain_id": commitment.chain_id,
        "v1_tip": commitment.v1_tip,
        "v1_state_root": commitment.v1_root,
        "v1_height": commitment.anchor_height.to_string(),
        "successor_base_root": successor_base_root,
        "transition_preview_id": app.0.transition_preview_id,
        "transition_authorization_id": (!app.0.adopted).then_some(app.0.transition_authorization_id),
        "earth_adoption_id": app.0.adopted.then_some(app.0.transition_authorization_id),
        "commitment": commitment,
        "live_rld": app.0.adopted
    })))
}

async fn escrow(
    State(app): State<App>,
    RoutePath(id): RoutePath<String>,
) -> Api<serde_json::Value> {
    let id = parse_hash(&id).map_err(bad)?;
    let store = app.0.store.lock().map_err(|_| busy())?;
    let chain = store.chain();
    let escrow = chain.state().escrow(id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            "candidate escrow absent from selected branch".into(),
        )
    })?;
    let confirmations = chain
        .height()
        .checked_sub(escrow.opened_height)
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| bad("candidate escrow height mismatch"))?;
    Ok(Json(serde_json::json!({
        "status":network_status(app.0.adopted),
        "live_rld":app.0.adopted,
        "chain_id":chain.chain_id(),
        "tip":chain.tip(),
        "height":chain.height().to_string(),
        "state_root":chain.state().root().map_err(bad)?,
        "escrow":escrow,
        "confirmations":confirmations.to_string()
    })))
}

async fn command_status(
    State(app): State<App>,
    RoutePath(id): RoutePath<String>,
) -> Api<serde_json::Value> {
    let id = parse_hash(&id).map_err(bad)?;
    let store = app.0.store.lock().map_err(|_| busy())?;
    let included = store.selected_inclusion(id).map_err(bad)?;
    if included.is_none() && !store.has_submission(id).map_err(bad)? {
        return Err((StatusCode::NOT_FOUND, "candidate command unknown".into()));
    }
    let (block, height, confirmations) = match included {
        Some((block, height, confirmations)) => (
            Some(block),
            Some(height.to_string()),
            Some(confirmations.to_string()),
        ),
        None => (None, None, None),
    };
    Ok(Json(serde_json::json!({
        "status":network_status(app.0.adopted),
        "live_rld":app.0.adopted,
        "command":id,
        "candidate_included":block.is_some(),
        "selected_block":block,
        "selected_height":height,
        "candidate_confirmations":confirmations,
        "tip":store.chain().tip()
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
    if body.len() > MAX_BLOCK_BYTES {
        return Err(bad("template request byte bound"));
    }
    let request: TemplateRequest = serde_json::from_slice(&body).map_err(bad)?;
    let store = app.0.store.lock().map_err(|_| busy())?;
    if !store.healthy() {
        return Err(busy());
    }
    let timestamp = store.chain().template_time(now()).map_err(bad)?;
    if timestamp > now().saturating_add(7200) {
        return Err(bad("clock behind median"));
    }
    let mut commands = if request.include_submitted {
        store
            .mineable_commands(&request.miner, timestamp)
            .map_err(bad)?
    } else {
        Vec::new()
    };
    commands.extend(request.commands);
    Ok(Json(
        store
            .chain()
            .template(request.miner, timestamp, commands)
            .map_err(bad)?,
    ))
}

async fn submit_command(State(app): State<App>, body: Bytes) -> Api<serde_json::Value> {
    if body.len() > 32768 {
        return Err(bad("candidate command byte bound"));
    }
    // Template validation needs a valid fee recipient, but a non-mining peer
    // must be able to durably relay a signed command to another miner.
    if app.0.miner.is_none() && !app.0.relay_configured {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "candidate command intake needs a local miner or configured relay peer".into(),
        ));
    }
    let miner = app
        .0
        .miner
        .clone()
        .unwrap_or_else(|| app.0.validation_miner.clone());
    let permit = app
        .0
        .permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| busy())?;
    let command: Command = serde_json::from_slice(&body).map_err(bad)?;
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut store = app
            .0
            .store
            .lock()
            .map_err(|_| "candidate store lock poisoned".to_owned())?;
        let timestamp = store.chain().template_time(now())?;
        if timestamp > now().saturating_add(7200) {
            return Err("clock behind candidate median".into());
        }
        let (id, newly_submitted) = store.submit_command(command, &miner, timestamp)?;
        if newly_submitted {
            app.0.submissions.fetch_add(1, Ordering::Release);
        }
        Ok::<_, String>(serde_json::json!({
            "status":network_status(app.0.adopted),
            "newly_submitted":newly_submitted,
            "command":id,
            "confirmed":false,
            "submitted_candidate_commands":store.submitted_count()
        }))
    })
    .await
    .map_err(bad)?
    .map_err(bad)?;
    Ok(Json(result))
}

async fn submit_block(State(app): State<App>, body: Bytes) -> Api<serde_json::Value> {
    if body.len() > MAX_BLOCK_BYTES {
        return Err(bad("candidate block byte bound"));
    }
    let permit = app
        .0
        .permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| busy())?;
    let block: Block = serde_json::from_slice(&body).map_err(bad)?;
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut store = app
            .0
            .store
            .lock()
            .map_err(|_| "candidate store lock poisoned".to_owned())?;
        let selected = store.accept(block, now())?;
        Ok::<_, String>(serde_json::json!({
            "status":network_status(app.0.adopted),
            "selected":selected,
            "tip":store.chain().tip(),
            "height":store.chain().height().to_string()
        }))
    })
    .await
    .map_err(bad)?
    .map_err(bad)?;
    Ok(Json(result))
}

async fn write_checkpoint(State(app): State<App>, body: Bytes) -> Api<serde_json::Value> {
    if !body.is_empty() {
        return Err(bad("candidate checkpoint request must have an empty body"));
    }
    let permit = app
        .0
        .permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| busy())?;
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut store = app
            .0
            .store
            .lock()
            .map_err(|_| "candidate store lock poisoned".to_owned())?;
        let tip = store.write_replayed_checkpoint()?;
        Ok::<_, String>(serde_json::json!({
            "status":network_status(app.0.adopted),
            "checkpoint":tip,
            "height":store.chain().height().to_string(),
            "state_root":store.chain().state().root()?,
            "full_replay_required_on_reopen":true,
            "blocks_pruned":false,
            "live_rld":app.0.adopted
        }))
    })
    .await
    .map_err(bad)?
    .map_err(bad)?;
    Ok(Json(result))
}

async fn finality_status(State(app): State<App>) -> Api<Option<FinalityCertificate>> {
    if !app.0.adopted {
        return Err(bad("Earth finality requires adopted mode"));
    }
    let store = app.0.store.lock().map_err(|_| busy())?;
    Ok(Json(store.finality().cloned()))
}

async fn finality_draft(
    State(app): State<App>,
    RoutePath(block): RoutePath<String>,
) -> Api<FinalityStatement> {
    if !app.0.adopted {
        return Err(bad("Earth finality requires adopted mode"));
    }
    let block = parse_hash(&block).map_err(bad)?;
    let store = app.0.store.lock().map_err(|_| busy())?;
    let previous = store
        .finality()
        .map(|cert| cert.statement.id())
        .transpose()
        .map_err(bad)?;
    let statement = FinalityStatement::from_chain(
        store.chain(),
        app.0.transition_authorization_id,
        block,
        previous,
    )
    .map_err(bad)?;
    Ok(Json(statement))
}

async fn install_finality(State(app): State<App>, body: Bytes) -> Api<serde_json::Value> {
    if !app.0.adopted || body.len() > 8192 {
        return Err(bad("invalid Earth finality request"));
    }
    let cert: FinalityCertificate = serde_json::from_slice(&body).map_err(bad)?;
    if serde_json::to_vec(&cert).map_err(bad)? != body {
        return Err(bad("noncanonical Earth finality certificate"));
    }
    let mut store = app.0.store.lock().map_err(|_| busy())?;
    let id = store.install_finality(cert).map_err(bad)?;
    Ok(Json(
        serde_json::json!({"certificate_id":id,"finalized":true}),
    ))
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
    v1_tip: Hash,
    transition_preview_id: Hash,
    common: Hash,
    tip: Hash,
    blocks: Vec<Block>,
}
fn sync_response(
    chain: &CandidateChain,
    transition_preview_id: Hash,
    locator: &[Hash],
) -> Result<SyncResponse> {
    if locator.is_empty() || locator.len() > 64 {
        bail!("candidate locator bound");
    }
    let path = chain.best_blocks().map_err(|e| anyhow!(e))?;
    let ids = path
        .iter()
        .map(|b| b.header.id())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| anyhow!(e))?;
    let known: std::collections::BTreeSet<_> = locator.iter().copied().collect();
    let start = match ids.iter().rposition(|id| known.contains(id)) {
        Some(index) => index + 1,
        None if known.contains(&chain.v1_tip()) => 0,
        None => bail!("no shared candidate ancestry"),
    };
    Ok(SyncResponse {
        chain_id: chain.chain_id(),
        v1_tip: chain.v1_tip(),
        transition_preview_id,
        common: if start == 0 {
            chain.v1_tip()
        } else {
            ids[start - 1]
        },
        tip: chain.tip(),
        blocks: path.into_iter().skip(start).take(8).cloned().collect(),
    })
}
async fn sync(State(app): State<App>, body: Bytes) -> Api<SyncResponse> {
    if body.len() > 8192 {
        return Err(bad("candidate sync request byte bound"));
    }
    let request: SyncRequest = serde_json::from_slice(&body).map_err(bad)?;
    let store = app.0.store.lock().map_err(|_| busy())?;
    Ok(Json(
        sync_response(store.chain(), app.0.transition_preview_id, &request.locator).map_err(bad)?,
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingRequest {
    offset: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingPage {
    chain_id: Hash,
    v1_tip: Hash,
    transition_preview_id: Hash,
    tip: Hash,
    commands: Vec<Command>,
    next_offset: Option<usize>,
}

async fn pending_page(State(app): State<App>, body: Bytes) -> Api<PendingPage> {
    if body.len() > 128 {
        return Err(bad("candidate pending request byte bound"));
    }
    let request: PendingRequest = serde_json::from_slice(&body).map_err(bad)?;
    if request.offset > 128 {
        return Err(bad("candidate pending request offset bound"));
    }
    let store = app.0.store.lock().map_err(|_| busy())?;
    if !store.healthy() {
        return Err(busy());
    }
    let timestamp = store.chain().template_time(now()).map_err(bad)?;
    let mineable = store
        .mineable_commands(&app.0.validation_miner, timestamp)
        .map_err(bad)?;
    // A deep reorganization can return many journaled commands to the queue.
    // Only advertise the bounded wave that a miner can currently include;
    // expired or otherwise invalid history must not hide new commands.
    let submitted = &mineable;
    let mut commands = Vec::new();
    let mut bytes = 512usize;
    for command in submitted.iter().skip(request.offset).take(8) {
        let encoded = serde_json::to_vec(command).map_err(bad)?;
        if bytes.saturating_add(encoded.len()) > MAX_BLOCK_BYTES {
            break;
        }
        bytes += encoded.len();
        commands.push((*command).clone());
    }
    if commands.is_empty() && request.offset < submitted.len() {
        return Err(bad("candidate command exceeds pending page bound"));
    }
    let end = request.offset + commands.len();
    Ok(Json(PendingPage {
        chain_id: store.chain().chain_id(),
        v1_tip: store.chain().v1_tip(),
        transition_preview_id: app.0.transition_preview_id,
        tip: store.chain().tip(),
        commands,
        next_offset: (end < submitted.len()).then_some(end),
    }))
}
fn locator(chain: &CandidateChain) -> Result<Vec<Hash>> {
    let path = chain.best_blocks().map_err(|e| anyhow!(e))?;
    let mut ids = Vec::new();
    let mut back = 0usize;
    let mut step = 1usize;
    while back < path.len() && ids.len() < 63 {
        ids.push(
            path[path.len() - 1 - back]
                .header
                .id()
                .map_err(|e| anyhow!(e))?,
        );
        if ids.len() > 10 {
            step = step.saturating_mul(2);
        }
        back = back.saturating_add(step);
    }
    ids.push(chain.v1_tip());
    Ok(ids)
}
async fn pull_peer(app: &App, client: &reqwest::Client, peer: &str) -> Result<()> {
    for _ in 0..16 {
        let request = {
            let store = app
                .0
                .store
                .lock()
                .map_err(|_| anyhow!("candidate store lock"))?;
            serde_json::json!({"locator":locator(store.chain())?})
        };
        let mut response = client
            .post(format!("{peer}{}/sync", api_base(app.0.adopted)))
            .json(&request)
            .send()
            .await?
            .error_for_status()?;
        let limit = MAX_BLOCK_BYTES * 8 + 8192;
        if response
            .content_length()
            .is_some_and(|len| len > limit as u64)
        {
            bail!("oversized candidate peer response");
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if bytes.len() + chunk.len() > limit {
                bail!("oversized candidate peer response");
            }
            bytes.extend(chunk);
        }
        let batch: SyncResponse = serde_json::from_slice(&bytes)?;
        if batch.blocks.len() > 8 {
            bail!("candidate peer block count bound");
        }
        let terminal = batch.blocks.is_empty();
        let mut store = app
            .0
            .store
            .lock()
            .map_err(|_| anyhow!("candidate store lock"))?;
        let chain = store.chain();
        if batch.chain_id != chain.chain_id()
            || batch.v1_tip != chain.v1_tip()
            || batch.transition_preview_id != app.0.transition_preview_id
        {
            bail!("candidate peer anchor or preview mismatch");
        }
        if batch.common != chain.v1_tip() && chain.block(batch.common).is_none() {
            bail!("candidate peer supplied unknown common parent");
        }
        let mut parent = batch.common;
        for block in batch.blocks {
            if block.header.parent != parent {
                bail!("discontinuous candidate peer response");
            }
            parent = block.header.id().map_err(|e| anyhow!(e))?;
            store.accept(block, now()).map_err(|e| anyhow!(e))?;
        }
        if terminal || parent == batch.tip {
            break;
        }
    }
    if app.0.adopted {
        let certificate =
            rld_value_successor::candidate_client::fetch_finality(client, peer).await?;
        if let Some(certificate) = certificate {
            let mut store = app
                .0
                .store
                .lock()
                .map_err(|_| anyhow!("candidate store lock"))?;
            let old_height = store.finality().map_or(0, |old| old.statement.height);
            if certificate.statement.height > old_height {
                store
                    .install_finality(certificate)
                    .map_err(|e| anyhow!(e))?;
            } else if certificate.statement.height == old_height
                && store.finality() != Some(&certificate)
            {
                bail!("conflicting Earth source finality certificates");
            }
        }
    }
    Ok(())
}

/// Pull one bounded page after block sync. Each item still passes ordinary
/// durable admission, so a peer's journal is never trusted as chain state.
async fn pull_pending_peer(app: &App, client: &reqwest::Client, peer: &str) -> Result<()> {
    let offset = *app
        .0
        .pending_cursors
        .lock()
        .map_err(|_| anyhow!("candidate pending cursor lock"))?
        .get(peer)
        .unwrap_or(&0);
    let response = client
        .post(format!("{peer}{}/pending", api_base(app.0.adopted)))
        .json(&serde_json::json!({"offset": offset}))
        .send()
        .await?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(());
    }
    let mut response = response.error_for_status()?;
    let limit = MAX_BLOCK_BYTES + 8192;
    if response
        .content_length()
        .is_some_and(|len| len > limit as u64)
    {
        bail!("oversized candidate pending response");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len().saturating_add(chunk.len()) > limit {
            bail!("oversized candidate pending response");
        }
        bytes.extend(chunk);
    }
    let page: PendingPage = serde_json::from_slice(&bytes)?;
    if page.commands.len() > 8
        || page.next_offset.is_some_and(|next| {
            next != offset + page.commands.len() || next <= offset || next > 128
        })
    {
        bail!("malformed candidate pending page");
    }
    {
        let store = app
            .0
            .store
            .lock()
            .map_err(|_| anyhow!("candidate store lock"))?;
        if page.chain_id != store.chain().chain_id()
            || page.v1_tip != store.chain().v1_tip()
            || page.transition_preview_id != app.0.transition_preview_id
        {
            bail!("candidate pending page anchor or preview mismatch");
        }
    }
    for command in page.commands {
        let encoded = serde_json::to_vec(&command)?;
        if encoded.len() > 32768 {
            continue;
        }
        // A command may already be mined or invalid on our selected branch.
        // Neither outcome creates a balance or blocks the next page.
        let _ = submit_command(State(app.clone()), Bytes::from(encoded)).await;
    }
    app.0
        .pending_cursors
        .lock()
        .map_err(|_| anyhow!("candidate pending cursor lock"))?
        .insert(peer.to_owned(), page.next_offset.unwrap_or(0));
    Ok(())
}

/// Announce our currently mineable journal commands to a configured peer.
/// A timed refresh lets a restarted peer recover its missing journal entries.
async fn push_pending_peer(app: &App, client: &reqwest::Client, peer: &str) -> Result<()> {
    let pending = {
        let store = app
            .0
            .store
            .lock()
            .map_err(|_| anyhow!("candidate store lock"))?;
        let timestamp = store.chain().template_time(now()).map_err(|e| anyhow!(e))?;
        if timestamp > now().saturating_add(7200) {
            bail!("clock behind candidate median");
        }
        store
            .mineable_commands(&app.0.validation_miner, timestamp)
            .map_err(|e| anyhow!(e))?
            .into_iter()
            .map(|command| Ok((command_id(&command).map_err(|e| anyhow!(e))?, command)))
            .collect::<Result<Vec<_>>>()?
    };
    let to_send = {
        let mut cursors = app
            .0
            .pending_push
            .lock()
            .map_err(|_| anyhow!("candidate pending push lock"))?;
        let (since, sent) = cursors
            .entry(peer.to_owned())
            .or_insert_with(|| (Instant::now(), BTreeSet::new()));
        if since.elapsed() >= Duration::from_secs(120) {
            *since = Instant::now();
            sent.clear();
        }
        let live = pending.iter().map(|(id, _)| *id).collect::<BTreeSet<_>>();
        sent.retain(|id| live.contains(id));
        pending
            .into_iter()
            .filter(|(id, _)| !sent.contains(id))
            .take(8)
            .collect::<Vec<_>>()
    };
    for (id, command) in to_send {
        let response = client
            .post(format!("{peer}{}/commands", api_base(app.0.adopted)))
            .json(&command)
            .send()
            .await?;
        if !response.status().is_success() {
            bail!("peer declined candidate command: {}", response.status());
        }
        app.0
            .pending_push
            .lock()
            .map_err(|_| anyhow!("candidate pending push lock"))?
            .get_mut(peer)
            .ok_or_else(|| anyhow!("candidate pending push cursor missing"))?
            .1
            .insert(id);
    }
    Ok(())
}

fn mine_loop(app: App, miner: String, interval_ms: u64) {
    while app.0.running.load(Ordering::Acquire) {
        let candidate = (|| -> Result<(Block, u64)> {
            let store = app
                .0
                .store
                .lock()
                .map_err(|_| anyhow!("candidate store lock"))?;
            if !store.healthy() {
                bail!("candidate store unhealthy");
            }
            let time = store.chain().template_time(now()).map_err(|e| anyhow!(e))?;
            if time > now().saturating_add(7200) {
                bail!("clock behind candidate median");
            }
            let commands = store
                .mineable_commands(&miner, time)
                .map_err(|e| anyhow!(e))?;
            let epoch = app.0.submissions.load(Ordering::Acquire);
            store
                .chain()
                .template(miner.clone(), time, commands)
                .map(|block| (block, epoch))
                .map_err(|e| anyhow!(e))
        })();
        let (mut block, epoch) = match candidate {
            Ok(candidate) => candidate,
            Err(error) => {
                eprintln!("candidate mining paused: {error}");
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
                    let mut store = match app.0.store.lock() {
                        Ok(store) => store,
                        Err(_) => return,
                    };
                    if store.chain().tip() == block.header.parent
                        && app.0.submissions.load(Ordering::Acquire) == epoch
                    {
                        if let Err(error) = store.accept(block, now()) {
                            eprintln!("candidate mined block rejected: {error}");
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
                    if app.0.submissions.load(Ordering::Acquire) != epoch
                        || app
                            .0
                            .store
                            .lock()
                            .is_ok_and(|store| store.chain().tip() != block.header.parent)
                    {
                        break;
                    }
                }
                Err(error) => {
                    eprintln!("candidate mining failed: {error}");
                    break;
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let (common, mode) = match Args::parse().command {
        Action::Run {
            common,
            transition_authorization,
            accept_transition_authorization,
            transition_signer,
            offline_v1_copy,
        } => (
            common,
            Mode::Candidate {
                transition_authorization,
                accept_transition_authorization,
                transition_signer,
                offline_v1_copy,
            },
        ),
        Action::RunAdopted {
            common,
            earth_adoption,
            accept_earth_adoption,
        } => (
            common,
            Mode::Adopted {
                earth_adoption,
                accept_earth_adoption,
            },
        ),
    };
    let Common {
        genesis,
        history,
        adoption,
        manifest_pin,
        accept_adoption,
        pinned_v1_source,
        v1_data_dir,
        transition_preview,
        accept_transition_preview,
        candidate_dir,
        listen,
        peer,
        mine_to,
        mine_interval_ms,
    } = common;
    if matches!(
        mode,
        Mode::Candidate {
            offline_v1_copy: false,
            ..
        }
    ) {
        bail!("--offline-v1-copy is required: use a disposable copy of the v1 data directory");
    }
    if !listen.ip().is_loopback() {
        bail!("Earth successor node must listen on loopback behind a bounded public gateway");
    }
    if peer.len() > 16 {
        bail!("at most 16 candidate peers");
    }
    let peers = peer
        .iter()
        .map(|p| validate_peer(p))
        .collect::<Result<Vec<_>>>()?;
    if let Some(miner) = &mine_to {
        rld_core::validate_ed25519_public_key(miner).map_err(|e| anyhow!(e))?;
    }
    if mine_interval_ms > 60_000 {
        bail!("candidate mining interval exceeds bound");
    }
    let genesis_bytes = read(&genesis, 65536)?;
    let history_bytes = read(&history, 32 * 1024 * 1024)?;
    let a: Adoption = serde_json::from_slice(&read(&adoption, 65536)?)?;
    let context = a
        .verify_with_pinned_release_source(
            &genesis_bytes,
            &history_bytes,
            parse_hash(&manifest_pin)?,
            parse_hash(&accept_adoption)?,
            parse_hash(&pinned_v1_source)?,
        )
        .map_err(|e| anyhow!(e))?;
    if context.started_at > now() {
        bail!("v1 adoption begins in the future");
    }
    let v1 = V1Store::open(&v1_data_dir, context, now()).map_err(|e| anyhow!(e))?;
    let fresh_earth = matches!(mode, Mode::Adopted { .. })
        && v1.chain().context.legacy_height == 0
        && v1.chain().height() == 0
        && v1.chain().best_blocks().map_err(|e| anyhow!(e))?.is_empty();
    if !fresh_earth && v1.chain().height() <= v1.chain().context.legacy_height {
        bail!("offline v1 copy contains no replayed PoW block");
    }
    let validation_miner = if fresh_earth {
        a.approvals
            .first()
            .ok_or_else(|| anyhow!("fresh Earth has no signed validator"))?
            .public_key
            .clone()
    } else {
        v1.chain()
            .block(v1.chain().tip())
            .ok_or_else(|| anyhow!("replayed v1 tip block absent"))?
            .header
            .miner
            .clone()
    };
    rld_core::validate_ed25519_public_key(&validation_miner).map_err(|error| anyhow!(error))?;
    let preview_bytes = read(&transition_preview, 4096)?;
    let preview: TransitionPreview = serde_json::from_slice(&preview_bytes)?;
    if preview.canonical_bytes().map_err(|e| anyhow!(e))? != preview_bytes {
        bail!("transition preview must have exact canonical bytes");
    }
    preview
        .verify_for_candidate(
            v1.chain(),
            a.statement.implementation_source_sha256,
            parse_hash(&accept_transition_preview)?,
        )
        .map_err(|e| anyhow!(e))?;
    let transition_preview_id = preview.id().map_err(|e| anyhow!(e))?;
    let (adopted, transition_authorization_id) = match mode {
        Mode::Candidate {
            transition_authorization,
            accept_transition_authorization,
            transition_signer,
            ..
        } => {
            let authorization_bytes = read(&transition_authorization, 2048)?;
            let authorization: TransitionAuthorization =
                serde_json::from_slice(&authorization_bytes)?;
            if authorization.canonical_bytes().map_err(|e| anyhow!(e))? != authorization_bytes {
                bail!("transition authorization must have exact canonical bytes");
            }
            let id = parse_hash(&accept_transition_authorization)?;
            authorization
                .verify_for_candidate(&preview, id, &transition_signer)
                .map_err(|e| anyhow!(e))?;
            (false, id)
        }
        Mode::Adopted {
            earth_adoption,
            accept_earth_adoption,
        } => {
            let bytes = read(&earth_adoption, 8192)?;
            let signed: EarthSuccessorAdoption = serde_json::from_slice(&bytes)?;
            if serde_json::to_vec(&signed)? != bytes {
                bail!("Earth adoption must have exact canonical bytes");
            }
            let id = parse_hash(&accept_earth_adoption)?;
            signed
                .verify(&genesis_bytes, &history_bytes, &a, v1.chain(), &preview, id)
                .map_err(|e| anyhow!(e))?;
            (true, id)
        }
    };
    let candidate = if adopted {
        let keys = a
            .approvals
            .iter()
            .map(|approval| approval.public_key.clone())
            .collect();
        CandidateStore::open_finalized(
            &candidate_dir,
            v1.chain(),
            now(),
            transition_authorization_id,
            keys,
        )
        .map_err(|e| anyhow!(e))?
    } else {
        CandidateStore::open(&candidate_dir, v1.chain(), now()).map_err(|e| anyhow!(e))?
    };
    let v1_lease = v1.into_directory_lease();
    let app = App(Arc::new(Runtime {
        store: Mutex::new(candidate),
        _v1_lease: v1_lease,
        transition_preview_id,
        transition_authorization_id,
        adopted,
        permits: Arc::new(Semaphore::new(2)),
        running: AtomicBool::new(true),
        miner: mine_to.clone(),
        relay_configured: !peers.is_empty(),
        validation_miner,
        submissions: AtomicU64::new(0),
        pending_cursors: Mutex::new(BTreeMap::new()),
        pending_push: Mutex::new(BTreeMap::new()),
    }));
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .context("bind Earth successor loopback")?;
    let base = api_base(adopted);
    let router = Router::new()
        .route(&format!("{base}/status"), get(status))
        .route(&format!("{base}/continuity"), get(continuity))
        .route(&format!("{base}/escrows/{{id}}"), get(escrow))
        .route(&format!("{base}/commands/{{id}}"), get(command_status))
        .route(&format!("{base}/template"), post(template))
        .route(&format!("{base}/commands"), post(submit_command))
        .route(&format!("{base}/blocks"), post(submit_block))
        .route(&format!("{base}/checkpoint"), post(write_checkpoint))
        .route(
            &format!("{base}/finality"),
            get(finality_status).post(install_finality),
        )
        .route(
            &format!("{base}/finality-draft/{{block}}"),
            get(finality_draft),
        )
        .route(&format!("{base}/sync"), post(sync))
        .route(&format!("{base}/pending"), post(pending_page))
        .layer(DefaultBodyLimit::max(MAX_BLOCK_BYTES))
        .with_state(app.clone());
    let miner = mine_to.map(|key| {
        let runtime = app.clone();
        std::thread::spawn(move || mine_loop(runtime, key, mine_interval_ms))
    });
    let peer_app = app.clone();
    let peer_task = tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("candidate HTTP client");
        while peer_app.0.running.load(Ordering::Acquire) {
            for peer in &peers {
                if let Err(error) = pull_peer(&peer_app, &client, peer).await {
                    eprintln!("candidate peer sync unavailable: {error}");
                    continue;
                }
                if let Err(error) = pull_pending_peer(&peer_app, &client, peer).await {
                    eprintln!("candidate pending pull unavailable: {error}");
                }
                if let Err(error) = push_pending_peer(&peer_app, &client, peer).await {
                    eprintln!("candidate pending announcement unavailable: {error}");
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
    let shutdown_app = app.clone();
    let shutdown = async move {
        #[cfg(unix)]
        {
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("candidate SIGTERM handler");
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
        }
        #[cfg(not(unix))]
        tokio::signal::ctrl_c()
            .await
            .expect("candidate CTRL-C handler");
        shutdown_app.0.running.store(false, Ordering::Release);
    };
    eprintln!("{} listening on {listen}", network_status(adopted));
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await?;
    app.0.running.store(false, Ordering::Release);
    peer_task.abort();
    if let Some(miner) = miner {
        miner
            .join()
            .map_err(|_| anyhow!("candidate miner thread panicked"))?;
    }
    Ok(())
}
