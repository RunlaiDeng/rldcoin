//! Loopback-only candidate merchant endpoint. It is not a PoW v1 payment API.

use anyhow::{anyhow, bail, Result};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use rld_core::{
    sign_bytes, validate_ed25519_public_key, AdmissionHash32 as Hash, Amount, Identity,
};
use rld_fast_payments::{Funding, PaymentOffer, SignedState};
use rld_pow::{storage::Store as V1Store, transition::Adoption, OutPoint};
use rld_value_successor::{
    candidate_client::{
        load_verified_transition_preview_file, loopback_origin, now, refresh_mode,
        verify_earth_adoption_file, NodeMode,
    },
    chain::storage::CandidateStore,
    signed_state_hash,
    wallet_guard::{FeeFunding, GuardedRecipient},
    watchtower::{WatchAck, WatchedReceipt},
    ActionFee, ActionFeeIntent, DisputeAction,
};
use serde::Deserialize;
use std::{
    fs,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

fn mode_status(mode: NodeMode) -> &'static str {
    match mode {
        NodeMode::Candidate => "UNADOPTED_LOCAL_CANDIDATE_ONLY",
        NodeMode::Adopted(_) => "ADOPTED_EARTH_SUCCESSOR_V1",
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
    candidate_dir: PathBuf,
    #[arg(long)]
    wallet_dir: PathBuf,
    #[arg(long)]
    receiver_key: PathBuf,
    #[arg(long)]
    funding_config: PathBuf,
    #[arg(long)]
    node: String,
    #[arg(long)]
    watchtower: String,
    #[arg(long)]
    watcher_public_key: String,
    #[arg(long, default_value = "127.0.0.1:48301")]
    listen: SocketAddr,
    /// Confirm that this process sees only a disposable PoW v1 copy.
    #[arg(long)]
    offline_v1_copy: bool,
    #[arg(long, requires = "accept_earth_adoption")]
    earth_adoption: Option<PathBuf>,
    #[arg(long, requires = "earth_adoption")]
    accept_earth_adoption: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FundingConfig {
    funding: Funding,
    initial: SignedState,
    fee_input: OutPoint,
    fee_input_amount: Amount,
    fee: Amount,
    #[serde(with = "rld_pow::decimal")]
    valid_through_height: u128,
}

struct Session {
    store: CandidateStore,
    wallet: GuardedRecipient,
    receiver_secret: Zeroizing<String>,
    fee: FeeFunding,
}

struct Runtime {
    session: Mutex<Session>,
    client: reqwest::Client,
    node: String,
    watchtower: String,
    watcher_public_key: String,
    transition_preview_id: Hash,
    mode: NodeMode,
}

type Api<T> = std::result::Result<Json<T>, (StatusCode, String)>;

fn read(path: &Path, limit: usize, owner_only: bool) -> Result<Zeroizing<Vec<u8>>> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > limit as u64 {
        bail!("unsafe or oversized receiver input");
    }
    #[cfg(unix)]
    if owner_only {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            bail!("receiver key must be owner-only");
        }
    }
    #[cfg(not(unix))]
    let _ = owner_only;
    let mut bytes = Zeroizing::new(Vec::new());
    fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        bail!("receiver input exceeded bound");
    }
    Ok(bytes)
}

fn parse_hash(input: &str) -> Result<Hash> {
    Hash::from_hex(input).map_err(|error| anyhow!(error))
}

async fn status(State(runtime): State<Arc<Runtime>>) -> Api<serde_json::Value> {
    let session = runtime.session.lock().await;
    Ok(Json(serde_json::json!({
        "status":mode_status(runtime.mode),
        "live_rld":matches!(runtime.mode, NodeMode::Adopted(_)),
        "chain_id":session.store.chain().chain_id(),
        "tip":session.store.chain().tip(),
        "height":session.store.chain().height().to_string(),
        "receipt_sequence":session.wallet.latest().state.sequence,
        "watchtower_ack_required":true,
        "watcher_public_key":runtime.watcher_public_key
        ,"transition_preview_id":runtime.transition_preview_id
    })))
}

async fn offer(State(runtime): State<Arc<Runtime>>, body: Bytes) -> Api<WatchedReceipt> {
    if body.len() > 8192 {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "candidate offer too large".into(),
        ));
    }
    let payment: PaymentOffer = serde_json::from_slice(&body)
        .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    let mut session = runtime.session.lock().await;
    refresh_mode(
        &mut session.store,
        &runtime.client,
        &runtime.node,
        runtime.transition_preview_id,
        runtime.mode,
    )
    .await
    .map_err(|error| (StatusCode::SERVICE_UNAVAILABLE, error.to_string()))?;
    let Session {
        store,
        wallet,
        receiver_secret,
        fee,
    } = &mut *session;
    let receipt = wallet
        .accept_offer(
            store.chain(),
            2,
            matches!(runtime.mode, NodeMode::Adopted(_)),
            payment,
            receiver_secret,
            fee.clone(),
        )
        .map_err(|error| (StatusCode::CONFLICT, error))?;
    let package = wallet.watch_package().clone();
    let mut response = runtime
        .client
        .post(format!(
            "{}{}/packages",
            runtime.watchtower,
            if matches!(runtime.mode, NodeMode::Adopted(_)) {
                "/v1/earth-watchtower"
            } else {
                "/v1/candidate-watchtower"
            }
        ))
        .json(&package)
        .send()
        .await
        .map_err(|error| (StatusCode::SERVICE_UNAVAILABLE, error.to_string()))?
        .error_for_status()
        .map_err(|error| (StatusCode::SERVICE_UNAVAILABLE, error.to_string()))?;
    if response
        .content_length()
        .is_some_and(|length| length > 8192)
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "watch acknowledgment too large".into(),
        ));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| (StatusCode::SERVICE_UNAVAILABLE, error.to_string()))?
    {
        if bytes.len().saturating_add(chunk.len()) > 8192 {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "watch acknowledgment exceeded bound".into(),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    let watch_ack: WatchAck = serde_json::from_slice(&bytes)
        .map_err(|error| (StatusCode::SERVICE_UNAVAILABLE, error.to_string()))?;
    watch_ack
        .verify(&package, &runtime.watcher_public_key)
        .map_err(|error| (StatusCode::SERVICE_UNAVAILABLE, error))?;
    let delivery = WatchedReceipt {
        status: mode_status(runtime.mode).into(),
        live_rld: matches!(runtime.mode, NodeMode::Adopted(_)),
        receipt,
        watch_package: package,
        watch_ack,
    };
    delivery
        .verify(
            &delivery.watch_package.funding,
            &delivery.receipt.sender,
            &runtime.watcher_public_key,
        )
        .map_err(|error| (StatusCode::SERVICE_UNAVAILABLE, error))?;
    Ok(Json(delivery))
}

async fn shutdown() {
    #[cfg(unix)]
    {
        if let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! {
                _ = terminate.recv() => {},
                _ = tokio::signal::ctrl_c() => {},
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let mode = if let (Some(path), Some(id)) = (&args.earth_adoption, &args.accept_earth_adoption) {
        let _ = path;
        NodeMode::Adopted(parse_hash(id)?)
    } else {
        if !args.offline_v1_copy {
            bail!("candidate receiver requires disposable v1 copy");
        }
        NodeMode::Candidate
    };
    if !args.listen.ip().is_loopback() {
        bail!("receiver requires loopback listener");
    }
    let node = loopback_origin(&args.node)?;
    let watchtower = loopback_origin(&args.watchtower)?;
    validate_ed25519_public_key(&args.watcher_public_key).map_err(|error| anyhow!(error))?;
    let genesis = read(&args.genesis, 65536, false)?;
    let history = read(&args.history, 32 * 1024 * 1024, false)?;
    let adoption: Adoption = serde_json::from_slice(&read(&args.adoption, 65536, false)?)?;
    let context = adoption
        .verify_with_pinned_release_source(
            &genesis,
            &history,
            parse_hash(&args.manifest_pin)?,
            parse_hash(&args.accept_adoption)?,
            parse_hash(&args.pinned_v1_source)?,
        )
        .map_err(|error| anyhow!(error))?;
    let v1 = V1Store::open(&args.v1_data_dir, context, now()?).map_err(|error| anyhow!(error))?;
    let fresh_earth = matches!(mode, NodeMode::Adopted(_))
        && v1.chain().context.legacy_height == 0
        && v1.chain().height() == 0
        && v1.chain().best_blocks().map_err(|e| anyhow!(e))?.is_empty();
    if !fresh_earth && v1.chain().height() <= v1.chain().context.legacy_height {
        bail!("receiver v1 copy lacks accepted PoW history");
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
    let mut store = match mode {
        NodeMode::Adopted(id) => CandidateStore::open_finalized(
            &args.candidate_dir,
            v1.chain(),
            now()?,
            id,
            adoption.approvals.iter().map(|approval| approval.public_key.clone()).collect(),
        ),
        NodeMode::Candidate => CandidateStore::open(&args.candidate_dir, v1.chain(), now()?),
    }
    .map_err(|error| anyhow!(error))?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()?;
    refresh_mode(&mut store, &client, &node, preview_id, mode).await?;
    let config: FundingConfig = serde_json::from_slice(&read(&args.funding_config, 16384, false)?)?;
    let identity: Identity = serde_json::from_slice(&read(&args.receiver_key, 8192, true)?)?;
    let receiver = identity.public_key;
    let secret = Zeroizing::new(identity.secret_key);
    if receiver != config.funding.party_a && receiver != config.funding.party_b {
        bail!("receiver key is not a channel party");
    }
    config
        .initial
        .verify(&config.funding)
        .map_err(|error| anyhow!(error))?;
    let fee = FeeFunding {
        input: config.fee_input,
        input_amount: config.fee_input_amount,
        fee: config.fee,
        valid_through_height: config.valid_through_height,
    };
    let intent = ActionFeeIntent {
        chain_id: config.funding.chain_id,
        action: DisputeAction::Challenge,
        channel: config.funding.id().map_err(|error| anyhow!(error))?,
        signed_state: signed_state_hash(&config.initial).map_err(|error| anyhow!(error))?,
        input: fee.input.clone(),
        owner: receiver.clone(),
        fee: fee.fee,
        change: fee.input_amount.checked_sub(fee.fee)?,
        valid_through_height: fee.valid_through_height,
    };
    let initial_fee = ActionFee {
        owner_signature: sign_bytes(
            &secret,
            &intent.signing_bytes().map_err(|error| anyhow!(error))?,
        )
        .map_err(|error| anyhow!(error))?,
        intent,
    };
    let wallet = GuardedRecipient::open(
        &args.wallet_dir,
        config.funding,
        receiver,
        config.initial,
        Some(initial_fee),
    )
    .map_err(|error| anyhow!(error))?;
    let runtime = Arc::new(Runtime {
        session: Mutex::new(Session {
            store,
            wallet,
            receiver_secret: secret,
            fee,
        }),
        client,
        node,
        watchtower,
        watcher_public_key: args.watcher_public_key,
        transition_preview_id: preview_id,
        mode,
    });
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    eprintln!(
        "{} receiver listening on {}",
        mode_status(mode),
        args.listen
    );
    let base = if matches!(mode, NodeMode::Adopted(_)) {
        "/v1/earth-payment"
    } else {
        "/v1/candidate-payment"
    };
    axum::serve(
        listener,
        Router::new()
            .route(&format!("{base}/status"), get(status))
            .route(&format!("{base}/offers"), post(offer))
            .layer(DefaultBodyLimit::max(8192))
            .with_state(runtime),
    )
    .with_graceful_shutdown(shutdown())
    .await?;
    Ok(())
}
