//! Loopback-only monitor with a separate acknowledgement key for candidate
//! receipt delivery. The challenge itself still needs no private key.
//! A prepared package is not a live RLD payment guarantee.

use anyhow::{anyhow, bail, Context as _, Result};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use rld_core::{AdmissionHash32 as Hash, Identity};
use rld_fast_payments::successor::Escrow;
use rld_value_successor::candidate_client::{verify_node_preview_mode, NodeMode};
use rld_value_successor::watchtower::{
    storage::WatchStore, WatchAck, WatchDecision, WatchPackage, EARTH_STATUS,
};
use serde::Deserialize;
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

const CANDIDATE_STATUS: &str = "UNADOPTED_LOCAL_CANDIDATE_ONLY";

#[derive(Parser)]
struct Args {
    #[arg(long)]
    node: String,
    #[arg(long)]
    accept_transition_preview: String,
    #[arg(long)]
    package: PathBuf,
    /// Watchtower-owned durable state, outside the merchant wallet directory.
    #[arg(long)]
    watch_state_dir: PathBuf,
    /// Local acknowledgement signer; never used for channel value or challenges.
    #[arg(long)]
    ack_key: PathBuf,
    #[arg(long, default_value = "127.0.0.1:48302")]
    listen: SocketAddr,
    #[arg(long, default_value_t = 250)]
    poll_ms: u64,
    #[arg(long)]
    accept_earth_adoption: Option<String>,
}

#[derive(Deserialize)]
struct EscrowResponse {
    status: String,
    chain_id: Hash,
    height: String,
    live_rld: bool,
    escrow: Escrow,
}

struct Runtime {
    store: Mutex<WatchStore>,
    watcher_public: String,
    watcher_secret: Zeroizing<String>,
    client: reqwest::Client,
    node: String,
    transition_preview_id: Hash,
    mode: NodeMode,
}

type Api<T> = std::result::Result<Json<T>, (StatusCode, String)>;

fn loopback_origin(input: &str) -> Result<String> {
    let url = reqwest::Url::parse(input)?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("missing candidate host"))?;
    let ip: IpAddr = host
        .parse()
        .context("watchtower node must be a loopback IP")?;
    if url.scheme() != "http"
        || !ip.is_loopback()
        || url.port().is_none()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        bail!("watchtower node must be an explicit loopback HTTP origin");
    }
    Ok(input.trim_end_matches('/').to_owned())
}

fn load_package(path: &PathBuf) -> Result<WatchPackage> {
    let metadata = std::fs::symlink_metadata(path).context("read watch package metadata")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 32_768 {
        bail!("unsafe or oversized watch package");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("watch package is readable by other users");
        }
    }
    let bytes = std::fs::read(path).context("read watch package")?;
    if bytes.len() > 32_768 {
        bail!("watch package exceeded byte bound");
    }
    let package: WatchPackage = serde_json::from_slice(&bytes)?;
    package.validate().map_err(|error| anyhow!(error))?;
    Ok(package)
}

fn load_ack_key(path: &PathBuf) -> Result<Identity> {
    let metadata = std::fs::symlink_metadata(path).context("read watcher key metadata")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 8192 {
        bail!("unsafe or oversized watcher key");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("watcher key must be owner-only");
        }
    }
    let file = std::fs::File::open(path)?;
    let mut bytes = Zeroizing::new(Vec::new());
    use std::io::Read;
    file.take(8193).read_to_end(&mut bytes)?;
    if bytes.len() > 8192 {
        bail!("watcher key exceeded byte bound");
    }
    Ok(serde_json::from_slice(&bytes)?)
}

async fn watch_status(State(runtime): State<Arc<Runtime>>) -> Api<serde_json::Value> {
    let store = runtime.store.lock().await;
    Ok(Json(serde_json::json!({
        "status":if matches!(runtime.mode, NodeMode::Adopted(_)) { EARTH_STATUS } else { CANDIDATE_STATUS },
        "live_rld":matches!(runtime.mode, NodeMode::Adopted(_)),
        "chain_id":store.latest().funding.chain_id,
        "channel":store.latest().funding.id().map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR,error))?,
        "sequence":store.latest().state.state.sequence,
        "watcher":runtime.watcher_public,
        "healthy":store.healthy()
    })))
}

async fn accept_package(State(runtime): State<Arc<Runtime>>, body: Bytes) -> Api<WatchAck> {
    if body.len() > 32_768 {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "watch package too large".into(),
        ));
    }
    let package: WatchPackage = serde_json::from_slice(&body)
        .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    let node = verify_node_preview_mode(
        &runtime.client,
        &runtime.node,
        runtime.transition_preview_id,
        runtime.mode,
    )
    .await
    .map_err(|error| (StatusCode::SERVICE_UNAVAILABLE, error.to_string()))?;
    if node.chain_id != package.funding.chain_id {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "candidate watchtower chain mismatch".into(),
        ));
    }
    let canonical = serde_json::to_vec(&package)
        .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    if body.as_ref() != canonical {
        return Err((StatusCode::BAD_REQUEST, "noncanonical watch package".into()));
    }
    let mut store = runtime.store.lock().await;
    match store.observe(package.clone()) {
        Ok(_) => {}
        Err(error) if store.healthy() => return Err((StatusCode::CONFLICT, error)),
        Err(error) => return Err((StatusCode::SERVICE_UNAVAILABLE, error)),
    }
    let ack = WatchAck::sign_saved_for_mode(
        &package,
        &runtime.watcher_public,
        &runtime.watcher_secret,
        matches!(runtime.mode, NodeMode::Adopted(_)),
    )
    .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))?;
    Ok(Json(ack))
}

async fn tick(
    client: &reqwest::Client,
    origin: &str,
    package: &WatchPackage,
    accepted_preview: Hash,
    mode: NodeMode,
) -> Result<WatchDecision> {
    let node = verify_node_preview_mode(client, origin, accepted_preview, mode).await?;
    if node.chain_id != package.funding.chain_id {
        bail!("candidate watchtower chain mismatch");
    }
    let channel = package.validate().map_err(|error| anyhow!(error))?;
    let response = client
        .get(format!(
            "{origin}{}/escrows/{}",
            mode.base(),
            channel.to_hex()
        ))
        .send()
        .await?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(WatchDecision::FundingMissing);
    }
    let observation: EscrowResponse = response.error_for_status()?.json().await?;
    if observation.status
        != if matches!(mode, NodeMode::Adopted(_)) {
            EARTH_STATUS
        } else {
            CANDIDATE_STATUS
        }
        || observation.live_rld != matches!(mode, NodeMode::Adopted(_))
    {
        bail!("watchtower refuses mismatched node mode");
    }
    let height = observation
        .height
        .parse::<u128>()
        .context("candidate height")?;
    let decision = package
        .decide(observation.chain_id, height, Some(&observation.escrow))
        .map_err(|error| anyhow!(error))?;
    if let WatchDecision::Challenge(command) = &decision {
        let response: serde_json::Value = client
            .post(format!("{origin}{}/commands", mode.base()))
            .json(command)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if response["status"]
            != if matches!(mode, NodeMode::Adopted(_)) {
                EARTH_STATUS
            } else {
                CANDIDATE_STATUS
            }
            || response["confirmed"] != false
        {
            bail!("candidate did not acknowledge durable challenge submission");
        }
        eprintln!(
            "candidate watchtower challenge submitted: {}",
            response["command"].as_str().unwrap_or("unknown")
        );
    }
    Ok(decision)
}

async fn monitor(
    runtime: Arc<Runtime>,
    package_path: PathBuf,
    client: reqwest::Client,
    origin: String,
    poll_ms: u64,
) -> Result<()> {
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut last_package_error: Option<String> = None;
    loop {
        let latest = {
            let mut store = runtime.store.lock().await;
            match load_package(&package_path) {
                Ok(refreshed) => match store.observe(refreshed) {
                    Ok(true) => {
                        last_package_error = None;
                        eprintln!(
                            "candidate watchtower saved sequence {}",
                            store.latest().state.state.sequence
                        );
                    }
                    Ok(false) => last_package_error = None,
                    Err(error) if store.healthy() => {
                        let message = format!("merchant package rejected: {error}");
                        if last_package_error.as_ref() != Some(&message) {
                            eprintln!("{message}; retaining watchtower state");
                        }
                        last_package_error = Some(message);
                    }
                    Err(error) => bail!("watchtower durability failure: {error}"),
                },
                Err(error) => {
                    let message = format!("merchant package unavailable: {error}");
                    if last_package_error.as_ref() != Some(&message) {
                        eprintln!("{message}; retaining watchtower state");
                    }
                    last_package_error = Some(message);
                }
            }
            store.latest().clone()
        };
        match tick(
            &client,
            &origin,
            &latest,
            runtime.transition_preview_id,
            runtime.mode,
        )
        .await
        {
            Ok(WatchDecision::ContestExpired) => {
                bail!("candidate contest expired before challenge")
            }
            Ok(WatchDecision::FeeExpired) => bail!("candidate challenge fee authorization expired"),
            Ok(WatchDecision::Settled) => return Ok(()),
            Ok(_) => {}
            Err(error) => eprintln!("candidate watchtower observation unavailable: {error}"),
        }
        #[cfg(unix)]
        tokio::select! {
            _ = terminate.recv() => return Ok(()),
            _ = tokio::signal::ctrl_c() => return Ok(()),
            _ = tokio::time::sleep(Duration::from_millis(poll_ms)) => {}
        }
        #[cfg(not(unix))]
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            _ = tokio::time::sleep(Duration::from_millis(poll_ms)) => {}
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if !(100..=10_000).contains(&args.poll_ms) || !args.listen.ip().is_loopback() {
        bail!("watchtower requires bounded polling and loopback acknowledgment listener");
    }
    let origin = loopback_origin(&args.node)?;
    let accepted_preview =
        Hash::from_hex(&args.accept_transition_preview).map_err(|error| anyhow!(error))?;
    let mode = if let Some(id) = &args.accept_earth_adoption {
        NodeMode::Adopted(Hash::from_hex(id).map_err(|error| anyhow!(error))?)
    } else {
        NodeMode::Candidate
    };
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()?;
    verify_node_preview_mode(&client, &origin, accepted_preview, mode).await?;
    let merchant_dir = args
        .package
        .parent()
        .ok_or_else(|| anyhow!("watch package needs a parent directory"))?
        .canonicalize()?;
    let watch_parent = args
        .watch_state_dir
        .parent()
        .ok_or_else(|| anyhow!("watch state needs a parent directory"))?
        .canonicalize()?;
    let watch_name = args
        .watch_state_dir
        .file_name()
        .ok_or_else(|| anyhow!("watch state needs a directory name"))?;
    let watch_root = watch_parent.join(watch_name);
    if watch_root.starts_with(&merchant_dir) || merchant_dir.starts_with(&watch_root) {
        bail!("watchtower state must be outside merchant wallet directory");
    }
    let initial = load_package(&args.package).ok();
    let mut store =
        WatchStore::open(&watch_root, initial.clone()).map_err(|error| anyhow!(error))?;
    if let Some(package) = initial {
        if let Err(error) = store.observe(package) {
            if !store.healthy() {
                bail!("watchtower durability failure: {error}");
            }
            eprintln!("merchant package rejected; retaining watchtower state: {error}");
        }
    }
    let identity = load_ack_key(&args.ack_key)?;
    WatchAck::sign_saved_for_mode(
        store.latest(),
        &identity.public_key,
        &identity.secret_key,
        matches!(mode, NodeMode::Adopted(_)),
    )
    .map_err(|error| anyhow!(error))?;
    let runtime = Arc::new(Runtime {
        store: Mutex::new(store),
        watcher_public: identity.public_key,
        watcher_secret: Zeroizing::new(identity.secret_key),
        client: client.clone(),
        node: origin.clone(),
        transition_preview_id: accepted_preview,
        mode,
    });
    eprintln!(
        "{} watchtower loaded sequence {}",
        if matches!(mode, NodeMode::Adopted(_)) {
            EARTH_STATUS
        } else {
            CANDIDATE_STATUS
        },
        runtime.store.lock().await.latest().state.state.sequence
    );
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    let base = if matches!(mode, NodeMode::Adopted(_)) {
        "/v1/earth-watchtower"
    } else {
        "/v1/candidate-watchtower"
    };
    let server = axum::serve(
        listener,
        Router::new()
            .route(&format!("{base}/status"), get(watch_status))
            .route(&format!("{base}/packages"), post(accept_package))
            .layer(DefaultBodyLimit::max(32_768))
            .with_state(runtime.clone()),
    );
    tokio::select! {
        result = server => result.map_err(Into::into),
        result = monitor(runtime, args.package, client, origin, args.poll_ms) => result,
    }
}
