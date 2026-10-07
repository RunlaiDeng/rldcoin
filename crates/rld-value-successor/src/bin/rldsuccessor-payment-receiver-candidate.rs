//! Isolated loopback receiver: durable receipt before a pinned watcher ack.
use anyhow::{anyhow, bail, Result};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use rld_core::{sign_bytes, Amount};
use rld_fast_payments::{Funding, PaymentOffer, SignedState};
use rld_pow::OutPoint;
use rld_value_successor::{
    candidate_client::{loopback_origin, refresh},
    candidate_inputs::{
        http_client, key, read, response, CandidateArgs, CandidateInputs, LocalKey,
    },
    chain::CandidateEscrowObservation,
    signed_state_hash,
    wallet_guard::{FeeFunding, GuardedRecipient},
    watchtower::{WatchAck, WatchedReceipt, CANDIDATE_STATUS},
    ActionFee, ActionFeeIntent, DisputeAction,
};
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::sync::Mutex;

#[derive(Parser)]
struct Args {
    #[command(flatten)]
    candidate: CandidateArgs,
    #[arg(long)]
    node: String,
    #[arg(long)]
    watchtower: String,
    #[arg(long)]
    watcher_public_key: String,
    #[arg(long)]
    wallet_dir: PathBuf,
    #[arg(long)]
    receiver_key: PathBuf,
    #[arg(long)]
    funding_config: PathBuf,
    #[arg(long, default_value = "127.0.0.1:48301")]
    listen: SocketAddr,
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
struct Runtime {
    inputs: CandidateInputs,
    wallet: GuardedRecipient,
    key: LocalKey,
    client: reqwest::Client,
    node: String,
    watchtower: String,
    watcher: String,
    funding: Funding,
    fee: FeeFunding,
}
type Shared = Arc<Mutex<Runtime>>;
type Api<T> = std::result::Result<Json<T>, (StatusCode, String)>;
fn unavailable(error: impl ToString) -> (StatusCode, String) {
    (StatusCode::SERVICE_UNAVAILABLE, error.to_string())
}

async fn status(State(shared): State<Shared>) -> Api<serde_json::Value> {
    let runtime = shared.try_lock().map_err(unavailable)?;
    Ok(Json(
        serde_json::json!({"status":CANDIDATE_STATUS, "live_rld":false,
        "chain_id":runtime.funding.chain_id, "receipt_sequence":runtime.wallet.latest().state.sequence,
        "watcher":runtime.watcher}),
    ))
}

async fn offers(State(shared): State<Shared>, body: Bytes) -> Api<WatchedReceipt> {
    let offer: PaymentOffer = serde_json::from_slice(&body)
        .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
    let mut runtime = shared.try_lock().map_err(unavailable)?;
    let Runtime {
        inputs,
        wallet,
        key,
        client,
        node,
        watchtower,
        watcher,
        funding,
        fee,
    } = &mut *runtime;
    refresh(&mut inputs.store, client, node, inputs.preview_id)
        .await
        .map_err(unavailable)?;
    let receipt = wallet
        .accept_offer(
            inputs.store.chain(),
            2,
            false,
            offer,
            &key.secret,
            fee.clone(),
        )
        .map_err(|error| (StatusCode::CONFLICT, error))?;
    // A retry may already have its receipt on disk. Always obtain and verify
    // the same complete saved package acknowledgement before returning it.
    let package = wallet.watch_package().clone();
    let ack: WatchAck = response(
        client
            .post(format!("{watchtower}/v1/candidate-watchtower/packages"))
            .json(&package)
            .send()
            .await
            .map_err(unavailable)?,
        8192,
    )
    .await
    .map_err(unavailable)?;
    let delivery = WatchedReceipt {
        status: CANDIDATE_STATUS.into(),
        live_rld: false,
        receipt,
        watch_package: package,
        watch_ack: ack,
    };
    delivery
        .verify_on_chain(
            funding,
            &delivery.receipt.sender,
            watcher,
            inputs.store.chain(),
        )
        .map_err(unavailable)?;
    Ok(Json(delivery))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if !args.listen.ip().is_loopback() {
        bail!("candidate receiver requires a loopback listener");
    }
    let node = loopback_origin(&args.node)?;
    let watchtower = loopback_origin(&args.watchtower)?;
    let mut inputs = args.candidate.open()?;
    let client = http_client()?;
    refresh(&mut inputs.store, &client, &node, inputs.preview_id).await?;
    let key = key(&args.receiver_key)?;
    let config: FundingConfig = serde_json::from_slice(&read(&args.funding_config, 32_768)?)?;
    let fee = FeeFunding {
        input: config.fee_input,
        input_amount: config.fee_input_amount,
        fee: config.fee,
        valid_through_height: config.valid_through_height,
    };
    CandidateEscrowObservation::new(inputs.store.chain(), 2)
        .map_err(|error| anyhow!(error))?
        .verify_payment_readiness(
            &config.funding,
            &key.public,
            &fee.input,
            fee.input_amount,
            fee.fee,
            fee.valid_through_height,
        )
        .map_err(|error| anyhow!(error))?;
    rld_core::validate_ed25519_public_key(&args.watcher_public_key)
        .map_err(|error| anyhow!(error))?;
    let initial_fee = if args.wallet_dir.join("watch-package.json").try_exists()? {
        None
    } else {
        let intent = ActionFeeIntent {
            chain_id: config.funding.chain_id,
            action: DisputeAction::Challenge,
            channel: config.funding.id().map_err(|error| anyhow!(error))?,
            signed_state: signed_state_hash(&config.initial).map_err(|error| anyhow!(error))?,
            input: fee.input.clone(),
            owner: key.public.clone(),
            fee: fee.fee,
            change: fee
                .input_amount
                .checked_sub(fee.fee)
                .map_err(|error| anyhow!(error))?,
            valid_through_height: fee.valid_through_height,
        };
        Some(ActionFee {
            owner_signature: sign_bytes(
                &key.secret,
                &intent.signing_bytes().map_err(|error| anyhow!(error))?,
            )
            .map_err(|error| anyhow!(error))?,
            intent,
        })
    };
    let wallet = GuardedRecipient::open(
        &args.wallet_dir,
        config.funding.clone(),
        key.public.clone(),
        config.initial,
        initial_fee,
    )
    .map_err(|error| anyhow!(error))?;
    let shared = Arc::new(Mutex::new(Runtime {
        inputs,
        wallet,
        key,
        client,
        node,
        watchtower,
        watcher: args.watcher_public_key,
        funding: config.funding,
        fee,
    }));
    let router = Router::new()
        .route("/v1/candidate-payment/status", get(status))
        .route("/v1/candidate-payment/offers", post(offers))
        .layer(DefaultBodyLimit::max(32_768))
        .with_state(shared);
    axum::serve(tokio::net::TcpListener::bind(args.listen).await?, router)
        .with_graceful_shutdown(rld_value_successor::candidate_inputs::shutdown_signal())
        .await?;
    Ok(())
}
