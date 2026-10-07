//! Isolated loopback payer with durable offers and fully verified watch receipts.
use anyhow::{anyhow, bail, Context as _, Result};
use clap::Parser;
use rld_core::Amount;
use rld_fast_payments::{Funding, SignedState};
use rld_value_successor::{
    candidate_client::{loopback_origin, refresh},
    candidate_inputs::{
        hash, http_client, key, read, response, CandidateArgs, CandidateInputs, LocalKey,
    },
    wallet_payer::WatchedPayer,
    watchtower::WatchedReceipt,
};
use serde::Deserialize;
use std::{
    io::{BufRead, Read, Write},
    path::PathBuf,
    time::Instant,
};

#[derive(Parser)]
struct Args {
    #[command(flatten)]
    candidate: CandidateArgs,
    #[arg(long)]
    node: String,
    #[arg(long)]
    receiver: String,
    #[arg(long)]
    watcher_public_key: String,
    #[arg(long)]
    wallet_dir: PathBuf,
    #[arg(long)]
    payer_key: PathBuf,
    #[arg(long)]
    funding_config: PathBuf,
    #[arg(
        long,
        required_unless_present = "session_stdin",
        conflicts_with = "session_stdin"
    )]
    amount_runlai: Option<String>,
    #[arg(
        long,
        required_unless_present = "session_stdin",
        conflicts_with = "session_stdin"
    )]
    payment_id: Option<String>,
    #[arg(long)]
    session_stdin: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FundingConfig {
    funding: Funding,
    initial: SignedState,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    amount_runlai: String,
    payment_id: String,
}

struct Payer {
    inputs: CandidateInputs,
    wallet: WatchedPayer,
    key: LocalKey,
    client: reqwest::Client,
    node: String,
    receiver: String,
    wallet_dir: PathBuf,
    funding: Funding,
    watcher: String,
}

impl Payer {
    async fn pay(&mut self, request: Request) -> Result<()> {
        let started = Instant::now();
        let amount = Amount(
            request
                .amount_runlai
                .parse()
                .context("invalid amount_runlai")?,
        );
        let payment_id = hash(&request.payment_id)?;
        refresh(
            &mut self.inputs.store,
            &self.client,
            &self.node,
            self.inputs.preview_id,
        )
        .await?;
        let (delivery, recorded) = if let Some(saved) = self.wallet.recorded(payment_id) {
            if saved.receipt.amount != amount {
                bail!("recorded payment amount differs");
            }
            saved
                .verify_on_chain(
                    &self.funding,
                    &self.key.public,
                    &self.watcher,
                    self.inputs.store.chain(),
                )
                .map_err(|error| anyhow!(error))?;
            (saved.clone(), true)
        } else {
            let offer = self
                .wallet
                .begin_payment(&self.key.secret, amount, payment_id)
                .map_err(|error| anyhow!(error))?;
            let delivered = async {
                let delivery: WatchedReceipt = response(
                    self.client
                        .post(format!("{}/v1/candidate-payment/offers", self.receiver))
                        .json(&offer)
                        .send()
                        .await?,
                    65_536,
                )
                .await?;
                refresh(
                    &mut self.inputs.store,
                    &self.client,
                    &self.node,
                    self.inputs.preview_id,
                )
                .await?;
                self.wallet
                    .complete_payment(self.inputs.store.chain(), delivery.clone())
                    .map_err(|error| anyhow!(error))?;
                Ok::<_, anyhow::Error>(delivery)
            }
            .await
            .context("signed offer remains pending")?;
            (delivered, false)
        };
        serde_json::to_writer(
            std::io::stdout(),
            &serde_json::json!({
                "status":"UNADOPTED_LOCAL_CANDIDATE_ONLY", "live_rld":false,
                "previously_recorded":recorded, "sequence":delivery.receipt.updated.state.sequence,
                "payment_id":payment_id, "payer_request_to_record_ms":started.elapsed().as_millis(),
                "evidence_file":self.wallet_dir.join("deliveries").join(format!("{:020}.json", delivery.receipt.updated.state.sequence)),
            }),
        )?;
        println!();
        std::io::stdout().flush()?;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let node = loopback_origin(&args.node)?;
    let receiver = loopback_origin(&args.receiver)?;
    let mut inputs = args.candidate.open()?;
    let client = http_client()?;
    refresh(&mut inputs.store, &client, &node, inputs.preview_id).await?;
    let key = key(&args.payer_key)?;
    let config: FundingConfig = serde_json::from_slice(&read(&args.funding_config, 32_768)?)?;
    if config.funding.chain_id != inputs.store.chain().chain_id() {
        bail!("payer funding chain mismatch");
    }
    let wallet = WatchedPayer::open(
        &args.wallet_dir,
        config.funding.clone(),
        key.public.clone(),
        config.initial,
        args.watcher_public_key.clone(),
    )
    .map_err(|error| anyhow!(error))?;
    let mut payer = Payer {
        inputs,
        wallet,
        key,
        client,
        node,
        receiver,
        wallet_dir: args.wallet_dir,
        funding: config.funding,
        watcher: args.watcher_public_key,
    };
    if args.session_stdin {
        // Bound each line before allocation or signing; EOF closes the session.
        let mut stdin = std::io::stdin().lock();
        loop {
            let mut line = Vec::new();
            let size = (&mut stdin).take(4097).read_until(b'\n', &mut line)?;
            if size == 0 {
                break;
            }
            if size > 4096 {
                bail!("payer request exceeded line bound");
            }
            payer.pay(serde_json::from_slice(&line)?).await?;
        }
    } else {
        payer
            .pay(Request {
                amount_runlai: args
                    .amount_runlai
                    .ok_or_else(|| anyhow!("missing amount"))?,
                payment_id: args
                    .payment_id
                    .ok_or_else(|| anyhow!("missing payment ID"))?,
            })
            .await?;
    }
    Ok(())
}
