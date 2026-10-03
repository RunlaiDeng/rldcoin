//! Loopback-only candidate payer. It cannot spend live PoW v1 RLD.

use anyhow::{anyhow, bail, Context as _, Result};
use clap::Parser;
use rld_core::{
    sign_bytes, validate_ed25519_public_key, verify_bytes, AdmissionHash32 as Hash, Amount,
    Identity,
};
use rld_fast_payments::{ConfirmedEscrow, Funding, SignedState};
use rld_pow::{storage::Store as V1Store, transition::Adoption};
use rld_value_successor::{
    candidate_client::{
        load_verified_transition_preview_file, loopback_origin, now, refresh_mode,
        verify_earth_adoption_file, NodeMode,
    },
    chain::{storage::CandidateStore, CandidateEscrowObservation},
    wallet_payer::WatchedPayer,
    watchtower::WatchedReceipt,
};
use serde::Deserialize;
use std::{
    fs,
    io::{BufRead, Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

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
    payer_key: PathBuf,
    #[arg(long)]
    funding_config: PathBuf,
    #[arg(long)]
    node: String,
    #[arg(long)]
    receiver: String,
    #[arg(long)]
    watcher_public_key: String,
    #[arg(long)]
    amount_runlai: Option<String>,
    #[arg(long)]
    payment_id: Option<String>,
    /// Read bounded JSON payment requests from stdin, keeping the verified chain and wallet open.
    #[arg(long)]
    session_stdin: bool,
    /// Confirm that this process sees only a disposable PoW v1 copy.
    #[arg(long)]
    offline_v1_copy: bool,
    #[arg(long, requires = "accept_earth_adoption")]
    earth_adoption: Option<PathBuf>,
    #[arg(long, requires = "earth_adoption")]
    accept_earth_adoption: Option<String>,
}

fn mode_status(mode: NodeMode) -> &'static str {
    match mode {
        NodeMode::Candidate => "UNADOPTED_LOCAL_CANDIDATE_ONLY",
        NodeMode::Adopted(_) => "ADOPTED_EARTH_SUCCESSOR_V1",
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FundingConfig {
    funding: Funding,
    initial: SignedState,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PaymentRequest {
    amount_runlai: String,
    payment_id: String,
}

fn checked_request(request: &PaymentRequest) -> Result<(Amount, Hash)> {
    let amount: Amount = request.amount_runlai.parse()?;
    if amount.is_zero() {
        bail!("candidate payment amount must be positive");
    }
    let payment_id = hash(&request.payment_id)?;
    if payment_id.is_zero() {
        bail!("candidate payment ID must be nonzero");
    }
    Ok((amount, payment_id))
}

fn bounded(path: &Path, limit: usize, owner_only: bool) -> Result<Zeroizing<Vec<u8>>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit as u64 {
        bail!("unsafe or oversized candidate payer input");
    }
    #[cfg(unix)]
    if owner_only {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("candidate payer key must be owner-only");
        }
    }
    #[cfg(not(unix))]
    let _ = owner_only;
    let mut bytes = Zeroizing::new(Vec::new());
    fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        bail!("candidate payer input exceeded bound");
    }
    Ok(bytes)
}

fn hash(input: &str) -> Result<Hash> {
    Hash::from_hex(input).map_err(|error| anyhow!(error))
}

async fn delivery(
    client: &reqwest::Client,
    receiver: &str,
    offer: &rld_fast_payments::PaymentOffer,
    mode: NodeMode,
) -> Result<WatchedReceipt> {
    let mut response = client
        .post(format!("{receiver}{}/offers", if matches!(mode, NodeMode::Adopted(_)) { "/v1/earth-payment" } else { "/v1/candidate-payment" }))
        .json(offer)
        .send()
        .await
        .context("candidate receiver response unavailable; signed offer remains pending for identical retry")?;
    if !response.status().is_success() {
        bail!(
            "candidate receiver returned {}; signed offer remains pending for identical retry",
            response.status()
        );
    }
    if response
        .content_length()
        .is_some_and(|length| length > 32_768)
    {
        bail!("candidate delivery response too large");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.context(
        "candidate delivery body interrupted; signed offer remains pending for identical retry",
    )? {
        if bytes.len().saturating_add(chunk.len()) > 32_768 {
            bail!("candidate delivery response exceeded bound");
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes)
        .context("candidate delivery is invalid; signed offer remains pending for identical retry")
}

fn report(
    root: &Path,
    watched: &WatchedReceipt,
    previously_recorded: bool,
    elapsed: Option<Duration>,
    mode: NodeMode,
) -> Result<()> {
    let mut value = serde_json::json!({
        "status":mode_status(mode),
        "live_rld":matches!(mode, NodeMode::Adopted(_)),
        "previously_recorded":previously_recorded,
        "payment_id":watched.receipt.payment_id,
        "sequence":watched.receipt.updated.state.sequence,
        "watcher":watched.watch_ack.watcher,
        "evidence_file":root.join("deliveries").join(format!("{:020}.json", watched.receipt.updated.state.sequence)),
    });
    if let Some(elapsed) = elapsed {
        value["payer_request_to_record_ms"] = serde_json::json!(elapsed.as_millis());
    }
    println!("{}", serde_json::to_string(&value)?);
    std::io::stdout().flush()?;
    Ok(())
}

fn read_request_line(input: &mut impl BufRead) -> Result<Option<Vec<u8>>> {
    const MAX_LINE: usize = 4096;
    let mut line = Vec::new();
    loop {
        let available = input.fill_buf()?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Ok(Some(line))
            };
        }
        let end = available.iter().position(|byte| *byte == b'\n');
        let count = end.map_or(available.len(), |position| position + 1);
        if line.len().saturating_add(count) > MAX_LINE {
            bail!("candidate payment request exceeded 4096 bytes");
        }
        line.extend_from_slice(&available[..count]);
        input.consume(count);
        if end.is_some() {
            return Ok(Some(line));
        }
    }
}

struct PayerSession<'a> {
    wallet: &'a mut WatchedPayer,
    store: &'a mut CandidateStore,
    secret: &'a str,
    config: &'a FundingConfig,
    client: &'a reqwest::Client,
    receiver_client: &'a reqwest::Client,
    node: &'a str,
    receiver: &'a str,
    preview_id: Hash,
    wallet_dir: &'a Path,
    mode: NodeMode,
}

impl PayerSession<'_> {
    async fn pay(
        &mut self,
        request: PaymentRequest,
        refresh_before_offer: bool,
        started: Option<Instant>,
    ) -> Result<()> {
        let (amount, payment_id) = checked_request(&request)?;
        if let Some(previous) = self.wallet.recorded(payment_id) {
            if previous.status != mode_status(self.mode)
                || previous.live_rld != matches!(self.mode, NodeMode::Adopted(_))
            {
                bail!("recorded payment belongs to a different adoption mode");
            }
            if previous.receipt.amount != amount {
                bail!("payment ID already recorded with a different amount");
            }
            return report(
                self.wallet_dir,
                previous,
                true,
                started.map(|time| time.elapsed()),
                self.mode,
            );
        }
        if refresh_before_offer {
            refresh_mode(
                self.store,
                self.client,
                self.node,
                self.preview_id,
                self.mode,
            )
            .await?;
        }
        (if matches!(self.mode, NodeMode::Adopted(_)) {
            CandidateEscrowObservation::new_finalized(self.store.chain(), 2)
        } else {
            CandidateEscrowObservation::new(self.store.chain(), 2)
        })
        .map_err(|error| anyhow!(error))?
        .verify_confirmed_escrow(&self.config.funding)
        .map_err(|error| anyhow!(error))?;
        let offer = self
            .wallet
            .begin_payment(self.secret, amount, payment_id)
            .map_err(|error| anyhow!(error))?;
        let watched = delivery(self.receiver_client, self.receiver, &offer, self.mode).await?;
        if watched.status != mode_status(self.mode)
            || watched.live_rld != matches!(self.mode, NodeMode::Adopted(_))
        {
            bail!("receiver delivery adoption mode mismatch; signed offer remains pending");
        }
        refresh_mode(self.store, self.client, self.node, self.preview_id, self.mode)
            .await
            .context("candidate replay unavailable after offer; signed offer remains pending for identical retry")?;
        self.wallet
            .complete_payment(self.store.chain(), watched)
            .map_err(|error| anyhow!(error))?;
        report(
            self.wallet_dir,
            self.wallet
                .recorded(payment_id)
                .ok_or_else(|| anyhow!("payer delivery not recorded"))?,
            false,
            started.map(|time| time.elapsed()),
            self.mode,
        )
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let mode = if let (Some(_), Some(id)) = (&args.earth_adoption, &args.accept_earth_adoption) {
        NodeMode::Adopted(hash(id)?)
    } else {
        if !args.offline_v1_copy {
            bail!("candidate payer requires a disposable v1 copy");
        }
        NodeMode::Candidate
    };
    let node = loopback_origin(&args.node)?;
    let receiver = loopback_origin(&args.receiver)?;
    validate_ed25519_public_key(&args.watcher_public_key).map_err(|error| anyhow!(error))?;
    if args.session_stdin && (args.amount_runlai.is_some() || args.payment_id.is_some()) {
        bail!("session stdin cannot be combined with a one-shot payment");
    }
    if !args.session_stdin && (args.amount_runlai.is_none() || args.payment_id.is_none()) {
        bail!("one-shot payment needs amount and payment ID");
    }
    let one_shot = if args.session_stdin {
        None
    } else {
        Some(PaymentRequest {
            amount_runlai: args.amount_runlai.expect("checked one-shot amount"),
            payment_id: args.payment_id.expect("checked one-shot ID"),
        })
    };
    if let Some(request) = &one_shot {
        checked_request(request)?;
    }
    let genesis = bounded(&args.genesis, 65_536, false)?;
    let history = bounded(&args.history, 32 * 1024 * 1024, false)?;
    let adoption: Adoption = serde_json::from_slice(&bounded(&args.adoption, 65_536, false)?)?;
    let context = adoption
        .verify_with_pinned_release_source(
            &genesis,
            &history,
            hash(&args.manifest_pin)?,
            hash(&args.accept_adoption)?,
            hash(&args.pinned_v1_source)?,
        )
        .map_err(|error| anyhow!(error))?;
    let v1 = V1Store::open(&args.v1_data_dir, context, now()?).map_err(|error| anyhow!(error))?;
    let fresh_earth = matches!(mode, NodeMode::Adopted(_))
        && v1.chain().context.legacy_height == 0
        && v1.chain().height() == 0
        && v1.chain().best_blocks().map_err(|e| anyhow!(e))?.is_empty();
    if !fresh_earth && v1.chain().height() <= v1.chain().context.legacy_height {
        bail!("candidate payer v1 copy lacks accepted PoW history");
    }
    let preview = load_verified_transition_preview_file(
        &args.transition_preview,
        v1.chain(),
        adoption.statement.implementation_source_sha256,
        hash(&args.accept_transition_preview)?,
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
    let receiver_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()?;
    refresh_mode(&mut store, &client, &node, preview_id, mode).await?;
    let config: FundingConfig =
        serde_json::from_slice(&bounded(&args.funding_config, 16_384, false)?)?;
    config
        .initial
        .verify(&config.funding)
        .map_err(|error| anyhow!(error))?;
    let identity: Identity = serde_json::from_slice(&bounded(&args.payer_key, 8192, true)?)?;
    let payer = identity.public_key;
    let secret = Zeroizing::new(identity.secret_key);
    let proof = b"RLD-EARTH-PAYER-KEY-CHECK";
    verify_bytes(
        &payer,
        proof,
        &sign_bytes(&secret, proof).map_err(|error| anyhow!(error))?,
    )
    .map_err(|error| anyhow!(error))?;
    let mut wallet = WatchedPayer::open(
        &args.wallet_dir,
        config.funding.clone(),
        payer,
        config.initial.clone(),
        args.watcher_public_key,
    )
    .map_err(|error| anyhow!(error))?;
    let mut session = PayerSession {
        wallet: &mut wallet,
        store: &mut store,
        secret: &secret,
        config: &config,
        client: &client,
        receiver_client: &receiver_client,
        node: &node,
        receiver: &receiver,
        preview_id,
        wallet_dir: &args.wallet_dir,
        mode,
    };
    if args.session_stdin {
        let stdin = std::io::stdin();
        let mut input = stdin.lock();
        while let Some(line) = read_request_line(&mut input)? {
            let started = Instant::now();
            let result = serde_json::from_slice::<PaymentRequest>(&line)
                .context("invalid candidate payment request");
            let result = match result {
                Ok(request) => session.pay(request, true, Some(started)).await,
                Err(error) => Err(error),
            };
            if let Err(error) = result {
                println!(
                    "{}",
                    serde_json::json!({
                        "status":mode_status(mode),
                        "live_rld":matches!(mode, NodeMode::Adopted(_)),
                        "error":error.to_string(),
                        "payer_request_to_error_ms":started.elapsed().as_millis(),
                    })
                );
                std::io::stdout().flush()?;
            }
        }
        Ok(())
    } else {
        session
            .pay(one_shot.expect("checked one-shot payment"), false, None)
            .await
    }
}
