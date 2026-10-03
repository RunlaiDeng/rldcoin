//! Prepare a signed stale close to exercise a live Earth watchtower challenge.
use anyhow::{anyhow, bail, Result};
use clap::Parser;
use rld_core::{sign_bytes, Identity};
use rld_fast_payments::{Funding, SignedState};
use rld_pow::OutPoint;
use rld_value_successor::{
    chain::Command, signed_state_hash, ActionFee, ActionFeeIntent, DisputeAction,
};
use serde::Deserialize;
use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    payer_config: PathBuf,
    #[arg(long)]
    fee_transfer: PathBuf,
    #[arg(long)]
    payer_key: PathBuf,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Deserialize)]
struct PayerConfig {
    funding: Funding,
    initial: SignedState,
}

fn read(path: &Path, key: bool) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 64 * 1024 {
        bail!("unsafe or oversized Earth input");
    }
    if key && meta.permissions().mode() & 0o077 != 0 {
        bail!("payer key must be owner-only");
    }
    Ok(fs::read(path)?)
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.output.exists() {
        bail!("refusing to replace prepared close");
    }
    let config: PayerConfig = serde_json::from_slice(&read(&args.payer_config, false)?)?;
    let key: Identity = serde_json::from_slice(&read(&args.payer_key, true)?)?;
    let transfer: Command = serde_json::from_slice(&read(&args.fee_transfer, false)?)?;
    let Command::Transfer(transfer) = transfer else {
        bail!("expected channel fee funding transfer");
    };
    if key.public_key != config.funding.party_a
        || transfer.owner != key.public_key
        || transfer.chain_id != config.funding.chain_id
        || config.initial.state.sequence != 0
    {
        bail!("close inputs do not belong to the channel payer");
    }
    config.initial.verify(&config.funding).map_err(|error| anyhow!(error))?;
    let output = transfer.outputs.get(1).ok_or_else(|| anyhow!("missing payer change"))?;
    if output.owner != key.public_key {
        bail!("fee transfer change does not belong to payer");
    }
    let input = OutPoint {
        transaction: transfer.id().map_err(|error| anyhow!(error))?,
        index: 1,
    };
    let intent = ActionFeeIntent {
        chain_id: config.funding.chain_id,
        action: DisputeAction::Close,
        channel: config.funding.id().map_err(|error| anyhow!(error))?,
        signed_state: signed_state_hash(&config.initial).map_err(|error| anyhow!(error))?,
        input,
        owner: key.public_key,
        fee: config.funding.close_fee,
        change: output.amount.checked_sub(config.funding.close_fee)
            .map_err(|error| anyhow!(error))?,
        valid_through_height: u128::MAX,
    };
    let fee = ActionFee {
        owner_signature: sign_bytes(&key.secret_key, &intent.signing_bytes()
            .map_err(|error| anyhow!(error))?).map_err(|error| anyhow!(error))?,
        intent,
    };
    let command = Command::Close {
        channel: fee.intent.channel,
        state: config.initial,
        fee,
    };
    let mut output = fs::OpenOptions::new()
        .write(true).create_new(true).mode(0o600).open(&args.output)?;
    output.write_all(&serde_json::to_vec(&command)?)?;
    output.sync_all()?;
    println!("{}", serde_json::json!({
        "result":"EARTH_STALE_CLOSE_PREPARED",
        "channel":config.funding.id().map_err(|error| anyhow!(error))?,
        "state_sequence":0,
        "output":args.output,
    }));
    Ok(())
}
