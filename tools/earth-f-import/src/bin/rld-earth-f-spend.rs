//! Sign a destination spend of one finalized, mature Earth import.
use anyhow::{anyhow, bail, Result};
use clap::Parser;
use rld_core::{
    sign_bytes, validate_ed25519_public_key, AdmissionHash32 as Hash, Amount, Identity,
};
use rld_pow::{OutPoint, Output, Transfer};
use rld_value_successor::{
    chain::Command as SourceCommand, destination::pow::Command as DestinationCommand,
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    export_command: PathBuf,
    #[arg(long)]
    recipient_key: PathBuf,
    #[arg(long)]
    send_to: String,
    #[arg(long)]
    amount_runlai: String,
    #[arg(long)]
    valid_through_height: u128,
    #[arg(long)]
    output: PathBuf,
}

fn read(path: &Path, limit: u64, key: bool) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > limit {
        bail!("unsafe or oversized input: {}", path.display());
    }
    if key && meta.permissions().mode() & 0o077 != 0 {
        bail!("recipient key must be owner-only");
    }
    Ok(fs::read(path)?)
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.output.exists() || args.valid_through_height == 0 {
        bail!("invalid output or transfer expiry");
    }
    validate_ed25519_public_key(&args.send_to).map_err(|error| anyhow!(error))?;
    let export: SourceCommand =
        serde_json::from_slice(&read(&args.export_command, 32_768, false)?)?;
    let SourceCommand::Export(export) = export else {
        bail!("expected signed Earth export");
    };
    let identity: Identity = serde_json::from_slice(&read(&args.recipient_key, 8_192, true)?)?;
    if identity.public_key != export.intent.recipient {
        bail!("key does not own imported value");
    }
    let payment: Amount = args.amount_runlai.parse()?;
    let fee = Amount(1);
    let imported = export
        .intent
        .amount
        .checked_sub(export.intent.destination_fee)
        .map_err(|error| anyhow!(error))?;
    let change = imported
        .checked_sub(payment.checked_add(fee).map_err(|error| anyhow!(error))?)
        .map_err(|error| anyhow!(error))?;
    if payment.is_zero() || change.is_zero() {
        bail!("transfer must leave positive recipient change after fee");
    }
    let export_id = export.intent.id().map_err(|error| anyhow!(error))?;
    let mut bytes = b"RLD-EARTH-DESTINATION-POW-IMPORT-OUTPUT\0".to_vec();
    bytes.extend(export.intent.destination_chain_id.0);
    bytes.extend(export.intent.source_chain_id.0);
    bytes.extend(export_id.0);
    let input = OutPoint {
        transaction: Hash(Sha256::digest(bytes).into()),
        index: 0,
    };
    let mut transfer = Transfer {
        chain_id: export.intent.destination_chain_id,
        owner: identity.public_key.clone(),
        inputs: vec![input],
        outputs: vec![
            Output {
                owner: args.send_to,
                amount: payment,
            },
            Output {
                owner: identity.public_key,
                amount: change,
            },
        ],
        fee,
        valid_through_height: args.valid_through_height,
        signature: String::new(),
    };
    transfer.signature = sign_bytes(
        &identity.secret_key,
        &transfer.signing_bytes().map_err(|error| anyhow!(error))?,
    )
    .map_err(|error| anyhow!(error))?;
    let command = DestinationCommand::Transfer(transfer.clone());
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&args.output)?;
    output.write_all(&serde_json::to_vec(&command)?)?;
    output.sync_all()?;
    println!(
        "{}",
        serde_json::json!({
            "result":"EARTH_DESTINATION_SPEND_PREPARED",
            "transaction":transfer.id().map_err(|error| anyhow!(error))?,
            "export":export_id,
            "amount_runlai":payment,
            "output":args.output,
        })
    );
    Ok(())
}
