//! Durable isolated import acknowledgement; never destination consensus credit.
use anyhow::{anyhow, bail, Result};
use clap::Parser;
use rld_core::AdmissionWork;
use rld_cross_region::{ProofBundle, MAX_BUNDLE_BYTES};
use rld_value_successor::{
    candidate_client::refresh,
    candidate_inputs::{canonical, hash, http_client, key, CandidateArgs},
    chain::ObservationPolicy,
    destination::storage::DestinationStore,
};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::PathBuf,
};

#[derive(Parser)]
struct Args {
    #[command(flatten)]
    candidate: CandidateArgs,
    #[arg(long)]
    node: String,
    #[arg(long)]
    destination_dir: PathBuf,
    #[arg(long)]
    destination_chain_id: String,
    #[arg(long)]
    source_work_pin: String,
    #[arg(long, default_value_t = 2)]
    minimum_confirmations: u128,
    #[arg(long)]
    bundle_file: PathBuf,
    #[arg(long)]
    operator_key: PathBuf,
    #[arg(long)]
    miner_fee_to: String,
    #[arg(long)]
    ack_output: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let node = rld_value_successor::candidate_client::loopback_origin(&args.node)?;
    let mut inputs = args.candidate.open()?;
    let client = http_client()?;
    refresh(&mut inputs.store, &client, &node, inputs.preview_id).await?;
    let policy = ObservationPolicy {
        source_chain_id: inputs.store.chain().chain_id(),
        accepted_v1_tip: inputs.store.chain().v1_tip(),
        minimum_confirmations: args.minimum_confirmations,
        minimum_cumulative_work: AdmissionWork::from_hex(&args.source_work_pin)
            .map_err(|error| anyhow!(error))?,
    };
    let bundle: ProofBundle = canonical(&args.bundle_file, MAX_BUNDLE_BYTES)?;
    let operator = key(&args.operator_key)?;
    let mut destination = DestinationStore::open(
        &args.destination_dir,
        hash(&args.destination_chain_id)?,
        policy,
        inputs.store.chain(),
    )
    .map_err(|error| anyhow!(error))?;
    destination
        .import_or_reuse(inputs.store.chain(), bundle.clone(), &args.miner_fee_to)
        .map_err(|error| anyhow!(error))?;
    let ack = destination
        .attest_import(
            inputs.store.chain(),
            &bundle,
            &operator.public,
            &operator.secret,
        )
        .map_err(|error| anyhow!(error))?;
    let bytes = serde_json::to_vec(&ack)?;
    match fs::symlink_metadata(&args.ack_output) {
        Ok(meta) => {
            if !meta.is_file()
                || meta.file_type().is_symlink()
                || rld_value_successor::candidate_inputs::read(&args.ack_output, 8192)? != bytes
            {
                bail!("existing candidate acknowledgement differs");
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&args.ack_output)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            File::open(
                args.ack_output
                    .parent()
                    .ok_or_else(|| anyhow!("missing acknowledgement parent"))?,
            )?
            .sync_all()?;
        }
        Err(error) => return Err(error.into()),
    }
    serde_json::to_writer(std::io::stdout(), &ack)?;
    Ok(())
}
