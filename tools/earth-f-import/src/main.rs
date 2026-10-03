//! Prepare a finalized real-value Earth import from a separately replayed source.
use anyhow::{anyhow, bail, Result};
use clap::Parser;
use rld_core::AdmissionHash32 as Hash;
use rld_pow::{storage::Store as V1Store, transition::Adoption};
use rld_value_successor::{
    candidate_client::{load_verified_transition_preview_file, verify_earth_adoption_file},
    chain::{finality::FinalityCertificate, storage::CandidateStore, Command as SourceCommand},
    destination::pow::Command as DestinationCommand,
};
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    genesis: PathBuf,
    #[arg(long)]
    history: PathBuf,
    #[arg(long)]
    pow_adoption: PathBuf,
    #[arg(long)]
    manifest_pin: String,
    #[arg(long)]
    accept_pow_adoption: String,
    #[arg(long)]
    pinned_pow_source: String,
    #[arg(long)]
    v1_data_dir: PathBuf,
    #[arg(long)]
    transition_preview: PathBuf,
    #[arg(long)]
    accept_transition_preview: String,
    #[arg(long)]
    earth_adoption: PathBuf,
    #[arg(long)]
    accept_earth_adoption: String,
    #[arg(long)]
    source_dir: PathBuf,
    #[arg(long)]
    export_command: PathBuf,
    #[arg(long)]
    finality_certificate: PathBuf,
    #[arg(long)]
    output: PathBuf,
}

fn hash(value: &str) -> Result<Hash> {
    Hash::from_hex(value).map_err(|error| anyhow!(error))
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn read(path: &PathBuf, limit: u64) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > limit {
        bail!("unsafe or oversized import input: {}", path.display());
    }
    Ok(fs::read(path)?)
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.output.exists() {
        bail!("import output already exists");
    }
    let genesis = read(&args.genesis, 65_536)?;
    let history = read(&args.history, 32 * 1024 * 1024)?;
    let pow: Adoption = serde_json::from_slice(&read(&args.pow_adoption, 65_536)?)?;
    let source_pin = hash(&args.pinned_pow_source)?;
    let context = pow
        .verify_with_pinned_release_source(
            &genesis,
            &history,
            hash(&args.manifest_pin)?,
            hash(&args.accept_pow_adoption)?,
            source_pin,
        )
        .map_err(|error| anyhow!(error))?;
    let v1 = V1Store::open(&args.v1_data_dir, context, now()?).map_err(|error| anyhow!(error))?;
    let preview = load_verified_transition_preview_file(
        &args.transition_preview,
        v1.chain(),
        source_pin,
        hash(&args.accept_transition_preview)?,
    )?;
    let earth_id = hash(&args.accept_earth_adoption)?;
    verify_earth_adoption_file(
        &args.earth_adoption,
        &genesis,
        &history,
        &pow,
        v1.chain(),
        &preview,
        earth_id,
    )?;
    let validators = pow
        .approvals
        .iter()
        .map(|approval| approval.public_key.clone())
        .collect();
    let mut source =
        CandidateStore::open_finalized(&args.source_dir, v1.chain(), now()?, earth_id, validators)
            .map_err(|error| anyhow!(error))?;
    let certificate: FinalityCertificate =
        serde_json::from_slice(&read(&args.finality_certificate, 65_536)?)?;
    source
        .install_finality(certificate.clone())
        .map_err(|error| anyhow!(error))?;
    let export: SourceCommand = serde_json::from_slice(&read(&args.export_command, 32_768)?)?;
    let SourceCommand::Export(export) = export else {
        bail!("expected a signed Earth export command");
    };
    let export_id = export.intent.id().map_err(|error| anyhow!(error))?;
    let bundle = source
        .chain()
        .export_bundle(export_id, certificate.statement.block)
        .map_err(|error| anyhow!(error))?;
    let command = DestinationCommand::FinalizedImport {
        bundle,
        certificate,
    };
    let bytes = serde_json::to_vec(&command)?;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&args.output)?;
    output.write_all(&bytes)?;
    output.sync_all()?;
    println!(
        "{}",
        serde_json::json!({
            "result":"EARTH_FINALIZED_IMPORT_PREPARED",
            "export_id":export_id,
            "checkpoint":source.finality().map(|c| c.statement.block),
            "source_height":source.chain().height().to_string(),
            "output":args.output,
        })
    );
    Ok(())
}
