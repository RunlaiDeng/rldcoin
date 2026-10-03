//! Review and sign direct, empty-genesis Earth value rules.
//! No subcommand runs a value node or opens public service.

use anyhow::{anyhow, bail, Result};
use clap::{Args as ClapArgs, Parser, Subcommand};
use rld_core::{sign_bytes, verify_bytes, AdmissionHash32 as Hash, Identity};
use rld_pow::{storage::Store as PowStore, transition::Adoption, transition::Approval};
use rld_value_successor::{
    adoption::{EarthSuccessorAdoption, EarthSuccessorAdoptionStatement},
    transition::TransitionPreview,
};
use serde::Serialize;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    action: Action,
}

#[derive(ClapArgs)]
struct Source {
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
    pow_data_dir: PathBuf,
}

#[derive(Subcommand)]
enum Action {
    Draft {
        #[command(flatten)]
        source: Source,
        #[arg(long)]
        preview_out: PathBuf,
        #[arg(long)]
        statement_out: PathBuf,
    },
    Approve {
        #[command(flatten)]
        source: Source,
        #[arg(long)]
        preview: PathBuf,
        #[arg(long)]
        statement: PathBuf,
        #[arg(long)]
        #[arg(long, required = true, num_args = 4)]
        validator_key: Vec<PathBuf>,
        #[arg(long)]
        confirm_fresh_earth: bool,
        #[arg(long)]
        output: PathBuf,
    },
    Verify {
        #[command(flatten)]
        source: Source,
        #[arg(long)]
        preview: PathBuf,
        #[arg(long)]
        earth_adoption: PathBuf,
        #[arg(long)]
        accept_earth_adoption: String,
    },
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > limit as u64 {
        bail!("unsafe or oversized adoption input");
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        bail!("adoption input exceeded bound");
    }
    Ok(bytes)
}

fn parse_hash(value: &str) -> Result<Hash> {
    Hash::from_hex(value).map_err(|error| anyhow!(error))
}

fn canonical<T: serde::de::DeserializeOwned + Serialize>(path: &Path, limit: usize) -> Result<T> {
    let bytes = read(path, limit)?;
    let value: T = serde_json::from_slice(&bytes)?;
    if serde_json::to_vec(&value)? != bytes {
        bail!("adoption input is not canonical JSON");
    }
    Ok(value)
}

fn exclusive_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(&serde_json::to_vec(value)?)?;
    file.sync_all()?;
    File::open(
        path.parent()
            .ok_or_else(|| anyhow!("missing output directory"))?,
    )?
    .sync_all()?;
    Ok(())
}

struct Replayed {
    genesis: Vec<u8>,
    history: Vec<u8>,
    pow_adoption: Adoption,
    pow: PowStore,
    preview: TransitionPreview,
    statement: EarthSuccessorAdoptionStatement,
}

fn replay(source: &Source) -> Result<Replayed> {
    let genesis = read(&source.genesis, 65_536)?;
    let history = read(&source.history, 32 * 1024 * 1024)?;
    // The signed typed statement is canonical independently of file spacing.
    let pow_adoption: Adoption = serde_json::from_slice(&read(&source.pow_adoption, 65_536)?)?;
    let pin = parse_hash(&source.manifest_pin)?;
    let pow_id = parse_hash(&source.accept_pow_adoption)?;
    let adopted_source = parse_hash(&source.pinned_pow_source)?;
    let context = pow_adoption
        .verify_with_pinned_release_source(&genesis, &history, pin, pow_id, adopted_source)
        .map_err(|error| anyhow!(error))?;
    if context.started_at > now()? {
        bail!("PoW adoption begins in the future");
    }
    let pow =
        PowStore::open(&source.pow_data_dir, context, now()?).map_err(|error| anyhow!(error))?;
    let preview = TransitionPreview::from_replayed_v1(pow.chain(), adopted_source)
        .map_err(|error| anyhow!(error))?;
    let statement =
        EarthSuccessorAdoptionStatement::from_replayed_fresh_chain(pow.chain(), &preview)
            .map_err(|error| anyhow!(error))?;
    Ok(Replayed {
        genesis,
        history,
        pow_adoption,
        pow,
        preview,
        statement,
    })
}

fn checked_inputs(replayed: &Replayed, preview_path: &Path, statement_path: &Path) -> Result<()> {
    let preview: TransitionPreview = canonical(preview_path, 4096)?;
    let statement: EarthSuccessorAdoptionStatement = canonical(statement_path, 4096)?;
    if preview != replayed.preview || statement != replayed.statement {
        bail!("replayed fresh chain differs from reviewed preview or statement");
    }
    Ok(())
}

fn main() -> Result<()> {
    match Cli::parse().action {
        Action::Draft {
            source,
            preview_out,
            statement_out,
        } => {
            if preview_out == statement_out || preview_out.exists() || statement_out.exists() {
                bail!("draft outputs must be distinct and absent");
            }
            let replayed = replay(&source)?;
            exclusive_json(&preview_out, &replayed.preview)?;
            exclusive_json(&statement_out, &replayed.statement)?;
            println!(
                "{}",
                serde_json::json!({
                    "result":"UNSIGNED_NEW_EARTH_SUCCESSOR_DRAFT",
                    "chain_id":replayed.statement.fresh_chain_id.to_hex(),
                    "v1_height":replayed.statement.v1_height.to_string(),
                    "preview_id":replayed.preview.id().map_err(|error|anyhow!(error))?.to_hex(),
                    "adoption_id":replayed.statement.id().map_err(|error|anyhow!(error))?.to_hex(),
                    "live_rld":false
                })
            );
        }
        Action::Approve {
            source,
            preview,
            statement,
            validator_key,
            confirm_fresh_earth,
            output,
        } => {
            if !confirm_fresh_earth {
                bail!("explicit fresh Earth confirmation required");
            }
            let replayed = replay(&source)?;
            checked_inputs(&replayed, &preview, &statement)?;
            let bytes = replayed
                .statement
                .signing_bytes()
                .map_err(|error| anyhow!(error))?;
            let mut approvals = Vec::new();
            for path in validator_key {
                let key: Identity = serde_json::from_slice(&read(&path, 16_384)?)?;
                let signature =
                    sign_bytes(&key.secret_key, &bytes).map_err(|error| anyhow!(error))?;
                verify_bytes(&key.public_key, &bytes, &signature)
                    .map_err(|error| anyhow!(error))?;
                approvals.push(Approval {
                    public_key: key.public_key,
                    signature,
                });
            }
            approvals.sort_by(|a, b| a.public_key.cmp(&b.public_key));
            let adoption = EarthSuccessorAdoption {
                statement: replayed.statement,
                approvals,
            };
            let id = adoption.statement.id().map_err(|error| anyhow!(error))?;
            adoption
                .verify(
                    &replayed.genesis,
                    &replayed.history,
                    &replayed.pow_adoption,
                    replayed.pow.chain(),
                    &replayed.preview,
                    id,
                )
                .map_err(|error| anyhow!(error))?;
            exclusive_json(&output, &adoption)?;
            println!(
                "{}",
                serde_json::json!({"result":"PASS_UNANIMOUS_EARTH_SUCCESSOR_ADOPTION","adoption_id":id.to_hex(),"value_runtime_started":false})
            );
        }
        Action::Verify {
            source,
            preview,
            earth_adoption,
            accept_earth_adoption,
        } => {
            let replayed = replay(&source)?;
            let supplied_preview: TransitionPreview = canonical(&preview, 4096)?;
            if supplied_preview != replayed.preview {
                bail!("successor preview differs from fresh PoW replay");
            }
            let adoption: EarthSuccessorAdoption = canonical(&earth_adoption, 8192)?;
            let accepted = parse_hash(&accept_earth_adoption)?;
            adoption
                .verify(
                    &replayed.genesis,
                    &replayed.history,
                    &replayed.pow_adoption,
                    replayed.pow.chain(),
                    &supplied_preview,
                    accepted,
                )
                .map_err(|error| anyhow!(error))?;
            println!(
                "{}",
                serde_json::json!({"result":"PASS_NEW_EARTH_SUCCESSOR_ADOPTION_VERIFICATION","adoption_id":accepted.to_hex(),"value_runtime_started":false})
            );
        }
    }
    Ok(())
}
