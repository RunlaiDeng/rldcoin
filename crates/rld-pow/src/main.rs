//! Offline Earth genesis adoption utility. It does not run a retired chain.
use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand};
use rld_core::{AdmissionHash32 as Hash, AdmissionWork as Work, Identity};
use rld_pow::transition::{self, Adoption, AdoptionStatement, Approval};
use serde::Serialize;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Draft {
        #[arg(long)]
        genesis: PathBuf,
        #[arg(long)]
        history: PathBuf,
        #[arg(long)]
        manifest_pin: String,
        #[arg(long)]
        initial_target: String,
        #[arg(long)]
        output: PathBuf,
    },
    Approve {
        #[arg(long)]
        genesis: PathBuf,
        #[arg(long)]
        history: PathBuf,
        #[arg(long)]
        statement: PathBuf,
        #[arg(long)]
        manifest_pin: String,
        #[arg(long, required = true, num_args = 4)]
        validator_key: Vec<PathBuf>,
        #[arg(long)]
        confirm_fresh_earth: bool,
        #[arg(long)]
        output: PathBuf,
    },
    Verify {
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
    },
}

fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > limit {
        bail!("unsafe or oversized Earth input");
    }
    Ok(fs::read(path)?)
}
fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(&serde_json::to_vec(value)?)?;
    file.sync_all()?;
    Ok(())
}
fn pin(value: &str) -> Result<Hash> {
    Hash::from_hex(value).map_err(|e| anyhow!(e))
}
fn main() -> Result<()> {
    match Args::parse().command {
        Command::Draft {
            genesis,
            history,
            manifest_pin,
            initial_target,
            output,
        } => {
            let target = Work::from_hex(&initial_target).map_err(|e| anyhow!(e))?;
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let draft = transition::draft(
                &read(&genesis, 65_536)?,
                &read(&history, 32 * 1024 * 1024)?,
                pin(&manifest_pin)?,
                target,
                now,
            )
            .map_err(|e| anyhow!(e))?;
            if draft.legacy_height != 0 {
                bail!("Earth genesis must have empty predecessor history");
            }
            write_json(&output, &draft)?;
            println!(
                "{}",
                serde_json::json!({"adoption_id":draft.id().map_err(|e| anyhow!(e))?,"legacy_height":"0","signed":false})
            );
        }
        Command::Approve {
            genesis,
            history,
            statement,
            manifest_pin,
            validator_key,
            confirm_fresh_earth,
            output,
        } => {
            if !confirm_fresh_earth {
                bail!("explicit fresh Earth confirmation required");
            }
            let genesis = read(&genesis, 65_536)?;
            let history = read(&history, 32 * 1024 * 1024)?;
            let statement: AdoptionStatement = serde_json::from_slice(&read(&statement, 65_536)?)?;
            let manifest = pin(&manifest_pin)?;
            let expected = transition::draft(
                &genesis,
                &history,
                manifest,
                statement.initial_target,
                statement.started_at,
            )
            .map_err(|e| anyhow!(e))?;
            if expected.signing_bytes().map_err(|e| anyhow!(e))?
                != statement.signing_bytes().map_err(|e| anyhow!(e))?
                || statement.legacy_height != 0
            {
                bail!("Earth adoption statement differs from empty genesis");
            }
            let bytes = statement.signing_bytes().map_err(|e| anyhow!(e))?;
            let mut approvals = Vec::new();
            for path in validator_key {
                let key: Identity = serde_json::from_slice(&read(&path, 16_384)?)?;
                let signature =
                    rld_core::sign_bytes(&key.secret_key, &bytes).map_err(|e| anyhow!(e))?;
                approvals.push(Approval {
                    public_key: key.public_key,
                    signature,
                });
            }
            approvals.sort_by(|a, b| a.public_key.cmp(&b.public_key));
            let adoption = Adoption {
                statement,
                approvals,
            };
            let id = adoption.statement.id().map_err(|e| anyhow!(e))?;
            adoption
                .verify(&genesis, &history, manifest, id)
                .map_err(|e| anyhow!(e))?;
            write_json(&output, &adoption)?;
            println!(
                "{}",
                serde_json::json!({"adoption_id":id,"signed":true,"genesis_only":true})
            );
        }
        Command::Verify {
            genesis,
            history,
            adoption,
            manifest_pin,
            accept_adoption,
        } => {
            let adoption: Adoption = serde_json::from_slice(&read(&adoption, 65_536)?)?;
            let context = adoption
                .verify(
                    &read(&genesis, 65_536)?,
                    &read(&history, 32 * 1024 * 1024)?,
                    pin(&manifest_pin)?,
                    pin(&accept_adoption)?,
                )
                .map_err(|e| anyhow!(e))?;
            if context.legacy_height != 0 {
                bail!("not a fresh Earth genesis");
            }
            println!(
                "{}",
                serde_json::json!({"chain_id":context.chain_id().map_err(|e| anyhow!(e))?,"genesis_only":true,"result":"PASS"})
            );
        }
    }
    Ok(())
}
