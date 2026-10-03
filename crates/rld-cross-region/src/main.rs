//! Manual file handoff for the candidate transport spool. Every output remains
//! UNVERIFIED; this process cannot move or credit RLD.

use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand};
use rld_core::AdmissionHash32 as Hash;
use rld_cross_region::{CourierStore, ProofBundle, MAX_BUNDLE_BYTES, MAX_PROOF_BYTES};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(name = "rldcourier-candidate")]
#[command(about = "Unverified cross-region proof file spool; never credits RLD")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Wrap opaque source-proof bytes for offline carriage.
    #[command(name = "wrap-unverified")]
    Wrap {
        #[arg(long)]
        source_chain: String,
        #[arg(long)]
        destination_chain: String,
        #[arg(long)]
        export_id: String,
        #[arg(long)]
        source_checkpoint: String,
        #[arg(long)]
        source_height: u128,
        #[arg(long)]
        proof_file: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Store a delivered bundle without treating its claims as verified.
    #[command(name = "receive-unverified")]
    Receive {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        bundle_file: PathBuf,
        /// Retain an additional unverified proof version for the same export.
        #[arg(long)]
        retain_variant: bool,
    },
    /// Copy the exact stored bundle to another local file for retransmission.
    #[command(name = "carry-unverified")]
    Carry {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        source_chain: String,
        #[arg(long)]
        export_id: String,
        /// Select an exact proof when several versions of one export exist.
        #[arg(long)]
        bundle_id: Option<String>,
        #[arg(long)]
        output: PathBuf,
    },
}

fn parse_hash(value: &str) -> Result<Hash> {
    Hash::from_hex(value).map_err(|e| anyhow!(e))
}

fn candidate<T>(result: std::result::Result<T, String>) -> Result<T> {
    result.map_err(|error| anyhow!(error))
}

fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > max as u64 {
        bail!("unsafe or oversized input file");
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > max {
        bail!("input file grew beyond bound");
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn main() -> Result<()> {
    match Args::parse().command {
        Command::Wrap {
            source_chain,
            destination_chain,
            export_id,
            source_checkpoint,
            source_height,
            proof_file,
            output,
        } => {
            let proof = read_bounded(&proof_file, MAX_PROOF_BYTES)?;
            let bundle = candidate(ProofBundle::from_proof(
                parse_hash(&source_chain)?,
                parse_hash(&destination_chain)?,
                parse_hash(&export_id)?,
                parse_hash(&source_checkpoint)?,
                source_height,
                &proof,
            ))?;
            let bytes = serde_json::to_vec(&bundle)?;
            if bytes.len() > MAX_BUNDLE_BYTES {
                bail!("encoded bundle too large");
            }
            write_new(&output, &bytes)?;
            println!("WRAPPED_UNVERIFIED {}", candidate(bundle.id())?.to_hex());
        }
        Command::Receive {
            data_dir,
            bundle_file,
            retain_variant,
        } => {
            let bytes = read_bounded(&bundle_file, MAX_BUNDLE_BYTES)?;
            let bundle: ProofBundle = serde_json::from_slice(&bytes)?;
            if bytes != serde_json::to_vec(&bundle)? {
                bail!("noncanonical bundle file");
            }
            let id = candidate(bundle.id())?;
            let mut store = candidate(CourierStore::open(&data_dir))?;
            let newly_stored = if retain_variant {
                candidate(store.enqueue_variant(bundle))?
            } else {
                candidate(store.enqueue(bundle))?
            };
            println!("RECEIVED_UNVERIFIED {} new={newly_stored}", id.to_hex());
        }
        Command::Carry {
            data_dir,
            source_chain,
            export_id,
            bundle_id,
            output,
        } => {
            let store = candidate(CourierStore::open(&data_dir))?;
            let source = parse_hash(&source_chain)?;
            let export = parse_hash(&export_id)?;
            let bundle = match bundle_id {
                Some(id) => {
                    let bundle = candidate(store.bundle_by_id(parse_hash(&id)?))?;
                    if bundle.source_chain_id != source || bundle.export_id != export {
                        bail!("selected bundle belongs to another source/export pair");
                    }
                    bundle
                }
                None => candidate(store.bundle_for_export(source, export))?
                    .ok_or_else(|| anyhow!("unknown source/export pair"))?,
            };
            write_new(&output, &serde_json::to_vec(&bundle)?)?;
            println!("CARRIED_UNVERIFIED {}", candidate(bundle.id())?.to_hex());
        }
    }
    Ok(())
}
