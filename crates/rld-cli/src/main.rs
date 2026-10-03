use std::{fs, path::PathBuf};

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use rld_core::{generate_identity, sign_bytes, Identity};

#[derive(Parser)]
#[command(name = "rld", about = "Earth key ceremony utility")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create an Ed25519 identity for an offline ceremony or wallet.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign reviewed canonical bytes with a local ceremony key.
    Sign {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        message_hex: String,
    },
}

fn main() -> Result<()> {
    match Args::parse().command {
        Command::Keygen { out } => keygen(out),
        Command::Sign { key, message_hex } => sign(key, message_hex),
    }
}

fn keygen(out: PathBuf) -> Result<()> {
    if out.exists() {
        bail!("refusing to overwrite existing key: {}", out.display());
    }
    let identity = generate_identity();
    let bytes = serde_json::to_vec_pretty(&identity)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use std::io::Write;
    options.open(&out)?.write_all(&bytes)?;
    println!("key created: {}", out.display());
    println!("public key: {}", identity.public_key);
    Ok(())
}

fn sign(key: PathBuf, message_hex: String) -> Result<()> {
    let metadata = fs::symlink_metadata(&key)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 16_384 {
        bail!("unsafe ceremony key file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("ceremony key must be mode 0600");
        }
    }
    let identity: Identity = serde_json::from_slice(&fs::read(key)?)?;
    let message = hex::decode(message_hex)?;
    if message.is_empty() || message.len() > 65_536 {
        bail!("invalid ceremony message length");
    }
    println!(
        "{}",
        sign_bytes(&identity.secret_key, &message).map_err(anyhow::Error::msg)?
    );
    Ok(())
}
