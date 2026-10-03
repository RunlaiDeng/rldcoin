//! Public-only drafting and assembly of a candidate destination authorization.
//! Never reads a signing key or activates a destination network.
use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand};
use rld_core::AdmissionHash32 as Hash;
use rld_value_successor::{
    destination::pow::{
        authorization::{
            DestinationGenesisAuthorization, DestinationGenesisAuthorizationStatement,
        },
        Context,
    },
    transition::TransitionPreview,
};
use serde::Serialize;
use std::{fs, io::Read, io::Write, path::PathBuf};

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Print the statement ID and exact bytes for an external Ed25519 signer.
    Draft {
        #[arg(long)]
        destination_context: PathBuf,
        #[arg(long)]
        transition_preview: PathBuf,
    },
    /// Verify and assemble a public signature without reading a secret key.
    Assemble {
        #[arg(long)]
        destination_context: PathBuf,
        #[arg(long)]
        transition_preview: PathBuf,
        #[arg(long)]
        accept_destination_authorization: String,
        #[arg(long)]
        signer_public_key: String,
        #[arg(long)]
        signature: String,
    },
}

fn canonical_file<T: serde::de::DeserializeOwned + serde::Serialize>(
    path: &PathBuf,
    limit: u64,
) -> Result<T> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit {
        bail!("unsafe or oversized candidate input");
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        bail!("candidate input exceeded bound");
    }
    let value: T = serde_json::from_slice(&bytes)?;
    if serde_json::to_vec(&value)? != bytes {
        bail!("candidate input must have exact canonical bytes");
    }
    Ok(value)
}

fn statement(
    context: &PathBuf,
    preview: &PathBuf,
) -> Result<(
    Context,
    TransitionPreview,
    DestinationGenesisAuthorizationStatement,
)> {
    let context: Context = canonical_file(context, 8192)?;
    let preview: TransitionPreview = canonical_file(preview, 4096)?;
    let statement = DestinationGenesisAuthorizationStatement::from_context(&context, &preview)
        .map_err(|error| anyhow!(error))?;
    Ok((context, preview, statement))
}

fn main() -> Result<()> {
    match Args::parse().action {
        Action::Draft {
            destination_context,
            transition_preview,
        } => {
            let (_, _, statement) = statement(&destination_context, &transition_preview)?;
            #[derive(Serialize)]
            struct Draft {
                statement: DestinationGenesisAuthorizationStatement,
                statement_id: Hash,
                signing_bytes_hex: String,
            }
            let draft = Draft {
                statement_id: statement.id().map_err(|error| anyhow!(error))?,
                signing_bytes_hex: hex::encode(
                    statement.signing_bytes().map_err(|error| anyhow!(error))?,
                ),
                statement,
            };
            serde_json::to_writer(std::io::stdout(), &draft)?;
        }
        Action::Assemble {
            destination_context,
            transition_preview,
            accept_destination_authorization,
            signer_public_key,
            signature,
        } => {
            let (context, preview, statement) =
                statement(&destination_context, &transition_preview)?;
            let authorization = DestinationGenesisAuthorization {
                statement,
                signer_public_key: signer_public_key.clone(),
                signature,
            };
            authorization
                .verify_for_candidate(
                    &context,
                    &preview,
                    Hash::from_hex(&accept_destination_authorization)
                        .map_err(|error| anyhow!(error))?,
                    &signer_public_key,
                )
                .map_err(|error| anyhow!(error))?;
            std::io::stdout().write_all(
                &authorization
                    .canonical_bytes()
                    .map_err(|error| anyhow!(error))?,
            )?;
        }
    }
    Ok(())
}
