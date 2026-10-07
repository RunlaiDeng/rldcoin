//! Public-only review and assembly; no signing key or activation.
use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use rld_value_successor::{
    candidate_inputs::{canonical, hash},
    transition::{TransitionAuthorization, TransitionAuthorizationStatement, TransitionPreview},
};
use std::{io::Write, path::PathBuf};

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    action: Action,
}
#[derive(Subcommand)]
enum Action {
    Draft {
        #[arg(long)]
        transition_preview: PathBuf,
    },
    Assemble {
        #[arg(long)]
        transition_preview: PathBuf,
        #[arg(long)]
        accept_transition_authorization: String,
        #[arg(long)]
        signer_public_key: String,
        #[arg(long)]
        signature: String,
    },
}

fn main() -> Result<()> {
    match Args::parse().action {
        Action::Draft { transition_preview } => {
            let preview: TransitionPreview = canonical(&transition_preview, 4096)?;
            let statement = TransitionAuthorizationStatement::from_preview(&preview)
                .map_err(|error| anyhow!(error))?;
            serde_json::to_writer(
                std::io::stdout(),
                &serde_json::json!({
                    "statement_id": statement.id().map_err(|error| anyhow!(error))?,
                    "signing_bytes_hex": hex::encode(statement.signing_bytes().map_err(|error| anyhow!(error))?),
                    "statement": statement,
                }),
            )?;
        }
        Action::Assemble {
            transition_preview,
            accept_transition_authorization,
            signer_public_key,
            signature,
        } => {
            let preview: TransitionPreview = canonical(&transition_preview, 4096)?;
            let authorization = TransitionAuthorization {
                statement: TransitionAuthorizationStatement::from_preview(&preview)
                    .map_err(|error| anyhow!(error))?,
                signer_public_key: signer_public_key.clone(),
                signature,
            };
            authorization
                .verify_for_candidate(
                    &preview,
                    hash(&accept_transition_authorization)?,
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
