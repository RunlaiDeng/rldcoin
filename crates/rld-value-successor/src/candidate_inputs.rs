//! Shared bounded inputs for isolated, explicitly accepted candidate tools.
//! These tools cannot activate adopted Earth rules or migrate test value.

use crate::{
    candidate_client::{load_verified_transition_preview_file, now},
    chain::storage::CandidateStore,
};
use anyhow::{anyhow, bail, Result};
use clap::Args;
use rld_core::{AdmissionHash32 as Hash, Identity};
use rld_pow::{storage::Store, transition::Adoption};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[derive(Args)]
pub struct SourceArgs {
    #[arg(long)]
    pub genesis: PathBuf,
    #[arg(long)]
    pub history: PathBuf,
    #[arg(long)]
    pub adoption: PathBuf,
    #[arg(long)]
    pub manifest_pin: String,
    #[arg(long)]
    pub accept_adoption: String,
    #[arg(long)]
    pub pinned_v1_source: String,
    #[arg(long)]
    pub v1_data_dir: PathBuf,
    #[arg(long)]
    pub offline_v1_copy: bool,
}

pub fn hash(input: &str) -> Result<Hash> {
    Hash::from_hex(input).map_err(|error| anyhow!(error))
}

pub fn read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit as u64 {
        bail!("unsafe or oversized candidate input");
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        bail!("candidate input exceeded byte bound");
    }
    Ok(bytes)
}

pub fn canonical<T: DeserializeOwned + Serialize>(path: &Path, limit: usize) -> Result<T> {
    let bytes = read(path, limit)?;
    let value: T = serde_json::from_slice(&bytes)?;
    if serde_json::to_vec(&value)? != bytes {
        bail!("candidate input must have exact canonical bytes");
    }
    Ok(value)
}

impl SourceArgs {
    pub fn replay(&self) -> Result<Store> {
        if !self.offline_v1_copy {
            bail!("explicit disposable v1 copy required");
        }
        let genesis = read(&self.genesis, 65_536)?;
        let history = read(&self.history, 32 * 1024 * 1024)?;
        let adoption: Adoption = serde_json::from_slice(&read(&self.adoption, 65_536)?)?;
        let context = adoption
            .verify_with_pinned_release_source(
                &genesis,
                &history,
                hash(&self.manifest_pin)?,
                hash(&self.accept_adoption)?,
                hash(&self.pinned_v1_source)?,
            )
            .map_err(|error| anyhow!(error))?;
        if context.started_at > now()? {
            bail!("candidate adoption begins in the future");
        }
        Store::open(&self.v1_data_dir, context, now()?).map_err(|error| anyhow!(error))
    }
}

#[derive(Args)]
pub struct CandidateArgs {
    #[command(flatten)]
    pub source: SourceArgs,
    #[arg(long)]
    pub transition_preview: PathBuf,
    #[arg(long)]
    pub accept_transition_preview: String,
    #[arg(long)]
    pub candidate_dir: PathBuf,
}

pub struct CandidateInputs {
    // Keep the replay cut locked for the whole client lifetime.
    pub v1: Store,
    pub store: CandidateStore,
    pub preview_id: Hash,
}

impl CandidateArgs {
    pub fn open(&self) -> Result<CandidateInputs> {
        let v1 = self.source.replay()?;
        let preview = load_verified_transition_preview_file(
            &self.transition_preview,
            v1.chain(),
            hash(&self.source.pinned_v1_source)?,
            hash(&self.accept_transition_preview)?,
        )?;
        let preview_id = preview.id().map_err(|error| anyhow!(error))?;
        let store = CandidateStore::open(&self.candidate_dir, v1.chain(), now()?)
            .map_err(|error| anyhow!(error))?;
        Ok(CandidateInputs {
            v1,
            store,
            preview_id,
        })
    }
}

pub struct LocalKey {
    pub public: String,
    pub secret: Zeroizing<String>,
}

pub fn key(path: &Path) -> Result<LocalKey> {
    let metadata = fs::symlink_metadata(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("candidate key must be owner-only");
        }
    }
    let bytes = Zeroizing::new(read(path, 8192)?);
    let identity: Identity = serde_json::from_slice(&bytes)?;
    rld_core::validate_ed25519_public_key(&identity.public_key).map_err(|error| anyhow!(error))?;
    Ok(LocalKey {
        public: identity.public_key,
        secret: Zeroizing::new(identity.secret_key),
    })
}

pub fn http_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(20))
        .build()?)
}

pub async fn response<T: DeserializeOwned>(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<T> {
    response = response.error_for_status()?;
    if response
        .content_length()
        .is_some_and(|size| size > limit as u64)
    {
        bail!("candidate response too large");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len().saturating_add(chunk.len()) > limit {
            bail!("candidate response exceeded bound");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&bytes)?)
}

/// Normal shutdown of the owned loopback service on either terminal or TERM.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {},
                    _ = term.recv() => {},
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
