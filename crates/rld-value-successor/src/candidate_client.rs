//! Bounded, locally verified sync for an unadopted candidate chain.

use crate::adoption::EarthSuccessorAdoption;
use crate::chain::finality::FinalityCertificate;
use crate::chain::{storage::CandidateStore, Block, CandidateChain};
use crate::transition::TransitionPreview;
use anyhow::{anyhow, bail, Context as _, Result};
use rld_core::AdmissionHash32 as Hash;
use rld_pow::{transition::Adoption, Chain, MAX_BLOCK_BYTES, MAX_TRACKED_BLOCKS};
use serde::Deserialize;
use std::{
    fs::{self, File},
    io::Read,
    net::IpAddr,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncResponse {
    chain_id: Hash,
    v1_tip: Hash,
    transition_preview_id: Hash,
    common: Hash,
    tip: Hash,
    blocks: Vec<Block>,
}

#[derive(Deserialize)]
pub struct CandidateNodeStatus {
    pub chain_id: Hash,
    pub transition_preview_id: Hash,
    status: String,
    live_rld: bool,
    earth_adoption_id: Option<Hash>,
}

#[derive(Clone, Copy)]
pub enum NodeMode {
    Candidate,
    Adopted(Hash),
}

impl NodeMode {
    pub fn base(self) -> &'static str {
        match self {
            Self::Candidate => "/v1/successor-candidate",
            Self::Adopted(_) => "/v1/earth",
        }
    }
}

pub fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

pub fn loopback_origin(input: &str) -> Result<String> {
    let url = reqwest::Url::parse(input)?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("missing candidate host"))?;
    let ip: IpAddr = host
        .parse()
        .context("candidate host must be a loopback IP")?;
    if url.scheme() != "http"
        || !ip.is_loopback()
        || url.port().is_none()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        bail!("candidate node must be an explicit loopback HTTP origin");
    }
    Ok(input.trim_end_matches('/').to_owned())
}

pub async fn verify_node_preview(
    client: &reqwest::Client,
    node: &str,
    accepted_preview: Hash,
) -> Result<CandidateNodeStatus> {
    verify_node_preview_mode(client, node, accepted_preview, NodeMode::Candidate).await
}

pub async fn verify_node_preview_mode(
    client: &reqwest::Client,
    node: &str,
    accepted_preview: Hash,
    mode: NodeMode,
) -> Result<CandidateNodeStatus> {
    if accepted_preview.is_zero() {
        bail!("missing accepted transition preview");
    }
    let mut response = client
        .get(format!("{node}{}/status", mode.base()))
        .send()
        .await?
        .error_for_status()?;
    if response.content_length().is_some_and(|size| size > 8192) {
        bail!("candidate status response too large");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len().saturating_add(chunk.len()) > 8192 {
            bail!("candidate status response exceeded bound");
        }
        bytes.extend_from_slice(&chunk);
    }
    let status: CandidateNodeStatus = serde_json::from_slice(&bytes)?;
    let identity_ok = match mode {
        NodeMode::Candidate => {
            status.status == "UNADOPTED_LOCAL_CANDIDATE_ONLY"
                && !status.live_rld
                && status.earth_adoption_id.is_none()
        }
        NodeMode::Adopted(id) => {
            status.status == "ADOPTED_EARTH_SUCCESSOR_V1"
                && status.live_rld
                && status.earth_adoption_id == Some(id)
        }
    };
    if !identity_ok || status.transition_preview_id != accepted_preview {
        bail!("candidate node transition preview mismatch");
    }
    Ok(status)
}

/// Check the exact operator-selected candidate cut before opening any
/// successor store, wallet or destination credit. This is local consent only.
pub fn verify_transition_preview_file(
    path: &Path,
    v1: &Chain,
    adopted_v1_source: Hash,
    accepted_id: Hash,
) -> Result<Hash> {
    load_verified_transition_preview_file(path, v1, adopted_v1_source, accepted_id)?
        .id()
        .map_err(|e| anyhow!(e))
}

/// Return the same verified bytes for callers that must bind another signed
/// decision to this exact preview without reopening a mutable input path.
pub fn load_verified_transition_preview_file(
    path: &Path,
    v1: &Chain,
    adopted_v1_source: Hash,
    accepted_id: Hash,
) -> Result<TransitionPreview> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 4096 {
        bail!("unsafe or oversized transition preview");
    }
    let mut bytes = Vec::new();
    File::open(path)?.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        bail!("transition preview exceeded byte bound");
    }
    let preview: TransitionPreview = serde_json::from_slice(&bytes)?;
    if preview.canonical_bytes().map_err(|e| anyhow!(e))? != bytes {
        bail!("transition preview must have exact canonical bytes");
    }
    preview
        .verify_for_candidate(v1, adopted_v1_source, accepted_id)
        .map_err(|e| anyhow!(e))?;
    Ok(preview)
}

pub fn verify_earth_adoption_file(
    path: &Path,
    genesis: &[u8],
    history: &[u8],
    pow_adoption: &Adoption,
    v1: &Chain,
    preview: &TransitionPreview,
    accepted_id: Hash,
) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 8192 {
        bail!("unsafe or oversized Earth adoption");
    }
    let mut bytes = Vec::new();
    File::open(path)?.take(8193).read_to_end(&mut bytes)?;
    if bytes.len() > 8192 {
        bail!("Earth adoption exceeded byte bound");
    }
    let adoption: EarthSuccessorAdoption = serde_json::from_slice(&bytes)?;
    if serde_json::to_vec(&adoption)? != bytes {
        bail!("Earth adoption is not canonical JSON");
    }
    adoption
        .verify(genesis, history, pow_adoption, v1, preview, accepted_id)
        .map_err(|error| anyhow!(error))
}

fn locator(chain: &CandidateChain, cursor: Option<Hash>) -> Result<Vec<Hash>> {
    let path = chain.best_blocks().map_err(|error| anyhow!(error))?;
    let mut ids = Vec::new();
    if let Some(id) = cursor.filter(|id| chain.block(*id).is_some()) {
        ids.push(id);
    }
    let mut back = 0usize;
    let mut step = 1usize;
    while back < path.len() && ids.len() < 63 {
        let id = path[path.len() - 1 - back]
            .header
            .id()
            .map_err(|error| anyhow!(error))?;
        if !ids.contains(&id) {
            ids.push(id);
        }
        if ids.len() > 10 {
            step = step.saturating_mul(2);
        }
        back = back.saturating_add(step);
    }
    ids.push(chain.v1_tip());
    Ok(ids)
}

pub async fn refresh(
    store: &mut CandidateStore,
    client: &reqwest::Client,
    node: &str,
    accepted_preview: Hash,
) -> Result<()> {
    refresh_mode(store, client, node, accepted_preview, NodeMode::Candidate).await
}

pub async fn refresh_mode(
    store: &mut CandidateStore,
    client: &reqwest::Client,
    node: &str,
    accepted_preview: Hash,
    mode: NodeMode,
) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(20), async {
        refresh_bounded(store, client, node, accepted_preview, mode).await?;
        if let NodeMode::Adopted(_) = mode {
            refresh_finality(store, client, node).await?;
        }
        Ok(())
    })
    .await
    .map_err(|_| anyhow!("candidate sync exceeded 20-second budget"))?
}

pub async fn refresh_finality(
    store: &mut CandidateStore,
    client: &reqwest::Client,
    node: &str,
) -> Result<()> {
    let certificate = fetch_finality(client, node).await?;
    if let Some(certificate) = certificate {
        let old_height = store.finality().map_or(0, |old| old.statement.height);
        if certificate.statement.height > old_height {
            store
                .install_finality(certificate)
                .map_err(|error| anyhow!(error))?;
        } else if certificate.statement.height == old_height {
            if let Some(old) = store.finality() {
                if old != &certificate {
                    bail!("conflicting Earth finality certificates");
                }
            }
        }
    }
    Ok(())
}

pub async fn fetch_finality(
    client: &reqwest::Client,
    node: &str,
) -> Result<Option<FinalityCertificate>> {
    let mut response = client
        .get(format!("{node}/v1/earth/finality"))
        .send()
        .await?
        .error_for_status()?;
    if response.content_length().is_some_and(|len| len > 8192) {
        bail!("oversized Earth finality response");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len() + chunk.len() > 8192 {
            bail!("oversized Earth finality response");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&bytes)?)
}

async fn refresh_bounded(
    store: &mut CandidateStore,
    client: &reqwest::Client,
    node: &str,
    accepted_preview: Hash,
    mode: NodeMode,
) -> Result<()> {
    if accepted_preview.is_zero() {
        bail!("missing accepted transition preview");
    }
    let mut cursor = None;
    let mut observed_tip = None;
    for _ in 0..MAX_TRACKED_BLOCKS.div_ceil(8) {
        let mut response = client
            .post(format!("{node}{}/sync", mode.base()))
            .json(&serde_json::json!({"locator":locator(store.chain(), cursor)?}))
            .send()
            .await?
            .error_for_status()?;
        if response
            .content_length()
            .is_some_and(|n| n > (MAX_BLOCK_BYTES * 8 + 8192) as u64)
        {
            bail!("candidate sync response too large");
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if bytes.len().saturating_add(chunk.len()) > MAX_BLOCK_BYTES * 8 + 8192 {
                bail!("candidate sync response exceeded bound");
            }
            bytes.extend_from_slice(&chunk);
        }
        let batch: SyncResponse = serde_json::from_slice(&bytes)?;
        if batch.chain_id != store.chain().chain_id()
            || batch.v1_tip != store.chain().v1_tip()
            || batch.transition_preview_id != accepted_preview
            || batch.blocks.len() > 8
        {
            bail!("candidate sync network, preview or batch mismatch");
        }
        let target = *observed_tip.get_or_insert(batch.tip);
        if batch.common != store.chain().v1_tip() && store.chain().block(batch.common).is_none() {
            bail!("candidate sync unknown common block");
        }
        let mut parent = batch.common;
        for block in &batch.blocks {
            if block.header.parent != parent {
                bail!("discontinuous candidate sync response");
            }
            parent = block.header.id().map_err(|error| anyhow!(error))?;
            store
                .accept(block.clone(), now()?)
                .map_err(|error| anyhow!(error))?;
        }
        if store.chain().tip() == target
            || store
                .chain()
                .best_blocks()
                .map_err(|error| anyhow!(error))?
                .iter()
                .any(|block| block.header.id().ok() == Some(target))
        {
            return Ok(());
        }
        if batch.blocks.is_empty() || cursor == Some(parent) {
            bail!("candidate peer did not advance to its selected branch");
        }
        cursor = Some(parent);
    }
    bail!("candidate sync page budget reached")
}
