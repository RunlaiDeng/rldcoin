//! Supplemental client bootstrap; never infer upgrade consent from a peer.
use anyhow::{anyhow, bail, Result};
use rld_core::AdmissionHash32 as Hash;
use rld_pow::{transition::Adoption, Chain};
use rld_value_successor::{
    adoption::EarthSuccessorAdoption,
    candidate_client::{load_transition_preview_file, verify_earth_adoption_file, NodeMode},
    chain::{storage::CandidateStore, Block},
    transition::TransitionPreview,
    upgrade::{UpgradeAuthorization, VerifiedUpgrade},
};
use std::{
    fs::{self, File},
    io::Read,
    path::Path,
    time::Duration,
};

#[allow(dead_code)]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    chain_id: Hash,
    v1_tip: Hash,
    transition_preview_id: Hash,
    common: Hash,
    tip: Hash,
    blocks: Vec<Block>,
}

/// Start with a minimal valid locator while catching up a selected branch.
/// The peer can fall back to the genesis anchor after a fork; every returned
/// block still passes ordinary consensus validation. No history is trusted.
#[allow(dead_code)] // Offline import and bootstrap qualification share this module.
pub async fn refresh_source(
    store: &mut CandidateStore,
    http: &reqwest::Client,
    node: &str,
    preview: Hash,
    mode: NodeMode,
) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut cursor = store.chain().tip();
        let mut target = None;
        for _ in 0..1_000_000usize {
            let anchor = store.chain().v1_tip();
            let locator = if cursor == anchor {
                vec![anchor]
            } else {
                vec![cursor, anchor]
            };
            let mut response = http
                .post(format!("{node}{}/sync", mode.base()))
                .json(&serde_json::json!({"locator":locator}))
                .send()
                .await?
                .error_for_status()?;
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                if bytes.len().saturating_add(chunk.len()) > rld_pow::MAX_BLOCK_BYTES * 8 + 8192 {
                    bail!("client sync response byte bound");
                }
                bytes.extend(chunk);
            }
            let page: Page = serde_json::from_slice(&bytes)?;
            if preview.is_zero()
                || page.chain_id != store.chain().chain_id()
                || page.v1_tip != anchor
                || page.transition_preview_id != preview
                || page.blocks.len() > 8
            {
                bail!("client sync identity or page bound");
            }
            let target = *target.get_or_insert(page.tip);
            if page.common != anchor && store.chain().block(page.common).is_none() {
                bail!("client sync unknown common ancestor");
            }
            let empty = page.blocks.is_empty();
            let mut parent = page.common;
            for block in page.blocks {
                if block.header.parent != parent {
                    bail!("client sync discontinuous page");
                }
                parent = block.header.id().map_err(|e| anyhow!(e))?;
                store
                    .accept(block, rld_value_successor::candidate_client::now()?)
                    .map_err(|e| anyhow!(e))?;
            }
            if store.chain().tip() == target
                || store.chain().block(target).is_some()
                    && store
                        .chain()
                        .is_selected_ancestor(target)
                        .map_err(|e| anyhow!(e))?
            {
                if let NodeMode::Adopted(_) = mode {
                    rld_value_successor::candidate_client::refresh_finality(store, http, node)
                        .await?;
                }
                return Ok(());
            }
            if empty || parent == cursor {
                bail!("client peer did not advance");
            }
            cursor = parent;
        }
        bail!("client sync page budget reached")
    })
    .await
    .map_err(|_| anyhow!("client sync exceeded 20-second budget; verified progress retained"))?
}

fn bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_file() || m.file_type().is_symlink() || m.len() > limit {
        bail!("unsafe or oversized client authorization");
    }
    let mut bytes = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        bail!("client authorization exceeds bound");
    }
    Ok(bytes)
}
pub struct VerifiedClient {
    pub preview: TransitionPreview,
    pub upgrade: Option<VerifiedUpgrade>,
}
impl VerifiedClient {
    #[allow(clippy::too_many_arguments)]
    pub fn load(
        genesis: &[u8],
        history: &[u8],
        pow: &Adoption,
        v1: &Chain,
        preview_path: &Path,
        preview_pin: Hash,
        mode: NodeMode,
        earth_path: Option<&Path>,
        authorization_path: Option<&Path>,
        authorization_pin: Option<Hash>,
    ) -> Result<Self> {
        if authorization_path.is_some() != authorization_pin.is_some() {
            bail!("upgrade requires both authorization and explicit acceptance pin");
        }
        let preview = load_transition_preview_file(preview_path)?;
        let upgrade = if let Some(path) = authorization_path {
            let NodeMode::Adopted(earth_pin) = mode else {
                bail!("compatible upgrade requires adopted mode");
            };
            let original_bytes = bounded(
                earth_path.ok_or_else(|| anyhow!("missing original Earth adoption"))?,
                8192,
            )?;
            let original: EarthSuccessorAdoption = serde_json::from_slice(&original_bytes)?;
            if serde_json::to_vec(&original)? != original_bytes {
                bail!("noncanonical original Earth adoption");
            }
            let bytes = bounded(path, 65536)?;
            let signed: UpgradeAuthorization = serde_json::from_slice(&bytes)?;
            if signed.canonical_bytes().map_err(|e| anyhow!(e))? != bytes {
                bail!("noncanonical compatible upgrade authorization");
            }
            Some(
                signed
                    .verify(
                        genesis,
                        history,
                        pow,
                        &original,
                        v1,
                        &preview,
                        preview_pin,
                        earth_pin,
                        authorization_pin.expect("checked paired pin"),
                    )
                    .map_err(|e| anyhow!(e))?,
            )
        } else {
            preview
                .verify_for_candidate(v1, pow.statement.implementation_source_sha256, preview_pin)
                .map_err(|e| anyhow!(e))?;
            if let NodeMode::Adopted(id) = mode {
                verify_earth_adoption_file(
                    earth_path.ok_or_else(|| anyhow!("missing original Earth adoption"))?,
                    genesis,
                    history,
                    pow,
                    v1,
                    &preview,
                    id,
                )?;
            }
            None
        };
        Ok(Self { preview, upgrade })
    }
    pub fn open(
        &self,
        path: &Path,
        v1: &Chain,
        now: u64,
        mode: NodeMode,
        pow: &Adoption,
    ) -> Result<CandidateStore> {
        let result = if let Some(upgrade) = &self.upgrade {
            CandidateStore::open_compatible(path, v1, now, upgrade)
        } else {
            match mode {
                NodeMode::Adopted(id) => CandidateStore::open_finalized(
                    path,
                    v1,
                    now,
                    id,
                    pow.approvals.iter().map(|a| a.public_key.clone()).collect(),
                ),
                NodeMode::Candidate => CandidateStore::open(path, v1, now),
            }
        };
        result.map_err(|e| anyhow!(e))
    }
}

#[cfg(test)]
mod sync_tests {
    use super::*;
    use serde_json::{json, Value};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    async fn attempt(page: Value, expected: bool, label: &str) {
        let context = rld_pow::Context {
            network_domain: "client-sync-qualification".into(),
            zone_id: "isolated".into(),
            currency_genesis: Hash([1; 32]),
            manifest_pin: Hash([2; 32]),
            transition_id: Hash([3; 32]),
            legacy_height: 0,
            legacy_state_root: Hash([4; 32]),
            started_at: 1_000_000,
            initial_target: rld_pow::target_limit(),
            regional: None,
        };
        let v1 = Chain::new(context).unwrap();
        let root =
            std::env::temp_dir().join(format!("rld-sync-test-{}-{label}", std::process::id()));
        assert!(!root.exists());
        let mut store = CandidateStore::open(&root, &v1, 1_000_600).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let node = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 8192];
            let _ = stream.read(&mut request).await.unwrap();
            let bytes = serde_json::to_vec(&page).unwrap();
            let header=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",bytes.len());
            stream.write_all(header.as_bytes()).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
        });
        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let result = refresh_source(
            &mut store,
            &http,
            &node,
            Hash([71; 32]),
            NodeMode::Candidate,
        )
        .await;
        assert_eq!(result.is_ok(), expected, "{label}: {result:?}");
        assert_eq!(store.chain().height(), if expected { 1 } else { 0 });
        task.await.unwrap();
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
    fn page() -> Value {
        let context = rld_pow::Context {
            network_domain: "client-sync-qualification".into(),
            zone_id: "isolated".into(),
            currency_genesis: Hash([1; 32]),
            manifest_pin: Hash([2; 32]),
            transition_id: Hash([3; 32]),
            legacy_height: 0,
            legacy_state_root: Hash([4; 32]),
            started_at: 1_000_000,
            initial_target: rld_pow::target_limit(),
            regional: None,
        };
        let v1 = Chain::new(context).unwrap();
        let c = rld_value_successor::chain::CandidateChain::from_replayed_pow_chain(&v1).unwrap();
        let mut block = c
            .template(rld_core::generate_identity().public_key, 1_000_600, vec![])
            .unwrap();
        while !rld_value_successor::chain::mine_batch(&mut block, 10000).unwrap() {}
        json!({"chain_id":c.chain_id(),"v1_tip":c.v1_tip(),"transition_preview_id":Hash([71;32]),"common":c.v1_tip(),"tip":block.header.id().unwrap(),"blocks":[block]})
    }
    #[tokio::test]
    async fn accepts_valid_page_and_rejects_mismatched_untrusted_pages_before_advancing() {
        attempt(page(), true, "valid").await;
        let mut p = page();
        p["chain_id"] = json!(Hash([88; 32]));
        attempt(p, false, "chain").await;
        let mut p = page();
        p["transition_preview_id"] = json!(Hash([88; 32]));
        attempt(p, false, "preview").await;
        let mut p = page();
        p["common"] = json!(Hash([88; 32]));
        attempt(p, false, "common").await;
        let mut p = page();
        p["blocks"][0]["header"]["parent"] = json!(Hash([88; 32]));
        attempt(p, false, "parent").await;
        let mut p = page();
        p["blocks"] = json!(vec![p["blocks"][0].clone(); 9]);
        attempt(p, false, "bound").await;
        let mut p = page();
        p["blocks"] = json!([]);
        attempt(p, false, "no-progress").await;
    }
}
