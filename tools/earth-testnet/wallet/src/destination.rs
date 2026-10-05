//! Independently replay the explicitly pinned destination. A receipt supplied by
//! an endpoint is never sufficient without selected-chain validation here.
use anyhow::{anyhow, ensure, Result};
use rld_core::AdmissionHash32 as Hash;
use rld_value_successor::{
    candidate_client::{loopback_origin, now},
    chain::CandidateChain,
    destination::pow::{
        self,
        authorization::DestinationGenesisAuthorization,
        receipt::{ImportInclusionReceipt, InclusionPolicy},
        storage::DestinationPowStore,
        Block, Command, Context,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
fn err(e: impl std::fmt::Display) -> anyhow::Error {
    anyhow!(e.to_string())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub node: String,
    pub context: PathBuf,
    pub authorization: PathBuf,
}
pub struct Replay {
    pub store: DestinationPowStore,
    pub node: String,
    pub authorization: Hash,
    pub fresh: bool,
    pub checked: u64,
    #[cfg(test)]
    pub isolated_fixture: bool,
}
impl Replay {
    pub fn open(
        path: &Path,
        root: &Path,
        source: &crate::chain::Replay,
        pin: &str,
        signer: &str,
    ) -> Result<Self> {
        let config: Config = serde_json::from_slice(&crate::files::read(path, 8192)?)?;
        ensure!(
            config.context.is_absolute() && config.authorization.is_absolute(),
            "目的链记录必须使用绝对路径"
        );
        let context: Context = serde_json::from_slice(&crate::files::read(&config.context, 8192)?)?;
        ensure!(
            context.chain_id.to_hex()
                == "6f952ed6eff0aa16d27bd18ab6c760357a21770a954952fffeb4852537c5363a",
            "未接受此目的链身份"
        );
        let bytes = crate::files::read(&config.authorization, 8192)?;
        let auth: DestinationGenesisAuthorization = serde_json::from_slice(&bytes)?;
        ensure!(
            auth.canonical_bytes().map_err(err)? == bytes,
            "目的链授权不是规范编码"
        );
        let pin = Hash::from_hex(pin).map_err(err)?;
        let preview = source
            .preview
            .as_ref()
            .ok_or_else(|| anyhow!("缺少预览身份"))?;
        let store = if let Some(upgrade) = source.upgrade.as_ref() {
            upgrade
                .verify_destination_authorization(&auth, &context, preview, pin, signer)
                .map_err(err)?;
            DestinationPowStore::open_compatible(
                &root.join("destination"),
                context,
                source.store.chain(),
                now()?,
                upgrade,
            )
            .map_err(err)?
        } else {
            auth.verify_for_candidate(&context, preview, pin, signer)
                .map_err(err)?;
            DestinationPowStore::open(
                &root.join("destination"),
                context,
                source.store.chain(),
                now()?,
            )
            .map_err(err)?
        };
        Ok(Self {
            store,
            node: loopback_origin(&config.node)?,
            authorization: pin,
            fresh: false,
            checked: 0,
            #[cfg(test)]
            isolated_fixture: false,
        })
    }
    pub async fn refresh(&mut self, source: &CandidateChain, http: &reqwest::Client) -> Result<()> {
        self.fresh = false;
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            self.refresh_inner(source, http),
        )
        .await
        .map_err(|_| anyhow!("本次目的链同步达到时间预算；已验证进度保留，请继续刷新"))?
    }
    async fn refresh_inner(
        &mut self,
        source: &CandidateChain,
        http: &reqwest::Client,
    ) -> Result<()> {
        #[cfg(test)]
        if self.isolated_fixture {
            self.store.audit_source(source).map_err(err)?;
            self.fresh = true;
            self.checked = now()?;
            return Ok(());
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Page {
            chain_id: Hash,
            genesis: Hash,
            common: Hash,
            tip: Hash,
            blocks: Vec<Block>,
        }
        let mut cursor = None;
        let mut complete = false;
        for _ in 0..4096 {
            let locator = self.store.chain().block_locator(cursor).map_err(err)?;
            let mut response = http
                .post(format!("{}/v1/earth-destination/sync", self.node))
                .json(&json!({"locator":locator}))
                .send()
                .await?
                .error_for_status()?;
            let bytes = bounded(&mut response, 2 * pow::MAX_DESTINATION_BLOCK_BYTES + 8192).await?;
            let p: Page = serde_json::from_slice(&bytes)?;
            let c = self.store.chain();
            ensure!(
                p.chain_id == c.chain_id()
                    && p.genesis == c.genesis()
                    && p.blocks.len() <= 2
                    && (p.common == c.genesis() || c.block(p.common).is_some()),
                "目的链同步身份、数量或公共祖先不正确"
            );
            let terminal = p.blocks.is_empty();
            let mut parent = p.common;
            for b in p.blocks {
                ensure!(b.header.parent == parent, "目的链区块不连续");
                parent = b.header.id().map_err(err)?;
                self.store.accept(source, b, now()?).map_err(err)?;
            }
            if terminal || parent == p.tip {
                complete = true;
                break;
            }
            ensure!(cursor != Some(parent), "目的链同步没有进展");
            cursor = Some(parent);
        }
        ensure!(complete, "目的链本次同步达到分页上限；请继续刷新");
        self.store.audit_source(source).map_err(err)?;
        let mut response = http
            .get(format!("{}/v1/earth-destination/status", self.node))
            .send()
            .await?
            .error_for_status()?;
        let s: Value = serde_json::from_slice(&bounded(&mut response, 16384).await?)?;
        let c = self.store.chain();
        ensure!(
            s["live_rld"] == true
                && s["storage_healthy"] == true
                && s["halted"] == false
                && s["source_fresh"] == true
                && s["earth_adoption_id"] == crate::ADOPTION
                && s["destination_authorization_id"] == self.authorization.to_hex()
                && s["destination_chain_id"] == c.chain_id().to_hex()
                && s["destination_genesis"] == c.genesis().to_hex()
                && s["source_tip"] == source.tip().to_hex()
                && s["tip"] == c.tip().to_hex()
                && s["height"] == c.height().to_string()
                && s["state_root"] == c.state().root().map_err(err)?.to_hex()
                && s["chainwork"] == serde_json::to_value(c.chainwork())?,
            "本机目的链重放与节点或源链视图不一致"
        );
        self.checked = now()?;
        self.fresh = true;
        Ok(())
    }
    pub fn policy(&self) -> InclusionPolicy {
        InclusionPolicy {
            destination_chain_id: self.store.chain().chain_id(),
            accepted_genesis: self.store.chain().genesis(),
            minimum_confirmations: 12,
            minimum_inclusion_work: rld_core::header_work(rld_pow::target_limit()),
        }
    }
    pub fn status(&self, journal: &[Journal], owner: Option<&str>) -> Result<Value> {
        let c = self.store.chain();
        let fresh = self.fresh && now()?.saturating_sub(self.checked) <= 30;
        let held = reserved(c, journal);
        let mut spendable = 0u128;
        let mut immature = 0u128;
        let mut reserved_amount = 0u128;
        for (point, coin) in coins(c)? {
            if Some(coin.output.owner.as_str()) == owner {
                let amount = if coin.spendable_height > c.height() {
                    &mut immature
                } else if held.contains(&point) {
                    &mut reserved_amount
                } else {
                    &mut spendable
                };
                *amount = amount
                    .checked_add(coin.output.amount.0)
                    .ok_or_else(|| anyhow!("目的链余额溢出"))?;
            }
        }
        let mut entries = vec![];
        for j in journal {
            let id = command_id(&j.command).map_err(err)?;
            let included = c.best_blocks().map_err(err)?.iter().find_map(|b| {
                b.commands
                    .iter()
                    .any(|x| command_id(x).ok() == Some(id))
                    .then_some(b.header.height)
            });
            entries.push(json!({"id":id,"kind":if matches!(j.command,Command::FinalizedImport{..}){"目的链导入"}else{"目的链转账"},"height":included.map(|x|x.to_string()),"confirmed":included.is_some()}));
        }
        Ok(
            json!({"spendable":crate::chain::format(spendable),"immature":crate::chain::format(immature),"reserved":crate::chain::format(reserved_amount),"configured":true,"fresh":fresh,"chain_id":c.chain_id(),"genesis":c.genesis(),"height":c.height().to_string(),"tip":c.tip(),"journal":entries,"probabilistic_finality":true}),
        )
    }
    pub fn verify_receipt(
        &mut self,
        source: &CandidateChain,
        bundle: &rld_cross_region::ProofBundle,
        receipt: &ImportInclusionReceipt,
    ) -> Result<Value> {
        ensure!(
            self.fresh && now()?.saturating_sub(self.checked) <= 30,
            "目的链观察已经过时"
        );
        let policy = self.policy();
        let o = self
            .store
            .verify_import_receipt(source, bundle, &policy, receipt)
            .map_err(err)?;
        Ok(
            json!({"selected_tip":o.selected_tip,"confirmations":o.confirmations.to_string(),"recipient_spendable_height":receipt.recipient_spendable_height.to_string(),"current_height":self.store.chain().height().to_string(),"probabilistic_finality":true}),
        )
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    pub command: Command,
    pub created_at: u64,
}
pub async fn bounded(response: &mut reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![];
    while let Some(b) = response.chunk().await? {
        ensure!(bytes.len() + b.len() <= limit, "节点响应超过限制");
        bytes.extend(b);
    }
    Ok(bytes)
}

pub fn command_id(command: &Command) -> Result<Hash> {
    use sha2::{Digest, Sha256};
    let mut bytes = b"RLD-EARTH-DESTINATION-SUBMITTED-COMMAND\0".to_vec();
    bytes.extend(serde_json::to_vec(command)?);
    Ok(Hash(Sha256::digest(bytes).into()))
}

pub fn coins(
    chain: &pow::DestinationPowChain,
) -> Result<std::collections::BTreeMap<rld_pow::OutPoint, rld_pow::Coin>> {
    use sha2::{Digest, Sha256};
    let mut points = std::collections::BTreeSet::new();
    for block in chain.best_blocks().map_err(err)? {
        for command in block.commands {
            match command {
                Command::LegacyImport { .. } => anyhow::bail!("旧链迁移导入不能进入新测试链钱包"),
                Command::FinalizedImport { bundle, .. } | Command::Import(bundle) => {
                    let mut bytes = b"RLD-EARTH-DESTINATION-POW-IMPORT-OUTPUT\0".to_vec();
                    bytes.extend(chain.chain_id().0);
                    bytes.extend(bundle.source_chain_id.0);
                    bytes.extend(bundle.export_id.0);
                    let id = Hash(Sha256::digest(bytes).into());
                    for index in [0, 1] {
                        points.insert(rld_pow::OutPoint {
                            transaction: id,
                            index,
                        });
                    }
                }
                Command::Transfer(t) => {
                    let id = t.id().map_err(err)?;
                    for index in (0..t.outputs.len() as u16).chain(std::iter::once(u16::MAX)) {
                        points.insert(rld_pow::OutPoint {
                            transaction: id,
                            index,
                        });
                    }
                }
            }
        }
    }
    let mut result = std::collections::BTreeMap::new();
    let mut total = 0u128;
    for p in points {
        if let Some(coin) = chain.state().coin(&p) {
            total = total
                .checked_add(coin.output.amount.0)
                .ok_or_else(|| anyhow!("目的链余额溢出"))?;
            result.insert(p, coin.clone());
        }
    }
    ensure!(
        total == chain.state().imported_total().0,
        "目的链输出索引不完整；拒绝显示部分余额"
    );
    Ok(result)
}
pub fn reserved(
    chain: &pow::DestinationPowChain,
    journal: &[Journal],
) -> std::collections::BTreeSet<rld_pow::OutPoint> {
    journal
        .iter()
        .filter_map(|j| {
            if let Command::Transfer(t) = &j.command {
                Some(t)
            } else {
                None
            }
        })
        .filter(|t| t.chain_id == chain.chain_id() && chain.height() < t.valid_through_height)
        .flat_map(|t| t.inputs.iter())
        .filter(|p| chain.state().coin(p).is_some())
        .cloned()
        .collect()
}
pub fn prepare(
    chain: &pow::DestinationPowChain,
    owner: &str,
    to: &str,
    amount: u128,
    fee: u128,
    journal: &[Journal],
) -> Result<rld_pow::Transfer> {
    rld_core::validate_ed25519_public_key(to).map_err(err)?;
    ensure!(amount > 0 && fee > 0, "金额和手续费必须大于零");
    let needed = amount.checked_add(fee).ok_or_else(|| anyhow!("金额溢出"))?;
    let held = reserved(chain, journal);
    let mut inputs = vec![];
    let mut total = 0u128;
    for (point, coin) in coins(chain)? {
        if coin.output.owner == owner
            && coin.spendable_height <= chain.height()
            && !held.contains(&point)
        {
            inputs.push(point);
            total = total
                .checked_add(coin.output.amount.0)
                .ok_or_else(|| anyhow!("余额溢出"))?;
            if total >= needed || inputs.len() == 32 {
                break;
            }
        }
    }
    ensure!(
        total >= needed,
        "目的链当前成熟且未占用余额不足，或需要先整理超过 32 个输入"
    );
    let mut outputs = vec![rld_pow::Output {
        owner: to.into(),
        amount: rld_core::Amount(amount),
    }];
    if total > needed {
        outputs.push(rld_pow::Output {
            owner: owner.into(),
            amount: rld_core::Amount(total - needed),
        });
    }
    Ok(rld_pow::Transfer {
        chain_id: chain.chain_id(),
        owner: owner.into(),
        inputs,
        outputs,
        fee: rld_core::Amount(fee),
        valid_through_height: chain
            .height()
            .checked_add(12)
            .ok_or_else(|| anyhow!("高度溢出"))?,
        signature: String::new(),
    })
}
