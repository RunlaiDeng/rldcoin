use crate::{compatibility, files, ADOPTION, CHAIN, ORIGIN_SOURCE, PREVIEW, SOURCE};
use anyhow::{anyhow, ensure, Result};
use rld_core::{AdmissionHash32 as Hash, Amount};
use rld_fast_payments::{Funding, SignedState};
use rld_pow::{storage::Store as V1Store, transition::Adoption, Coin, OutPoint, Output, Transfer};
use rld_value_successor::{
    candidate_client::{self as client, NodeMode},
    chain::{storage::CandidateStore, CandidateChain, Command},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::Duration,
};
fn hash(s: &str) -> Result<Hash> {
    Hash::from_hex(s).map_err(|e| anyhow!(e))
}
fn digest(bytes: &[u8]) -> Hash {
    Hash(Sha256::digest(bytes).into())
}
fn err(e: String) -> anyhow::Error {
    anyhow!(e)
}
#[derive(Deserialize)]
struct Pins {
    manifest_pin: String,
    pow_adoption_id: String,
}
pub struct Replay {
    pub upgrade: Option<rld_value_successor::upgrade::VerifiedUpgrade>,
    pub preview: Option<rld_value_successor::transition::TransitionPreview>,
    #[cfg(test)]
    pub isolated_fixture: bool,
    pub store: CandidateStore,
    pub http: reqwest::Client,
    pub node: String,
    pub fresh: bool,
    pub error: Option<String>,
    pub checked_at: u64,
    _v1: V1Store,
}
impl Replay {
    pub fn open(
        records: &Path,
        root: &Path,
        node: &str,
        authorization: Option<&Path>,
        authorization_pin: Option<&str>,
    ) -> Result<Self> {
        ensure!(
            rld_core::implementation_source::IMPLEMENTATION_SOURCE_COMMITMENT == SOURCE,
            "必须使用精确的已发布共识源码构建钱包"
        );
        let genesis = files::read(&records.join("genesis.json"), 65536)?;
        let history = files::read(&records.join("history.json"), 65536)?;
        let p: Pins = serde_json::from_slice(&files::read(&records.join("pins.json"), 8192)?)?;
        let adoption: Adoption =
            serde_json::from_slice(&files::read(&records.join("pow-adoption.json"), 8192)?)?;
        let context = adoption
            .verify_with_pinned_release_source(
                &genesis,
                &history,
                hash(&p.manifest_pin)?,
                hash(&p.pow_adoption_id)?,
                hash(ORIGIN_SOURCE)?,
            )
            .map_err(err)?;
        let v1 = V1Store::open(&root.join("genesis"), context, client::now()?).map_err(err)?;
        ensure!(
            v1.chain().height() == 0 && v1.chain().tip() == hash(CHAIN)?,
            "钱包仅适用于当前 Earth 空创世"
        );
        let mode = NodeMode::Adopted(hash(ADOPTION)?);
        let verified = compatibility::VerifiedClient::load(
            &genesis,
            &history,
            &adoption,
            v1.chain(),
            &records.join("preview.json"),
            hash(PREVIEW)?,
            mode,
            Some(&records.join("value-adoption.json")),
            authorization,
            authorization_pin.map(hash).transpose()?,
        )?;
        ensure!(
            verified.preview.id().map_err(err)? == hash(PREVIEW)?,
            "预览身份不一致"
        );
        let store = verified.open(
            &root.join("source"),
            v1.chain(),
            client::now()?,
            mode,
            &adoption,
        )?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()?;
        Ok(Self {
            upgrade: verified.upgrade,
            preview: Some(verified.preview),
            #[cfg(test)]
            isolated_fixture: false,
            store,
            http,
            node: client::loopback_origin(node)?,
            fresh: false,
            error: None,
            checked_at: 0,
            _v1: v1,
        })
    }
    pub async fn refresh(&mut self) -> Result<()> {
        #[cfg(test)]
        if self.isolated_fixture {
            self.checked_at = client::now()?;
            self.fresh = true;
            self.error = None;
            return Ok(());
        }
        self.fresh = false;
        let result = tokio::time::timeout(Duration::from_secs(2), self.refresh_inner())
            .await
            .map_err(|_| anyhow!("本次源链同步达到时间预算；已验证进度保留，请继续刷新"))
            .and_then(|result| result);
        self.error = result
            .as_ref()
            .err()
            .map(|_| "节点暂不可用或仍在同步。保留上次已验证余额，暂停发送。".into());
        result
    }
    async fn refresh_inner(&mut self) -> Result<()> {
        client::verify_node_preview_mode(
            &self.http,
            &self.node,
            hash(PREVIEW)?,
            NodeMode::Adopted(hash(ADOPTION)?),
        )
        .await?;
        compatibility::refresh_source(
            &mut self.store,
            &self.http,
            &self.node,
            hash(PREVIEW)?,
            NodeMode::Adopted(hash(ADOPTION)?),
        )
        .await?;
        let mut response = self
            .http
            .get(format!("{}/v1/earth/status", self.node))
            .send()
            .await?
            .error_for_status()?;
        let mut bytes = Vec::new();
        while let Some(c) = response.chunk().await? {
            ensure!(bytes.len() + c.len() <= 8192, "状态响应过大");
            bytes.extend_from_slice(&c);
        }
        let s: serde_json::Value = serde_json::from_slice(&bytes)?;
        let chain = self.store.chain();
        ensure!(
            s["chain_id"] == CHAIN
                && s["earth_adoption_id"] == ADOPTION
                && s["storage_healthy"] == true
                && s["live_rld"] == true,
            "节点身份或存储不正确"
        );
        ensure!(
            s["tip"] == chain.tip().to_hex()
                && s["height"] == chain.height().to_string()
                && s["state_root"] == chain.state().root().map_err(err)?.to_hex()
                && s["chainwork"] == serde_json::to_value(chain.chainwork())?,
            "本机重放与节点视图仍未一致"
        );
        let finality = chain
            .finalized()
            .map(|(block, height)| serde_json::json!({"block":block,"height":height.to_string()}));
        ensure!(
            s["finalized_source"] == serde_json::to_value(finality)?,
            "终局观察不一致"
        );
        self.checked_at = client::now()?;
        self.fresh = true;
        Ok(())
    }
}
// Enumerate possible output identifiers, then ask the authoritative replayed
// Ledger for every coin. Supply reconciliation below prevents partial balances.
pub fn coins(chain: &CandidateChain) -> Result<BTreeMap<OutPoint, Coin>> {
    let mut points = BTreeSet::new();
    let mut channels: BTreeMap<Hash, (Funding, SignedState)> = BTreeMap::new();
    let mut reserves: Vec<(Hash, OutPoint)> = Vec::new();
    let mut add = |id: Hash, indices: Vec<u16>| {
        for index in indices {
            let point = OutPoint {
                transaction: id,
                index,
            };
            if chain.state().coin(&point).is_some() {
                points.insert(point);
            }
        }
    };
    let mut cursor = chain.v1_tip();
    loop {
        let (_, page) = chain.sync_page(&[cursor], 64).map_err(err)?;
        if page.is_empty() {
            break;
        }
        for block in page {
            cursor = block.header.id().map_err(err)?;
            let h = &block.header;
            let mut bytes = b"RLD-EARTH-UNIFIED-SUCCESSOR-COINBASE\0".to_vec();
            bytes.extend(h.chain_id.0);
            bytes.extend(h.parent.0);
            bytes.extend(h.height.to_be_bytes());
            bytes.extend(hex::decode(&h.miner)?);
            bytes.extend(h.commands_root.0);
            add(digest(&bytes), vec![0]);
            for command in &block.commands {
                match command {
                    Command::Transfer(tx) => {
                        let mut indices = (0..tx.outputs.len() as u16).collect::<Vec<_>>();
                        indices.push(u16::MAX);
                        add(tx.id().map_err(err)?, indices);
                    }
                    Command::Open(open) => {
                        let f = open.intent.funding().map_err(err)?;
                        let id = f.id().map_err(err)?;
                        add(id, vec![1, 2]);
                        channels.insert(id, (f, open.initial.clone()));
                    }
                    Command::ReserveChallengeFee(r) => {
                        reserves.push((r.intent.channel, r.intent.input.clone()))
                    }
                    Command::Close {
                        channel,
                        state,
                        fee,
                    }
                    | Command::Challenge {
                        channel,
                        state,
                        fee,
                    } => {
                        add(fee.intent.id().map_err(err)?, vec![0, 1]);
                        let old = channels
                            .get_mut(channel)
                            .ok_or_else(|| anyhow!("通道索引缺失"))?;
                        old.1 = state.clone();
                    }
                    Command::Finalize { channel } => {
                        let (f, s) = channels
                            .get(channel)
                            .ok_or_else(|| anyhow!("结算通道索引缺失"))?;
                        let mut bytes = b"RLD-EARTH-UNIFIED-CHANNEL-SETTLEMENT\0".to_vec();
                        bytes.extend(channel.0);
                        bytes.extend(s.state.signing_bytes(f).map_err(err)?);
                        bytes.extend(h.height.to_be_bytes());
                        add(digest(&bytes), vec![0, 1, 2]);
                        for (_, input) in reserves.iter().filter(|(id, _)| id == channel) {
                            let mut b = b"RLD-EARTH-UNIFIED-CHALLENGE-FEE-REFUND\0".to_vec();
                            b.extend(channel.0);
                            b.extend(input.transaction.0);
                            b.extend(input.index.to_be_bytes());
                            add(digest(&b), vec![0]);
                        }
                    }
                    Command::Export(e) => add(e.intent.id().map_err(err)?, vec![1, 2]),
                }
            }
        }
    }
    let mut found = BTreeMap::new();
    let mut sum = 0u128;
    for point in points {
        if let Some(coin) = chain.state().coin(&point) {
            sum = sum
                .checked_add(coin.output.amount.0)
                .ok_or_else(|| anyhow!("余额溢出"))?;
            found.insert(point, coin.clone());
        }
    }
    ensure!(
        sum == chain.state().totals().map_err(err)?.0 .0,
        "余额索引不完整；拒绝显示部分余额"
    );
    Ok(found)
}
pub const UNIT: u128 = 1_000_000_000_000_000_000_000_000;
pub fn amount(s: &str) -> Result<u128> {
    ensure!(
        !s.is_empty() && s.len() <= 80 && s.bytes().all(|b| b.is_ascii_digit() || b == b'.'),
        "金额必须为普通十进制数字"
    );
    let parts = s.split('.').collect::<Vec<_>>();
    ensure!(parts.len() <= 2 && !parts[0].is_empty(), "金额格式不正确");
    ensure!(
        parts[0] == "0" || !parts[0].starts_with('0'),
        "金额不能有多余前导零"
    );
    let whole = parts[0].parse::<u128>()?;
    let frac = parts.get(1).copied().unwrap_or("");
    ensure!(
        frac.len() <= 24 && (parts.len() == 1 || !frac.is_empty()),
        "最多支持 24 位小数"
    );
    let fraction = if frac.is_empty() {
        0
    } else {
        frac.parse::<u128>()?
            .checked_mul(10u128.pow((24 - frac.len()) as u32))
            .ok_or_else(|| anyhow!("金额溢出"))?
    };
    whole
        .checked_mul(UNIT)
        .and_then(|v| v.checked_add(fraction))
        .ok_or_else(|| anyhow!("金额溢出"))
}
pub fn format(n: u128) -> String {
    let whole = n / UNIT;
    let frac = n % UNIT;
    if frac == 0 {
        whole.to_string()
    } else {
        format!("{whole}.{}", format!("{frac:024}").trim_end_matches('0'))
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    pub command: Command,
    pub created_at: u64,
}
pub fn reserved(chain: &CandidateChain, journal: &[Journal]) -> Result<BTreeSet<OutPoint>> {
    let mut result = BTreeSet::new();
    for j in journal {
        let (inputs, expiry) = match &j.command {
            Command::Transfer(t) => (t.inputs.clone(), t.valid_through_height),
            Command::Open(o) => (vec![o.intent.input.clone()], o.intent.valid_through_height),
            Command::ReserveChallengeFee(r) => (vec![r.intent.input.clone()], u128::MAX),
            Command::Close { fee, .. } | Command::Challenge { fee, .. } => (
                vec![fee.intent.input.clone()],
                fee.intent.valid_through_height,
            ),
            Command::Export(e) => (vec![e.intent.input.clone()], e.intent.valid_through_height),
            Command::Finalize { .. } => (vec![], 0),
        };
        if chain.height() < expiry {
            result.extend(
                inputs
                    .into_iter()
                    .filter(|p| chain.state().coin(p).is_some()),
            );
        }
    }
    Ok(result)
}
pub fn prepare(
    chain: &CandidateChain,
    owner: &str,
    to: &str,
    value: u128,
    fee: u128,
    journal: &[Journal],
) -> Result<Transfer> {
    rld_core::validate_ed25519_public_key(to).map_err(err)?;
    ensure!(value > 0 && fee >= 1, "金额及手续费必须大于零");

    let total = value.checked_add(fee).ok_or_else(|| anyhow!("金额溢出"))?;
    let held = reserved(chain, journal)?;
    let mut inputs = Vec::new();
    let mut sum = 0u128;
    for (point, coin) in coins(chain)? {
        if coin.output.owner == owner
            && coin.spendable_height <= chain.height()
            && !held.contains(&point)
        {
            inputs.push(point);
            sum = sum
                .checked_add(coin.output.amount.0)
                .ok_or_else(|| anyhow!("余额溢出"))?;
            if sum >= total || inputs.len() == 32 {
                break;
            }
        }
    }
    ensure!(
        sum >= total,
        "当前可花余额不足，或需要先合并超过 32 个小额输入"
    );
    let mut outputs = vec![Output {
        owner: to.into(),
        amount: Amount(value),
    }];
    if sum > total {
        outputs.push(Output {
            owner: owner.into(),
            amount: Amount(sum - total),
        });
    }
    Ok(Transfer {
        chain_id: chain.chain_id(),
        owner: owner.into(),
        inputs,
        outputs,
        fee: Amount(fee),
        valid_through_height: chain
            .height()
            .checked_add(12)
            .ok_or_else(|| anyhow!("高度溢出"))?,
        signature: String::new(),
    })
}

#[cfg(test)]
pub fn fixture(root: &Path, node: &str) -> Replay {
    let context = rld_pow::Context {
        network_domain: "wallet-io-fixture".into(),
        zone_id: "fixture".into(),
        currency_genesis: Hash([1; 32]),
        manifest_pin: Hash([2; 32]),
        transition_id: Hash([3; 32]),
        legacy_height: 0,
        legacy_state_root: Hash([4; 32]),
        started_at: 1_000_000,
        initial_target: rld_pow::target_limit(),
        regional: None,
    };
    let v1 = V1Store::open(&root.join("genesis"), context, 1_000_000).unwrap();
    let keys = crate::tests::fixture_validators()
        .iter()
        .map(|k| k.public_key.clone())
        .collect();
    let store = CandidateStore::open_finalized(
        &root.join("source"),
        v1.chain(),
        client::now().unwrap(),
        Hash([21; 32]),
        keys,
    )
    .unwrap();
    Replay {
        upgrade: None,
        preview: None,
        isolated_fixture: true,
        store,
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .no_proxy()
            .build()
            .unwrap(),
        node: node.into(),
        fresh: false,
        error: None,
        checked_at: 0,
        _v1: v1,
    }
}
