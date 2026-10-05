mod address;
mod chain;
#[path = "../../earth-payment-tools/src/compatibility.rs"]
mod compatibility;
mod destination;
mod files;
mod product;
mod snapshot;
mod vault;
use anyhow::{anyhow, ensure, Result};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use rand::{rngs::OsRng, RngCore};
use rld_core::sign_bytes;
use rld_value_successor::{
    candidate_client::now,
    chain::{storage::command_id, Command},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use zeroize::Zeroizing;
pub const CHAIN: &str = "e8a8dd66eac5a8fe70816901c6b06035fc92b2193213d8fa0f00d2f10a32438e";
pub const ORIGIN_SOURCE: &str = "d4fdaf6dbb05d00e1820f585dc7ddeb5f0d10f927b003d4551c0429a92d66b54";
pub const ADOPTION: &str = "816c334ccfbb9f36d8e28bf7905f2d986808888ff350d0db876f5a646a025940";
pub const PREVIEW: &str = "7e35a41673f254d338fa4fedfcc0d82240bed1eac378f12a81eaf1a23d5e081e";
pub const SOURCE: &str = "d4fdaf6dbb05d00e1820f585dc7ddeb5f0d10f927b003d4551c0429a92d66b54";
#[derive(Parser)]
#[command(
    version = "0.3.0-product-candidate",
    about = "Worthless-test-currency wallet; cannot connect to retired mainnet"
)]
struct Args {
    #[arg(long)]
    records: PathBuf,
    #[arg(long)]
    data: PathBuf,
    #[arg(long, default_value = "http://127.0.0.1:48320")]
    node: String,
    #[arg(long, default_value_t = 48340)]
    port: u16,
    #[arg(long, requires = "accept_compatibility_authorization")]
    compatibility_authorization: Option<PathBuf>,
    #[arg(long)]
    accept_compatibility_authorization: Option<String>,
    #[arg(long,requires_all=["accept_destination_authorization","destination_signer"])]
    destination_config: Option<PathBuf>,
    #[arg(long, requires = "destination_config")]
    accept_destination_authorization: Option<String>,
    #[arg(long, requires = "destination_config")]
    destination_signer: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    #[serde(default = "default_chain")]
    chain_id: String,
    vault: Option<vault::Vault>,
    backup_verified: bool,
    journal: Vec<chain::Journal>,
    #[serde(default)]
    external_public: Option<String>,
    #[serde(default)]
    retired: bool,
    #[serde(default)]
    products: product::Book,
    #[serde(default)]
    destination_journal: Vec<destination::Journal>,
}
fn default_chain() -> String {
    CHAIN.into()
}
impl Default for Saved {
    fn default() -> Self {
        Self {
            chain_id: default_chain(),
            vault: None,
            backup_verified: false,
            journal: vec![],
            external_public: None,
            retired: false,
            products: product::Book::default(),
            destination_journal: vec![],
        }
    }
}
impl Saved {
    fn owner(&self) -> Option<&str> {
        self.vault
            .as_ref()
            .map(|v| v.public_key.as_str())
            .or(self.external_public.as_deref())
    }
}
struct Draft {
    tx: rld_pow::Transfer,
    tip: String,
    created: u64,
    id: String,
}
struct Wallet {
    saved: Saved,
    replay: chain::Replay,
    destination: Option<destination::Replay>,
    path: PathBuf,
    secret: Option<Zeroizing<String>>,
    unlocked_until: u64,
    draft: Option<Draft>,
    write_failed: bool,
    product_draft: Option<product::Draft>,
    _lock: std::fs::File,
}
#[derive(Clone)]
struct App {
    wallet: Arc<Mutex<Wallet>>,
    token: String,
    origin: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    action: String,
    #[serde(default)]
    password: String,
    backup: Option<vault::Vault>,
    snapshot: Option<snapshot::Snapshot>,
    packet: Option<Value>,
    channel: Option<String>,
    kind: Option<String>,
    peer: Option<String>,
    close_fee: Option<String>,
    destination: Option<String>,
    destination_fee: Option<String>,
    watcher: Option<String>,
    watch_url: Option<String>,
    input: Option<rld_pow::OutPoint>,
    signature: Option<String>,
    to: Option<String>,
    amount: Option<String>,
    fee: Option<String>,
    draft: Option<String>,
    transaction: Option<String>,
}
fn random() -> String {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |x, (a, b)| x | (a ^ b)) == 0
}
fn auth(origin: &str, expected: &str, headers: &HeaderMap) -> Result<()> {
    ensure!(
        headers.get(header::HOST).and_then(|v| v.to_str().ok()) == origin.strip_prefix("http://"),
        "无效本机访问地址"
    );
    if let Some(value) = headers.get(header::ORIGIN) {
        ensure!(value.to_str()? == origin, "拒绝跨站请求");
    }
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");
    ensure!(same(token, expected), "本机会话已失效；请重新打开启动链接");
    Ok(())
}
impl Wallet {
    fn persist(&mut self) -> Result<()> {
        ensure!(
            !self.write_failed,
            "磁盘保存曾失败；请保留数据目录并重启核验，当前停止写入和发送"
        );
        let result = (|| {
            ensure!(self.saved.journal.len() <= 10000, "交易记录已达容量上限");
            ensure!(
                self.saved.destination_journal.len() <= 10000,
                "目的链记录达到容量上限"
            );
            ensure!(
                self.saved.products.channels.len() <= 1000
                    && self.saved.products.invitations.len() <= 1000
                    && self.saved.products.returns.len() <= 10000
                    && self
                        .saved
                        .products
                        .channels
                        .iter()
                        .map(|c| { c.receipts.len() + usize::from(c.pending_receive.is_some()) })
                        .sum::<usize>()
                        <= 10000,
                "通道或返回证明记录达到容量上限"
            );
            let bytes = serde_json::to_vec(&self.saved)?;
            ensure!(
                bytes.len() <= snapshot::MAX,
                "钱包记录达到容量上限，请保留数据目录"
            );
            files::atomic(&self.path, &bytes)
        })();
        if let Err(error) = result {
            // A failure can happen after rename. Retain the in-memory journal and
            // prohibit further writes/delivery until restart reconciles the disk.
            // Serialization and capacity failures also leave an unsaved decision.
            self.write_failed = true;
            self.secret = None;
            self.draft = None;
            self.product_draft = None;
            return Err(error.context("保存失败，付款已暂停；保留整个数据目录并重启核验"));
        }
        Ok(())
    }
    fn expire(&mut self) {
        if self.secret.is_some() && now().unwrap_or(u64::MAX) >= self.unlocked_until {
            self.secret = None;
            self.draft = None;
            self.product_draft = None;
        }
    }
    fn status(&mut self) -> Result<Value> {
        self.expire();
        let c = self.replay.store.chain();
        let owner = self.saved.owner();
        let mut held = chain::reserved(c, &self.saved.journal)?;
        held.extend(product::reserved_inputs(&self.saved.products, c));
        let mut spendable = 0u128;
        let mut immature = 0u128;
        let mut reserved = 0u128;
        for (p, coin) in chain::coins(c)? {
            if Some(coin.output.owner.as_str()) == owner {
                let target = if coin.spendable_height > c.height() {
                    &mut immature
                } else if held.contains(&p) {
                    &mut reserved
                } else {
                    &mut spendable
                };
                *target = target
                    .checked_add(coin.output.amount.0)
                    .ok_or_else(|| anyhow!("余额溢出"))?;
            }
        }
        let mut history = Vec::new();
        let journal_ids = self
            .saved
            .journal
            .iter()
            .filter_map(|j| match &j.command {
                Command::Transfer(t) => Some(t.id().map_err(|e| anyhow!(e))),
                _ => None,
            })
            .collect::<Result<std::collections::BTreeSet<_>>>()?;
        let mut included_journal = std::collections::BTreeSet::new();
        let mut selected_commands = std::collections::BTreeMap::new();
        let mut cursor = c.v1_tip();
        loop {
            let (_, page) = c.sync_page(&[cursor], 64).map_err(|e| anyhow!(e))?;
            if page.is_empty() {
                break;
            }
            for b in page {
                cursor = b.header.id().map_err(|e| anyhow!(e))?;
                for cmd in &b.commands {
                    selected_commands
                        .insert(command_id(cmd).map_err(|e| anyhow!(e))?, b.header.height);
                    if let Command::Transfer(tx) = cmd {
                        let id = tx.id().map_err(|e| anyhow!(e))?;
                        if journal_ids.contains(&id) {
                            included_journal.insert(id);
                        }
                        if Some(tx.owner.as_str()) == owner
                            || tx.outputs.iter().any(|o| Some(o.owner.as_str()) == owner)
                        {
                            history.push(json!({"id":tx.id().map_err(|e|anyhow!(e))?,"direction":if Some(tx.owner.as_str())==owner{"发送"}else{"接收"},"amount":chain::format(tx.outputs.iter().filter(|o|if Some(tx.owner.as_str())==owner{Some(o.owner.as_str())!=owner}else{Some(o.owner.as_str())==owner}).map(|o|o.amount.0).sum()),"status":"已纳入选定链","confirmations":(c.height()-b.header.height+1).to_string(),"height":b.header.height.to_string()}));
                            if history.len() > 100 {
                                history.remove(0);
                            }
                        }
                    }
                }
            }
        }
        for j in &self.saved.journal {
            if let Command::Transfer(t) = &j.command {
                let id = t.id().map_err(|e| anyhow!(e))?.to_hex();
                if !included_journal.contains(&t.id().map_err(|e| anyhow!(e))?) {
                    let state = if c.height() >= t.valid_through_height {
                        "已过期"
                    } else if t.inputs.iter().any(|p| c.state().coin(p).is_none()) {
                        "输入已花费或发生重组"
                    } else {
                        "待确认，可原样重试"
                    };
                    history.push(json!({"id":id,"direction":"发送","amount":chain::format(t.outputs[0].amount.0),"status":state,"confirmations":"0"}));
                }
            }
        }
        let mut commands = Vec::new();
        for j in &self.saved.journal {
            if matches!(j.command, Command::Transfer(_)) {
                continue;
            }
            let id = command_id(&j.command).map_err(|e| anyhow!(e))?;
            let (kind, expiry) = match &j.command {
                Command::Open(o) => ("开通通道", o.intent.valid_through_height),
                Command::ReserveChallengeFee(_) => ("锁定挑战储备", u128::MAX),
                Command::Close { fee, .. } => ("申请关闭", fee.intent.valid_through_height),
                Command::Challenge { fee, .. } => ("提交挑战", fee.intent.valid_through_height),
                Command::Finalize { .. } => ("通道结算", u128::MAX),
                Command::Export(e) => ("跨区导出", e.intent.valid_through_height),
                Command::Transfer(_) => unreachable!(),
            };
            let included = selected_commands.get(&id).copied();
            let mut record = json!({"id":id,"kind":kind,"height":included.map(|h|h.to_string()),"status":if included.is_some(){"已纳入选定链"}else if c.height()>=expiry{"已过期"}else{"未确认，可原样重试"},"confirmed":included.is_some()});
            if let Command::Export(e) = &j.command {
                let export = e.intent.id().map_err(|e| anyhow!(e))?;
                let ready = c
                    .state()
                    .export_record(export)
                    .is_some_and(|r| c.finalized().is_some_and(|(_, h)| h >= r.export_height));
                record["export_id"] = json!(export);
                record["bundle_ready"] = json!(ready);
                record["locked_amount"] = json!(chain::format(e.intent.amount.0));
                record["destination_completed"] = json!(false);
                if self.replay.fresh && now()?.saturating_sub(self.replay.checked_at) <= 30 {
                    if let (Some(d), Some(returned)) = (
                        self.destination.as_mut(),
                        self.saved
                            .products
                            .returns
                            .iter()
                            .find(|r| r.bundle.export_id == export),
                    ) {
                        if let Ok(observation) =
                            d.verify_receipt(c, &returned.bundle, &returned.receipt)
                        {
                            record["destination_completed"] = json!(true);
                            record["destination_observation"] = observation;
                        }
                    }
                }
            }
            commands.push(record);
        }
        history.reverse();
        history.truncate(100);
        Ok(
            json!({"test_only":true,"has_monetary_value":false,"mainnet_authorized":false,"test_fixture":cfg!(test),"created":owner.is_some(),"destination":self.destination.as_ref().map(|d|d.status(&self.saved.destination_journal,owner)).transpose()?,"address":owner.map(|p|address::encode(&self.saved.chain_id,p)).transpose()?,"public_key":owner,"external_signer":self.saved.external_public.is_some(),"retired":self.saved.retired,"products":product::status(&self.saved.products,c,owner)?,"unlocked":self.secret.is_some(),"backup_verified":self.saved.backup_verified,"write_failed":self.write_failed,"fresh":!self.saved.retired&&!self.write_failed&&self.replay.fresh&&now()?.saturating_sub(self.replay.checked_at)<=30,"checked_at":self.replay.checked_at,"sync_error":self.replay.error,"height":c.height().to_string(),"tip":c.tip(),"state_root":c.state().root().map_err(|e|anyhow!(e))?,"chain_id":self.saved.chain_id,"spendable":chain::format(spendable),"immature":chain::format(immature),"reserved":chain::format(reserved),"history":history,"commands":commands,"scope":"Earth 普通转账余额；通道与跨区锁定金额另列。"}),
        )
    }
    async fn action(&mut self, mut r: Request) -> Result<Value> {
        self.expire();
        let password = Zeroizing::new(std::mem::take(&mut r.password));
        if r.action.starts_with("product_") {
            ensure!(
                !self.write_failed && !self.saved.retired,
                "钱包已停用或磁盘写入失败"
            );
            return self.product_action(r).await;
        }
        ensure!(
            !self.saved.retired
                || matches!(
                    r.action.as_str(),
                    "lock" | "backup" | "full_backup" | "refresh"
                ),
            "此设备已停用签名；请在新的数据目录恢复迁移备份"
        );
        if !matches!(r.action.as_str(), "lock" | "backup" | "refresh") {
            ensure!(
                !self.write_failed,
                "磁盘保存失败后已暂停操作；请保留整个数据目录并重启核验"
            );
        }
        match r.action.as_str() {
            "create" => {
                ensure!(self.saved.owner().is_none(), "已有钱包；不能覆盖");
                let v = vault::Vault::create(&password)?;
                self.saved.vault = Some(v);
                self.persist()?;
                Ok(json!({"ok":true}))
            }
            "restore" => {
                ensure!(
                    self.saved.owner().is_none(),
                    "已有钱包；请使用新的数据目录恢复"
                );
                let v = r.backup.ok_or_else(|| anyhow!("请选择加密备份"))?;
                let _secret = v.unlock(&password)?;
                self.saved.vault = Some(v);
                self.saved.backup_verified = true;
                self.persist()?;
                Ok(json!({"ok":true}))
            }
            "external_wallet" => {
                ensure!(self.saved.owner().is_none(), "已有钱包；不能覆盖");
                let public = address::decode(
                    &self.saved.chain_id,
                    &r.to.ok_or_else(|| anyhow!("请输入外部签名器公钥"))?,
                )?;
                self.saved.external_public = Some(public);
                self.persist()?;
                Ok(json!({"ok":true}))
            }
            "full_backup" | "handoff" => {
                ensure!(self.saved.owner().is_some(), "请先创建钱包");
                // Prepare a portable snapshot before retiring this instance. Deliver it
                // only after retirement is durably saved; an uncertain write fails closed.
                let mut portable = self.saved.clone();
                if r.action == "handoff" {
                    portable.retired = false;
                }
                let snapshot = snapshot::Snapshot::seal(&portable, &password)?;
                if r.action == "handoff" {
                    ensure!(!self.saved.retired, "此设备已经停用");
                    self.saved.retired = true;
                    self.secret = None;
                    self.draft = None;
                    self.product_draft = None;
                    self.persist()?;
                }
                Ok(json!({"snapshot":snapshot,"retired":self.saved.retired}))
            }
            "restore_full" => {
                ensure!(
                    self.saved.owner().is_none(),
                    "已有钱包；请使用新的数据目录恢复"
                );
                let snapshot = r.snapshot.ok_or_else(|| anyhow!("请选择完整备份"))?;
                let mut restored = snapshot.open(&password, &self.saved.chain_id)?;
                restored.backup_verified = true;
                self.saved = restored;
                self.persist()?;
                Ok(json!({"ok":true,"retired":self.saved.retired}))
            }
            "verify_full" => {
                let restored = r
                    .snapshot
                    .ok_or_else(|| anyhow!("请选择完整备份"))?
                    .open(&password, &self.saved.chain_id)?;
                ensure!(
                    restored.owner() == self.saved.owner(),
                    "此备份属于另一个钱包"
                );
                // A key-only or old snapshot cannot certify current signing decisions.
                let mut current = self.saved.clone();
                current.backup_verified = false;
                let mut restored = restored;
                restored.backup_verified = false;
                ensure!(
                    serde_json::to_vec(&current)? == serde_json::to_vec(&restored)?,
                    "备份记录已过时；请重新下载当前完整备份"
                );
                self.saved.backup_verified = true;
                self.persist()?;
                Ok(json!({"ok":true}))
            }
            "backup" => Ok(
                json!({"backup":self.saved.vault.as_ref().ok_or_else(||anyhow!("请先创建钱包"))?}),
            ),
            "verify_backup" => {
                let v = r
                    .backup
                    .ok_or_else(|| anyhow!("请重新选择刚保存的备份文件"))?;
                let secret = v.unlock(&password)?;
                let current = self
                    .saved
                    .vault
                    .as_ref()
                    .ok_or_else(|| anyhow!("未创建钱包"))?;
                ensure!(v.public_key == current.public_key, "此备份属于另一个钱包");
                let proof = b"RLD-EARTH-BACKUP-RESTORE-CHECK";
                rld_core::verify_bytes(
                    &current.public_key,
                    proof,
                    &sign_bytes(&secret, proof).map_err(|e| anyhow!(e))?,
                )
                .map_err(|e| anyhow!(e))?;
                self.saved.backup_verified = true;
                self.persist()?;
                Ok(json!({"ok":true}))
            }
            "unlock" => {
                ensure!(!self.saved.retired, "迁移后原设备已停用签名");
                let v = self
                    .saved
                    .vault
                    .as_ref()
                    .ok_or_else(|| anyhow!("未创建钱包"))?;
                self.secret = Some(v.unlock(&password)?);
                self.unlocked_until = now()? + 300;
                Ok(json!({"ok":true}))
            }
            "lock" => {
                self.secret = None;
                self.draft = None;
                self.product_draft = None;
                Ok(json!({"ok":true}))
            }
            "refresh" => {
                self.replay.refresh().await?;
                self.status()
            }
            "prepare" => {
                ensure!(
                    self.secret.is_some() && self.saved.backup_verified,
                    "请先验证备份并解锁"
                );
                self.replay.refresh().await?;
                let owner = &self.saved.vault.as_ref().unwrap().public_key;
                let to = address::decode(
                    &self.saved.chain_id,
                    &r.to.ok_or_else(|| anyhow!("请填写收款地址"))?,
                )?;
                ensure!(owner != &to, "收款人与当前钱包相同；请使用余额整理操作");
                let amount = chain::amount(&r.amount.ok_or_else(|| anyhow!("请填写金额"))?)?;
                let fee = chain::amount(&r.fee.ok_or_else(|| anyhow!("请填写手续费"))?)?;
                let tx = chain::prepare(
                    self.replay.store.chain(),
                    owner,
                    &to,
                    amount,
                    fee,
                    &self.saved.journal,
                )?;
                ensure!(
                    tx.inputs.iter().all(|p| !product::reserved_inputs(
                        &self.saved.products,
                        self.replay.store.chain()
                    )
                    .contains(p)),
                    "交易输入已被通道邀请占用"
                );
                let id = random();
                self.product_draft = None;
                let response = json!({"draft":id,"recipient":to,"amount":chain::format(amount),"fee":chain::format(fee),"total":chain::format(amount+fee),"change":chain::format(tx.outputs.get(1).map(|o|o.amount.0).unwrap_or(0)),"expires_height":tx.valid_through_height.to_string()});
                self.draft = Some(Draft {
                    tx,
                    tip: self.replay.store.chain().tip().to_hex(),
                    created: now()?,
                    id,
                });
                Ok(response)
            }
            "send" => {
                ensure!(
                    self.secret.is_some() && self.saved.backup_verified,
                    "钱包已锁定或备份未验证"
                );
                self.replay.refresh().await?;
                self.expire();
                ensure!(self.secret.is_some(), "钱包已自动锁定，请重新解锁");
                let d = self.draft.take().ok_or_else(|| anyhow!("请重新预览交易"))?;
                ensure!(
                    r.draft.as_deref() == Some(&d.id) && now()?.saturating_sub(d.created) <= 120,
                    "交易预览已过期"
                );
                ensure!(
                    self.replay.store.chain().tip().to_hex() == d.tip,
                    "链状态已变化，请重新预览金额和输入"
                );
                let mut tx = d.tx;
                tx.signature = sign_bytes(
                    self.secret.as_ref().unwrap(),
                    &tx.signing_bytes().map_err(|e| anyhow!(e))?,
                )
                .map_err(|e| anyhow!(e))?;
                ensure!(
                    tx.inputs.iter().all(|p| !product::reserved_inputs(
                        &self.saved.products,
                        self.replay.store.chain()
                    )
                    .contains(p)),
                    "交易输入已被通道邀请占用"
                );
                let command = Command::Transfer(tx);
                let c = self.replay.store.chain();
                c.template(
                    self.saved.vault.as_ref().unwrap().public_key.clone(),
                    c.template_time(now()?).map_err(|e| anyhow!(e))?,
                    vec![command.clone()],
                )
                .map_err(|e| anyhow!(e))?;
                ensure!(self.saved.journal.len() < 10000, "交易记录已达上限");
                self.saved.journal.push(chain::Journal {
                    command: command.clone(),
                    created_at: now()?,
                });
                self.persist()?;
                self.submit(command).await
            }
            "retry" => {
                self.replay.refresh().await?;
                let id = r.transaction.ok_or_else(|| anyhow!("缺少交易编号"))?;
                let j = self
                    .saved
                    .journal
                    .iter()
                    .find(|j| {
                        command_id(&j.command)
                            .map(|h| h.to_hex() == id)
                            .unwrap_or(false)
                    })
                    .ok_or_else(|| anyhow!("找不到已签名交易"))?;
                self.submit(j.command.clone()).await
            }
            _ => Err(anyhow!("未知操作")),
        }
    }
    async fn submit(&mut self, command: Command) -> Result<Value> {
        let expected = command_id(&command).map_err(|e| anyhow!(e))?;
        let response = self
            .replay
            .http
            .post(format!("{}/v1/earth/commands", self.replay.node))
            .json(&command)
            .send()
            .await;
        // The journal was flushed before delivery. Every ambiguous outcome keeps the
        // exact signed command reserved and exposes retry, never a new signature.
        let mut response = match response {
            Ok(r) if r.status().is_success() => r,
            _ => {
                return Ok(
                    json!({"delivery":"unknown","message":"签名交易已保存，但节点尚未确认接收。请保留记录并原样重试；没有重复签名。"}),
                )
            }
        };
        let mut bytes = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(c)) => {
                    if bytes.len() + c.len() > 8192 {
                        return Ok(
                            json!({"delivery":"unknown","message":"节点回执过大；原交易已保留，可原样重试。"}),
                        );
                    }
                    bytes.extend_from_slice(&c);
                }
                Ok(None) => break,
                Err(_) => {
                    return Ok(
                        json!({"delivery":"unknown","message":"节点回执中断；原交易已保留，可原样重试。"}),
                    )
                }
            }
        }
        let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        if v["command"] != expected.to_hex()
            || v["status"] != "ADOPTED_EARTH_SUCCESSOR_V1"
            || v["confirmed"] != false
        {
            return Ok(json!({"delivery":"unknown","message":"节点回执不完整；原交易已保留。"}));
        }
        Ok(
            json!({"delivery":"accepted","message":"节点已接收，正在等待区块确认。这还不是最终结算。"}),
        )
    }
}
async fn capability(
    State(app): State<App>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if let Err(e) = auth(&app.origin, &app.token, request.headers()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":e.to_string()})),
        )
            .into_response();
    }
    if request
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|n| n > 34 * 1024 * 1024)
    {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({"error":"请求超出大小限制"})),
        )
            .into_response();
    }
    next.run(request).await
}
async fn api(State(app): State<App>, headers: HeaderMap, body: axum::body::Bytes) -> Response {
    if let Err(e) = auth(&app.origin, &app.token, &headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":e.to_string()})),
        )
            .into_response();
    }
    let r: Request = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"请求格式不正确"})),
            )
                .into_response()
        }
    };
    let result = app.wallet.lock().await.action(r).await;
    match result {
        Ok(v) => Json(v).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":e.to_string()})),
        )
            .into_response(),
    }
}
async fn status(State(app): State<App>, headers: HeaderMap) -> Response {
    if let Err(e) = auth(&app.origin, &app.token, &headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":e.to_string()})),
        )
            .into_response();
    }
    match app.wallet.lock().await.status() {
        Ok(v) => Json(v).into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"余额核验失败；暂停显示与发送，请检查节点日志。"})),
        )
            .into_response(),
    }
}
async fn page(State(app): State<App>, headers: HeaderMap) -> Response {
    if headers.get(header::HOST).and_then(|v| v.to_str().ok()) != app.origin.strip_prefix("http://")
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    Html(include_str!("../static/index.html")).into_response()
}
fn validate_saved(saved: &Saved) -> Result<()> {
    rld_core::AdmissionHash32::from_hex(&saved.chain_id).map_err(|e| anyhow!(e))?;
    ensure!(
        saved.vault.is_none() || saved.external_public.is_none(),
        "钱包不能同时含有本机和外部签名身份"
    );
    ensure!(
        saved.owner().is_some()
            || (!saved.backup_verified
                && saved.journal.is_empty()
                && saved.products.is_empty()
                && saved.destination_journal.is_empty()
                && !saved.retired),
        "空钱包含有异常记录"
    );
    if let Some(owner) = saved.owner() {
        rld_core::validate_ed25519_public_key(owner).map_err(|e| anyhow!(e))?;
    }
    ensure!(saved.journal.len() <= 10000, "交易记录超过容量");
    let mut seen = std::collections::BTreeSet::new();
    for j in &saved.journal {
        ensure!(
            seen.insert(command_id(&j.command).map_err(|e| anyhow!(e))?),
            "重复的签名记录"
        );
        product::verify_command(
            &j.command,
            saved.owner().ok_or_else(|| anyhow!("记录没有钱包身份"))?,
            &saved.chain_id,
        )?;
    }
    product::validate_book(&saved.products, saved.owner(), &saved.chain_id)?;
    ensure!(
        saved.destination_journal.len() <= 10000,
        "目的链记录超过容量"
    );
    let mut seen = std::collections::BTreeSet::new();
    for j in &saved.destination_journal {
        ensure!(
            seen.insert(destination::command_id(&j.command).map_err(|e| anyhow!(e))?),
            "目的链命令重复"
        );
        match &j.command {
            rld_value_successor::destination::pow::Command::FinalizedImport { bundle, .. } => {
                bundle.id().map_err(|e| anyhow!(e))?;
                ensure!(
                    bundle.source_chain_id.to_hex() == saved.chain_id,
                    "导入材料来自另一条源链"
                );
            }
            rld_value_successor::destination::pow::Command::Transfer(t) => {
                ensure!(
                    Some(t.owner.as_str()) == saved.owner()
                        && t.chain_id.to_hex() != saved.chain_id,
                    "目的链转账身份错误"
                );
                rld_core::verify_bytes(
                    &t.owner,
                    &t.signing_bytes().map_err(|e| anyhow!(e))?,
                    &t.signature,
                )
                .map_err(|e| anyhow!(e))?;
            }
            _ => return Err(anyhow!("仅支持已终局导入和目的链普通转账")),
        }
    }
    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    let a = Args::parse();
    ensure!(a.port > 1024, "请使用非特权端口");
    files::directory(&a.data)?;
    let lock = files::lock(&a.data.join("wallet.lock"))?;
    let path = a.data.join("wallet.json");
    let saved: Saved = if path.exists() {
        serde_json::from_slice(&files::read(&path, 16 * 1024 * 1024)?)?
    } else {
        Saved::default()
    };
    validate_saved(&saved)?;
    ensure!(saved.chain_id == CHAIN, "钱包记录属于另一条链");
    let replay = chain::Replay::open(
        &a.records,
        &a.data,
        &a.node,
        a.compatibility_authorization.as_deref(),
        a.accept_compatibility_authorization.as_deref(),
    )?;
    let destination = if let Some(path) = a.destination_config.as_ref() {
        Some(destination::Replay::open(
            path,
            &a.data,
            &replay,
            a.accept_destination_authorization.as_deref().unwrap(),
            a.destination_signer.as_deref().unwrap(),
        )?)
    } else {
        None
    };
    let app = App {
        wallet: Arc::new(Mutex::new(Wallet {
            saved,
            replay,
            destination,
            path,
            secret: None,
            unlocked_until: 0,
            draft: None,
            write_failed: false,
            product_draft: None,
            _lock: lock,
        })),
        token: random(),
        origin: format!("http://127.0.0.1:{}", a.port),
    };
    let background = app.clone();
    tokio::spawn(async move {
        loop {
            let mut w = background.wallet.lock().await;
            w.expire();
            if w.replay.refresh().await.is_ok() {
                let Wallet {
                    replay,
                    destination,
                    ..
                } = &mut *w;
                if let Some(d) = destination {
                    let _ = d.refresh(replay.store.chain(), &replay.http).await;
                }
            }
            drop(w);
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    });
    let router=Router::new().route("/",get(page)).route("/api/status",get(status)).route("/api",post(api).route_layer(axum::middleware::from_fn_with_state(app.clone(),capability))).layer(DefaultBodyLimit::max(34 * 1024 * 1024)).with_state(app.clone()).layer(axum::middleware::map_response(|mut response:Response|async move{let h=response.headers_mut();h.insert(header::CACHE_CONTROL,"no-store".parse().unwrap());h.insert("Referrer-Policy","no-referrer".parse().unwrap());h.insert("X-Content-Type-Options","nosniff".parse().unwrap());h.insert("Content-Security-Policy","default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'".parse().unwrap());response}));
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, a.port)).await?;
    println!("Open locally: {}/#{}", app.origin, app.token);
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
#[cfg(test)]
mod tests;
