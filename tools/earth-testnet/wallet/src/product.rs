//! Supplemental wallet flows. No consensus rules, production pins, or signing
//! domains are changed by this module.
use crate::{address, chain, random, Request, Wallet};
use anyhow::{anyhow, ensure, Result};
use rld_core::{sign_bytes, verify_bytes, AdmissionHash32 as Hash, Amount};
use rld_cross_region::value::{ExportCommand, ExportIntent};
use rld_fast_payments::{
    successor::{OpenChannel, OpenIntent},
    ChannelState, Funding, PaymentOffer, PaymentReceipt, Phase, SignedState,
};
use rld_pow::{Coin, OutPoint};
use rld_value_successor::{
    candidate_client::{loopback_origin, now},
    chain::{storage::command_id, CandidateChain, CandidateEscrowObservation, Command},
    signed_state_hash,
    watchtower::{WatchAck, WatchPackage, WatchedReceipt, EARTH_STATUS},
    ActionFee, ActionFeeIntent, ChallengeFeeReserve, ChallengeFeeReserveIntent, DisputeAction,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

fn err(e: impl std::fmt::Display) -> anyhow::Error {
    anyhow!(e.to_string())
}
fn hash(s: &str) -> Result<Hash> {
    Hash::from_hex(s).map_err(err)
}
fn field<'a>(s: &'a Option<String>, name: &str) -> Result<&'a str> {
    s.as_deref().ok_or_else(|| anyhow!("请填写{name}"))
}
fn parse<T: serde::de::DeserializeOwned>(r: &Request) -> Result<T> {
    Ok(serde_json::from_value(
        r.packet.clone().ok_or_else(|| anyhow!("请选择交换文件"))?,
    )?)
}

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Book {
    #[serde(default)]
    pub returns: Vec<ReturnRecord>,
    pub invitations: Vec<OpenChannel>,
    pub channels: Vec<Channel>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReturnRecord {
    pub bundle: rld_cross_region::ProofBundle,
    pub receipt: rld_value_successor::destination::pow::receipt::ImportInclusionReceipt,
    pub verified_at: u64,
}
impl Book {
    pub fn is_empty(&self) -> bool {
        self.invitations.is_empty() && self.channels.is_empty() && self.returns.is_empty()
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Channel {
    pub funding: Funding,
    pub opening: OpenChannel,
    pub initial: SignedState,
    pub latest: SignedState,
    pub watcher: Option<String>,
    pub watch_url: Option<String>,
    pub protection: Option<WatchPackage>,
    pub ack: Option<WatchAck>,
    pub pending_offer: Option<PaymentOffer>,
    pub pending_receive: Option<PaymentReceipt>,
    pub receipts: Vec<WatchedReceipt>,
}
impl Channel {
    fn id(&self) -> Result<Hash> {
        self.funding.id().map_err(err)
    }
    fn new(open: &OpenChannel) -> Result<Self> {
        let funding = open.intent.funding().map_err(err)?;
        open.initial.verify(&funding).map_err(err)?;
        Ok(Self {
            funding,
            opening: open.clone(),
            initial: open.initial.clone(),
            latest: open.initial.clone(),
            watcher: None,
            watch_url: None,
            protection: None,
            ack: None,
            pending_offer: None,
            pending_receive: None,
            receipts: vec![],
        })
    }
}
pub enum Work {
    Command(Command),
    Destination(rld_value_successor::destination::pow::Command),
    Invite(OpenChannel),
    Accept(OpenChannel),
    Offer {
        channel: Hash,
        amount: Amount,
        payment: Hash,
    },
    Receive {
        channel: Hash,
        offer: PaymentOffer,
    },
    Protect {
        channel: Hash,
        watcher: String,
        url: String,
        intent: ActionFeeIntent,
    },
}
pub struct Draft {
    pub work: Work,
    pub tip: Hash,
    pub destination_tip: Option<Hash>,
    pub created: u64,
    pub id: String,
}

pub fn command_message(command: &Command, owner: &str) -> Result<Option<Vec<u8>>> {
    let (chain, public, bytes) = match command {
        Command::Transfer(t) => (t.chain_id, &t.owner, t.signing_bytes().map_err(err)?),
        Command::Open(o) => (
            o.intent.chain_id,
            &o.intent.party_a,
            o.intent.signing_bytes().map_err(err)?,
        ),
        Command::ReserveChallengeFee(r) => (
            r.intent.chain_id,
            &r.intent.owner,
            r.intent.signing_bytes().map_err(err)?,
        ),
        Command::Close { fee, .. } | Command::Challenge { fee, .. } => (
            fee.intent.chain_id,
            &fee.intent.owner,
            fee.intent.signing_bytes().map_err(err)?,
        ),
        Command::Export(e) => (
            e.intent.source_chain_id,
            &e.intent.owner,
            e.intent.signing_bytes().map_err(err)?,
        ),
        Command::Finalize { .. } => return Ok(None),
    };
    ensure!(
        public == owner && !chain.is_zero(),
        "命令签名身份不属于当前钱包"
    );
    Ok(Some(bytes))
}
pub fn verify_command(command: &Command, owner: &str, chain: &str) -> Result<()> {
    let expected = hash(chain)?;
    let (id, sig) = match command {
        Command::Transfer(t) => (t.chain_id, Some(&t.signature)),
        Command::Open(o) => {
            ensure!(
                o.initial.state
                    == ChannelState::initial(&o.intent.funding().map_err(err)?).map_err(err)?,
                "开通初始状态不正确"
            );
            o.initial
                .verify(&o.intent.funding().map_err(err)?)
                .map_err(err)?;
            (o.intent.chain_id, Some(&o.signature_a))
        }
        Command::ReserveChallengeFee(r) => (r.intent.chain_id, Some(&r.owner_signature)),
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
            ensure!(
                *channel == fee.intent.channel
                    && signed_state_hash(state).map_err(err)? == fee.intent.signed_state,
                "争议命令未绑定通道状态"
            );
            ensure!(
                fee.intent.action
                    == if matches!(command, Command::Close { .. }) {
                        DisputeAction::Close
                    } else {
                        DisputeAction::Challenge
                    },
                "争议动作不匹配"
            );
            (fee.intent.chain_id, Some(&fee.owner_signature))
        }
        Command::Export(e) => (e.intent.source_chain_id, Some(&e.owner_signature)),
        Command::Finalize { .. } => return Ok(()),
    };
    ensure!(id == expected, "命令属于另一条链");
    verify_bytes(
        owner,
        &command_message(command, owner)?.unwrap(),
        sig.unwrap(),
    )
    .map_err(err)
}
pub fn validate_book(book: &Book, owner: Option<&str>, chain: &str) -> Result<()> {
    ensure!(
        book.channels.len() <= 1000 && book.invitations.len() <= 1000,
        "通道记录超过容量"
    );
    ensure!(book.returns.len() <= 10000, "返回证明超过容量");
    let mut returned = std::collections::BTreeSet::new();
    for record in &book.returns {
        ensure!(
            record.bundle.source_chain_id.to_hex() == chain
                && record.receipt.source_chain_id.to_hex() == chain
                && record.receipt.export_id == record.bundle.export_id
                && record.receipt.bundle_id == record.bundle.id().map_err(err)?
                && returned.insert(record.bundle.export_id),
            "返回证明身份或编号不一致"
        );
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut inputs = std::collections::BTreeSet::new();
    for open in &book.invitations {
        ensure!(
            Some(open.intent.party_a.as_str()) == owner && open.intent.chain_id == hash(chain)?,
            "邀请身份错误"
        );
        ensure!(
            inputs.insert(open.intent.id().map_err(err)?),
            "通道邀请编号重复"
        );
        let f = open.intent.funding().map_err(err)?;
        ensure!(
            open.initial.state == ChannelState::initial(&f).map_err(err)?,
            "邀请必须从初始状态开始"
        );
        verify_bytes(
            &f.party_a,
            &open.intent.signing_bytes().map_err(err)?,
            &open.signature_a,
        )
        .map_err(err)?;
        verify_bytes(
            &f.party_a,
            &open.initial.state.signing_bytes(&f).map_err(err)?,
            &open.initial.signature_a,
        )
        .map_err(err)?;
        ensure!(
            open.initial.signature_b.is_empty(),
            "本机邀请含有意外的对方签名"
        );
    }
    let mut receipt_count = 0;
    for c in &book.channels {
        ensure!(
            ids.insert(c.id()?)
                && c.funding.chain_id == hash(chain)?
                && (Some(c.funding.party_a.as_str()) == owner
                    || Some(c.funding.party_b.as_str()) == owner),
            "重复通道或不属于当前钱包"
        );
        ensure!(
            c.opening.intent.funding().map_err(err)? == c.funding && c.opening.initial == c.initial,
            "通道开通记录不匹配"
        );
        verify_command(&Command::Open(c.opening.clone()), &c.funding.party_a, chain)?;
        c.initial.verify(&c.funding).map_err(err)?;
        ensure!(
            c.initial.state == ChannelState::initial(&c.funding).map_err(err)?,
            "通道初始分配不正确"
        );
        let mut latest = c.initial.clone();
        let mut payments = std::collections::BTreeSet::new();
        for w in &c.receipts {
            ensure!(
                payments.insert(w.receipt.payment_id) && w.receipt.previous == latest,
                "通道回执顺序不连续或付款编号重复"
            );
            w.verify(
                &c.funding,
                &w.receipt.sender,
                c.watcher
                    .as_deref()
                    .ok_or_else(|| anyhow!("回执没有固定守护者身份"))?,
            )
            .map_err(err)?;
            ensure!(
                w.live_rld && w.status == EARTH_STATUS,
                "本机钱包不能接受模拟回执"
            );
            latest = w.receipt.updated.clone();
            receipt_count += 1;
        }
        if let Some(p) = &c.pending_receive {
            ensure!(
                p.previous == latest && !payments.contains(&p.payment_id),
                "待守护回执与本机记录不一致"
            );
            p.verify(&c.funding, owner.unwrap()).map_err(err)?;
            latest = p.updated.clone();
        }
        ensure!(c.latest == latest, "通道最新状态缺少连续签名记录");
        if let Some(p) = &c.pending_offer {
            ensure!(
                c.pending_receive.is_none()
                    && p.previous == c.latest
                    && Some(p.sender.as_str()) == owner
                    && !payments.contains(&p.payment_id),
                "待付款记录错误"
            );
            p.verify(&c.funding).map_err(err)?;
        }
        if let Some(p) = &c.protection {
            p.validate().map_err(err)?;
            ensure!(
                p.funding == c.funding && p.state == c.latest,
                "守护包没有绑定最新状态"
            );
            if let Some(a) = &c.ack {
                a.verify(
                    p,
                    c.watcher
                        .as_deref()
                        .ok_or_else(|| anyhow!("缺少守护者公钥"))?,
                )
                .map_err(err)?;
                ensure!(a.live_rld, "模拟守护回执不能用于真实付款");
            }
        } else {
            ensure!(c.ack.is_none(), "守护确认缺少守护包");
        }
        if let Some(u) = &c.watch_url {
            ensure!(
                loopback_origin(u).map_err(err)? == *u,
                "守护服务必须为固定本机地址"
            );
        }
    }
    ensure!(receipt_count <= 10000, "通道回执超过容量");
    Ok(())
}
pub fn reserved_inputs(book: &Book, c: &CandidateChain) -> Vec<OutPoint> {
    book.invitations
        .iter()
        .filter(|o| {
            c.height() < o.intent.valid_through_height && c.state().coin(&o.intent.input).is_some()
        })
        .map(|o| o.intent.input.clone())
        .collect()
}
fn select(w: &Wallet, owner: &str, amount: u128) -> Result<(OutPoint, Coin)> {
    let c = w.replay.store.chain();
    let mut held = chain::reserved(c, &w.saved.journal)?;
    held.extend(reserved_inputs(&w.saved.products, c));
    chain::coins(c)?
        .into_iter()
        .filter(|(p, x)| {
            x.output.owner == owner
                && x.spendable_height <= c.height()
                && !held.contains(p)
                && x.output.amount.0 >= amount
        })
        .min_by_key(|(_, x)| x.output.amount.0)
        .ok_or_else(|| anyhow!("需要一个足额、成熟且未占用的输入；可先进行余额整理"))
}
fn get(book: &Book, id: Hash) -> Result<&Channel> {
    book.channels
        .iter()
        .find(|c| c.id().ok() == Some(id))
        .ok_or_else(|| anyhow!("本机没有此通道记录"))
}
fn get_mut(book: &mut Book, id: Hash) -> Result<&mut Channel> {
    book.channels
        .iter_mut()
        .find(|c| c.id().ok() == Some(id))
        .ok_or_else(|| anyhow!("本机没有此通道记录"))
}
fn ready(c: &CandidateChain, p: &WatchPackage, receiver: &str) -> Result<()> {
    p.validate().map_err(err)?;
    ensure!(p.fee.intent.owner == receiver, "守护费用不属于收款方");
    let f = &p.fee.intent;
    CandidateEscrowObservation::new_finalized(c, 2)
        .map_err(err)?
        .verify_payment_readiness(
            &p.funding,
            receiver,
            &f.input,
            f.fee.checked_add(f.change).map_err(err)?,
            f.fee,
            f.valid_through_height,
        )
        .map_err(err)
}
fn initial_open(o: &OpenChannel, c: &CandidateChain, owner: &str, peer: bool) -> Result<()> {
    let f = o.intent.funding().map_err(err)?;
    ensure!(
        o.intent.chain_id == c.chain_id() && (if peer { &f.party_b } else { &f.party_a }) == owner,
        "通道邀请不属于当前链或钱包"
    );
    ensure!(
        o.initial.state == ChannelState::initial(&f).map_err(err)?
            && c.height() < o.intent.valid_through_height,
        "邀请状态错误或已经过期"
    );
    let coin = c
        .state()
        .coin(&o.intent.input)
        .ok_or_else(|| anyhow!("邀请输入已不存在"))?;
    ensure!(
        coin.output.owner == f.party_a
            && coin.spendable_height <= c.height()
            && coin.output.amount.0
                == o.intent
                    .capacity
                    .0
                    .checked_add(o.intent.opening_fee.0)
                    .and_then(|x| x.checked_add(o.intent.change.0))
                    .ok_or_else(|| anyhow!("金额溢出"))?,
        "邀请资金不匹配或未成熟"
    );
    verify_bytes(
        &f.party_a,
        &o.intent.signing_bytes().map_err(err)?,
        &o.signature_a,
    )
    .map_err(err)?;
    verify_bytes(
        &f.party_a,
        &o.initial.state.signing_bytes(&f).map_err(err)?,
        &o.initial.signature_a,
    )
    .map_err(err)
}
pub fn status(book: &Book, c: &CandidateChain, owner: Option<&str>) -> Result<Value> {
    let mut channels = vec![];
    for b in &book.channels {
        let id = b.id()?;
        let escrow = c.state().escrow(id);
        let (phase, deadline) = match escrow.map(|e| &e.phase) {
            None => ("等待链上开通", None),
            Some(Phase::Open) => ("已开通", None),
            Some(Phase::Closing {
                deadline_height, ..
            }) => ("争议保护期", Some(deadline_height.to_string())),
            Some(Phase::Settled) => ("已结算", None),
        };
        channels.push(json!({"id":id,"peer":if Some(b.funding.party_a.as_str())==owner{&b.funding.party_b}else{&b.funding.party_a},"balance":chain::format(if Some(b.funding.party_a.as_str())==owner{b.latest.state.balance_a.0}else{b.latest.state.balance_b.0}),"sequence":b.latest.state.sequence,"phase":phase,"deadline":deadline,"pending":b.pending_offer.is_some()||b.pending_receive.is_some(),"watcher":b.watcher,"guard_ack":b.ack.as_ref().map(|a|a.sequence),"guard_is_point_in_time":true,"receipts":b.receipts.len()}));
    }
    let mut reserves = book
        .channels
        .iter()
        .flat_map(|b| {
            let inputs = b
                .receipts
                .iter()
                .map(|w| w.watch_package.fee.intent.input.clone())
                .chain(b.protection.iter().map(|p| p.fee.intent.input.clone()));
            inputs.collect::<Vec<_>>()
        })
        .collect::<std::collections::BTreeSet<_>>();
    for block in c.best_blocks().map_err(err)? {
        for command in block.commands {
            if let Command::ReserveChallengeFee(r) = command {
                if Some(r.intent.owner.as_str()) == owner {
                    reserves.insert(r.intent.input);
                }
            }
        }
    }
    let fee_reserves=reserves.into_iter().filter_map(|p|c.state().reserved_challenge_fee(&p).filter(|x|Some(x.coin.output.owner.as_str())==owner).map(|x|json!({"input":p,"amount":chain::format(x.coin.output.amount.0),"channel":x.channel}))).collect::<Vec<_>>();
    Ok(
        json!({"fee_reserves":fee_reserves,"channels":channels,"invitations":book.invitations.iter().map(|o|json!({"id":o.intent.id().ok(),"peer":o.intent.party_b,"expires":o.intent.valid_through_height.to_string(),"packet":o})).collect::<Vec<_>>() }),
    )
}
impl Wallet {
    fn product_owner(&self) -> Result<String> {
        self.saved
            .owner()
            .map(str::to_owned)
            .ok_or_else(|| anyhow!("请先创建钱包"))
    }
    fn active_signer(&self) -> Result<&str> {
        ensure!(
            self.saved.backup_verified && !self.saved.retired && !self.write_failed,
            "请先验证备份；停用或磁盘故障时禁止签名"
        );
        self.secret
            .as_deref()
            .map(|s| s.as_str())
            .ok_or_else(|| anyhow!("请先解锁钱包"))
    }
    fn journal_command(&mut self, command: Command) -> Result<()> {
        let c = self.replay.store.chain();
        let owner = self.product_owner()?;
        verify_command(&command, &owner, &c.chain_id().to_hex())?;
        c.template(
            owner,
            c.template_time(now()?).map_err(err)?,
            vec![command.clone()],
        )
        .map_err(err)?;
        let id = command_id(&command).map_err(err)?;
        ensure!(
            !self
                .saved
                .journal
                .iter()
                .any(|j| command_id(&j.command).ok() == Some(id)),
            "该签名交易已有记录，请原样重试"
        );
        self.saved.journal.push(chain::Journal {
            command,
            created_at: now()?,
        });
        self.persist()
    }
    async fn watcher_ack(
        &self,
        package: &WatchPackage,
        url: &str,
        public: &str,
    ) -> Result<WatchAck> {
        ensure!(
            loopback_origin(url).map_err(err)? == url,
            "守护服务必须使用本机地址"
        );
        let mut response = self
            .replay
            .http
            .post(format!("{url}/v1/earth-watchtower/packages"))
            .json(package)
            .send()
            .await?
            .error_for_status()?;
        let mut bytes = Vec::new();
        while let Some(b) = response.chunk().await? {
            ensure!(bytes.len() + b.len() <= 8192, "守护回执超过限制");
            bytes.extend(b);
        }
        let ack: WatchAck = serde_json::from_slice(&bytes)?;
        ack.verify(package, public).map_err(err)?;
        ensure!(
            ack.live_rld && ack.status == EARTH_STATUS,
            "守护服务未确认正式链模式"
        );
        Ok(ack)
    }
    async fn refresh_destination(&mut self) -> Result<()> {
        self.replay.refresh().await?;
        self.destination
            .as_mut()
            .ok_or_else(|| anyhow!("启动时尚未配置并接受目的链原始授权"))?
            .refresh(self.replay.store.chain(), &self.replay.http)
            .await
    }
    async fn submit_destination(
        &mut self,
        command: rld_value_successor::destination::pow::Command,
    ) -> Result<Value> {
        let d = self
            .destination
            .as_ref()
            .ok_or_else(|| anyhow!("未配置目的链"))?;
        let id = crate::destination::command_id(&command)?;
        let response = self
            .replay
            .http
            .post(format!("{}/v1/earth-destination/commands", d.node))
            .json(&command)
            .send()
            .await;
        let accepted = if let Ok(mut response) = response {
            if response.status().is_success() {
                if let Ok(bytes) = crate::destination::bounded(&mut response, 8192).await {
                    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                    v["command"] == id.to_hex()
                        && v["live_rld"] == true
                        && v["status"] == EARTH_STATUS
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };
        Ok(
            json!({"delivery":if accepted{"accepted"}else{"unknown"},"message":if accepted{"目的链节点已接收原命令；尚未完成确认、成熟或返回证明。"}else{"已保存原始导入命令，网络结果不确定；可原样重试。"}}),
        )
    }
    pub async fn product_action(&mut self, r: Request) -> Result<Value> {
        let owner = self.product_owner()?;
        match r.action.as_str() {
            "product_packet" => {
                let id = hash(field(&r.channel, "通道编号")?)?;
                let b = get(&self.saved.products, id)?;
                if let Some(p) = &b.pending_offer {
                    return Ok(
                        json!({"packet":p,"message":"已保存的原始付款提议；未收到完整受保护回执前不算付款完成。"}),
                    );
                }
                if let Some(p) = &b.pending_receive {
                    return Ok(
                        json!({"packet":p,"message":"仅本机已签名待守护记录；尚未提供完整付款回执。"}),
                    );
                }
                let packet = if let Some(w) = b.receipts.last() {
                    json!(w)
                } else if let (Some(p), Some(a)) = (&b.protection, &b.ack) {
                    json!({"package":p,"ack":a,"watcher":b.watcher})
                } else {
                    json!(b.opening)
                };
                Ok(json!({"packet":packet,"message":"已取出本机保存的原始交换文件。"}))
            }
            "product_import_receipt" => {
                let w: WatchedReceipt = parse(&r)?;
                let id = w.watch_package.funding.id().map_err(err)?;
                let b = get(&self.saved.products, id)?;
                let watcher = b
                    .watcher
                    .as_deref()
                    .ok_or_else(|| anyhow!("请先固定并核验守护者身份"))?;
                w.verify(&b.funding, &owner, watcher).map_err(err)?;
                ensure!(w.live_rld, "不能导入模拟付款回执");
                if b.receipts.iter().any(|x| x == &w) {
                    return Ok(json!({"ok":true,"message":"回执已经保存，没有重复扣款。"}));
                }
                let p = b
                    .pending_offer
                    .as_ref()
                    .ok_or_else(|| anyhow!("没有对应的待付款提议"))?;
                ensure!(
                    p.proposed == w.receipt.updated.state
                        && p.previous == w.receipt.previous
                        && p.payment_id == w.receipt.payment_id
                        && p.amount == w.receipt.amount,
                    "回执与本机已签名付款不匹配"
                );
                self.replay.refresh().await?;
                ready(
                    self.replay.store.chain(),
                    &w.watch_package,
                    &w.watch_package.fee.intent.owner,
                )?;
                let b = get_mut(&mut self.saved.products, id)?;
                b.latest = w.receipt.updated.clone();
                b.protection = Some(w.watch_package.clone());
                b.ack = Some(w.watch_ack.clone());
                b.receipts.push(w);
                b.pending_offer = None;
                self.persist()?;
                Ok(
                    json!({"ok":true,"message":"完整受保护回执已核验并保存；通道最终结算仍需链上保护期。"}),
                )
            }
            "product_import_protection" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Packet {
                    package: WatchPackage,
                    ack: WatchAck,
                    watcher: String,
                }
                let p: Packet = parse(&r)?;
                let id = p.package.funding.id().map_err(err)?;
                let b = get(&self.saved.products, id)?;
                ensure!(
                    b.latest == p.package.state && b.funding == p.package.funding,
                    "守护交换文件不是此通道的最新状态"
                );
                if let Some(key) = &b.watcher {
                    ensure!(key == &p.watcher, "不能替换已固定的守护者身份");
                }
                p.ack.verify(&p.package, &p.watcher).map_err(err)?;
                ensure!(p.ack.live_rld, "不能导入模拟守护回执");
                self.replay.refresh().await?;
                ready(
                    self.replay.store.chain(),
                    &p.package,
                    &p.package.fee.intent.owner,
                )?;
                let b = get_mut(&mut self.saved.products, id)?;
                b.watcher = Some(p.watcher);
                b.protection = Some(p.package);
                b.ack = Some(p.ack);
                self.persist()?;
                Ok(
                    json!({"ok":true,"message":"已固定守护者公钥并核验当前费用储备；请通过可信渠道核对这个公钥。"}),
                )
            }
            "product_destination_retry" => {
                self.refresh_destination().await?;
                let id = hash(field(&r.transaction, "目的链命令编号")?)?;
                let command = self
                    .saved
                    .destination_journal
                    .iter()
                    .find(|j| crate::destination::command_id(&j.command).ok() == Some(id))
                    .ok_or_else(|| anyhow!("找不到原始目的链命令"))?
                    .command
                    .clone();
                self.submit_destination(command).await
            }
            "product_return_receipt" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Packet {
                    bundle: rld_cross_region::ProofBundle,
                    receipt: rld_value_successor::destination::pow::receipt::ImportInclusionReceipt,
                }
                let p: Packet = parse(&r)?;
                self.refresh_destination().await?;
                ensure!(self.saved.journal.iter().any(|j|matches!(&j.command,Command::Export(e) if e.intent.id().ok()==Some(p.bundle.export_id))),"不是本机导出的返回证明");
                let observed = self.destination.as_mut().unwrap().verify_receipt(
                    self.replay.store.chain(),
                    &p.bundle,
                    &p.receipt,
                )?;
                if let Some(old) = self
                    .saved
                    .products
                    .returns
                    .iter()
                    .find(|x| x.bundle.export_id == p.bundle.export_id)
                {
                    ensure!(
                        old.bundle == p.bundle && old.receipt == p.receipt,
                        "不能用另一份返回证明替换原记录"
                    );
                } else {
                    self.saved.products.returns.push(ReturnRecord {
                        bundle: p.bundle,
                        receipt: p.receipt,
                        verified_at: now()?,
                    });
                    self.persist()?;
                }
                Ok(
                    json!({"observation":observed,"message":"返回证明已按本机源链和目的链重放核验；目的链终局仍是概率性的，源链资产仍保持导出锁定。"}),
                )
            }
            "product_destination_receipt" => {
                self.refresh_destination().await?;
                let id = hash(field(&r.transaction, "目的链命令编号")?)?;
                let command = &self
                    .saved
                    .destination_journal
                    .iter()
                    .find(|j| crate::destination::command_id(&j.command).ok() == Some(id))
                    .ok_or_else(|| anyhow!("找不到已保存的导入命令"))?
                    .command;
                let rld_value_successor::destination::pow::Command::FinalizedImport {
                    bundle, ..
                } = command
                else {
                    return Err(anyhow!("不是导入命令"));
                };
                let d = self.destination.as_mut().unwrap();
                let policy = d.policy();
                let receipt = d
                    .store
                    .observe_import(self.replay.store.chain(), bundle, &policy)
                    .map_err(err)?;
                Ok(
                    json!({"packet":{"bundle":bundle,"receipt":receipt},"message":"本机完整重放核验的导入包含证明；请把文件交还源链付款方核验。目的链仍可能重组。"}),
                )
            }
            "product_export_bundle" => {
                self.replay.refresh().await?;
                let id = hash(field(&r.transaction, "导出编号")?)?;
                ensure!(
                    self.saved.journal.iter().any(
                        |j| matches!(&j.command,Command::Export(e) if e.intent.id().ok()==Some(id))
                    ),
                    "不是本机保存的导出记录"
                );
                if let Some(j)=self.saved.destination_journal.iter().find(|j|matches!(&j.command,rld_value_successor::destination::pow::Command::FinalizedImport{bundle,..} if bundle.export_id==id)) {return Ok(json!({"packet":j.command,"message":"已取出原始目的链导入材料；源链资产仍保持锁定。"}));}
                let certificate = self
                    .replay
                    .store
                    .finality()
                    .ok_or_else(|| anyhow!("导出还没有已签名的源链终局证明"))?
                    .clone();
                let bundle = self
                    .replay
                    .store
                    .chain()
                    .export_bundle(id, certificate.statement.block)
                    .map_err(err)?;
                let command = rld_value_successor::destination::pow::Command::FinalizedImport {
                    bundle,
                    certificate,
                };
                self.saved
                    .destination_journal
                    .push(crate::destination::Journal {
                        command: command.clone(),
                        created_at: now()?,
                    });
                self.persist()?;
                Ok(
                    json!({"packet":command,"message":"原始导入材料已落盘。源链导出仍然锁定，收到目的链有效证明前不能视为跨区完成。"}),
                )
            }
            "product_prepare" => {
                ensure!(self.saved.backup_verified, "请先验证当前钱包备份");
                ensure!(
                    self.secret.is_some()
                        || self.saved.external_public.is_some()
                        || matches!(
                            r.kind.as_deref(),
                            Some("challenge" | "finalize" | "destination_import")
                        ),
                    "请先解锁钱包"
                );
                self.replay.refresh().await?;
                let c = self.replay.store.chain();
                let kind = field(&r.kind, "操作类型")?;
                let expires = c
                    .height()
                    .checked_add(12)
                    .ok_or_else(|| anyhow!("高度溢出"))?;
                let mut signing = None;
                let (work, review) = match kind {
                    "destination_transfer" => {
                        self.refresh_destination().await?;
                        let d = self.destination.as_ref().unwrap();
                        let to = address::decode(
                            &d.store.chain().chain_id().to_hex(),
                            field(&r.to, "目的链收款地址")?,
                        )?;
                        let amount = chain::amount(field(&r.amount, "金额")?)?;
                        let fee = chain::amount(field(&r.fee, "手续费")?)?;
                        let t = crate::destination::prepare(
                            d.store.chain(),
                            &owner,
                            &to,
                            amount,
                            fee,
                            &self.saved.destination_journal,
                        )?;
                        let review = json!({"操作":"目的链普通转账","收款人":to,"金额":chain::format(amount),"手续费":chain::format(fee),"有效至":t.valid_through_height.to_string(),"说明":"目的链余额与源链余额分开；签名后先落盘再提交，确认仍可能重组。"});
                        (
                            Work::Destination(
                                rld_value_successor::destination::pow::Command::Transfer(t),
                            ),
                            review,
                        )
                    }
                    "destination_import" => {
                        let command: rld_value_successor::destination::pow::Command = parse(&r)?;
                        let rld_value_successor::destination::pow::Command::FinalizedImport {
                            bundle,
                            ..
                        } = &command
                        else {
                            return Err(anyhow!("只接受带源链终局证明的导入"));
                        };
                        let export_record = self
                            .replay
                            .store
                            .chain()
                            .state()
                            .export_record(bundle.export_id)
                            .ok_or_else(|| anyhow!("本机源链没有此导出记录"))?;
                        let amount = export_record.command.intent.amount;
                        let recipient = export_record.command.intent.recipient.clone();
                        let export = bundle.export_id;
                        self.refresh_destination().await?;
                        let d = self.destination.as_mut().unwrap();
                        let source = self.replay.store.chain();
                        d.store
                            .template(
                                source,
                                owner.clone(),
                                d.store.chain().template_time(now()?).map_err(err)?,
                                vec![command.clone()],
                            )
                            .map_err(err)?;
                        let review = json!({"操作":"提交已终局源链导入","源链导出":export,"目的链":d.store.chain().chain_id(),"收款人":recipient,"金额":chain::format(amount.0),"说明":"本机重放与原始授权已核验。节点接收后还需目的链确认、导入成熟和返回证明。"});
                        (Work::Destination(command), review)
                    }
                    "consolidate" => {
                        let fee = chain::amount(field(&r.fee, "手续费")?)?;
                        ensure!(fee > 0, "手续费必须大于零");
                        let mut held = chain::reserved(c, &self.saved.journal)?;
                        held.extend(reserved_inputs(&self.saved.products, c));
                        let selected = chain::coins(c)?
                            .into_iter()
                            .filter(|(p, x)| {
                                x.output.owner == owner
                                    && x.spendable_height <= c.height()
                                    && !held.contains(p)
                            })
                            .take(32)
                            .collect::<Vec<_>>();
                        ensure!(selected.len() > 1, "至少需要两个成熟且未占用的输入才能合并");
                        let total = selected.iter().try_fold(0u128, |s, (_, x)| {
                            s.checked_add(x.output.amount.0)
                                .ok_or_else(|| anyhow!("余额溢出"))
                        })?;
                        ensure!(total > fee, "合并金额不足以支付手续费");
                        let t = rld_pow::Transfer {
                            chain_id: c.chain_id(),
                            owner: owner.clone(),
                            inputs: selected.iter().map(|(p, _)| p.clone()).collect(),
                            outputs: vec![rld_pow::Output {
                                owner: owner.clone(),
                                amount: Amount(total - fee),
                            }],
                            fee: Amount(fee),
                            valid_through_height: expires,
                            signature: String::new(),
                        };
                        (
                            Work::Command(Command::Transfer(t)),
                            json!({"操作":"合并本机余额输入","输入数量":selected.len(),"合并后金额":chain::format(total-fee),"手续费":chain::format(fee),"收款人":owner}),
                        )
                    }
                    "split" | "transfer" => {
                        let to = if kind == "split" {
                            owner.clone()
                        } else {
                            address::decode(&self.saved.chain_id, field(&r.to, "收款地址")?)?
                        };
                        ensure!(
                            kind == "split" || to != owner,
                            "请使用拆分余额操作给自己的钱包分配小额输入"
                        );
                        let value = chain::amount(field(&r.amount, "金额")?)?;
                        let fee = chain::amount(field(&r.fee, "手续费")?)?;
                        let t = chain::prepare(c, &owner, &to, value, fee, &self.saved.journal)?;
                        ensure!(
                            t.inputs
                                .iter()
                                .all(|p| !reserved_inputs(&self.saved.products, c).contains(p)),
                            "输入已被通道邀请占用；请等待邀请失效或资金确认"
                        );
                        (
                            Work::Command(Command::Transfer(t.clone())),
                            json!({"操作":if kind=="split"{"拆分本机余额输入"}else{"普通转账"},"收款人":to,"金额":chain::format(value),"手续费":chain::format(fee),"找零":chain::format(t.outputs.get(1).map(|o|o.amount.0).unwrap_or(0)),"有效至":expires.to_string()}),
                        )
                    }
                    "open" => {
                        let peer =
                            address::decode(&self.saved.chain_id, field(&r.peer, "对方地址")?)?;
                        let capacity = chain::amount(field(&r.amount, "通道总额")?)?;
                        let fee = chain::amount(field(&r.fee, "开通费")?)?;
                        let close_fee = chain::amount(field(&r.close_fee, "结算费")?)?;
                        let total = capacity
                            .checked_add(fee)
                            .ok_or_else(|| anyhow!("金额溢出"))?;
                        let (input, coin) = select(self, &owner, total)?;
                        let intent = OpenIntent {
                            chain_id: c.chain_id(),
                            input,
                            party_a: owner.clone(),
                            party_b: peer.clone(),
                            capacity: Amount(capacity),
                            close_fee: Amount(close_fee),
                            opening_fee: Amount(fee),
                            change: Amount(coin.output.amount.0 - total),
                            valid_through_height: expires,
                        };
                        let initial = SignedState {
                            state: ChannelState::initial(&intent.funding().map_err(err)?)
                                .map_err(err)?,
                            signature_a: String::new(),
                            signature_b: String::new(),
                        };
                        (
                            Work::Invite(OpenChannel {
                                intent,
                                signature_a: String::new(),
                                initial,
                            }),
                            json!({"操作":"签署通道邀请","对方":peer,"存入":chain::format(capacity),"开通费":chain::format(fee),"结算预留费":chain::format(close_fee),"有效至":expires.to_string(),"说明":"先保存并发送邀请，对方签署初始分配后才能广播开通；邀请将占用该输入。"}),
                        )
                    }
                    "accept" => {
                        let o: OpenChannel = parse(&r)?;
                        initial_open(&o, c, &owner, true)?;
                        ensure!(o.initial.signature_b.is_empty(), "邀请已含对方签名");
                        (
                            Work::Accept(o.clone()),
                            json!({"操作":"接受通道邀请","出资人":o.intent.party_a,"容量":chain::format(o.intent.capacity.0),"你的初始余额":"0","结算费":chain::format(o.intent.close_fee.0),"有效至":o.intent.valid_through_height.to_string()}),
                        )
                    }
                    "fund" => {
                        let o: OpenChannel = parse(&r)?;
                        initial_open(&o, c, &owner, false)?;
                        o.initial
                            .verify(&o.intent.funding().map_err(err)?)
                            .map_err(err)?;
                        ensure!(
                            self.saved
                                .products
                                .invitations
                                .iter()
                                .any(|i| i.intent == o.intent
                                    && i.signature_a == o.signature_a
                                    && i.initial.state == o.initial.state
                                    && i.initial.signature_a == o.initial.signature_a),
                            "签署文件不对应本机保存的原始邀请"
                        );
                        (
                            Work::Command(Command::Open(o.clone())),
                            json!({"操作":"广播开通通道","对方":o.intent.party_b,"存入":chain::format(o.intent.capacity.0),"开通费":chain::format(o.intent.opening_fee.0),"说明":"双签初始分配已核验；区块开通并终局之后才能进行受保护支付。"}),
                        )
                    }
                    "export" => {
                        let destination = hash(field(&r.destination, "目的链 ID")?)?;
                        let to = address::decode(
                            &destination.to_hex(),
                            field(&r.to, "目的链收款地址")?,
                        )?;
                        let amount = chain::amount(field(&r.amount, "导出金额")?)?;
                        let fee = chain::amount(field(&r.fee, "源链手续费")?)?;
                        let df = chain::amount(field(&r.destination_fee, "目的链手续费")?)?;
                        let total = amount.checked_add(fee).ok_or_else(|| anyhow!("金额溢出"))?;
                        let (input, coin) = select(self, &owner, total)?;
                        let intent = ExportIntent {
                            source_chain_id: c.chain_id(),
                            destination_chain_id: destination,
                            input,
                            owner: owner.clone(),
                            recipient: to.clone(),
                            amount: Amount(amount),
                            source_fee: Amount(fee),
                            destination_fee: Amount(df),
                            change: Amount(coin.output.amount.0 - total),
                            valid_through_height: expires,
                        };
                        intent.signing_bytes().map_err(err)?;
                        (
                            Work::Command(Command::Export(ExportCommand {
                                intent,
                                owner_signature: String::new(),
                            })),
                            json!({"操作":"锁定源链并导出","目的链":destination,"收款人":to,"导出金额":chain::format(amount),"源链费":chain::format(fee),"目的链费":chain::format(df),"目的链净额":chain::format(amount-df),"说明":"导出没有因超时或回执缺失而自动退款的规则。需要源链终局证明、目的链导入与返回证明。"}),
                        )
                    }
                    "reserve" | "close" | "challenge" | "finalize" | "protect" | "offer"
                    | "receive" => {
                        let id = hash(field(&r.channel, "通道编号")?)?;
                        let b = get(&self.saved.products, id)?;
                        let e = c
                            .state()
                            .escrow(id)
                            .ok_or_else(|| anyhow!("通道尚未在本机选定链上开通"))?;
                        ensure!(e.funding == b.funding, "链上通道与本机身份不一致");
                        match kind {
                            "reserve" => {
                                ensure!(matches!(e.phase, Phase::Open), "当前通道不处于开通状态");
                                let minimum = chain::amount(field(&r.fee, "储备金额下限")?)?;
                                ensure!(minimum > 0, "储备金额必须大于零");
                                let (input, coin) = select(self, &owner, minimum)?;
                                (
                                    Work::Command(Command::ReserveChallengeFee(
                                        ChallengeFeeReserve {
                                            intent: ChallengeFeeReserveIntent {
                                                chain_id: c.chain_id(),
                                                channel: id,
                                                input,
                                                owner: owner.clone(),
                                            },
                                            owner_signature: String::new(),
                                        },
                                    )),
                                    json!({"操作":"锁定挑战费用储备","通道":id,"实际锁定整个输入":chain::format(coin.output.amount.0),"说明":"整枚输入锁定至通道结算，不能作为普通余额重复花费。"}),
                                )
                            }
                            "finalize" => {
                                let Phase::Closing {
                                    deadline_height,
                                    ref best,
                                    ..
                                } = e.phase
                                else {
                                    return Err(anyhow!("通道尚未开始关闭"));
                                };
                                ensure!(c.height() > deadline_height, "保护期还未结束");
                                ensure!(
                                    b.latest == *best
                                        && b.pending_offer.is_none()
                                        && b.pending_receive.is_none(),
                                    "本机持有不同或待完成状态；禁止结算旧分配，请先核验和挑战"
                                );
                                (
                                    Work::Command(Command::Finalize { channel: id }),
                                    json!({"操作":"结算通道","通道":id,"保护期截止":deadline_height.to_string(),"说明":"依据链上已确认的最佳状态分配；未确认新的回执应先挑战。"}),
                                )
                            }
                            "close" | "challenge" => {
                                ensure!(
                                    b.pending_offer.is_none()
                                        && (kind == "challenge" || b.pending_receive.is_none()),
                                    "有未完成付款，请先原样恢复或完成守护确认"
                                );
                                if let Phase::Closing { best, .. } = &e.phase {
                                    ensure!(
                                        b.latest.state.sequence >= best.state.sequence,
                                        "链上已存在更新状态；禁止用旧状态继续关闭"
                                    );
                                }
                                let protected = if kind == "challenge" {
                                    b.protection.as_ref().filter(|p| {
                                        p.state == b.latest && p.fee.intent.owner == owner
                                    })
                                } else {
                                    None
                                };
                                let af = if let Some(p) = protected {
                                    p.validate().map_err(err)?;
                                    p.fee.clone()
                                } else {
                                    let fee = chain::amount(field(&r.fee, "动作手续费")?)?;
                                    let (input, coin) = select(self, &owner, fee)?;
                                    ActionFee {
                                        intent: ActionFeeIntent {
                                            chain_id: c.chain_id(),
                                            action: if kind == "close" {
                                                DisputeAction::Close
                                            } else {
                                                DisputeAction::Challenge
                                            },
                                            channel: id,
                                            signed_state: signed_state_hash(&b.latest)
                                                .map_err(err)?,
                                            input,
                                            owner: owner.clone(),
                                            fee: Amount(fee),
                                            change: Amount(coin.output.amount.0 - fee),
                                            valid_through_height: expires,
                                        },
                                        owner_signature: String::new(),
                                    }
                                };
                                let fee = af.intent.fee.0;
                                let cmd = if kind == "close" {
                                    Command::Close {
                                        channel: id,
                                        state: b.latest.clone(),
                                        fee: af,
                                    }
                                } else {
                                    Command::Challenge {
                                        channel: id,
                                        state: b.latest.clone(),
                                        fee: af,
                                    }
                                };
                                (
                                    Work::Command(cmd),
                                    json!({"操作":if kind=="close"{"申请关闭"}else{"提交较新状态挑战"},"通道":id,"状态序号":b.latest.state.sequence,"动作手续费":chain::format(fee),"说明":"关闭仍保留原协议完整的 2016 区块保护期。"}),
                                )
                            }
                            "protect" => {
                                let watcher = field(&r.watcher, "守护者公钥")?.to_owned();
                                rld_core::validate_ed25519_public_key(&watcher).map_err(err)?;
                                if let Some(key) = &b.watcher {
                                    ensure!(key == &watcher, "禁止替换已固定的守护者身份");
                                }
                                let url = loopback_origin(field(&r.watch_url, "守护者本机地址")?)
                                    .map_err(err)?;
                                let input = r
                                    .input
                                    .clone()
                                    .ok_or_else(|| anyhow!("请选择已确认的费用储备输入"))?;
                                let reserve = c
                                    .state()
                                    .reserved_challenge_fee(&input)
                                    .ok_or_else(|| anyhow!("输入不是链上费用储备"))?;
                                let fee = chain::amount(field(&r.fee, "挑战手续费")?)?;
                                ensure!(
                                    fee > 0
                                        && reserve.coin.output.amount.0 >= fee
                                        && reserve.coin.output.owner == owner,
                                    "费用储备金额或身份错误"
                                );
                                let intent = ActionFeeIntent {
                                    chain_id: c.chain_id(),
                                    action: DisputeAction::Challenge,
                                    channel: id,
                                    signed_state: signed_state_hash(&b.latest).map_err(err)?,
                                    input,
                                    owner: owner.clone(),
                                    fee: Amount(fee),
                                    change: Amount(reserve.coin.output.amount.0 - fee),
                                    valid_through_height: u128::MAX,
                                };
                                CandidateEscrowObservation::new_finalized(c, 2)
                                    .map_err(err)?
                                    .verify_payment_readiness(
                                        &b.funding,
                                        &owner,
                                        &intent.input,
                                        reserve.coin.output.amount,
                                        Amount(fee),
                                        u128::MAX,
                                    )
                                    .map_err(err)?;
                                (
                                    Work::Protect {
                                        channel: id,
                                        watcher: watcher.clone(),
                                        url: url.clone(),
                                        intent,
                                    },
                                    json!({"操作":"授权守护最新通道状态","通道":id,"序号":b.latest.state.sequence,"守护者":watcher,"服务":url,"挑战手续费":chain::format(fee),"说明":"授权只针对此状态的挑战，持续有效；服务保存签名确认后才可收款。"}),
                                )
                            }
                            "offer" => {
                                ensure!(
                                    b.pending_offer.is_none() && b.pending_receive.is_none(),
                                    "请先完成或原样重试上一笔付款"
                                );
                                let p = b
                                    .protection
                                    .as_ref()
                                    .ok_or_else(|| anyhow!("请先导入收款方完整守护证明"))?;
                                let ack = b.ack.as_ref().ok_or_else(|| anyhow!("缺少守护确认"))?;
                                ack.verify(p, b.watcher.as_deref().unwrap_or(""))
                                    .map_err(err)?;
                                let receiver = if owner == b.funding.party_a {
                                    &b.funding.party_b
                                } else {
                                    &b.funding.party_a
                                };
                                ready(c, p, receiver)?;
                                let amount = Amount(chain::amount(field(&r.amount, "付款金额")?)?);
                                let payment = hash(&random())?;
                                b.latest
                                    .state
                                    .propose_payment(&b.funding, &owner, amount, payment)
                                    .map_err(err)?;
                                (
                                    Work::Offer {
                                        channel: id,
                                        amount,
                                        payment,
                                    },
                                    json!({"操作":"签署通道付款提议","收款人":receiver,"金额":chain::format(amount.0),"付款编号":payment,"说明":"会先保存签名决策。对方完成双签和守护确认后才形成完整回执。"}),
                                )
                            }
                            _ => {
                                let offer: PaymentOffer = parse(&r)?;
                                offer.verify(&b.funding).map_err(err)?;
                                ensure!(
                                    offer.sender != owner && b.pending_offer.is_none(),
                                    "不能接受自己发送的付款，或本机已有待付款"
                                );
                                if let Some(old) = b
                                    .receipts
                                    .iter()
                                    .find(|w| w.receipt.payment_id == offer.payment_id)
                                {
                                    ensure!(
                                        old.receipt.previous == offer.previous
                                            && old.receipt.updated.state == offer.proposed
                                            && old.receipt.sender == offer.sender
                                            && old.receipt.amount == offer.amount,
                                        "付款编号重复但内容不同"
                                    );
                                    return Ok(
                                        json!({"packet":old,"message":"原回执已保存；没有重复签名或重复入账。"}),
                                    );
                                }
                                if let Some(p) = &b.pending_receive {
                                    ensure!(
                                        p.previous == offer.previous
                                            && p.updated.state == offer.proposed
                                            && p.payment_id == offer.payment_id,
                                        "上一笔待守护付款尚未完成"
                                    );
                                } else {
                                    ensure!(
                                        offer.previous == b.latest,
                                        "付款不是本机最新状态的下一笔"
                                    );
                                }
                                let p = b
                                    .protection
                                    .as_ref()
                                    .ok_or_else(|| anyhow!("请先配置并确认自己的守护储备"))?;
                                ready(c, p, &owner)?;
                                (
                                    Work::Receive {
                                        channel: id,
                                        offer: offer.clone(),
                                    },
                                    json!({"操作":"接收通道付款并提交守护","付款人":offer.sender,"金额":chain::format(offer.amount.0),"付款编号":offer.payment_id,"说明":"守护服务未确认时只保存待守护记录，禁止继续签署下一笔。"}),
                                )
                            }
                        }
                    }
                    _ => return Err(anyhow!("不支持的产品操作")),
                };
                if self.saved.external_public.is_some() {
                    if let Work::Destination(
                        rld_value_successor::destination::pow::Command::Transfer(t),
                    ) = &work
                    {
                        signing = Some(
                            json!({"algorithm":"Ed25519","public_key":owner,"message_hex":hex::encode(t.signing_bytes().map_err(err)?),"command":t,"chain_id":t.chain_id,"tip":self.destination.as_ref().unwrap().store.chain().tip(),"review":review}),
                        );
                    } else if matches!(work, Work::Destination(_)) {
                    } else if let Work::Command(cmd) = &work {
                        ensure!(
                            !matches!(cmd, Command::Open(_)),
                            "双重开通签名请使用本机钱包流程；外部签名器适配尚待设备验收"
                        );
                        signing=if matches!(cmd,Command::Challenge{fee,..} if !fee.owner_signature.is_empty()){None}else{command_message(cmd,&owner)?}.map(|b|json!({"algorithm":"Ed25519","public_key":owner,"message_hex":hex::encode(b),"command":cmd,"chain_id":self.replay.store.chain().chain_id(),"tip":self.replay.store.chain().tip(),"review":review}));
                    } else {
                        return Err(anyhow!(
                            "该通道交换操作需要本机密钥；外部设备仍需专用适配与验收"
                        ));
                    }
                }
                let id = random();
                self.draft = None;
                self.product_draft = Some(Draft {
                    destination_tip: if matches!(work, Work::Destination(_)) {
                        self.destination.as_ref().map(|d| d.store.chain().tip())
                    } else {
                        None
                    },
                    tip: self.replay.store.chain().tip(),
                    created: now()?,
                    work,
                    id: id.clone(),
                });
                Ok(json!({"draft":id,"review":review,"signing_request":signing}))
            }
            "product_confirm" => {
                ensure!(self.saved.backup_verified, "请先验证备份");
                self.replay.refresh().await?;
                self.expire();
                let d = self
                    .product_draft
                    .take()
                    .ok_or_else(|| anyhow!("请重新预览操作"))?;
                ensure!(
                    r.draft.as_deref() == Some(d.id.as_str())
                        && now()?.saturating_sub(d.created) <= 120
                        && self.replay.store.chain().tip() == d.tip,
                    "链状态或预览已变化，请重新核对"
                );
                let destination_tip = d.destination_tip;
                match d.work {
                    Work::Destination(mut command) => {
                        self.refresh_destination().await?;
                        ensure!(
                            destination_tip
                                == Some(self.destination.as_ref().unwrap().store.chain().tip()),
                            "目的链预览已变化，请重新核对"
                        );
                        if let rld_value_successor::destination::pow::Command::Transfer(t) =
                            &mut command
                        {
                            let bytes = t.signing_bytes().map_err(err)?;
                            t.signature = if self.saved.external_public.is_some() {
                                let sig = field(&r.signature, "外部签名")?.to_owned();
                                verify_bytes(&owner, &bytes, &sig).map_err(err)?;
                                sig
                            } else {
                                sign_bytes(self.active_signer()?, &bytes).map_err(err)?
                            };
                        }
                        let d = self.destination.as_mut().unwrap();
                        let source = self.replay.store.chain();
                        d.store
                            .template(
                                source,
                                owner,
                                d.store.chain().template_time(now()?).map_err(err)?,
                                vec![command.clone()],
                            )
                            .map_err(err)?;
                        let id = crate::destination::command_id(&command)?;
                        if !self
                            .saved
                            .destination_journal
                            .iter()
                            .any(|j| crate::destination::command_id(&j.command).ok() == Some(id))
                        {
                            self.saved
                                .destination_journal
                                .push(crate::destination::Journal {
                                    command: command.clone(),
                                    created_at: now()?,
                                });
                            self.persist()?;
                        }
                        self.submit_destination(command).await
                    }
                    Work::Command(mut command) => {
                        if self.saved.external_public.is_some()
                            && !matches!(&command,Command::Challenge{fee,..} if !fee.owner_signature.is_empty())
                        {
                            if let Some(bytes) = command_message(&command, &owner)? {
                                let sig = field(&r.signature, "外部签名")?.to_owned();
                                verify_bytes(&owner, &bytes, &sig).map_err(err)?;
                                set_signature(&mut command, sig)?;
                            }
                        } else if !matches!(command, Command::Open(_) | Command::Finalize { .. })
                            && !matches!(&command,Command::Challenge{fee,..} if !fee.owner_signature.is_empty())
                        {
                            let bytes = command_message(&command, &owner)?.unwrap();
                            set_signature(
                                &mut command,
                                sign_bytes(self.active_signer()?, &bytes).map_err(err)?,
                            )?;
                        }
                        if let Command::Open(o) = &command {
                            let id = o.intent.funding().map_err(err)?.id().map_err(err)?;
                            if get(&self.saved.products, id).is_err() {
                                self.saved.products.channels.push(Channel::new(o)?);
                            }
                        }
                        self.journal_command(command.clone())?;
                        self.submit(command).await
                    }
                    Work::Invite(mut o) => {
                        let secret = self.active_signer()?;
                        o.signature_a = sign_bytes(secret, &o.intent.signing_bytes().map_err(err)?)
                            .map_err(err)?;
                        o.initial.signature_a = sign_bytes(
                            secret,
                            &o.initial
                                .state
                                .signing_bytes(&o.intent.funding().map_err(err)?)
                                .map_err(err)?,
                        )
                        .map_err(err)?;
                        self.saved.products.invitations.push(o.clone());
                        self.persist()?;
                        Ok(
                            json!({"packet":o,"message":"原始邀请已保存；请发送给对方，收到初始分配双签文件后再广播开通。"}),
                        )
                    }
                    Work::Accept(mut o) => {
                        o.initial.signature_b = sign_bytes(
                            self.active_signer()?,
                            &o.initial
                                .state
                                .signing_bytes(&o.intent.funding().map_err(err)?)
                                .map_err(err)?,
                        )
                        .map_err(err)?;
                        let id = o.intent.funding().map_err(err)?.id().map_err(err)?;
                        ensure!(
                            get(&self.saved.products, id).is_err(),
                            "已保存此邀请；请使用原文件而不是重复签名"
                        );
                        self.saved.products.channels.push(Channel::new(&o)?);
                        self.persist()?;
                        Ok(
                            json!({"packet":o,"message":"已保存双签初始状态。请将此文件交还出资方，开通后还需锁定挑战储备并接入守护。"}),
                        )
                    }
                    Work::Protect {
                        channel,
                        watcher,
                        url,
                        intent,
                    } => {
                        let fee = ActionFee {
                            owner_signature: sign_bytes(
                                self.active_signer()?,
                                &intent.signing_bytes().map_err(err)?,
                            )
                            .map_err(err)?,
                            intent,
                        };
                        let b = get_mut(&mut self.saved.products, channel)?;
                        let p = WatchPackage {
                            funding: b.funding.clone(),
                            state: b.latest.clone(),
                            fee,
                        };
                        p.validate().map_err(err)?;
                        b.watcher = Some(watcher.clone());
                        b.watch_url = Some(url.clone());
                        b.protection = Some(p.clone());
                        b.ack = None;
                        self.persist()?;
                        let ack = self.watcher_ack(&p, &url, &watcher).await?;
                        get_mut(&mut self.saved.products, channel)?.ack = Some(ack.clone());
                        self.persist()?;
                        Ok(
                            json!({"packet":{"package":p,"ack":ack,"watcher":watcher},"message":"守护服务已签署保存确认；请将完整交换文件交给付款人核验。"}),
                        )
                    }
                    Work::Offer {
                        channel,
                        amount,
                        payment,
                    } => {
                        let b = get(&self.saved.products, channel)?;
                        let offer = PaymentOffer::new(
                            &b.funding,
                            b.latest.clone(),
                            owner,
                            self.active_signer()?,
                            amount,
                            payment,
                        )
                        .map_err(err)?;
                        get_mut(&mut self.saved.products, channel)?.pending_offer =
                            Some(offer.clone());
                        self.persist()?;
                        Ok(
                            json!({"packet":offer,"message":"付款提议已保存。可重复发送此原文件，禁止在完整回执到达前签署下一笔。"}),
                        )
                    }
                    Work::Receive { channel, offer } => {
                        let b = get(&self.saved.products, channel)?;
                        let receipt = if let Some(p) = &b.pending_receive {
                            p.clone()
                        } else {
                            offer
                                .cosign(&b.funding, self.active_signer()?)
                                .map_err(err)?
                        };
                        let mut package = b
                            .protection
                            .clone()
                            .ok_or_else(|| anyhow!("缺少自己的守护配置"))?;
                        let url = b
                            .watch_url
                            .clone()
                            .ok_or_else(|| anyhow!("缺少守护服务地址"))?;
                        let watcher = b.watcher.clone().ok_or_else(|| anyhow!("缺少守护者身份"))?;
                        if b.pending_receive.is_none() {
                            package.state = receipt.updated.clone();
                            package.fee.intent.signed_state =
                                signed_state_hash(&package.state).map_err(err)?;
                            package.fee.owner_signature = sign_bytes(
                                self.active_signer()?,
                                &package.fee.intent.signing_bytes().map_err(err)?,
                            )
                            .map_err(err)?;
                        }
                        let b = get_mut(&mut self.saved.products, channel)?;
                        b.latest = receipt.updated.clone();
                        b.pending_receive = Some(receipt.clone());
                        b.protection = Some(package.clone());
                        b.ack = None;
                        self.persist()?;
                        let ack = self.watcher_ack(&package, &url, &watcher).await?;
                        let w = WatchedReceipt {
                            status: EARTH_STATUS.into(),
                            live_rld: true,
                            receipt,
                            watch_package: package,
                            watch_ack: ack,
                        };
                        w.verify(&w.watch_package.funding, &w.receipt.sender, &watcher)
                            .map_err(err)?;
                        let b = get_mut(&mut self.saved.products, channel)?;
                        b.ack = Some(w.watch_ack.clone());
                        b.pending_receive = None;
                        b.receipts.push(w.clone());
                        self.persist()?;
                        Ok(
                            json!({"packet":w,"message":"双签付款与守护保存证明已经核验并落盘。请把完整回执发送给付款人。"}),
                        )
                    }
                }
            }
            "product_retry_watch" => {
                let id = hash(field(&r.channel, "通道编号")?)?;
                let b = get(&self.saved.products, id)?;
                let p = b
                    .protection
                    .clone()
                    .ok_or_else(|| anyhow!("没有待守护包"))?;
                let public = b.watcher.clone().ok_or_else(|| anyhow!("缺少守护者身份"))?;
                let url = b.watch_url.clone().ok_or_else(|| anyhow!("缺少守护地址"))?;
                self.replay.refresh().await?;
                ready(self.replay.store.chain(), &p, &owner)?;
                let ack = self.watcher_ack(&p, &url, &public).await?;
                let b = get_mut(&mut self.saved.products, id)?;
                b.ack = Some(ack.clone());
                let packet = if let Some(receipt) = b.pending_receive.take() {
                    let w = WatchedReceipt {
                        status: EARTH_STATUS.into(),
                        live_rld: true,
                        receipt,
                        watch_package: p,
                        watch_ack: ack,
                    };
                    w.verify(&b.funding, &w.receipt.sender, &public)
                        .map_err(err)?;
                    b.receipts.push(w.clone());
                    json!(w)
                } else {
                    json!({"package":p,"ack":ack,"watcher":public})
                };
                self.persist()?;
                Ok(json!({"packet":packet,"message":"已原样重试守护包并保存确认，没有重新签名。"}))
            }
            _ => Err(anyhow!("未知产品操作")),
        }
    }
}
fn set_signature(command: &mut Command, sig: String) -> Result<()> {
    match command {
        Command::Transfer(t) => t.signature = sig,
        Command::ReserveChallengeFee(r) => r.owner_signature = sig,
        Command::Close { fee, .. } | Command::Challenge { fee, .. } => fee.owner_signature = sig,
        Command::Export(e) => e.owner_signature = sig,
        _ => return Err(anyhow!("此命令不能用单份外部签名完成")),
    }
    Ok(())
}
