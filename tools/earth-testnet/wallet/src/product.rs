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
    s.as_deref().ok_or_else(|| anyhow!("Enter {name}"))
}
fn parse<T: serde::de::DeserializeOwned>(r: &Request) -> Result<T> {
    Ok(serde_json::from_value(
        r.packet.clone().ok_or_else(|| anyhow!("Select an exchange file"))?,
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
        "Command signing identity does not belong to this wallet"
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
                "Invalid initial opening state"
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
                "Dispute command does not bind the channel state"
            );
            ensure!(
                fee.intent.action
                    == if matches!(command, Command::Close { .. }) {
                        DisputeAction::Close
                    } else {
                        DisputeAction::Challenge
                    },
                "Dispute action does not match"
            );
            (fee.intent.chain_id, Some(&fee.owner_signature))
        }
        Command::Export(e) => (e.intent.source_chain_id, Some(&e.owner_signature)),
        Command::Finalize { .. } => return Ok(()),
    };
    ensure!(id == expected, "Command belongs to another chain");
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
        "Channel record capacity exceeded"
    );
    ensure!(book.returns.len() <= 10000, "Return proof capacity exceeded");
    let mut returned = std::collections::BTreeSet::new();
    for record in &book.returns {
        ensure!(
            record.bundle.source_chain_id.to_hex() == chain
                && record.receipt.source_chain_id.to_hex() == chain
                && record.receipt.export_id == record.bundle.export_id
                && record.receipt.bundle_id == record.bundle.id().map_err(err)?
                && returned.insert(record.bundle.export_id),
            "Return proof identity or identifier differs"
        );
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut inputs = std::collections::BTreeSet::new();
    for open in &book.invitations {
        ensure!(
            Some(open.intent.party_a.as_str()) == owner && open.intent.chain_id == hash(chain)?,
            "Invalid invitation identity"
        );
        ensure!(
            inputs.insert(open.intent.id().map_err(err)?),
            "Duplicate channel invitation identifier"
        );
        let f = open.intent.funding().map_err(err)?;
        ensure!(
            open.initial.state == ChannelState::initial(&f).map_err(err)?,
            "Invitation must start from the initial state"
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
            "Local invitation contains an unexpected peer signature"
        );
    }
    let mut receipt_count = 0;
    for c in &book.channels {
        ensure!(
            ids.insert(c.id()?)
                && c.funding.chain_id == hash(chain)?
                && (Some(c.funding.party_a.as_str()) == owner
                    || Some(c.funding.party_b.as_str()) == owner),
            "Duplicate channel or channel outside this wallet"
        );
        ensure!(
            c.opening.intent.funding().map_err(err)? == c.funding && c.opening.initial == c.initial,
            "Channel opening record differs"
        );
        verify_command(&Command::Open(c.opening.clone()), &c.funding.party_a, chain)?;
        c.initial.verify(&c.funding).map_err(err)?;
        ensure!(
            c.initial.state == ChannelState::initial(&c.funding).map_err(err)?,
            "Invalid initial channel allocation"
        );
        let mut latest = c.initial.clone();
        let mut payments = std::collections::BTreeSet::new();
        for w in &c.receipts {
            ensure!(
                payments.insert(w.receipt.payment_id) && w.receipt.previous == latest,
                "Channel receipt sequence is discontinuous or payment identifier is duplicated"
            );
            w.verify(
                &c.funding,
                &w.receipt.sender,
                c.watcher
                    .as_deref()
                    .ok_or_else(|| anyhow!("Receipt lacks a pinned watcher identity"))?,
            )
            .map_err(err)?;
            ensure!(
                w.live_rld && w.status == EARTH_STATUS,
                "Local wallet cannot accept simulated receipts"
            );
            latest = w.receipt.updated.clone();
            receipt_count += 1;
        }
        if let Some(p) = &c.pending_receive {
            ensure!(
                p.previous == latest && !payments.contains(&p.payment_id),
                "Pending watcher receipt differs from the local record"
            );
            p.verify(&c.funding, owner.unwrap()).map_err(err)?;
            latest = p.updated.clone();
        }
        ensure!(c.latest == latest, "Latest channel state lacks a continuous signed history");
        if let Some(p) = &c.pending_offer {
            ensure!(
                c.pending_receive.is_none()
                    && p.previous == c.latest
                    && Some(p.sender.as_str()) == owner
                    && !payments.contains(&p.payment_id),
                "Invalid pending payment record"
            );
            p.verify(&c.funding).map_err(err)?;
        }
        if let Some(p) = &c.protection {
            p.validate().map_err(err)?;
            ensure!(
                p.funding == c.funding && p.state == c.latest,
                "Watcher package does not bind the latest state"
            );
            if let Some(a) = &c.ack {
                a.verify(
                    p,
                    c.watcher
                        .as_deref()
                        .ok_or_else(|| anyhow!("Missing watcher public key"))?,
                )
                .map_err(err)?;
                ensure!(a.live_rld, "Simulated watcher receipts cannot authorize payments");
            }
        } else {
            ensure!(c.ack.is_none(), "Watcher confirmation lacks its package");
        }
        if let Some(u) = &c.watch_url {
            ensure!(
                loopback_origin(u).map_err(err)? == *u,
                "Watcher service must use a pinned loopback address"
            );
        }
    }
    ensure!(receipt_count <= 10000, "Channel receipt capacity exceeded");
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
        .ok_or_else(|| anyhow!("One sufficiently funded mature unreserved input is required; consolidate balances first"))
}
fn get(book: &Book, id: Hash) -> Result<&Channel> {
    book.channels
        .iter()
        .find(|c| c.id().ok() == Some(id))
        .ok_or_else(|| anyhow!("Channel record is absent from this device"))
}
fn get_mut(book: &mut Book, id: Hash) -> Result<&mut Channel> {
    book.channels
        .iter_mut()
        .find(|c| c.id().ok() == Some(id))
        .ok_or_else(|| anyhow!("Channel record is absent from this device"))
}
fn ready(c: &CandidateChain, p: &WatchPackage, receiver: &str) -> Result<()> {
    p.validate().map_err(err)?;
    ensure!(p.fee.intent.owner == receiver, "Watcher fee does not belong to the recipient");
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
        "Channel invitation belongs to another chain or wallet"
    );
    ensure!(
        o.initial.state == ChannelState::initial(&f).map_err(err)?
            && c.height() < o.intent.valid_through_height,
        "Invitation state is invalid or expired"
    );
    let coin = c
        .state()
        .coin(&o.intent.input)
        .ok_or_else(|| anyhow!("Invitation input no longer exists"))?;
    ensure!(
        coin.output.owner == f.party_a
            && coin.spendable_height <= c.height()
            && coin.output.amount.0
                == o.intent
                    .capacity
                    .0
                    .checked_add(o.intent.opening_fee.0)
                    .and_then(|x| x.checked_add(o.intent.change.0))
                    .ok_or_else(|| anyhow!("Amount overflow"))?,
        "Invitation funding differs or is immature"
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
            None => ("Waiting for on-chain opening", None),
            Some(Phase::Open) => ("Open", None),
            Some(Phase::Closing {
                deadline_height, ..
            }) => ("Dispute protection period", Some(deadline_height.to_string())),
            Some(Phase::Settled) => ("Settled", None),
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
            .ok_or_else(|| anyhow!("Create a wallet first"))
    }
    fn active_signer(&self) -> Result<&str> {
        ensure!(
            self.saved.backup_verified && !self.saved.retired && !self.write_failed,
            "Verify the backup first; signing is forbidden after deactivation or disk failure"
        );
        self.secret
            .as_deref()
            .map(|s| s.as_str())
            .ok_or_else(|| anyhow!("Unlock the wallet first"))
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
            "This signed transaction is already retained; retry the exact original"
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
            "Watcher service must use a loopback address"
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
            ensure!(bytes.len() + b.len() <= 8192, "Watcher receipt exceeds the limit");
            bytes.extend(b);
        }
        let ack: WatchAck = serde_json::from_slice(&bytes)?;
        ack.verify(package, public).map_err(err)?;
        ensure!(
            ack.live_rld && ack.status == EARTH_STATUS,
            "Watcher service has not confirmed the authenticated chain mode"
        );
        Ok(ack)
    }
    async fn refresh_destination(&mut self) -> Result<()> {
        self.replay.refresh().await?;
        self.destination
            .as_mut()
            .ok_or_else(|| anyhow!("Original destination authorization was not configured and accepted at startup"))?
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
            .ok_or_else(|| anyhow!("Destination chain is not configured"))?;
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
            json!({"delivery":if accepted{"accepted"}else{"unknown"},"message":if accepted{"Destination node received the original command; confirmation, maturity and return proof remain pending."}else{"Original import command retained; network outcome is unknown. Retry the exact original."}}),
        )
    }
    pub async fn product_action(&mut self, r: Request) -> Result<Value> {
        let owner = self.product_owner()?;
        match r.action.as_str() {
            "product_packet" => {
                let id = hash(field(&r.channel, "Channel identifier")?)?;
                let b = get(&self.saved.products, id)?;
                if let Some(p) = &b.pending_offer {
                    return Ok(
                        json!({"packet":p,"message":"Retained original payment proposal; payment remains incomplete until a complete protected receipt arrives."}),
                    );
                }
                if let Some(p) = &b.pending_receive {
                    return Ok(
                        json!({"packet":p,"message":"Only the local signed watcher-pending record is available; the complete payment receipt is absent."}),
                    );
                }
                let packet = if let Some(w) = b.receipts.last() {
                    json!(w)
                } else if let (Some(p), Some(a)) = (&b.protection, &b.ack) {
                    json!({"package":p,"ack":a,"watcher":b.watcher})
                } else {
                    json!(b.opening)
                };
                Ok(json!({"packet":packet,"message":"Retrieved the exact original exchange file retained locally."}))
            }
            "product_import_receipt" => {
                let w: WatchedReceipt = parse(&r)?;
                let id = w.watch_package.funding.id().map_err(err)?;
                let b = get(&self.saved.products, id)?;
                let watcher = b
                    .watcher
                    .as_deref()
                    .ok_or_else(|| anyhow!("Pin and verify the watcher identity first"))?;
                w.verify(&b.funding, &owner, watcher).map_err(err)?;
                ensure!(w.live_rld, "Simulated payment receipts cannot be imported");
                if b.receipts.iter().any(|x| x == &w) {
                    return Ok(json!({"ok":true,"message":"Receipt already retained; no duplicate debit."}));
                }
                let p = b
                    .pending_offer
                    .as_ref()
                    .ok_or_else(|| anyhow!("Matching pending payment proposal is absent"))?;
                ensure!(
                    p.proposed == w.receipt.updated.state
                        && p.previous == w.receipt.previous
                        && p.payment_id == w.receipt.payment_id
                        && p.amount == w.receipt.amount,
                    "Receipt differs from the locally signed payment"
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
                    json!({"ok":true,"message":"Complete protected receipt verified and retained; final channel settlement still requires the on-chain protection period."}),
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
                    "Watcher exchange file does not contain the latest channel state"
                );
                if let Some(key) = &b.watcher {
                    ensure!(key == &p.watcher, "A pinned watcher identity cannot be replaced");
                }
                p.ack.verify(&p.package, &p.watcher).map_err(err)?;
                ensure!(p.ack.live_rld, "Simulated watcher receipts cannot be imported");
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
                    json!({"ok":true,"message":"Watcher public key pinned and current fee reserve verified; confirm this public key through a trusted channel."}),
                )
            }
            "product_destination_retry" => {
                self.refresh_destination().await?;
                let id = hash(field(&r.transaction, "Destination command identifier")?)?;
                let command = self
                    .saved
                    .destination_journal
                    .iter()
                    .find(|j| crate::destination::command_id(&j.command).ok() == Some(id))
                    .ok_or_else(|| anyhow!("Original destination command is absent"))?
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
                ensure!(self.saved.journal.iter().any(|j|matches!(&j.command,Command::Export(e) if e.intent.id().ok()==Some(p.bundle.export_id))),"Return proof was not exported by this wallet");
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
                        "Another return proof cannot replace the original record"
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
                    json!({"observation":observed,"message":"Return proof verified by local source and destination replay; destination finality remains probabilistic and source assets remain export-locked."}),
                )
            }
            "product_destination_receipt" => {
                self.refresh_destination().await?;
                let id = hash(field(&r.transaction, "Destination command identifier")?)?;
                let command = &self
                    .saved
                    .destination_journal
                    .iter()
                    .find(|j| crate::destination::command_id(&j.command).ok() == Some(id))
                    .ok_or_else(|| anyhow!("Retained import command is absent"))?
                    .command;
                let rld_value_successor::destination::pow::Command::FinalizedImport {
                    bundle, ..
                } = command
                else {
                    return Err(anyhow!("Command is not an import"));
                };
                let d = self.destination.as_mut().unwrap();
                let policy = d.policy();
                let receipt = d
                    .store
                    .observe_import(self.replay.store.chain(), bundle, &policy)
                    .map_err(err)?;
                Ok(
                    json!({"packet":{"bundle":bundle,"receipt":receipt},"message":"Import inclusion proof verified by complete local replay; return the file to the source payer for verification. Destination reorganization remains possible."}),
                )
            }
            "product_export_bundle" => {
                self.replay.refresh().await?;
                let id = hash(field(&r.transaction, "Export identifier")?)?;
                ensure!(
                    self.saved.journal.iter().any(
                        |j| matches!(&j.command,Command::Export(e) if e.intent.id().ok()==Some(id))
                    ),
                    "Export record is not retained by this wallet"
                );
                if let Some(j)=self.saved.destination_journal.iter().find(|j|matches!(&j.command,rld_value_successor::destination::pow::Command::FinalizedImport{bundle,..} if bundle.export_id==id)) {return Ok(json!({"packet":j.command,"message":"Original destination import material retrieved; source assets remain locked."}));}
                let certificate = self
                    .replay
                    .store
                    .finality()
                    .ok_or_else(|| anyhow!("Export lacks a signed source-finality proof"))?
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
                    json!({"packet":command,"message":"Original import material is durable. Source export remains locked; cross-region completion requires a valid destination proof."}),
                )
            }
            "product_prepare" => {
                ensure!(self.saved.backup_verified, "Verify the current wallet backup first");
                ensure!(
                    self.secret.is_some()
                        || self.saved.external_public.is_some()
                        || matches!(
                            r.kind.as_deref(),
                            Some("challenge" | "finalize" | "destination_import")
                        ),
                    "Unlock the wallet first"
                );
                self.replay.refresh().await?;
                let c = self.replay.store.chain();
                let kind = field(&r.kind, "Action type")?;
                let expires = c
                    .height()
                    .checked_add(12)
                    .ok_or_else(|| anyhow!("Height overflow"))?;
                let mut signing = None;
                let (work, review) = match kind {
                    "destination_transfer" => {
                        self.refresh_destination().await?;
                        let d = self.destination.as_ref().unwrap();
                        let to = address::decode(
                            &d.store.chain().chain_id().to_hex(),
                            field(&r.to, "Destination recipient address")?,
                        )?;
                        let amount = chain::amount(field(&r.amount, "Amount")?)?;
                        let fee = chain::amount(field(&r.fee, "Fee")?)?;
                        let t = crate::destination::prepare(
                            d.store.chain(),
                            &owner,
                            &to,
                            amount,
                            fee,
                            &self.saved.destination_journal,
                        )?;
                        let review = json!({"Action":"Ordinary destination transfer","Recipient":to,"Amount":chain::format(amount),"Fee":chain::format(fee),"Valid until":t.valid_through_height.to_string(),"Description":"Destination and source balances are separate; signed commands become durable before submission. Confirmed history may still reorganize."});
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
                            return Err(anyhow!("Imports require a source-finality proof"));
                        };
                        let export_record = self
                            .replay
                            .store
                            .chain()
                            .state()
                            .export_record(bundle.export_id)
                            .ok_or_else(|| anyhow!("Export is absent from the locally replayed source chain"))?;
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
                        let review = json!({"Action":"Submit finalized source import","Source export":export,"Destination chain":d.store.chain().chain_id(),"Recipient":recipient,"Amount":chain::format(amount.0),"Description":"Local replay and original authorization verified. Node receipt still requires destination confirmation, import maturity and return proof."});
                        (Work::Destination(command), review)
                    }
                    "consolidate" => {
                        let fee = chain::amount(field(&r.fee, "Fee")?)?;
                        ensure!(fee > 0, "Fee must be positive");
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
                        ensure!(selected.len() > 1, "Consolidation requires at least two mature unreserved inputs");
                        let total = selected.iter().try_fold(0u128, |s, (_, x)| {
                            s.checked_add(x.output.amount.0)
                                .ok_or_else(|| anyhow!("Balance overflow"))
                        })?;
                        ensure!(total > fee, "Consolidated amount cannot cover the fee");
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
                            json!({"Action":"Consolidate local balance inputs","Input count":selected.len(),"Consolidated amount":chain::format(total-fee),"Fee":chain::format(fee),"Recipient":owner}),
                        )
                    }
                    "split" | "transfer" => {
                        let to = if kind == "split" {
                            owner.clone()
                        } else {
                            address::decode(&self.saved.chain_id, field(&r.to, "Recipient address")?)?
                        };
                        ensure!(
                            kind == "split" || to != owner,
                            "Use balance splitting to allocate smaller inputs to this wallet"
                        );
                        let value = chain::amount(field(&r.amount, "Amount")?)?;
                        let fee = chain::amount(field(&r.fee, "Fee")?)?;
                        let t = chain::prepare(c, &owner, &to, value, fee, &self.saved.journal)?;
                        ensure!(
                            t.inputs
                                .iter()
                                .all(|p| !reserved_inputs(&self.saved.products, c).contains(p)),
                            "Input is reserved by a channel invitation; wait for expiry or funding confirmation"
                        );
                        (
                            Work::Command(Command::Transfer(t.clone())),
                            json!({"Action":if kind=="split"{"Split local balance inputs"}else{"Ordinary transfer"},"Recipient":to,"Amount":chain::format(value),"Fee":chain::format(fee),"Change":chain::format(t.outputs.get(1).map(|o|o.amount.0).unwrap_or(0)),"Valid until":expires.to_string()}),
                        )
                    }
                    "open" => {
                        let peer =
                            address::decode(&self.saved.chain_id, field(&r.peer, "Peer address")?)?;
                        let capacity = chain::amount(field(&r.amount, "Channel total")?)?;
                        let fee = chain::amount(field(&r.fee, "Opening fee")?)?;
                        let close_fee = chain::amount(field(&r.close_fee, "Settlement fee")?)?;
                        let total = capacity
                            .checked_add(fee)
                            .ok_or_else(|| anyhow!("Amount overflow"))?;
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
                            json!({"Action":"Sign channel invitation","Peer":peer,"Deposit":chain::format(capacity),"Opening fee":chain::format(fee),"Reserved settlement fee":chain::format(close_fee),"Valid until":expires.to_string(),"Description":"Retain and send the invitation first; broadcast opening after the peer signs the initial allocation. The invitation reserves this input."}),
                        )
                    }
                    "accept" => {
                        let o: OpenChannel = parse(&r)?;
                        initial_open(&o, c, &owner, true)?;
                        ensure!(o.initial.signature_b.is_empty(), "Invitation already contains the peer signature");
                        (
                            Work::Accept(o.clone()),
                            json!({"Action":"Accept channel invitation","Funder":o.intent.party_a,"Capacity":chain::format(o.intent.capacity.0),"Your initial balance":"0","Settlement fee":chain::format(o.intent.close_fee.0),"Valid until":o.intent.valid_through_height.to_string()}),
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
                            "Signed file differs from the original local invitation"
                        );
                        (
                            Work::Command(Command::Open(o.clone())),
                            json!({"Action":"Broadcast channel opening","Peer":o.intent.party_b,"Deposit":chain::format(o.intent.capacity.0),"Opening fee":chain::format(o.intent.opening_fee.0),"Description":"Initial dual-signed allocation verified; protected payments require on-chain opening and finality."}),
                        )
                    }
                    "export" => {
                        let destination = hash(field(&r.destination, "Destination chain ID")?)?;
                        let to = address::decode(
                            &destination.to_hex(),
                            field(&r.to, "Destination recipient address")?,
                        )?;
                        let amount = chain::amount(field(&r.amount, "Export amount")?)?;
                        let fee = chain::amount(field(&r.fee, "Source fee")?)?;
                        let df = chain::amount(field(&r.destination_fee, "Destination fee")?)?;
                        let total = amount.checked_add(fee).ok_or_else(|| anyhow!("Amount overflow"))?;
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
                            json!({"Action":"Lock source assets and export","Destination chain":destination,"Recipient":to,"Export amount":chain::format(amount),"Source fee":chain::format(fee),"Destination fee":chain::format(df),"Destination net amount":chain::format(amount-df),"Description":"Exports do not refund automatically after timeout or missing receipts. Source finality, destination import and return proof remain required."}),
                        )
                    }
                    "reserve" | "close" | "challenge" | "finalize" | "protect" | "offer"
                    | "receive" => {
                        let id = hash(field(&r.channel, "Channel identifier")?)?;
                        let b = get(&self.saved.products, id)?;
                        let e = c
                            .state()
                            .escrow(id)
                            .ok_or_else(|| anyhow!("Channel is not open on the locally selected chain"))?;
                        ensure!(e.funding == b.funding, "On-chain channel differs from local identities");
                        match kind {
                            "reserve" => {
                                ensure!(matches!(e.phase, Phase::Open), "Channel is not currently open");
                                let minimum = chain::amount(field(&r.fee, "Minimum reserve amount")?)?;
                                ensure!(minimum > 0, "Reserve amount must be positive");
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
                                    json!({"Action":"Lock challenge fee reserve","Channel":id,"The complete input is locked":chain::format(coin.output.amount.0),"Description":"The complete input remains locked until channel settlement and cannot be spent as ordinary balance."}),
                                )
                            }
                            "finalize" => {
                                let Phase::Closing {
                                    deadline_height,
                                    ref best,
                                    ..
                                } = e.phase
                                else {
                                    return Err(anyhow!("Channel closing has not started"));
                                };
                                ensure!(c.height() > deadline_height, "Protection period has not ended");
                                ensure!(
                                    b.latest == *best
                                        && b.pending_offer.is_none()
                                        && b.pending_receive.is_none(),
                                    "Local state differs or remains pending; verify and challenge before settling an older allocation"
                                );
                                (
                                    Work::Command(Command::Finalize { channel: id }),
                                    json!({"Action":"Settle channel","Channel":id,"Protection deadline":deadline_height.to_string(),"Description":"Distribute using the best confirmed on-chain state; challenge first when a newer receipt remains unconfirmed."}),
                                )
                            }
                            "close" | "challenge" => {
                                ensure!(
                                    b.pending_offer.is_none()
                                        && (kind == "challenge" || b.pending_receive.is_none()),
                                    "Payment remains incomplete; recover the exact original or complete watcher confirmation first"
                                );
                                if let Phase::Closing { best, .. } = &e.phase {
                                    ensure!(
                                        b.latest.state.sequence >= best.state.sequence,
                                        "A newer on-chain state exists; closing with an older state is forbidden"
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
                                    let fee = chain::amount(field(&r.fee, "Action fee")?)?;
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
                                    json!({"Action":if kind=="close"{"Request closing"}else{"Challenge with a newer state"},"Channel":id,"State sequence":b.latest.state.sequence,"Action fee":chain::format(fee),"Description":"Closing retains the original complete 2016-block protection period."}),
                                )
                            }
                            "protect" => {
                                let watcher = field(&r.watcher, "Watcher public key")?.to_owned();
                                rld_core::validate_ed25519_public_key(&watcher).map_err(err)?;
                                if let Some(key) = &b.watcher {
                                    ensure!(key == &watcher, "Replacing a pinned watcher identity is forbidden");
                                }
                                let url = loopback_origin(field(&r.watch_url, "Watcher loopback address")?)
                                    .map_err(err)?;
                                let input = r
                                    .input
                                    .clone()
                                    .ok_or_else(|| anyhow!("Select a confirmed fee-reserve input"))?;
                                let reserve = c
                                    .state()
                                    .reserved_challenge_fee(&input)
                                    .ok_or_else(|| anyhow!("Input is not an on-chain fee reserve"))?;
                                let fee = chain::amount(field(&r.fee, "Challenge fee")?)?;
                                ensure!(
                                    fee > 0
                                        && reserve.coin.output.amount.0 >= fee
                                        && reserve.coin.output.owner == owner,
                                    "Invalid fee-reserve amount or identity"
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
                                    json!({"Action":"Authorize watching the latest channel state","Channel":id,"Sequence":b.latest.state.sequence,"Watcher":watcher,"Service":url,"Challenge fee":chain::format(fee),"Description":"Authorization remains valid for challenges to this exact state; payment requires the service to retain its signed acknowledgment."}),
                                )
                            }
                            "offer" => {
                                ensure!(
                                    b.pending_offer.is_none() && b.pending_receive.is_none(),
                                    "Complete or retry the exact previous payment first"
                                );
                                let p = b
                                    .protection
                                    .as_ref()
                                    .ok_or_else(|| anyhow!("Import the recipient complete watcher proof first"))?;
                                let ack = b.ack.as_ref().ok_or_else(|| anyhow!("Missing watcher acknowledgment"))?;
                                ack.verify(p, b.watcher.as_deref().unwrap_or(""))
                                    .map_err(err)?;
                                let receiver = if owner == b.funding.party_a {
                                    &b.funding.party_b
                                } else {
                                    &b.funding.party_a
                                };
                                ready(c, p, receiver)?;
                                let amount = Amount(chain::amount(field(&r.amount, "Payment amount")?)?);
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
                                    json!({"Action":"Sign channel payment proposal","Recipient":receiver,"Amount":chain::format(amount.0),"Payment identifier":payment,"Description":"The signing decision becomes durable first; a complete receipt requires peer dual signatures and watcher acknowledgment."}),
                                )
                            }
                            _ => {
                                let offer: PaymentOffer = parse(&r)?;
                                offer.verify(&b.funding).map_err(err)?;
                                ensure!(
                                    offer.sender != owner && b.pending_offer.is_none(),
                                    "Cannot accept your own payment or accept while another payment is pending"
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
                                        "Duplicate payment identifier with different content"
                                    );
                                    return Ok(
                                        json!({"packet":old,"message":"Original receipt retained; no repeated signing or duplicate credit."}),
                                    );
                                }
                                if let Some(p) = &b.pending_receive {
                                    ensure!(
                                        p.previous == offer.previous
                                            && p.updated.state == offer.proposed
                                            && p.payment_id == offer.payment_id,
                                        "Previous watcher-pending payment remains incomplete"
                                    );
                                } else {
                                    ensure!(
                                        offer.previous == b.latest,
                                        "Payment is not the successor of the latest local state"
                                    );
                                }
                                let p = b
                                    .protection
                                    .as_ref()
                                    .ok_or_else(|| anyhow!("Configure and confirm your watcher reserve first"))?;
                                ready(c, p, &owner)?;
                                (
                                    Work::Receive {
                                        channel: id,
                                        offer: offer.clone(),
                                    },
                                    json!({"Action":"Receive channel payment and request watcher custody","Payer":offer.sender,"Amount":chain::format(offer.amount.0),"Payment identifier":offer.payment_id,"Description":"Retain only a pending record before watcher acknowledgment; signing the next payment is forbidden."}),
                                )
                            }
                        }
                    }
                    _ => return Err(anyhow!("Unsupported product action")),
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
                            "Use the local wallet flow for dual opening signatures; external signer integration still requires device qualification"
                        );
                        signing=if matches!(cmd,Command::Challenge{fee,..} if !fee.owner_signature.is_empty()){None}else{command_message(cmd,&owner)?}.map(|b|json!({"algorithm":"Ed25519","public_key":owner,"message_hex":hex::encode(b),"command":cmd,"chain_id":self.replay.store.chain().chain_id(),"tip":self.replay.store.chain().tip(),"review":review}));
                    } else {
                        return Err(anyhow!(
                            "This channel exchange requires a local key; external devices require a dedicated qualified adapter"
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
                ensure!(self.saved.backup_verified, "Verify the backup first");
                self.replay.refresh().await?;
                self.expire();
                let d = self
                    .product_draft
                    .take()
                    .ok_or_else(|| anyhow!("Preview the action again"))?;
                ensure!(
                    r.draft.as_deref() == Some(d.id.as_str())
                        && now()?.saturating_sub(d.created) <= 120
                        && self.replay.store.chain().tip() == d.tip,
                    "Chain state or preview changed; review again"
                );
                let destination_tip = d.destination_tip;
                match d.work {
                    Work::Destination(mut command) => {
                        self.refresh_destination().await?;
                        ensure!(
                            destination_tip
                                == Some(self.destination.as_ref().unwrap().store.chain().tip()),
                            "Destination preview changed; review again"
                        );
                        if let rld_value_successor::destination::pow::Command::Transfer(t) =
                            &mut command
                        {
                            let bytes = t.signing_bytes().map_err(err)?;
                            t.signature = if self.saved.external_public.is_some() {
                                let sig = field(&r.signature, "External signature")?.to_owned();
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
                                let sig = field(&r.signature, "External signature")?.to_owned();
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
                            json!({"packet":o,"message":"Original invitation retained; send it to the peer and broadcast opening after receiving the initial dual-signed allocation."}),
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
                            "Invitation already retained; use the original file without signing again"
                        );
                        self.saved.products.channels.push(Channel::new(&o)?);
                        self.persist()?;
                        Ok(
                            json!({"packet":o,"message":"Initial dual-signed state retained; return it to the funder. After opening, lock a challenge reserve and connect a watcher."}),
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
                            json!({"packet":{"package":p,"ack":ack,"watcher":watcher},"message":"Watcher signed its durable acknowledgment; return the complete exchange file to the payer for verification."}),
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
                            json!({"packet":offer,"message":"Payment proposal retained. Resend the original file; do not sign the next payment before the complete receipt arrives."}),
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
                            .ok_or_else(|| anyhow!("Missing your watcher configuration"))?;
                        let url = b
                            .watch_url
                            .clone()
                            .ok_or_else(|| anyhow!("Missing watcher service address"))?;
                        let watcher = b.watcher.clone().ok_or_else(|| anyhow!("Missing watcher identity"))?;
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
                            json!({"packet":w,"message":"Dual-signed payment and watcher custody proof verified and durable; send the complete receipt to the payer."}),
                        )
                    }
                }
            }
            "product_retry_watch" => {
                let id = hash(field(&r.channel, "Channel identifier")?)?;
                let b = get(&self.saved.products, id)?;
                let p = b
                    .protection
                    .clone()
                    .ok_or_else(|| anyhow!("No pending watcher package"))?;
                let public = b.watcher.clone().ok_or_else(|| anyhow!("Missing watcher identity"))?;
                let url = b.watch_url.clone().ok_or_else(|| anyhow!("Missing watcher address"))?;
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
                Ok(json!({"packet":packet,"message":"Retried the exact original watcher package and retained acknowledgment without signing again."}))
            }
            _ => Err(anyhow!("Unknown product action")),
        }
    }
}
fn set_signature(command: &mut Command, sig: String) -> Result<()> {
    match command {
        Command::Transfer(t) => t.signature = sig,
        Command::ReserveChallengeFee(r) => r.owner_signature = sig,
        Command::Close { fee, .. } | Command::Challenge { fee, .. } => fee.owner_signature = sig,
        Command::Export(e) => e.owner_signature = sig,
        _ => return Err(anyhow!("This command requires more than one external signature")),
    }
    Ok(())
}
