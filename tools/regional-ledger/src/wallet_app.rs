//! Loopback wallet application over per-request native locks; no Python driver.
use crate::{storage::Store, wallet, wallet_agent, wallet_client, wallet_proposal, *};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

pub const REVIEW_SECONDS: u64 = 300;

pub struct Options {
    pub ledger: PathBuf,
    pub authority: String,
    pub currency: Hash,
    pub wallet: PathBuf,
    pub heads: PathBuf,
    pub owner: String,
    pub expected: Option<Hash>,
    pub key: Option<PathBuf>,
    pub encrypted_key: Option<PathBuf>,
    pub passphrase: Option<Zeroizing<Vec<u8>>>,
    pub backup_dir: Option<PathBuf>,
    pub miner: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Action {
    Status {},
    Init {},
    Backup {},
    Prepare {
        request: Value,
    },
    Sign {
        review_id: Hash,
        review_commitment: Hash,
    },
    CancelReview {
        review_id: String,
    },
    Recover {
        intent: Hash,
    },
    Submit {
        intent: Hash,
    },
    Combine {
        contributions: Vec<Command>,
    },
    SubmitCombined {
        combined_id: String,
    },
    Receipt {
        expectation: wallet::ReceiptExpectation,
    },
    ProposalInputs {
        owners: Vec<String>,
    },
    ProposalBuild {
        request: wallet_proposal::BuildRequest,
        selection_pin: wallet::Pin,
    },
    ProposalReview {
        proposal: wallet_proposal::Proposal,
    },
}

pub struct App {
    options: Options,
    pub saved: wallet_client::State,
    context: Value,
    failed: bool,
    previews: BTreeMap<Hash, (Instant, wallet_agent::Prepared)>,
    combinations: BTreeMap<String, (Instant, wallet::Combined)>,
    recovery_notice: Option<&'static str>,
    _lock: File,
}

fn json_value<T: Serialize>(value: T) -> Result<Value> {
    serde_json::to_value(value).map_err(|e| e.to_string())
}

pub(crate) fn random_id() -> Result<Hash> {
    let mut bytes = [0; 32];
    getrandom::getrandom(&mut bytes).map_err(|e| e.to_string())?;
    Ok(Hash(bytes))
}

fn private_dir(path: &Path) -> Result<()> {
    require(path.is_absolute(), "private directory must be absolute")?;
    for p in path.ancestors() {
        match fs::symlink_metadata(p) {
            Ok(m) => require(
                m.is_dir() && !m.file_type().is_symlink(),
                "private directory symlink or type invalid",
            )?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.to_string()),
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .map_err(|e| e.to_string())?;
    }
    #[cfg(not(unix))]
    {
        return Err("native wallet app requires Unix custody".into());
    }
    crate::storage::safe_dir(path)
}

impl App {
    pub fn open(options: Options) -> Result<Self> {
        require(cfg!(unix), "native wallet app requires Unix custody")?;
        private_dir(&options.heads)?;
        require(
            options.key.is_none() || options.encrypted_key.is_none(),
            "choose exactly one native key format",
        )?;
        for path in [&options.key, &options.encrypted_key].into_iter().flatten() {
            crate::storage::safe_dir(path.parent().ok_or("private key parent missing")?)?;
            wallet_client::private_read(path)?;
        }
        if let Some(path) = &options.backup_dir {
            private_dir(path)?;
        }
        crate::verification_keys::validate_ed25519_public_key(&options.owner)?;
        if let Some(miner) = &options.miner {
            crate::verification_keys::validate_ed25519_public_key(miner)?;
        }
        let mut open = OpenOptions::new();
        open.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open.custom_flags(libc::O_NOFOLLOW).mode(0o600);
        }
        let lock = open
            .open(options.heads.join(".app.lock"))
            .map_err(|e| e.to_string())?;
        wallet_client::private_metadata(&lock)?;
        lock.try_lock().map_err(|e| e.to_string())?;
        let store = Store::open(&options.ledger, &options.authority, options.currency)?;
        let context = json!({"currency":options.currency,"region":store.chain.region,"fixture_only":true,"live_rld":false,
            "regions":store.journal.bootstrap.admissions.iter().map(|a| Ok(json!({"id":a.id()?,"name":a.region}))).collect::<Result<Vec<_>>>()?});
        if let Some(key) = &options.encrypted_key {
            let pass = options
                .passphrase
                .as_ref()
                .ok_or("encrypted wallet requires terminal unlock")?;
            crate::keystore::check(&store, &options.owner, key, pass)?;
        }
        require(
            options.encrypted_key.is_some() || options.passphrase.is_none(),
            "passphrase needs encrypted key",
        )?;
        let saved = {
            let client = wallet_client::Client::lock(
                &options.heads,
                &options.wallet,
                options.owner.clone(),
                &store,
            )?;
            client.open(&store, options.expected)?
        };
        let mut app = Self {
            options,
            saved,
            context,
            failed: false,
            previews: BTreeMap::new(),
            combinations: BTreeMap::new(),
            recovery_notice: None,
            _lock: lock,
        };
        if app.saved.pending.is_some() {
            app.reconcile(&store)?;
        }
        Ok(app)
    }

    fn head(&self) -> Result<Hash> {
        self.saved.head.ok_or_else(|| "请先初始化本机钱包".into())
    }

    fn client(&self, store: &Store) -> Result<wallet_client::Client> {
        wallet_client::Client::lock(
            &self.options.heads,
            &self.options.wallet,
            self.options.owner.clone(),
            store,
        )
    }

    fn save(&mut self, store: &Store, proposed: wallet_client::State) -> Result<()> {
        require(!self.failed, "保存失败；保留目录并重启核验")?;
        let result = self.client(store).and_then(|client| {
            client.store(
                store,
                wallet_client::Transition {
                    previous: self.saved.clone(),
                    proposed,
                },
            )
        });
        match result {
            Ok(saved) => {
                self.saved = saved;
                Ok(())
            }
            Err(e) => {
                self.failed = true;
                Err(e)
            }
        }
    }

    fn reconcile(&mut self, store: &Store) -> Result<()> {
        let result = self.client(store)?.reconcile(store, self.saved.clone())?;
        self.save(store, result.state)?;
        self.recovery_notice = result.recovery_notice;
        Ok(())
    }

    fn agent(&self, store: &Store) -> Result<wallet_agent::Agent> {
        wallet_agent::Agent::open(&self.options.wallet, store)
    }

    fn retain_review(&mut self, prepared: wallet_agent::Prepared) -> Result<Value> {
        require(self.previews.len() < 4, "review capacity reached")?;
        let id = random_id()?;
        let mut result = json_value(&prepared)?;
        result["review_id"] = json!(id);
        self.previews.insert(id, (Instant::now(), prepared));
        Ok(result)
    }

    fn status(&self, store: &Store) -> Result<Value> {
        let view = self
            .saved
            .head
            .map(|head| self.agent(store)?.view(store, head))
            .transpose()?;
        let contacts = store
            .journal
            .contact_records
            .keys()
            .map(|id| store.contact_status(*id))
            .collect::<Result<Vec<_>>>()?;
        let path = self
            .options
            .ledger
            .join("transport/regional-contact-status.json");
        let transport = match fs::symlink_metadata(&path) {
            Ok(_) => {
                crate::storage::safe_dir(path.parent().ok_or("transport parent missing")?)?;
                let raw = wallet_client::private_read(&path)?;
                let report = crate::wallet_http::decode_unique(&raw)?;
                require(
                    wallet_client::canonical(&report)? == raw,
                    "noncanonical transport report",
                )?;
                require(
                    report["currency"] == json!(self.saved.binding.currency)
                        && report["region"] == json!(self.saved.binding.region),
                    "transport report identity differs",
                )?;
                json!({"reported_at_unix":report.get("observed_at_unix").ok_or("transport observation missing")?,"report_is_historical":true,
                    "process_liveness_verified":false,"transport_receipt_is_payment_authority":false,
                    "observation":report.get("transport").ok_or("transport observation missing")?})
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Value::Null,
            Err(e) => return Err(e.to_string()),
        };
        Ok(
            json!({"format":wallet_client::FORMAT,"context":self.context,"owner":self.options.owner,"wallet":view,
            "contacts":{"currency":self.options.currency,"region":store.chain.region,"local_height":store.chain.height(),"contacts":contacts,"source_http_required":false},
            "transport":transport,"checked_at_unix":SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e|e.to_string())?.as_secs(),
            "signing_enabled":self.options.key.is_some() || self.options.encrypted_key.is_some() && self.options.passphrase.is_some(),
            "encrypted_key_enabled":self.options.encrypted_key.is_some(),"backup_enabled":self.options.encrypted_key.is_some() && self.options.passphrase.is_some() && self.options.backup_dir.is_some(),
            "local_block_producer_enabled":self.options.miner.is_some(),"recovery_notice":self.recovery_notice,
            "external_rollback_anchor_qualified":false,"remote_current_state_known":false,"live_rld":false}),
        )
    }

    fn submit(&self, store: &mut Store, commands: Vec<Command>) -> Result<Value> {
        let miner = self
            .options
            .miner
            .clone()
            .ok_or("未配置本地区出块；可下载签名交给本地出块者")?;
        let mut block = store.template(commands, miner)?;
        mine(&mut block)?;
        store.accept(block.clone())?;
        json_value(block)
    }

    pub fn act(&mut self, action: Action) -> Result<Value> {
        require(!self.failed, "保存失败；保留目录并重启核验")?;
        // No Store/Agent or caller operation lock is held during socket waits.
        let mut store = Store::open(
            &self.options.ledger,
            &self.options.authority,
            self.options.currency,
        )?;
        match action {
            Action::Status {} => return self.status(&store),
            Action::Init {} => {
                require(
                    self.saved.head.is_none() && !self.options.wallet.exists(),
                    "wallet already initialized or interrupted",
                )?;
                let head = wallet_agent::Agent::create(
                    &self.options.wallet,
                    &store,
                    self.options.owner.clone(),
                )?
                .journal
                .head()?;
                let mut proposed = self.saved.clone();
                proposed.head = Some(head);
                self.save(&store, proposed)?;
                return self.status(&store);
            }
            Action::Receipt { expectation } => {
                require(
                    expectation.currency == self.saved.binding.currency
                        && expectation.destination == self.saved.binding.region,
                    "receipt expectation differs from local currency/destination",
                )?;
                return json_value(wallet::receipt(&store, expectation)?);
            }
            _ => (),
        }
        let head = self.head()?;
        let view = self.agent(&store)?.view(&store, head)?;
        self.previews
            .retain(|_, (at, _)| at.elapsed().as_secs() < REVIEW_SECONDS);
        self.combinations
            .retain(|_, (at, _)| at.elapsed().as_secs() < REVIEW_SECONDS);
        match action {
            Action::Backup {} => {
                require(
                    self.saved.pending.is_none(),
                    "backup needs reconciled consent",
                )?;
                let key = self
                    .options
                    .encrypted_key
                    .as_ref()
                    .ok_or("backup needs encrypted key")?;
                let pass = self
                    .options
                    .passphrase
                    .as_ref()
                    .ok_or("backup needs terminal unlock")?;
                let directory = self
                    .options
                    .backup_dir
                    .as_ref()
                    .ok_or("backup needs configured directory")?;
                let path = directory.join(format!(
                    "wallet-backup-{}.enc.json",
                    &random_id()?.to_hex()[..32]
                ));
                let agent = self.agent(&store)?;
                let saved = crate::keystore::backup(&store, &agent, head, key, &path, pass)?;
                require(saved == head, "backup head differs from caller")?;
                Ok(
                    json!({"binding":agent.journal.binding,"wallet_head":saved,"complete_native_owner_journal":true,
                    "caller_head_included":false,"fixture_only":true,"live_rld":false,"saved_file":path,"retain_latest_head_separately":true}),
                )
            }
            Action::Prepare { mut request } => {
                require(
                    self.previews.len() < 4 && request.is_object(),
                    "review capacity reached",
                )?;
                if let Some(owner) = request.get("owner") {
                    require(
                        *owner == json!(self.options.owner),
                        "request belongs to another wallet owner",
                    )?;
                }
                request["owner"] = json!(self.options.owner);
                let req = serde_json::from_value(request).map_err(|e| e.to_string())?;
                let prepared = self.agent(&store)?.prepare(&store, req, head)?;
                self.retain_review(prepared)
            }
            Action::ProposalBuild {
                request,
                selection_pin,
            } => {
                let built = wallet_proposal::build(
                    &store,
                    &self.agent(&store)?,
                    head,
                    wallet_proposal::BuildInput {
                        request,
                        selection_pin,
                    },
                )?;
                let mut result = self.retain_review(built.prepared)?;
                result["proposal"] = json_value(built.proposal)?;
                Ok(result)
            }
            Action::ProposalReview { proposal } => {
                let prepared =
                    wallet_proposal::review(&store, &self.agent(&store)?, head, proposal)?;
                self.retain_review(prepared)
            }
            Action::ProposalInputs { owners } => {
                require(
                    (2..=16).contains(&owners.len())
                        && owners.windows(2).all(|p| p[0] < p[1])
                        && owners.contains(&self.options.owner),
                    "参与者须唯一、排序并包括本钱包",
                )?;
                let mut views = Vec::new();
                let reserved: BTreeSet<_> = view
                    .signed
                    .iter()
                    .filter(|r| r.state == "SIGNED_PENDING_INCLUSION")
                    .flat_map(|r| r.inputs.iter())
                    .collect();
                for owner in &owners {
                    let mut observed = json_value(wallet::view(&store, owner)?)?;
                    for coin in observed["coins"]
                        .as_array_mut()
                        .ok_or("native coins missing")?
                    {
                        let id: Hash = serde_json::from_value(coin["id"].clone())
                            .map_err(|e| e.to_string())?;
                        coin["reserved_by_this_wallet"] = json!(reserved.contains(&id));
                    }
                    observed["private_reservations_known"] = json!(owner == &self.options.owner);
                    views.push(observed);
                }
                Ok(
                    json!({"pin":view.ledger.pin,"owners":views,"peer_wallet_reservations_known":false,"live_rld":false,"wallet_head":head}),
                )
            }
            Action::CancelReview { review_id } => {
                if let Ok(id) = Hash::from_hex(&review_id) {
                    self.previews.remove(&id);
                }
                Ok(json!({"review_canceled":true,"signed_inputs_released":false}))
            }
            Action::Sign {
                review_id,
                review_commitment,
            } => {
                require(
                    self.options.key.is_some()
                        || self.options.encrypted_key.is_some()
                            && self.options.passphrase.is_some(),
                    "read-only wallet",
                )?;
                require(self.saved.pending.is_none(), "pending recovery")?;
                let prepared = self
                    .previews
                    .get(&review_id)
                    .ok_or("审阅已过期；请重新预览")?
                    .1
                    .clone();
                require(
                    prepared.review_commitment == review_commitment,
                    "review commitment changed",
                )?;
                let mut proposed = self.saved.clone();
                proposed.pending = Some(wallet_client::Pending {
                    prepared: prepared.clone(),
                });
                self.save(&store, proposed)?;
                let result = (|| {
                    let mut agent = self.agent(&store)?;
                    if let Some(key) = &self.options.encrypted_key {
                        agent.sign_encrypted(
                            &store,
                            prepared.draft,
                            key,
                            review_commitment,
                            head,
                            self.options
                                .passphrase
                                .as_ref()
                                .ok_or("terminal unlock missing")?,
                        )
                    } else {
                        agent.sign(
                            &store,
                            prepared.draft,
                            self.options.key.as_ref().ok_or("private key missing")?,
                            review_commitment,
                            head,
                        )
                    }
                })();
                self.previews.clear();
                match result {
                    Ok(signed) => {
                        let mut proposed = self.saved.clone();
                        proposed.head = Some(signed.wallet_head);
                        proposed.pending = None;
                        self.save(&store, proposed)?;
                        json_value(signed)
                    }
                    Err(e) => {
                        if self.reconcile(&store).is_err() {
                            self.failed = true;
                        }
                        Err(e)
                    }
                }
            }
            Action::Recover { intent } => {
                json_value(self.agent(&store)?.recover(&store, intent, head)?)
            }
            Action::Submit { intent } => {
                let commands = self.agent(&store)?.recover(&store, intent, head)?.commands;
                self.submit(&mut store, commands)
            }
            Action::Combine { contributions } => {
                require(
                    self.combinations.len() < 4 && (1..=16).contains(&contributions.len()),
                    "owner contribution capacity",
                )?;
                let combined = wallet::combine(&store, contributions)?;
                let id = random_id()?.to_hex();
                let mut value = json_value(&combined)?;
                value["combined_id"] = json!(id);
                self.combinations.insert(id, (Instant::now(), combined));
                Ok(value)
            }
            Action::SubmitCombined { combined_id } => {
                let commands = self
                    .combinations
                    .get(&combined_id)
                    .ok_or("组合审阅已失效")?
                    .1
                    .commands
                    .clone();
                self.submit(&mut store, commands)
            }
            Action::Status {} | Action::Init {} | Action::Receipt { .. } => unreachable!(),
        }
    }
}
