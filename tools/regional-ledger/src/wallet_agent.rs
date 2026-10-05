//! Persist signed owner commands before returning them. Local reservations never
//! refund an included export and never depend on a transport timeout or receipt.
use super::*;
use crate::{
    storage::{read_json, safe_dir, Store},
    wallet::{Draft, Pin, Request},
};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
pub const MAX_SIGNED: usize = 128;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub currency: Hash,
    pub region: Hash,
    pub owner: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub pin: Pin,
    pub incidents: Vec<Hash>,
}
impl Observation {
    pub(crate) fn current(node: &Store) -> Result<Self> {
        let mut incidents = node
            .conflicts
            .iter()
            .map(|p| p.id())
            .collect::<Result<Vec<_>>>()?;
        incidents.sort();
        Ok(Self {
            pin: Pin::current(node)?,
            incidents,
        })
    }
    pub(crate) fn check(&self, node: &Store, binding: &Binding) -> Result<()> {
        let p = &self.pin;
        require(
            p.currency == binding.currency
                && p.region == binding.region
                && node.chain.height() >= p.height,
            "wallet observed ledger height/domain rollback",
        )?;
        let (tip, state) = if p.height == 0 {
            (node.chain.region, Ledger::default().root()?)
        } else {
            let block = node.block_at(p.height)?;
            (block.header.id()?, block.header.state)
        };
        require(
            tip == p.tip && state == p.state,
            "wallet observed ledger prefix differs or rolled back",
        )?;
        let initial = epoch::Registry::initial(&node.trust, node.chain.region)?;
        let epochs = node.evidence.epoch_proofs(node.chain.region);
        let ordinal = |id| -> Result<usize> {
            if id == initial {
                return Ok(0);
            }
            epochs
                .iter()
                .position(|e| e.statement.id().ok() == Some(id))
                .map(|n| n + 1)
                .ok_or("wallet observed epoch proof missing".into())
        };
        require(
            ordinal(node.chain.epoch)? >= ordinal(p.epoch)?,
            "wallet observed validator era rollback",
        )?;
        if crate::paged_bft::is_profile(&node.trust.region(binding.region)?.rules) {
            let (historical, _) = node.paged_history_at(p.height)?;
            require(
                historical.finalized == p.finality
                    && historical.epoch == p.epoch
                    && historical.tip()? == p.tip
                    && historical.ledger.root()? == p.state,
                "paged wallet observed exact selected native history differs",
            )?;
        } else {
            if let Some(old) = p.finality {
                let snapshot = node.evidence.snapshot(old)?;
                let current = node.evidence.snapshot(
                    node.chain
                        .finalized
                        .ok_or("wallet observed finality disappeared")?,
                )?;
                require(
                    snapshot.statement.region == binding.region
                        && current.statement.height >= snapshot.statement.height
                        && node
                            .evidence
                            .descends_from(current.statement.id()?, snapshot.statement.id()?)?,
                    "wallet observed finality rollback",
                )?;
            }
        }
        require(
            self.incidents.len() <= conflict::MAX_INCIDENTS
                && self.incidents.windows(2).all(|p| p[0] < p[1]),
            "wallet observed incident bound/order",
        )?;
        let actual = node
            .conflicts
            .iter()
            .map(|p| p.id())
            .collect::<Result<BTreeSet<_>>>()?;
        require(
            self.incidents.iter().all(|id| actual.contains(id)),
            "wallet observed incident disappeared",
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub previous_head: Hash,
    pub observation: Observation,
    pub draft: Draft,
    pub review_commitment: Hash,
    pub command: Command,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    pub binding: Binding,
    pub creation: Observation,
    pub records: Vec<Record>,
}
impl Journal {
    pub fn head(&self) -> Result<Hash> {
        id("wallet-signature-journal-v1", self)
    }
    fn validate(&self, node: &Store) -> Result<()> {
        require(
            self.binding.currency == node.trust.currency()?
                && self.binding.region == node.chain.region
                && self.records.len() <= MAX_SIGNED,
            "wallet journal binding/count mismatch",
        )?;
        validate_ed25519_public_key(&self.binding.owner)?;
        self.creation.check(node, &self.binding)?;
        let mut prefix = Self {
            binding: self.binding.clone(),
            creation: self.creation.clone(),
            records: vec![],
        };
        let mut known = BTreeSet::new();
        let mut observed_chain = Chain::new(node.chain.region, &node.trust)?;
        let mut observed_events = node.events()?;
        for r in &self.records {
            r.observation.check(node, &self.binding)?;
            require(
                r.observation.pin.height >= observed_chain.height(),
                "wallet observed signing history moved backwards",
            )?;
            if crate::paged_bft::is_profile(&node.trust.region(node.chain.region)?.rules) {
                observed_chain = node.paged_history_at(r.observation.pin.height)?.0;
            } else {
                while observed_chain.height() < r.observation.pin.height {
                    node.journal.replay_event(
                        &mut observed_chain,
                        &node.trust,
                        &node.evidence,
                        observed_events
                            .next()
                            .transpose()?
                            .ok_or("wallet signing-height native prefix missing")?,
                    )?;
                }
            }
            let actual_owners = r
                .draft
                .intent
                .inputs
                .iter()
                .map(|i| {
                    Ok((
                        *i,
                        observed_chain
                            .ledger
                            .coins
                            .get(i)
                            .ok_or("wallet observed input absent or spent")?
                            .payment
                            .owner
                            .clone(),
                    ))
                })
                .collect::<Result<BTreeMap<_, _>>>()?;
            let owners = wallet::required_owners(&r.draft);
            let actual_amounts = r
                .draft
                .intent
                .inputs
                .iter()
                .map(|i| (*i, observed_chain.ledger.coins[i].payment.amount))
                .collect::<BTreeMap<_, _>>();
            require(r.draft.input_owners == actual_owners && r.draft.input_amounts == actual_amounts
                && owners.contains(&self.binding.owner)
                && ((r.draft.request.participants.is_empty() && owners == vec![self.binding.owner.clone()])
                    || (r.draft.request.participants == owners && (2..=16).contains(&owners.len()))),
                "wallet retained ownership or participant description differs from native observed history")?;
            let Command::Spend(signed) = &r.command else {
                return Err("wallet journal contains a non-owner command".into());
            };
            require(
                r.previous_head == prefix.head()?
                    && r.draft.pin == r.observation.pin
                    && r.review_commitment == id("wallet-reviewed-draft", &r.draft)?
                    && r.draft.intent == signed.intent
                    && r.draft.intent_id == signed.intent.id()?
                    && signed.intent.currency == self.binding.currency
                    && signed.intent.region == self.binding.region
                    && r.draft.request.owner == self.binding.owner
                    && signed.approvals.len() == 1
                    && signed.approvals[0].key == self.binding.owner
                    && known.insert(r.draft.intent_id)
                    && !signed.intent.inputs.is_empty()
                    && signed.intent.inputs.len() <= 16
                    && signed.intent.inputs.windows(2).all(|p| p[0] < p[1])
                    && signed.intent.valid_through > r.observation.pin.height
                    && signed.intent.valid_through <= r.observation.pin.height.saturating_add(32),
                "wallet journal signature/request chain mismatch",
            )?;
            verify_bytes(
                &self.binding.owner,
                &signed.intent.bytes()?,
                &signed.approvals[0].signature,
            )?;
            let prior_height = prefix
                .records
                .last()
                .map(|r| r.observation.pin.height)
                .unwrap_or(self.creation.pin.height);
            require(
                r.observation.pin.height >= prior_height,
                "wallet observed signing history moved backwards",
            )?;
            for old in &prefix.records {
                if old.draft.intent.inputs.iter().any(|id| {
                    signed.intent.inputs.contains(id)
                        && old.draft.input_owners.get(id) == Some(&self.binding.owner)
                }) {
                    require(
                        outcome(node, old, r.observation.pin.height)? != "SIGNED_PENDING_INCLUSION",
                        "wallet journal signs overlapping live inputs",
                    )?;
                }
            }
            prefix.records.push(r.clone());
        }
        encode("wallet-agent-journal", self)?;
        Ok(())
    }
}
fn outcome(node: &Store, record: &Record, height: u64) -> Result<&'static str> {
    require(
        height <= node.chain.height(),
        "wallet observation is ahead of native ledger",
    )?;
    for block in node.blocks()? {
        let block = block?;
        if block.header.height > height {
            break;
        }
        for command in &block.commands {
            if let Command::Spend(signed) = command {
                if signed.intent.id()? == record.draft.intent_id {
                    return Ok("INCLUDED_IN_LOCAL_LEDGER");
                }
            }
        }
    }
    for block in node.blocks()? {
        let block = block?;
        if block.header.height > height {
            break;
        }
        for command in &block.commands {
            if let Command::Spend(signed) = command {
                if signed
                    .intent
                    .inputs
                    .iter()
                    .any(|id| record.draft.intent.inputs.contains(id))
                {
                    return Ok("INPUTS_CONSUMED_BY_OTHER_LOCAL_COMMAND");
                }
            }
        }
    }
    if height >= record.draft.intent.valid_through {
        Ok("EXPIRED_BEFORE_INCLUSION")
    } else {
        Ok("SIGNED_PENDING_INCLUSION")
    }
}
#[derive(Debug, Serialize)]
pub struct Pending {
    pub intent_id: Hash,
    pub intent: Intent,
    pub inputs: Vec<Hash>,
    pub valid_through: u64,
    pub state: &'static str,
    pub required_owners: Vec<String>,
    pub retained_approvals_complete: bool,
    pub local_export_finalized: bool,
    pub quarantined: bool,
}
#[derive(Debug, Serialize)]
pub struct View {
    pub ledger: wallet::View,
    pub wallet_head: Hash,
    pub available: Amount,
    pub available_onward_export: Amount,
    pub reserved_owned_outputs: Amount,
    pub signed: Vec<Pending>,
    pub external_rollback_anchor_qualified: bool,
    pub local_region_quarantined: bool,
    pub incident_ids: Vec<Hash>,
}
#[derive(Debug, Serialize)]
pub struct Prepared {
    pub draft: Draft,
    pub review_commitment: Hash,
    pub wallet_head: Hash,
}
#[derive(Debug, Serialize)]
pub struct Signed {
    pub commands: Vec<Command>,
    pub intent_id: Hash,
    pub previous_wallet_head: Hash,
    pub wallet_head: Hash,
    pub state: &'static str,
    pub recovered_exact_retry: bool,
    pub required_owners: Vec<String>,
    pub retained_approvals_complete: bool,
}
pub struct Agent {
    dir: PathBuf,
    _lock: File,
    pub journal: Journal,
    healthy: bool,
}
fn io(e: std::io::Error) -> String {
    e.to_string()
}
fn present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io(error)),
    }
}
impl Agent {
    /// Exclusive fresh target. An interrupted restore marker forbids signing.
    pub(crate) fn restore(
        dir: &Path,
        node: &Store,
        journal: Journal,
        encrypted_key: &[u8],
    ) -> Result<Self> {
        journal.validate(node)?;
        safe_dir(dir.parent().ok_or("wallet parent missing")?)?;
        let mut options = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            options.mode(0o700);
        }
        options.create(dir).map_err(io)?;
        crate::keystore::private_create(
            &dir.join("RESTORING"),
            b"restore incomplete; preserve files",
        )?;
        crate::keystore::private_create(&dir.join("LOCK"), b"")?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.join("LOCK"))
            .map_err(io)?;
        lock.try_lock().map_err(|e| e.to_string())?;
        let agent = Self {
            dir: dir.into(),
            _lock: lock,
            journal,
            healthy: true,
        };
        crate::keystore::private_create(&dir.join("key.enc.json"), encrypted_key)?;
        agent.persist(&agent.journal)?;
        fs::remove_file(dir.join("RESTORING")).map_err(io)?;
        File::open(dir).map_err(io)?.sync_all().map_err(io)?;
        File::open(dir.parent().unwrap())
            .map_err(io)?
            .sync_all()
            .map_err(io)?;
        Ok(agent)
    }
    pub fn create(dir: &Path, node: &Store, owner: String) -> Result<Self> {
        validate_ed25519_public_key(&owner)?;
        safe_dir(dir.parent().ok_or("wallet parent missing")?)?;
        let mut options = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            options.mode(0o700);
        }
        options.create(dir).map_err(io)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(dir.join("LOCK"))
            .map_err(io)?;
        lock.try_lock().map_err(|e| e.to_string())?;
        let journal = Journal {
            binding: Binding {
                currency: node.trust.currency()?,
                region: node.chain.region,
                owner,
            },
            creation: Observation::current(node)?,
            records: vec![],
        };
        journal.validate(node)?;
        let agent = Self {
            dir: dir.into(),
            _lock: lock,
            journal,
            healthy: true,
        };
        agent.persist(&agent.journal)?;
        Ok(agent)
    }
    pub fn open(dir: &Path, node: &Store) -> Result<Self> {
        safe_dir(dir)?;
        require(
            !present(&dir.join("RESTORING"))?,
            "wallet restore incomplete; preserve target and restore to a fresh directory",
        )?;
        let path = dir.join("LOCK");
        let meta = fs::symlink_metadata(&path).map_err(io)?;
        require(
            meta.is_file() && !meta.file_type().is_symlink(),
            "unsafe wallet lock",
        )?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(io)?;
        lock.try_lock().map_err(|e| e.to_string())?;
        let journal: Journal = read_json(&dir.join("wallet.json"))?;
        journal.validate(node)?;
        let mut agent = Self {
            dir: dir.into(),
            _lock: lock,
            journal,
            healthy: true,
        };
        let next = dir.join("wallet.next");
        if present(&next)? {
            let proposed: Journal = read_json(&next)?;
            proposed.validate(node)?;
            require(
                proposed.binding == agent.journal.binding
                    && proposed.creation == agent.journal.creation
                    && proposed.records.len() == agent.journal.records.len() + 1
                    && proposed.records.starts_with(&agent.journal.records),
                "wallet interrupted commit is not an exact extension",
            )?;
            File::open(&next).map_err(io)?.sync_all().map_err(io)?;
            fs::rename(&next, dir.join("wallet.json")).map_err(io)?;
            File::open(dir).map_err(io)?.sync_all().map_err(io)?;
            agent.journal = proposed;
        }
        Ok(agent)
    }
    fn persist(&self, journal: &Journal) -> Result<()> {
        let bytes = serde_json::to_vec(journal).map_err(|e| e.to_string())?;
        require(bytes.len() <= MAX_BYTES, "wallet journal byte bound")?;
        let dest = self.dir.join("wallet.json");
        if present(&dest)? {
            let m = fs::symlink_metadata(&dest).map_err(io)?;
            require(
                m.is_file() && !m.file_type().is_symlink(),
                "unsafe wallet journal",
            )?;
        }
        let temp = self.dir.join("wallet.next");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp).map_err(io)?;
        file.write_all(&bytes).map_err(io)?;
        file.sync_all().map_err(io)?;
        fs::rename(temp, dest).map_err(io)?;
        File::open(&self.dir).map_err(io)?.sync_all().map_err(io)
    }
    fn require_head(&self, expected: Hash) -> Result<()> {
        require(
            self.healthy,
            "wallet requires reopen after persistence failure",
        )?;
        require(
            self.journal.head()? == expected,
            "caller-retained wallet head rejects stale backup or request",
        )
    }
    fn reserved(&self, node: &Store) -> Result<BTreeSet<Hash>> {
        let mut result = BTreeSet::new();
        for record in &self.journal.records {
            if outcome(node, record, node.chain.height())? == "SIGNED_PENDING_INCLUSION" {
                result.extend(
                    record
                        .draft
                        .input_owners
                        .iter()
                        .filter(|(_, owner)| *owner == &self.journal.binding.owner)
                        .map(|(id, _)| *id),
                );
            }
        }
        Ok(result)
    }
    pub fn view(&self, node: &Store, expected: Hash) -> Result<View> {
        self.require_head(expected)?;
        self.journal.validate(node)?;
        let mut ledger = wallet::view(node, &self.journal.binding.owner)?;
        ledger.pending_signed_intents_tracked = true;
        let reserved = self.reserved(node)?;
        let exposure = node.safety.exposure(&node.chain, &node.evidence)?;
        let local_region_quarantined = node.safety.regions.contains_key(&node.chain.region);
        let retained = sum(ledger
            .coins
            .iter()
            .filter(|c| reserved.contains(&c.id))
            .map(|c| c.amount))?;
        let available = sum(ledger
            .coins
            .iter()
            .filter(|c| c.spendable_now && !reserved.contains(&c.id))
            .map(|c| c.amount))?;
        let available_onward_export = sum(ledger
            .coins
            .iter()
            .filter(|c| c.eligible_for_onward_export && !reserved.contains(&c.id))
            .map(|c| c.amount))?;
        let signed = self
            .journal
            .records
            .iter()
            .map(|r| {
                Ok(Pending {
                    intent_id: r.draft.intent_id,
                    intent: r.draft.intent.clone(),
                    inputs: r.draft.intent.inputs.clone(),
                    valid_through: r.draft.intent.valid_through,
                    state: outcome(node, r, node.chain.height())?,
                    required_owners: wallet::required_owners(&r.draft),
                    retained_approvals_complete: r.draft.request.participants.is_empty(),
                    quarantined: local_region_quarantined
                        || exposure
                            .affected_historical_exports
                            .contains(&r.draft.intent_id)
                        || r.draft
                            .intent
                            .inputs
                            .iter()
                            .any(|i| exposure.quarantined_coins.contains(i)),
                    local_export_finalized: !exposure
                        .affected_historical_exports
                        .contains(&r.draft.intent_id)
                        && node
                            .chain
                            .ledger
                            .exports
                            .get(&r.draft.intent_id)
                            .map(|export| {
                                node.chain
                                    .finalized
                                    .and_then(|s| node.evidence.snapshot(s).ok())
                                    .map(|s| export.height <= s.statement.height)
                                    .unwrap_or(false)
                            })
                            .unwrap_or(false),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(View {
            ledger,
            wallet_head: self.journal.head()?,
            available,
            available_onward_export,
            reserved_owned_outputs: retained,
            signed,
            external_rollback_anchor_qualified: false,
            local_region_quarantined,
            incident_ids: node
                .conflicts
                .iter()
                .map(|p| p.id())
                .collect::<Result<Vec<_>>>()?,
        })
    }
    pub fn prepare(&self, node: &Store, request: Request, expected: Hash) -> Result<Prepared> {
        self.require_head(expected)?;
        self.journal.validate(node)?;
        require(
            request.owner == self.journal.binding.owner,
            "wallet request belongs to another owner",
        )?;
        let draft = wallet::prepare_with_reserved(node, request, &self.reserved(node)?)?;
        Ok(Prepared {
            review_commitment: id("wallet-reviewed-draft", &draft)?,
            draft,
            wallet_head: expected,
        })
    }
    pub fn recover(&self, node: &Store, intent: Hash, expected: Hash) -> Result<Signed> {
        self.require_head(expected)?;
        self.journal.validate(node)?;
        let record = self
            .journal
            .records
            .iter()
            .find(|r| r.draft.intent_id == intent)
            .ok_or("wallet signed intent not retained")?;
        Ok(Signed {
            commands: vec![record.command.clone()],
            intent_id: intent,
            previous_wallet_head: record.previous_head,
            wallet_head: expected,
            state: outcome(node, record, node.chain.height())?,
            recovered_exact_retry: true,
            required_owners: wallet::required_owners(&record.draft),
            retained_approvals_complete: record.draft.request.participants.is_empty(),
        })
    }
    pub fn sign(
        &mut self,
        node: &Store,
        draft: Draft,
        key_file: &Path,
        review: Hash,
        expected: Hash,
    ) -> Result<Signed> {
        self.sign_using(node, draft, key_file, review, expected, None)
    }
    pub fn sign_encrypted(
        &mut self,
        node: &Store,
        draft: Draft,
        key_file: &Path,
        review: Hash,
        expected: Hash,
        passphrase: &[u8],
    ) -> Result<Signed> {
        self.sign_using(node, draft, key_file, review, expected, Some(passphrase))
    }
    fn sign_using(
        &mut self,
        node: &Store,
        draft: Draft,
        key_file: &Path,
        review: Hash,
        expected: Hash,
        passphrase: Option<&[u8]>,
    ) -> Result<Signed> {
        require(
            self.healthy,
            "wallet requires reopen after persistence failure",
        )?;
        self.journal.validate(node)?;
        let head = self.journal.head()?;
        require(
            review == id("wallet-reviewed-draft", &draft)?,
            "wallet review commitment differs",
        )?;
        if let Some((n, r)) = self
            .journal
            .records
            .iter()
            .enumerate()
            .find(|(_, r)| r.draft == draft && r.review_commitment == review)
        {
            require(
                expected == head
                    || (n + 1 == self.journal.records.len() && expected == r.previous_head),
                "wallet retry uses stale head",
            )?;
            return Ok(Signed {
                commands: vec![r.command.clone()],
                intent_id: r.draft.intent_id,
                previous_wallet_head: r.previous_head,
                wallet_head: head,
                state: outcome(node, r, node.chain.height())?,
                recovered_exact_retry: true,
                required_owners: wallet::required_owners(&r.draft),
                retained_approvals_complete: r.draft.request.participants.is_empty(),
            });
        }
        self.require_head(expected)?;
        require(
            self.journal.records.len() < MAX_SIGNED,
            "wallet signed-record capacity full; retained commands remain",
        )?;
        require(
            draft.request.owner == self.journal.binding.owner,
            "wallet draft belongs to another owner",
        )?;
        let command = wallet::sign_with_reserved_key(
            node,
            draft.clone(),
            key_file,
            review,
            &self.reserved(node)?,
            passphrase,
        )?;
        let record = Record {
            previous_head: head,
            observation: Observation::current(node)?,
            draft,
            review_commitment: review,
            command,
        };
        let mut journal = self.journal.clone();
        journal.records.push(record.clone());
        journal.validate(node)?;
        if let Err(error) = self.persist(&journal) {
            self.healthy = false;
            return Err(error);
        }
        self.journal = journal;
        Ok(Signed {
            required_owners: wallet::required_owners(&record.draft),
            retained_approvals_complete: record.draft.request.participants.is_empty(),
            commands: vec![record.command],
            intent_id: record.draft.intent_id,
            previous_wallet_head: head,
            wallet_head: self.journal.head()?,
            state: "SIGNED_PENDING_INCLUSION",
            recovered_exact_retry: false,
        })
    }
}
