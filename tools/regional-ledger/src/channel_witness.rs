//! Separately locked ground witness. A funding-pinned role authenticates every
//! complete owner creation/extension; its current journal is checked before a
//! new owner signature. Metadata never initializes native monetary state.
use super::*;
pub const FORMAT: &str = "RLD-NATIVE-CHANNEL-WITNESS-V2";
pub const MAX_ENTRIES: usize = crate::contact::MAX_CONTACTS;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct WitnessBinding {
    format: String,
    profile: Hash,
    currency: Hash,
    region: Hash,
    key: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
enum Payload {
    Birth(Box<Journal>),
    Advance(Box<Record>),
    Seal(Box<seal::SealRecord>),
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Entry {
    previous: Hash,
    payload: Payload,
    approval: Approval,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct WitnessJournal {
    binding: WitnessBinding,
    creation: Observation,
    entries: Vec<Entry>,
}
fn slot(binding: &Binding) -> Result<Hash> {
    id("channel-witness-owner-slot-v1", binding)
}
fn required_key(node: &Store, journal: &Journal) -> Result<String> {
    journal.validate(node)?;
    let cp = journal
        .creation
        .pin
        .finality
        .ok_or("owner creation checkpoint absent")?;
    let native = node
        .evidence
        .snapshots
        .get(&cp)
        .ok_or("creation checkpoint absent")?
        .1
        .channel_state
        .as_ref()
        .ok_or("funding absent")?;
    let escrow = native
        .book
        .channels
        .get(&journal.binding.channel)
        .ok_or("funding channel absent")?;
    match &escrow.funding.intent.action {
        c::Action::Open {
            witness: Some(key), ..
        } => Ok(key.clone()),
        _ => Err("no signed funding witness policy; custody is read-only".into()),
    }
}
impl WitnessJournal {
    fn head(&self) -> Result<Hash> {
        id("channel-freshness-witness-journal-v1", self)
    }
    fn bytes(&self, p: &Payload, previous: Hash) -> Result<Vec<u8>> {
        encode(
            "channel-freshness-witness-entry-v1",
            &(&self.binding, previous, p),
        )
    }
    fn replay(&self, node: &Store) -> Result<BTreeMap<Hash, Journal>> {
        encode("complete-native-channel-witness", self)?;
        require(
            self.binding.format == FORMAT
                && self.binding.profile == c::profile_hash()?
                && self.binding.currency == node.trust.currency()?
                && self.binding.region == node.chain.region
                && self.entries.len() <= MAX_ENTRIES,
            "witness domain/profile/bound",
        )?;
        validate_ed25519_public_key(&self.binding.key)?;
        self.creation.check(
            node,
            &OwnerBinding {
                currency: self.binding.currency,
                region: self.binding.region,
                owner: self.binding.key.clone(),
            },
        )?;
        let mut prefix = Self {
            binding: self.binding.clone(),
            creation: self.creation.clone(),
            entries: vec![],
        };
        let mut owners = BTreeMap::new();
        for e in &self.entries {
            require(
                e.previous == prefix.head()? && e.approval.key == self.binding.key,
                "witness prior head/key differs",
            )?;
            verify_bytes(
                &e.approval.key,
                &self.bytes(&e.payload, e.previous)?,
                &e.approval.signature,
            )?;
            match &e.payload {
                Payload::Birth(j) => {
                    require(
                        j.records.is_empty()
                            && required_key(node, j)? == self.binding.key
                            && !owners.contains_key(&slot(&j.binding)?),
                        "witness refuses repeated owner inception or different policy",
                    )?;
                    owners.insert(slot(&j.binding)?, *j.clone());
                }
                Payload::Advance(record) => {
                    seal::request_inceptions(node, &owners, &record.partial.request)?;
                    let owner = owners
                        .get_mut(&slot(&record.partial.binding)?)
                        .ok_or("witness owner inception absent")?;
                    require(
                        record.previous_head == owner.head()? && owner.records.len() < MAX_SIGNED,
                        "witness refuses forgotten highest signed owner state",
                    )?;
                    owner.records.push(*record.clone());
                    owner.validate(node)?;
                }
                Payload::Seal(record) => seal::validate(node, &self.binding, &owners, record)?,
            }
            prefix.entries.push(e.clone());
        }
        Ok(owners)
    }
}
pub struct Witness {
    dir: PathBuf,
    _lock: File,
    journal: WitnessJournal,
    pending: Option<WitnessJournal>,
    healthy: bool,
}
fn read(path: &Path) -> Result<WitnessJournal> {
    serde_json::from_slice(&crate::keystore::private_read(path, MAX_BYTES)?)
        .map_err(|e| e.to_string())
}
impl Witness {
    pub fn create(dir: &Path, node: &Store, key: String, native_head: Hash) -> Result<Self> {
        node.require_storage_head(native_head)?;
        validate_ed25519_public_key(&key)?;
        require(
            c::is_profile(&node.trust.region(node.chain.region)?.rules),
            "explicit witness profile required",
        )?;
        crate::storage::safe_dir(dir.parent().ok_or("witness parent absent")?)?;
        let mut d = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            d.mode(0o700);
        }
        d.create(dir).map_err(io)?;
        crate::keystore::private_create(
            &dir.join("CREATING"),
            b"incomplete witness creation; retain",
        )?;
        crate::keystore::private_create(&dir.join("LOCK"), b"")?;
        let journal = WitnessJournal {
            binding: WitnessBinding {
                format: FORMAT.into(),
                profile: c::profile_hash()?,
                currency: node.trust.currency()?,
                region: node.chain.region,
                key,
            },
            creation: Observation::current(node)?,
            entries: vec![],
        };
        journal.replay(node)?;
        let w = Self {
            dir: dir.into(),
            _lock: lock(dir)?,
            journal,
            pending: None,
            healthy: true,
        };
        w.persist(&w.journal)?;
        fs::remove_file(dir.join("CREATING")).map_err(io)?;
        File::open(dir).map_err(io)?.sync_all().map_err(io)?;
        File::open(dir.parent().unwrap())
            .map_err(io)?
            .sync_all()
            .map_err(io)?;
        Ok(w)
    }
    pub fn open(dir: &Path, node: &Store) -> Result<Self> {
        crate::storage::safe_dir(dir)?;
        require(
            !exists(&dir.join("CREATING"))? && !exists(&dir.join("RESTORING"))?,
            "witness creation/restore incomplete",
        )?;
        let lock = lock(dir)?;
        let journal = read(&dir.join("witness.json"))?;
        journal.replay(node)?;
        let pending = if exists(&dir.join("witness.next"))? {
            let next = read(&dir.join("witness.next"))?;
            next.replay(node)?;
            require(
                next.binding == journal.binding
                    && next.creation == journal.creation
                    && next.entries.len() == journal.entries.len() + 1
                    && next.entries.starts_with(&journal.entries),
                "pending witness is not exact signed extension",
            )?;
            Some(next)
        } else {
            None
        };
        Ok(Self {
            dir: dir.into(),
            _lock: lock,
            journal,
            pending,
            healthy: true,
        })
    }
    pub fn head(&self) -> Result<Hash> {
        self.journal.head()
    }
    fn current(&self, node: &Store, head: Hash) -> Result<BTreeMap<Hash, Journal>> {
        require(
            self.healthy && self.pending.is_none() && !head.is_zero() && self.head()? == head,
            "separately retained current witness head required; pending is recover-only",
        )?;
        self.journal.replay(node)
    }
    fn persist(&self, j: &WitnessJournal) -> Result<()> {
        let bytes = serde_json::to_vec(j).map_err(|e| e.to_string())?;
        require(
            bytes.len() <= MAX_BYTES,
            "combined witness index/evidence bound",
        )?;
        crate::keystore::private_create(&self.dir.join("witness.next"), &bytes)?;
        fs::rename(self.dir.join("witness.next"), self.dir.join("witness.json")).map_err(io)?;
        File::open(&self.dir).map_err(io)?.sync_all().map_err(io)
    }
    fn append(&mut self, node: &Store, payload: Payload, key: &Path, head: Hash) -> Result<()> {
        self.current(node, head)?;
        require(
            self.journal.entries.len() < MAX_ENTRIES,
            "witness full; prior commitments retained",
        )?;
        let mut proposed = self.journal.clone();
        let approval = crate::signer::read_and_sign(
            key,
            &proposed.binding.key,
            &proposed.bytes(&payload, head)?,
        )?;
        proposed.entries.push(Entry {
            previous: head,
            payload,
            approval,
        });
        proposed.replay(node)?;
        if let Err(e) = self.persist(&proposed) {
            self.healthy = false;
            return Err(e);
        }
        self.journal = proposed;
        Ok(())
    }
    fn exact_owner(&self, node: &Store, j: &Journal, head: Hash) -> Result<()> {
        let owners = self.current(node, head)?;
        require(
            owners.get(&slot(&j.binding)?) == Some(j),
            "live witness disagrees with exact retained owner journal; no reset/adoption",
        )
    }
    fn recover_for(&mut self, node: &Store, j: &Journal, expected: Hash) -> Result<()> {
        require(
            self.healthy,
            "witness handle failed; reopen before recovery",
        )?;
        let target = self.pending.as_ref().unwrap_or(&self.journal);
        let owners = target.replay(node)?;
        require(
            owners.get(&slot(&j.binding)?) == Some(j),
            "witness exact owner extension is absent; recovery cannot first attest",
        )?;
        let last = target.entries.last().ok_or("witness response absent")?;
        let exact_last = match &last.payload {
            Payload::Birth(b) => **b == *j,
            Payload::Advance(r) => j.records.last() == Some(r.as_ref()),
            Payload::Seal(_) => false,
        };
        require(
            expected == target.head()? || (expected == last.previous && exact_last),
            "witness recovery rejects stale head",
        )?;
        require(
            self.pending.is_none() || exact_last,
            "pending witness recovery requires this exact owner's retained response",
        )?;
        // All native/caller/complete-response predicates precede publication.
        if let Some(next) = &self.pending {
            File::open(self.dir.join("witness.next"))
                .map_err(io)?
                .sync_all()
                .map_err(io)?;
            fs::rename(self.dir.join("witness.next"), self.dir.join("witness.json")).map_err(io)?;
            File::open(&self.dir).map_err(io)?.sync_all().map_err(io)?;
            self.journal = next.clone();
            self.pending = None;
        }
        Ok(())
    }
}
#[derive(Debug, Serialize)]
pub struct Witnessed {
    pub owner: Response,
    pub witness_head: Hash,
    pub independent_operations_qualified: bool,
}
#[derive(Clone)]
pub struct Reviewed {
    pub request: Request,
    pub review: Hash,
    pub owner_head: Hash,
    pub native_head: Hash,
}
impl Agent {
    pub fn create(
        dir: &Path,
        node: &Store,
        channel: Hash,
        owner: String,
        native_head: Hash,
    ) -> Result<Self> {
        let _ = (dir, node, channel, owner, native_head);
        Err("witness required; bare fresh-directory creation is disabled".into())
    }
    pub fn prepare(
        &self,
        node: &Store,
        request: &Request,
        head: Hash,
        native_head: Hash,
    ) -> Result<Hash> {
        let _ = (node, request, head, native_head);
        Err("live authenticated witness required before new signing review".into())
    }
    pub fn sign(
        &mut self,
        node: &Store,
        request: Request,
        key: &Path,
        reviewed: Hash,
        head: Hash,
        native_head: Hash,
    ) -> Result<Response> {
        let _ = (node, request, key, reviewed, head, native_head);
        Err("live authenticated witness required; no bare first signing".into())
    }
    pub fn recover(
        &mut self,
        node: &Store,
        request: &Request,
        reviewed: Hash,
        head: Hash,
        native_head: Hash,
    ) -> Result<Response> {
        let _ = (node, request, reviewed, head, native_head);
        Err("witness-bound exact response recovery required".into())
    }
    pub fn create_witnessed(
        dir: &Path,
        node: &Store,
        channel: Hash,
        owner: String,
        native_head: Hash,
        w: &mut Witness,
        authorization: (&Path, Hash),
    ) -> Result<Self> {
        let (key, whead) = authorization;
        node.require_storage_head(native_head)?;
        let binding = Binding {
            purpose: PURPOSE.into(),
            profile: c::profile_hash()?,
            currency: node.trust.currency()?,
            region: node.chain.region,
            channel,
            owner,
        };
        let owners = w.current(node, whead)?;
        require(
            !owners.contains_key(&slot(&binding)?),
            "original owner inception retained; fresh-directory reset forbidden",
        )?;
        let preview = Journal {
            binding,
            creation: Observation::current(node)?,
            records: vec![],
        };
        require(
            required_key(node, &preview)? == w.journal.binding.key,
            "funding does not authorize this witness role",
        )?;
        let agent = Self::create_component(
            dir,
            node,
            channel,
            preview.binding.owner.clone(),
            native_head,
        )?;
        // Keep the owner read-only on any partially committed witness birth.
        crate::keystore::private_create(
            &dir.join("CREATING"),
            b"witness birth incomplete; retain original custody",
        )?;
        w.append(
            node,
            Payload::Birth(Box::new(agent.journal.clone())),
            key,
            whead,
        )?;
        fs::remove_file(dir.join("CREATING")).map_err(io)?;
        File::open(dir).map_err(io)?.sync_all().map_err(io)?;
        Ok(agent)
    }
    pub fn prepare_witnessed(
        &self,
        node: &Store,
        request: &Request,
        heads: (Hash, Hash),
        w: &Witness,
        whead: Hash,
    ) -> Result<Hash> {
        let (head, native_head) = heads;
        w.exact_owner(node, &self.journal, whead)?;
        seal::request_inceptions(node, &w.current(node, whead)?, request)?;
        self.prepare_component(node, request, head, native_head)
    }
    pub fn sign_witnessed(
        &mut self,
        node: &Store,
        input: Reviewed,
        key: &Path,
        w: &mut Witness,
        wkey: &Path,
        whead: Hash,
    ) -> Result<Witnessed> {
        let Reviewed {
            request,
            review: reviewed,
            owner_head: head,
            native_head,
        } = input;
        w.exact_owner(node, &self.journal, whead)?;
        seal::request_inceptions(node, &w.current(node, whead)?, &request)?;
        let response = self.sign_component(node, request, key, reviewed, head, native_head)?;
        w.append(
            node,
            Payload::Advance(Box::new(
                self.journal
                    .records
                    .last()
                    .ok_or("signed record missing")?
                    .clone(),
            )),
            wkey,
            whead,
        )?;
        Ok(Witnessed {
            owner: response,
            witness_head: w.head()?,
            independent_operations_qualified: false,
        })
    }
    /// Explicit first witness attestation only for a previously durable owner
    /// response; no owner key is read. This is not keyless recover-only.
    pub fn finish_witness(
        &mut self,
        node: &Store,
        input: &Reviewed,
        w: &mut Witness,
        wkey: &Path,
        whead: Hash,
    ) -> Result<Witnessed> {
        let Reviewed {
            request,
            review: reviewed,
            owner_head: head,
            native_head,
        } = input;
        let (reviewed, head, native_head) = (*reviewed, *head, *native_head);
        let retained = self.recovery_preview(node, request, reviewed, head, native_head)?;
        let target = self.pending.as_ref().unwrap_or(&self.journal);
        let record = target.records.last().ok_or("owner response absent")?;
        require(
            record.partial == retained.partial,
            "only last exact retained owner transition may be first attested",
        )?;
        let owners = w.current(node, whead)?;
        let old = owners
            .get(&slot(&self.journal.binding)?)
            .ok_or("witness inception absent")?;
        require(
            target.records.len() == old.records.len() + 1
                && target.records.starts_with(&old.records),
            "witness completion is not exact retained extension",
        )?;
        let record = record.clone();
        let response = self.recover_component(node, request, reviewed, head, native_head)?;
        w.append(node, Payload::Advance(Box::new(record)), wkey, whead)?;
        Ok(Witnessed {
            owner: response,
            witness_head: w.head()?,
            independent_operations_qualified: false,
        })
    }
    pub fn recover_witnessed(
        &mut self,
        node: &Store,
        input: &Reviewed,
        w: &mut Witness,
        whead: Hash,
    ) -> Result<Witnessed> {
        let Reviewed {
            request,
            review: reviewed,
            owner_head: head,
            native_head,
        } = input;
        let (reviewed, head, native_head) = (*reviewed, *head, *native_head);
        node.require_storage_head(native_head)?;
        require(
            reviewed == review(&self.journal.binding, request)?,
            "owner recovery review differs",
        )?;
        self.recovery_preview(node, request, reviewed, head, native_head)?;
        let target = self.pending.as_ref().unwrap_or(&self.journal);
        require(
            target
                .records
                .iter()
                .any(|r| r.partial.request == *request && r.review == reviewed),
            "response absent; no first signing in recovery",
        )?;
        w.recover_for(node, target, whead)?;
        let response = self.recover_component(node, request, reviewed, head, native_head)?;
        Ok(Witnessed {
            owner: response,
            witness_head: w.head()?,
            independent_operations_qualified: false,
        })
    }
}

#[cfg(test)]
#[path = "channel_witness_tests.rs"]
pub(super) mod tests;

#[path = "channel_seal.rs"]
mod seal;

pub use seal::Sealed;
