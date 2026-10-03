//! A separately locked signer journal. A caller-retained expected head prevents
//! stale-directory reuse when that external pin survives. Joint rollback of all
//! state/pins or access to copied private keys is outside this mechanism.
use super::*;
use crate::{
    epoch::{Registry, Transition},
    storage::{read_json, safe_dir, Store},
};
use ed25519_dalek::{Signer as _, SigningKey};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;
pub const MAX_VOTES: usize = 128;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub currency: Hash,
    pub region: Hash,
    pub key: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum Request {
    Checkpoint(Box<Snapshot>),
    Handoff {
        proposal: Box<Transition>,
        previous_epochs: Vec<Transition>,
    },
}
impl Request {
    fn bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::Checkpoint(s) => s.statement.bytes(),
            Self::Handoff { proposal, .. } => proposal
                .statement
                .approval_bytes(crate::joint_epoch::Role::New),
        }
    }
    fn validate(&self, trust: &Trust, binding: &Binding) -> Result<()> {
        match self {
            Self::Checkpoint(snapshot) => {
                require(
                    !crate::bft::is_profile(&trust.region(binding.region)?.rules),
                    "BFT region cannot sign a legacy unanimous checkpoint",
                )?;
                require(
                    snapshot.approvals.is_empty()
                        && snapshot.statement.currency == binding.currency
                        && snapshot.statement.region == binding.region
                        && !snapshot.blocks.is_empty()
                        && snapshot.blocks.len() <= MAX_BLOCKS,
                    "invalid signer checkpoint request",
                )?;
                let registry = Registry::verify_chain(trust, binding.region, &snapshot.epochs)?;
                let keys = registry.checkpoint_keys(trust, &snapshot.statement)?;
                require(
                    keys.contains(&binding.key),
                    "key is not active in checkpoint era",
                )?;
                let headers = snapshot
                    .blocks
                    .iter()
                    .map(|b| b.header.clone())
                    .collect::<Vec<_>>();
                if trust.region(binding.region)?.rules == crate::segmented::RULES {
                    crate::segmented::shape(snapshot, trust)?;
                    crate::segmented::headers(&snapshot.statement, &headers, trust)?;
                    for block in &snapshot.blocks {
                        require(
                            block.header.commands == id("commands", &block.commands)?,
                            "segmented signer command commitment",
                        )?;
                    }
                    return Ok(());
                }
                for proof in &snapshot.epochs {
                    require(
                        headers.starts_with(&proof.closing.headers),
                        "checkpoint forks from its handoff closing prefix",
                    )?;
                }
                let mut parent = binding.region;
                for (i, block) in snapshot.blocks.iter().enumerate() {
                    let h = &block.header;
                    require(
                        h.currency == binding.currency
                            && h.region == binding.region
                            && h.height == i as u64 + 1
                            && h.parent == parent
                            && h.commands == id("commands", &block.commands)?
                            && h.work_valid()?,
                        "signer request does not commit exact mined history",
                    )?;
                    validate_ed25519_public_key(&h.miner)?;
                    parent = h.id()?;
                }
                require(
                    snapshot.statement.height == snapshot.blocks.len() as u64
                        && snapshot.statement.block == parent
                        && snapshot
                            .blocks
                            .last()
                            .is_some_and(|b| b.header.state == snapshot.statement.state),
                    "signer terminal statement differs from history",
                )
            }
            Self::Handoff {
                proposal,
                previous_epochs,
            } => {
                require(
                    trust.region(binding.region)?.rules != crate::bft::ROLE_RULES,
                    "role-scoped readiness requires a separate native purpose-bound journal",
                )?;
                require(
                    proposal.old_approvals.is_empty()
                        && proposal.new_approvals.is_empty()
                        && proposal.statement.region == binding.region
                        && proposal.statement.currency == binding.currency,
                    "handoff request contains approvals or wrong identity",
                )?;
                let registry = Registry::verify_chain(trust, binding.region, previous_epochs)?;
                let (previous, number, keys, floor) = registry.latest(trust, binding.region)?;
                proposal.validate_request(trust, previous, number, &keys, floor)?;
                registry.fresh_bft_keys(trust, binding.region, &proposal.statement.validators)?;
                if crate::bft::has_epochs(&trust.region(binding.region)?.rules) {
                    require(
                        !keys.contains(&binding.key)
                            && proposal.statement.validators.contains(&binding.key),
                        "old BFT keys must fence through their original BFT signer journal",
                    )?;
                }
                require(
                    keys.contains(&binding.key)
                        || proposal.statement.validators.contains(&binding.key),
                    "key has no old/new handoff role",
                )
            }
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub previous_head: Hash,
    pub request: Request,
    pub approval: Approval,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    pub binding: Binding,
    pub records: Vec<Record>,
}
impl Journal {
    pub fn head(&self) -> Result<Hash> {
        id("signer-lock-journal", self)
    }
    fn validate(&self, trust: &Trust) -> Result<()> {
        require(
            self.binding.currency == trust.currency()? && self.records.len() <= MAX_VOTES,
            "signer identity or vote count mismatch",
        )?;
        trust.region(self.binding.region)?;
        validate_ed25519_public_key(&self.binding.key)?;
        let mut prefix = Self {
            binding: self.binding.clone(),
            records: vec![],
        };
        for record in &self.records {
            require(
                record.previous_head == prefix.head()? && record.approval.key == self.binding.key,
                "signer lock predecessor or identity mismatch",
            )?;
            prefix.check_next(&record.request, trust)?;
            verify_bytes(
                &record.approval.key,
                &record.request.bytes()?,
                &record.approval.signature,
            )?;
            prefix.records.push(record.clone());
        }
        encode("signer-journal", self)?;
        Ok(())
    }
    fn check_next(&self, request: &Request, trust: &Trust) -> Result<()> {
        request.validate(trust, &self.binding)?;
        let last = self.records.iter().rev().find_map(|r| match &r.request {
            Request::Checkpoint(s) => Some(s.as_ref()),
            _ => None,
        });
        match request {
            Request::Checkpoint(snapshot) => {
                for r in &self.records {
                    if let Request::Handoff { proposal, .. } = &r.request {
                        require(
                            snapshot.statement.epoch != proposal.statement.previous_epoch,
                            "era was sealed; no further old-key checkpoints",
                        )?;
                    }
                }
                if let Some(previous) = last {
                    let prefix =
                        if trust.region(self.binding.region)?.rules == crate::segmented::RULES {
                            snapshot.base == Some(previous.statement.id()?)
                                && snapshot.blocks.first().is_some_and(|block| {
                                    block.header.height == previous.statement.height + 1
                                        && block.header.parent == previous.statement.block
                                })
                        } else {
                            snapshot.blocks.starts_with(&previous.blocks)
                        };
                    require(
                        snapshot.statement.height > previous.statement.height
                            && prefix
                            && snapshot.statement.previous == Some(previous.statement.id()?),
                        "checkpoint violates durable prefix or predecessor lock",
                    )?;
                } else {
                    let consent = self.records.iter().rev().find_map(|r| match &r.request {
                        Request::Handoff { proposal, .. }
                            if proposal.statement.id().ok() == Some(snapshot.statement.epoch) =>
                        {
                            Some(proposal.as_ref())
                        }
                        _ => None,
                    });
                    if let Some(proposal) = consent {
                        require(
                            snapshot.statement.previous
                                == Some(proposal.statement.closing_checkpoint),
                            "joining signer must extend its consented closing checkpoint",
                        )?;
                    } else {
                        require(
                            snapshot.statement.epoch
                                == Registry::initial(trust, self.binding.region)?
                                && snapshot.statement.previous.is_none(),
                            "existing-era signer requires original lock history or joint consent",
                        )?;
                    }
                }
                Ok(())
            }
            Request::Handoff {
                proposal,
                previous_epochs,
            } => {
                for r in &self.records {
                    if let Request::Handoff { proposal: old, .. } = &r.request {
                        require(
                            old.statement.previous_epoch != proposal.statement.previous_epoch,
                            "previous era already sealed for one handoff",
                        )?;
                    }
                }
                let registry = Registry::verify_chain(trust, self.binding.region, previous_epochs)?;
                let (_, _, old_keys, _) = registry.latest(trust, self.binding.region)?;
                if old_keys.contains(&self.binding.key) {
                    require(
                        last.is_some_and(|s| {
                            s.statement.id().ok() == Some(proposal.statement.closing_checkpoint)
                        }),
                        "old signer must have voted for the exact closing checkpoint",
                    )?;
                }
                if let Some(last) = last {
                    require(
                        last.statement.height <= proposal.statement.closing_height
                            && proposal.closing.headers.starts_with(
                                &last
                                    .blocks
                                    .iter()
                                    .map(|b| b.header.clone())
                                    .collect::<Vec<_>>(),
                            ),
                        "handoff violates existing signed prefix",
                    )?;
                }
                Ok(())
            }
        }
    }
}
#[derive(Debug, Serialize)]
pub struct Receipt {
    pub approval: Approval,
    pub previous_head: Hash,
    pub lock_head: Hash,
    pub request_id: Hash,
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
impl Agent {
    pub fn create(dir: &Path, node: &Store, key: String) -> Result<Self> {
        validate_ed25519_public_key(&key)?;
        node.safety.check_region(node.chain.region)?;
        let mut known = node.trust.region(node.chain.region)?.validators.clone();
        for proof in node.evidence.epoch_proofs(node.chain.region) {
            known.extend(proof.statement.validators);
        }
        require(node.chain.finalized.is_none() || !known.contains(&key),"authorized key cannot initialize a fresh late signer; retain its original lock journal")?;
        safe_dir(dir.parent().ok_or("signer parent missing")?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(dir).map_err(io)?;
        }
        #[cfg(not(unix))]
        fs::create_dir(dir).map_err(io)?;
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
                key,
            },
            records: vec![],
        };
        journal.validate(&node.trust)?;
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
        let lockpath = dir.join("LOCK");
        let meta = fs::symlink_metadata(&lockpath).map_err(io)?;
        require(
            meta.is_file() && !meta.file_type().is_symlink(),
            "unsafe signer lock",
        )?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(lockpath)
            .map_err(io)?;
        lock.try_lock().map_err(|e| e.to_string())?;
        let journal: Journal = read_json(&dir.join("signer.json"))?;
        journal.validate(&node.trust)?;
        require(
            journal.binding.region == node.chain.region,
            "signer belongs to another region",
        )?;
        Ok(Self {
            dir: dir.into(),
            _lock: lock,
            journal,
            healthy: true,
        })
    }
    fn persist(&self, journal: &Journal) -> Result<()> {
        let bytes = serde_json::to_vec(journal).map_err(|e| e.to_string())?;
        require(bytes.len() <= MAX_BYTES, "signer journal byte bound")?;
        let dest = self.dir.join("signer.json");
        if dest.exists() {
            let meta = fs::symlink_metadata(&dest).map_err(io)?;
            require(
                meta.is_file() && !meta.file_type().is_symlink(),
                "unsafe signer journal",
            )?;
        }
        let temp = self.dir.join("signer.next");
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
    pub fn checkpoint(&mut self, node: &Store, key_file: &Path, expected: Hash) -> Result<Receipt> {
        self.vote(
            node,
            Request::Checkpoint(Box::new(node.snapshot_request()?)),
            key_file,
            expected,
        )
    }
    pub fn handoff(
        &mut self,
        node: &Store,
        proposal: Transition,
        key_file: &Path,
        expected: Hash,
    ) -> Result<Receipt> {
        require(
            proposal.statement.previous_epoch == node.chain.epoch
                && node.chain.finalized == Some(proposal.statement.closing_checkpoint),
            "handoff does not close the node's installed current era",
        )?;
        if crate::bft::is_joint(&node.trust.region(node.chain.region)?.rules) {
            let closing = node
                .evidence
                .snapshot(proposal.statement.closing_checkpoint)?;
            crate::joint_epoch::closing_matches(&proposal, closing)?;
        }
        let previous_epochs = node.snapshot_request()?.epochs;
        self.vote(
            node,
            Request::Handoff {
                proposal: Box::new(proposal),
                previous_epochs,
            },
            key_file,
            expected,
        )
    }
    /// Recover only an exact already durable handoff, including after activation.
    /// A missing record cannot fall through to a fresh signature or head adoption.
    pub fn recover_handoff(
        &self,
        node: &Store,
        proposal: &Transition,
        expected: Hash,
    ) -> Result<Receipt> {
        node.safety.check_region(node.chain.region)?;
        let current = self.journal.head()?;
        let (index,record)=self.journal.records.iter().enumerate().find(|(_,r)| {
            matches!(&r.request,Request::Handoff{proposal:p,..} if p.as_ref()==proposal)
        }).ok_or("handoff recovery cannot first-sign")?;
        require(
            expected == current
                || (index + 1 == self.journal.records.len() && expected == record.previous_head),
            "handoff recovery rejects stale caller head",
        )?;
        if crate::bft::is_joint(&node.trust.region(node.chain.region)?.rules) {
            crate::joint_epoch::closing_matches(
                proposal,
                node.evidence
                    .snapshot(proposal.statement.closing_checkpoint)?,
            )?;
        }
        Ok(Receipt {
            approval: record.approval.clone(),
            previous_head: record.previous_head,
            lock_head: current,
            request_id: id("signer-request", &record.request)?,
        })
    }
    fn vote(
        &mut self,
        node: &Store,
        request: Request,
        key_file: &Path,
        expected: Hash,
    ) -> Result<Receipt> {
        require(
            self.healthy,
            "signer requires reopen after persistence failure",
        )?;
        node.safety.check_region(node.chain.region)?;
        let current = self.journal.head()?;
        if let Some(last) = self.journal.records.last() {
            if last.request == request && (expected == current || expected == last.previous_head) {
                return Ok(Receipt {
                    approval: last.approval.clone(),
                    previous_head: last.previous_head,
                    lock_head: current,
                    request_id: id("signer-request", &request)?,
                });
            }
        }
        require(
            expected == current,
            "caller-retained signer head rejects stale backup or response",
        )?;
        self.journal.check_next(&request, &node.trust)?;
        require(
            self.journal.records.len() < MAX_VOTES,
            "signer lock capacity full",
        )?;
        let approval = read_and_sign(key_file, &self.journal.binding.key, &request.bytes()?)?;
        let mut journal = self.journal.clone();
        journal.records.push(Record {
            previous_head: current,
            request: request.clone(),
            approval: approval.clone(),
        });
        journal.validate(&node.trust)?;
        if let Err(error) = self.persist(&journal) {
            self.healthy = false;
            return Err(error);
        }
        self.journal = journal;
        Ok(Receipt {
            approval,
            previous_head: current,
            lock_head: self.journal.head()?,
            request_id: id("signer-request", &request)?,
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    secret_key: String,
}
pub(crate) fn read_and_sign(path: &Path, expected: &str, bytes: &[u8]) -> Result<Approval> {
    let meta = fs::symlink_metadata(path).map_err(io)?;
    require(
        meta.is_file() && !meta.file_type().is_symlink() && meta.len() <= 256,
        "unsafe signing key input",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        require(
            meta.permissions().mode() & 0o077 == 0,
            "signing key file must be private",
        )?;
    }
    let raw = Zeroizing::new(fs::read(path).map_err(io)?);
    let input: KeyFile = serde_json::from_slice(&raw).map_err(|_| "invalid signing key file")?;
    let secret = Zeroizing::new(input.secret_key);
    let decoded =
        Zeroizing::new(hex::decode(&*secret).map_err(|_| "invalid signing key material")?);
    let seed = Zeroizing::new(
        <[u8; 32]>::try_from(decoded.as_slice())
            .map_err(|_| "signing key must be a 32-byte seed")?,
    );
    let signing = SigningKey::from_bytes(&seed);
    let public = hex::encode(signing.verifying_key().to_bytes());
    require(public == expected, "key file does not match pinned signer")?;
    Ok(Approval {
        key: public,
        signature: hex::encode(signing.sign(bytes).to_bytes()),
    })
}
