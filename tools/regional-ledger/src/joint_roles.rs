//! Purpose-bound New readiness custody for the separately admitted role profile.
//! This journal never votes for a block or substitutes for an old BFT fence.
use super::*;
use crate::{
    joint_epoch::{CarriedApproval, Role},
    storage::Store,
    wallet_agent::Observation,
};
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReadyRequest {
    pub proposal: Box<epoch::Transition>,
    pub previous_epochs: Vec<epoch::Transition>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReadyBinding {
    pub currency: Hash,
    pub region: Hash,
    pub key: String,
    pub role: Role,
    pub statement: Hash,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReadyCreation {
    pub binding: ReadyBinding,
    pub creation: Observation,
    pub head: Hash,
    pub scope: ReadyRequest,
}
impl ReadyCreation {
    pub fn observe(journal: &ReadyJournal) -> Result<Self> {
        require(
            journal.approval.is_none(),
            "initial readiness already approved",
        )?;
        Ok(Self {
            binding: journal.binding.clone(),
            creation: journal.creation.clone(),
            head: journal.head()?,
            scope: ReadyRequest {
                proposal: journal.scope.proposal.clone(),
                previous_epochs: journal.scope.previous_epochs.clone(),
            },
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VoterCreation {
    pub binding: bft::Binding,
    pub creation: Observation,
    pub head: Hash,
}
impl VoterCreation {
    pub fn observe(journal: &bft::Journal) -> Result<Self> {
        require(
            journal.records.is_empty() && journal.origin.is_some(),
            "initial role voter is not empty purpose-bound custody",
        )?;
        Ok(Self {
            binding: journal.binding.clone(),
            creation: journal.creation.clone(),
            head: journal.head()?,
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReadyJournal {
    pub format: String,
    pub binding: ReadyBinding,
    pub creation: Observation,
    pub scope: CarriedApproval,
    pub approval: Option<Approval>,
}
impl ReadyJournal {
    pub fn head(&self) -> Result<Hash> {
        id("bft-joint-ready-journal-v1", self)
    }
    pub fn carried(&self) -> Result<CarriedApproval> {
        let mut result = self.scope.clone();
        result.approval = self
            .approval
            .clone()
            .ok_or("readiness recovery cannot first-sign")?;
        Ok(result)
    }
    pub fn validate(&self, node: &Store) -> Result<()> {
        let b = &self.binding;
        let s = &self.scope.proposal.statement;
        require(
            self.format == "RLD-BFT-JOINT-READY-JOURNAL-V1"
                && node.trust.region(b.region)?.rules == bft::ROLE_RULES
                && b.currency == node.trust.currency()?
                && b.region == node.chain.region
                && b.role == Role::New
                && b.statement == s.id()?
                && self.scope.role == Role::New
                && self.scope.approval.key == b.key
                && self.scope.approval.signature.is_empty(),
            "readiness purpose/identity binding",
        )?;
        self.creation.check(
            node,
            &wallet_agent::Binding {
                currency: b.currency,
                region: b.region,
                owner: b.key.clone(),
            },
        )?;
        require(
            self.creation.pin.epoch == s.previous_epoch
                && self.creation.pin.height == s.closing_height
                && self.creation.pin.finality == Some(s.closing_checkpoint),
            "readiness creation does not bind selected old boundary",
        )?;
        self.scope.verify_scope(&node.trust, &node.evidence)?;
        node.safety.check_region(b.region)?;
        if let Some(approval) = &self.approval {
            require(
                approval.key == b.key,
                "readiness approval key differs from journal owner",
            )?;
            self.carried()?.verify(&node.trust, &node.evidence)?;
        }
        encode("bft-joint-ready-journal-v1", self)?;
        Ok(())
    }
    fn current_boundary(&self, node: &Store) -> Result<()> {
        let s = &self.scope.proposal.statement;
        require(
            node.chain.epoch == s.previous_epoch
                && node.chain.height() == s.closing_height
                && node.chain.finalized == Some(s.closing_checkpoint),
            "fresh readiness needs exact installed old closing boundary",
        )
    }
}

#[derive(Debug, Serialize)]
pub struct ReadyReceipt {
    pub approval: CarriedApproval,
    pub previous_head: Hash,
    pub head: Hash,
    pub recovered_exact_retry: bool,
}
/// Immutable full native provenance, never a hash-only grant of voting rights.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VoterOrigin {
    pub format: String,
    pub proof: Box<epoch::Transition>,
    pub old: Option<Box<bft::Journal>>,
    pub old_head: Option<Hash>,
    pub ready: ReadyJournal,
    pub ready_head: Hash,
}
impl VoterOrigin {
    pub(crate) fn validate(
        &self,
        node: &Store,
        journal: &bft::Journal,
        depth: usize,
    ) -> Result<()> {
        require(depth < epoch::MAX_EPOCHS, "voter custody ancestry bound")?;
        let s = &self.proof.statement;
        require(
            self.format == "RLD-BFT-JOINT-VOTER-ORIGIN-V1"
                && node.trust.region(s.region)?.rules == bft::ROLE_RULES
                && s.currency == journal.binding.currency
                && s.region == journal.binding.region
                && journal.creation.pin.epoch == s.id()?
                && journal.creation.pin.height == s.closing_height
                && journal.creation.pin.finality == Some(s.closing_checkpoint)
                && self.ready.binding.key == journal.binding.key,
            "voter custody activation/creation identity",
        )?;
        self.ready.validate(node)?;
        self.ready.carried()?.verify(&node.trust, &node.evidence)?;
        require(
            self.ready.head()? == self.ready_head,
            "voter readiness head differs",
        )?;
        // Both complete witnesses authenticate independently. A closing
        // checkpoint can have different valid ordered quorum subsets; retain
        // each exact witness rather than require identical certificate bytes.
        let mut checked = node.evidence.clone();
        checked.install_epoch(*self.proof.clone(), &node.trust)?;
        require(
            self.proof.statement == self.ready.scope.proposal.statement,
            "voter readiness selected a different handoff",
        )?;
        let prior = epoch::Registry::verify_chain(
            &node.trust,
            s.region,
            &self.ready.scope.previous_epochs,
        )?;
        let (_, _, old_keys, _) = prior.latest(&node.trust, s.region)?;
        let eid = s.id()?;
        require(
            node.evidence
                .epoch_proofs(s.region)
                .iter()
                .any(|p| p.statement.id().ok() == Some(eid)),
            "voter activation missing from native evidence",
        )?;
        if old_keys.contains(&journal.binding.key) {
            let old = self
                .old
                .as_deref()
                .ok_or("continuing voter needs original old journal")?;
            require(
                old.binding == journal.binding
                    && old.creation.pin.epoch == s.previous_epoch
                    && Some(old.head()?) == self.old_head
                    && old.state_at_depth(node, depth + 1)?.epoch_fence == Some(s.id()?),
                "continuing voter lacks exact native fenced custody/head",
            )?;
        } else {
            require(
                self.old.is_none() && self.old_head.is_none(),
                "joining voter has unexpected old custody",
            )?;
        }
        Ok(())
    }
}
pub struct ReadyAgent {
    dir: PathBuf,
    _lock: File,
    pub journal: ReadyJournal,
    healthy: bool,
}
fn io(error: std::io::Error) -> String {
    error.to_string()
}
impl ReadyAgent {
    pub fn initial_journal(
        node: &Store,
        key: String,
        request: ReadyRequest,
    ) -> Result<ReadyJournal> {
        let statement = request.proposal.statement.id()?;
        let journal = ReadyJournal {
            format: "RLD-BFT-JOINT-READY-JOURNAL-V1".into(),
            binding: ReadyBinding {
                currency: node.trust.currency()?,
                region: node.chain.region,
                key: key.clone(),
                role: Role::New,
                statement,
            },
            creation: Observation::current(node)?,
            scope: CarriedApproval {
                format: "RLD-JOINT-EPOCH-APPROVAL-V2".into(),
                proposal: request.proposal,
                previous_epochs: request.previous_epochs,
                role: Role::New,
                approval: Approval {
                    key,
                    signature: String::new(),
                },
            },
            approval: None,
        };
        journal.validate(node)?;
        journal.current_boundary(node)?;
        journal.head()?; // Complete bounded validation precedes creating any target.
        Ok(journal)
    }
    pub fn create(dir: &Path, node: &Store, key: String, request: ReadyRequest) -> Result<Self> {
        let journal = Self::initial_journal(node, key, request)?;
        storage::safe_dir(dir.parent().ok_or("readiness parent missing")?)?;
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(dir).map_err(io)?;
        keystore::private_create(&dir.join("LOCK"), b"")?;
        let agent = Self {
            dir: dir.into(),
            _lock: bft::lock(dir)?,
            journal,
            healthy: true,
        };
        agent.persist(&agent.journal)?;
        Ok(agent)
    }
    pub fn recover_creation(dir: &Path, node: &Store, marker: &ReadyCreation) -> Result<Self> {
        let lock = bft::lock(dir)?;
        let retained = dir.join("ready.json");
        let next = dir.join("ready.next");
        let has_retained = retained_file(&retained)?;
        let has_next = retained_file(&next)?;
        require(
            has_retained != has_next,
            "readiness creation needs exactly one retained empty journal",
        )?;
        let path = if has_retained { &retained } else { &next };
        let journal: ReadyJournal =
            serde_json::from_slice(&keystore::private_read(path, MAX_BYTES)?)
                .map_err(|_| "invalid retained readiness creation")?;
        journal.validate(node)?;
        require(
            ReadyCreation::observe(&journal)? == *marker,
            "readiness creation differs from separately retained marker",
        )?;
        File::open(path).map_err(io)?.sync_all().map_err(io)?;
        if !has_retained {
            fs::rename(&next, &retained).map_err(io)?;
        }
        File::open(dir).map_err(io)?.sync_all().map_err(io)?;
        Ok(Self {
            dir: dir.into(),
            _lock: lock,
            journal,
            healthy: true,
        })
    }
    pub fn open(dir: &Path, node: &Store) -> Result<Self> {
        let lock = bft::lock(dir)?;
        let journal: ReadyJournal =
            serde_json::from_slice(&keystore::private_read(&dir.join("ready.json"), MAX_BYTES)?)
                .map_err(|_| "invalid readiness journal")?;
        journal.validate(node)?;
        let mut agent = Self {
            dir: dir.into(),
            _lock: lock,
            journal,
            healthy: true,
        };
        let next = dir.join("ready.next");
        let next_exists = match fs::symlink_metadata(&next) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(io(error)),
        };
        if next_exists {
            let proposed: ReadyJournal =
                serde_json::from_slice(&keystore::private_read(&next, MAX_BYTES)?)
                    .map_err(|_| "invalid interrupted readiness journal")?;
            proposed.validate(node)?;
            require(
                agent.journal.approval.is_none()
                    && proposed.approval.is_some()
                    && proposed.binding == agent.journal.binding
                    && proposed.creation == agent.journal.creation
                    && proposed.scope == agent.journal.scope,
                "interrupted readiness is not exact signed extension",
            )?;
            File::open(&next).map_err(io)?.sync_all().map_err(io)?;
            fs::rename(next, dir.join("ready.json")).map_err(io)?;
            File::open(dir).map_err(io)?.sync_all().map_err(io)?;
            agent.journal = proposed;
        }
        Ok(agent)
    }
    fn persist(&self, journal: &ReadyJournal) -> Result<()> {
        let raw = serde_json::to_vec(journal).map_err(|_| "readiness journal encoding")?;
        require(raw.len() <= MAX_BYTES, "readiness journal byte capacity")?;
        let next = self.dir.join("ready.next");
        keystore::private_create(&next, &raw)?;
        fs::rename(next, self.dir.join("ready.json")).map_err(io)?;
        File::open(&self.dir).map_err(io)?.sync_all().map_err(io)
    }
    pub fn sign(
        &mut self,
        node: &Store,
        key: Option<&Path>,
        expected: Hash,
        recover_only: bool,
    ) -> Result<ReadyReceipt> {
        require(
            self.healthy,
            "readiness requires reopen after persistence failure",
        )?;
        self.journal.validate(node)?;
        let head = self.journal.head()?;
        if self.journal.approval.is_some() {
            let mut unsigned = self.journal.clone();
            unsigned.approval = None;
            let previous = unsigned.head()?;
            require(
                expected == head || expected == previous,
                "retained readiness has stale caller head",
            )?;
            return Ok(ReadyReceipt {
                approval: self.journal.carried()?,
                previous_head: previous,
                head,
                recovered_exact_retry: true,
            });
        }
        require(!recover_only, "readiness recovery cannot first-sign")?;
        require(expected == head, "readiness caller head differs")?;
        self.journal.current_boundary(node)?;
        let mut journal = self.journal.clone();
        journal.approval = Some(signer::read_and_sign(
            key.ok_or("new readiness requires explicit private key")?,
            &journal.binding.key,
            &journal.scope.proposal.statement.approval_bytes(Role::New)?,
        )?);
        journal.validate(node)?;
        if let Err(error) = self.persist(&journal) {
            self.healthy = false;
            return Err(error);
        }
        self.journal = journal;
        Ok(ReadyReceipt {
            approval: self.journal.carried()?,
            previous_head: head,
            head: self.journal.head()?,
            recovered_exact_retry: false,
        })
    }
}
pub(crate) fn retained_file(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io(error)),
    }
}
