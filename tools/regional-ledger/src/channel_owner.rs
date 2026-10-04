//! Ground channel owner custody. Separate purpose-bound journals retain only
//! this owner's partial approval, never a peer signature, before response release.
use super::*;
use crate::{
    channel_receipt as r, channels as c,
    storage::Store,
    wallet_agent::{Binding as OwnerBinding, Observation},
};
use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};
pub const PURPOSE: &str = "RLD-NATIVE-CHANNEL-OWNER-V1";
pub const MAX_SIGNED: usize = crate::wallet_agent::MAX_SIGNED;
fn io(error: std::io::Error) -> String {
    error.to_string()
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub purpose: String,
    pub profile: Hash,
    pub currency: Hash,
    pub region: Hash,
    pub channel: Hash,
    pub owner: String,
}
impl Binding {
    fn owner(&self) -> OwnerBinding {
        OwnerBinding {
            currency: self.currency,
            region: self.region,
            owner: self.owner.clone(),
        }
    }
    fn validate(&self, node: &Store) -> Result<()> {
        require(
            self.purpose == PURPOSE
                && self.profile == c::profile_hash()?
                && self.currency == node.trust.currency()?
                && self.region == node.chain.region
                && c::is_profile(&node.trust.region(self.region)?.rules),
            "channel owner purpose/profile/domain mismatch",
        )?;
        validate_ed25519_public_key(&self.owner)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum Request {
    Initial {
        checkpoint: Hash,
        state: c::StateStatement,
    },
    Payment(Box<r::Receipt>),
}
impl Request {
    fn state(&self) -> &c::StateStatement {
        match self {
            Self::Initial { state, .. } => state,
            Self::Payment(r) => &r.next.statement,
        }
    }
    fn checkpoint(&self) -> Hash {
        match self {
            Self::Initial { checkpoint, .. } => *checkpoint,
            Self::Payment(r) => r.statement.checkpoint,
        }
    }
    fn verify(&self, node: &Store, binding: &Binding) -> Result<()> {
        encode("channel-owner-complete-request", self)?;
        let state = self.state();
        require(
            state.currency == binding.currency
                && state.region == binding.region
                && state.channel == binding.channel,
            "owner request domain differs",
        )?;
        let (_, ledger) = node
            .evidence
            .snapshots
            .get(&self.checkpoint())
            .ok_or("owner funding checkpoint absent")?;
        let native = ledger
            .channel_state
            .as_ref()
            .ok_or("owner checkpoint lacks funding")?;
        native.declaration.verify(&node.trust, binding.region)?;
        let escrow = native
            .book
            .channels
            .get(&binding.channel)
            .ok_or("owner funding channel absent")?;
        require(
            escrow.terms()?.0.contains(&binding.owner),
            "owner is not an actual funded party",
        )?;
        match self {
            Self::Initial { state, .. } => {
                require(
                    state.sequence == 0 && matches!(escrow.phase, c::Phase::Open),
                    "initial signing needs certified open initial funding",
                )?;
                escrow.verify_statement(state, binding.channel, &native.declaration)
            }
            Self::Payment(receipt) => receipt.verify_unsigned_anchor(&node.trust, &node.evidence),
        }
    }
    fn check_observation(&self, node: &Store, observation: &Observation) -> Result<()> {
        let snapshot = node.evidence.snapshot(self.checkpoint())?;
        let pin = &observation.pin;
        require(
            pin.finality == Some(self.checkpoint())
                && snapshot.statement.region == pin.region
                && snapshot.statement.currency == pin.currency
                && snapshot.statement.height == pin.height
                && snapshot.statement.block == pin.tip
                && snapshot.statement.state == pin.state
                && snapshot.statement.epoch == pin.epoch,
            "signing checkpoint differs from exact observed native prefix",
        )
    }
    fn check_current(&self, node: &Store, binding: &Binding) -> Result<()> {
        self.verify(node, binding)?;
        self.check_observation(node, &Observation::current(node)?)?;
        channel_safety(node, binding.channel)
    }
}
fn channel_safety(node: &Store, channel: Hash) -> Result<()> {
    node.safety.check_region(node.chain.region)?;
    let escrow = node
        .chain
        .ledger
        .channel_state
        .as_ref()
        .ok_or("current channel funding absent")?
        .book
        .channels
        .get(&channel)
        .ok_or("current channel absent")?;
    require(
        matches!(escrow.phase, c::Phase::Open),
        "new signing needs currently open channel",
    )?;
    node.safety.check_channels(&escrow.channel_dependencies)?;
    for dependency in &escrow.dependencies {
        node.safety
            .check_region(node.evidence.snapshot(*dependency)?.statement.region)?;
    }
    Ok(())
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Partial {
    pub binding: Binding,
    pub request: Request,
    pub state_approval: Approval,
    pub invoice_approval: Option<Approval>,
}
impl Partial {
    fn verify(&self, node: &Store) -> Result<()> {
        self.binding.validate(node)?;
        self.request.verify(node, &self.binding)?;
        require(
            self.state_approval.key == self.binding.owner,
            "partial state approval belongs to another party",
        )?;
        verify_bytes(
            &self.binding.owner,
            &self.request.state().bytes()?,
            &self.state_approval.signature,
        )?;
        match (&self.request, &self.invoice_approval) {
            (Request::Initial { .. }, None) => Ok(()),
            (Request::Payment(r), Some(a)) => {
                require(
                    a.key == self.binding.owner,
                    "partial invoice approval belongs to another party",
                )?;
                verify_bytes(&a.key, &r.statement.bytes()?, &a.signature)
            }
            _ => Err("owner partial invoice purpose differs".into()),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Record {
    previous_head: Hash,
    observation: Observation,
    review: Hash,
    partial: Partial,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Journal {
    binding: Binding,
    creation: Observation,
    records: Vec<Record>,
}
impl Journal {
    fn head(&self) -> Result<Hash> {
        id("channel-owner-journal-v1", self)
    }
    fn validate(&self, node: &Store) -> Result<()> {
        encode("complete-channel-owner-journal", self)?;
        self.binding.validate(node)?;
        require(
            self.records.len() <= MAX_SIGNED,
            "channel owner retained record capacity",
        )?;
        self.creation.check(node, &self.binding.owner())?;
        let checkpoint = self
            .creation
            .pin
            .finality
            .ok_or("owner creation funding certificate missing")?;
        let native = node
            .evidence
            .snapshots
            .get(&checkpoint)
            .ok_or("owner creation checkpoint absent")?
            .1
            .channel_state
            .as_ref()
            .ok_or("owner creation funding absent")?;
        let escrow = native
            .book
            .channels
            .get(&self.binding.channel)
            .ok_or("owner creation channel absent")?;
        let initial = Request::Initial {
            checkpoint,
            state: c::StateStatement {
                currency: self.binding.currency,
                region: self.binding.region,
                channel: self.binding.channel,
                sequence: 0,
                payouts: escrow.terms()?.2,
            },
        };
        initial.verify(node, &self.binding)?;
        initial.check_observation(node, &self.creation)?;
        let mut prefix = Self {
            binding: self.binding.clone(),
            creation: self.creation.clone(),
            records: vec![],
        };
        let mut invoices = BTreeSet::new();
        for record in &self.records {
            require(
                record.previous_head == prefix.head()?
                    && record.partial.binding == self.binding
                    && record.review == review(&self.binding, &record.partial.request)?,
                "channel owner journal head/review/binding differs",
            )?;
            record.observation.check(node, &self.binding.owner())?;
            require(
                record.observation.pin.height
                    >= prefix
                        .records
                        .last()
                        .map_or(self.creation.pin.height, |r| r.observation.pin.height),
                "owner signing observation moved backwards",
            )?;
            record.partial.verify(node)?;
            record
                .partial
                .request
                .check_observation(node, &record.observation)?;
            next_request(&prefix, &record.partial.request, &mut invoices)?;
            prefix.records.push(record.clone());
        }
        Ok(())
    }
}
fn next_request(journal: &Journal, request: &Request, invoices: &mut BTreeSet<Hash>) -> Result<()> {
    match (journal.records.last(), request) {
        (None, Request::Initial { .. }) => Ok(()),
        (Some(previous), Request::Payment(r)) => {
            let old = &previous.partial.request;
            require(
                r.prior.statement == *old.state()
                    && r.next.statement.sequence > old.state().sequence,
                "owner refuses replacement/omission of highest signed state",
            )?;
            let receipt = match old {
                Request::Initial { .. } => None,
                Request::Payment(p) => Some(p.id()?),
            };
            require(
                r.statement.previous_receipt == receipt
                    && invoices.insert(r.statement.expected.invoice),
                "owner receipt linkage or repeated invoice",
            )
        }
        _ => Err("owner requires initial signing first, then only advancing payments".into()),
    }
}
pub fn review(binding: &Binding, request: &Request) -> Result<Hash> {
    id("channel-owner-reviewed-request-v1", &(binding, request))
}
#[derive(Debug, Serialize)]
pub struct Response {
    pub partial: Partial,
    pub previous_head: Hash,
    pub owner_head: Hash,
    pub recovered_exact_response: bool,
    pub first_signed_this_call: bool,
    pub approvals_complete: bool,
    pub on_chain_credit: bool,
    pub independent_latest_protection: bool,
    pub live_rld: bool,
}
fn response(journal: &Journal, record: &Record, recovered: bool) -> Result<Response> {
    Ok(Response {
        partial: record.partial.clone(),
        previous_head: record.previous_head,
        owner_head: journal.head()?,
        recovered_exact_response: recovered,
        first_signed_this_call: !recovered,
        approvals_complete: false,
        on_chain_credit: false,
        independent_latest_protection: false,
        live_rld: false,
    })
}
fn load(path: &Path) -> Result<Journal> {
    serde_json::from_slice(&crate::keystore::private_read(path, MAX_BYTES)?)
        .map_err(|e| e.to_string())
}
fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(io(e)),
    }
}
fn lock(dir: &Path) -> Result<File> {
    crate::keystore::private_read(&dir.join("LOCK"), 0)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(dir.join("LOCK")).map_err(io)?;
    file.try_lock().map_err(|e| e.to_string())?;
    Ok(file)
}
pub struct Agent {
    dir: PathBuf,
    _lock: File,
    journal: Journal,
    pending: Option<Journal>,
    healthy: bool,
}
impl Agent {
    fn create_component(
        dir: &Path,
        node: &Store,
        channel: Hash,
        owner: String,
        native_head: Hash,
    ) -> Result<Self> {
        node.require_storage_head(native_head)?;
        let binding = Binding {
            purpose: PURPOSE.into(),
            profile: c::profile_hash()?,
            currency: node.trust.currency()?,
            region: node.chain.region,
            channel,
            owner,
        };
        binding.validate(node)?;
        channel_safety(node, channel)?;
        let initial = Self::initial(node, &binding)?;
        initial.check_current(node, &binding)?;
        crate::storage::safe_dir(dir.parent().ok_or("owner parent missing")?)?;
        let mut options = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            options.mode(0o700);
        }
        options.create(dir).map_err(io)?;
        crate::keystore::private_create(
            &dir.join("CREATING"),
            b"incomplete channel owner creation; preserve target",
        )?;
        crate::keystore::private_create(&dir.join("LOCK"), b"")?;
        let agent = Self {
            dir: dir.into(),
            _lock: lock(dir)?,
            journal: Journal {
                binding,
                creation: Observation::current(node)?,
                records: vec![],
            },
            pending: None,
            healthy: true,
        };
        agent.journal.validate(node)?;
        agent.persist(&agent.journal)?;
        fs::remove_file(dir.join("CREATING")).map_err(io)?;
        File::open(dir).map_err(io)?.sync_all().map_err(io)?;
        File::open(dir.parent().unwrap())
            .map_err(io)?
            .sync_all()
            .map_err(io)?;
        Ok(agent)
    }
    fn initial(node: &Store, binding: &Binding) -> Result<Request> {
        let native = node
            .chain
            .ledger
            .channel_state
            .as_ref()
            .ok_or("native channel absent")?;
        let escrow = native
            .book
            .channels
            .get(&binding.channel)
            .ok_or("native channel absent")?;
        Ok(Request::Initial {
            checkpoint: node
                .chain
                .finalized
                .ok_or("certified initial funding required")?,
            state: c::StateStatement {
                currency: binding.currency,
                region: binding.region,
                channel: binding.channel,
                sequence: 0,
                payouts: escrow.terms()?.2,
            },
        })
    }
    pub fn head(&self) -> Result<Hash> {
        self.journal.head()
    }
    pub fn binding(&self) -> &Binding {
        &self.journal.binding
    }
    pub fn initial_request(&self, node: &Store) -> Result<Request> {
        Self::initial(node, &self.journal.binding)
    }
    pub fn open(dir: &Path, node: &Store) -> Result<Self> {
        crate::storage::safe_dir(dir)?;
        require(
            !exists(&dir.join("CREATING"))? && !exists(&dir.join("RESTORING"))?,
            "owner creation/restore incomplete; retain target",
        )?;
        let lock = lock(dir)?;
        let journal = load(&dir.join("owner.json"))?;
        journal.validate(node)?;
        let pending = if exists(&dir.join("owner.next"))? {
            let candidate = load(&dir.join("owner.next"))?;
            candidate.validate(node)?;
            require(
                candidate.binding == journal.binding
                    && candidate.creation == journal.creation
                    && candidate.records.len() == journal.records.len() + 1
                    && candidate.records.starts_with(&journal.records),
                "pending owner response is not one exact authenticated extension",
            )?;
            Some(candidate)
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
    fn persist(&self, journal: &Journal) -> Result<()> {
        let bytes = serde_json::to_vec(journal).map_err(|e| e.to_string())?;
        require(bytes.len() <= MAX_BYTES, "owner journal byte bound")?;
        crate::keystore::private_create(&self.dir.join("owner.next"), &bytes)?;
        fs::rename(self.dir.join("owner.next"), self.dir.join("owner.json")).map_err(io)?;
        File::open(&self.dir).map_err(io)?.sync_all().map_err(io)
    }
    fn current(&self, node: &Store, head: Hash, native_head: Hash) -> Result<()> {
        node.require_storage_head(native_head)?;
        require(
            self.healthy && self.pending.is_none() && head == self.head()? && !head.is_zero(),
            "exact caller owner head required; pending/failing custody is recover-only",
        )?;
        self.journal.validate(node)
    }
    fn prepare_component(
        &self,
        node: &Store,
        request: &Request,
        head: Hash,
        native_head: Hash,
    ) -> Result<Hash> {
        self.current(node, head, native_head)?;
        request.check_current(node, &self.journal.binding)?;
        let mut invoices = self
            .journal
            .records
            .iter()
            .filter_map(|r| match &r.partial.request {
                Request::Payment(p) => Some(p.statement.expected.invoice),
                _ => None,
            })
            .collect();
        next_request(&self.journal, request, &mut invoices)?;
        review(&self.journal.binding, request)
    }
    /// Recovery never reads a key or signs. A predecessor head is accepted only
    /// for the last exact retained response, never for a different request.
    /// Validate both caller transition and complete retained response without
    /// publishing either custody journal. Witness recovery calls this first.
    fn recovery_preview(
        &self,
        node: &Store,
        request: &Request,
        reviewed: Hash,
        head: Hash,
        native_head: Hash,
    ) -> Result<Response> {
        node.require_storage_head(native_head)?;
        require(
            self.healthy && reviewed == review(&self.journal.binding, request)?,
            "owner recovery review/health mismatch",
        )?;
        self.journal.validate(node)?;
        if let Some(candidate) = &self.pending {
            candidate.validate(node)?;
            let record = candidate
                .records
                .last()
                .ok_or("pending owner response missing")?;
            require(
                record.partial.request == *request
                    && record.review == reviewed
                    && (head == self.head()? || head == candidate.head()?),
                "pending recovery needs exact retained response and caller transition head",
            )?;
        }
        let target = self.pending.as_ref().unwrap_or(&self.journal);
        let (n, record) = target
            .records
            .iter()
            .enumerate()
            .find(|(_, r)| r.partial.request == *request && r.review == reviewed)
            .ok_or("exact owner response absent; recovery cannot first-sign")?;
        require(
            head == target.head()?
                || (n + 1 == target.records.len() && head == record.previous_head),
            "recovery refuses stale owner head",
        )?;
        response(target, record, true)
    }
    fn recover_component(
        &mut self,
        node: &Store,
        request: &Request,
        reviewed: Hash,
        head: Hash,
        native_head: Hash,
    ) -> Result<Response> {
        let retained = self.recovery_preview(node, request, reviewed, head, native_head)?;
        if let Some(candidate) = &self.pending {
            File::open(self.dir.join("owner.next"))
                .map_err(io)?
                .sync_all()
                .map_err(io)?;
            fs::rename(self.dir.join("owner.next"), self.dir.join("owner.json")).map_err(io)?;
            File::open(&self.dir).map_err(io)?.sync_all().map_err(io)?;
            self.journal = candidate.clone();
            self.pending = None;
        }
        Ok(retained)
    }
    fn sign_component(
        &mut self,
        node: &Store,
        request: Request,
        key: &Path,
        reviewed: Hash,
        head: Hash,
        native_head: Hash,
    ) -> Result<Response> {
        // Explicit recovery uses a separate method; signing cannot promote a tail.
        self.current(node, head, native_head)?;
        require(
            reviewed == self.prepare_component(node, &request, head, native_head)?,
            "owner review differs from exact current request",
        )?;
        require(
            self.journal.records.len() < MAX_SIGNED,
            "owner capacity full; highest signed states retained",
        )?;
        let state_approval = crate::signer::read_and_sign(
            key,
            &self.journal.binding.owner,
            &request.state().bytes()?,
        )?;
        let invoice_approval = match &request {
            Request::Initial { .. } => None,
            Request::Payment(r) => Some(crate::signer::read_and_sign(
                key,
                &self.journal.binding.owner,
                &r.statement.bytes()?,
            )?),
        };
        let partial = Partial {
            binding: self.journal.binding.clone(),
            request,
            state_approval,
            invoice_approval,
        };
        let record = Record {
            previous_head: head,
            observation: Observation::current(node)?,
            review: reviewed,
            partial,
        };
        let mut journal = self.journal.clone();
        journal.records.push(record.clone());
        journal.validate(node)?;
        if let Err(e) = self.persist(&journal) {
            self.healthy = false;
            return Err(e);
        }
        self.journal = journal;
        response(&self.journal, &record, false)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum Combined {
    Initial(c::SignedState),
    Payment(Box<r::Receipt>),
}
/// Full native signatures are mandatory. Two partials are only construction;
/// combine never accepts a payment or changes money/native storage heads.
pub fn combine(node: &Store, parts: Vec<Partial>, native_head: Hash) -> Result<Combined> {
    node.require_storage_head(native_head)?;
    combine_inner(node, parts, true)
}
fn combine_inner(node: &Store, mut parts: Vec<Partial>, current: bool) -> Result<Combined> {
    require(parts.len() == 2, "both actual owner partials required")?;
    for p in &parts {
        p.verify(node)?;
        if current {
            p.request.check_current(node, &p.binding)?;
        }
    }
    parts.sort_by(|a, b| a.binding.owner.cmp(&b.binding.owner));
    let a = &parts[0];
    let b = &parts[1];
    require(
        a.request == b.request
            && a.binding.owner != b.binding.owner
            && a.binding.channel == b.binding.channel,
        "owner partial request/parties differ",
    )?;
    let approvals = parts.iter().map(|p| p.state_approval.clone()).collect();
    match &a.request {
        Request::Initial { state, .. } => {
            let signed = c::SignedState {
                statement: state.clone(),
                approvals,
                witness: None,
            };
            let native = node
                .chain
                .ledger
                .channel_state
                .as_ref()
                .ok_or("native funding absent")?;
            native.book.channels[&state.channel].verify_parties(
                &signed,
                state.channel,
                &native.declaration,
            )?;
            Ok(Combined::Initial(signed))
        }
        Request::Payment(r) => {
            let mut receipt = *r.clone();
            receipt.next.approvals = approvals;
            receipt.approvals = parts
                .iter()
                .map(|p| {
                    p.invoice_approval
                        .clone()
                        .ok_or("invoice approval absent".into())
                })
                .collect::<Result<_>>()?;
            receipt.verify_party_anchor(&node.trust, &node.evidence)?;
            if current {
                receipt.check_safety(node)?;
            }
            Ok(Combined::Payment(Box::new(receipt)))
        }
    }
}

#[cfg(test)]
#[path = "channel_owner_tests.rs"]
mod tests;

#[path = "channel_witness.rs"]
pub mod witness;
