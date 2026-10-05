//! Explicitly admitted ground profile: four equal validators, quorum three.
//! Two phases, durable prepare-QC locks, authenticated highest-QC view changes.
//! No independent custody, pacemaker, dynamic-membership or adoption claim.
use super::*;
use crate::{storage::Store, wallet_agent::Observation};
use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};
pub const RULES: &str = "RLD-REGIONAL-BFT-FIXTURE-V1";
/// Separate signed profile: ordinary 3-of-4 BFT, all-old/all-new epoch activation.
/// Legacy BFT admission never adopts handoff authorization automatically.
pub const EPOCH_RULES: &str = "RLD-REGIONAL-BFT-UNANIMOUS-EPOCH-FIXTURE-V1";
pub const JOINT_RULES: &str = "RLD-REGIONAL-BFT-JOINT-EPOCH-FIXTURE-V1";
pub const ROLE_RULES: &str = "RLD-REGIONAL-BFT-JOINT-ROLES-FIXTURE-V1";
pub fn is_joint(rules: &str) -> bool {
    rules == JOINT_RULES || rules == ROLE_RULES
}
pub fn has_epochs(rules: &str) -> bool {
    rules == EPOCH_RULES || is_joint(rules)
}
pub fn is_profile(rules: &str) -> bool {
    rules == RULES
        || rules == channels::BFT_RULES
        || crate::paged_bft::is_profile(rules)
        || has_epochs(rules)
}
pub const MAX_ROUNDS: u64 = 32;
pub const MAX_RECORDS: usize = 128;

pub fn creation_observation(node: &Store) -> Result<Observation> {
    Context::current(node)?;
    Observation::current(node)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub currency: Hash,
    pub region: Hash,
    pub epoch: Hash,
    pub previous: Option<Hash>,
    pub parent_height: u64,
    pub parent_block: Hash,
    pub parent_state: Hash,
}
impl Context {
    pub fn current(node: &Store) -> Result<Self> {
        require(
            is_profile(&node.trust.region(node.chain.region)?.rules),
            "region has not authorized the BFT profile",
        )?;
        Ok(Self {
            currency: node.trust.currency()?,
            region: node.chain.region,
            epoch: node.chain.epoch,
            previous: node.chain.finalized,
            parent_height: node.chain.height(),
            parent_block: node.chain.tip()?,
            parent_state: node.chain.ledger.root()?,
        })
    }
    fn statement(&self, block: Hash, state: Hash) -> Result<Statement> {
        Ok(Statement {
            currency: self.currency,
            region: self.region,
            epoch: self.epoch,
            previous: self.previous,
            height: self
                .parent_height
                .checked_add(1)
                .ok_or("BFT height overflow")?,
            block,
            state,
        })
    }
    pub fn keys(&self, trust: &Trust, evidence: &VerifiedEvidence) -> Result<Vec<String>> {
        evidence.check_trust(trust)?;
        require(
            is_profile(&trust.region(self.region)?.rules)
                && self.currency == trust.currency()?
                && (crate::paged_bft::is_profile(&trust.region(self.region)?.rules)
                    || self.parent_height < MAX_BLOCKS as u64),
            "BFT context profile/domain/height",
        )?;
        evidence
            .epochs
            .checkpoint_keys(trust, &self.statement(Hash::ZERO, Hash::ZERO)?)
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Phase {
    Prepare,
    Commit,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Vote {
    pub context: Context,
    pub round: u64,
    pub value: Hash,
    pub phase: Phase,
    pub approval: Approval,
}
impl Vote {
    pub(crate) fn bytes(&self) -> Result<Vec<u8>> {
        encode(
            "bft-vote-v1",
            &(
                &self.context,
                self.round,
                self.value,
                self.phase,
                &self.approval.key,
            ),
        )
    }
    pub(crate) fn verify(&self, keys: &[String]) -> Result<()> {
        require(
            self.round < MAX_ROUNDS
                && !self.value.is_zero()
                && keys.len() == 4
                && keys.windows(2).all(|p| p[0] < p[1])
                && keys.contains(&self.approval.key),
            "BFT vote round/value/membership",
        )?;
        verify_bytes(&self.approval.key, &self.bytes()?, &self.approval.signature)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Quorum {
    pub context: Context,
    pub round: u64,
    pub value: Hash,
    pub phase: Phase,
    pub votes: Vec<Vote>,
}
impl Quorum {
    pub fn verify(&self, keys: &[String]) -> Result<()> {
        require(
            (3..=4).contains(&self.votes.len())
                && self
                    .votes
                    .windows(2)
                    .all(|p| p[0].approval.key < p[1].approval.key),
            "BFT quorum requires three distinct ordered active voters",
        )?;
        for v in &self.votes {
            require(
                v.context == self.context
                    && v.round == self.round
                    && v.value == self.value
                    && v.phase == self.phase,
                "BFT quorum mixes context, round, value or phase",
            )?;
            v.verify(keys)?;
        }
        Ok(())
    }
    pub fn combine(votes: Vec<Vote>, trust: &Trust, evidence: &VerifiedEvidence) -> Result<Self> {
        let first = votes.first().ok_or("BFT votes missing")?;
        let q = Self {
            context: first.context.clone(),
            round: first.round,
            value: first.value,
            phase: first.phase,
            votes,
        };
        q.verify(&q.context.keys(trust, evidence)?)?;
        Ok(q)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Certificate {
    pub prepared: Quorum,
    pub committed: Quorum,
}
impl Certificate {
    pub fn verify(&self, context: &Context, value: Hash, keys: &[String]) -> Result<()> {
        self.prepared.verify(keys)?;
        self.committed.verify(keys)?;
        require(
            self.prepared.phase == Phase::Prepare
                && self.committed.phase == Phase::Commit
                && self.prepared.context == *context
                && self.committed.context == *context
                && self.prepared.value == value
                && self.committed.value == value
                && self.prepared.round == self.committed.round,
            "BFT certificate lacks matching prepare and commit quorums",
        )
    }
}
pub fn checkpoint_auth(
    s: &Statement,
    approvals: &[Approval],
    certificate: Option<&Certificate>,
    headers: &[Header],
    keys: &[String],
    trust: &Trust,
) -> Result<()> {
    if !is_profile(&trust.region(s.region)?.rules) {
        require(
            certificate.is_none(),
            "legacy region cannot reinterpret a BFT certificate",
        )?;
        return crate::epoch::approvals(approvals, keys, &s.bytes()?);
    }
    require(
        approvals.is_empty()
            && !headers.is_empty()
            && if crate::paged_bft::is_profile(&trust.region(s.region)?.rules) {
                headers.len() == if s.previous.is_some() { 2 } else { 1 }
            } else {
                headers.len() as u64 == s.height
            },
        "BFT checkpoint cannot use legacy approvals or omit history",
    )?;
    let (height, block, state) = if headers.len() == 1 {
        (0, s.region, Ledger::default().root()?)
    } else {
        let parent = &headers[headers.len() - 2];
        (parent.height, parent.id()?, parent.state)
    };
    let c = Context {
        currency: s.currency,
        region: s.region,
        epoch: s.epoch,
        previous: s.previous,
        parent_height: height,
        parent_block: block,
        parent_state: state,
    };
    require(
        height.checked_add(1) == Some(s.height)
            && headers.last().unwrap().anchor == s.previous
            && (height == 0) == s.previous.is_none(),
        "BFT next-block/parent checkpoint mismatch",
    )?;
    certificate
        .ok_or("BFT prepare/commit certificate missing")?
        .verify(&c, s.id()?, keys)
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TimeoutVote {
    pub context: Context,
    pub round: u64,
    pub high: Option<Quorum>,
    pub approval: Approval,
}
impl TimeoutVote {
    pub(crate) fn bytes(&self) -> Result<Vec<u8>> {
        encode(
            "bft-timeout-v1",
            &(&self.context, self.round, &self.high, &self.approval.key),
        )
    }
    pub(crate) fn verify(&self, keys: &[String]) -> Result<()> {
        require(
            self.round.checked_add(1).is_some_and(|n| n < MAX_ROUNDS)
                && keys.contains(&self.approval.key),
            "BFT timeout round or key",
        )?;
        if let Some(q) = &self.high {
            q.verify(keys)?;
            require(
                q.context == self.context && q.phase == Phase::Prepare && q.round <= self.round,
                "timeout high QC is not a verified earlier prepare quorum",
            )?;
        }
        verify_bytes(&self.approval.key, &self.bytes()?, &self.approval.signature)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TimeoutCertificate {
    pub context: Context,
    pub round: u64,
    pub votes: Vec<TimeoutVote>,
}
impl TimeoutCertificate {
    pub fn selected(&self, keys: &[String]) -> Result<Option<Quorum>> {
        require(
            (3..=4).contains(&self.votes.len())
                && self
                    .votes
                    .windows(2)
                    .all(|p| p[0].approval.key < p[1].approval.key),
            "BFT timeout quorum requires three ordered distinct active voters",
        )?;
        let mut highest: Option<Quorum> = None;
        for v in &self.votes {
            require(
                v.context == self.context && v.round == self.round,
                "timeout certificate mixes context/round",
            )?;
            v.verify(keys)?;
            if let Some(q) = &v.high {
                if let Some(old) = &highest {
                    if old.round == q.round {
                        require(
                            old.value == q.value,
                            "conflicting prepare QCs at highest round",
                        )?;
                    }
                    if q.round > old.round
                        || (q.round == old.round
                            && id("bft-prepare-qc", q)? < id("bft-prepare-qc", old)?)
                    {
                        highest = Some(q.clone());
                    }
                } else {
                    highest = Some(q.clone());
                }
            }
        }
        Ok(highest)
    }
    pub fn combine(
        votes: Vec<TimeoutVote>,
        trust: &Trust,
        evidence: &VerifiedEvidence,
    ) -> Result<Self> {
        let first = votes.first().ok_or("timeout votes missing")?;
        let result = Self {
            context: first.context.clone(),
            round: first.round,
            votes,
        };
        result.selected(&result.context.keys(trust, evidence)?)?;
        Ok(result)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    pub round: u64,
    pub snapshot: Box<Snapshot>,
    pub timeout: Option<TimeoutCertificate>,
    pub leader: Approval,
}
impl Proposal {
    pub fn context(&self) -> Result<Context> {
        context_of(&self.snapshot)
    }
    pub(crate) fn bytes(&self) -> Result<Vec<u8>> {
        encode(
            "bft-proposal-v1",
            &(self.round, &self.snapshot, &self.timeout, &self.leader.key),
        )
    }
    pub fn verify(&self, trust: &Trust, evidence: &VerifiedEvidence) -> Result<Option<Quorum>> {
        let context = self.context()?;
        let keys = context.keys(trust, evidence)?;
        let value = self.snapshot.statement.id()?;
        let selected = authorize(
            &context,
            self.round,
            &self.timeout,
            value,
            &self.leader.key,
            &keys,
        )?;
        verify_prospective(&self.snapshot, trust, evidence)?;
        verify_bytes(&self.leader.key, &self.bytes()?, &self.leader.signature)?;
        Ok(selected)
    }
}
pub fn leader(context: &Context, round: u64, keys: &[String]) -> Result<String> {
    require(round < MAX_ROUNDS && keys.len() == 4, "BFT leader bound")?;
    Ok(keys[((context.parent_height + round) % 4) as usize].clone())
}
fn authorize(
    context: &Context,
    round: u64,
    timeout: &Option<TimeoutCertificate>,
    value: Hash,
    key: &str,
    keys: &[String],
) -> Result<Option<Quorum>> {
    require(
        key == leader(context, round, keys)? && !value.is_zero(),
        "proposal is not from authorized round leader",
    )?;
    if round == 0 {
        require(
            timeout.is_none(),
            "initial BFT proposal cannot supply timeout",
        )?;
        return Ok(None);
    }
    let tc = timeout
        .as_ref()
        .ok_or("nonzero BFT round needs authenticated timeout certificate")?;
    require(
        tc.context == *context && tc.round.checked_add(1) == Some(round),
        "BFT proposal lacks immediate predecessor timeout",
    )?;
    let high = tc.selected(keys)?;
    if let Some(q) = &high {
        require(
            q.value == value,
            "new leader omitted highest prepared value",
        )?;
    }
    Ok(high)
}
fn context_of(snapshot: &Snapshot) -> Result<Context> {
    require(
        (snapshot.base.is_none()
            || (snapshot.base == snapshot.statement.previous && snapshot.blocks.len() == 2))
            && !snapshot.blocks.is_empty()
            && snapshot.blocks.len() <= MAX_BLOCKS,
        "BFT proposal block bound",
    )?;
    let s = &snapshot.statement;
    let (height, block, state) = if snapshot.blocks.len() == 1 {
        (0, s.region, Ledger::default().root()?)
    } else {
        let p = &snapshot.blocks[snapshot.blocks.len() - 2].header;
        (p.height, p.id()?, p.state)
    };
    Ok(Context {
        currency: s.currency,
        region: s.region,
        epoch: s.epoch,
        previous: s.previous,
        parent_height: height,
        parent_block: block,
        parent_state: state,
    })
}
fn verify_prospective(
    snapshot: &Snapshot,
    trust: &Trust,
    evidence: &VerifiedEvidence,
) -> Result<()> {
    crate::segmented::shape(snapshot, trust)?;
    let c = context_of(snapshot)?;
    c.keys(trust, evidence)?;
    require(
        snapshot.approvals.is_empty()
            && snapshot.bft.is_none()
            && c.parent_height.checked_add(1) == Some(snapshot.statement.height),
        "proposal contains finality or wrong target height",
    )?;
    let registry = crate::epoch::Registry::verify_chain(trust, c.region, &snapshot.epochs)?;
    registry.checkpoint_keys(trust, &snapshot.statement)?;
    let native_prefix = evidence
        .epoch_proofs(c.region)
        .into_iter()
        .take(snapshot.epochs.len())
        .collect::<Vec<_>>();
    if crate::bft::is_joint(&trust.region(c.region)?.rules) {
        require(
            snapshot
                .epochs
                .iter()
                .map(|p| p.statement.id())
                .collect::<Result<Vec<_>>>()?
                == native_prefix
                    .iter()
                    .map(|p| p.statement.id())
                    .collect::<Result<Vec<_>>>()?,
            "proposal authority prefix differs",
        )?;
        let mut checked = evidence.clone();
        for proof in &snapshot.epochs {
            checked.install_epoch(proof.clone(), trust)?;
        }
    } else {
        require(
            snapshot.epochs == native_prefix,
            "proposal authority prefix differs",
        )?;
    }

    if let Some(previous) = c.previous {
        let parent = evidence.snapshot(previous)?;
        require(
            parent.statement.region == c.region
                && parent.statement.height == c.parent_height
                && parent.statement.block == c.parent_block
                && parent.statement.state == c.parent_state
                && if crate::paged_bft::is_profile(&trust.region(c.region)?.rules) {
                    snapshot.blocks.first() == parent.blocks.last()
                } else {
                    snapshot.blocks[..snapshot.blocks.len() - 1] == parent.blocks
                },
            "proposal forks from certified parent",
        )?;
    } else {
        require(c.parent_height == 0, "BFT proposal lacks certified parent")?;
    }
    let replay = evidence.replay_extension(snapshot, trust)?;
    require(
        replay.statement(trust)? == snapshot.statement,
        "proposal differs from complete native value replay",
    )
}
pub(crate) fn validate_next(snapshot: &Snapshot, node: &Store) -> Result<()> {
    verify_prospective(snapshot, &node.trust, &node.evidence)?;
    require(
        context_of(snapshot)? == Context::current(node)?
            && crate::paged_bft::parent_matches(snapshot, node)?,
        "BFT next proposal differs from current native parent",
    )
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum Request {
    EpochFence {
        context: Context,
        proposal: Box<epoch::Transition>,
        previous_epochs: Vec<epoch::Transition>,
    },
    Propose {
        round: u64,
        snapshot: Box<Snapshot>,
        timeout: Option<TimeoutCertificate>,
    },
    Prepare(Box<Proposal>),
    Commit {
        proposal: Box<Proposal>,
        prepared: Quorum,
    },
    Timeout {
        context: Context,
        round: u64,
    },
}
impl Request {
    fn context(&self) -> Result<Context> {
        match self {
            Self::Propose { snapshot, .. } => context_of(snapshot),
            Self::Prepare(p) | Self::Commit { proposal: p, .. } => p.context(),
            Self::Timeout { context, .. } => Ok(context.clone()),
            Self::EpochFence { context, .. } => Ok(context.clone()),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Message {
    EpochApproval {
        statement: Box<epoch::EpochStatement>,
        approval: Approval,
    },
    Proposal(Box<Proposal>),
    Vote(Box<Vote>),
    Timeout(Box<TimeoutVote>),
}
impl Message {
    fn approval(&self) -> &Approval {
        match self {
            Self::Proposal(p) => &p.leader,
            Self::Vote(v) => &v.approval,
            Self::Timeout(t) => &t.approval,
            Self::EpochApproval { approval, .. } => approval,
        }
    }
    fn set_approval(&mut self, a: Approval) {
        match self {
            Self::Proposal(p) => p.leader = a,
            Self::Vote(v) => v.approval = a,
            Self::Timeout(t) => t.approval = a,
            Self::EpochApproval { approval, .. } => *approval = a,
        }
    }
    pub(crate) fn bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::Proposal(p) => p.bytes(),
            Self::Vote(v) => v.bytes(),
            Self::Timeout(t) => t.bytes(),
            Self::EpochApproval { statement, .. } => {
                statement.approval_bytes(crate::joint_epoch::Role::Old)
            }
        }
    }
}
#[derive(Clone, Default, Debug, Serialize)]
pub struct State {
    pub epoch_fence: Option<Hash>,
    pub context: Option<Context>,
    pub round: u64,
    pub lock: Option<Quorum>,
    pub prepared: Option<Hash>,
    pub committed: Option<Hash>,
    pub proposed: bool,
}
impl State {
    fn enter(
        &mut self,
        c: &Context,
        trust: &Trust,
        evidence: &VerifiedEvidence,
    ) -> Result<Vec<String>> {
        let keys = c.keys(trust, evidence)?;
        if self.context.as_ref() != Some(c) {
            if let Some(old) = &self.context {
                require(
                    c.region == old.region
                        && c.currency == old.currency
                        && c.parent_height > old.parent_height,
                    "BFT signer context rollback or domain change",
                )?;
            }
            *self = Self {
                context: Some(c.clone()),
                ..Default::default()
            };
        }
        Ok(keys)
    }
    fn round(&mut self, round: u64) -> Result<()> {
        require(
            round >= self.round && round < MAX_ROUNDS,
            "BFT old/exhausted round",
        )?;
        if round > self.round {
            self.round = round;
            self.prepared = None;
            self.committed = None;
            self.proposed = false;
        }
        Ok(())
    }
    fn apply(&mut self, request: &Request, key: &str, node: &Store) -> Result<Message> {
        require(
            self.epoch_fence.is_none(),
            "BFT signer epoch is durably fenced",
        )?;
        if let Request::EpochFence {
            context,
            proposal,
            previous_epochs,
        } = request
        {
            crate::bft_epoch::validate_fence(node, context, proposal, previous_epochs, key)?;
            require(
                self.context
                    .as_ref()
                    .is_none_or(|old| old.parent_height < context.parent_height),
                "BFT signer already acted beyond the handoff closing checkpoint",
            )?;
            self.epoch_fence = Some(proposal.statement.id()?);
            return Ok(Message::EpochApproval {
                statement: Box::new(proposal.statement.clone()),
                approval: Approval {
                    key: key.into(),
                    signature: String::new(),
                },
            });
        }
        self.apply_authenticated(request, key, &node.trust, &node.evidence)
    }
    // Shared ordinary execution kernel. The paged caller supplies only evidence
    // just derived by ordered native genesis replay, never a persisted ledger.
    fn apply_authenticated(
        &mut self,
        request: &Request,
        key: &str,
        trust: &Trust,
        evidence: &VerifiedEvidence,
    ) -> Result<Message> {
        require(
            self.epoch_fence.is_none() && !matches!(request, Request::EpochFence { .. }),
            "ordinary BFT action requires unfenced authenticated context",
        )?;
        let c = request.context()?;
        crate::joint_epoch::signing_context(&c, trust, evidence)?;
        let keys = self.enter(&c, trust, evidence)?;
        require(
            keys.contains(&key.into()),
            "BFT signing key is not active in this era",
        )?;
        let approval = Approval {
            key: key.into(),
            signature: String::new(),
        };
        match request {
            Request::Propose {
                round,
                snapshot,
                timeout,
            } => {
                verify_prospective(snapshot, trust, evidence)?;
                authorize(&c, *round, timeout, snapshot.statement.id()?, key, &keys)?;
                self.round(*round)?;
                require(!self.proposed, "BFT leader already proposed in this round")?;
                self.proposed = true;
                Ok(Message::Proposal(Box::new(Proposal {
                    round: *round,
                    snapshot: snapshot.clone(),
                    timeout: timeout.clone(),
                    leader: approval,
                })))
            }
            Request::Prepare(p) => {
                let high = p.verify(trust, evidence)?;
                let value = p.snapshot.statement.id()?;
                self.round(p.round)?;
                require(
                    self.prepared.is_none(),
                    "BFT signer already prepared this round",
                )?;
                if let Some(lock) = &self.lock {
                    require(
                        lock.value == value || high.as_ref().is_some_and(|q| q.round > lock.round),
                        "proposal violates durable prepared lock without a newer valid prepare QC",
                    )?;
                }
                self.prepared = Some(value);
                Ok(Message::Vote(Box::new(Vote {
                    context: c,
                    round: p.round,
                    value,
                    phase: Phase::Prepare,
                    approval,
                })))
            }
            Request::Commit {
                proposal: p,
                prepared: q,
            } => {
                p.verify(trust, evidence)?;
                q.verify(&keys)?;
                let value = p.snapshot.statement.id()?;
                require(
                    p.round == self.round
                        && self.prepared == Some(value)
                        && self.committed.is_none()
                        && q.context == c
                        && q.round == p.round
                        && q.value == value
                        && q.phase == Phase::Prepare,
                    "BFT commit needs own current prepare and matching prepared quorum",
                )?;
                self.lock = Some(q.clone());
                self.committed = Some(value);
                Ok(Message::Vote(Box::new(Vote {
                    context: c,
                    round: p.round,
                    value,
                    phase: Phase::Commit,
                    approval,
                })))
            }
            Request::Timeout { round, .. } => {
                require(
                    *round == self.round && round.checked_add(1).is_some_and(|n| n < MAX_ROUNDS),
                    "BFT timeout does not advance current bounded round",
                )?;
                let high = self.lock.clone();
                self.round += 1;
                self.prepared = None;
                self.committed = None;
                self.proposed = false;
                Ok(Message::Timeout(Box::new(TimeoutVote {
                    context: c,
                    round: *round,
                    high,
                    approval,
                })))
            }
            Request::EpochFence { .. } => unreachable!("fence handled before ordinary signing"),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub currency: Hash,
    pub region: Hash,
    pub key: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub previous_head: Hash,
    pub observation: Observation,
    pub request: Request,
    pub message: Message,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    pub binding: Binding,
    pub creation: Observation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<Box<crate::joint_roles::VoterOrigin>>,
    pub records: Vec<Record>,
}
impl Journal {
    pub fn head(&self) -> Result<Hash> {
        id("bft-signer-journal-v1", self)
    }
    fn validate_header(&self, node: &Store, depth: usize) -> Result<()> {
        require(
            depth <= crate::epoch::MAX_EPOCHS,
            "BFT custody ancestry bound",
        )?;
        require(
            self.records.len() <= MAX_RECORDS
                && self.binding.currency == node.trust.currency()?
                && self.binding.region == node.chain.region
                && is_profile(&node.trust.region(self.binding.region)?.rules),
            "BFT journal binding/count/profile",
        )?;
        validate_ed25519_public_key(&self.binding.key)?;
        let b = crate::wallet_agent::Binding {
            currency: self.binding.currency,
            region: self.binding.region,
            owner: self.binding.key.clone(),
        };
        self.creation.check(node, &b)?;
        if node.trust.region(b.region)?.rules == ROLE_RULES {
            match &self.origin {
                Some(origin) => origin.validate(node, self, depth)?,
                None => require(
                    self.creation.pin.height == 0
                        && node.trust.region(b.region)?.validators.contains(&b.owner)
                        && self.creation.pin.epoch
                            == crate::epoch::Registry::initial(&node.trust, b.region)?,
                    "role-scoped empty voter requires genesis or native custody provenance",
                )?,
            }
        } else {
            require(
                self.origin.is_none(),
                "legacy voter cannot adopt role custody provenance",
            )?;
        }
        Ok(())
    }
    /// Read-only native replay of complete original legacy records held in
    /// pages. Both external heads are required. This does not create/adopt a
    /// paged signer, raise the 128-record bound, recover custody or first-sign.
    pub fn state_from_retained(
        &self,
        node: &Store,
        stream: &crate::retained_pages::Stream<Record>,
        storage_head: Hash,
        native_head: Hash,
    ) -> Result<State> {
        require(
            self.records.is_empty(),
            "retained replay requires an empty journal header",
        )?;
        let scope = crate::retained_pages::Scope::bind(
            &node.trust,
            self.binding.region,
            crate::retained_pages::Purpose::BftSigner(self.binding.key.clone()),
            self.head()?,
        )?;
        stream.require_scope(&scope)?;
        require(
            stream.record_count() <= MAX_RECORDS as u64,
            "BFT journal record capacity",
        )?;
        let mut replay = replay::Replay::new(self, node, 0)?;
        stream.visit(storage_head, |record| replay.push(record))?;
        replay.finish(native_head)
    }
    pub fn state(&self, node: &Store) -> Result<State> {
        require(
            !crate::paged_bft::is_profile(&node.trust.region(self.binding.region)?.rules),
            "paged signer header is not complete custody authority",
        )?;
        self.state_at_depth(node, 0)
    }
    pub(crate) fn state_at_depth(&self, node: &Store, depth: usize) -> Result<State> {
        let mut replay = replay::Replay::new(self, node, depth)?;
        for record in &self.records {
            replay.push(record)?;
        }
        let state = replay.finish(self.head()?)?;
        encode("bft-journal", self)?;
        Ok(state)
    }
}
pub struct Agent {
    dir: PathBuf,
    _lock: File,
    pub journal: Journal,
    healthy: bool,
    paged: Option<crate::retained_pages::Stream<Record>>,
}
/// Read-only result of the full journal validation in the same locked open.
/// No decoded status can initialize a journal or authorize a signature.
#[derive(Serialize)]
pub struct Status {
    binding: Binding,
    creation: Observation,
    external_rollback_anchor_qualified: bool,
    head: Hash,
    records: usize,
    state: State,
}
#[derive(Debug, Serialize)]
pub struct Signed {
    pub message: Message,
    pub previous_head: Hash,
    pub head: Hash,
    pub recovered_exact_retry: bool,
}
fn io(_: std::io::Error) -> String {
    "BFT private journal operation failed".into()
}
fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(io(e)),
    }
}
pub(crate) fn lock(dir: &Path) -> Result<File> {
    crate::keystore::private_read(&dir.join("LOCK"), 16)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let lock = options.open(dir.join("LOCK")).map_err(io)?;
    lock.try_lock()
        .map_err(|_| "BFT signer is already locked")?;
    Ok(lock)
}
impl Agent {
    pub fn create(dir: &Path, node: &Store, key: String) -> Result<Self> {
        let c = Context::current(node)?;
        let keys = c.keys(&node.trust, &node.evidence)?;
        require(keys.contains(&key), "new BFT signer key is not active")?;
        if node.chain.height() > 0 {
            require(
                node.trust.region(c.region)?.rules != ROLE_RULES,
                "role-scoped voter creation requires native handoff custody",
            )?;
            let previous = node.evidence.epoch_proofs(c.region);
            require(
                !node.trust.region(c.region)?.validators.contains(&key)
                    && previous
                        .iter()
                        .filter(|p| p.statement.id().ok() != Some(c.epoch))
                        .all(|p| !p.statement.validators.contains(&key)),
                "active historical BFT key needs its original journal, not a new empty signer",
            )?;
            require(
                has_epochs(&node.trust.region(c.region)?.rules)
                    && previous.last().is_some_and(|p| {
                        p.statement.id().ok() == Some(c.epoch)
                            && p.statement.closing_height == node.chain.height()
                            && Some(p.statement.closing_checkpoint) == node.chain.finalized
                            && p.statement.validators.contains(&key)
                    }),
                "fresh BFT signer can start only at its exact newly activated epoch boundary",
            )?;
        }
        crate::storage::safe_dir(dir.parent().ok_or("BFT signer parent missing")?)?;
        let mut options = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            options.mode(0o700);
        }
        options.create(dir).map_err(io)?;
        crate::keystore::private_create(&dir.join("LOCK"), b"")?;
        let journal = Journal {
            binding: Binding {
                currency: c.currency,
                region: c.region,
                key,
            },
            creation: Observation::current(node)?,
            origin: None,
            records: vec![],
        };
        let agent = Self {
            dir: dir.into(),
            _lock: lock(dir)?,
            journal,
            healthy: true,
            paged: None,
        };
        if crate::paged_bft::is_profile(&node.trust.region(c.region)?.rules) {
            return Self::create_paged(agent, node);
        }
        agent.journal.state(node)?;
        agent.persist(&agent.journal)?;
        Ok(agent)
    }
    pub fn open(dir: &Path, node: &Store) -> Result<Self> {
        Self::open_state(dir, node).map(|(agent, _)| agent)
    }
    /// Keep the actual signer lock alive alongside its exact verified observation.
    /// Signing still independently revalidates the current journal and expected head.
    pub fn open_with_status(dir: &Path, node: &Store) -> Result<(Self, Status)> {
        let (agent, state) = Self::open_state(dir, node)?;
        let status = Status {
            head: agent.head()?,
            binding: agent.journal.binding.clone(),
            state,
            records: agent.record_count(),
            creation: agent.journal.creation.clone(),
            external_rollback_anchor_qualified: false,
        };
        Ok((agent, status))
    }
    fn open_state(dir: &Path, node: &Store) -> Result<(Self, State)> {
        let lock = lock(dir)?;
        if crate::paged_bft::is_profile(&node.trust.region(node.chain.region)?.rules) {
            return Self::open_paged(dir, lock, node);
        }
        require(
            !exists(&dir.join("bft-header.json"))?,
            "legacy signer cannot adopt paged custody",
        )?;
        let journal: Journal = serde_json::from_slice(&crate::keystore::private_read(
            &dir.join("bft.json"),
            MAX_BYTES,
        )?)
        .map_err(|_| "invalid BFT journal")?;
        let mut state = journal.state(node)?;
        let mut agent = Self {
            dir: dir.into(),
            _lock: lock,
            journal,
            healthy: true,
            paged: None,
        };
        let next = dir.join("bft.next");
        if exists(&next)? {
            let proposed: Journal =
                serde_json::from_slice(&crate::keystore::private_read(&next, MAX_BYTES)?)
                    .map_err(|_| "invalid interrupted BFT journal")?;
            let proposed_state = proposed.state(node)?;
            require(
                proposed.binding == agent.journal.binding
                    && proposed.creation == agent.journal.creation
                    && proposed.origin == agent.journal.origin
                    && proposed.records.len() == agent.journal.records.len() + 1
                    && proposed.records.starts_with(&agent.journal.records),
                "interrupted BFT journal is not exact extension",
            )?;
            File::open(&next).map_err(io)?.sync_all().map_err(io)?;
            fs::rename(next, dir.join("bft.json")).map_err(io)?;
            File::open(dir).map_err(io)?.sync_all().map_err(io)?;
            agent.journal = proposed;
            state = proposed_state;
        }
        Ok((agent, state))
    }
    fn persist(&self, journal: &Journal) -> Result<()> {
        let bytes = serde_json::to_vec(journal).map_err(|_| "BFT journal encoding")?;
        require(bytes.len() <= MAX_BYTES, "BFT signer byte capacity")?;
        let temp = self.dir.join("bft.next");
        crate::keystore::private_create(&temp, &bytes)?;
        fs::rename(temp, self.dir.join("bft.json")).map_err(io)?;
        File::open(&self.dir).map_err(io)?.sync_all().map_err(io)
    }
    pub fn role_journal(
        node: &Store,
        key: String,
        old: Option<(&Agent, Hash)>,
        ready: &crate::joint_roles::ReadyAgent,
        ready_head: Hash,
        proof: crate::epoch::Transition,
    ) -> Result<Journal> {
        let c = Context::current(node)?;
        require(
            node.trust.region(c.region)?.rules == ROLE_RULES
                && c.epoch == proof.statement.id()?
                && c.parent_height == proof.statement.closing_height
                && c.previous == Some(proof.statement.closing_checkpoint),
            "new role voter needs exact locally activated boundary",
        )?;
        if let Some((agent, head)) = old {
            require(
                agent.healthy && agent.journal.head()? == head,
                "old native voter head differs",
            )?;
        }
        require(
            ready.journal.head()? == ready_head,
            "native readiness head differs",
        )?;
        let journal = Journal {
            binding: Binding {
                currency: c.currency,
                region: c.region,
                key,
            },
            creation: Observation::current(node)?,
            origin: Some(Box::new(crate::joint_roles::VoterOrigin {
                format: "RLD-BFT-JOINT-VOTER-ORIGIN-V1".into(),
                proof: Box::new(proof),
                old: old.map(|(agent, _)| Box::new(agent.journal.clone())),
                old_head: old.map(|(_, head)| head),
                ready: ready.journal.clone(),
                ready_head,
            })),
            records: vec![],
        };
        journal.state(node)?;
        journal.head()?;
        node.safety.check_region(c.region)?;
        Ok(journal)
    }
    pub fn create_role(
        dir: &Path,
        node: &Store,
        key: String,
        old: Option<(&Agent, Hash)>,
        ready: &crate::joint_roles::ReadyAgent,
        ready_head: Hash,
        proof: crate::epoch::Transition,
    ) -> Result<Self> {
        let journal = Self::role_journal(node, key, old, ready, ready_head, proof)?;
        crate::storage::safe_dir(dir.parent().ok_or("BFT signer parent missing")?)?;
        let mut options = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            options.mode(0o700);
        }
        options.create(dir).map_err(io)?;
        crate::keystore::private_create(&dir.join("LOCK"), b"")?;
        let agent = Self {
            dir: dir.into(),
            _lock: lock(dir)?,
            journal,
            healthy: true,
            paged: None,
        };
        agent.persist(&agent.journal)?;
        Ok(agent)
    }
    pub fn recover_role_creation(
        dir: &Path,
        node: &Store,
        marker: &crate::joint_roles::VoterCreation,
    ) -> Result<Self> {
        let lock = lock(dir)?;
        let retained = dir.join("bft.json");
        let next = dir.join("bft.next");
        let has_retained = exists(&retained)?;
        let has_next = exists(&next)?;
        require(
            has_retained != has_next,
            "voter creation needs exactly one retained empty journal",
        )?;
        let path = if has_retained { &retained } else { &next };
        let journal: Journal =
            serde_json::from_slice(&crate::keystore::private_read(path, MAX_BYTES)?)
                .map_err(|_| "invalid retained voter creation")?;
        journal.state(node)?;
        require(
            crate::joint_roles::VoterCreation::observe(&journal)? == *marker,
            "voter creation differs from separately retained marker",
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
            paged: None,
        })
    }
    pub fn sign(
        &mut self,
        node: &Store,
        request: Request,
        key_file: Option<&Path>,
        expected: Hash,
    ) -> Result<Signed> {
        require(
            self.healthy,
            "BFT signer requires reopen after persistence failure",
        )?;
        if self.paged.is_some() {
            return self.sign_paged(node, request, key_file, expected);
        }
        let mut state = self.journal.state(node)?;
        let head = self.journal.head()?;
        if let Some((n, r)) = self
            .journal
            .records
            .iter()
            .enumerate()
            .find(|(_, r)| r.request == request)
        {
            require(
                expected == head
                    || (n + 1 == self.journal.records.len() && expected == r.previous_head),
                "BFT exact retry has stale caller head",
            )?;
            return Ok(Signed {
                message: r.message.clone(),
                previous_head: r.previous_head,
                head,
                recovered_exact_retry: true,
            });
        }
        require(
            expected == head,
            "caller-retained BFT head rejects old backup",
        )?;
        require(
            self.journal.records.len() < MAX_RECORDS,
            "BFT signer record capacity; keep old votes",
        )?;
        let c = request.context()?;
        require(
            node.trust.region(c.region)?.rules != ROLE_RULES
                || c.epoch == self.journal.creation.pin.epoch,
            "role voter cannot change era inside its original journal",
        )?;
        require(
            c == Context::current(node)?,
            "BFT request does not bind current native parent",
        )?;
        node.safety.check_region(c.region)?;
        let proposal = match &request {
            Request::Propose { snapshot, .. } => Some(snapshot.as_ref()),
            Request::Prepare(p) | Request::Commit { proposal: p, .. } => Some(p.snapshot.as_ref()),
            _ => None,
        };
        if let Some(s) = proposal {
            require(
                crate::paged_bft::parent_matches(s, node)?,
                "BFT proposal parent differs from actual replay",
            )?;
            node.safety.check(
                &node.chain,
                &s.blocks.last().unwrap().commands,
                &node.evidence,
            )?;
        }
        let mut message = state.apply(&request, &self.journal.binding.key, node)?;
        let approval = crate::signer::read_and_sign(
            key_file.ok_or("new BFT vote requires explicit private key")?,
            &self.journal.binding.key,
            &message.bytes()?,
        )?;
        message.set_approval(approval);
        let record = Record {
            previous_head: head,
            observation: Observation::current(node)?,
            request,
            message: message.clone(),
        };
        let mut journal = self.journal.clone();
        journal.records.push(record);
        journal.state(node)?;
        if let Err(e) = self.persist(&journal) {
            self.healthy = false;
            return Err(e);
        }
        self.journal = journal;
        Ok(Signed {
            message,
            previous_head: head,
            head: self.journal.head()?,
            recovered_exact_retry: false,
        })
    }
}

#[path = "bft_replay.rs"]
mod replay;

#[cfg(test)]
pub(crate) use replay::tests::compare_all_prefixes;

#[path = "paged_bft_agent.rs"]
mod paged_agent;

#[cfg(test)]
#[path = "paged_sign_cost.rs"]
pub(crate) mod sign_cost;
