use crate::{
    custody::Vault,
    store::{MAX_RECORD, Store},
};
use anyhow::{Context, Result, bail, ensure};
use minicbor::{Decode, Encode};
use rld_protocol::{
    codec::{Blob, Id, decode, encode, hash},
    consensus::{self, Action, Engine, Message, NewView, Payload, Proposal, ViewChange},
    crypto,
    model::*,
    proof::{self, Verifier},
    record,
    state::State,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, VecDeque},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

record!(Initial {currency:Currency  =>  0,genesis:DomainGenesis  =>  1});
record!(Committed {batch:Batch  =>  0,header:Checkpoint  =>  1,qc:Quorum  =>  2,configuration:Configuration  =>  3});
record!(TerminalRecord {payload:Payload  =>  0,qc:Quorum  =>  1});
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub enum Application {
    #[n(0)]
    Consensus(#[n(0)] Message),
    #[n(1)]
    Payment(#[n(0)] Release),
    #[n(2)]
    Operation(#[n(0)] Operation),
    #[n(3)]
    Certificate(#[n(0)] Certified),
    #[n(4)]
    Block(#[n(0)] Committed),
    #[n(5)]
    Candidate(#[n(0)] Payload),
    #[n(6)]
    Rejection(#[n(0)] Rejected),
}
record!(Dispatch {destination:Id  =>  0,message:Application  =>  1});
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub enum Event {
    #[n(0)]
    Initial(#[n(0)] Initial),
    #[n(1)]
    Queued(#[n(0)] Operation),
    #[n(2)]
    Received(#[n(0)] Message),
    #[n(3)]
    Sent(#[n(0)] Dispatch),
    #[n(4)]
    NativeCommitted(#[n(0)] Committed),
    #[n(5)]
    ControllerCommitted(#[n(0)] TerminalRecord),
    #[n(6)]
    Proof(#[n(0)] Certified),
    #[n(7)]
    Delivered(#[n(0)] Id),
    #[n(8)]
    Candidate(#[n(0)] Payload),
    #[n(9)]
    Conflict(#[n(0)] Message),
    #[n(10)]
    ConflictingBlock(#[n(0)] Committed),
    #[n(11)]
    Rejection(#[n(0)] Rejected),
    #[n(12)]
    MintIndex {
        #[n(0)]
        sequence: u64,
        #[n(1)]
        certificate: rld_protocol::mints::index::Certificate,
    },
}
#[derive(Clone)]
pub struct Core {
    pub initial: Initial,
    pub(crate) mint_certificates: crate::mint_certificates::Certificates,
    pub(crate) mint_storage: Arc<crate::mint_store::MintStore>,
    pub(crate) utxo_storage: Arc<crate::utxo_store::Utxos>,
    pub(crate) permanent_storage: Arc<crate::object_store::Objects>,
    pub(crate) applied_storage: Arc<crate::applied_store::AppliedStore>,
    pub(crate) state_index: Option<Arc<crate::state_index::StateIndex>>,
    pub state: Arc<State>,
    pub head: Id,
    pub history: crate::history::History,
    pub engines: Vec<Engine>,
    pub pending: Vec<Operation>,
    pub terminals: Vec<TerminalRecord>,
    pub proofs: crate::receipts::Receipts,
    pub outbox: Vec<(Id, Dispatch)>,
    pub candidates: Vec<Payload>,
    pub delivered: Vec<Id>,
    pub failed: Vec<(Id, String)>,
    pub faults: Vec<Blob>,
    pub rejections: Vec<Rejected>,
    sent_rejections: Vec<Id>,
    pending_rejections: BTreeMap<Id, u64>,
}
pub struct Node {
    pub core: Core,
    store: Store,
    signers: Vec<Vault>,
    timers: BTreeMap<(Id, u64), (u64, Instant)>,
    halted: bool,
    native_reconciled: BTreeMap<Id, u64>,
    terminal_reconciled: BTreeMap<Id, usize>,
    rejection_cursor: Option<Id>,
    pub last_error: Option<String>,
}
fn payload_namespace(p: &Payload) -> Id {
    match p {
        Payload::Native { header, .. } => header.domain,
        Payload::Export(r) => r.creation.controller.id,
        Payload::Cancel(c) => c.controller,
    }
}
fn message_position(m: &Message) -> (Id, u64) {
    match m {
        Message::Proposal(p) => (p.preprepare.namespace, p.preprepare.sequence),
        Message::Vote(v) => (v.namespace, v.sequence),
        Message::ViewChange(v) => (v.namespace, v.sequence),
        Message::NewView(v) => (v.leader.namespace, v.leader.sequence),
        Message::Finalized { proposal, .. } => {
            (proposal.preprepare.namespace, proposal.preprepare.sequence)
        }
    }
}
fn empty_vote() -> Vote {
    Vote {
        currency: Id::ZERO,
        namespace: Id::ZERO,
        configuration: Id::ZERO,
        sequence: 0,
        view: 0,
        phase: 0,
        statement: Id::ZERO,
        validator: Id::ZERO,
        key: KeyLeaf {
            validator: Id::ZERO,
            key: Id::ZERO,
            path: vec![],
        },
        signature: Signature {
            key: Id::ZERO,
            bytes: Blob(vec![]),
        },
    }
}
impl Core {
    fn initial_state(initial: &Initial) -> Result<State> {
        ensure!(
            initial.currency.proof == crate::executable_profile()?,
            "currency proof programs differ from this source-bound host executable; preserve old state and use its matching release"
        );
        State::genesis(&initial.currency, &initial.genesis)
    }
    fn new(initial: Initial, mut state: State, root: &Path) -> Result<Self> {
        let applied_storage = Arc::new(crate::applied_store::AppliedStore::open(
            &root.join("applied-index"),
            &initial,
        )?);
        state.applied = state.applied.on_empty_storage(applied_storage.clone())?;
        let utxo_storage = Arc::new(crate::utxo_store::Utxos::open(
            &root.join("utxo-index"),
            &initial,
        )?);
        state.outputs = state
            .outputs
            .clone()
            .on_empty_storage(utxo_storage.clone())?;
        let mint_storage = Arc::new(crate::mint_store::MintStore::open(
            &root.join("mint-index"),
            &initial,
        )?);
        state.mints = state.mints.clone().on_empty_storage(mint_storage.clone())?;
        let mint_certificates =
            crate::mint_certificates::Certificates::open(&root.join("mint-proof-index"), &initial)?;
        let permanent_storage =
            crate::state_storage::Backings::initialize(root, &initial, &mut state)?;
        let history = crate::history::History::open(&root.join("history-index"), &initial)?;
        let proofs = crate::receipts::Receipts::open(&root.join("receipt-index"), &initial)?;
        let head = rld_protocol::state::genesis_id(initial.currency.id(), &initial.genesis);
        Ok(Self {
            initial,
            applied_storage,
            permanent_storage,
            utxo_storage,
            mint_storage,
            mint_certificates,
            state_index: None,
            state: Arc::new(state),
            head,
            history,
            engines: vec![],
            pending: vec![],
            terminals: vec![],
            proofs,
            outbox: vec![],
            candidates: vec![],
            delivered: vec![],
            failed: vec![],
            faults: vec![],
            rejections: vec![],
            sent_rejections: vec![],
            pending_rejections: BTreeMap::new(),
        })
    }
    fn engine(&mut self, namespace: Id, sequence: u64) -> Result<usize> {
        if let Some(i) = self
            .engines
            .iter()
            .position(|e| e.namespace == namespace && e.sequence == sequence)
        {
            return Ok(i);
        }
        let (config, pool) = if namespace == self.state.domain {
            ensure!(
                sequence
                    == self
                        .state
                        .sequence
                        .checked_add(1)
                        .context("sequence exhaustion")?,
                "native position not current"
            );
            (self.state.configuration.clone(), None)
        } else {
            let c = self
                .state
                .controllers
                .iter()
                .find(|c| c.id == namespace)
                .context("unknown local controller")?;
            ensure!(
                sequence == 0
                    && self.terminal_statement(namespace).is_none()
                    && !self.state.resolutions.get(namespace)?.is_some(),
                "controller terminal"
            );
            (c.configuration.clone(), Some(c.pool_index))
        };
        ensure!(
            self.engines.len() <= self.state.configuration.limits.controllers as usize + 1,
            "active PBFT engine limit"
        );
        self.engines
            .push(Engine::new(config, namespace, pool, sequence)?);
        Ok(self.engines.len() - 1)
    }
    pub fn terminal_statement(&self, id: Id) -> Option<Id> {
        self.terminals.iter().find_map(|r| match &r.payload {
            Payload::Export(v) if v.terminal.controller == id => Some(v.terminal.id()),
            Payload::Cancel(v) if v.controller == id => Some(v.terminal.id()),
            _ => None,
        })
    }
    fn validate_payload(&self, p: &Payload) -> Result<()> {
        match p {
            Payload::Native { batch, header } => {
                let (_, expected) =
                    self.state
                        .execute_batch(&self.initial.currency, self.head, batch)?;
                ensure!(*header == expected, "native proposal execution");
            }
            Payload::Export(r) => {
                ensure!(
                    r.qc.votes.is_empty()
                        && r.creation.controller.source == self.state.domain
                        && self.state.controllers.contains(&r.creation.controller),
                    "prospective release"
                );
                let w = proof::ControllerWitness {
                    currency: self.initial.currency.clone(),
                    creation: r.creation.clone(),
                    terminal: r.terminal.clone(),
                    material: r.material.clone(),
                    covers: r.covers.clone(),
                    cancellation_authorization: None,
                };
                proof::execute_controller(&w)?;
                Verifier {
                    currency: &self.initial.currency,
                }
                .receipt(
                    self.initial.currency.proof.controller_image,
                    &proof::terminal_journal(&r.terminal),
                    &r.receipt,
                )?;
            }
            Payload::Cancel(c) => {
                consensus::validate_cancel_candidate(&self.state, &self.initial.currency, c)?
            }
        }
        Ok(())
    }
    fn authenticate_proposal_material(&self, p: &Proposal) -> Result<()> {
        let payload = consensus::payload(p)?;
        match &payload {
            Payload::Native { batch, header } => {
                ensure!(
                    header.currency == self.state.currency
                        && header.domain == self.state.domain
                        && header.sequence == p.preprepare.sequence
                        && header.configuration == p.preprepare.configuration
                        && header.batch == hash("RLD-BATCH", self.state.currency, batch),
                    "native complete envelope binding"
                );
                if let Some(old) = self.history.at(header.sequence)? {
                    if old.header.id() == header.id() {
                        ensure!(old.batch == *batch, "changed historical native body");
                    }
                } else {
                    self.validate_payload(&payload)?;
                }
            }
            _ => self.validate_payload(&payload)?,
        }
        Ok(())
    }
    fn authentication(&self, m: &Message) -> Result<(Option<Id>, Id)> {
        let (ns, seq) = message_position(m);
        let (cfg, pool, known) = if ns == self.state.domain {
            if let Some(old) = self.history.at(seq)? {
                (old.configuration.clone(), None, Some(old.header.id()))
            } else {
                ensure!(
                    seq == self
                        .state
                        .sequence
                        .checked_add(1)
                        .context("native exhaustion")?,
                    "unknown native position"
                );
                (self.state.configuration.clone(), None, None)
            }
        } else {
            let c = self
                .state
                .controllers
                .iter()
                .find(|c| c.id == ns)
                .context("unknown controller")?;
            ensure!(seq == 0, "controller position");
            (
                c.configuration.clone(),
                Some(c.pool_index),
                self.terminal_statement(ns),
            )
        };
        let mut e = Engine::new(cfg.clone(), ns, pool, seq)?;
        let statement = match m {
            Message::Proposal(p) => {
                crypto::verify_vote(&cfg, ns, pool, &p.preprepare)?;
                ensure!(
                    p.preprepare.sequence == seq
                        && p.preprepare.phase == 1
                        && p.preprepare.validator == e.primary(p.preprepare.view),
                    "proposal authentication"
                );
                consensus::payload(p)?.statement()
            }
            Message::Vote(v) => {
                crypto::verify_vote(&cfg, ns, pool, v)?;
                ensure!(
                    v.sequence == seq && (v.phase == 2 || v.phase == 3),
                    "vote position/phase"
                );
                v.statement
            }
            Message::ViewChange(v) => {
                e.verify_change(v)?;
                v.vote.statement
            }
            Message::NewView(v) => {
                e.verify_new_view(v)?;
                v.leader.statement
            }
            Message::Finalized { proposal, .. } => {
                e.handle(m)?;
                proposal.preprepare.statement
            }
        };
        match m {
            Message::Proposal(p) | Message::Finalized { proposal: p, .. } => {
                self.authenticate_proposal_material(p)?
            }
            Message::ViewChange(v) => {
                if let Some(p) = &v.prepared {
                    if !p.proposal.body.0.is_empty() {
                        self.authenticate_proposal_material(&p.proposal)?;
                    }
                }
            }
            Message::NewView(n) => {
                for v in &n.changes {
                    if let Some(p) = &v.prepared {
                        if !p.proposal.body.0.is_empty() {
                            self.authenticate_proposal_material(&p.proposal)?;
                        }
                    }
                }
            }
            _ => {}
        }
        let known = known.or_else(|| {
            self.engines
                .iter()
                .find(|e| e.namespace == ns && e.sequence == seq)
                .and_then(|e| e.finalized.as_ref())
                .and_then(|q| q.votes.first())
                .map(|v| v.statement)
        });
        Ok((known, statement))
    }
    fn apply(&mut self, event: &Event) -> Result<Vec<Action>> {
        let mut actions = Vec::new();
        match event {
            Event::Rejection(r) => {
                Verifier {
                    currency: &self.initial.currency,
                }
                .rejected(r)?;
                ensure!(
                    r.release.creation.controller.source == self.state.domain
                        && self
                            .state
                            .controllers
                            .contains(&r.release.creation.controller),
                    "foreign rejection receipt"
                );
                let id = r.release.creation.controller.id;
                if !self
                    .rejections
                    .iter()
                    .any(|r| r.release.creation.controller.id == id)
                {
                    self.rejections.push(r.clone());
                }
            }
            Event::Conflict(m) => {
                let (known, statement) = self.authentication(m)?;
                ensure!(
                    matches!(m, Message::Finalized { .. })
                        && known.is_some_and(|old| old != statement),
                    "not a qualified conflicting certificate"
                );
                self.faults.push(Blob(encode(m)));
            }
            Event::ConflictingBlock(c) => {
                let old = self
                    .history
                    .at(c.header.sequence)?
                    .context("conflict position")?;
                ensure!(
                    old.configuration == c.configuration && old.header.id() != c.header.id(),
                    "not a conflicting native certificate"
                );
                crypto::verify_quorum(
                    &old.configuration,
                    self.state.domain,
                    None,
                    &c.qc,
                    3,
                    c.header.id(),
                )?;
                ensure!(
                    c.qc.votes[0].sequence == c.header.sequence,
                    "conflict QC position"
                );
                self.faults.push(Blob(encode(c)));
            }
            Event::Candidate(candidate) => {
                self.validate_payload(candidate)?;
                if !self.candidates.contains(candidate) {
                    ensure!(self.candidates.len() < 4096, "candidate queue full");
                    self.candidates.push(candidate.clone());
                }
            }
            Event::Initial(_) => bail!("duplicate initialization"),
            Event::Queued(op) => {
                if self.pending.iter().any(|v| v == op)
                    || self.state.applied.get(op.id())?.is_some()
                {
                    return Ok(actions);
                }
                ensure!(self.pending.len() < 4096, "pending queue full");
                self.state.execute_batch(
                    &self.initial.currency,
                    self.head,
                    &Batch {
                        operations: vec![op.clone()],
                    },
                )?;
                self.pending.push(op.clone());
            }
            Event::Received(message) => {
                let (namespace, sequence) = message_position(message);
                self.authentication(message)?;
                if namespace == self.state.domain && sequence <= self.state.sequence {
                    return Ok(actions);
                }
                if namespace != self.state.domain && self.terminal_statement(namespace).is_some() {
                    return Ok(actions);
                }
                let i = self.engine(namespace, sequence)?;
                actions = self.engines[i].handle(message)?;
            }
            Event::Sent(dispatch) => {
                if let Application::Rejection(r) = &dispatch.message {
                    let id = r.release.creation.controller.id;
                    self.pending_rejections.remove(&id);
                    if !self.sent_rejections.contains(&id) {
                        self.sent_rejections.push(id);
                    }
                }
                if let Application::Consensus(Message::ViewChange(change)) = &dispatch.message {
                    let i = self.engine(change.namespace, change.sequence)?;
                    self.engines[i].begin_change(change)?;
                }
                let id = hash("RLD-DISPATCH", self.state.currency, dispatch);
                if !self.outbox.iter().any(|(i, _)| *i == id) && !self.delivered.contains(&id) {
                    ensure!(self.outbox.len() < 8192, "durable outbox full");
                    self.outbox.push((id, dispatch.clone()));
                }
            }
            Event::Delivered(id) => {
                self.outbox.retain(|(key, _)| key != id);
                if !self.delivered.contains(id) {
                    self.delivered.push(*id);
                }
            }
            Event::NativeCommitted(c) => {
                ensure!(
                    c.configuration == self.state.configuration,
                    "committing configuration"
                );
                let (mut next, h) =
                    self.state
                        .execute_batch(&self.initial.currency, self.head, &c.batch)?;
                ensure!(h == c.header, "committed native body");
                crypto::verify_quorum(&c.configuration, self.state.domain, None, &c.qc, 3, h.id())?;
                ensure!(c.qc.votes[0].sequence == h.sequence, "commit position");
                crate::state_storage::Backings::seal(&mut next)?;
                self.head = h.id();
                self.state = Arc::new(next);
                self.history.push(
                    c.clone(),
                    crate::state_storage::Backings::snapshot(&self.state)?,
                )?;
                for op in &c.batch.operations {
                    if let Command::Reject(r) = &op.command {
                        let id = r.creation.controller.id;
                        if !self.sent_rejections.contains(&id) {
                            self.pending_rejections
                                .entry(id)
                                .or_insert(c.header.sequence);
                        }
                    }
                    let terminal = match &op.command {
                        Command::ObserveExport(r) => {
                            let mut r = r.clone();
                            let qc = r.qc.clone();
                            r.qc = Quorum { votes: vec![] };
                            Some(TerminalRecord {
                                payload: Payload::Export(r),
                                qc,
                            })
                        }
                        Command::RedeemCancel(v) => {
                            let mut v = v.clone();
                            let qc = v.qc.clone();
                            v.qc = Quorum { votes: vec![] };
                            Some(TerminalRecord {
                                payload: Payload::Cancel(v),
                                qc,
                            })
                        }
                        Command::RedeemRejected(v) => {
                            let mut r = v.release.clone();
                            let qc = r.qc.clone();
                            r.qc = Quorum { votes: vec![] };
                            Some(TerminalRecord {
                                payload: Payload::Export(r),
                                qc,
                            })
                        }
                        _ => None,
                    };
                    if let Some(t) = terminal {
                        let id = payload_namespace(&t.payload);
                        if let Some(old) = self.terminal_statement(id) {
                            ensure!(
                                old == t.payload.statement(),
                                "conflicting retained terminal"
                            )
                        } else {
                            self.terminals.push(t)
                        }
                        self.candidates.retain(|p| payload_namespace(p) != id);
                        self.engines.retain(|e| e.namespace != id);
                    }
                }

                let mut still_pending = Vec::new();
                for op in &self.pending {
                    if self.state.applied.get(op.id())?.is_some() {
                        continue;
                    }
                    match self.state.execute_batch(
                        &self.initial.currency,
                        self.head,
                        &Batch {
                            operations: vec![op.clone()],
                        },
                    ) {
                        Ok(_) => still_pending.push(op.clone()),
                        Err(error) => self.failed.push((op.id(), error.to_string())),
                    }
                }
                self.pending = still_pending;
                self.engines
                    .retain(|e| e.namespace != self.state.domain || e.sequence > h.sequence);
            }
            Event::ControllerCommitted(record) => {
                self.validate_payload(&record.payload)?;
                let (id, config, index) = match &record.payload {
                    Payload::Export(r) => (
                        r.creation.controller.id,
                        &r.creation.controller.configuration,
                        r.creation.controller.pool_index,
                    ),
                    Payload::Cancel(r) => {
                        let c = self
                            .state
                            .controllers
                            .iter()
                            .find(|c| c.id == r.controller)
                            .context("controller")?;
                        (c.id, &c.configuration, c.pool_index)
                    }
                    _ => bail!("native controller outcome"),
                };
                crypto::verify_quorum(
                    config,
                    id,
                    Some(index),
                    &record.qc,
                    3,
                    record.payload.statement(),
                )?;
                if let Some(previous) = self.terminal_statement(id) {
                    ensure!(
                        previous == record.payload.statement(),
                        "conflicting terminal result"
                    );
                } else {
                    self.terminals.push(record.clone());
                }
                self.engines.retain(|e| e.namespace != id);
                self.candidates.retain(|p| payload_namespace(p) != id);
            }
            Event::MintIndex {
                sequence,
                certificate,
            } => {
                ensure!(
                    *sequence <= self.state.sequence,
                    "future Mint correspondence anchor"
                );
                rld_protocol::mints::index::verify(&self.initial.currency, certificate)?;
                ensure!(
                    certificate.claim == self.proof_context().mint_claim_at(*sequence)?,
                    "Mint correspondence differs from verified local history"
                );
                self.mint_certificates
                    .insert_verified(*sequence, certificate)?;
            }
            Event::Proof(p) => {
                Verifier {
                    currency: &self.initial.currency,
                }
                .native(p)?;
                let old = self
                    .history
                    .at(p.header.sequence)?
                    .filter(|v| v.header == p.header && v.configuration == p.configuration)
                    .context("certificate does not name retained local checkpoint")?;
                ensure!(
                    old.qc.votes[0].statement == p.qc.votes[0].statement,
                    "certificate statement"
                );
                self.proofs.insert_verified(p)?;
            }
        }
        Ok(actions)
    }
    pub fn proof_context(&self) -> crate::proving::ProofContext {
        crate::proving::ProofContext {
            initial: self.initial.clone(),
            state_index: self.state_index.clone(),
            state: self.state.clone(),
            history: self.history.clone(),
            proofs: self.proofs.clone(),
            mint_certificates: self.mint_certificates.clone(),
        }
    }
    pub fn state_at(&self, sequence: u64) -> Result<State> {
        self.proof_context().state_at(sequence)
    }
    pub fn cancel_draft(&self, id: Id) -> Result<(Controller, Cancellation)> {
        self.proof_context().cancel_draft(id)
    }
    pub fn native_input(&self, sequence: u64) -> Result<proof::NativeInput> {
        self.proof_context().native_input(sequence)
    }
    pub fn native_witness(&self, sequence: u64) -> Result<proof::NativeWitness> {
        self.proof_context().native_witness(sequence)
    }
    pub fn creation(&self, id: Id) -> Result<Creation> {
        self.proof_context().creation(id)
    }
}

impl Node {
    pub fn queue_candidate(&mut self, payload: Payload) -> Result<()> {
        if self.core.candidates.contains(&payload)
            || self
                .core
                .terminal_statement(payload_namespace(&payload))
                .is_some()
        {
            return Ok(());
        }
        self.persist(Event::Candidate(payload.clone()))?;
        self.send(Dispatch {
            destination: self.core.state.domain,
            message: Application::Candidate(payload),
        })
    }
    fn recover_terminal_effects(&mut self) -> Result<()> {
        for record in self.core.terminals.clone() {
            match record.payload {
                Payload::Export(mut r) => {
                    r.qc = record.qc;
                    self.send(Dispatch {
                        destination: r.creation.controller.ticket.destination,
                        message: Application::Payment(r.clone()),
                    })?;
                    if !self
                        .core
                        .state
                        .resolutions
                        .get(r.creation.controller.id)?
                        .is_some()
                    {
                        self.internal(Command::ObserveExport(r), "observe-export")?;
                    }
                }
                Payload::Cancel(mut c) => {
                    c.qc = record.qc;
                    if !self.core.state.redemptions.get(c.controller)?.is_some() {
                        self.internal(Command::RedeemCancel(c), "redeem-cancel")?;
                    }
                }
                _ => bail!("invalid terminal record"),
            }
        }
        Ok(())
    }
    fn recover_rejection_effects(&mut self) -> Result<()> {
        // The journal-derived pending index retains only unsent obligations,
        // not every historical rejection payload. Every payload is reread under
        // the immutable verified history root before proof construction.
        let cursor = self.rejection_cursor.unwrap_or(Id::ZERO);
        let pending: Vec<_> = self
            .core
            .pending_rejections
            .range((
                std::ops::Bound::Excluded(cursor),
                std::ops::Bound::Unbounded,
            ))
            .chain(self.core.pending_rejections.range(..=cursor))
            .take(16)
            .map(|(id, sequence)| (*id, *sequence))
            .collect();
        for (id, sequence) in pending {
            self.rejection_cursor = Some(id);
            let Some(certified) = self.core.proofs.at_or_after(sequence)? else {
                continue;
            };
            let record = self
                .core
                .history
                .at(sequence)?
                .context("pending rejection record")?;
            let release = record
                .batch
                .operations
                .iter()
                .find_map(|op| match &op.command {
                    Command::Reject(r) if r.creation.controller.id == id => Some(r),
                    _ => None,
                })
                .context("pending rejection native command")?;
            let context = self.core.proof_context();
            let at = certified.header.sequence;
            let c = &release.creation.controller;
            let evidence = Rejected {
                release: release.clone(),
                destination: certified.as_ref().clone(),
                decision: context.witness_at(at, "decisions", c.id)?,
                leaf_decision: context.witness_at(at, "coupon_uses", c.ticket.coupon)?,
            };
            Verifier {
                currency: &self.core.initial.currency,
            }
            .rejected(&evidence)?;
            self.send(Dispatch {
                destination: c.source,
                message: Application::Rejection(evidence),
            })?;
        }
        Ok(())
    }
    fn recover_signed_responses(&mut self) -> Result<()> {
        let mut pending: Vec<_> = self
            .signers
            .iter()
            .flat_map(|s| s.pending_responses().iter().cloned())
            .collect();
        pending.sort_by_key(|r| {
            (
                match r.vote.phase {
                    4 => 0,
                    5 => 1,
                    1 => 2,
                    _ => 3,
                },
                r.vote.view,
            )
        });
        for response in pending {
            let v = response.vote;
            if (v.namespace == self.core.state.domain && v.sequence > self.core.state.sequence)
                || (v.namespace != self.core.state.domain
                    && self.core.terminal_statement(v.namespace).is_none()
                    && !self.core.state.resolutions.get(v.namespace)?.is_some())
            {
                let _ = self.core.engine(v.namespace, v.sequence);
            }
            let Some(e) = self
                .core
                .engines
                .iter()
                .find(|e| {
                    e.namespace == v.namespace
                        && e.sequence == v.sequence
                        && e.configuration.id() == v.configuration
                })
                .cloned()
            else {
                continue;
            };
            if v.view < e.view
                || (v.phase == 4 && (v.view <= e.view || e.changing_to.is_some_and(|t| t > v.view)))
                || (v.phase == 5 && e.changing_to.is_some_and(|t| v.view < t))
                || (v.phase <= 3 && (v.view != e.view || e.changing_to.is_some()))
            {
                continue;
            }
            let message = match v.phase {
                1 => Message::Proposal(Proposal {
                    preprepare: v,
                    body: response.context,
                }),
                2 | 3 => Message::Vote(v),
                4 => {
                    let (ns, seq, next, prepared): (Id, u64, u64, Option<consensus::Prepared>) =
                        decode(&response.context.0, rld_protocol::MAX_CAPSULE)?;
                    Message::ViewChange(ViewChange {
                        namespace: ns,
                        sequence: seq,
                        next_view: next,
                        prepared,
                        vote: v,
                    })
                }
                5 => {
                    let changes: Vec<ViewChange> =
                        decode(&response.context.0, rld_protocol::MAX_CAPSULE)?;
                    Message::NewView(NewView { changes, leader: v })
                }
                _ => bail!("retained signer purpose"),
            };
            let d = Dispatch {
                destination: self.core.state.domain,
                message: Application::Consensus(message.clone()),
            };
            let id = hash("RLD-DISPATCH", self.core.state.currency, &d);
            if !self.core.delivered.contains(&id) && !self.core.outbox.iter().any(|(i, _)| *i == id)
            {
                self.send(d)?;
            }
            // Sending and applying are independent crash boundaries.
            let applied = match &message {
                Message::Proposal(p) => e.proposal.as_ref() == Some(p),
                Message::Vote(v) => e
                    .prepares
                    .iter()
                    .chain(e.commits.iter())
                    .any(|old| old == v),
                Message::ViewChange(v) => e.changes.contains(v),
                Message::NewView(v) => e.new_view.as_ref() == Some(v),
                _ => false,
            };
            if !applied {
                self.receive(message)?;
            }
        }
        Ok(())
    }
    pub fn initialize(path: &Path, head: &Path, initial: Initial) -> Result<Self> {
        let state = Core::initial_state(&initial)?;
        let store = Store::create(path, head, &encode(&Event::Initial(initial.clone())))?;
        let core = Core::new(initial, state, store.root_path())?;
        let mut node = Self {
            core,
            store,
            signers: vec![],
            timers: BTreeMap::new(),
            native_reconciled: BTreeMap::new(),
            terminal_reconciled: BTreeMap::new(),
            rejection_cursor: None,
            halted: false,
            last_error: None,
        };
        node.attach_state_index();
        Ok(node)
    }
    pub fn open(path: &Path, head: &Path, recover: bool) -> Result<Self> {
        let mut store = Store::open(path, head, recover)?;
        let mut core: Option<Core> = None;
        let root = store.root_path().to_owned();
        store.walk(|n, bytes| {
            let event: Event = decode(bytes, MAX_RECORD)?;
            if n == 1 {
                let Event::Initial(initial) = event else {
                    bail!("initial record required")
                };
                let state = Core::initial_state(&initial)?;
                core = Some(Core::new(initial, state, &root)?);
            } else {
                core.as_mut().context("initial record")?.apply(&event)?;
            }
            Ok(())
        })?;
        store.finish_recovery()?;
        let mut node = Self {
            halted: core.as_ref().is_some_and(|c| !c.faults.is_empty()),
            core: core.context("empty journal")?,
            store,
            signers: vec![],
            timers: BTreeMap::new(),
            native_reconciled: BTreeMap::new(),
            terminal_reconciled: BTreeMap::new(),
            rejection_cursor: None,
            last_error: None,
        };
        node.attach_state_index();
        Ok(node)
    }
    fn attach_state_index(&mut self) {
        match crate::state_index::StateIndex::open(
            &self.store.root_path().join("state-index"),
            &self.core.initial,
        ) {
            Ok(index) => self.core.state_index = Some(index),
            Err(error) => {
                self.last_error = Some(format!(
                    "derived state index unavailable; full native replay retained: {error}"
                ))
            }
        }
    }
    pub fn state_index_error(&self) -> Option<String> {
        self.core.state_index.as_ref().and_then(|i| i.issue())
    }
    pub fn add_signer(&mut self, signer: Vault) -> Result<()> {
        ensure!(
            signer.binding().currency == self.core.state.currency
                && signer.binding().domain == self.core.state.domain,
            "signer currency/home"
        );
        ensure!(
            !self.signers.iter().any(|v| v.binding() == signer.binding()),
            "duplicate signer custody"
        );
        self.signers.push(signer);
        self.reconcile_custody()
    }
    fn signer(&mut self, cfg: &Configuration) -> Result<&mut Vault> {
        self.signers
            .iter_mut()
            .find(|v| {
                v.binding().epoch == cfg.epoch
                    && v.binding().pool_epoch == cfg.pool_epoch
                    && cfg
                        .validators
                        .iter()
                        .any(|k| k.identity == v.binding().identity)
            })
            .context("no current operator signing custody loaded")
    }
    fn persist(&mut self, event: Event) -> Result<Vec<Action>> {
        ensure!(
            !self.halted,
            "node halted after storage failure; restart with verified latest heads"
        );
        let mut next = self.core.clone();
        let actions = next.apply(&event)?;
        if let Err(error) = self.store.append(&encode(&event)) {
            self.halted = true;
            return Err(error);
        }
        self.core = next;
        Ok(actions)
    }
    pub fn submit(&mut self, op: Operation) -> Result<Id> {
        let id = op.id();
        if let Some(old) = self.core.state.applied.get(id)? {
            ensure!(
                old.digest == Id::digest(&encode(&op)),
                "changed retained operation bytes"
            );
            return Ok(id);
        }
        if let Some(old) = self.core.pending.iter().find(|a| a.id() == id) {
            ensure!(old == &op, "changed pending operation bytes");
            return Ok(id);
        }
        // Ordinary new payments must not scan permanent history. Only the four
        // wrapper-retransmission kinds need the historical semantic comparison.
        let mut previous = None;
        let retained = match &op.command {
            Command::Import(r) | Command::Reject(r) => self
                .core
                .state
                .decisions
                .get(r.creation.controller.id)?
                .is_some(),
            Command::ObserveExport(r) => self
                .core
                .state
                .resolutions
                .get(r.creation.controller.id)?
                .is_some(),
            Command::RedeemCancel(c) => self.core.state.redemptions.get(c.controller)?.is_some(),
            _ => false,
        };
        if retained {
            for h in self.core.history.iter() {
                let h = h?;
                if let Some(old) =
                    h.batch
                        .operations
                        .iter()
                        .find(|old| match (&old.command, &op.command) {
                            (Command::Import(a), Command::Import(b))
                            | (Command::Reject(a), Command::Reject(b))
                            | (Command::ObserveExport(a), Command::ObserveExport(b)) => {
                                a.terminal == b.terminal
                                    && a.creation.controller == b.creation.controller
                            }
                            (Command::RedeemCancel(a), Command::RedeemCancel(b)) => {
                                a.terminal == b.terminal && a.controller == b.controller
                            }
                            _ => false,
                        })
                {
                    previous = Some(old.clone());
                    break;
                }
            }
        }
        if let Some(old) = previous {
            match &op.command {
                Command::Import(r) | Command::Reject(r) | Command::ObserveExport(r) => Verifier {
                    currency: &self.core.initial.currency,
                }
                .release(r)?,
                Command::RedeemCancel(c) => {
                    consensus::validate_cancel_candidate(
                        &self.core.state,
                        &self.core.initial.currency,
                        c,
                    )?;
                    let controller = self
                        .core
                        .state
                        .controllers
                        .iter()
                        .find(|v| v.id == c.controller)
                        .context("controller")?;
                    crypto::verify_quorum(
                        &controller.configuration,
                        controller.id,
                        Some(controller.pool_index),
                        &c.qc,
                        3,
                        c.terminal.id(),
                    )?;
                }
                _ => unreachable!(),
            }
            return Ok(old.id());
        }
        self.persist(Event::Queued(op))?;
        Ok(id)
    }
    fn send(&mut self, dispatch: Dispatch) -> Result<()> {
        let id = hash("RLD-DISPATCH", self.core.state.currency, &dispatch);
        if self.core.delivered.contains(&id) || self.core.outbox.iter().any(|(i, _)| *i == id) {
            return Ok(());
        }
        self.persist(Event::Sent(dispatch))?;
        Ok(())
    }
    pub fn acknowledge(&mut self, id: Id) -> Result<()> {
        ensure!(
            self.core.outbox.iter().any(|(i, _)| *i == id),
            "unknown outbox item"
        );
        self.persist(Event::Delivered(id))?;
        Ok(())
    }
    pub fn mint_index_certificate(
        &mut self,
        sequence: u64,
        certificate: rld_protocol::mints::index::Certificate,
    ) -> Result<()> {
        self.persist(Event::MintIndex {
            sequence,
            certificate,
        })?;
        Ok(())
    }
    pub fn certificate(&mut self, p: Certified) -> Result<()> {
        self.persist(Event::Proof(p))?;
        self.recover_rejection_effects()?;
        Ok(())
    }
    pub fn accept_block(&mut self, c: Committed) -> Result<()> {
        if c.header.sequence <= self.core.state.sequence {
            let old = self
                .core
                .history
                .at(c.header.sequence)?
                .context("history position")?;
            ensure!(
                old.configuration == c.configuration,
                "historical configuration"
            );
            crypto::verify_quorum(
                &c.configuration,
                self.core.state.domain,
                None,
                &c.qc,
                3,
                c.header.id(),
            )?;
            ensure!(
                c.qc.votes[0].sequence == c.header.sequence,
                "historical certificate position"
            );
            if old.header != c.header {
                self.persist(Event::ConflictingBlock(c))?;
                self.halted = true;
                bail!("conflicting certified native history retained; signing halted")
            }
            ensure!(old.batch == c.batch, "changed historical batch");
            return Ok(());
        }
        self.persist(Event::NativeCommitted(c))?;
        self.reconcile_custody()?;

        Ok(())
    }
    pub fn receive(&mut self, message: Message) -> Result<()> {
        let (ns, seq) = message_position(&message);
        let (known, statement) = self.core.authentication(&message)?;
        if matches!(message, Message::Finalized { .. }) && known.is_some_and(|old| old != statement)
        {
            self.persist(Event::Conflict(message))?;
            self.halted = true;
            bail!("conflicting complete certificate retained; signing halted")
        }
        if matches!(message, Message::NewView(_)) {
            self.timers.remove(&(ns, seq));
        }
        let actions = self.persist(Event::Received(message))?;
        self.actions(ns, seq, actions)
    }
    fn actions(&mut self, namespace: Id, sequence: u64, actions: Vec<Action>) -> Result<()> {
        let mut queue: VecDeque<Action> = actions.into();
        let mut steps = 0;
        while let Some(action) = queue.pop_front() {
            steps += 1;
            ensure!(steps <= 1024, "consensus action budget");
            match action {
                Action::Sign { phase, statement } => {
                    let e = self
                        .core
                        .engines
                        .iter()
                        .find(|e| e.namespace == namespace && e.sequence == sequence)
                        .context("active engine")?
                        .clone();
                    let vote = self.signer(&e.configuration)?.sign_vote(
                        &e.configuration,
                        namespace,
                        e.pool_index,
                        sequence,
                        e.view,
                        phase,
                        statement,
                        Blob(vec![]),
                    )?;
                    let message = Message::Vote(vote);
                    self.send(Dispatch {
                        destination: self.core.state.domain,
                        message: Application::Consensus(message.clone()),
                    })?;
                    let actions = self.persist(Event::Received(message))?;
                    queue.extend(actions);
                }
                Action::Commit { proposal, qc } => {
                    let payload = consensus::payload(&proposal)?;
                    let finality = Message::Finalized {
                        proposal: proposal.clone(),
                        qc: qc.clone(),
                    };
                    self.send(Dispatch {
                        destination: self.core.state.domain,
                        message: Application::Consensus(finality),
                    })?;
                    match payload {
                        Payload::Native { batch, header } => {
                            let c = Committed {
                                batch,
                                header,
                                qc,
                                configuration: self.core.state.configuration.clone(),
                            };
                            self.accept_block(c)?;
                        }
                        other => {
                            self.persist(Event::ControllerCommitted(TerminalRecord {
                                payload: other.clone(),
                                qc: qc.clone(),
                            }))?;
                            self.reconcile_custody()?;
                            match other {
                                Payload::Export(mut r) => {
                                    r.qc = qc;
                                    self.send(Dispatch {
                                        destination: r.creation.controller.ticket.destination,
                                        message: Application::Payment(r.clone()),
                                    })?;
                                    if !self
                                        .core
                                        .state
                                        .resolutions
                                        .get(r.creation.controller.id)?
                                        .is_some()
                                    {
                                        self.internal(Command::ObserveExport(r), "observe-export")?;
                                    }
                                }
                                Payload::Cancel(mut c) => {
                                    c.qc = qc;
                                    if !self.core.state.redemptions.get(c.controller)?.is_some() {
                                        self.internal(Command::RedeemCancel(c), "redeem-cancel")?;
                                    }
                                }
                                _ => unreachable!(),
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
    fn internal(&mut self, command: Command, tag: &str) -> Result<()> {
        let nonce = hash(
            "RLD-INTERNAL-NONCE",
            self.core.state.currency,
            &(tag, &command),
        );
        let op = Operation {
            currency: self.core.state.currency,
            home: self.core.state.domain,
            nonce,
            command,
            covers: vec![],
            authorizations: vec![],
        };
        self.submit(op)?;
        Ok(())
    }
    pub fn ingest(&mut self, dispatch: Dispatch) -> Result<()> {
        ensure!(
            dispatch.destination == self.core.state.domain,
            "not the monetary destination"
        );
        match dispatch.message {
            Application::Consensus(m) => self.receive(m)?,
            Application::Candidate(payload) => {
                self.queue_candidate(payload)?;
            }
            Application::Operation(op) => {
                self.submit(op)?;
            }
            Application::Certificate(p) => self.certificate(p)?,
            Application::Block(c) => self.accept_block(c)?,
            Application::Rejection(r) => {
                if !self.core.rejections.iter().any(|v| v == &r) {
                    self.persist(Event::Rejection(r))?;
                }
            }
            Application::Payment(r) => {
                Verifier {
                    currency: &self.core.initial.currency,
                }
                .release(&r)?;
                if !self
                    .core
                    .state
                    .decisions
                    .get(r.creation.controller.id)?
                    .is_some()
                {
                    self.internal(Command::Import(r), "import")?;
                }
            }
        }
        Ok(())
    }
    pub fn propose(&mut self, candidate: Option<Payload>) -> Result<bool> {
        let (ns, seq) = match &candidate {
            Some(Payload::Export(r)) => (r.creation.controller.id, 0),
            Some(Payload::Cancel(c)) => (c.controller, 0),
            _ => (
                self.core.state.domain,
                self.core
                    .state
                    .sequence
                    .checked_add(1)
                    .context("sequence exhaustion")?,
            ),
        };
        let i = self.core.engine(ns, seq)?;
        let e = self.core.engines[i].clone();
        if e.proposal.is_some() || e.terminal() || e.changing_to.is_some() {
            return Ok(false);
        }
        let identity = match self.signer(&e.configuration) {
            Ok(v) => v.binding().identity,
            Err(_) => return Ok(false),
        };
        if e.primary(e.view) != identity {
            return Ok(false);
        }
        let selected = e
            .new_view
            .as_ref()
            .map(|nv| e.verify_new_view(nv))
            .transpose()?
            .flatten();
        let payload = if let Some(mut p) = selected {
            if p.body.0.is_empty() {
                let statement = p.preprepare.statement;
                let retained = e
                    .prepared
                    .iter()
                    .map(|p| &p.proposal)
                    .chain(
                        e.changes
                            .iter()
                            .filter_map(|v| v.prepared.as_ref().map(|p| &p.proposal)),
                    )
                    .find(|p| p.preprepare.statement == statement && !p.body.0.is_empty());
                if let Some(retained) = retained {
                    p.body = retained.body.clone();
                } else if let Some(candidate) =
                    candidate.as_ref().filter(|v| v.statement() == statement)
                {
                    p.body = Blob(encode(candidate));
                } else {
                    return Ok(false);
                }
            }
            consensus::payload(&p)?
        } else if let Some(p) = candidate {
            p
        } else {
            let mut batch = Batch { operations: vec![] };
            for op in &self.core.pending {
                let mut tentative = batch.clone();
                tentative.operations.push(op.clone());
                if encode(&tentative).len() + 256 * 1024 < rld_protocol::MAX_CAPSULE
                    && self
                        .core
                        .state
                        .execute_batch(&self.core.initial.currency, self.core.head, &tentative)
                        .is_ok()
                {
                    batch = tentative;
                }
                if batch.operations.len() == 64 {
                    break;
                }
            }
            if batch.operations.is_empty() {
                return Ok(false);
            }
            let (_, header) = self.core.state.execute_batch(
                &self.core.initial.currency,
                self.core.head,
                &batch,
            )?;
            Payload::Native { batch, header }
        };
        self.core.validate_payload(&payload)?;
        let vote = self.signer(&e.configuration)?.sign_vote(
            &e.configuration,
            ns,
            e.pool_index,
            seq,
            e.view,
            1,
            payload.statement(),
            Blob(encode(&payload)),
        )?;
        let proposal = Proposal {
            preprepare: vote,
            body: Blob(encode(&payload)),
        };
        let message = Message::Proposal(proposal);
        self.send(Dispatch {
            destination: self.core.state.domain,
            message: Application::Consensus(message.clone()),
        })?;
        self.receive(message)?;
        Ok(true)
    }
    fn reconcile_custody(&mut self) -> Result<()> {
        for signer in &mut self.signers {
            let binding = hash(
                "RLD-LOCAL-CUSTODY-CURSOR",
                self.core.state.currency,
                signer.binding(),
            );
            let after = self.native_reconciled.get(&binding).copied().unwrap_or(0);
            for committed in self.core.history.after(after) {
                let committed = committed?;
                if committed
                    .configuration
                    .validators
                    .iter()
                    .any(|v| v.identity == signer.binding().identity)
                    && signer.binding().epoch == committed.configuration.epoch
                    && signer.binding().pool_epoch == committed.configuration.pool_epoch
                {
                    signer.reconcile_native(
                        &committed.configuration,
                        &committed.qc,
                        committed.header.id(),
                    )?;
                }
                self.native_reconciled
                    .insert(binding, committed.header.sequence);
            }
            let terminal_after = self.terminal_reconciled.get(&binding).copied().unwrap_or(0);
            for (index, record) in self.core.terminals.iter().enumerate().skip(terminal_after) {
                let id = match &record.payload {
                    Payload::Export(r) => r.creation.controller.id,
                    Payload::Cancel(c) => c.controller,
                    _ => continue,
                };
                let c = self
                    .core
                    .state
                    .controllers
                    .iter()
                    .find(|c| c.id == id)
                    .context("terminal creation")?;
                if c.configuration
                    .validators
                    .iter()
                    .any(|v| v.identity == signer.binding().identity)
                    && signer.binding().epoch == c.configuration.epoch
                    && signer.binding().pool_epoch == c.configuration.pool_epoch
                {
                    signer.retire_controller(
                        &c.configuration,
                        id,
                        c.pool_index,
                        &record.qc,
                        record.payload.statement(),
                    )?;
                }
                self.terminal_reconciled.insert(binding, index + 1);
            }
        }
        Ok(())
    }
    pub fn tick(&mut self) -> Result<()> {
        ensure!(
            !self.halted,
            "node halted; reconcile retained evidence before signing"
        );
        self.recover_signed_responses()?;
        let done: Vec<_> = self
            .core
            .engines
            .iter()
            .filter_map(|e| {
                e.finalized
                    .as_ref()
                    .zip(e.proposal.as_ref())
                    .map(|(q, p)| (e.namespace, e.sequence, q.clone(), p.clone()))
            })
            .collect();
        for (ns, seq, q, p) in done {
            self.actions(ns, seq, vec![Action::Commit { proposal: p, qc: q }])?;
        }
        self.recover_terminal_effects()?;
        self.recover_rejection_effects()?;
        self.propose(None)?;
        for candidate in self.core.candidates.clone() {
            self.propose(Some(candidate))?;
        }
        // Rebuild actions whose authenticated input was journaled before a crash,
        // but whose private response had not yet been released.
        for e in self.core.engines.clone() {
            if e.terminal() || e.changing_to.is_some() {
                continue;
            }
            let Ok(signer) = self.signer(&e.configuration) else {
                continue;
            };
            let identity = signer.binding().identity;
            if let Some(p) = &e.proposal {
                let mut actions = Vec::new();
                if !e.prepares.iter().any(|v| v.validator == identity) {
                    actions.push(Action::Sign {
                        phase: 2,
                        statement: p.preprepare.statement,
                    });
                }
                if e.prepared
                    .as_ref()
                    .is_some_and(|p| p.proposal.preprepare.view == e.view)
                    && !e.commits.iter().any(|v| v.validator == identity)
                {
                    actions.push(Action::Sign {
                        phase: 3,
                        statement: p.preprepare.statement,
                    });
                }
                self.actions(e.namespace, e.sequence, actions)?;
            }
        }
        let engines = self.core.engines.clone();
        self.timers.retain(|key, _| {
            engines
                .iter()
                .any(|e| (e.namespace, e.sequence) == *key && !e.terminal())
        });
        for e in engines {
            if e.terminal() {
                continue;
            }
            let active = e.proposal.is_some()
                || if e.namespace == self.core.state.domain {
                    !self.core.pending.is_empty()
                } else {
                    self.core
                        .candidates
                        .iter()
                        .any(|p| payload_namespace(p) == e.namespace)
                };
            if !active {
                continue;
            }
            let view = e.changing_to.unwrap_or(e.view);
            let now = Instant::now();
            let timer = self
                .timers
                .entry((e.namespace, e.sequence))
                .or_insert((view, now));
            if timer.0 != view {
                *timer = (view, now);
            }
            // Checked exponential timeouts allow eventual synchrony without a
            // permanent wall-clock expiry of an outstanding payment.
            let millis = 10_000u64
                .checked_shl(u32::try_from(view).context("view timer exhausted")?)
                .context("view timer exhausted")?;
            let expires = timer
                .1
                .checked_add(Duration::from_millis(millis))
                .context("view timer exhausted")?;
            if now < expires {
                continue;
            }
            let next = e.next_view()?;
            let statement = e.change_digest(&ViewChange {
                namespace: e.namespace,
                sequence: e.sequence,
                next_view: next,
                prepared: e.prepared.clone(),
                vote: empty_vote(),
            });
            let Ok(signer) = self.signer(&e.configuration) else {
                continue;
            };
            let vote = signer.sign_vote(
                &e.configuration,
                e.namespace,
                e.pool_index,
                e.sequence,
                next,
                4,
                statement,
                Blob(encode(&(e.namespace, e.sequence, next, &e.prepared))),
            )?;
            let m = Message::ViewChange(ViewChange {
                namespace: e.namespace,
                sequence: e.sequence,
                next_view: next,
                prepared: e.prepared.clone(),
                vote,
            });
            self.send(Dispatch {
                destination: self.core.state.domain,
                message: Application::Consensus(m.clone()),
            })?;
            self.receive(m)?;
            self.timers.insert((e.namespace, e.sequence), (next, now));
        }
        for e in self.core.engines.clone() {
            if e.terminal() {
                continue;
            }
            let targets: std::collections::BTreeSet<_> = e
                .changes
                .iter()
                .filter(|v| v.next_view > e.view && e.changing_to.is_none_or(|t| v.next_view >= t))
                .map(|v| v.next_view)
                .collect();
            for next in targets {
                let mut changes: Vec<_> = e
                    .changes
                    .iter()
                    .filter(|v| v.next_view == next)
                    .cloned()
                    .collect();
                changes.sort_by_key(|v| v.vote.validator);
                let quorum = e.configuration.quorum()?;
                if changes.len() < quorum {
                    continue;
                }
                changes.truncate(quorum);
                for change in &mut changes {
                    if let Some(prepared) = &mut change.prepared {
                        prepared.proposal.body.0.clear();
                    }
                }
                let Ok(signer) = self.signer(&e.configuration) else {
                    continue;
                };
                if signer.binding().identity != e.primary(next) {
                    continue;
                }
                let leader = signer.sign_vote(
                    &e.configuration,
                    e.namespace,
                    e.pool_index,
                    e.sequence,
                    next,
                    5,
                    e.new_view_digest(&changes, next),
                    Blob(encode(&changes)),
                )?;
                let m = Message::NewView(NewView { changes, leader });
                self.send(Dispatch {
                    destination: self.core.state.domain,
                    message: Application::Consensus(m.clone()),
                })?;
                self.receive(m)?;
                if e.namespace == self.core.state.domain {
                    self.propose(None)?;
                } else if let Some(candidate) = self
                    .core
                    .candidates
                    .iter()
                    .find(|p| payload_namespace(p) == e.namespace)
                    .cloned()
                {
                    self.propose(Some(candidate))?;
                }
                break;
            }
        }
        Ok(())
    }
    pub fn archive_history(&mut self) -> Result<bool> {
        ensure!(
            !self.halted,
            "halted node cannot publish archive maintenance"
        );
        self.store.archive_completed()
    }
    pub fn journal_tip(&self) -> Id {
        self.store.tip.head
    }
}
