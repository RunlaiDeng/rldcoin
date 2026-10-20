//! PBFT safety state. The node must durably publish each returned state before
//! requesting signatures or releasing any messages. Timeouts only request a
//! view change; they never commit, refund, unlock escrow or erase evidence.
use crate::{
    codec::{Blob, Id, decode, hash},
    crypto,
    model::*,
    record,
};
use anyhow::{Result, ensure};
use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};

record!(Proposal {preprepare:Vote  =>  0,body:Blob  =>  1});
record!(Prepared {proposal:Proposal  =>  0,qc:Quorum  =>  1});
record!(ViewChange {namespace:Id  =>  0,sequence:u64  =>  1,next_view:u64  =>  2,prepared:Option<Prepared>  =>  3,vote:Vote  =>  4});
record!(NewView {changes:Vec<ViewChange>  =>  0,leader:Vote  =>  1});
record!(Engine {configuration:Configuration  =>  0,namespace:Id  =>  1,pool_index:Option<u32>  =>  2,sequence:u64  =>  3,view:u64  =>  4,proposal:Option<Proposal>  =>  5,prepares:Vec<Vote>  =>  6,commits:Vec<Vote>  =>  7,prepared:Option<Prepared>  =>  8,finalized:Option<Quorum>  =>  9,changes:Vec<ViewChange>  =>  10,new_view:Option<NewView>  =>  11,changing_to:Option<u64> => 12});

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub enum Message {
    #[n(0)]
    Proposal(#[n(0)] Proposal),
    #[n(1)]
    Vote(#[n(0)] Vote),
    #[n(2)]
    ViewChange(#[n(0)] ViewChange),
    #[n(3)]
    NewView(#[n(0)] NewView),
    #[n(4)]
    Finalized {
        #[n(0)]
        proposal: Proposal,
        #[n(1)]
        qc: Quorum,
    },
}
#[derive(Clone, Debug)]
pub enum Action {
    Sign { phase: u8, statement: Id },
    Commit { proposal: Proposal, qc: Quorum },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub enum Payload {
    #[n(0)]
    Native {
        #[n(0)]
        batch: Batch,
        #[n(1)]
        header: Checkpoint,
    },
    #[n(1)]
    Export(#[n(0)] Release),
    #[n(2)]
    Cancel(#[n(0)] Cancellation),
}
impl Payload {
    pub fn statement(&self) -> Id {
        match self {
            Self::Native { header, .. } => header.id(),
            Self::Export(r) => r.terminal.id(),
            Self::Cancel(c) => c.terminal.id(),
        }
    }
}
pub fn payload(p: &Proposal) -> Result<Payload> {
    let v: Payload = decode(&p.body.0, crate::MAX_CAPSULE)?;
    ensure!(
        v.statement() == p.preprepare.statement,
        "proposal statement/body"
    );
    Ok(v)
}

impl Engine {
    pub fn new(
        configuration: Configuration,
        namespace: Id,
        pool_index: Option<u32>,
        sequence: u64,
    ) -> Result<Self> {
        configuration.validate()?;
        ensure!(pool_index.is_none() || sequence == 0, "controller sequence");
        Ok(Self {
            configuration,
            namespace,
            pool_index,
            sequence,
            view: 0,
            proposal: None,
            prepares: vec![],
            commits: vec![],
            prepared: None,
            finalized: None,
            changes: vec![],
            new_view: None,
            changing_to: None,
        })
    }
    pub fn primary(&self, view: u64) -> Id {
        self.configuration.validators[(view % self.configuration.validators.len() as u64) as usize]
            .identity
    }
    fn vote(&self, v: &Vote) -> Result<()> {
        crypto::verify_vote(&self.configuration, self.namespace, self.pool_index, v)?;
        ensure!(v.sequence == self.sequence, "PBFT position");
        Ok(())
    }
    pub fn handle(&mut self, m: &Message) -> Result<Vec<Action>> {
        let mut actions = Vec::new();
        match m {
            Message::Finalized { proposal, qc } => {
                self.vote(&proposal.preprepare)?;
                payload(proposal)?;
                ensure!(
                    proposal.preprepare.phase == 1
                        && proposal.preprepare.validator == self.primary(proposal.preprepare.view),
                    "certified primary"
                );
                crypto::verify_quorum(
                    &self.configuration,
                    self.namespace,
                    self.pool_index,
                    qc,
                    3,
                    proposal.preprepare.statement,
                )?;
                ensure!(
                    qc.votes[0].sequence == self.sequence
                        && qc.votes[0].view == proposal.preprepare.view,
                    "certified position"
                );
                if let Some(old) = &self.finalized {
                    ensure!(
                        old.votes[0].statement == proposal.preprepare.statement,
                        "conflicting complete certificate"
                    );
                    return Ok(actions);
                }
                self.proposal = Some(proposal.clone());
                self.finalized = Some(qc.clone());
                actions.push(Action::Commit {
                    proposal: proposal.clone(),
                    qc: qc.clone(),
                });
            }
            Message::Proposal(p) => {
                self.vote(&p.preprepare)?;
                if self.changing_to.is_some() {
                    return Ok(actions);
                }
                ensure!(
                    p.preprepare.phase == 1
                        && p.preprepare.view == self.view
                        && p.preprepare.validator == self.primary(self.view),
                    "preprepare primary/view"
                );
                payload(p)?;
                if let Some(old) = &self.proposal {
                    ensure!(old == p, "primary equivocation");
                    return Ok(actions);
                }
                if self.view == 0 {
                    ensure!(self.prepared.is_none(), "unexpected initial lock");
                } else {
                    let nv = self
                        .new_view
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("new-view certificate required"))?;
                    if let Some(chosen) = self.verify_new_view(nv)? {
                        ensure!(
                            chosen.preprepare.statement == p.preprepare.statement,
                            "new-view chosen body"
                        );
                    }
                }
                self.proposal = Some(p.clone());
                actions.push(Action::Sign {
                    phase: 2,
                    statement: p.preprepare.statement,
                });
            }
            Message::Vote(v) => {
                self.vote(v)?;
                ensure!(
                    v.view == self.view && (v.phase == 2 || v.phase == 3),
                    "prepare/commit view"
                );
                let p = self
                    .proposal
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("proposal body not installed"))?;
                ensure!(
                    v.statement == p.preprepare.statement,
                    "vote proposal mismatch"
                );
                let votes = if v.phase == 2 {
                    &mut self.prepares
                } else {
                    &mut self.commits
                };
                if let Some(old) = votes.iter().find(|x| x.validator == v.validator) {
                    ensure!(old == v, "validator equivocation");
                    return Ok(actions);
                }
                votes.push(v.clone());
                votes.sort_by_key(|v| v.validator);
                if v.phase == 2
                    && self.prepares.len() >= self.configuration.quorum()?
                    && self
                        .prepared
                        .as_ref()
                        .is_none_or(|p| p.proposal.preprepare.view < self.view)
                {
                    let qc = Quorum {
                        votes: self.prepares.clone(),
                    };
                    crypto::verify_quorum(
                        &self.configuration,
                        self.namespace,
                        self.pool_index,
                        &qc,
                        2,
                        v.statement,
                    )?;
                    self.prepared = Some(Prepared {
                        proposal: p.clone(),
                        qc,
                    });
                    if self.changing_to.is_none() {
                        actions.push(Action::Sign {
                            phase: 3,
                            statement: v.statement,
                        });
                    }
                }
                if self.commits.len() >= self.configuration.quorum()? && self.finalized.is_none() {
                    let qc = Quorum {
                        votes: self.commits.clone(),
                    };
                    crypto::verify_quorum(
                        &self.configuration,
                        self.namespace,
                        self.pool_index,
                        &qc,
                        3,
                        v.statement,
                    )?;
                    self.finalized = Some(qc.clone());
                    actions.push(Action::Commit {
                        proposal: p.clone(),
                        qc,
                    });
                }
            }
            Message::ViewChange(vc) => {
                self.verify_change(vc)?;
                ensure!(vc.next_view >= self.view, "stale view change");
                if let Some(old) = self
                    .changes
                    .iter()
                    .find(|x| x.vote.validator == vc.vote.validator && x.next_view == vc.next_view)
                {
                    ensure!(old == vc, "changed view-change evidence");
                } else {
                    let mut own: Vec<_> = self
                        .changes
                        .iter()
                        .filter(|x| x.vote.validator == vc.vote.validator)
                        .map(|x| x.next_view)
                        .collect();
                    own.sort();
                    if own.len() >= 8 {
                        let oldest = own[0];
                        if vc.next_view <= oldest {
                            return Ok(actions);
                        }
                        self.changes.retain(|x| {
                            x.vote.validator != vc.vote.validator || x.next_view != oldest
                        });
                    }
                    self.changes.push(vc.clone());
                }
            }
            Message::NewView(nv) => {
                if self.new_view.as_ref() == Some(nv) {
                    return Ok(actions);
                }
                let _ = self.verify_new_view(nv)?;
                ensure!(
                    nv.leader.view > self.view || self.new_view.as_ref() == Some(nv),
                    "stale new view"
                );
                ensure!(
                    self.finalized.is_none()
                        && self
                            .changing_to
                            .is_none_or(|target| nv.leader.view >= target),
                    "already committed or newer view requested"
                );
                self.changing_to = None;
                self.view = nv.leader.view;
                self.proposal = None;
                self.prepares.clear();
                self.commits.clear();
                self.new_view = Some(nv.clone());
                self.changes.retain(|v| v.next_view >= self.view);
            }
        }
        Ok(actions)
    }
    pub fn change_digest(&self, vc: &ViewChange) -> Id {
        hash(
            "RLD-PBFT-VIEW-CHANGE",
            self.configuration.currency,
            &(vc.namespace, vc.sequence, vc.next_view, &vc.prepared),
        )
    }
    pub fn verify_change(&self, vc: &ViewChange) -> Result<()> {
        self.vote(&vc.vote)?;
        ensure!(
            vc.namespace == self.namespace
                && vc.sequence == self.sequence
                && vc.vote.phase == 4
                && vc.vote.view == vc.next_view
                && vc.next_view > 0
                && vc.vote.statement == self.change_digest(vc),
            "view-change binding"
        );
        if let Some(p) = &vc.prepared {
            self.vote(&p.proposal.preprepare)?;
            ensure!(
                p.proposal.preprepare.phase == 1
                    && p.proposal.preprepare.validator == self.primary(p.proposal.preprepare.view)
                    && p.proposal.preprepare.view < vc.next_view,
                "prepared primary/view"
            );
            payload(&p.proposal)?;
            crypto::verify_quorum(
                &self.configuration,
                self.namespace,
                self.pool_index,
                &p.qc,
                2,
                p.proposal.preprepare.statement,
            )?;
            ensure!(
                p.qc.votes[0].view == p.proposal.preprepare.view
                    && p.qc.votes[0].sequence == self.sequence,
                "prepared QC position"
            );
        }
        Ok(())
    }
    pub fn new_view_digest(&self, changes: &[ViewChange], view: u64) -> Id {
        hash(
            "RLD-PBFT-NEW-VIEW",
            self.configuration.currency,
            &(self.namespace, self.sequence, view, changes),
        )
    }
    pub fn verify_new_view(&self, nv: &NewView) -> Result<Option<Proposal>> {
        self.vote(&nv.leader)?;
        ensure!(
            nv.leader.phase == 5
                && nv.leader.view > 0
                && nv.leader.validator == self.primary(nv.leader.view)
                && nv.changes.len() >= self.configuration.quorum()?
                && nv.changes.len() <= self.configuration.validators.len()
                && nv
                    .changes
                    .windows(2)
                    .all(|w| w[0].vote.validator < w[1].vote.validator)
                && nv.leader.statement == self.new_view_digest(&nv.changes, nv.leader.view),
            "new-view binding/quorum"
        );
        let mut highest: Option<&Prepared> = None;
        for vc in &nv.changes {
            self.verify_change(vc)?;
            ensure!(vc.next_view == nv.leader.view, "mixed new views");
            if let Some(p) = &vc.prepared {
                if let Some(old) = highest {
                    if p.proposal.preprepare.view == old.proposal.preprepare.view {
                        ensure!(
                            p.proposal.preprepare.statement == old.proposal.preprepare.statement,
                            "conflicting highest prepared"
                        );
                    }
                }
                if highest.is_none_or(|v| {
                    p.proposal.preprepare.view > v.proposal.preprepare.view
                        || (p.proposal.preprepare.view == v.proposal.preprepare.view
                            && Id::digest(&p.proposal.body.0) < Id::digest(&v.proposal.body.0))
                }) {
                    highest = Some(p);
                }
            }
        }
        Ok(highest.map(|p| p.proposal.clone()))
    }
    pub fn begin_change(&mut self, change: &ViewChange) -> Result<()> {
        self.verify_change(change)?;
        ensure!(
            change.next_view > self.view && self.changing_to.is_none_or(|v| change.next_view >= v),
            "view-change progression"
        );
        self.changing_to = Some(change.next_view);
        Ok(())
    }
    pub fn terminal(&self) -> bool {
        self.finalized.is_some()
    }
    pub fn statement(&self) -> Result<Id> {
        self.proposal
            .as_ref()
            .map(|p| p.preprepare.statement)
            .ok_or_else(|| anyhow::anyhow!("no proposal"))
    }
    pub fn next_view(&self) -> Result<u64> {
        ensure!(!self.terminal(), "committed round");
        self.changing_to
            .unwrap_or(self.view)
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("view exhaustion"))
    }
}

pub fn validate_cancel_candidate(
    state: &crate::state::State,
    currency: &Currency,
    cancel: &Cancellation,
) -> Result<()> {
    let c = state
        .controllers
        .iter()
        .find(|c| c.id == cancel.controller)
        .ok_or_else(|| anyhow::anyhow!("local controller absent"))?;
    let birth = state
        .births
        .iter()
        .find(|b| b.controller == c.id)
        .ok_or_else(|| anyhow::anyhow!("controller birth absent"))?;
    ensure!(
        birth.sequence == cancel.source_header.sequence
            && cancel.source_header.domain == c.source
            && cancel.source_header.configuration == c.configuration.id(),
        "cancel birth"
    );
    crypto::verify_quorum(
        &c.configuration,
        c.source,
        None,
        &cancel.source_qc,
        3,
        cancel.source_header.id(),
    )?;
    ensure!(
        cancel.source_qc.votes[0].sequence == birth.sequence,
        "creation QC sequence"
    );
    let verifier = crate::proof::Verifier { currency };
    verifier.witness(
        &cancel.source_header,
        "controllers",
        c.id,
        hash("RLD-CONTROLLER", state.currency, c),
        &cancel.delegation,
    )?;
    let d = Delegation {
        coupon: c.ticket.coupon,
        controller: Some(c.id),
        closed: false,
    };
    verifier.witness(
        &cancel.source_header,
        "coupon_uses",
        d.coupon,
        hash("RLD-DELEGATION", state.currency, &d),
        &cancel.coupon_use,
    )?;
    crate::proof::validate_terminal(c, cancel.source_header.id(), &cancel.terminal, 2)?;
    crypto::authorize(
        &c.ticket.cancel_policy,
        std::slice::from_ref(&cancel.authorization),
        &crate::proof::cancellation_bytes(c),
    )?;
    ensure!(
        cancel.qc.votes.is_empty(),
        "candidate contains its own terminal QC"
    );
    Ok(())
}
