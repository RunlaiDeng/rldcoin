//! Typed public consensus carriage. The mesh never supplies validator rights.
//! Standalone proof verification precedes catch-up or any new local signature.
use super::*;
use crate::{bft, storage::Store};

pub const FORMAT: &str = "RLD-REGIONAL-BFT-NETWORK-V2";
pub const COLD_BATCH_FORMAT: &str = "RLD-BFT-COLD-NETWORK-CHECK-V1";
pub const MAX_COLD_BATCH: usize = 4;
pub const LIVE_BATCH_FORMAT: &str = "RLD-BFT-LIVE-NETWORK-INSPECTION-V1";

#[derive(Debug, Serialize)]
pub struct LiveChecked {
    pub message_id: Hash,
    pub value: Option<Hash>,
    pub evidence: Evidence,
    pub epochs: Vec<epoch::Transition>,
}

/// Authenticate each complete live envelope under one read-only store open.
/// Return nothing or synchronize nothing until the whole bounded batch passes.
pub fn inspect_live_batch(wires: Vec<WireEnvelope>, node: &Store) -> Result<Vec<LiveChecked>> {
    require(
        !wires.is_empty() && wires.len() <= MAX_COLD_BATCH,
        "live network batch count exceeds bound",
    )?;
    require(
        serde_json::to_vec(&wires).map_err(|e| e.to_string())?.len() <= MAX_BYTES,
        "encoded live network batch exceeds bound",
    )?;
    let mut checked = Vec::with_capacity(wires.len());
    let mut size = 2usize;
    for wire in wires {
        require(
            serde_json::to_vec(&wire).map_err(|e| e.to_string())?.len()
                <= crate::contact::MAX_PAYLOAD,
            "live network envelope exceeds payload bound",
        )?;
        let envelope = wire.expand()?;
        let message_id = envelope.verify(node)?;
        let value = envelope.value()?;
        let epochs = envelope.carried_epochs().to_vec();
        let row = LiveChecked {
            message_id,
            value,
            evidence: envelope.evidence,
            epochs,
        };
        size = size
            .checked_add(
                serde_json::to_vec(&row).map_err(|e| e.to_string())?.len()
                    + usize::from(!checked.is_empty()),
            )
            .ok_or("live network batch response length overflow")?;
        // Reserve wrapper space; the CLI checks the exact complete output too.
        require(
            size <= MAX_BYTES - 1024,
            "live network batch response exceeds bound",
        )?;
        checked.push(row);
    }
    Ok(checked)
}

#[derive(Debug, Serialize)]
pub struct ColdChecked {
    pub message_id: Hash,
    pub value: Option<Hash>,
}

/// Complete independent envelope authentication, never catch-up or signing.
/// Return nothing unless the entire bounded ordered batch succeeds.
pub fn check_cold_batch(wires: Vec<WireEnvelope>, node: &Store) -> Result<Vec<ColdChecked>> {
    require(
        !wires.is_empty() && wires.len() <= MAX_COLD_BATCH,
        "cold network batch count exceeds bound",
    )?;
    require(
        serde_json::to_vec(&wires).map_err(|e| e.to_string())?.len() <= MAX_BYTES,
        "encoded cold network batch exceeds bound",
    )?;
    let mut checked = Vec::with_capacity(wires.len());
    for wire in wires {
        require(
            serde_json::to_vec(&wire).map_err(|e| e.to_string())?.len()
                <= crate::contact::MAX_PAYLOAD,
            "cold network envelope exceeds payload bound",
        )?;
        let envelope = wire.expand()?;
        checked.push(ColdChecked {
            message_id: envelope.verify(node)?,
            value: envelope.value()?,
        });
    }
    Ok(checked)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Body {
    Signed(Box<bft::Message>),
    Finalized(Box<Snapshot>),
    Submission(Vec<Command>),
    EpochApproval(Box<crate::joint_epoch::CarriedApproval>),
    EpochActivation(Box<epoch::Transition>),
    EpochSigned {
        message: Box<bft::Message>,
        epochs: Vec<epoch::Transition>,
    },
    EpochSubmission {
        commands: Vec<Command>,
        epochs: Vec<epoch::Transition>,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub format: String,
    pub currency: Hash,
    pub region: Hash,
    pub evidence: Evidence,
    pub body: Body,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireEnvelope {
    pub format: String,
    pub currency: Hash,
    pub region: Hash,
    pub evidence: crate::carriage::CarriedEvidence,
    pub body: Body,
}
impl WireEnvelope {
    pub fn expand(self) -> Result<Envelope> {
        require(self.format == FORMAT, "consensus wire format mismatch")?;
        Ok(Envelope {
            format: self.format,
            currency: self.currency,
            region: self.region,
            evidence: self.evidence.expand()?,
            body: self.body,
        })
    }
}
impl Envelope {
    pub fn pack(&self) -> Result<WireEnvelope> {
        require(self.format == FORMAT, "consensus wire format mismatch")?;
        Ok(WireEnvelope {
            format: self.format.clone(),
            currency: self.currency,
            region: self.region,
            evidence: crate::carriage::CarriedEvidence::pack(&self.evidence)?,
            body: self.body.clone(),
        })
    }
    pub fn carried_epochs(&self) -> &[epoch::Transition] {
        match &self.body {
            Body::EpochSigned { epochs, .. } | Body::EpochSubmission { epochs, .. } => epochs,
            _ => &[],
        }
    }
    pub fn value(&self) -> Result<Option<Hash>> {
        match &self.body {
            Body::Signed(message) | Body::EpochSigned { message, .. } => match message.as_ref() {
                bft::Message::Proposal(p) => Ok(Some(p.snapshot.statement.id()?)),
                bft::Message::Vote(v) => Ok(Some(v.value)),
                bft::Message::Timeout(_) => Ok(None),
                bft::Message::EpochApproval { .. } => Ok(None),
            },
            Body::Finalized(s) => Ok(Some(s.statement.id()?)),
            Body::Submission(_) | Body::EpochSubmission { .. } | Body::EpochApproval(_) => Ok(None),
            Body::EpochActivation(proof) => Ok(Some(proof.statement.id()?)),
        }
    }
    pub fn verify(&self, node: &Store) -> Result<Hash> {
        require(
            self.format == FORMAT
                && self.currency == node.trust.currency()?
                && self.region == node.chain.region
                && bft::is_profile(&node.trust.region(self.region)?.rules),
            "consensus envelope domain/profile mismatch",
        )?;
        let mut evidence = VerifiedEvidence::verify(&self.evidence, &node.trust)?;
        if matches!(
            self.body,
            Body::EpochSigned { .. } | Body::EpochSubmission { .. }
        ) {
            require(
                crate::bft::is_joint(&node.trust.region(self.region)?.rules),
                "scoped epoch body requires joint profile",
            )?;
        }
        require(
            self.carried_epochs().len() <= epoch::MAX_EPOCHS,
            "consensus carried epoch bound",
        )?;
        for proof in self.carried_epochs() {
            require(
                proof.statement.region == self.region,
                "carried epoch foreign region",
            )?;
            evidence.install_epoch(proof.clone(), &node.trust)?;
        }
        match &self.body {
            Body::EpochApproval(vote) => {
                require(
                    vote.proposal.statement.region == self.region
                        && vote.proposal.statement.currency == self.currency,
                    "joint approval envelope domain",
                )?;
                vote.verify(&node.trust, &evidence)?;
            }
            Body::EpochActivation(proof) => {
                require(
                    crate::bft::is_joint(&node.trust.region(self.region)?.rules)
                        && proof.statement.region == self.region
                        && proof.statement.currency == self.currency,
                    "joint activation envelope profile/domain",
                )?;
                let mut verified = evidence.clone();
                verified.install_epoch((**proof).clone(), &node.trust)?;
            }
            Body::Signed(message) | Body::EpochSigned { message, .. } => {
                let c = match message.as_ref() {
                    bft::Message::Proposal(p) => {
                        p.verify(&node.trust, &evidence)?;
                        p.context()?
                    }
                    bft::Message::Vote(v) => {
                        v.verify(&v.context.keys(&node.trust, &evidence)?)?;
                        v.context.clone()
                    }
                    bft::Message::Timeout(t) => {
                        t.verify(&t.context.keys(&node.trust, &evidence)?)?;
                        t.context.clone()
                    }
                    bft::Message::EpochApproval { .. } => {
                        return Err("epoch approvals require an explicit complete activation certificate, not ordinary consensus carriage".into());
                    }
                };
                require(
                    c.currency == self.currency && c.region == self.region,
                    "consensus message differs from envelope domain",
                )?;
                // Even votes bind an independently certified native parent.
                if let Some(previous) = c.previous {
                    let parent = evidence.snapshot(previous)?;
                    require(
                        parent.statement.region == c.region
                            && parent.statement.height == c.parent_height
                            && parent.statement.block == c.parent_block
                            && parent.statement.state == c.parent_state,
                        "consensus message omits or changes certified parent",
                    )?;
                } else {
                    require(
                        c.parent_height == 0
                            && c.parent_block == c.region
                            && c.parent_state == Ledger::default().root()?,
                        "consensus message changes native genesis parent",
                    )?;
                }
            }
            Body::Finalized(snapshot) => {
                require(
                    snapshot.statement.region == self.region,
                    "foreign finality message",
                )?;
                let mut verified = evidence.clone();
                verified.add((**snapshot).clone(), &node.trust)?;
            }
            Body::Submission(commands) | Body::EpochSubmission { commands, .. } => {
                require(
                    !commands.is_empty() && commands.len() <= 4,
                    "submission command bound",
                )?;
                let local = self
                    .evidence
                    .snapshots
                    .iter()
                    .filter(|s| s.statement.region == self.region)
                    .max_by_key(|s| s.statement.height);
                let mut chain = Chain::new(self.region, &node.trust)?;
                if let Some(s) = local {
                    chain = evidence.replay_extension(s, &node.trust)?;
                    chain.install(s.statement.id()?, &evidence)?;
                    if crate::bft::is_joint(&node.trust.region(self.region)?.rules) {
                        chain.epoch =
                            crate::joint_epoch::next_epoch(&chain, &node.trust, &evidence)?;
                    }
                }
                // Validate real signed commands against the supplied certified
                // parent. Receiving a submission neither signs nor debits.
                chain.template(
                    commands.clone(),
                    node.trust.region(self.region)?.validators[0].clone(),
                    &node.trust,
                    &evidence,
                )?;
            }
        }
        id("bft-network-envelope-v2", self)
    }
}

pub fn sync(node: &mut Store, evidence: Evidence) -> Result<()> {
    bft::Context::current(node)?;
    VerifiedEvidence::verify(&evidence, &node.trust)?;
    node.add_evidence(evidence)?;
    let mut snapshots = node
        .journal
        .evidence
        .snapshots
        .iter()
        .filter(|s| s.statement.region == node.chain.region)
        .cloned()
        .collect::<Vec<_>>();
    snapshots.sort_by_key(|s| s.statement.height);
    for snapshot in snapshots {
        if snapshot.statement.height > node.chain.height() {
            // Every step remains an atomic next-block/finality native commit.
            install_carried_epochs(node, &snapshot)?;
            node.finalize(snapshot)?;
        }
    }
    Ok(())
}

fn install_carried_epochs(node: &mut Store, snapshot: &Snapshot) -> Result<()> {
    for proof in &snapshot.epochs {
        if node.chain.epoch == proof.statement.previous_epoch
            && node.chain.height() == proof.statement.closing_height
        {
            node.install_epoch(proof.clone())?;
        }
    }
    Ok(())
}

pub fn activate(node: &mut Store, proof: epoch::Transition, evidence: Evidence) -> Result<Hash> {
    require(
        crate::bft::is_joint(&node.trust.region(node.chain.region)?.rules)
            && proof.statement.region == node.chain.region,
        "joint activation wrong profile/region",
    )?;
    let mut checked = VerifiedEvidence::verify(&evidence, &node.trust)?;
    let eid = checked.install_epoch(proof.clone(), &node.trust)?;
    sync(node, evidence)?;
    if !node
        .journal
        .epoch_proofs
        .iter()
        .any(|p| p.statement.id().ok() == Some(eid))
    {
        node.install_epoch(proof)?;
    }
    Ok(eid)
}

pub const ACTIVATION_OBSERVATION_FORMAT: &str = "RLD-BFT-ACTIVATION-OBSERVATION-V1";

#[derive(Debug, Serialize, Deserialize)]
pub struct ActivationObservation {
    pub format: String,
    pub currency: Hash,
    pub region: Hash,
    pub epoch: Hash,
    pub activated_epoch: Hash,
    pub request_sha256: Hash,
    pub carried_index: Option<usize>,
    pub proofs: Vec<epoch::Transition>,
    pub fixture_only: bool,
    pub independent_freshness_qualified: bool,
    pub signing_authority: bool,
}

/// Authenticate the complete original envelope before selecting or installing
/// any proof. Each certificate variant still takes ordinary native activation.
/// The observation comes from ordered local journal replay in this same store;
/// evidence membership or a matching statement cannot replace that replay.
pub fn activate_observed(
    node: &mut Store,
    envelope: Envelope,
    carried_index: Option<usize>,
    request_sha256: Hash,
) -> Result<ActivationObservation> {
    require(
        serde_json::to_vec(&envelope)
            .map_err(|e| e.to_string())?
            .len()
            <= MAX_BYTES,
        "activation complete envelope bytes bound",
    )?;
    envelope.verify(node)?;
    let proof = match carried_index {
        Some(index) => envelope
            .carried_epochs()
            .get(index)
            .cloned()
            .ok_or("activation carried index outside exact envelope")?,
        None => match &envelope.body {
            Body::EpochActivation(proof) => (**proof).clone(),
            _ => return Err("activation requires complete typed epoch envelope".into()),
        },
    };
    let activated_epoch = activate(node, proof, envelope.evidence)?;
    let context = crate::bft::Context::current(node)?;
    let observation = ActivationObservation {
        format: ACTIVATION_OBSERVATION_FORMAT.into(),
        currency: context.currency,
        region: context.region,
        epoch: context.epoch,
        activated_epoch,
        request_sha256,
        carried_index,
        proofs: node.observed_installed_epochs()?,
        fixture_only: true,
        independent_freshness_qualified: false,
        signing_authority: false,
    };
    require(
        serde_json::to_vec(&observation)
            .map_err(|e| e.to_string())?
            .len()
            <= MAX_BYTES,
        "activation observation bytes bound",
    )?;
    Ok(observation)
}
