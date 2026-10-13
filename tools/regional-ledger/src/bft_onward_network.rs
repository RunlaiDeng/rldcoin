//! Explicit complete two-hop network evidence. Ordinary Runtime adoption is separate.
use crate::{
    bft_network::{self, Body},
    carriage::CarriedEvidence,
    storage::{CompleteOnwardNetworkHistory, Store},
    *,
};

pub const FORMAT: &str = "RLD-REGIONAL-BFT-COMPLETE-ONWARD-NETWORK-V1";

#[cfg(test)]
#[path = "onward_execution_cost.rs"]
pub(crate) mod execution_cost;

#[path = "onward_receive_witness.rs"]
mod receive_witness;
pub(crate) use receive_witness::ReceiveWitness;

#[path = "onward_local_construction_witness.rs"]
mod local_construction_witness;
pub(crate) use local_construction_witness::LocalConstructionWitness;

#[path = "onward_archive_read_witness.rs"]
mod archive_read_witness;
pub(crate) use archive_read_witness::ArchiveReadWitness;

enum ForeignVerification<'a> {
    Independent,
    Receive(&'a mut ReceiveWitness),
    Construction(&'a mut LocalConstructionWitness),
    Archive(&'a mut ArchiveReadWitness),
}

pub(crate) fn local_envelope(body: Body, node: &Store) -> Result<WireEnvelope> {
    local_envelope_inner(body, node, &mut LocalConstructionWitness::new())
}

#[cfg(test)]
pub(crate) fn local_envelope_with_limit_for_test(
    body: Body,
    node: &Store,
    limit: usize,
) -> Result<WireEnvelope> {
    local_envelope_inner(
        body,
        node,
        &mut LocalConstructionWitness::with_limit_for_test(limit),
    )
}

fn local_envelope_inner(
    body: Body,
    node: &Store,
    witness: &mut LocalConstructionWitness,
) -> Result<WireEnvelope> {
    let result = construct_local_envelope(body, node, witness);
    if result.is_err() {
        witness.disable();
    }
    result
}

fn construct_local_envelope(
    body: Body,
    node: &Store,
    witness: &mut LocalConstructionWitness,
) -> Result<WireEnvelope> {
    let (history, evidence) = node.onward_network_material_for_construction(witness)?;
    let envelope = Envelope {
        format: FORMAT.into(),
        currency: node.trust.currency()?,
        region: node.chain.region,
        history,
        evidence,
        body,
    };
    envelope.verify_for_construction(node, witness)?;
    let wire = envelope.pack()?;
    wire.clone()
        .expand()?
        .verify_for_construction(node, witness)?;
    Ok(wire)
}

/// Local owner queue admission only. Complete envelope and current Native
/// execution still authenticate owners, maturity, value and dependencies.
/// The separate explicit incoming Submission API keeps its original body rules.
pub(crate) fn require_local_owner_commands(commands: &[Command]) -> Result<()> {
    require(
        !commands.is_empty()
            && commands.len() <= 4
            && commands.iter().all(|command| {
                matches!(command, Command::Spend(signed)
                    if signed.intent.destination.is_none()
                        && signed.intent.remote.is_none()
                        && signed.intent.destination_fee.is_zero())
            }),
        "onward owner queue requires one to four local Spend commands",
    )
}

/// Incoming conflict custody and full authentication precede any dependency
/// installation or body deduplication. Partial durable failure never acknowledges.
pub(crate) fn sync_envelope(node: &mut Store, wire: WireEnvelope) -> Result<()> {
    inspect(node, wire.clone())?;
    install_envelope(node, wire)
}

pub(crate) fn sync_envelope_with_receive(
    node: &mut Store,
    wire: WireEnvelope,
    witness: &mut ReceiveWitness,
) -> Result<()> {
    let result = inspect_with_receive(node, wire.clone(), witness)
        .and_then(|_| install_envelope(node, wire));
    if result.is_err() {
        witness.disable();
    }
    result
}

// The Native append/replay kernel remains independent of the pure witness.
fn install_envelope(node: &mut Store, wire: WireEnvelope) -> Result<()> {
    let envelope = wire.expand()?;
    if let Some(proof) = envelope.history {
        node.accept_complete_onward_network_history(proof)?;
    }
    for snapshot in envelope.evidence.snapshots {
        node.finalize_onward_network_certificate(snapshot)?;
    }
    if let Body::Finalized(snapshot) = envelope.body {
        node.finalize_onward_network_certificate(*snapshot)?;
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub format: String,
    pub currency: Hash,
    pub region: Hash,
    pub history: Option<CompleteOnwardNetworkHistory>,
    pub evidence: Evidence,
    pub body: Body,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireEnvelope {
    pub format: String,
    pub currency: Hash,
    pub region: Hash,
    pub history: Option<CompleteOnwardNetworkHistory>,
    pub evidence: CarriedEvidence,
    pub body: Body,
}
fn wire_bound<T: Serialize>(wire: &T) -> Result<()> {
    require(
        crate::encoded_size::check_json(wire, crate::contact::MAX_PAYLOAD)?
            <= crate::contact::MAX_PAYLOAD,
        "complete onward network original wire capacity",
    )
}
fn domain(format: &str, currency: Hash, region: Hash, node: &Store) -> Result<()> {
    require(
        format == FORMAT
            && currency == node.trust.currency()?
            && region == node.chain.region
            && node.trust.region(region)?.rules == crate::paged_bft::ONWARD_NETWORK_RULES,
        "complete onward network envelope domain/profile differs",
    )?;
    node.require_onward_network_state()
}
impl WireEnvelope {
    pub fn expand(self) -> Result<Envelope> {
        wire_bound(&self)?;
        require(
            self.format == FORMAT,
            "complete onward network wire format differs",
        )?;
        let envelope = Envelope {
            format: self.format,
            currency: self.currency,
            region: self.region,
            history: self.history,
            evidence: self.evidence.expand()?,
            body: self.body,
        };
        crate::encoded_size::check("complete-onward-network-envelope-v1", &envelope)?;
        Ok(envelope)
    }
}
impl Envelope {
    /// Packing preserves bytes and bounds only. It never authenticates authority.
    pub fn pack(&self) -> Result<WireEnvelope> {
        require(
            self.format == FORMAT,
            "complete onward network envelope format differs",
        )?;
        crate::encoded_size::check("complete-onward-network-envelope-v1", self)?;
        let wire = WireEnvelope {
            format: self.format.clone(),
            currency: self.currency,
            region: self.region,
            history: self.history.clone(),
            evidence: CarriedEvidence::pack(&self.evidence)?,
            body: self.body.clone(),
        };
        wire_bound(&wire)?;
        Ok(wire)
    }
    /// Pure authentication. Inbound processing uses inspect so a later refusal
    /// cannot hide an independently authentic conflicting certificate.
    pub fn verify(&self, node: &Store) -> Result<Hash> {
        self.verify_inner(node, ForeignVerification::Independent)
    }
    pub(crate) fn verify_with_receive(
        &self,
        node: &Store,
        witness: &mut ReceiveWitness,
    ) -> Result<Hash> {
        let result = self.verify_inner(node, ForeignVerification::Receive(&mut *witness));
        if result.is_err() {
            witness.disable();
        }
        result
    }
    pub(crate) fn verify_for_construction(
        &self,
        node: &Store,
        witness: &mut LocalConstructionWitness,
    ) -> Result<Hash> {
        let result = self.verify_inner(node, ForeignVerification::Construction(&mut *witness));
        if result.is_err() {
            witness.disable();
        }
        result
    }
    pub(crate) fn verify_for_archive(
        &self,
        node: &Store,
        witness: &mut ArchiveReadWitness,
    ) -> Result<Hash> {
        let result = self.verify_inner(node, ForeignVerification::Archive(&mut *witness));
        if result.is_err() {
            witness.disable();
        }
        result
    }
    fn verify_inner(&self, node: &Store, mut mode: ForeignVerification<'_>) -> Result<Hash> {
        crate::encoded_size::check("complete-onward-network-envelope-v1", self)?;
        domain(&self.format, self.currency, self.region, node)?;
        require(
            self.evidence.snapshots.len() <= MAX_SNAPSHOTS,
            "complete onward network local evidence count",
        )?;
        node.check_onward_network_safety()?;
        let mut pending = None;
        let mut verified = if let Some(proof) = &self.history {
            match &mut mode {
                ForeignVerification::Receive(witness) => {
                    // Preserve receive's route checks and delayed whole-envelope
                    // commit; construction never shares this entry or policy.
                    proof.require_route(self.region, &node.trust)?;
                    if let Some(foreign) = witness.lookup(proof, self.region, &node.trust) {
                        foreign
                    } else {
                        let foreign = proof.verify_anchors(self.region, &node.trust)?;
                        pending = witness.prepare(proof, self.region, &node.trust, &foreign);
                        foreign
                    }
                }
                ForeignVerification::Construction(witness) => {
                    witness.verify_anchors(proof, self.region, &node.trust)?
                }
                ForeignVerification::Archive(witness) => {
                    // Only a prior fully checked cold record may supply this
                    // foreign base; this record cannot commit its own candidate.
                    witness.verify_anchors(proof, self.region, &node.trust)?
                }
                ForeignVerification::Independent => {
                    proof.verify_anchors(self.region, &node.trust)?
                }
            }
        } else {
            VerifiedEvidence {
                trust_binding: Some(node.trust.binding),
                ..VerifiedEvidence::default()
            }
        };
        for (index, snapshot) in self.evidence.snapshots.iter().enumerate() {
            require(
                snapshot.statement.region == self.region
                    && snapshot.statement.height == index as u64 + 1,
                "complete onward network exact local genesis prefix required",
            )?;
            verified.add(snapshot.clone(), &node.trust)?;
            crate::encoded_size::check("complete-onward-network-derived-v1", &verified.snapshots)?;
        }
        if let Body::Finalized(snapshot) = &self.body {
            require(
                snapshot.statement.region == self.region,
                "foreign finality message",
            )?;
            verified.add((**snapshot).clone(), &node.trust)?;
        }
        crate::encoded_size::check("complete-onward-network-derived-v1", &verified.snapshots)?;
        require(
            verified.snapshots.len() <= MAX_SNAPSHOTS,
            "complete onward network complete active evidence bound",
        )?;
        require(
            matches!(
                &self.body,
                Body::Signed(_) | Body::Finalized(_) | Body::Submission(_)
            ),
            "complete onward network initial-epoch body required",
        )?;
        // Only this invocation's independently executed material enters the same
        // ordinary body kernel. The old public envelope admission is not called
        // or relaxed, and this adapter is never serialized as an old envelope.
        let body = bft_network::Envelope {
            format: self.format.clone(),
            currency: self.currency,
            region: self.region,
            evidence: self.evidence.clone(),
            body: self.body.clone(),
            origins: None,
        };
        bft_network::verify_authenticated_body(&body, node, verified)?;
        let identity = id("complete-onward-network-envelope-v1", self)?;
        if let (ForeignVerification::Receive(witness), Some(entry)) = (mode, pending) {
            witness.commit(entry);
        }
        Ok(identity)
    }
}

/// Bounded inbound inspection, with actual Native incident custody before any
/// fallible expansion/value check. Success does not synchronize or credit value.
pub fn inspect(node: &mut Store, wire: WireEnvelope) -> Result<Hash> {
    inspect_inner(node, wire, None)
}
pub(crate) fn inspect_with_receive(
    node: &mut Store,
    wire: WireEnvelope,
    witness: &mut ReceiveWitness,
) -> Result<Hash> {
    let result = inspect_inner(node, wire, Some(&mut *witness));
    if result.is_err() {
        witness.disable();
    }
    result
}
fn inspect_inner(
    node: &mut Store,
    wire: WireEnvelope,
    witness: Option<&mut ReceiveWitness>,
) -> Result<Hash> {
    wire_bound(&wire)?;
    domain(&wire.format, wire.currency, wire.region, node)?;
    require(
        wire.evidence.snapshots.len() <= MAX_SNAPSHOTS,
        "complete onward network raw local certificate bound",
    )?;
    let mut candidates = match &wire.history {
        Some(proof) => {
            proof.require_route(wire.region, &node.trust)?;
            proof.complete_snapshots()?
        }
        None => Vec::new(),
    };
    // Complete foreign proofs and directly present local certificates can prove
    // an incident even if another prefix reference cannot expand. Incomplete
    // raw local candidates grant nothing; the normal Conflict verifier decides.
    candidates.extend(wire.evidence.snapshots.iter().map(|s| s.snapshot.clone()));
    match &wire.body {
        Body::Finalized(snapshot) => candidates.push(*snapshot.clone()),
        Body::Signed(message) => {
            if let crate::bft::Message::Proposal(proposal) = message.as_ref() {
                candidates.push(*proposal.snapshot.clone());
            }
        }
        _ => {}
    }
    node.observe_onward_network_conflicts(&candidates)?;
    let envelope = wire.expand()?;
    // Expansion may make an additional complete local certificate available.
    let mut expanded = envelope.evidence.snapshots.clone();
    match &envelope.body {
        Body::Finalized(snapshot) => expanded.push(*snapshot.clone()),
        Body::Signed(message) => {
            if let crate::bft::Message::Proposal(proposal) = message.as_ref() {
                expanded.push(*proposal.snapshot.clone());
            }
        }
        _ => {}
    }
    node.observe_onward_network_conflicts(&expanded)?;
    match witness {
        Some(witness) => envelope.verify_with_receive(node, witness),
        None => envelope.verify(node),
    }
}
