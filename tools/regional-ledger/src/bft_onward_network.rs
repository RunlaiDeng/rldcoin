//! Explicit complete two-hop network evidence. Ordinary Runtime adoption is separate.
use crate::{
    bft_network::{self, Body},
    carriage::CarriedEvidence,
    storage::{CompleteOnwardNetworkHistory, Store},
    *,
};

pub const FORMAT: &str = "RLD-REGIONAL-BFT-COMPLETE-ONWARD-NETWORK-V1";

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
        crate::encoded_size::check("complete-onward-network-envelope-v1", self)?;
        domain(&self.format, self.currency, self.region, node)?;
        require(
            self.evidence.snapshots.len() <= MAX_SNAPSHOTS,
            "complete onward network local evidence count",
        )?;
        node.check_onward_network_safety()?;
        let mut verified = if let Some(proof) = &self.history {
            proof.verify_anchors(self.region, &node.trust)?
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
        id("complete-onward-network-envelope-v1", self)
    }
}

/// Bounded inbound inspection, with actual Native incident custody before any
/// fallible expansion/value check. Success does not synchronize or credit value.
pub fn inspect(node: &mut Store, wire: WireEnvelope) -> Result<Hash> {
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
    envelope.verify(node)
}
