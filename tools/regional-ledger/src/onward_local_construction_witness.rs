//! One local construction's optional exact already-executed foreign closure.
//! A foreign-only result may be remembered before C/body authentication, but
//! nothing escapes the constructor unless its complete original checks succeed.
//! This lifetime and policy are distinct from ReceiveWitness.
use super::*;

type Limits = [usize; 6];
fn limits() -> Limits {
    [
        MAX_BYTES,
        MAX_SNAPSHOTS,
        MAX_BLOCKS,
        MAX_COINS,
        contact::MAX_PAYLOAD,
        contact::MAX_FRAME,
    ]
}

struct Entry {
    proof: CompleteOnwardNetworkHistory,
    currency: Currency,
    regions: BTreeMap<Hash, Admission>,
    binding: Hash,
    destination: Hash,
    profile: &'static str,
    limits: Limits,
    foreign: VerifiedEvidence,
}

/// Only the local constructor creates this in production. It is never stored,
/// serialized or passed to Native installation, custody or independent readers.
pub(crate) struct LocalConstructionWitness {
    entry: Option<Box<Entry>>,
    disabled: bool,
    limit: usize,
}
impl LocalConstructionWitness {
    pub(crate) fn new() -> Self {
        Self {
            entry: None,
            disabled: false,
            limit: MAX_BYTES,
        }
    }
    #[cfg(test)]
    pub(crate) fn with_limit_for_test(limit: usize) -> Self {
        Self {
            limit: limit.min(MAX_BYTES),
            ..Self::new()
        }
    }
    pub(crate) fn disable(&mut self) {
        self.entry = None;
        self.disabled = true;
    }
    pub(crate) fn verify_anchors(
        &mut self,
        proof: &CompleteOnwardNetworkHistory,
        destination: Hash,
        trust: &Trust,
    ) -> Result<VerifiedEvidence> {
        let result = self.verify_inner(proof, destination, trust);
        if result.is_err() {
            self.disable();
        }
        result
    }
    fn verify_inner(
        &mut self,
        proof: &CompleteOnwardNetworkHistory,
        destination: Hash,
        trust: &Trust,
    ) -> Result<VerifiedEvidence> {
        if !self.disabled {
            if let Some(old) = &self.entry {
                if old.proof == *proof
                    && old.currency == trust.currency
                    && old.regions == trust.regions
                    && old.binding == trust.binding
                    && old.destination == destination
                    && old.profile == crate::paged_bft::ONWARD_NETWORK_RULES
                    && old.limits == limits()
                {
                    // Hits retain original routing, admission and size checks.
                    // Misses run the same checks inside the full verifier below.
                    proof.require_route(destination, trust)?;
                    return Ok(old.foreign.clone());
                }
            }
        }
        let foreign = proof.verify_anchors(destination, trust)?;
        if !self.disabled && self.entry.is_none() {
            let bound = limits();
            let retained = (
                proof,
                &trust.currency,
                &trust.regions,
                trust.binding,
                destination,
                crate::paged_bft::ONWARD_NETWORK_RULES,
                bound,
                &foreign.snapshots,
                &foreign.epochs.regions,
                foreign.trust_binding,
            );
            // Optional logical accounting precedes all retention clones. A cap
            // failure disables retention, never the successful full verifier.
            if foreign.trust_binding != Some(trust.binding)
                || foreign.snapshots.len() != 2
                || foreign
                    .snapshots
                    .values()
                    .any(|(s, _)| s.statement.region == destination)
                || !foreign.epochs.regions.is_empty()
                || crate::encoded_size::check_json(&retained, self.limit).is_err()
            {
                self.disable();
            } else {
                self.entry = Some(Box::new(Entry {
                    proof: proof.clone(),
                    currency: trust.currency.clone(),
                    regions: trust.regions.clone(),
                    binding: trust.binding,
                    destination,
                    profile: crate::paged_bft::ONWARD_NETWORK_RULES,
                    limits: bound,
                    foreign: foreign.clone(),
                }));
            }
        }
        Ok(foreign)
    }
}
