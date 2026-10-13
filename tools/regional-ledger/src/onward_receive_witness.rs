//! One Runtime receive's optional exact already-executed foreign closure.
//! Never a Store initializer, installed-membership fact, or envelope verdict.
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

pub(super) struct Entry {
    proof: CompleteOnwardNetworkHistory,
    currency: Currency,
    regions: BTreeMap<Hash, Admission>,
    binding: Hash,
    destination: Hash,
    profile: &'static str,
    limits: Limits,
    foreign: VerifiedEvidence,
}

/// Created only by the private receive path; no serialized or caller-supplied
/// ledger can populate it. Keep at most the first exact successful closure.
pub(crate) struct ReceiveWitness {
    entry: Option<Box<Entry>>,
    disabled: bool,
    limit: usize,
}
impl ReceiveWitness {
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
    pub(super) fn lookup(
        &self,
        proof: &CompleteOnwardNetworkHistory,
        destination: Hash,
        trust: &Trust,
    ) -> Option<VerifiedEvidence> {
        if self.disabled {
            return None;
        }
        let old = self.entry.as_ref()?;
        if old.proof != *proof
            || old.currency != trust.currency
            || old.regions != trust.regions
            || old.binding != trust.binding
            || old.destination != destination
            || old.profile != crate::paged_bft::ONWARD_NETWORK_RULES
            || old.limits != limits()
        {
            return None;
        }
        // C certificates, body verification and current safety never enter this
        // saved base. Each envelope extends only its own fresh clone.
        Some(old.foreign.clone())
    }
    pub(super) fn prepare(
        &mut self,
        proof: &CompleteOnwardNetworkHistory,
        destination: Hash,
        trust: &Trust,
        foreign: &VerifiedEvidence,
    ) -> Option<Entry> {
        if self.disabled || self.entry.is_some() {
            return None;
        }
        // Account the entire optional retained object before any proof/ledger
        // clone. This is a logical encoded bound, not a measured heap bound.
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
            return None;
        }
        Some(Entry {
            proof: proof.clone(),
            currency: trust.currency.clone(),
            regions: trust.regions.clone(),
            binding: trust.binding,
            destination,
            profile: crate::paged_bft::ONWARD_NETWORK_RULES,
            limits: bound,
            foreign: foreign.clone(),
        })
    }
    pub(super) fn commit(&mut self, entry: Entry) {
        // Called only after this envelope's original C/body/identity checks also
        // succeeded. Failure must never seed a later verification.
        if !self.disabled && self.entry.is_none() {
            self.entry = Some(Box::new(entry));
        }
    }
}
