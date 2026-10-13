//! One cold archive read's optional exact already-executed foreign closure.
//! Every record still authenticates C/body and exact prior Native custody.
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
    format: &'static str,
    profile: &'static str,
    limits: Limits,
    foreign: VerifiedEvidence,
}

/// Owned only by one read_authenticated call. A provisional foreign result is
/// never reusable until the whole cold record and expected value have passed.
pub(crate) struct ArchiveReadWitness {
    entry: Option<Box<Entry>>,
    pending: Option<Box<Entry>>,
    disabled: bool,
    limit: usize,
}
impl ArchiveReadWitness {
    pub(crate) fn new() -> Self {
        Self {
            entry: None,
            pending: None,
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
        self.pending = None;
        self.disabled = true;
    }
    pub(crate) fn begin_record(&mut self) {
        // Only completed earlier records may supply a base to this record.
        self.pending = None;
    }
    pub(crate) fn commit_record(&mut self) {
        // The caller has also checked exact installed material and record.value.
        // A mismatching proof cannot replace the first committed entry.
        if !self.disabled && self.entry.is_none() {
            self.entry = self.pending.take();
        }
        self.pending = None;
    }
    pub(super) fn verify_anchors(
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
                    && old.format == FORMAT
                    && old.profile == crate::paged_bft::ONWARD_NETWORK_RULES
                    && old.limits == limits()
                {
                    // Keep current routing/admission/size checks on every hit.
                    // No C certificate, body verdict or membership fact is saved.
                    proof.require_route(destination, trust)?;
                    return Ok(old.foreign.clone());
                }
            }
        }
        let foreign = proof.verify_anchors(destination, trust)?;
        if !self.disabled && self.entry.is_none() && self.pending.is_none() {
            let bound = limits();
            let retained = (
                proof,
                &trust.currency,
                &trust.regions,
                trust.binding,
                destination,
                FORMAT,
                crate::paged_bft::ONWARD_NETWORK_RULES,
                bound,
                &foreign.snapshots,
                &foreign.epochs.regions,
                foreign.trust_binding,
            );
            // The complete optional object is logically bounded before any
            // retention clone. Cap refusal falls back to full verification.
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
                self.pending = Some(Box::new(Entry {
                    proof: proof.clone(),
                    currency: trust.currency.clone(),
                    regions: trust.regions.clone(),
                    binding: trust.binding,
                    destination,
                    format: FORMAT,
                    profile: crate::paged_bft::ONWARD_NETWORK_RULES,
                    limits: bound,
                    foreign: foreign.clone(),
                }));
            }
        }
        Ok(foreign)
    }
}
