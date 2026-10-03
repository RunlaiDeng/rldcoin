//! Join authenticated observations to finalized membership without treating
//! changing checkpoint metadata, disappearance or display JSON as resolution.
use super::{inclusion::*, observation::*, *};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Local correlation only, not a protocol nullifier or a contribution ticket.
/// The fixed-width genesis pin separates otherwise identical entry identifiers.
fn obligation_id(manifest: AdmissionHash32, entry: AdmissionHash32) -> AdmissionHash32 {
    let mut hash = Sha256::new();
    hash.update(b"RLD-LOCAL-ADMISSION-OBLIGATION-V1\0");
    hash.update(manifest.0);
    hash.update(entry.0);
    AdmissionHash32(hash.finalize().into())
}

#[derive(Debug)]
pub struct VerifiedObservedEntryTreatment<'a> {
    obligation_id: AdmissionHash32,
    entry_id: AdmissionHash32,
    observed_source_header: AdmissionHash32,
    inclusion: Option<VerifiedAdmissionInclusion<'a>>,
    canonical_now: bool,
    in_next_confirmed_batch: bool,
}

impl<'a> VerifiedObservedEntryTreatment<'a> {
    pub fn obligation_id(&self) -> AdmissionHash32 {
        self.obligation_id
    }
    pub fn entry_id(&self) -> AdmissionHash32 {
        self.entry_id
    }
    pub fn inclusion(&self) -> Option<&VerifiedAdmissionInclusion<'a>> {
        self.inclusion.as_ref()
    }
}

/// Both the originating observation and the current verifier are borrowed.
/// No JSON, external Ledger, arbitrary Epoch, or rejection-ID list can create it.
#[derive(Debug)]
pub struct VerifiedAdmissionReconciliation<'a> {
    replay: &'a M0CandidateReplay,
    observation: &'a VerifiedAdmissionObservation,
    current: AdmissionObservationReport,
    entries: Vec<VerifiedObservedEntryTreatment<'a>>,
}

impl<'a> VerifiedAdmissionReconciliation<'a> {
    pub fn entries(&self) -> &[VerifiedObservedEntryTreatment<'a>] {
        &self.entries
    }
    pub fn all_observed_entries_included(&self) -> bool {
        !self.entries.is_empty() && self.entries.iter().all(|e| e.inclusion.is_some())
    }
    pub fn report(&self) -> AdmissionReconciliationReport {
        AdmissionReconciliationReport {
            format_version: "RLD-ADMISSION-OBSERVATION-RECONCILIATION-V1".into(),
            manifest_sha256: self.replay.manifest_sha256().into(),
            observed_at_finalized_height: self.observation.report().finalized_height.clone(),
            observed_at_finalized_commit: self.observation.report().finalized_commit_hash.clone(),
            current_finalized_height: self.current.finalized_height.clone(),
            current_finalized_commit: self.current.finalized_commit_hash.clone(),
            current_finalized_state_root: self.current.finalized_state_root.clone(),
            entries: self
                .entries
                .iter()
                .map(|e| ObservedEntryTreatmentReport {
                    obligation_id: e.obligation_id.to_hex(),
                    entry_id: e.entry_id.to_hex(),
                    observed_source_header: e.observed_source_header.to_hex(),
                    disposition: if e.inclusion.is_some() {
                        ObservedEntryDisposition::FinalizedCheckpoint
                    } else if e.canonical_now {
                        ObservedEntryDisposition::UnresolvedCanonical
                    } else {
                        ObservedEntryDisposition::UnresolvedReorged
                    },
                    in_next_confirmed_batch: e.in_next_confirmed_batch,
                    inclusion: e.inclusion.as_ref().map(|i| i.report()),
                })
                .collect(),
            all_observed_entries_included: self.all_observed_entries_included(),
            recovery_authorized: false,
            live_authorization: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservedEntryDisposition {
    FinalizedCheckpoint,
    UnresolvedCanonical,
    UnresolvedReorged,
}

/// Unsigned display only. Even complete checkpoint inclusion cannot clear a
/// live stall without the separately certified recovery/challenge protocol.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ObservedEntryTreatmentReport {
    pub obligation_id: String,
    pub entry_id: String,
    pub observed_source_header: String,
    pub disposition: ObservedEntryDisposition,
    pub in_next_confirmed_batch: bool,
    pub inclusion: Option<AdmissionInclusionReport>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct AdmissionReconciliationReport {
    pub format_version: String,
    pub manifest_sha256: String,
    pub observed_at_finalized_height: String,
    pub observed_at_finalized_commit: Option<String>,
    pub current_finalized_height: String,
    pub current_finalized_commit: Option<String>,
    pub current_finalized_state_root: String,
    pub entries: Vec<ObservedEntryTreatmentReport>,
    pub all_observed_entries_included: bool,
    pub recovery_authorized: bool,
    pub live_authorization: bool,
}

impl M0CandidateReplay {
    pub fn reconcile_admission_observation<'a>(
        &'a self,
        observation: &'a VerifiedAdmissionObservation,
    ) -> Result<VerifiedAdmissionReconciliation<'a>, String> {
        let origin = observation.report();
        if origin.manifest_sha256 != self.manifest_sha256()
            || observation.ledger_height > u128::from(self.ledger.height)
        {
            return Err(
                "observation belongs to a different genesis or a future certified head".into(),
            );
        }
        let pin = AdmissionHash32::from_hex(self.manifest_sha256()).map_err(|e| e.to_string())?;
        if observation.entry_sources.is_empty() {
            return Err("observation has no confirmed entries to reconcile".into());
        }
        let commit_id = self
            .anchors
            .get(&observation.ledger_height)
            .ok_or("observation origin is absent from this certified history")?
            .to_hex();
        let commit = self
            .ledger
            .consensus_commits
            .get(&commit_id)
            .ok_or("observation origin has no retained certificate")?;
        if origin.finalized_commit_hash.as_ref() != Some(&commit_id)
            || origin.finalized_state_root != commit.proposal.expected_state_root
        {
            return Err("observation origin conflicts with this certified history".into());
        }
        // Require the complete original source/confirmation dependency set,
        // including branches since displaced. Missing evidence is not rejection.
        for header in &observation.source_headers {
            let batch = self
                .log
                .retained_header_batch(*header)
                .map_err(|e| e.to_string())?;
            self.verify_anchor(&batch.ledger_anchor)
                .map_err(|e| e.to_string())?;
            for entry in &batch.entries {
                self.verify_entry(entry).map_err(|e| e.to_string())?;
            }
        }
        let current = self.observe_admission()?;
        let mut entries = Vec::with_capacity(observation.entry_sources.len());
        for (entry_id, source_header) in &observation.entry_sources {
            let inclusion = self.verified_admission_inclusion(*entry_id)?;
            let canonical_now = self
                .log
                .entry_appears_in_ancestry_of(*entry_id, self.log.canonical_tip())
                .map_err(|e| e.to_string())?;
            if inclusion.is_some() && !canonical_now {
                return Err("finalized entry disappeared from canonical Admission ancestry".into());
            }
            entries.push(VerifiedObservedEntryTreatment {
                obligation_id: obligation_id(pin, *entry_id),
                entry_id: *entry_id,
                observed_source_header: *source_header,
                inclusion,
                canonical_now,
                in_next_confirmed_batch: current.entry_sources.contains_key(entry_id),
            });
        }
        Ok(VerifiedAdmissionReconciliation {
            replay: self,
            observation,
            current: current.report().clone(),
            entries,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_obligation_identity_is_genesis_and_entry_scoped() {
        let a = obligation_id(AdmissionHash32([1; 32]), AdmissionHash32([2; 32]));
        assert_ne!(
            a,
            obligation_id(AdmissionHash32([3; 32]), AdmissionHash32([2; 32]))
        );
        assert_ne!(
            a,
            obligation_id(AdmissionHash32([1; 32]), AdmissionHash32([3; 32]))
        );
    }
}
