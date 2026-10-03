//! Facts derived from this verifier's own exact genesis, certified Ledger and
//! retained Admission sources. No caller clock, prepared checkpoint, root or
//! availability flag can construct the verified capability below.
use super::*;
use serde::{Deserialize, Serialize};

pub const OBSERVATION_VERSION: &str = "RLD-M0-ADMISSION-OBSERVATION-V1";
pub const OBSERVATION_MAX_JSON_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAdmissionObservation {
    report: AdmissionObservationReport,
    // Kept only in this non-deserializable capability. Display JSON cannot
    // supply the dependencies needed for subsequent authenticated treatment.
    pub(super) ledger_height: u128,
    pub(super) source_headers: Vec<AdmissionHash32>,
    pub(super) entry_sources: BTreeMap<AdmissionHash32, AdmissionHash32>,
}

impl VerifiedAdmissionObservation {
    /// A display projection, not a remotely authenticated certificate or a
    /// signing capability. Deserializing this report cannot recreate `Self`.
    pub fn report(&self) -> &AdmissionObservationReport {
        &self.report
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdmissionObservationReport {
    pub format_version: String,
    pub manifest_sha256: String,
    pub finalized_height: String,
    pub finalized_epoch: String,
    pub finalized_state_root: String,
    pub finalized_commit_hash: Option<String>,
    pub committed_admission_header: String,
    pub canonical_admission_tip: String,
    pub confirmed_prefix: Option<ConfirmedPrefixReport>,
    pub signature_authorized: bool,
    pub live_censorship_policy_active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConfirmedPrefixReport {
    pub header_id: String,
    pub admission_era: String,
    pub log_height: String,
    pub cumulative_work: String,
    pub confirmations: u16,
    pub descendant_work: String,
    pub entries_root: String,
    pub availability_root: String,
    pub entry_ids: Vec<String>,
    pub observed_ledger_height: String,
    pub observed_ledger_epoch: String,
    pub finalized_lag_epochs: String,
    pub lag_limit_epochs: String,
    pub finalized_lag_exceeded: bool,
    pub next_block_within_lag_bound: bool,
}

impl M0CandidateReplay {
    pub fn observe_admission(&self) -> Result<VerifiedAdmissionObservation, String> {
        // The private replay state is established only by pinned birth and
        // authenticated transitions. Observation must survive a certified
        // successor without granting general snapshot/runtime admission.
        self.manifest
            .validate_replayed_candidate_identity(&self.ledger)?;
        let admission = self
            .ledger
            .admission_state
            .as_ref()
            .ok_or("missing Admission birth")?;
        if admission.committed_header != self.log.committed_header() {
            return Err("Admission observation has inconsistent finalized projections".into());
        }
        let height = u128::from(self.ledger.height);
        let mapping = &admission.genesis.config.contribution_epoch_mapping;
        let epoch = mapping.epoch_at_height(height).map_err(|e| e.to_string())?;
        let commit_hash = if height == 0 {
            None
        } else {
            Some(
                self.anchors
                    .get(&height)
                    .ok_or("observation clock lacks its certified commit")?
                    .to_hex(),
            )
        };
        let selected = self
            .log
            .confirmed_prefix_for_observation()
            .map_err(|e| e.to_string())?;
        let mut source_headers = Vec::new();
        let mut entry_sources = BTreeMap::new();
        let confirmed_prefix = if let Some(prefix) = selected {
            if prefix.prior_committed_header != admission.committed_header
                || prefix.canonical_tip != self.log.canonical_tip()
            {
                return Err("observation prefix differs from retained canonical history".into());
            }
            // Never rely on a cached availability bit. Confirming headers can
            // contain their own entries, whose bodies must also remain present.
            for header in &prefix.source_headers {
                let source = self
                    .log
                    .retained_header_batch(*header)
                    .map_err(|e| e.to_string())?;
                self.verify_anchor(&source.ledger_anchor)
                    .map_err(|e| e.to_string())?;
                for entry in &source.entries {
                    self.verify_entry(entry).map_err(|e| e.to_string())?;
                    if prefix.entry_ids.binary_search(&entry.entry_id()).is_ok()
                        && entry_sources.insert(entry.entry_id(), *header).is_some()
                    {
                        return Err("confirmed observation repeats an entry in its ancestry".into());
                    }
                }
            }
            if entry_sources.len() != prefix.entry_ids.len() {
                return Err("confirmed observation is missing an entry source".into());
            }
            source_headers = prefix.source_headers;
            let observed_epoch = mapping
                .epoch_at_height(prefix.observed_ledger_height)
                .map_err(|e| e.to_string())?;
            let lag = epoch
                .checked_sub(observed_epoch)
                .ok_or("observation precedes the authenticated source anchor")?;
            let next_block_within_lag_bound = self
                .ledger
                .height
                .checked_add(1)
                .and_then(|h| mapping.epoch_at_height(u128::from(h)).ok())
                .and_then(|e| e.checked_sub(observed_epoch))
                .is_some_and(|lag| lag <= crate::MAX_ADMISSION_LAG_EPOCHS);
            Some(ConfirmedPrefixReport {
                header_id: prefix.selected_header.header_id().to_hex(),
                admission_era: prefix.selected_header.admission_era.to_string(),
                log_height: prefix.selected_header.log_height.to_string(),
                cumulative_work: hex::encode(prefix.selected_header.cumulative_work.to_be_bytes()),
                confirmations: prefix.confirmations,
                descendant_work: hex::encode(prefix.descendant_work.to_be_bytes()),
                entries_root: crate::admission_entry_root(prefix.entry_ids.iter().copied())
                    .map_err(|e| e.to_string())?
                    .to_hex(),
                availability_root: crate::admission_availability_root(&prefix.availability)
                    .map_err(|e| e.to_string())?
                    .to_hex(),
                entry_ids: prefix.entry_ids.iter().map(|id| id.to_hex()).collect(),
                observed_ledger_height: prefix.observed_ledger_height.to_string(),
                observed_ledger_epoch: observed_epoch.to_string(),
                finalized_lag_epochs: lag.to_string(),
                lag_limit_epochs: crate::MAX_ADMISSION_LAG_EPOCHS.to_string(),
                finalized_lag_exceeded: lag > crate::MAX_ADMISSION_LAG_EPOCHS,
                next_block_within_lag_bound,
            })
        } else {
            None
        };
        let report = AdmissionObservationReport {
            format_version: OBSERVATION_VERSION.into(),
            manifest_sha256: self.manifest_sha256().into(),
            finalized_height: height.to_string(),
            finalized_epoch: epoch.to_string(),
            finalized_state_root: self.ledger.state_root().map_err(|e| e.to_string())?,
            finalized_commit_hash: commit_hash,
            committed_admission_header: admission.committed_header.to_hex(),
            canonical_admission_tip: self.log.canonical_tip().to_hex(),
            confirmed_prefix,
            signature_authorized: false,
            live_censorship_policy_active: false,
        };
        bounded_json_size(&report, OBSERVATION_MAX_JSON_BYTES)?;
        Ok(VerifiedAdmissionObservation {
            report,
            ledger_height: height,
            source_headers,
            entry_sources,
        })
    }
}
