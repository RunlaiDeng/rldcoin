//! First confirmed observations reconstructed from the verifier's ordered inputs.
//! Persistence/authentication of that order belongs to the node or role adapter.
//! Neither this private projection nor its unsigned pages authorize live policy.
use super::{observation::VerifiedAdmissionObservation, reconciliation::*, *};
use serde::{Deserialize, Serialize};
use std::ops::Bound::{Excluded, Unbounded};

pub const MAX_OBLIGATION_DEPENDENCY_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_OBLIGATION_PAGE_ENTRIES: usize = 32;
pub const MAX_OBLIGATION_PAGE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct AdmissionObligationHistory {
    first: BTreeMap<AdmissionHash32, Arc<VerifiedAdmissionObservation>>,
    pub(super) dependency_bytes: usize,
}

impl AdmissionObligationHistory {
    pub(super) fn with_current_observation(
        &self,
        replay: &M0CandidateReplay,
    ) -> Result<Self, String> {
        // This private projection only records *new* first confirmations. The
        // replay constructor and source/commit transitions already establish
        // Ledger/log identity. When all selected entries have a first record,
        // retain the source availability checks but do not serialize another
        // complete observation (including a full Ledger state-root calculation).
        // Public observation and obligation queries still reconstruct the report.
        let selected = replay
            .log
            .confirmed_prefix_for_observation()
            .map_err(|e| e.to_string())?;
        match selected {
            None => return Ok(self.clone()),
            Some(prefix)
                if prefix
                    .entry_ids
                    .iter()
                    .all(|id| self.first.contains_key(id)) =>
            {
                for header in &prefix.source_headers {
                    let source = replay
                        .log
                        .retained_header_batch(*header)
                        .map_err(|e| e.to_string())?;
                    replay
                        .verify_anchor(&source.ledger_anchor)
                        .map_err(|e| e.to_string())?;
                    for entry in &source.entries {
                        replay.verify_entry(entry).map_err(|e| e.to_string())?;
                    }
                }
                return Ok(self.clone());
            }
            Some(_) => {}
        }
        self.with_full_current_observation(replay)
    }

    pub(super) fn with_full_current_observation(
        &self,
        replay: &M0CandidateReplay,
    ) -> Result<Self, String> {
        let observation = replay.observe_admission()?;
        let fresh: Vec<_> = observation
            .entry_sources
            .keys()
            .filter(|entry| !self.first.contains_key(entry))
            .copied()
            .collect();
        if fresh.is_empty() {
            return Ok(self.clone());
        }
        // Requires a retained certificate, raw sources and current exact
        // genesis. A display projection or a prepared proposal cannot enter.
        replay.reconcile_admission_observation(&observation)?;
        if self
            .first
            .len()
            .checked_add(fresh.len())
            .is_none_or(|n| n > MAX_M0_REPLAY_ENTRIES)
        {
            return Err("local Admission obligation entry limit reached".into());
        }
        // Bound stored logical dependencies separately from existing source
        // and certificate limits. One immutable scope is shared by its entries.
        let report_bytes = bounded_json_size(
            observation.report(),
            observation::OBSERVATION_MAX_JSON_BYTES,
        )?;
        let cost = observation
            .source_headers
            .len()
            .checked_mul(64)
            .and_then(|n| {
                observation
                    .entry_sources
                    .len()
                    .checked_mul(256)
                    .and_then(|m| n.checked_add(m))
            })
            .and_then(|n| report_bytes.checked_mul(2).and_then(|m| n.checked_add(m)))
            .and_then(|n| n.checked_add(1024))
            .ok_or("local Admission obligation dependency size overflow")?;
        let bytes = self
            .dependency_bytes
            .checked_add(cost)
            .filter(|n| *n <= MAX_OBLIGATION_DEPENDENCY_BYTES)
            .ok_or("local Admission obligation dependency limit reached")?;
        let mut next = self.clone();
        let scope = Arc::new(observation);
        for entry in fresh {
            next.first.insert(entry, scope.clone());
        }
        next.dependency_bytes = bytes;
        Ok(next)
    }
}

fn default_limit() -> usize {
    16
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionObligationQuery {
    #[serde(default)]
    pub after_entry_id: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: usize,
}
impl Default for AdmissionObligationQuery {
    fn default() -> Self {
        Self {
            after_entry_id: None,
            limit: default_limit(),
        }
    }
}
impl AdmissionObligationQuery {
    pub fn validate(&self) -> Result<Option<AdmissionHash32>, String> {
        if self.limit == 0 || self.limit > MAX_OBLIGATION_PAGE_ENTRIES {
            return Err("Admission obligation page limit must be 1..32".into());
        }
        self.after_entry_id
            .as_ref()
            .map(|raw| {
                let id = AdmissionHash32::from_hex(raw).map_err(|e| e.to_string())?;
                if id.is_zero() || id.to_hex() != *raw {
                    return Err(
                        "Admission obligation cursor must be a canonical nonzero entry ID".into(),
                    );
                }
                Ok(id)
            })
            .transpose()
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct AdmissionObligationEntryReport {
    pub obligation_id: String,
    pub entry_id: String,
    pub first_confirmed_at_finalized_height: String,
    pub first_confirmed_at_epoch: String,
    pub first_confirmed_at_commit: String,
    pub first_confirmed_at_state_root: String,
    pub elapsed_confirmed_epochs: String,
    pub past_observation_lag_limit: bool,
    pub treatment: ObservedEntryTreatmentReport,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct AdmissionObligationPage {
    pub format_version: String,
    pub manifest_sha256: String,
    pub current_finalized_height: String,
    pub current_finalized_epoch: String,
    pub current_finalized_state_root: String,
    pub total_observed_entries: usize,
    pub retained_dependency_bytes: usize,
    pub entries: Vec<AdmissionObligationEntryReport>,
    pub next_after_entry_id: Option<String>,
    pub clock_basis: String,
    pub contribution_eligibility_verified: bool,
    pub objective_rejections_evaluated: bool,
    pub live_censorship_policy_active: bool,
    pub recovery_authorized: bool,
    pub signature_authorized: bool,
}

impl M0CandidateReplay {
    /// Rebuild from sealed chronological inputs before using this display in a
    /// role. Unordered legacy node sources cannot establish first receipt time.
    pub fn admission_obligations(
        &self,
        query: &AdmissionObligationQuery,
    ) -> Result<AdmissionObligationPage, String> {
        let cursor = query.validate()?;
        let current = self.observe_admission()?;
        let epoch: u128 = current
            .report()
            .finalized_epoch
            .parse::<u128>()
            .map_err(|e| e.to_string())?;
        let mut selected: Vec<_> = self
            .admission_obligations
            .first
            .range((cursor.map_or(Unbounded, Excluded), Unbounded))
            .take(query.limit + 1)
            .collect();
        let more = selected.len() > query.limit;
        selected.truncate(query.limit);
        // Recheck each original dependency scope once per page, including
        // off-canonical sources; disappearing evidence never resolves a claim.
        let mut reconciled = BTreeMap::new();
        let mut entries = Vec::with_capacity(selected.len());
        for (entry_id, scope) in selected {
            let origin = scope.report();
            let key = (scope.ledger_height, origin.canonical_admission_tip.clone());
            if let std::collections::btree_map::Entry::Vacant(entry) = reconciled.entry(key.clone())
            {
                entry.insert(self.reconcile_admission_observation(scope)?.report());
            }
            let treatment = reconciled[&key]
                .entries
                .iter()
                .find(|e| e.entry_id == entry_id.to_hex())
                .ok_or("first observation lost its obligated entry")?
                .clone();
            let first_epoch: u128 = origin
                .finalized_epoch
                .parse::<u128>()
                .map_err(|e| e.to_string())?;
            let elapsed = epoch
                .checked_sub(first_epoch)
                .ok_or("obligation clock regressed")?;
            entries.push(AdmissionObligationEntryReport {
                obligation_id: treatment.obligation_id.clone(),
                entry_id: entry_id.to_hex(),
                first_confirmed_at_finalized_height: origin.finalized_height.clone(),
                first_confirmed_at_epoch: origin.finalized_epoch.clone(),
                first_confirmed_at_commit: origin
                    .finalized_commit_hash
                    .clone()
                    .ok_or("obligation has no certified clock")?,
                first_confirmed_at_state_root: origin.finalized_state_root.clone(),
                elapsed_confirmed_epochs: elapsed.to_string(),
                past_observation_lag_limit: elapsed > crate::MAX_ADMISSION_LAG_EPOCHS,
                treatment,
            });
        }
        let page = AdmissionObligationPage {
            format_version: "RLD-ADMISSION-OBLIGATION-PAGE-V1".into(),
            manifest_sha256: self.manifest_sha256().into(),
            current_finalized_height: current.report().finalized_height.clone(),
            current_finalized_epoch: current.report().finalized_epoch.clone(),
            current_finalized_state_root: current.report().finalized_state_root.clone(),
            total_observed_entries: self.admission_obligations.first.len(),
            retained_dependency_bytes: self.admission_obligations.dependency_bytes,
            next_after_entry_id: more.then(|| entries.last().unwrap().entry_id.clone()),
            entries,
            clock_basis: "LOCAL_VERIFIED_INPUT_ORDER_REQUIRES_DURABLE_ADAPTER".into(),
            contribution_eligibility_verified: false,
            objective_rejections_evaluated: false,
            live_censorship_policy_active: false,
            recovery_authorized: false,
            signature_authorized: false,
        };
        bounded_json_size(&page, MAX_OBLIGATION_PAGE_BYTES)?;
        Ok(page)
    }
}
