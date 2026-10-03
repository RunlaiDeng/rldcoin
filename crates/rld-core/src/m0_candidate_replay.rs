//! Bounded, keyless semantic replay from an independently pinned M0 genesis.
//!
//! This is a dependency for role-local verification, not signing authority or
//! an independent client implementation. In particular, replaying a certified
//! dormant tag-28 candidate does not authorize it under the live M0 profile.
//! There is no snapshot importer, caller-supplied Ledger, trusted boolean,
//! external resolver callback, signing key, disk write or activation operation.

use std::{collections::BTreeMap, io, sync::Arc};

use crate::{
    verify_admission_sidecar, AdmissionCheckpointProofContextV1, AdmissionCheckpointProofV1,
    AdmissionError, AdmissionHash32, AdmissionLedgerAnchorV1, AdmissionVerifiedHeaderSubmissionV1,
    ConsensusCommand, ConsensusCommit, ConsensusProposal, Ledger, M0GenesisManifestFile,
    PermissionlessAdmissionEntryV1, PermissionlessAdmissionLogV1,
    VerifiedAdmissionCheckpointTransitionV1,
};

pub mod inclusion;
pub mod obligations;
pub mod observation;
pub mod proposal_reference;
pub mod reconciliation;
pub mod source_frame;
pub mod transcript;

// Local verifier resource ceilings, not new consensus limits. Exhaustion stops
// this verifier without pruning evidence or changing protocol validity.
pub const MAX_M0_REPLAY_COMMITS: usize = 4096;
pub const MAX_M0_REPLAY_HEADERS: usize = 4096;
pub const MAX_M0_REPLAY_SIDECAR_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_M0_REPLAY_ENTRIES: usize = 8192;
pub const MAX_M0_REPLAY_COMMIT_BYTES: usize = 32 * 1024 * 1024;
const MAX_M0_REPLAY_PROPOSAL_JSON_BYTES: usize = 4 * 1024 * 1024;

fn bounded_json_size(value: &impl serde::Serialize, limit: usize) -> Result<usize, String> {
    struct Counter {
        remaining: usize,
    }
    impl io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.remaining = self.remaining.checked_sub(bytes.len()).ok_or_else(|| {
                io::Error::other("semantic replay local serialized-byte limit reached")
            })?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter { remaining: limit };
    serde_json::to_writer(&mut counter, value).map_err(|e| e.to_string())?;
    Ok(limit - counter.remaining)
}

#[derive(Clone, Debug)]
pub struct M0CandidateReplay {
    manifest: M0GenesisManifestFile,
    ledger: Ledger,
    log: PermissionlessAdmissionLogV1,
    anchors: BTreeMap<u128, AdmissionHash32>,
    admission_inclusions: BTreeMap<AdmissionHash32, inclusion::FinalizedAdmissionEntry>,
    admission_obligations: obligations::AdmissionObligationHistory,
    sidecars: BTreeMap<AdmissionHash32, Arc<Vec<u8>>>,
    sidecar_bytes: usize,
    retained_headers: usize,
    retained_entries: usize,
    retained_commit_bytes: usize,
}

/// A semantic result deliberately has no conversion into a vote, durable lock
/// or activation capability. Consumers must separately enforce live authority,
/// exact persisted ancestry, rollback protection and their own signature locks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct M0ProposalSemanticCheck {
    genesis_manifest_sha256: String,
    proposal_hash: String,
    parent_height: u128,
    parent_state_root: String,
    expected_height: u128,
    expected_state_root: String,
    command_tag: u16,
}

/// Read-only draft inspection. No constructor from external reports, and no
/// conversion into a finalized schedule, migration or signing permission.
#[derive(Clone, Debug, serde::Serialize)]
pub struct UpgradeIntentInspection {
    manifest_sha256: String,
    intent_id: String,
    parent_height: String,
    parent_state_root: String,
    earliest_activation_height: String,
    requested_activation_height: String,
    signature_authorized: bool,
    migration_verified: bool,
    schedule_finalized: bool,
}

/// Reviewable command identity; not an executable scheduling capability.
#[derive(Clone, Debug, serde::Serialize)]
pub struct UpgradeScheduleInspection {
    object_format: String,
    command_tag: u16,
    command_sha256: String,
    object_sha256: String,
    proposed_schedule_height: String,
    proposed_schedule_state_root: String,
    #[serde(flatten)]
    parent: UpgradeIntentInspection,
}

impl M0ProposalSemanticCheck {
    pub fn genesis_manifest_sha256(&self) -> &str {
        &self.genesis_manifest_sha256
    }
    pub fn proposal_hash(&self) -> &str {
        &self.proposal_hash
    }
    pub fn parent_height(&self) -> u128 {
        self.parent_height
    }
    pub fn parent_state_root(&self) -> &str {
        &self.parent_state_root
    }
    pub fn expected_height(&self) -> u128 {
        self.expected_height
    }
    pub fn expected_state_root(&self) -> &str {
        &self.expected_state_root
    }
    pub fn command_tag(&self) -> u16 {
        self.command_tag
    }
}

impl M0CandidateReplay {
    pub fn inspect_upgrade_schedule(
        &self,
        schedule: &crate::genesis::upgrade_wire::ScheduleUpgradeV1,
    ) -> Result<UpgradeScheduleInspection, String> {
        let earliest = schedule.check_bootstrap_parent(&self.ledger)?;
        let preview = self
            .ledger
            .preview_upgrade_schedule(schedule)
            .map_err(|e| e.to_string())?;
        Ok(UpgradeScheduleInspection {
            object_format: schedule.format_version.clone(),
            command_tag: 37,
            command_sha256: crate::hash_bytes(&schedule.candidate_command_bytes()?),
            object_sha256: crate::hash_bytes(&schedule.canonical_bytes()?),
            proposed_schedule_height: preview.height.to_string(),
            proposed_schedule_state_root: preview.state_root().map_err(|e| e.to_string())?,
            parent: UpgradeIntentInspection {
                manifest_sha256: self.manifest_sha256().into(),
                intent_id: schedule.intent_id()?,
                parent_height: self.ledger.height.to_string(),
                parent_state_root: self.ledger.state_root().map_err(|e| e.to_string())?,
                earliest_activation_height: earliest.to_string(),
                requested_activation_height: schedule.activation_height.to_string(),
                signature_authorized: false,
                migration_verified: false,
                schedule_finalized: false,
            },
        })
    }

    pub fn inspect_upgrade_intent(
        &self,
        intent: &crate::genesis::upgrade_intent::UpgradeIntentDraftV1,
    ) -> Result<UpgradeIntentInspection, String> {
        let earliest = intent.check_bootstrap_parent(&self.ledger)?;
        Ok(UpgradeIntentInspection {
            manifest_sha256: self.manifest_sha256().into(),
            intent_id: intent.intent_id()?,
            parent_height: self.ledger.height.to_string(),
            parent_state_root: self.ledger.state_root().map_err(|e| e.to_string())?,
            earliest_activation_height: earliest.to_string(),
            requested_activation_height: intent.activation_height.to_string(),
            signature_authorized: false,
            migration_verified: false,
            schedule_finalized: false,
        })
    }

    pub fn from_pinned_genesis(
        bytes: &[u8],
        expected_manifest_sha256: &str,
    ) -> Result<Self, String> {
        let manifest = M0GenesisManifestFile::decode_json(bytes)?;
        manifest.verify()?;
        if manifest.manifest_sha256() != expected_manifest_sha256 {
            return Err("semantic replay genesis does not match the independent pin".into());
        }
        let descriptor = manifest.descriptor();
        let mut ledger = Ledger::genesis_zone(
            descriptor.display_name.clone(),
            descriptor.genesis_validator_keys.clone(),
            descriptor.genesis_notary_keys.clone(),
            false,
        )
        .map_err(|e| e.to_string())?;
        manifest
            .bind_genesis(&mut ledger)
            .map_err(|e| e.to_string())?;
        manifest.validate_ledger_identity(&ledger)?;
        if ledger.state_root().map_err(|e| e.to_string())? != manifest.genesis_state_root() {
            return Err("semantic replay did not reconstruct the exact genesis root".into());
        }
        let genesis = manifest.admission_genesis();
        let log = PermissionlessAdmissionLogV1::new(
            genesis.context.clone(),
            genesis.config.clone(),
            genesis.genesis_header,
        )
        .map_err(|e| e.to_string())?;
        Ok(Self {
            manifest,
            ledger,
            log,
            anchors: BTreeMap::new(),
            admission_inclusions: BTreeMap::new(),
            admission_obligations: Default::default(),
            sidecars: BTreeMap::new(),
            sidecar_bytes: 0,
            retained_headers: 0,
            retained_entries: 0,
            retained_commit_bytes: 0,
        })
    }

    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    pub fn manifest_sha256(&self) -> &str {
        self.manifest.manifest_sha256()
    }

    pub fn contains_admission_header(&self, id: AdmissionHash32) -> bool {
        self.log.contains_header(id)
    }

    pub fn retained_admission_headers(&self) -> usize {
        self.retained_headers
    }

    pub fn retained_sidecar_bytes(&self) -> usize {
        self.sidecar_bytes
    }

    /// Sources can be supplied in any topological interleaving with certified
    /// commits. A header can only reference a commit already fully replayed;
    /// supplying a future QC or a claimed block hash never inserts an anchor.
    pub fn append_admission_source(
        &mut self,
        submission: &AdmissionVerifiedHeaderSubmissionV1,
    ) -> Result<AdmissionHash32, String> {
        if submission.entries.len() > crate::MAX_ADMISSION_ENTRIES_PER_HEADER {
            return Err("Admission source exceeds the per-header entry bound".into());
        }
        bounded_json_size(&submission.header, 16 * 1024)?;
        bounded_json_size(&submission.access_work, 16 * 1024)?;
        for submitted in &submission.entries {
            bounded_json_size(&submitted.entry, 8 * 1024)?;
        }
        self.verify_anchor(&submission.ledger_anchor)
            .map_err(|e| e.to_string())?;
        let id = submission.header.header_id();
        if self.log.contains_header(id) {
            let retained = self
                .log
                .retained_header_batch(id)
                .map_err(|e| e.to_string())?;
            if retained.header != submission.header
                || retained.access_work != submission.access_work
                || retained.ledger_anchor != submission.ledger_anchor
                || retained.entries.len() != submission.entries.len()
            {
                return Err(
                    "Admission source retry changed its header/work/anchor or entry count".into(),
                );
            }
            // AdmissionLog canonicalizes entry order. A retry must compare
            // the same canonical set, including every exact entry and payload.
            let mut entries = submission.entries.iter().collect::<Vec<_>>();
            entries.sort_unstable_by_key(|submitted| submitted.entry.entry_id());
            for (entry, submitted) in retained.entries.iter().zip(entries) {
                if entry != &submitted.entry {
                    return Err("Admission source retry substituted an entry".into());
                }
                verify_admission_sidecar(entry, &submitted.payload).map_err(|e| e.to_string())?;
                if self
                    .sidecars
                    .get(&entry.payload_commitment)
                    .map(|p| p.as_slice())
                    != Some(submitted.payload.as_slice())
                {
                    return Err("Admission source retry substituted retained sidecar bytes".into());
                }
            }
            return Ok(id);
        }
        let entries = self
            .retained_entries
            .checked_add(submission.entries.len())
            .ok_or("semantic replay entry count overflow")?;
        if self.retained_headers >= MAX_M0_REPLAY_HEADERS || entries > MAX_M0_REPLAY_ENTRIES {
            return Err("semantic replay local retained-source limit reached".into());
        }
        let mut added = BTreeMap::new();
        let mut added_bytes = 0usize;
        for submitted in &submission.entries {
            verify_admission_sidecar(&submitted.entry, &submitted.payload)
                .map_err(|e| e.to_string())?;
            let key = submitted.entry.payload_commitment;
            let existing = self
                .sidecars
                .get(&key)
                .map(|p| p.as_slice())
                .or_else(|| added.get(&key).map(|p: &&Vec<u8>| p.as_slice()));
            if let Some(existing) = existing {
                if existing != submitted.payload.as_slice() {
                    return Err("semantic replay sidecar content-address conflict".into());
                }
            } else {
                added_bytes = added_bytes
                    .checked_add(submitted.payload.len())
                    .ok_or("semantic replay byte count overflow")?;
                added.insert(key, &submitted.payload);
            }
        }
        let total_bytes = self
            .sidecar_bytes
            .checked_add(added_bytes)
            .ok_or("semantic replay byte count overflow")?;
        if total_bytes > MAX_M0_REPLAY_SIDECAR_BYTES {
            return Err("semantic replay local sidecar byte limit reached".into());
        }
        let mut next = self.clone();
        next.log
            .append_verified_header_ref(submission)
            .map_err(|e| e.to_string())?;
        next.sidecar_bytes = total_bytes;
        next.retained_entries = entries;
        next.retained_headers += 1;
        for (key, bytes) in added {
            next.sidecars.insert(key, Arc::new(bytes.clone()));
        }
        next.admission_obligations = next.admission_obligations.with_current_observation(&next)?;
        // The source and its first-observation projection publish together.
        *self = next;
        Ok(id)
    }

    /// Local signing preflight is stricter than historical replay. A successful
    /// result still requires the role's explicit policy and durable lock path.
    pub fn check_signed_proposal_for_local_authorization(
        &self,
        proposal: &ConsensusProposal,
    ) -> Result<M0ProposalSemanticCheck, String> {
        self.check_current_build_upgrade(&proposal.command)?;
        self.check_signed_proposal(proposal)
    }

    pub fn check_unsigned_proposal_for_local_authorization(
        &self,
        proposal: &ConsensusProposal,
    ) -> Result<(), String> {
        self.check_current_build_upgrade(&proposal.command)?;
        self.check_unsigned_proposal(proposal)
    }

    fn check_current_build_upgrade(&self, command: &ConsensusCommand) -> Result<(), String> {
        match command {
            ConsensusCommand::ScheduleUpgrade(schedule) => {
                crate::genesis::upgrade_migration::validate_current_schedule_artifacts(schedule)
            }
            ConsensusCommand::ActivateUpgrade(activation) => self
                .ledger
                .preview_first_upgrade_activation(activation)
                .map(|_| ()),
            _ => Ok(()),
        }
    }

    pub fn check_signed_proposal(
        &self,
        proposal: &ConsensusProposal,
    ) -> Result<M0ProposalSemanticCheck, String> {
        self.proposal_successor(proposal)?;
        Ok(M0ProposalSemanticCheck {
            genesis_manifest_sha256: self.manifest_sha256().into(),
            proposal_hash: proposal
                .wire_v1_proposal_hash(&self.ledger.descriptor.network_domain)
                .map_err(|e| e.to_string())?,
            parent_height: u128::from(proposal.parent_height),
            parent_state_root: proposal.parent_state_root.clone(),
            expected_height: u128::from(proposal.expected_height),
            expected_state_root: proposal.expected_state_root.clone(),
            command_tag: proposal.command.wire_v1_tag(),
        })
    }

    /// Checks the exact proposal before the proposer releases its first
    /// signature. This does not synthesize a signature, trust a supplied root,
    /// mutate replay state or authorize a currently dormant command.
    pub fn check_unsigned_proposal(&self, proposal: &ConsensusProposal) -> Result<(), String> {
        bounded_json_size(proposal, MAX_M0_REPLAY_PROPOSAL_JSON_BYTES)?;
        if !proposal.signature.is_empty() || proposal.round != 0 {
            return Err(
                "unsigned semantic preview requires an empty signature and round zero".into(),
            );
        }
        self.ledger
            .validate_consensus_proposal_authority_and_prestate(proposal)
            .map_err(|e| e.to_string())?;
        let network = &self.ledger.descriptor.network_domain;
        if proposal
            .command
            .wire_v1_command_hash(network)
            .map_err(|e| e.to_string())?
            != proposal.command_hash
        {
            return Err("unsigned proposal command commitment is not canonical".into());
        }
        // Enforce the existing canonical wire bounds and field rules before
        // evaluating the command, without requiring or inventing a signature.
        proposal
            .wire_v1_signing_bytes(network)
            .map_err(|e| e.to_string())?;
        let successor = match &proposal.command {
            ConsensusCommand::NetworkHeartbeat(_)
            | ConsensusCommand::ScheduleUpgrade(_)
            | ConsensusCommand::ActivateUpgrade(_) => {
                let mut next = self.ledger.clone();
                next.execute_consensus_command(proposal.command.clone())
                    .map_err(|e| e.to_string())?;
                (next.height, next.state_root().map_err(|e| e.to_string())?)
            }
            ConsensusCommand::CommitAdmissionCheckpoint(proof) => {
                let plan = self
                    .ledger
                    .plan_admission_checkpoint_proposal(proof)
                    .map_err(|e| e.to_string())?;
                let transition = self.verify_checkpoint(proof, &plan)?;
                self.ledger
                    .admission_checkpoint_successor_commitment_from_plan(&plan, &transition)
                    .map_err(|e| e.to_string())?
            }
            _ => {
                return Err(
                    "unsigned semantic preview rejects unsupported/value-bearing commands".into(),
                )
            }
        };
        if successor
            != (
                proposal.expected_height,
                proposal.expected_state_root.clone(),
            )
        {
            return Err(
                "unsigned proposal successor differs from independently executed state".into(),
            );
        }
        Ok(())
    }

    /// Replays a certified candidate transition without writing any role state.
    /// An identical already replayed certificate is idempotent; a different
    /// certificate for an old height is rejected rather than changing ancestry.
    pub fn replay_candidate_commit(&mut self, commit: &ConsensusCommit) -> Result<(), String> {
        if commit.votes.len() > self.ledger.descriptor.validator_keys.len() {
            return Err("candidate certificate exceeds the current committee size".into());
        }
        let bytes = bounded_json_size(commit, MAX_M0_REPLAY_PROPOSAL_JSON_BYTES)?;
        let network = &self.ledger.descriptor.network_domain;
        commit
            .verify_wire_v1(&self.ledger.descriptor.validator_keys, network)
            .map_err(|e| e.to_string())?;
        let hash = commit
            .wire_v1_commit_hash(network)
            .map_err(|e| e.to_string())?;
        if let Some(existing) = self.ledger.consensus_commits.get(&hash) {
            return if existing == commit {
                Ok(())
            } else {
                Err("candidate commit digest has conflicting bytes".into())
            };
        }
        if self.anchors.len() >= MAX_M0_REPLAY_COMMITS {
            return Err("semantic replay local certified-history limit reached".into());
        }
        let retained_commit_bytes = self
            .retained_commit_bytes
            .checked_add(bytes)
            .filter(|total| *total <= MAX_M0_REPLAY_COMMIT_BYTES)
            .ok_or("semantic replay local certified-history byte limit reached")?;
        let metadata = self
            .ledger
            .authenticate_consensus_commit_for_external_execution(commit)
            .map_err(|e| e.to_string())?;
        let (mut ledger, log) = self.proposal_successor(&commit.proposal)?;
        ledger
            .finalize_externally_executed_consensus_commit(metadata)
            .map_err(|e| e.to_string())?;
        self.manifest
            .validate_replayed_candidate_identity(&ledger)?;
        let block_id = AdmissionHash32::from_hex(&hash).map_err(|e| e.to_string())?;
        let height = u128::from(ledger.height);
        if self.anchors.contains_key(&height) {
            return Err("candidate replay cannot replace an existing finalized height".into());
        }
        let inclusions = self.prepare_finalized_inclusions(commit, &ledger)?;
        if let Some(inclusions) = inclusions {
            // A checkpoint can reveal the next bounded confirmed batch.
            let mut next = Self {
                manifest: self.manifest.clone(),
                ledger,
                log,
                anchors: self.anchors.clone(),
                admission_inclusions: inclusions,
                admission_obligations: self.admission_obligations.clone(),
                sidecars: self.sidecars.clone(),
                sidecar_bytes: self.sidecar_bytes,
                retained_headers: self.retained_headers,
                retained_entries: self.retained_entries,
                retained_commit_bytes,
            };
            next.anchors.insert(height, block_id);
            next.admission_obligations =
                next.admission_obligations.with_current_observation(&next)?;
            *self = next;
        } else {
            // Heartbeats change the certified clock, not first observations.
            self.ledger = ledger;
            self.log = log;
            self.anchors.insert(height, block_id);
            self.retained_commit_bytes = retained_commit_bytes;
        }
        Ok(())
    }

    fn proposal_successor(
        &self,
        proposal: &ConsensusProposal,
    ) -> Result<(Ledger, PermissionlessAdmissionLogV1), String> {
        bounded_json_size(proposal, MAX_M0_REPLAY_PROPOSAL_JSON_BYTES)?;
        let mut ledger = self.ledger.clone();
        let mut log = self.log.clone();
        match &proposal.command {
            ConsensusCommand::NetworkHeartbeat(_)
            | ConsensusCommand::ScheduleUpgrade(_)
            | ConsensusCommand::ActivateUpgrade(_) => {
                self.ledger
                    .validate_consensus_proposal(proposal)
                    .map_err(|e| e.to_string())?;
                ledger
                    .execute_consensus_command(proposal.command.clone())
                    .map_err(|e| e.to_string())?;
            }
            ConsensusCommand::CommitAdmissionCheckpoint(proof) => {
                let context = self
                    .ledger
                    .authenticate_admission_checkpoint_proposal(proposal, proof)
                    .map_err(|e| e.to_string())?;
                let transition = self.verify_checkpoint(proof, &context)?;
                ledger
                    .execute_authenticated_admission_checkpoint_transition(&context, &transition)
                    .map_err(|e| e.to_string())?;
                log.apply_replayed_main_wal_checkpoint_projection(&transition)
                    .map_err(|e| e.to_string())?;
            }
            _ => {
                return Err(
                    "candidate semantic replay rejects unsupported/value-bearing commands".into(),
                )
            }
        }
        Ok((ledger, log))
    }

    fn verify_anchor(&self, anchor: &AdmissionLedgerAnchorV1) -> Result<(), AdmissionError> {
        if self.anchors.get(&anchor.height) != Some(&anchor.block_id) {
            return Err(AdmissionError::ParentOrPrestate(
                "Admission anchor is absent from the locally replayed certified prefix".into(),
            ));
        }
        Ok(())
    }

    fn verify_entry(&self, entry: &PermissionlessAdmissionEntryV1) -> Result<(), AdmissionError> {
        let payload = self
            .sidecars
            .get(&entry.payload_commitment)
            .ok_or_else(|| {
                AdmissionError::ResourceOrAvailability(
                    "exact sidecar bytes are not retained locally".into(),
                )
            })?;
        verify_admission_sidecar(entry, payload)
    }

    fn verify_checkpoint<C: AdmissionCheckpointProofContextV1>(
        &self,
        proof: &AdmissionCheckpointProofV1,
        context: &C,
    ) -> Result<VerifiedAdmissionCheckpointTransitionV1, String> {
        let admission = self
            .ledger
            .admission_state
            .as_ref()
            .ok_or("missing replayed Admission state")?;
        self.log
            .verify_checkpoint_proof_against_ledger_state(
                proof,
                admission,
                context,
                |anchor| self.verify_anchor(anchor),
                |entry| {
                    if self.log.entry_appears_in_ancestry_of(
                        entry.entry_id(),
                        admission.committed_header,
                    )? {
                        return Err(AdmissionError::DuplicateOrNullifier(
                            "entry already committed in prior ancestry".into(),
                        ));
                    }
                    self.verify_entry(entry)
                },
                |header, work, anchor| {
                    let retained = self.log.retained_header_batch(header.header_id())?;
                    if retained.header != *header
                        || retained.access_work != *work
                        || retained.ledger_anchor != *anchor
                    {
                        return Err(AdmissionError::ParentOrPrestate(
                            "confirmation differs from retained source history".into(),
                        ));
                    }
                    for entry in &retained.entries {
                        self.verify_entry(entry)?;
                    }
                    Ok(())
                },
            )
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests;
