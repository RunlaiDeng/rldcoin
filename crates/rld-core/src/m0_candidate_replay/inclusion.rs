//! Finalized checkpoint membership, not contribution acceptance or recovery
//! clearance. The private index is derived only after full candidate execution
//! and QC validation. It is neither a persisted authority nor an input format.
use super::*;
use crate::{AdmissionCheckpointV1, PermissionlessAdmissionEntryV1};
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FinalizedAdmissionEntry {
    pub(super) ledger_height: u128,
    pub(super) source_header: AdmissionHash32,
    pub(super) checkpoint: Arc<AdmissionCheckpointV1>,
}

/// Borrows the verifier's authenticated history, preventing it from being
/// advanced while this capability is used. It cannot be deserialized.
#[derive(Debug)]
pub struct VerifiedAdmissionInclusion<'a> {
    manifest_sha256: &'a str,
    commit_hash: &'a str,
    certificate: &'a ConsensusCommit,
    checkpoint: &'a AdmissionCheckpointV1,
    source_header: AdmissionHash32,
    entry: &'a PermissionlessAdmissionEntryV1,
}

impl VerifiedAdmissionInclusion<'_> {
    pub fn certificate(&self) -> &ConsensusCommit {
        self.certificate
    }
    pub fn checkpoint(&self) -> &AdmissionCheckpointV1 {
        self.checkpoint
    }
    pub fn entry(&self) -> &PermissionlessAdmissionEntryV1 {
        self.entry
    }
    pub fn report(&self) -> AdmissionInclusionReport {
        AdmissionInclusionReport {
            format_version: "RLD-FINALIZED-ADMISSION-INCLUSION-V1".into(),
            manifest_sha256: self.manifest_sha256.into(),
            entry_id: self.entry.entry_id().to_hex(),
            source_header_id: self.source_header.to_hex(),
            checkpoint_id: self.checkpoint.checkpoint_id().to_hex(),
            checkpoint_header_id: self.checkpoint.header_id.to_hex(),
            checkpoint_entries_root: self.checkpoint.entries_root.to_hex(),
            checkpoint_availability_root: self.checkpoint.availability_root.to_hex(),
            finalized_commit_hash: self.commit_hash.into(),
            finalized_height: self.certificate.proposal.expected_height.to_string(),
            finalized_epoch: self.checkpoint.committed_ledger_epoch.to_string(),
            finalized_state_root: self.certificate.proposal.expected_state_root.clone(),
            contribution_accepted: false,
            recovery_authorized: false,
            live_authorization: false,
        }
    }
}

/// Unsigned local display projection. Consumers must independently verify the
/// genesis-rooted transcript; this JSON alone is not a finality proof.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct AdmissionInclusionReport {
    pub format_version: String,
    pub manifest_sha256: String,
    pub entry_id: String,
    pub source_header_id: String,
    pub checkpoint_id: String,
    pub checkpoint_header_id: String,
    pub checkpoint_entries_root: String,
    pub checkpoint_availability_root: String,
    pub finalized_commit_hash: String,
    pub finalized_height: String,
    pub finalized_epoch: String,
    pub finalized_state_root: String,
    pub contribution_accepted: bool,
    pub recovery_authorized: bool,
    pub live_authorization: bool,
}

impl M0CandidateReplay {
    pub(super) fn prepare_finalized_inclusions(
        &self,
        commit: &ConsensusCommit,
        successor: &Ledger,
    ) -> Result<Option<BTreeMap<AdmissionHash32, FinalizedAdmissionEntry>>, String> {
        let ConsensusCommand::CommitAdmissionCheckpoint(proof) = &commit.proposal.command else {
            return Ok(None);
        };
        let admission = successor
            .admission_state
            .as_ref()
            .ok_or("missing finalized Admission state")?;
        let checkpoint = admission
            .latest_checkpoint
            .as_ref()
            .ok_or("missing finalized checkpoint")?;
        if admission.latest_checkpoint_proof_id
            != Some(proof.proof_id().map_err(|e| e.to_string())?)
            || successor.height != commit.proposal.expected_height
        {
            return Err("finalized inclusion differs from executed checkpoint".into());
        }
        let checkpoint = Arc::new(checkpoint.clone());
        let mut entries = self.admission_inclusions.clone();
        for batch in &proof.batch_segment {
            for entry in &batch.entries {
                if entries.contains_key(&entry.entry_id()) || entries.len() >= MAX_M0_REPLAY_ENTRIES
                {
                    return Err(
                        "finalized inclusion repeats an entry or exceeds its local bound".into(),
                    );
                }
                entries.insert(
                    entry.entry_id(),
                    FinalizedAdmissionEntry {
                        ledger_height: u128::from(successor.height),
                        source_header: batch.header.header_id(),
                        checkpoint: checkpoint.clone(),
                    },
                );
            }
        }
        Ok(Some(entries))
    }

    pub fn verified_admission_inclusion(
        &self,
        entry_id: AdmissionHash32,
    ) -> Result<Option<VerifiedAdmissionInclusion<'_>>, String> {
        if entry_id.is_zero() {
            return Err("finalized inclusion requires a nonzero entry ID".into());
        }
        let Some(record) = self.admission_inclusions.get(&entry_id) else {
            return Ok(None);
        };
        let commit_id = self
            .anchors
            .get(&record.ledger_height)
            .ok_or("inclusion has no certified anchor")?
            .to_hex();
        let (commit_hash, certificate) = self
            .ledger
            .consensus_commits
            .get_key_value(&commit_id)
            .ok_or("inclusion has no retained finality certificate")?;
        let ConsensusCommand::CommitAdmissionCheckpoint(proof) = &certificate.proposal.command
        else {
            return Err("inclusion certificate is not a checkpoint".into());
        };
        let batch = proof
            .batch_segment
            .iter()
            .find(|b| b.header.header_id() == record.source_header)
            .ok_or("entry source is not in the finalized checkpoint batch")?;
        let entry = batch
            .entries
            .iter()
            .find(|e| e.entry_id() == entry_id)
            .ok_or("entry is absent from the finalized checkpoint batch")?;
        let retained = self
            .log
            .retained_header_batch(record.source_header)
            .map_err(|e| e.to_string())?;
        if &retained != batch {
            return Err("finalized inclusion source differs from retained bytes".into());
        }
        self.verify_anchor(&batch.ledger_anchor)
            .map_err(|e| e.to_string())?;
        self.verify_entry(entry).map_err(|e| e.to_string())?;
        Ok(Some(VerifiedAdmissionInclusion {
            manifest_sha256: self.manifest_sha256(),
            commit_hash,
            certificate,
            checkpoint: &record.checkpoint,
            source_header: record.source_header,
            entry,
        }))
    }
}
