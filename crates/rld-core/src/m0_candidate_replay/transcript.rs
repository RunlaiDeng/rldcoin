//! Local interchange for a keyless verifier. These are not consensus objects,
//! not a snapshot and not proof of live authorization. Every line is the exact
//! compact Serde JSON encoding, so ignored/duplicate/omitted fields and numeric
//! or field-order changes cannot be silently accepted by legacy inner types.

use super::M0CandidateReplay;
use crate::{
    AdmissionLedgerAnchorV1, AdmissionSidecarSubmissionV1, AdmissionVerifiedHeaderSubmissionV1,
    BaselineAccessWorkV1, ConsensusCommit, PermissionlessAdmissionEntryV1,
    PermissionlessAdmissionHeaderV1,
};
use serde::{Deserialize, Serialize};

pub const REPLAY_FRAME_VERSION: &str = "RLD-M0-CANDIDATE-SEMANTIC-REPLAY-V1";
pub const MAX_REPLAY_FRAME_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_REPLAY_TRANSCRIPT_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_REPLAY_TRANSCRIPT_RECORDS: usize = 16_384;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayFrame {
    pub format_version: String,
    pub event: ReplayEvent,
}

// Externally tagged to deserialize the original typed values directly.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReplayEvent {
    CertifiedCommit(Box<ConsensusCommit>),
    AdmissionSource(Box<ReplayAdmissionSource>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayAdmissionSource {
    pub entries: Vec<ReplaySidecar>,
    pub access_work: BaselineAccessWorkV1,
    pub header: PermissionlessAdmissionHeaderV1,
    pub ledger_anchor: AdmissionLedgerAnchorV1,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaySidecar {
    pub entry: PermissionlessAdmissionEntryV1,
    pub payload: Vec<u8>,
}

impl From<&AdmissionVerifiedHeaderSubmissionV1> for ReplayAdmissionSource {
    fn from(source: &AdmissionVerifiedHeaderSubmissionV1) -> Self {
        Self {
            entries: source
                .entries
                .iter()
                .map(|s| ReplaySidecar {
                    entry: s.entry.clone(),
                    payload: s.payload.clone(),
                })
                .collect(),
            access_work: source.access_work.clone(),
            header: source.header.clone(),
            ledger_anchor: source.ledger_anchor.clone(),
        }
    }
}

impl ReplayFrame {
    pub fn new(event: ReplayEvent) -> Self {
        Self {
            format_version: REPLAY_FRAME_VERSION.into(),
            event,
        }
    }

    /// Excludes the one mandatory LF frame separator used by the CLI reader.
    pub fn canonical_line(&self) -> Result<Vec<u8>, String> {
        if self.format_version != REPLAY_FRAME_VERSION {
            return Err("unsupported candidate replay frame version".into());
        }
        super::bounded_json_size(self, MAX_REPLAY_FRAME_BYTES)?;
        serde_json::to_vec(self).map_err(|e| e.to_string())
    }

    pub fn decode_line(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_REPLAY_FRAME_BYTES {
            return Err("candidate replay frame is empty or exceeds the local size limit".into());
        }
        let frame: Self = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if frame.canonical_line()? != bytes {
            return Err("candidate replay frame is not exact canonical typed JSON".into());
        }
        Ok(frame)
    }

    pub fn replay(self, verifier: &mut M0CandidateReplay) -> Result<(), String> {
        if self.format_version != REPLAY_FRAME_VERSION {
            return Err("unsupported candidate replay frame version".into());
        }
        match self.event {
            ReplayEvent::CertifiedCommit(commit) => verifier.replay_candidate_commit(&commit),
            ReplayEvent::AdmissionSource(source) => verifier
                .append_admission_source(&AdmissionVerifiedHeaderSubmissionV1 {
                    entries: source
                        .entries
                        .into_iter()
                        .map(|s| AdmissionSidecarSubmissionV1 {
                            entry: s.entry,
                            payload: s.payload,
                        })
                        .collect(),
                    access_work: source.access_work,
                    header: source.header,
                    ledger_anchor: source.ledger_anchor,
                })
                .map(|_| ()),
        }
    }
}
