//! Transport-only reference to a previously staged canonical tag-28 proof.
//! Resolving it reconstructs the original signed proposal; it grants no authority.
use crate::{AdmissionCheckpointProofV1, AdmissionHash32, ConsensusCommand, ConsensusProposal};
use serde::{Deserialize, Serialize};

pub const M0_PROPOSAL_REFERENCE_FORMAT: &str = "RLD-M0-ADMISSION-PROPOSAL-REFERENCE-V1";
pub const MAX_M0_PROPOSAL_REFERENCE_BYTES: usize = 4096;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionProposalReferenceV1 {
    pub format_version: String,
    pub proof_id: String,
    pub proposal_id: String,
    pub zone_id: String,
    pub currency_genesis_root: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub parent_height: u64,
    pub parent_state_root: String,
    pub round: u64,
    pub proposer_public_key: String,
    pub command_hash: String,
    pub expected_height: u64,
    pub expected_state_root: String,
    pub signature: String,
}

impl AdmissionProposalReferenceV1 {
    pub fn from_proposal(proposal: &ConsensusProposal) -> Result<Self, String> {
        let ConsensusCommand::CommitAdmissionCheckpoint(proof) = &proposal.command else {
            return Err("staged proposal reference requires tag28".into());
        };
        let reference = Self {
            format_version: M0_PROPOSAL_REFERENCE_FORMAT.into(),
            proof_id: proof.proof_id().map_err(|e| e.to_string())?.to_hex(),
            proposal_id: proposal.proposal_id.clone(),
            zone_id: proposal.zone_id.clone(),
            currency_genesis_root: proposal.currency_genesis_root.clone(),
            protocol_era: proposal.protocol_era,
            crypto_era: proposal.crypto_era,
            parent_height: proposal.parent_height,
            parent_state_root: proposal.parent_state_root.clone(),
            round: proposal.round,
            proposer_public_key: proposal.proposer_public_key.clone(),
            command_hash: proposal.command_hash.clone(),
            expected_height: proposal.expected_height,
            expected_state_root: proposal.expected_state_root.clone(),
            signature: proposal.signature.clone(),
        };
        reference.proof_id_bytes()?;
        Ok(reference)
    }

    pub fn proof_id_bytes(&self) -> Result<[u8; 32], String> {
        super::bounded_json_size(self, MAX_M0_PROPOSAL_REFERENCE_BYTES)?;
        if self.format_version != M0_PROPOSAL_REFERENCE_FORMAT {
            return Err("unsupported Admission proposal reference".into());
        }
        let id = AdmissionHash32::from_hex(&self.proof_id).map_err(|e| e.to_string())?;
        if id.is_zero() || id.to_hex() != self.proof_id {
            return Err("proposal reference requires a canonical nonzero proof ID".into());
        }
        Ok(id.0)
    }

    pub fn resolve(&self, canonical_proof: &[u8]) -> Result<ConsensusProposal, String> {
        let expected_id = self.proof_id_bytes()?;
        let proof = AdmissionCheckpointProofV1::from_canonical_bytes(canonical_proof)
            .map_err(|e| e.to_string())?;
        if proof.proof_id().map_err(|e| e.to_string())?.0 != expected_id {
            return Err("staged proof differs from proposal reference".into());
        }
        let network = proof.context.network_domain.clone();
        if proof.context.zone_id != self.zone_id
            || proof.context.currency_genesis.to_hex() != self.currency_genesis_root
            || proof.context.protocol_era != u128::from(self.protocol_era)
            || proof.context.crypto_era != u128::from(self.crypto_era)
        {
            return Err("staged proof and proposal contexts differ".into());
        }
        let proposal = ConsensusProposal {
            proposal_id: self.proposal_id.clone(),
            zone_id: self.zone_id.clone(),
            currency_genesis_root: self.currency_genesis_root.clone(),
            protocol_era: self.protocol_era,
            crypto_era: self.crypto_era,
            parent_height: self.parent_height,
            parent_state_root: self.parent_state_root.clone(),
            round: self.round,
            proposer_public_key: self.proposer_public_key.clone(),
            command: ConsensusCommand::CommitAdmissionCheckpoint(Box::new(proof)),
            command_hash: self.command_hash.clone(),
            expected_height: self.expected_height,
            expected_state_root: self.expected_state_root.clone(),
            signature: self.signature.clone(),
        };
        if proposal
            .command
            .wire_v1_command_hash(&network)
            .map_err(|e| e.to_string())?
            != proposal.command_hash
        {
            return Err("staged proof command commitment differs from signed header".into());
        }
        proposal
            .wire_v1_signing_bytes(&network)
            .map_err(|e| e.to_string())?;
        Ok(proposal)
    }
}
