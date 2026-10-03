//! Signed acknowledgment of an isolated destination-store import.
//!
//! The signer attests to a durable local event, not to destination consensus,
//! finality, independent operation or live RLD credit.

use super::SimulatedReceipt;
use crate::chain::{CandidateChain, ObservationPolicy};
use crate::{hash, require, Result};
use rld_core::{sign_bytes, validate_ed25519_public_key, verify_bytes, AdmissionHash32 as Hash};
use rld_cross_region::ProofBundle;
use rld_pow::OutPoint;
use serde::{Deserialize, Serialize};

pub const CANDIDATE_IMPORT_ACK_STATUS: &str = "UNADOPTED_DESTINATION_IMPORT_ACK_ONLY";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CandidateImportAck {
    pub status: String,
    pub live_rld: bool,
    pub bundle_id: Hash,
    pub source_policy: ObservationPolicy,
    pub receipt: SimulatedReceipt,
    pub operator: String,
    pub signature: String,
}

impl SimulatedReceipt {
    pub(crate) fn derived_id(&self) -> Hash {
        let mut bytes = b"RLD-DESTINATION-IMPORT-RECEIPT-SIMULATION-V1\0".to_vec();
        bytes.extend(self.destination_chain_id.0);
        bytes.extend(self.source_chain_id.0);
        bytes.extend(self.export_id.0);
        bytes.extend(self.source_checkpoint.0);
        bytes.extend(self.destination_height.to_be_bytes());
        bytes.extend(self.state_root.0);
        hash(&bytes)
    }

    fn verify_bundle(&self, bundle: &ProofBundle) -> Result<()> {
        bundle.validate()?;
        require(
            self.source_chain_id == bundle.source_chain_id
                && self.destination_chain_id == bundle.destination_chain_id
                && self.export_id == bundle.export_id
                && self.source_checkpoint == bundle.source_checkpoint
                && self.destination_height > 0
                && !self.state_root.is_zero()
                && self.id == self.derived_id(),
            "candidate import receipt does not match bundle or state",
        )?;
        let mut bytes = b"RLD-DESTINATION-IMPORT-OUTPUT-SIMULATION-V1\0".to_vec();
        bytes.extend(self.destination_chain_id.0);
        bytes.extend(self.source_chain_id.0);
        bytes.extend(self.export_id.0);
        let transaction = hash(&bytes);
        require(
            self.recipient_outpoint
                == OutPoint {
                    transaction,
                    index: 0,
                }
                && self.miner_fee_outpoint
                    == OutPoint {
                        transaction,
                        index: 1,
                    },
            "candidate import output identity differs",
        )
    }
}

impl CandidateImportAck {
    fn signing_bytes(&self) -> Result<Vec<u8>> {
        validate_ed25519_public_key(&self.operator)?;
        let mut bytes = b"RLD-EARTH-DESTINATION-DURABLE-IMPORT-ACK\0".to_vec();
        bytes.extend(self.bundle_id.0);
        bytes.extend(serde_json::to_vec(&self.source_policy).map_err(|e| e.to_string())?);
        bytes.extend(serde_json::to_vec(&self.receipt).map_err(|e| e.to_string())?);
        bytes.extend(hex::decode(&self.operator).map_err(|e| e.to_string())?);
        Ok(bytes)
    }

    pub(crate) fn sign(
        receipt: SimulatedReceipt,
        bundle: &ProofBundle,
        source_policy: &ObservationPolicy,
        operator_public: &str,
        operator_secret: &str,
    ) -> Result<Self> {
        receipt.verify_bundle(bundle)?;
        let mut ack = Self {
            status: CANDIDATE_IMPORT_ACK_STATUS.into(),
            live_rld: false,
            bundle_id: bundle.id()?,
            source_policy: source_policy.clone(),
            receipt,
            operator: operator_public.into(),
            signature: String::new(),
        };
        ack.signature = sign_bytes(operator_secret, &ack.signing_bytes()?)?;
        ack.verify(bundle, operator_public)?;
        Ok(ack)
    }

    /// Verify the operator's claim about one exact transported proof. This
    /// does not verify that any destination consensus included the import.
    pub fn verify(&self, bundle: &ProofBundle, pinned_operator: &str) -> Result<()> {
        validate_ed25519_public_key(pinned_operator)?;
        require(
            self.status == CANDIDATE_IMPORT_ACK_STATUS
                && !self.live_rld
                && self.operator == pinned_operator
                && self.bundle_id == bundle.id()?,
            "candidate import acknowledgment status, signer or bundle mismatch",
        )?;
        self.receipt.verify_bundle(bundle)?;
        verify_bytes(&self.operator, &self.signing_bytes()?, &self.signature)
    }

    /// Recheck the exact export against a separately replayed selected source
    /// branch in addition to verifying the destination operator's signature.
    /// This observation can be revoked by a later source reorganization.
    pub fn verify_with_replayed_source(
        &self,
        source: &CandidateChain,
        policy: &ObservationPolicy,
        bundle: &ProofBundle,
        pinned_operator: &str,
    ) -> Result<()> {
        self.verify(bundle, pinned_operator)?;
        require(
            &self.source_policy == policy,
            "candidate acknowledgment source policy differs",
        )?;
        let observed = source.observe_export_bundle(bundle, policy)?;
        require(
            observed.record.id()? == self.receipt.export_id,
            "candidate acknowledgment export differs from source proof",
        )
    }
}
