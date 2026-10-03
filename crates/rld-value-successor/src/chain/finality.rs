//! Unanimous, source-enforced finality for adopted Earth exports.
//! The four keys may have one owner; this is an explicit trust assumption.

use super::CandidateChain;
use crate::{hash, require, Result};
use rld_core::{verify_bytes, AdmissionHash32 as Hash, AdmissionWork as Work};
use rld_pow::transition::Approval;
use serde::{Deserialize, Serialize};

pub const MIN_FINALITY_DEPTH: u128 = 12;
pub const FORMAT: &str = "RLD-EARTH-SOURCE-FINALITY";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FinalityStatement {
    pub format: String,
    pub source_chain_id: Hash,
    pub source_v1_tip: Hash,
    pub earth_adoption_id: Hash,
    pub block: Hash,
    #[serde(with = "rld_pow::decimal")]
    pub height: u128,
    pub state_root: Hash,
    pub cumulative_work: Work,
    pub previous_certificate: Option<Hash>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FinalityCertificate {
    pub statement: FinalityStatement,
    pub approvals: Vec<Approval>,
}

impl FinalityStatement {
    pub fn from_chain(
        chain: &CandidateChain,
        adoption: Hash,
        block: Hash,
        previous_certificate: Option<Hash>,
    ) -> Result<Self> {
        require(!adoption.is_zero(), "missing Earth adoption for finality")?;
        let entry = chain.entries.get(&block).ok_or("unknown finality block")?;
        require(
            chain.is_selected_ancestor(block)?
                && chain.height() - entry.block.header.height + 1 >= MIN_FINALITY_DEPTH,
            "finality block is not sufficiently buried on selected source branch",
        )?;
        Ok(Self {
            format: FORMAT.into(),
            source_chain_id: chain.chain_id,
            source_v1_tip: chain.v1_tip,
            earth_adoption_id: adoption,
            block,
            height: entry.block.header.height,
            state_root: entry.block.header.state_root,
            cumulative_work: entry.cumulative_work,
            previous_certificate,
        })
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = b"RLD-EARTH-SOURCE-FINALITY\0".to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|error| error.to_string())?);
        Ok(bytes)
    }

    pub fn id(&self) -> Result<Hash> {
        Ok(hash(&self.signing_bytes()?))
    }
}

impl FinalityCertificate {
    pub fn verify(
        &self,
        chain: &CandidateChain,
        adoption: Hash,
        validators: &[String],
    ) -> Result<()> {
        require(
            validators.len() == 4
                && validators.windows(2).all(|pair| pair[0] < pair[1])
                && self.approvals.len() == validators.len(),
            "finality requires four sorted Earth validator keys",
        )?;
        let expected = FinalityStatement::from_chain(
            chain,
            adoption,
            self.statement.block,
            self.statement.previous_certificate,
        )?;
        require(
            self.statement == expected,
            "finality statement differs from replayed source",
        )?;
        let bytes = self.statement.signing_bytes()?;
        for (approval, key) in self.approvals.iter().zip(validators) {
            require(
                &approval.public_key == key,
                "finality signer differs from Earth validator",
            )?;
            verify_bytes(key, &bytes, &approval.signature)?;
        }
        Ok(())
    }
}
