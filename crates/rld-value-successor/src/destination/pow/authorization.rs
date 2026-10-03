//! Purpose-specific operator consent for one candidate destination genesis.
//! This is not a public source checkpoint or destination-chain adoption.

use super::{implementation_source_hash, Context};
use crate::{hash, require, transition::TransitionPreview, Result};
use rld_core::{verify_bytes, AdmissionHash32 as Hash};
use serde::{Deserialize, Serialize};

pub const FORMAT: &str = "RLD-EARTH-DESTINATION-GENESIS-AUTHORIZATION";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DestinationGenesisAuthorizationStatement {
    pub format: String,
    pub authorization_spec_sha256: Hash,
    pub destination_genesis: Hash,
    pub destination_context_sha256: Hash,
    pub source_transition_preview_id: Hash,
    pub successor_source_sha256: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DestinationGenesisAuthorization {
    pub statement: DestinationGenesisAuthorizationStatement,
    pub signer_public_key: String,
    pub signature: String,
}

impl DestinationGenesisAuthorizationStatement {
    pub fn from_context(context: &Context, preview: &TransitionPreview) -> Result<Self> {
        context.validate()?;
        let source = implementation_source_hash()?;
        require(
            context.source_policy.source_chain_id == preview.chain_id
                && context.source_policy.accepted_v1_tip == preview.v1_tip
                && preview.successor_source_sha256 == source,
            "destination context and source preview differ",
        )?;
        Ok(Self {
            format: FORMAT.into(),
            authorization_spec_sha256: hash(include_bytes!(
                "../../../../../docs/spec/EARTH-DESTINATION-AUTHORIZATION.md"
            )),
            destination_genesis: context.genesis()?,
            destination_context_sha256: hash(
                &serde_json::to_vec(context).map_err(|error| error.to_string())?,
            ),
            source_transition_preview_id: preview.id()?,
            successor_source_sha256: source,
        })
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = b"RLD-EARTH-DESTINATION-GENESIS-AUTHORIZATION\0".to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|error| error.to_string())?);
        Ok(bytes)
    }

    pub fn id(&self) -> Result<Hash> {
        Ok(hash(&self.signing_bytes()?))
    }
}

impl DestinationGenesisAuthorization {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }

    pub fn verify_for_candidate(
        &self,
        context: &Context,
        preview: &TransitionPreview,
        accepted_id: Hash,
        pinned_signer: &str,
    ) -> Result<()> {
        require(
            !accepted_id.is_zero(),
            "missing explicit destination authorization pin",
        )?;
        let expected = DestinationGenesisAuthorizationStatement::from_context(context, preview)?;
        require(
            self.statement == expected && self.statement.id()? == accepted_id,
            "destination authorization statement or local pin differs",
        )?;
        require(
            self.signer_public_key == pinned_signer,
            "destination authorization signer differs from local pin",
        )?;
        verify_bytes(
            pinned_signer,
            &self.statement.signing_bytes()?,
            &self.signature,
        )
    }
}
