//! Exact, unanimous rule-adoption authorization for a new Earth chain.
//! Verification is independent of the loopback candidate runtime. A signed
//! statement alone never starts a public node or qualifies payment safety.

use crate::{hash, require, transition::TransitionPreview, Result};
use rld_core::{verify_bytes, AdmissionHash32 as Hash};
use rld_pow::{transition::Adoption, transition::Approval, Chain};
use serde::{Deserialize, Serialize};

pub const FORMAT: &str = "RLD-EARTH-SUCCESSOR-ADOPTION";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EarthSuccessorAdoptionStatement {
    pub format: String,
    pub adoption_spec_sha256: Hash,
    pub fresh_manifest_pin: Hash,
    pub fresh_pow_adoption_id: Hash,
    pub fresh_chain_id: Hash,
    pub v1_tip: Hash,
    #[serde(with = "rld_pow::decimal")]
    pub v1_height: u128,
    pub transition_preview_id: Hash,
    pub successor_rules_sha256: Hash,
    pub successor_source_sha256: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EarthSuccessorAdoption {
    pub statement: EarthSuccessorAdoptionStatement,
    pub approvals: Vec<Approval>,
}

impl EarthSuccessorAdoptionStatement {
    pub fn from_replayed_fresh_chain(v1: &Chain, preview: &TransitionPreview) -> Result<Self> {
        let chain_id = v1.context.chain_id()?;
        require(
            v1.context.legacy_height == 0
                && v1.height() == 0
                && v1.state().emitted == rld_core::Amount::ZERO
                && v1.best_blocks()?.is_empty()
                && preview.chain_id == chain_id
                && preview.v1_manifest_pin == v1.context.manifest_pin
                && preview.v1_adoption_id == v1.context.transition_id
                && preview.v1_tip == v1.tip()
                && preview.v1_height == v1.height()
                && preview.personal_allocation == rld_core::Amount::ZERO
                && preview.incompatible_with_v1,
            "Earth must start directly from an empty signed genesis",
        )?;
        Ok(Self {
            format: FORMAT.into(),
            adoption_spec_sha256: hash(include_bytes!(
                "../../../docs/spec/EARTH-VALUE-ADOPTION.md"
            )),
            fresh_manifest_pin: v1.context.manifest_pin,
            fresh_pow_adoption_id: v1.context.transition_id,
            fresh_chain_id: chain_id,
            v1_tip: v1.tip(),
            v1_height: v1.height(),
            transition_preview_id: preview.id()?,
            successor_rules_sha256: preview.successor_spec_sha256,
            successor_source_sha256: preview.successor_source_sha256,
        })
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = b"RLD-EARTH-SUCCESSOR-ADOPTION\0".to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|error| error.to_string())?);
        Ok(bytes)
    }

    pub fn id(&self) -> Result<Hash> {
        Ok(hash(&self.signing_bytes()?))
    }
}

impl EarthSuccessorAdoption {
    pub fn verify(
        &self,
        genesis: &[u8],
        history: &[u8],
        v1_adoption: &Adoption,
        v1: &Chain,
        preview: &TransitionPreview,
        accepted_id: Hash,
    ) -> Result<()> {
        require(
            !accepted_id.is_zero(),
            "missing Earth successor adoption pin",
        )?;
        let adopted = v1_adoption.verify_with_pinned_release_source(
            genesis,
            history,
            preview.v1_manifest_pin,
            preview.v1_adoption_id,
            preview.v1_source_sha256,
        )?;
        require(
            adopted == v1.context,
            "replayed PoW chain differs from signed adoption",
        )?;
        preview.verify_for_candidate(v1, preview.v1_source_sha256, preview.id()?)?;
        let expected = EarthSuccessorAdoptionStatement::from_replayed_fresh_chain(v1, preview)?;
        require(
            self.statement == expected && self.statement.id()? == accepted_id,
            "Earth successor rules, source, cut or local pin differ",
        )?;
        require(
            self.approvals.len() == v1_adoption.approvals.len(),
            "every fresh PoW validator must adopt successor rules",
        )?;
        let bytes = self.statement.signing_bytes()?;
        for (approval, original) in self.approvals.iter().zip(&v1_adoption.approvals) {
            require(
                approval.public_key == original.public_key,
                "successor approvals differ from sorted PoW validators",
            )?;
            verify_bytes(&approval.public_key, &bytes, &approval.signature)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rld_core::sign_bytes;
    use rld_pow::{target_limit, transition};

    fn approvals(bytes: &[u8]) -> Vec<Approval> {
        let mut result = Vec::new();
        for seed in 2..=5 {
            let key = SigningKey::from_bytes(&[seed; 32]);
            result.push(Approval {
                public_key: hex::encode(key.verifying_key().to_bytes()),
                signature: sign_bytes(&hex::encode([seed; 32]), bytes).unwrap(),
            });
        }
        result.sort_by(|a, b| a.public_key.cmp(&b.public_key));
        result
    }

    #[test]
    fn fresh_chain_successor_requires_exact_four_validator_signatures_and_cut() {
        let genesis = include_bytes!("../../../vectors/m0-genesis-v3/manifest.json");
        let manifest = rld_core::M0GenesisManifestFile::decode_json(genesis).unwrap();
        let pin = Hash::from_hex(manifest.manifest_sha256()).unwrap();
        let history = b"[]";
        let draft = transition::draft(genesis, history, pin, target_limit(), 1_000_000).unwrap();
        let v1_adoption = Adoption {
            approvals: approvals(&draft.signing_bytes().unwrap()),
            statement: draft.clone(),
        };
        let context = v1_adoption
            .verify(genesis, history, pin, draft.id().unwrap())
            .unwrap();
        let v1 = Chain::new(context).unwrap();
        let preview =
            TransitionPreview::from_replayed_v1(&v1, draft.implementation_source_sha256).unwrap();
        let statement =
            EarthSuccessorAdoptionStatement::from_replayed_fresh_chain(&v1, &preview).unwrap();
        let valid = EarthSuccessorAdoption {
            approvals: approvals(&statement.signing_bytes().unwrap()),
            statement,
        };
        let accepted = valid.statement.id().unwrap();
        valid
            .verify(genesis, history, &v1_adoption, &v1, &preview, accepted)
            .unwrap();
        let mut missing = valid.clone();
        missing.approvals.pop();
        assert!(missing
            .verify(genesis, history, &v1_adoption, &v1, &preview, accepted)
            .is_err());
        let mut changed = valid.clone();
        changed.statement.v1_height += 1;
        assert!(changed
            .verify(genesis, history, &v1_adoption, &v1, &preview, accepted)
            .is_err());
        assert!(valid
            .verify(genesis, history, &v1_adoption, &v1, &preview, Hash([9; 32]))
            .is_err());
        assert!(valid
            .verify(genesis, b"[ ]", &v1_adoption, &v1, &preview, accepted)
            .is_err());
    }
}
