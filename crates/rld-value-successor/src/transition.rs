//! Reviewable, unsigned preview of one exact v1-to-successor handoff.
//!
//! A matching ID is explicit local candidate consent, not network governance
//! or permission to replace the deployed v1 rules.

use crate::{chain::CandidateChain, hash, require, Result};
use rld_core::{verify_bytes, AdmissionHash32 as Hash, AdmissionWork as Work, Amount};
use rld_pow::Chain;
use serde::{Deserialize, Serialize};

pub const FORMAT: &str = "RLD-EARTH-SUCCESSOR-TRANSITION-PREVIEW";
pub const AUTHORIZATION_FORMAT: &str = "RLD-EARTH-SUCCESSOR-TRANSITION-AUTHORIZATION";

/// A purpose-specific signed statement about one exact, independently pinned
/// preview. Signer provenance does not itself grant public consensus authority.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransitionAuthorizationStatement {
    pub format: String,
    pub authorization_spec_sha256: Hash,
    pub preview_id: Hash,
    pub v1_tip: Hash,
    pub successor_spec_sha256: Hash,
    pub successor_source_sha256: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransitionAuthorization {
    pub statement: TransitionAuthorizationStatement,
    pub signer_public_key: String,
    pub signature: String,
}

impl TransitionAuthorizationStatement {
    pub fn from_preview(preview: &TransitionPreview) -> Result<Self> {
        Ok(Self {
            format: AUTHORIZATION_FORMAT.into(),
            authorization_spec_sha256: hash(include_bytes!(
                "../../../docs/spec/EARTH-TRANSITION-AUTHORIZATION.md"
            )),
            preview_id: preview.id()?,
            v1_tip: preview.v1_tip,
            successor_spec_sha256: preview.successor_spec_sha256,
            successor_source_sha256: preview.successor_source_sha256,
        })
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = b"RLD-EARTH-SUCCESSOR-TRANSITION-AUTHORIZATION\0".to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|error| error.to_string())?);
        Ok(bytes)
    }

    pub fn id(&self) -> Result<Hash> {
        Ok(hash(&self.signing_bytes()?))
    }
}

impl TransitionAuthorization {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }

    pub fn verify_for_candidate(
        &self,
        preview: &TransitionPreview,
        accepted_id: Hash,
        pinned_signer: &str,
    ) -> Result<()> {
        require(
            !accepted_id.is_zero(),
            "missing explicit transition authorization pin",
        )?;
        let expected = TransitionAuthorizationStatement::from_preview(preview)?;
        require(
            self.statement == expected && self.statement.id()? == accepted_id,
            "transition authorization statement or local pin differs",
        )?;
        require(
            self.signer_public_key == pinned_signer,
            "transition authorization signer differs from local pin",
        )?;
        verify_bytes(
            pinned_signer,
            &self.statement.signing_bytes()?,
            &self.signature,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransitionPreview {
    pub format: String,
    pub network_domain: String,
    pub zone_id: String,
    pub currency_genesis: Hash,
    pub v1_manifest_pin: Hash,
    pub v1_adoption_id: Hash,
    pub v1_source_sha256: Hash,
    pub chain_id: Hash,
    pub v1_tip: Hash,
    #[serde(with = "rld_pow::decimal")]
    pub v1_height: u128,
    pub v1_state_root: Hash,
    pub v1_chainwork: Work,
    pub v1_emitted: Amount,
    pub successor_base_root: Hash,
    pub successor_spec_sha256: Hash,
    pub successor_source_sha256: Hash,
    #[serde(with = "rld_pow::decimal")]
    pub first_successor_height: u128,
    pub personal_allocation: Amount,
    pub incompatible_with_v1: bool,
}

impl TransitionPreview {
    pub fn from_replayed_v1(v1: &Chain, adopted_v1_source: Hash) -> Result<Self> {
        require(!adopted_v1_source.is_zero(), "missing adopted v1 source")?;
        let anchor = v1.replay_anchor()?;
        let candidate = CandidateChain::from_replayed_pow_chain(v1)?;
        let base = candidate.anchor_commitment()?;
        require(
            base.v1_root == anchor.state_root()
                && base.v1_tip == anchor.tip()
                && base.emitted == v1.state().emitted
                && base.liquid == base.emitted
                && base.locked == Amount::ZERO
                && base.retired == Amount::ZERO,
            "v1 value handoff is not exact",
        )?;
        let source =
            Hash::from_hex(rld_core::implementation_source::IMPLEMENTATION_SOURCE_COMMITMENT)
                .map_err(|error| error.to_string())?;
        require(!source.is_zero(), "missing candidate source commitment")?;
        Ok(Self {
            format: FORMAT.into(),
            network_domain: v1.context.network_domain.clone(),
            zone_id: v1.context.zone_id.clone(),
            currency_genesis: v1.context.currency_genesis,
            v1_manifest_pin: v1.context.manifest_pin,
            v1_adoption_id: v1.context.transition_id,
            v1_source_sha256: adopted_v1_source,
            chain_id: anchor.chain_id(),
            v1_tip: anchor.tip(),
            v1_height: anchor.height(),
            v1_state_root: anchor.state_root(),
            v1_chainwork: v1.chainwork(),
            v1_emitted: base.emitted,
            successor_base_root: base.root()?,
            successor_spec_sha256: hash(include_bytes!("../../../docs/spec/EARTH-VALUE-RULES.md")),
            successor_source_sha256: source,
            first_successor_height: anchor
                .height()
                .checked_add(1)
                .ok_or("successor activation height overflow")?,
            personal_allocation: Amount::ZERO,
            incompatible_with_v1: true,
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }

    pub fn id(&self) -> Result<Hash> {
        let mut bytes = b"RLD-EARTH-SUCCESSOR-TRANSITION-PREVIEW\0".to_vec();
        bytes.extend(self.canonical_bytes()?);
        Ok(hash(&bytes))
    }

    pub fn verify_for_candidate(
        &self,
        v1: &Chain,
        adopted_v1_source: Hash,
        accepted_id: Hash,
    ) -> Result<()> {
        require(
            !accepted_id.is_zero(),
            "missing explicit preview acceptance",
        )?;
        let expected = Self::from_replayed_v1(v1, adopted_v1_source)?;
        require(
            self == &expected && self.id()? == accepted_id,
            "transition preview, source, rules or v1 anchor differs",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rld_core::{generate_identity, sign_bytes};
    use rld_pow::{mine_batch, target_limit, Context, BLOCK_SECONDS};

    #[test]
    fn preview_pins_replayed_value_rules_source_and_exact_cut() {
        let owner = generate_identity();
        let mut v1 = Chain::new(Context {
            network_domain: "fixture:transition-preview".into(),
            zone_id: "fixture-earth".into(),
            currency_genesis: Hash([1; 32]),
            manifest_pin: Hash([2; 32]),
            transition_id: Hash([3; 32]),
            legacy_height: 0,
            legacy_state_root: Hash([4; 32]),
            started_at: 1_000_000,
            initial_target: target_limit(),
        })
        .unwrap();
        let timestamp = 1_000_000 + BLOCK_SECONDS;
        let mut first = v1
            .template(owner.public_key.clone(), timestamp, vec![])
            .unwrap();
        while !mine_batch(&mut first, 100_000).unwrap() {}
        v1.accept(first, timestamp).unwrap();
        let adopted_source = Hash([9; 32]);
        let preview = TransitionPreview::from_replayed_v1(&v1, adopted_source).unwrap();
        let id = preview.id().unwrap();
        assert_eq!(preview.v1_state_root, v1.state().root().unwrap());
        assert_eq!(preview.v1_emitted, v1.state().emitted);
        assert_eq!(preview.first_successor_height, v1.height() + 1);
        preview
            .verify_for_candidate(&v1, adopted_source, id)
            .unwrap();
        assert!(preview
            .verify_for_candidate(&v1, Hash([8; 32]), id)
            .is_err());
        assert!(preview
            .verify_for_candidate(&v1, adopted_source, Hash([7; 32]))
            .is_err());
        let mut forged = preview.clone();
        forged.v1_emitted = Amount::ZERO;
        assert!(forged
            .verify_for_candidate(&v1, adopted_source, forged.id().unwrap())
            .is_err());
        let mut forged = preview.clone();
        forged.successor_spec_sha256 = Hash([6; 32]);
        assert!(forged
            .verify_for_candidate(&v1, adopted_source, forged.id().unwrap())
            .is_err());
        let next_time = timestamp + BLOCK_SECONDS;
        let mut next = v1.template(owner.public_key, next_time, vec![]).unwrap();
        while !mine_batch(&mut next, 100_000).unwrap() {}
        v1.accept(next, next_time).unwrap();
        assert!(preview
            .verify_for_candidate(&v1, adopted_source, id)
            .is_err());
    }

    #[test]
    fn signed_authorization_binds_exact_preview_and_explicit_signer() {
        let owner = generate_identity();
        let signer = generate_identity();
        let other = generate_identity();
        let mut v1 = Chain::new(Context {
            network_domain: "fixture:signed-transition".into(),
            zone_id: "fixture-earth".into(),
            currency_genesis: Hash([1; 32]),
            manifest_pin: Hash([2; 32]),
            transition_id: Hash([3; 32]),
            legacy_height: 0,
            legacy_state_root: Hash([4; 32]),
            started_at: 1_000_000,
            initial_target: target_limit(),
        })
        .unwrap();
        let timestamp = 1_000_000 + BLOCK_SECONDS;
        let mut block = v1.template(owner.public_key, timestamp, vec![]).unwrap();
        while !mine_batch(&mut block, 100_000).unwrap() {}
        v1.accept(block, timestamp).unwrap();
        let preview = TransitionPreview::from_replayed_v1(&v1, Hash([9; 32])).unwrap();
        let statement = TransitionAuthorizationStatement::from_preview(&preview).unwrap();
        let id = statement.id().unwrap();
        let signed = TransitionAuthorization {
            signature: sign_bytes(&signer.secret_key, &statement.signing_bytes().unwrap()).unwrap(),
            signer_public_key: signer.public_key.clone(),
            statement,
        };
        let encoded = signed.canonical_bytes().unwrap();
        let decoded: TransitionAuthorization = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, signed);
        signed
            .verify_for_candidate(&preview, id, &signer.public_key)
            .unwrap();
        assert!(signed
            .verify_for_candidate(&preview, Hash([8; 32]), &signer.public_key)
            .is_err());
        assert!(signed
            .verify_for_candidate(&preview, id, &other.public_key)
            .is_err());
        let mut changed_preview = preview.clone();
        changed_preview.v1_tip = Hash([7; 32]);
        assert!(signed
            .verify_for_candidate(&changed_preview, id, &signer.public_key)
            .is_err());
        let mut changed_source = preview.clone();
        changed_source.successor_source_sha256 = Hash([6; 32]);
        assert!(signed
            .verify_for_candidate(&changed_source, id, &signer.public_key)
            .is_err());
        let mut bad_signature = signed.clone();
        bad_signature.signature = "00".into();
        assert!(bad_signature
            .verify_for_candidate(&preview, id, &signer.public_key)
            .is_err());
        let mut changed_statement = signed.clone();
        changed_statement.statement.successor_spec_sha256 = Hash([5; 32]);
        assert!(changed_statement
            .verify_for_candidate(
                &preview,
                changed_statement.statement.id().unwrap(),
                &signer.public_key
            )
            .is_err());
    }
}
