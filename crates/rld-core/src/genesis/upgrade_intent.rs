//! Unreleased upgrade-intent encoding. This is not a command or authorization.
//! A compiled migration registry and certified scheduling must validate these
//! commitments before any role may use them to change active capabilities.
use serde::{Deserialize, Serialize};

use super::v3::decimal_u128;
use crate::{hash_bytes, AdmissionContextV1, AdmissionHash32};

pub const UPGRADE_INTENT_VERSION: &str = "RLD-UPGRADE-INTENT-DRAFT-V1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradeIntentDraftV1 {
    pub format_version: String,
    pub network_domain: String,
    pub zone_id: String,
    pub currency_genesis: AdmissionHash32,
    #[serde(with = "decimal_u128")]
    pub protocol_era: u128,
    #[serde(with = "decimal_u128")]
    pub crypto_era: u128,
    #[serde(with = "decimal_u128")]
    pub sequence: u128,
    #[serde(with = "decimal_u128")]
    pub activation_height: u128,
    pub prior_active_commitment: AdmissionHash32,
    pub specification_hash: AdmissionHash32,
    pub implementation_source_commitment: AdmissionHash32,
    pub migration_id: String,
    pub migration_code_hash: AdmissionHash32,
    pub vector_root: AdmissionHash32,
    pub required_capabilities: Vec<String>,
    pub prior_finalized_upgrade: Option<AdmissionHash32>,
    pub immutable_invariant_commitment: AdmissionHash32,
}

impl UpgradeIntentDraftV1 {
    /// Check the first schedule's parent-state dependencies. The caller must
    /// obtain this ledger by authenticated replay. This neither finalizes a
    /// schedule nor validates migration support or enables a signing profile.
    pub(crate) fn check_bootstrap_parent(&self, parent: &crate::Ledger) -> Result<u128, String> {
        self.canonical_bytes()?;
        parent.m0_admission_genesis().map_err(|e| e.to_string())?;
        let birth = parent
            .m0_network_birth_v3
            .as_ref()
            .ok_or("upgrade requires V3 birth")?;
        let active = parent
            .m0_active_protocol
            .as_ref()
            .ok_or("missing active protocol state")?;
        active.validate_for_birth(birth)?;
        let descriptor = &parent.descriptor;
        if self.network_domain != descriptor.network_domain
            || self.zone_id != descriptor.zone_id
            || self.currency_genesis.to_hex() != descriptor.currency_genesis_root
            || self.protocol_era != u128::from(descriptor.protocol_era)
            || self.crypto_era != u128::from(descriptor.crypto_era)
        {
            return Err("upgrade intent context differs from parent".into());
        }
        if self.sequence
            != active
                .upgrade_sequence
                .checked_add(1)
                .ok_or("upgrade sequence exhausted")?
            || self.prior_finalized_upgrade.is_some()
            || self.prior_active_commitment.to_hex() != hash_bytes(&active.canonical_bytes()?)
            || self.immutable_invariant_commitment.to_hex() != hash_bytes(&birth.canonical_bytes()?)
        {
            return Err("upgrade intent differs from current birth or active commitment".into());
        }
        // Delay begins at the schedule block, not its parent. Two full epoch
        // spans must elapse even when scheduling at the end of an epoch.
        let mapping = &birth.admission_genesis.config.contribution_epoch_mapping;
        let schedule_height = u128::from(parent.height)
            .checked_add(1)
            .ok_or("schedule height exhausted")?;
        let delay = mapping
            .ledger_blocks_per_contribution_epoch
            .checked_mul(u128::from(
                birth.upgrade_constitution.minimum_activation_delay_epochs,
            ))
            .ok_or("upgrade delay overflow")?;
        let earliest = schedule_height
            .checked_add(delay)
            .ok_or("activation height overflow")?;
        if self.activation_height < earliest {
            return Err("upgrade activation precedes full constitution delay".into());
        }
        Ok(earliest)
    }

    /// Structural encoding only: hashes supplied by a caller are not evidence
    /// of review, implementation support or committee authorization.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        if self.format_version != UPGRADE_INTENT_VERSION {
            return Err("unsupported upgrade intent version".into());
        }
        AdmissionContextV1 {
            network_domain: self.network_domain.clone(),
            zone_id: self.zone_id.clone(),
            currency_genesis: self.currency_genesis,
            protocol_era: self.protocol_era,
            crypto_era: self.crypto_era,
        }
        .validate()
        .map_err(|e| e.to_string())?;
        if self.sequence == 0 || self.activation_height == 0 {
            return Err("upgrade sequence and activation height must be nonzero".into());
        }
        if (self.sequence == 1) != self.prior_finalized_upgrade.is_none()
            || self.prior_finalized_upgrade.is_some_and(|h| h.is_zero())
        {
            return Err("upgrade predecessor does not match sequence".into());
        }
        let hashes = [
            self.prior_active_commitment,
            self.specification_hash,
            self.implementation_source_commitment,
            self.migration_code_hash,
            self.vector_root,
            self.immutable_invariant_commitment,
        ];
        if hashes.iter().any(|h| h.is_zero()) {
            return Err("upgrade commitments must be nonzero".into());
        }
        fn identifier(s: &str) -> bool {
            !s.is_empty()
                && s.len() <= 64
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        }
        if !identifier(&self.migration_id)
            || self.required_capabilities.is_empty()
            || self.required_capabilities.len() > 32
            || self.required_capabilities.iter().any(|s| !identifier(s))
            || self.required_capabilities.windows(2).any(|w| w[0] >= w[1])
        {
            return Err("invalid migration identifier or noncanonical capability set".into());
        }
        fn text(out: &mut Vec<u8>, s: &str) {
            out.extend_from_slice(&(s.len() as u16).to_be_bytes());
            out.extend_from_slice(s.as_bytes());
        }
        let mut bytes = b"RLD-UPGRADE-INTENT-DRAFT-BYTES-V1\0".to_vec();
        text(&mut bytes, &self.network_domain);
        text(&mut bytes, &self.zone_id);
        bytes.extend_from_slice(&self.currency_genesis.0);
        for n in [
            self.protocol_era,
            self.crypto_era,
            self.sequence,
            self.activation_height,
        ] {
            bytes.extend_from_slice(&n.to_be_bytes());
        }
        for h in &hashes[..3] {
            bytes.extend_from_slice(&h.0);
        }
        text(&mut bytes, &self.migration_id);
        bytes.extend_from_slice(&self.migration_code_hash.0);
        bytes.extend_from_slice(&self.vector_root.0);
        bytes.extend_from_slice(&(self.required_capabilities.len() as u16).to_be_bytes());
        for c in &self.required_capabilities {
            text(&mut bytes, c);
        }
        match self.prior_finalized_upgrade {
            None => bytes.push(0),
            Some(h) => {
                bytes.push(1);
                bytes.extend_from_slice(&h.0);
            }
        }
        bytes.extend_from_slice(&self.immutable_invariant_commitment.0);
        Ok(bytes)
    }

    pub fn intent_id(&self) -> Result<String, String> {
        Ok(hash_bytes(&self.canonical_bytes()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upgrade_intent_matches_independent_python_vectors() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../vectors/upgrade-intent-draft-v1/vectors.json"
        ))
        .unwrap();
        for case in vectors["positive"].as_array().unwrap() {
            let intent: UpgradeIntentDraftV1 =
                serde_json::from_value(case["intent"].clone()).unwrap();
            assert_eq!(
                hex::encode(intent.canonical_bytes().unwrap()),
                case["canonical_hex"]
            );
            assert_eq!(intent.intent_id().unwrap(), case["intent_id"]);
        }
        for case in vectors["negative"].as_array().unwrap() {
            let rejected = serde_json::from_value::<UpgradeIntentDraftV1>(case["intent"].clone())
                .map(|intent| intent.canonical_bytes().is_err())
                .unwrap_or(true);
            assert!(rejected, "accepted negative vector: {}", case["name"]);
        }
    }
    fn intent() -> UpgradeIntentDraftV1 {
        UpgradeIntentDraftV1 {
            format_version: UPGRADE_INTENT_VERSION.into(),
            network_domain: "test:upgrade".into(),
            zone_id: "earth".into(),
            currency_genesis: AdmissionHash32([1; 32]),
            protocol_era: 0,
            crypto_era: 0,
            sequence: 1,
            activation_height: 128,
            prior_active_commitment: AdmissionHash32([2; 32]),
            specification_hash: AdmissionHash32([3; 32]),
            implementation_source_commitment: AdmissionHash32([4; 32]),
            migration_id: "test-only".into(),
            migration_code_hash: AdmissionHash32([5; 32]),
            vector_root: AdmissionHash32([6; 32]),
            required_capabilities: vec!["A".into(), "B".into()],
            prior_finalized_upgrade: None,
            immutable_invariant_commitment: AdmissionHash32([7; 32]),
        }
    }
    #[test]
    fn upgrade_schedule_parent_checks_birth_context_and_full_delay() {
        let manifest: crate::SignedM0GenesisManifestV3 = serde_json::from_str(include_str!(
            "../../../../vectors/m0-genesis-v3/manifest.json"
        ))
        .unwrap();
        let parent = manifest.reconstruct_genesis().unwrap();
        let birth = parent.m0_network_birth_v3.as_ref().unwrap();
        let active = parent.m0_active_protocol.as_ref().unwrap();
        let mut i = intent();
        i.network_domain = parent.descriptor.network_domain.clone();
        i.zone_id = parent.descriptor.zone_id.clone();
        i.currency_genesis =
            AdmissionHash32::from_hex(&parent.descriptor.currency_genesis_root).unwrap();
        i.protocol_era = u128::from(parent.descriptor.protocol_era);
        i.crypto_era = u128::from(parent.descriptor.crypto_era);
        i.prior_active_commitment =
            AdmissionHash32::from_hex(&hash_bytes(&active.canonical_bytes().unwrap())).unwrap();
        i.immutable_invariant_commitment =
            AdmissionHash32::from_hex(&hash_bytes(&birth.canonical_bytes().unwrap())).unwrap();
        let span = birth
            .admission_genesis
            .config
            .contribution_epoch_mapping
            .ledger_blocks_per_contribution_epoch;
        let earliest = u128::from(parent.height) + 1 + 2 * span;
        i.activation_height = earliest;
        let before = serde_json::to_vec(&parent).unwrap();
        assert_eq!(i.check_bootstrap_parent(&parent).unwrap(), earliest);
        let mut early = i.clone();
        early.activation_height -= 1;
        assert!(early.check_bootstrap_parent(&parent).is_err());
        for key in [
            "network_domain",
            "zone_id",
            "currency_genesis",
            "protocol_era",
            "crypto_era",
            "prior_active_commitment",
            "immutable_invariant_commitment",
        ] {
            let mut v = serde_json::to_value(&i).unwrap();
            v[key] = if key.ends_with("commitment") || key == "currency_genesis" {
                serde_json::json!("09".repeat(32))
            } else if key.ends_with("era") {
                serde_json::json!("99")
            } else {
                serde_json::json!("wrong")
            };
            let wrong: UpgradeIntentDraftV1 = serde_json::from_value(v).unwrap();
            assert!(wrong.check_bootstrap_parent(&parent).is_err(), "{key}");
        }
        let mut wrong = i.clone();
        wrong.sequence = 2;
        wrong.prior_finalized_upgrade = Some(AdmissionHash32([8; 32]));
        assert!(wrong.check_bootstrap_parent(&parent).is_err());
        let mut forged_parent = parent.clone();
        forged_parent
            .m0_active_protocol
            .as_mut()
            .unwrap()
            .upgrade_sequence = 1;
        assert!(i.check_bootstrap_parent(&forged_parent).is_err());
        // Arithmetic at the current U64 ledger frontier must not wrap. This
        // synthetic height is only an arithmetic test, not certified history.
        let mut frontier = parent.clone();
        frontier.height = u64::MAX;
        i.activation_height = u128::from(u64::MAX) + 1 + 2 * span;
        assert_eq!(
            i.check_bootstrap_parent(&frontier).unwrap(),
            i.activation_height
        );
        assert_eq!(serde_json::to_vec(&parent).unwrap(), before);
    }
    #[test]
    fn upgrade_intent_u128_and_canonical_json() {
        let mut i = intent();
        i.activation_height = u128::MAX;
        i.protocol_era = u128::MAX;
        let v = serde_json::to_value(&i).unwrap();
        assert_eq!(v["activation_height"], u128::MAX.to_string());
        assert_eq!(
            serde_json::from_value::<UpgradeIntentDraftV1>(v.clone()).unwrap(),
            i
        );
        for bad in [
            serde_json::json!(1),
            serde_json::json!("01"),
            serde_json::json!("+1"),
            serde_json::json!("340282366920938463463374607431768211456"),
        ] {
            let mut v = v.clone();
            v["sequence"] = bad;
            assert!(serde_json::from_value::<UpgradeIntentDraftV1>(v).is_err());
        }
        let mut v = v;
        v["authorized"] = serde_json::json!(true);
        assert!(serde_json::from_value::<UpgradeIntentDraftV1>(v).is_err());
    }
    #[test]
    fn upgrade_intent_rejects_ambiguous_sets_and_missing_commitments() {
        for caps in [
            vec![],
            vec!["B", "A"],
            vec!["A", "A"],
            vec!["A B"],
            vec!["A"; 33],
        ] {
            let mut i = intent();
            i.required_capabilities = caps.into_iter().map(String::from).collect();
            assert!(i.canonical_bytes().is_err());
        }
        let mut i = intent();
        i.migration_code_hash = AdmissionHash32([0; 32]);
        assert!(i.intent_id().is_err());
        let mut i = intent();
        i.sequence = 2;
        assert!(i.intent_id().is_err());
        i.prior_finalized_upgrade = Some(AdmissionHash32([8; 32]));
        assert!(i.intent_id().is_ok());
        i.sequence = 1;
        assert!(i.intent_id().is_err());
    }
    #[test]
    fn upgrade_intent_commits_every_field() {
        let i = intent();
        let id = i.intent_id().unwrap();
        let v = serde_json::to_value(&i).unwrap();
        for key in [
            "network_domain",
            "zone_id",
            "currency_genesis",
            "protocol_era",
            "crypto_era",
            "activation_height",
            "prior_active_commitment",
            "specification_hash",
            "implementation_source_commitment",
            "migration_id",
            "migration_code_hash",
            "vector_root",
            "immutable_invariant_commitment",
        ] {
            let mut v = v.clone();
            v[key] = if key.ends_with("hash")
                || key.ends_with("commitment")
                || key == "currency_genesis"
                || key == "vector_root"
            {
                serde_json::json!("09".repeat(32))
            } else if key.ends_with("era") || key == "activation_height" {
                serde_json::json!("129")
            } else {
                serde_json::json!("changed")
            };
            let changed: UpgradeIntentDraftV1 = serde_json::from_value(v).unwrap();
            assert_ne!(id, changed.intent_id().unwrap(), "{key}");
        }
        let mut changed = i.clone();
        changed.required_capabilities.push("C".into());
        assert_ne!(id, changed.intent_id().unwrap());
        let mut changed = i;
        changed.sequence = 2;
        changed.prior_finalized_upgrade = Some(AdmissionHash32([8; 32]));
        assert_ne!(id, changed.intent_id().unwrap());
    }
}
