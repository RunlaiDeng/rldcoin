use serde::{Deserialize, Serialize};

pub mod upgrade_activation;
mod upgrade_compatibility;
pub mod upgrade_intent;
pub mod upgrade_migration;
pub mod upgrade_pending;
pub mod upgrade_wire;
mod v3;
pub use v3::*;

use crate::{
    hash_bytes, sign_bytes, validate_ed25519_public_key, verify_bytes, AdmissionGenesisV1,
    AdmissionHash32, AdmissionLogConfigV1, Amount, Identity, Ledger, ValueCap, ZoneDescriptor,
    RLDCOIN_MAINNET_DOMAIN, RUNLAI_PER_RLD, TOTAL_SUPPLY_RUNLAI,
};

pub const M0_GENESIS_MANIFEST_VERSION: &str = "RLD-M0-GENESIS-MANIFEST-V2";
pub const M0_NETWORK_PHASE: &str = "M0_NETWORK_BIRTH";
pub const M0_CONTROL_MODEL: &str = "FOUNDER_BOOTSTRAPPED_SINGLE_CONTROL";
pub const M0_LEDGER_BINDING_VERSION: &str = "RLD-M0-NETWORK-BIRTH-STATE-V2";
pub const M0_ALLOWED_CONSENSUS_PROFILE: &str = "NETWORK_HEARTBEAT_ONLY_V1";
const M0_GENESIS_SIGNING_DOMAIN: &[u8] = b"RLD-M0-GENESIS-MANIFEST-SIGNATURE-V2\0";

/// Consensus-rooted M0 safety binding. This deliberately excludes the final
/// manifest hash because that hash commits to the genesis state root; including
/// it here would create a circular commitment. Every field is instead derived
/// from, and covered by, the founder-signed declaration.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct M0NetworkBirthStateV2 {
    pub format_version: String,
    pub network_phase: String,
    pub control_model: String,
    pub founder_public_key: String,
    pub founder_bootstrapped: bool,
    pub single_control_declared: bool,
    pub control_group_count: u64,
    pub control_group_id: String,
    pub value_cap: ValueCap,
    pub transferable_value_enabled: bool,
    pub testnet_state_import_allowed: bool,
    pub testnet_key_import_allowed: bool,
    pub allowed_consensus_profile: String,
    pub admission_genesis: AdmissionGenesisV1,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct M0GenesisDeclaration {
    pub format_version: String,
    pub network_phase: String,
    pub descriptor: ZoneDescriptor,
    pub genesis_state_root: String,
    pub fixed_total_supply_runlai: String,
    pub runlai_per_rld: String,
    pub value_cap: ValueCap,
    pub transferable_value_enabled: bool,
    pub founder_bootstrapped: bool,
    pub single_control_declared: bool,
    pub control_group_count: u64,
    pub control_group_id: String,
    pub testnet_state_import_allowed: bool,
    pub testnet_key_import_allowed: bool,
    pub founder_public_key: String,
    pub admission_genesis: AdmissionGenesisV1,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedM0GenesisManifest {
    pub declaration: M0GenesisDeclaration,
    pub manifest_sha256: String,
    pub founder_signature: String,
}

impl SignedM0GenesisManifest {
    pub fn create(
        display_name: impl Into<String>,
        validator_keys: Vec<String>,
        notary_keys: Vec<String>,
        control_group_id: impl Into<String>,
        admission_config: AdmissionLogConfigV1,
        admission_benchmark_report_sha256: AdmissionHash32,
        founder: &Identity,
    ) -> Result<Self, String> {
        let control_group_id = control_group_id.into();
        let mut ledger = Ledger::genesis_zone(display_name, validator_keys, notary_keys, false)
            .map_err(|error| error.to_string())?;
        let admission_genesis = AdmissionGenesisV1::for_descriptor(
            &ledger.descriptor,
            admission_config,
            admission_benchmark_report_sha256,
        )
        .map_err(|error| error.to_string())?;
        let network_birth = M0NetworkBirthStateV2::new(
            founder.public_key.clone(),
            control_group_id.clone(),
            admission_genesis.clone(),
        );
        ledger
            .bind_m0_network_birth(network_birth)
            .map_err(|error| error.to_string())?;
        let declaration = M0GenesisDeclaration {
            format_version: M0_GENESIS_MANIFEST_VERSION.into(),
            network_phase: M0_NETWORK_PHASE.into(),
            descriptor: ledger.descriptor.clone(),
            genesis_state_root: ledger.state_root().map_err(|error| error.to_string())?,
            fixed_total_supply_runlai: TOTAL_SUPPLY_RUNLAI.to_string(),
            runlai_per_rld: RUNLAI_PER_RLD.to_string(),
            value_cap: ValueCap::ValueCap0,
            transferable_value_enabled: false,
            founder_bootstrapped: true,
            single_control_declared: true,
            control_group_count: 1,
            control_group_id,
            testnet_state_import_allowed: false,
            testnet_key_import_allowed: false,
            founder_public_key: founder.public_key.clone(),
            admission_genesis,
        };
        let signing_bytes = declaration.signing_bytes()?;
        let manifest_sha256 = hash_bytes(&signing_bytes);
        let founder_signature = sign_bytes(&founder.secret_key, &signing_bytes)?;
        let manifest = Self {
            declaration,
            manifest_sha256,
            founder_signature,
        };
        manifest.verify()?;
        Ok(manifest)
    }

    pub fn verify(&self) -> Result<(), String> {
        self.declaration.validate()?;
        let signing_bytes = self.declaration.signing_bytes()?;
        if self.manifest_sha256 != hash_bytes(&signing_bytes) {
            return Err("M0 genesis manifest content hash mismatch".into());
        }
        verify_bytes(
            &self.declaration.founder_public_key,
            &signing_bytes,
            &self.founder_signature,
        )
        .map_err(|error| format!("M0 genesis founder signature is invalid: {error}"))?;

        let mut regenerated = Ledger::genesis_zone(
            &self.declaration.descriptor.display_name,
            self.declaration.descriptor.genesis_validator_keys.clone(),
            self.declaration.descriptor.genesis_notary_keys.clone(),
            false,
        )
        .map_err(|error| error.to_string())?;
        regenerated
            .bind_m0_network_birth(self.declaration.network_birth_state())
            .map_err(|error| error.to_string())?;
        if regenerated.descriptor != self.declaration.descriptor {
            return Err(
                "M0 genesis descriptor is not reproducible from its declared inputs".into(),
            );
        }
        let regenerated_root = regenerated
            .state_root()
            .map_err(|error| error.to_string())?;
        if regenerated_root != self.declaration.genesis_state_root {
            return Err("M0 genesis state root is not reproducible".into());
        }
        Ok(())
    }

    pub fn validate_ledger_identity(&self, ledger: &Ledger) -> Result<(), String> {
        self.verify()?;
        if ledger.m0_network_birth_v3.is_some() || ledger.m0_active_protocol.is_some() {
            return Err("V2 manifest cannot authorize a V3 or mixed birth state".into());
        }
        if ledger.descriptor != self.declaration.descriptor {
            return Err(
                "persisted ledger identity does not match the signed M0 genesis manifest".into(),
            );
        }
        if ledger.anchor_supply != Amount::TOTAL_SUPPLY {
            return Err("persisted ledger anchor supply does not match fixed M0 supply".into());
        }
        if ledger.m0_network_birth.as_ref() != Some(&self.declaration.network_birth_state()) {
            return Err(
                "persisted ledger has no exact consensus-rooted M0 network-birth binding".into(),
            );
        }
        let admission_state = ledger.admission_state.as_ref().ok_or_else(|| {
            "persisted M0 ledger has no consensus-rooted admission state".to_string()
        })?;
        admission_state
            .validate_for_descriptor(&ledger.descriptor)
            .map_err(|error| format!("persisted admission state is invalid: {error}"))?;
        if admission_state.genesis != self.declaration.admission_genesis {
            return Err(
                "persisted admission genesis differs from the founder-signed declaration".into(),
            );
        }
        if ledger.value_risk_policy.current_cap != ValueCap::ValueCap0
            || ledger.value_risk_policy.ever_enabled
            || ledger.value_risk_policy.pending_update.is_some()
        {
            return Err("M0 ledger must remain fail-closed at VALUE_CAP_0".into());
        }
        Ok(())
    }
}

impl M0GenesisDeclaration {
    pub fn network_birth_state(&self) -> M0NetworkBirthStateV2 {
        M0NetworkBirthStateV2::new(
            self.founder_public_key.clone(),
            self.control_group_id.clone(),
            self.admission_genesis.clone(),
        )
    }

    fn validate(&self) -> Result<(), String> {
        if self.format_version != M0_GENESIS_MANIFEST_VERSION
            || self.network_phase != M0_NETWORK_PHASE
        {
            return Err("unsupported M0 genesis manifest version or network phase".into());
        }
        self.descriptor.validate_identity()?;
        self.network_birth_state()
            .validate_for_descriptor(&self.descriptor)?;
        self.admission_genesis
            .validate_for_descriptor(&self.descriptor)
            .map_err(|error| error.to_string())?;
        if self.descriptor.testnet
            || self.descriptor.network_domain != RLDCOIN_MAINNET_DOMAIN
            || self.descriptor.anchor_supply != Amount::TOTAL_SUPPLY
            || self.descriptor.protocol_era != 1
            || self.descriptor.crypto_era != 1
        {
            return Err(
                "M0 genesis descriptor is not an era-1 fixed-supply mainnet identity".into(),
            );
        }
        if self.descriptor.validator_keys.len() != 4 {
            return Err("M0 fixed BFT requires exactly four genesis validators".into());
        }
        if self.fixed_total_supply_runlai != TOTAL_SUPPLY_RUNLAI.to_string()
            || self.runlai_per_rld != RUNLAI_PER_RLD.to_string()
            || self.value_cap != ValueCap::ValueCap0
            || self.transferable_value_enabled
        {
            return Err(
                "M0 monetary declaration must use the fixed supply with value disabled".into(),
            );
        }
        if !self.founder_bootstrapped
            || !self.single_control_declared
            || self.control_group_count != 1
            || self.control_group_id.trim().is_empty()
        {
            return Err("M0 genesis must explicitly disclose one founder control group".into());
        }
        if self.testnet_state_import_allowed || self.testnet_key_import_allowed {
            return Err("M0 genesis must forbid testnet state and key imports".into());
        }
        validate_ed25519_public_key(&self.founder_public_key)?;
        let mut all_keys = self.descriptor.genesis_validator_keys.clone();
        all_keys.extend(self.descriptor.genesis_notary_keys.clone());
        all_keys.push(self.founder_public_key.clone());
        for key in &all_keys {
            validate_ed25519_public_key(key)?;
        }
        all_keys.sort_unstable();
        if all_keys.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err("founder, validator and notary identities must be distinct".into());
        }
        if !is_sha256_hex(&self.genesis_state_root) {
            return Err("M0 genesis state root must be lowercase SHA-256 hex".into());
        }
        Ok(())
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        let mut out = M0_GENESIS_SIGNING_DOMAIN.to_vec();
        append_string(&mut out, &self.format_version)?;
        append_string(&mut out, &self.network_phase)?;
        append_descriptor(&mut out, &self.descriptor)?;
        append_string(&mut out, &self.genesis_state_root)?;
        append_string(&mut out, &self.fixed_total_supply_runlai)?;
        append_string(&mut out, &self.runlai_per_rld)?;
        out.push(self.value_cap.code());
        out.push(u8::from(self.transferable_value_enabled));
        out.push(u8::from(self.founder_bootstrapped));
        out.push(u8::from(self.single_control_declared));
        out.extend_from_slice(&self.control_group_count.to_be_bytes());
        append_string(&mut out, &self.control_group_id)?;
        out.push(u8::from(self.testnet_state_import_allowed));
        out.push(u8::from(self.testnet_key_import_allowed));
        append_string(&mut out, &self.founder_public_key)?;
        append_admission_genesis(&mut out, &self.admission_genesis)?;
        Ok(out)
    }
}

impl M0NetworkBirthStateV2 {
    pub fn new(
        founder_public_key: String,
        control_group_id: String,
        admission_genesis: AdmissionGenesisV1,
    ) -> Self {
        Self {
            format_version: M0_LEDGER_BINDING_VERSION.into(),
            network_phase: M0_NETWORK_PHASE.into(),
            control_model: M0_CONTROL_MODEL.into(),
            founder_public_key,
            founder_bootstrapped: true,
            single_control_declared: true,
            control_group_count: 1,
            control_group_id,
            value_cap: ValueCap::ValueCap0,
            transferable_value_enabled: false,
            testnet_state_import_allowed: false,
            testnet_key_import_allowed: false,
            allowed_consensus_profile: M0_ALLOWED_CONSENSUS_PROFILE.into(),
            admission_genesis,
        }
    }

    pub fn validate_for_descriptor(&self, descriptor: &ZoneDescriptor) -> Result<(), String> {
        if self.format_version != M0_LEDGER_BINDING_VERSION
            || self.network_phase != M0_NETWORK_PHASE
            || self.control_model != M0_CONTROL_MODEL
            || !self.founder_bootstrapped
            || !self.single_control_declared
            || self.control_group_count != 1
            || self.control_group_id.trim().is_empty()
            || self.control_group_id.len() > 128
            || !self.control_group_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
            || self.value_cap != ValueCap::ValueCap0
            || self.transferable_value_enabled
            || self.testnet_state_import_allowed
            || self.testnet_key_import_allowed
            || self.allowed_consensus_profile != M0_ALLOWED_CONSENSUS_PROFILE
        {
            return Err("invalid M0 network-birth ledger binding".into());
        }
        if descriptor.testnet
            || descriptor.network_domain != RLDCOIN_MAINNET_DOMAIN
            || descriptor.anchor_supply != Amount::TOTAL_SUPPLY
            || descriptor.protocol_era != 1
            || descriptor.crypto_era != 1
            || descriptor.genesis_validator_keys.len() != 4
        {
            return Err("M0 network-birth binding requires a fixed-supply mainnet Zone".into());
        }
        validate_ed25519_public_key(&self.founder_public_key)?;
        self.admission_genesis
            .validate_for_descriptor(descriptor)
            .map_err(|error| error.to_string())?;
        if descriptor
            .genesis_validator_keys
            .iter()
            .chain(&descriptor.genesis_notary_keys)
            .any(|key| key == &self.founder_public_key)
        {
            return Err(
                "M0 founder identity must be distinct from validator and notary keys".into(),
            );
        }
        Ok(())
    }
}

fn append_admission_genesis(
    out: &mut Vec<u8>,
    admission: &AdmissionGenesisV1,
) -> Result<(), String> {
    admission.validate().map_err(|error| error.to_string())?;
    append_string(out, &admission.context.network_domain)?;
    append_string(out, &admission.context.zone_id)?;
    out.extend_from_slice(&admission.context.currency_genesis.0);
    out.extend_from_slice(&admission.context.protocol_era.to_be_bytes());
    out.extend_from_slice(&admission.context.crypto_era.to_be_bytes());
    out.extend_from_slice(&admission.config.minimum_target.to_be_bytes());
    out.extend_from_slice(&admission.config.maximum_target.to_be_bytes());
    out.extend_from_slice(&admission.config.genesis_target.to_be_bytes());
    out.extend_from_slice(&admission.config.confirmation_work_floor.to_be_bytes());
    out.extend_from_slice(
        &admission
            .config
            .contribution_epoch_mapping
            .ledger_height_origin
            .to_be_bytes(),
    );
    out.extend_from_slice(
        &admission
            .config
            .contribution_epoch_mapping
            .contribution_epoch_origin
            .to_be_bytes(),
    );
    out.extend_from_slice(
        &admission
            .config
            .contribution_epoch_mapping
            .ledger_blocks_per_contribution_epoch
            .to_be_bytes(),
    );
    out.extend_from_slice(&admission.benchmark_report_sha256.0);
    out.extend_from_slice(&admission.genesis_header.0);
    Ok(())
}

fn append_descriptor(out: &mut Vec<u8>, descriptor: &ZoneDescriptor) -> Result<(), String> {
    append_string(out, &descriptor.zone_id)?;
    append_string(out, &descriptor.display_name)?;
    append_string(out, &descriptor.genesis_root)?;
    out.extend_from_slice(&descriptor.identity_version.to_be_bytes());
    append_string(out, &descriptor.identity_hash_suite)?;
    append_string(out, &descriptor.network_domain)?;
    out.extend_from_slice(&descriptor.anchor_supply.0.to_be_bytes());
    append_strings(out, &descriptor.genesis_validator_keys)?;
    append_strings(out, &descriptor.genesis_notary_keys)?;
    append_string(out, &descriptor.currency_genesis_root)?;
    append_strings(out, &descriptor.validator_keys)?;
    append_strings(out, &descriptor.notary_keys)?;
    out.extend_from_slice(&descriptor.protocol_era.to_be_bytes());
    out.extend_from_slice(&descriptor.crypto_era.to_be_bytes());
    out.push(u8::from(descriptor.testnet));
    Ok(())
}

fn append_strings(out: &mut Vec<u8>, values: &[String]) -> Result<(), String> {
    let count = u64::try_from(values.len()).map_err(|_| "string list is too long")?;
    out.extend_from_slice(&count.to_be_bytes());
    for value in values {
        append_string(out, value)?;
    }
    Ok(())
}

fn append_string(out: &mut Vec<u8>, value: &str) -> Result<(), String> {
    let length = u64::try_from(value.len()).map_err(|_| "manifest field is too long")?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{generate_identity, AdmissionWork, ContributionEpochMappingV1};

    fn admission_fixture() -> (AdmissionLogConfigV1, AdmissionHash32) {
        let target =
            AdmissionWork::from_hex(&format!("7f{}", "ff".repeat(31))).expect("valid target");
        (
            AdmissionLogConfigV1 {
                minimum_target: target,
                maximum_target: target,
                genesis_target: target,
                confirmation_work_floor: AdmissionWork([32, 0, 0, 0]),
                contribution_epoch_mapping: ContributionEpochMappingV1 {
                    ledger_height_origin: 0,
                    contribution_epoch_origin: 0,
                    ledger_blocks_per_contribution_epoch: 2,
                },
            },
            AdmissionHash32::from_hex(&hash_bytes(b"test-only admission benchmark report"))
                .expect("valid benchmark hash"),
        )
    }

    #[test]
    fn signed_m0_manifest_is_reproducible_and_tamper_evident() {
        let founder = generate_identity();
        let validators = (0..4)
            .map(|_| generate_identity().public_key)
            .collect::<Vec<_>>();
        let notaries = (0..4)
            .map(|_| generate_identity().public_key)
            .collect::<Vec<_>>();
        let (admission_config, admission_benchmark) = admission_fixture();
        let manifest = SignedM0GenesisManifest::create(
            "Rldcoin-M0",
            validators,
            notaries,
            "founder-control-1",
            admission_config,
            admission_benchmark,
            &founder,
        )
        .unwrap();
        manifest.verify().unwrap();
        assert_eq!(
            manifest.declaration.format_version,
            "RLD-M0-GENESIS-MANIFEST-V2"
        );
        assert_eq!(
            manifest.declaration.network_birth_state().format_version,
            "RLD-M0-NETWORK-BIRTH-STATE-V2"
        );

        let mut ledger = Ledger::genesis_zone(
            &manifest.declaration.descriptor.display_name,
            manifest
                .declaration
                .descriptor
                .genesis_validator_keys
                .clone(),
            manifest.declaration.descriptor.genesis_notary_keys.clone(),
            false,
        )
        .unwrap();
        let unbound_root = ledger.state_root().unwrap();
        ledger
            .bind_m0_network_birth(manifest.declaration.network_birth_state())
            .unwrap();
        assert_ne!(ledger.state_root().unwrap(), unbound_root);
        manifest.validate_ledger_identity(&ledger).unwrap();
        assert_eq!(
            ledger.admission_state.as_ref().unwrap().genesis,
            manifest.declaration.admission_genesis
        );
        let mut without_admission_extension = ledger.clone();
        without_admission_extension.admission_state = None;
        assert!(without_admission_extension.state_root().is_err());
        let expected_initial_asset_root = AdmissionHash32::from_hex(
            &without_admission_extension
                .state_root_before_admission()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            ledger
                .admission_state
                .as_ref()
                .unwrap()
                .censorship_guard
                .last_value_eligible_asset_root(),
            expected_initial_asset_root
        );
        let audit = ledger.audit_proof_bundle().unwrap();
        assert_eq!(audit.m0_network_birth, ledger.m0_network_birth);
        assert_eq!(audit.admission_state, ledger.admission_state);
        audit.verify_structure().unwrap();
        let mut tampered_audit = audit.clone();
        tampered_audit
            .admission_state
            .as_mut()
            .unwrap()
            .committed_header = AdmissionHash32::ZERO;
        tampered_audit.commitment_hash = tampered_audit.compute_commitment().unwrap();
        assert!(tampered_audit.verify_structure().is_err());

        let encoded = serde_json::to_vec(&ledger).unwrap();
        let mut restored: Ledger = serde_json::from_slice(&encoded).unwrap();
        manifest.validate_ledger_identity(&restored).unwrap();
        let root_before_rejection = restored.state_root().unwrap();
        let rejected = restored
            .execute_consensus_command(crate::ConsensusCommand::ActivatePendingValueRiskPolicy)
            .unwrap_err();
        assert!(matches!(rejected, crate::LedgerError::ValueRisk(_)));
        assert_eq!(restored.state_root().unwrap(), root_before_rejection);
        let heartbeat = crate::NetworkHeartbeatV1 {
            heartbeat_id: "genesis-test-heartbeat-1".into(),
            zone_id: restored.descriptor.zone_id.clone(),
            currency_genesis_root: restored.descriptor.currency_genesis_root.clone(),
            protocol_era: restored.descriptor.protocol_era,
            crypto_era: restored.descriptor.crypto_era,
            parent_height: restored.height,
            note_hash: hash_bytes(b"M0 persisted gate test"),
        };
        restored
            .execute_consensus_command(crate::ConsensusCommand::NetworkHeartbeat(heartbeat))
            .unwrap();
        assert_eq!(restored.height, 1);

        let mut tampered = manifest.clone();
        tampered.declaration.control_group_id.push_str("-tampered");
        assert!(tampered.verify().is_err());

        let mut tampered_admission_target = manifest.clone();
        tampered_admission_target
            .declaration
            .admission_genesis
            .config
            .confirmation_work_floor = AdmissionWork([33, 0, 0, 0]);
        assert!(tampered_admission_target.verify().is_err());

        let mut tampered_epoch_mapping = manifest.clone();
        tampered_epoch_mapping
            .declaration
            .admission_genesis
            .config
            .contribution_epoch_mapping
            .ledger_blocks_per_contribution_epoch = 3;
        assert!(tampered_epoch_mapping.verify().is_err());

        let mut tampered_benchmark = manifest.clone();
        tampered_benchmark
            .declaration
            .admission_genesis
            .benchmark_report_sha256 =
            AdmissionHash32::from_hex(&hash_bytes(b"other report")).unwrap();
        assert!(tampered_benchmark.verify().is_err());

        let mut missing_admission_state = ledger.clone();
        missing_admission_state.admission_state = None;
        assert!(manifest
            .validate_ledger_identity(&missing_admission_state)
            .is_err());

        let mut unknown_descriptor_field = serde_json::to_value(&manifest).unwrap();
        unknown_descriptor_field["declaration"]["descriptor"]["unsigned_extension"] =
            serde_json::json!("must-not-be-ignored");
        assert!(
            serde_json::from_value::<SignedM0GenesisManifest>(unknown_descriptor_field).is_err()
        );

        let mut unknown_ledger_field = serde_json::to_value(&ledger).unwrap();
        unknown_ledger_field["uncommitted_extension"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Ledger>(unknown_ledger_field).is_err());
    }

    #[test]
    fn admission_control_facts_change_the_m0_state_root_without_self_reference() {
        let founder = generate_identity();
        let validators = (0..4)
            .map(|_| generate_identity().public_key)
            .collect::<Vec<_>>();
        let notaries = (0..4)
            .map(|_| generate_identity().public_key)
            .collect::<Vec<_>>();
        let (admission_config, admission_benchmark) = admission_fixture();
        let manifest = SignedM0GenesisManifest::create(
            "Rldcoin-M0-control-facts",
            validators,
            notaries,
            "founder-control-facts",
            admission_config,
            admission_benchmark,
            &founder,
        )
        .unwrap();
        let mut ledger = Ledger::genesis_zone(
            &manifest.declaration.descriptor.display_name,
            manifest
                .declaration
                .descriptor
                .genesis_validator_keys
                .clone(),
            manifest.declaration.descriptor.genesis_notary_keys.clone(),
            false,
        )
        .unwrap();
        ledger
            .bind_m0_network_birth(manifest.declaration.network_birth_state())
            .unwrap();

        let config = ledger
            .admission_state
            .as_ref()
            .unwrap()
            .genesis
            .config
            .clone();
        let schedule = {
            let mut candidate = ledger.admission_state.as_ref().unwrap().control.clone();
            candidate.schedule_target(5, [64; 4], &config).unwrap()
        };
        let schedule_fact = crate::AdmissionLedgerControlFactV1::TargetSchedule(schedule);
        let genesis_root = ledger.state_root().unwrap();
        ledger
            .apply_admission_ledger_control_fact(&schedule_fact)
            .unwrap();
        let schedule_root = ledger.state_root().unwrap();
        assert_ne!(schedule_root, genesis_root);

        let mut forged_schedule = schedule_fact.clone();
        let crate::AdmissionLedgerControlFactV1::TargetSchedule(forged) = &mut forged_schedule
        else {
            unreachable!()
        };
        forged.target = AdmissionWork::ZERO;
        assert!(ledger
            .apply_admission_ledger_control_fact(&forged_schedule)
            .is_err());
        assert_eq!(ledger.state_root().unwrap(), schedule_root);

        let activation = {
            let mut candidate = ledger.admission_state.as_ref().unwrap().control.clone();
            candidate.activate_target(7, &config).unwrap()
        };
        ledger
            .apply_admission_ledger_control_fact(
                &crate::AdmissionLedgerControlFactV1::TargetActivation(activation),
            )
            .unwrap();
        let activation_root = ledger.state_root().unwrap();
        assert_ne!(activation_root, schedule_root);

        let finalized_prestate = AdmissionHash32::from_hex(&activation_root).unwrap();
        let authorization = crate::AdmissionRolloverAuthorizationV1 {
            terminal_header: AdmissionHash32::from_hex(&hash_bytes(b"terminal-header")).unwrap(),
            terminal_cumulative_work: AdmissionWork::from_be_bytes([
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
            successor_era: 1,
            finalized_ledger_state_root: finalized_prestate,
        };
        ledger
            .apply_admission_ledger_control_fact(
                &crate::AdmissionLedgerControlFactV1::RolloverAuthorization(authorization),
            )
            .unwrap();
        let rollover_root = ledger.state_root().unwrap();
        assert_ne!(rollover_root, activation_root);

        let audit = ledger.audit_proof_bundle().unwrap();
        assert_eq!(audit.admission_state, ledger.admission_state);
        audit.verify_structure().unwrap();
        let mut tampered_audit = audit;
        tampered_audit
            .admission_state
            .as_mut()
            .unwrap()
            .control
            .fact_count = 0;
        tampered_audit.commitment_hash = tampered_audit.compute_commitment().unwrap();
        assert!(tampered_audit.verify_structure().is_err());

        let mut tampered_accumulator = ledger.audit_proof_bundle().unwrap();
        tampered_accumulator
            .admission_state
            .as_mut()
            .unwrap()
            .control
            .fact_accumulator =
            AdmissionHash32::from_hex(&hash_bytes(b"forged-control-tip")).unwrap();
        tampered_accumulator.commitment_hash = tampered_accumulator.compute_commitment().unwrap();
        assert!(tampered_accumulator.verify_structure().is_err());
        manifest.validate_ledger_identity(&ledger).unwrap();
    }

    #[test]
    fn verified_admission_checkpoint_changes_the_m0_state_root_and_audit_bundle() {
        let founder = generate_identity();
        let validators = (0..4)
            .map(|_| generate_identity().public_key)
            .collect::<Vec<_>>();
        let notaries = (0..4)
            .map(|_| generate_identity().public_key)
            .collect::<Vec<_>>();
        let (admission_config, admission_benchmark) = admission_fixture();
        let manifest = SignedM0GenesisManifest::create(
            "Rldcoin-M0-checkpoint-transition",
            validators,
            notaries,
            "founder-checkpoint-transition",
            admission_config,
            admission_benchmark,
            &founder,
        )
        .unwrap();
        let mut ledger = Ledger::genesis_zone(
            &manifest.declaration.descriptor.display_name,
            manifest
                .declaration
                .descriptor
                .genesis_validator_keys
                .clone(),
            manifest.declaration.descriptor.genesis_notary_keys.clone(),
            false,
        )
        .unwrap();
        ledger
            .bind_m0_network_birth(manifest.declaration.network_birth_state())
            .unwrap();

        let admission = ledger.admission_state.as_ref().unwrap();
        let proof_id =
            AdmissionHash32::from_hex(&hash_bytes(b"verified-checkpoint-proof")).unwrap();
        let checkpoint = crate::AdmissionCheckpointV1 {
            context: admission.genesis.context.clone(),
            admission_era: 0,
            header_id: AdmissionHash32::from_hex(&hash_bytes(b"verified-checkpoint-header"))
                .unwrap(),
            log_height: 1,
            cumulative_work: AdmissionWork([1, 0, 0, 0]),
            confirmations: crate::MIN_ADMISSION_CONFIRMATIONS as u16,
            descendant_work: admission.genesis.config.confirmation_work_floor,
            entries_root: crate::admission_entry_root(std::iter::empty()).unwrap(),
            availability_root: crate::admission_availability_root(&[]).unwrap(),
            observed_ledger_epoch: 0,
            committed_ledger_epoch: 0,
        };
        let transition = crate::VerifiedAdmissionCheckpointTransitionV1 {
            prior_committed_header: admission.committed_header,
            entry_ids: Vec::new(),
            observed_ledger_height: 0,
            committing_ledger_height: 1,
            next_checkpoint_accumulator: crate::admission_checkpoint_accumulator_successor(
                admission.checkpoint_accumulator,
                admission.checkpoint_count,
                checkpoint.checkpoint_id(),
                proof_id,
            )
            .unwrap(),
            checkpoint,
            proof_id,
        };
        let genesis_root = ledger.state_root().unwrap();
        let proposal_context = ledger
            .test_authenticated_admission_checkpoint_proposal(&transition)
            .unwrap();
        let wrong_successor =
            crate::AuthenticatedAdmissionCheckpointProposalV1::from_authenticated_proposal(
                proposal_context.proposal_hash().to_owned(),
                proposal_context.command_hash().to_owned(),
                proposal_context.proof_id(),
                proposal_context.parent_height(),
                proposal_context.parent_state_root().to_owned(),
                u64::try_from(proposal_context.committing_ledger_height()).unwrap(),
                hash_bytes(b"wrong-tag-28-expected-state-root"),
            )
            .unwrap();
        assert!(ledger
            .execute_authenticated_admission_checkpoint_transition(&wrong_successor, &transition)
            .is_err());
        assert_eq!(ledger.state_root().unwrap(), genesis_root);

        let mut forged = transition.clone();
        forged.next_checkpoint_accumulator =
            AdmissionHash32::from_hex(&hash_bytes(b"forged-checkpoint-accumulator")).unwrap();
        assert!(ledger
            .execute_authenticated_admission_checkpoint_transition(&proposal_context, &forged)
            .is_err());
        assert_eq!(ledger.state_root().unwrap(), genesis_root);

        ledger
            .execute_authenticated_admission_checkpoint_transition(&proposal_context, &transition)
            .unwrap();
        let checkpoint_root = ledger.state_root().unwrap();
        assert_ne!(checkpoint_root, genesis_root);
        let applied = ledger.admission_state.as_ref().unwrap();
        assert_eq!(
            applied.latest_checkpoint.as_ref(),
            Some(&transition.checkpoint)
        );
        assert_eq!(applied.checkpoint_count, 1);
        assert_eq!(
            applied.checkpoint_accumulator,
            transition.next_checkpoint_accumulator
        );
        applied.validate_recovered().unwrap();

        let audit = ledger.audit_proof_bundle().unwrap();
        assert_eq!(audit.admission_state, ledger.admission_state);
        audit.verify_structure().unwrap();
        let mut tampered = audit;
        tampered
            .admission_state
            .as_mut()
            .unwrap()
            .checkpoint_accumulator =
            AdmissionHash32::from_hex(&hash_bytes(b"tampered-checkpoint-accumulator")).unwrap();
        tampered.commitment_hash = tampered.compute_commitment().unwrap();
        assert!(tampered.verify_structure().is_err());
        manifest.validate_ledger_identity(&ledger).unwrap();
    }
}
