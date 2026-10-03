//! Separately versioned, unreleased M0 candidate. V2 bytes are unchanged.

use super::*;

pub const M0_GENESIS_MANIFEST_V3: &str = "RLD-M0-GENESIS-MANIFEST-V3";
pub const M0_BIRTH_STATE_V3: &str = "RLD-M0-NETWORK-BIRTH-STATE-V3";
pub const M0_UPGRADE_CONSTITUTION_V1: &str = "RLD-M0-UPGRADE-CONSTITUTION-V1";
pub const M0_ACTIVE_PROTOCOL_V1: &str = "RLD-M0-ACTIVE-PROTOCOL-V1";
pub const M0_ACTIVE_PROTOCOL_V2: &str = "RLD-M0-ACTIVE-PROTOCOL-V2";
pub const M0_ADMISSION_CONSENSUS_PROFILE: &str = "NETWORK_HEARTBEAT_AND_ADMISSION_CHECKPOINT_V1";
pub const EARTH_GENESIS_MANIFEST: &str = "RLD-EARTH-GENESIS-MANIFEST";
pub const EARTH_NETWORK_PHASE: &str = "EARTH_NETWORK_BIRTH";
pub const EARTH_BIRTH_STATE: &str = "RLD-EARTH-GENESIS-STATE";
pub const EARTH_CONSTITUTION: &str = "RLD-EARTH-GENESIS-CONSTITUTION";
pub const EARTH_ACTIVE_PROTOCOL: &str = "RLD-EARTH-GENESIS-PROTOCOL";

fn append_descriptor_v3(bytes: &mut Vec<u8>, descriptor: &ZoneDescriptor) -> Result<(), String> {
    append_string(bytes, &descriptor.zone_id)?;
    append_string(bytes, &descriptor.display_name)?;
    append_string(bytes, &descriptor.genesis_root)?;
    bytes.extend_from_slice(&descriptor.identity_version.to_be_bytes());
    append_string(bytes, &descriptor.identity_hash_suite)?;
    append_string(bytes, &descriptor.network_domain)?;
    bytes.extend_from_slice(&descriptor.anchor_supply.0.to_be_bytes());
    append_strings(bytes, &descriptor.genesis_validator_keys)?;
    append_strings(bytes, &descriptor.genesis_notary_keys)?;
    append_string(bytes, &descriptor.currency_genesis_root)?;
    append_strings(bytes, &descriptor.validator_keys)?;
    append_strings(bytes, &descriptor.notary_keys)?;
    bytes.extend_from_slice(&u128::from(descriptor.protocol_era).to_be_bytes());
    bytes.extend_from_slice(&u128::from(descriptor.crypto_era).to_be_bytes());
    bytes.push(u8::from(descriptor.testnet));
    Ok(())
}

/// This limits the bootstrap upgrade authority, not the later separately gated
/// M5 value-policy authority. No field permits changing supply or restoring seats.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct M0UpgradeConstitutionV1 {
    pub format_version: String,
    pub fixed_supply_runlai: Amount,
    pub runlai_per_rld: Amount,
    pub bootstrap_upgrade_value_cap: ValueCap,
    pub founder_special_slot_ceiling: [u16; 6],
    pub minimum_activation_delay_epochs: u16,
    pub current_committee_finality_required: bool,
    pub preserve_existing_obligations: bool,
    pub replace_genesis_allowed: bool,
    pub restore_founder_weight_allowed: bool,
    pub value_activation_requires_m5_and_safety_case: bool,
}

impl M0UpgradeConstitutionV1 {
    pub fn bootstrap_v1() -> Self {
        Self {
            format_version: M0_UPGRADE_CONSTITUTION_V1.into(),
            fixed_supply_runlai: Amount::TOTAL_SUPPLY,
            runlai_per_rld: Amount(RUNLAI_PER_RLD),
            bootstrap_upgrade_value_cap: ValueCap::ValueCap0,
            founder_special_slot_ceiling: [1000, 1000, 750, 500, 250, 0],
            minimum_activation_delay_epochs: 2,
            current_committee_finality_required: true,
            preserve_existing_obligations: true,
            replace_genesis_allowed: false,
            restore_founder_weight_allowed: false,
            value_activation_requires_m5_and_safety_case: true,
        }
    }

    pub fn earth() -> Self {
        let mut value = Self::bootstrap_v1();
        value.format_version = EARTH_CONSTITUTION.into();
        value
    }

    pub fn validate(&self) -> Result<(), String> {
        if self != &Self::bootstrap_v1() && self != &Self::earth() {
            return Err("unsupported or invariant-changing M0 upgrade constitution".into());
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut bytes = if self.format_version == EARTH_CONSTITUTION {
            b"RLD-EARTH-GENESIS-CONSTITUTION-BYTES\0".to_vec()
        } else {
            b"RLD-M0-UPGRADE-CONSTITUTION-BYTES-V1\0".to_vec()
        };
        bytes.extend_from_slice(&self.fixed_supply_runlai.0.to_be_bytes());
        bytes.extend_from_slice(&self.runlai_per_rld.0.to_be_bytes());
        bytes.push(self.bootstrap_upgrade_value_cap.code());
        for ceiling in self.founder_special_slot_ceiling {
            bytes.extend_from_slice(&ceiling.to_be_bytes());
        }
        bytes.extend_from_slice(&self.minimum_activation_delay_epochs.to_be_bytes());
        bytes.extend_from_slice(&[1, 1, 0, 0, 1]);
        Ok(bytes)
    }

    pub fn commitment(&self) -> Result<String, String> {
        Ok(hash_bytes(&self.canonical_bytes()?))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct M0NetworkBirthStateV3 {
    pub format_version: String,
    pub founder_public_key: String,
    pub control_group_id: String,
    pub initial_consensus_profile: String,
    pub admission_genesis: AdmissionGenesisV1,
    pub upgrade_constitution: M0UpgradeConstitutionV1,
}

impl M0NetworkBirthStateV3 {
    pub fn validate_for_descriptor(&self, descriptor: &ZoneDescriptor) -> Result<(), String> {
        if !((self.format_version == M0_BIRTH_STATE_V3
            && self.upgrade_constitution.format_version == M0_UPGRADE_CONSTITUTION_V1)
            || (self.format_version == EARTH_BIRTH_STATE
                && self.upgrade_constitution.format_version == EARTH_CONSTITUTION))
            || self.initial_consensus_profile != M0_ALLOWED_CONSENSUS_PROFILE
        {
            return Err("invalid V3 immutable birth facts".into());
        }
        self.upgrade_constitution.validate()?;
        // Reuse validation, never the old root or V2 serialization/signature.
        M0NetworkBirthStateV2::new(
            self.founder_public_key.clone(),
            self.control_group_id.clone(),
            self.admission_genesis.clone(),
        )
        .validate_for_descriptor(descriptor)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = if self.format_version == EARTH_BIRTH_STATE {
            b"RLD-EARTH-GENESIS-STATE-BYTES\0".to_vec()
        } else {
            b"RLD-M0-NETWORK-BIRTH-BYTES-V3\0".to_vec()
        };
        append_string(&mut bytes, &self.format_version)?;
        append_string(&mut bytes, &self.founder_public_key)?;
        append_string(&mut bytes, &self.control_group_id)?;
        append_string(&mut bytes, &self.initial_consensus_profile)?;
        append_admission_genesis(&mut bytes, &self.admission_genesis)?;
        bytes.extend_from_slice(&self.upgrade_constitution.canonical_bytes()?);
        Ok(bytes)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct M0ActiveProtocolStateV1 {
    pub format_version: String,
    pub constitution_commitment: String,
    #[serde(with = "decimal_u128")]
    pub upgrade_sequence: u128,
    pub consensus_profile: String,
    pub founder_special_slot_ceiling: u16,
    pub last_activated_upgrade: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_prior_active_commitment"
    )]
    pub prior_active_commitment: Option<String>,
}

fn present_prior_active_commitment<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    // Missing is the V1 form; an explicitly present null must not become an
    // accepted extra V1 field. V2 requires a nonzero hash during validation.
    String::deserialize(deserializer).map(Some)
}

impl M0ActiveProtocolStateV1 {
    pub fn at_birth(birth: &M0NetworkBirthStateV3) -> Result<Self, String> {
        Ok(Self {
            format_version: if birth.format_version == EARTH_BIRTH_STATE {
                EARTH_ACTIVE_PROTOCOL.into()
            } else {
                M0_ACTIVE_PROTOCOL_V1.into()
            },
            constitution_commitment: birth.upgrade_constitution.commitment()?,
            upgrade_sequence: 0,
            consensus_profile: birth.initial_consensus_profile.clone(),
            founder_special_slot_ceiling: 1000,
            last_activated_upgrade: None,
            prior_active_commitment: None,
        })
    }

    pub fn validate_for_birth(&self, birth: &M0NetworkBirthStateV3) -> Result<(), String> {
        let initial = Self::at_birth(birth)?;
        if self == &initial {
            return Ok(());
        }
        self.canonical_bytes()?;
        if self.format_version != M0_ACTIVE_PROTOCOL_V2
            || self.constitution_commitment != initial.constitution_commitment
            || self.prior_active_commitment.as_deref()
                != Some(hash_bytes(&initial.canonical_bytes()?).as_str())
        {
            return Err("unsupported V3 active protocol successor binding".into());
        }
        // Structural binding only: main-WAL replay must prove activation.
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        if self.format_version == M0_ACTIVE_PROTOCOL_V2 {
            let prior = self
                .prior_active_commitment
                .as_deref()
                .ok_or("missing prior active commitment")?;
            let intent = self
                .last_activated_upgrade
                .as_deref()
                .ok_or("missing activated intent")?;
            if self.upgrade_sequence != 1
                || self.consensus_profile != M0_ADMISSION_CONSENSUS_PROFILE
                || self.founder_special_slot_ceiling != 1000
                || [prior, intent, self.constitution_commitment.as_str()]
                    .iter()
                    .any(|h| !is_sha256_hex(h) || *h == "0".repeat(64))
            {
                return Err("unsupported first active protocol successor".into());
            }
            let mut bytes = b"RLD-M0-ACTIVE-PROTOCOL-BYTES-V2\0".to_vec();
            bytes.extend_from_slice(
                &hex::decode(&self.constitution_commitment).map_err(|e| e.to_string())?,
            );
            bytes.extend_from_slice(&self.upgrade_sequence.to_be_bytes());
            append_string(&mut bytes, &self.consensus_profile)?;
            bytes.extend_from_slice(&self.founder_special_slot_ceiling.to_be_bytes());
            bytes.extend_from_slice(&hex::decode(prior).map_err(|e| e.to_string())?);
            bytes.extend_from_slice(&hex::decode(intent).map_err(|e| e.to_string())?);
            return Ok(bytes);
        }
        if self.format_version != M0_ACTIVE_PROTOCOL_V1
            && self.format_version != EARTH_ACTIVE_PROTOCOL
            || self.prior_active_commitment.is_some()
            || !is_sha256_hex(&self.constitution_commitment)
            || self.upgrade_sequence != 0
            || self.consensus_profile != M0_ALLOWED_CONSENSUS_PROFILE
            || self.founder_special_slot_ceiling != 1000
            || self.last_activated_upgrade.is_some()
        {
            return Err("unsupported active protocol state".into());
        }
        let mut bytes = if self.format_version == EARTH_ACTIVE_PROTOCOL {
            b"RLD-EARTH-GENESIS-PROTOCOL-BYTES\0".to_vec()
        } else {
            b"RLD-M0-ACTIVE-PROTOCOL-BYTES-V1\0".to_vec()
        };
        bytes.extend_from_slice(
            &hex::decode(&self.constitution_commitment).map_err(|e| e.to_string())?,
        );
        bytes.extend_from_slice(&self.upgrade_sequence.to_be_bytes());
        append_string(&mut bytes, &self.consensus_profile)?;
        bytes.extend_from_slice(&self.founder_special_slot_ceiling.to_be_bytes());
        bytes.push(0); // no activated-upgrade reference at birth
        Ok(bytes)
    }
}

pub(super) mod decimal_u128 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u128, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u128, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.is_empty()
            || (value.len() > 1 && value.starts_with('0'))
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(serde::de::Error::custom("noncanonical U128 decimal string"));
        }
        value.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct M0GenesisDeclarationV3 {
    pub format_version: String,
    pub network_phase: String,
    pub descriptor: ZoneDescriptor,
    pub genesis_state_root: String,
    pub founder_public_key: String,
    pub control_group_id: String,
    pub admission_genesis: AdmissionGenesisV1,
    pub upgrade_constitution: M0UpgradeConstitutionV1,
}

impl M0GenesisDeclarationV3 {
    pub fn network_birth_state(&self) -> M0NetworkBirthStateV3 {
        M0NetworkBirthStateV3 {
            format_version: if self.format_version == EARTH_GENESIS_MANIFEST {
                EARTH_BIRTH_STATE.into()
            } else {
                M0_BIRTH_STATE_V3.into()
            },
            founder_public_key: self.founder_public_key.clone(),
            control_group_id: self.control_group_id.clone(),
            initial_consensus_profile: M0_ALLOWED_CONSENSUS_PROFILE.into(),
            admission_genesis: self.admission_genesis.clone(),
            upgrade_constitution: self.upgrade_constitution.clone(),
        }
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        if !((self.format_version == M0_GENESIS_MANIFEST_V3
            && self.network_phase == M0_NETWORK_PHASE)
            || (self.format_version == EARTH_GENESIS_MANIFEST
                && self.network_phase == EARTH_NETWORK_PHASE))
            || !is_sha256_hex(&self.genesis_state_root)
        {
            return Err("invalid V3 genesis declaration".into());
        }
        self.descriptor.validate_identity()?;
        self.network_birth_state()
            .validate_for_descriptor(&self.descriptor)?;
        // V2 declaration validation also rejects overlaps among all role keys.
        let mut keys = self.descriptor.genesis_validator_keys.clone();
        keys.extend(self.descriptor.genesis_notary_keys.clone());
        keys.push(self.founder_public_key.clone());
        for key in &keys {
            validate_ed25519_public_key(key)?;
        }
        keys.sort_unstable();
        if keys.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err("founder, validator and notary identities must be distinct".into());
        }
        let mut bytes = if self.format_version == EARTH_GENESIS_MANIFEST {
            b"RLD-EARTH-GENESIS-MANIFEST-SIGNATURE\0".to_vec()
        } else {
            b"RLD-M0-GENESIS-MANIFEST-SIGNATURE-V3\0".to_vec()
        };
        append_string(&mut bytes, &self.format_version)?;
        append_string(&mut bytes, &self.network_phase)?;
        append_descriptor_v3(&mut bytes, &self.descriptor)?;
        append_string(&mut bytes, &self.genesis_state_root)?;
        bytes.extend_from_slice(&self.network_birth_state().canonical_bytes()?);
        Ok(bytes)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedM0GenesisManifestV3 {
    pub declaration: M0GenesisDeclarationV3,
    pub manifest_sha256: String,
    pub founder_signature: String,
}

impl SignedM0GenesisManifestV3 {
    pub fn create_earth(
        display_name: impl Into<String>,
        validator_keys: Vec<String>,
        notary_keys: Vec<String>,
        control_group_id: impl Into<String>,
        admission_config: AdmissionLogConfigV1,
        benchmark: AdmissionHash32,
        founder: &Identity,
    ) -> Result<Self, String> {
        let mut manifest = Self::create(
            display_name,
            validator_keys,
            notary_keys,
            control_group_id,
            admission_config,
            benchmark,
            founder,
        )?;
        manifest.declaration.format_version = EARTH_GENESIS_MANIFEST.into();
        manifest.declaration.network_phase = EARTH_NETWORK_PHASE.into();
        manifest.declaration.upgrade_constitution = M0UpgradeConstitutionV1::earth();
        let descriptor = &manifest.declaration.descriptor;
        let mut ledger = Ledger::genesis_zone(
            &descriptor.display_name,
            descriptor.genesis_validator_keys.clone(),
            descriptor.genesis_notary_keys.clone(),
            false,
        )
        .map_err(|error| error.to_string())?;
        ledger
            .bind_m0_network_birth_v3(manifest.declaration.network_birth_state())
            .map_err(|error| error.to_string())?;
        manifest.declaration.genesis_state_root =
            ledger.state_root().map_err(|error| error.to_string())?;
        let bytes = manifest.declaration.signing_bytes()?;
        manifest.manifest_sha256 = hash_bytes(&bytes);
        manifest.founder_signature = sign_bytes(&founder.secret_key, &bytes)?;
        manifest.verify()?;
        Ok(manifest)
    }

    pub fn create(
        display_name: impl Into<String>,
        validator_keys: Vec<String>,
        notary_keys: Vec<String>,
        control_group_id: impl Into<String>,
        admission_config: AdmissionLogConfigV1,
        benchmark: AdmissionHash32,
        founder: &Identity,
    ) -> Result<Self, String> {
        let mut ledger = Ledger::genesis_zone(display_name, validator_keys, notary_keys, false)
            .map_err(|e| e.to_string())?;
        let admission_genesis =
            AdmissionGenesisV1::for_descriptor(&ledger.descriptor, admission_config, benchmark)
                .map_err(|e| e.to_string())?;
        let mut declaration = M0GenesisDeclarationV3 {
            format_version: M0_GENESIS_MANIFEST_V3.into(),
            network_phase: M0_NETWORK_PHASE.into(),
            descriptor: ledger.descriptor.clone(),
            genesis_state_root: "0".repeat(64),
            founder_public_key: founder.public_key.clone(),
            control_group_id: control_group_id.into(),
            admission_genesis,
            upgrade_constitution: M0UpgradeConstitutionV1::bootstrap_v1(),
        };
        ledger
            .bind_m0_network_birth_v3(declaration.network_birth_state())
            .map_err(|e| e.to_string())?;
        declaration.genesis_state_root = ledger.state_root().map_err(|e| e.to_string())?;
        let bytes = declaration.signing_bytes()?;
        let manifest = Self {
            declaration,
            manifest_sha256: hash_bytes(&bytes),
            founder_signature: sign_bytes(&founder.secret_key, &bytes)?,
        };
        manifest.verify()?;
        Ok(manifest)
    }

    pub fn reconstruct_genesis(&self) -> Result<Ledger, String> {
        let bytes = self.declaration.signing_bytes()?;
        if self.manifest_sha256 != hash_bytes(&bytes) {
            return Err("V3 manifest content hash mismatch".into());
        }
        verify_bytes(
            &self.declaration.founder_public_key,
            &bytes,
            &self.founder_signature,
        )?;
        let descriptor = &self.declaration.descriptor;
        let mut ledger = Ledger::genesis_zone(
            &descriptor.display_name,
            descriptor.genesis_validator_keys.clone(),
            descriptor.genesis_notary_keys.clone(),
            false,
        )
        .map_err(|e| e.to_string())?;
        ledger
            .bind_m0_network_birth_v3(self.declaration.network_birth_state())
            .map_err(|e| e.to_string())?;
        if ledger.descriptor != *descriptor
            || ledger.state_root().map_err(|e| e.to_string())?
                != self.declaration.genesis_state_root
        {
            return Err("V3 genesis is not reproducible from signed inputs".into());
        }
        Ok(ledger)
    }

    pub fn verify(&self) -> Result<(), String> {
        self.reconstruct_genesis().map(|_| ())
    }

    pub fn validate_ledger_identity(&self, ledger: &Ledger) -> Result<(), String> {
        self.verify()?;
        // Core certified replay does not qualify live node/signer/witness
        // startup. Keep public runtime manifest admission shut until the
        // complete multi-role activation and recovery path is qualified.
        if ledger
            .m0_active_protocol
            .as_ref()
            .is_some_and(|active| active.upgrade_sequence != 0)
        {
            return Err("active successor runtime admission remains closed".into());
        }
        self.validate_replayed_candidate_identity(ledger)
    }

    // Only the private-state certified replay engine may admit a successor.
    // This structural check is not a general snapshot import authorization.
    pub(crate) fn validate_replayed_candidate_identity(
        &self,
        ledger: &Ledger,
    ) -> Result<(), String> {
        self.verify()?;
        if ledger.descriptor != self.declaration.descriptor
            || ledger.anchor_supply != Amount::TOTAL_SUPPLY
            || ledger.m0_network_birth.is_some()
            || ledger.m0_network_birth_v3.as_ref() != Some(&self.declaration.network_birth_state())
            || ledger.value_risk_policy.current_cap != ValueCap::ValueCap0
            || ledger.value_risk_policy.ever_enabled
            || ledger.value_risk_policy.pending_update.is_some()
        {
            return Err("persisted V3 candidate identity or zero-value boundary differs".into());
        }
        ledger.m0_admission_genesis().map_err(|e| e.to_string())?;
        ledger.state_root().map_err(|e| e.to_string())?;
        Ok(())
    }
}

/// Version dispatch keeps each signed declaration's strict schema separate.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum M0GenesisManifestFile {
    V2(SignedM0GenesisManifest),
    V3(SignedM0GenesisManifestV3),
}

impl From<SignedM0GenesisManifest> for M0GenesisManifestFile {
    fn from(value: SignedM0GenesisManifest) -> Self {
        Self::V2(value)
    }
}

impl M0GenesisManifestFile {
    /// Parse the original JSON bytes with each strict typed schema. Serde's
    /// untagged intermediate representation cannot faithfully decode u128;
    /// a Value intermediate would also lose large integer precision.
    pub fn decode_json(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > 65_536 {
            return Err("M0 genesis manifest exceeds 64 KiB".into());
        }
        match serde_json::from_slice::<SignedM0GenesisManifest>(bytes) {
            Ok(manifest) => Ok(Self::V2(manifest)),
            Err(v2_error) => serde_json::from_slice::<SignedM0GenesisManifestV3>(bytes)
                .map(Self::V3)
                .map_err(|v3_error| format!("invalid V2/V3 genesis: {v2_error}; {v3_error}")),
        }
    }

    pub fn verify(&self) -> Result<(), String> {
        match self {
            Self::V2(m) => m.verify(),
            Self::V3(m) => m.verify(),
        }
    }
    pub fn manifest_sha256(&self) -> &str {
        match self {
            Self::V2(m) => &m.manifest_sha256,
            Self::V3(m) => &m.manifest_sha256,
        }
    }
    pub fn descriptor(&self) -> &ZoneDescriptor {
        match self {
            Self::V2(m) => &m.declaration.descriptor,
            Self::V3(m) => &m.declaration.descriptor,
        }
    }
    pub fn admission_genesis(&self) -> &AdmissionGenesisV1 {
        match self {
            Self::V2(m) => &m.declaration.admission_genesis,
            Self::V3(m) => &m.declaration.admission_genesis,
        }
    }
    pub fn control_group_id(&self) -> &str {
        match self {
            Self::V2(m) => &m.declaration.control_group_id,
            Self::V3(m) => &m.declaration.control_group_id,
        }
    }
    pub fn genesis_state_root(&self) -> &str {
        match self {
            Self::V2(m) => &m.declaration.genesis_state_root,
            Self::V3(m) => &m.declaration.genesis_state_root,
        }
    }
    pub fn bind_genesis(&self, ledger: &mut Ledger) -> Result<(), crate::LedgerError> {
        match self {
            Self::V2(m) => ledger.bind_m0_network_birth(m.declaration.network_birth_state()),
            Self::V3(m) => ledger.bind_m0_network_birth_v3(m.declaration.network_birth_state()),
        }
    }
    pub fn validate_ledger_identity(&self, ledger: &Ledger) -> Result<(), String> {
        match self {
            Self::V2(m) => m.validate_ledger_identity(ledger),
            Self::V3(m) => m.validate_ledger_identity(ledger),
        }
    }
    pub(crate) fn validate_replayed_candidate_identity(
        &self,
        ledger: &Ledger,
    ) -> Result<(), String> {
        match self {
            Self::V2(m) => m.validate_ledger_identity(ledger),
            Self::V3(m) => m.validate_replayed_candidate_identity(ledger),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        generate_identity, AdmissionWork, ConsensusCommand, ContributionEpochMappingV1,
        NetworkHeartbeatV1,
    };

    fn fixture() -> (SignedM0GenesisManifestV3, SignedM0GenesisManifest) {
        let founder = generate_identity();
        let validators = (0..4)
            .map(|_| generate_identity().public_key)
            .collect::<Vec<_>>();
        let notaries = (0..4)
            .map(|_| generate_identity().public_key)
            .collect::<Vec<_>>();
        let target = AdmissionWork::from_hex(&format!("7f{}", "ff".repeat(31))).unwrap();
        let config = AdmissionLogConfigV1 {
            minimum_target: target,
            maximum_target: target,
            genesis_target: target,
            confirmation_work_floor: AdmissionWork([32, 0, 0, 0]),
            contribution_epoch_mapping: ContributionEpochMappingV1 {
                ledger_height_origin: 0,
                contribution_epoch_origin: 0,
                ledger_blocks_per_contribution_epoch: 64,
            },
        };
        let report = AdmissionHash32::from_hex(&hash_bytes(b"V3 disposable test fixture")).unwrap();
        let v3 = SignedM0GenesisManifestV3::create(
            "V3-candidate",
            validators.clone(),
            notaries.clone(),
            "single-control",
            config.clone(),
            report,
            &founder,
        )
        .unwrap();
        let v2 = SignedM0GenesisManifest::create(
            "V3-candidate",
            validators,
            notaries,
            "single-control",
            config,
            report,
            &founder,
        )
        .unwrap();
        (v3, v2)
    }

    #[test]
    fn v3_birth_is_separately_signed_rooted_replayable_and_auditable() {
        let (manifest, v2) = fixture();
        for file in [
            M0GenesisManifestFile::V2(v2.clone()),
            M0GenesisManifestFile::V3(manifest.clone()),
        ] {
            let decoded =
                M0GenesisManifestFile::decode_json(&serde_json::to_vec_pretty(&file).unwrap())
                    .unwrap();
            decoded.verify().unwrap();
            assert_eq!(decoded.manifest_sha256(), file.manifest_sha256());
        }
        let mut large_integer = manifest.clone();
        large_integer
            .declaration
            .admission_genesis
            .config
            .contribution_epoch_mapping
            .contribution_epoch_origin = u128::from(u64::MAX) + 7;
        let M0GenesisManifestFile::V3(decoded) =
            M0GenesisManifestFile::decode_json(&serde_json::to_vec(&large_integer).unwrap())
                .unwrap()
        else {
            panic!("V3 format changed");
        };
        assert_eq!(
            decoded
                .declaration
                .admission_genesis
                .config
                .contribution_epoch_mapping
                .contribution_epoch_origin,
            u128::from(u64::MAX) + 7
        );
        assert!(decoded.verify().is_err()); // altered signed value is never admitted
        let mut ledger = manifest.reconstruct_genesis().unwrap();
        assert_ne!(manifest.manifest_sha256, v2.manifest_sha256);
        assert_ne!(
            manifest.declaration.genesis_state_root,
            v2.declaration.genesis_state_root
        );
        assert!(v2.validate_ledger_identity(&ledger).is_err());
        let mut old = Ledger::genesis_zone(
            "V3-candidate",
            v2.declaration.descriptor.genesis_validator_keys.clone(),
            v2.declaration.descriptor.genesis_notary_keys.clone(),
            false,
        )
        .unwrap();
        old.bind_m0_network_birth(v2.declaration.network_birth_state())
            .unwrap();
        assert!(!serde_json::to_string(&old)
            .unwrap()
            .contains("m0_active_protocol"));
        assert!(manifest.validate_ledger_identity(&old).is_err());
        let old_before = serde_json::to_vec(&old).unwrap();
        assert!(old
            .bind_m0_network_birth_v3(manifest.declaration.network_birth_state())
            .is_err());
        assert_eq!(old_before, serde_json::to_vec(&old).unwrap());

        let before = serde_json::to_vec(&ledger).unwrap();
        assert!(ledger
            .execute_consensus_command(ConsensusCommand::ActivatePendingValueRiskPolicy)
            .is_err());
        assert!(ledger
            .bind_m0_network_birth(v2.declaration.network_birth_state())
            .is_err());
        assert_eq!(before, serde_json::to_vec(&ledger).unwrap());
        let heartbeat = NetworkHeartbeatV1 {
            heartbeat_id: "v3-first-heartbeat".into(),
            zone_id: ledger.descriptor.zone_id.clone(),
            currency_genesis_root: ledger.descriptor.currency_genesis_root.clone(),
            protocol_era: ledger.descriptor.protocol_era,
            crypto_era: ledger.descriptor.crypto_era,
            parent_height: 0,
            note_hash: hash_bytes(b"zero value"),
        };
        ledger
            .execute_consensus_command(ConsensusCommand::NetworkHeartbeat(heartbeat))
            .unwrap();
        let recovered: Ledger =
            serde_json::from_slice(&serde_json::to_vec(&ledger).unwrap()).unwrap();
        manifest.validate_ledger_identity(&recovered).unwrap();
        assert_eq!(
            ledger.state_root().unwrap(),
            recovered.state_root().unwrap()
        );
        assert_eq!(ledger.height, 1);
        assert_eq!(ledger.anchor_supply, Amount::TOTAL_SUPPLY);
        assert_eq!(
            ledger.m0_network_birth_v3,
            Some(manifest.declaration.network_birth_state())
        );
        let audit = ledger.audit_proof_bundle().unwrap();
        audit.verify_structure().unwrap();
        let mut altered_audit = audit.clone();
        altered_audit.m0_active_protocol = None;
        altered_audit.commitment_hash = altered_audit.compute_commitment().unwrap();
        assert!(altered_audit.verify_structure().is_err());
    }

    #[test]
    fn v3_unknown_constitution_mixed_state_and_fabricated_successors_fail_closed() {
        let (manifest, v2) = fixture();
        let ledger = manifest.reconstruct_genesis().unwrap();
        let mut altered = manifest.clone();
        altered
            .declaration
            .upgrade_constitution
            .founder_special_slot_ceiling[5] = 1;
        assert!(altered.verify().is_err());
        altered = manifest.clone();
        altered.declaration.upgrade_constitution.fixed_supply_runlai = Amount(1);
        assert!(altered.verify().is_err());
        altered = manifest.clone();
        altered.founder_signature = v2.founder_signature.clone();
        assert!(altered.verify().is_err());
        altered = manifest.clone();
        altered.declaration.control_group_id = "other-control".into();
        assert!(altered.verify().is_err());

        let mut invalid = ledger.clone();
        invalid.m0_active_protocol = None;
        assert!(invalid.state_root().is_err());
        assert!(manifest.validate_ledger_identity(&invalid).is_err());
        invalid = ledger.clone();
        invalid.m0_network_birth = Some(v2.declaration.network_birth_state());
        assert!(invalid.state_root().is_err());
        invalid = ledger.clone();
        invalid.m0_network_birth_v3 = None;
        assert!(invalid.state_root().is_err());
        invalid = ledger.clone();
        invalid
            .m0_active_protocol
            .as_mut()
            .unwrap()
            .upgrade_sequence = u128::MAX;
        assert!(invalid.state_root().is_err());
        invalid = ledger.clone();
        invalid
            .m0_active_protocol
            .as_mut()
            .unwrap()
            .consensus_profile = "NETWORK_HEARTBEAT_AND_ADMISSION_CHECKPOINT_V1".into();
        assert!(invalid.state_root().is_err());

        let encoded = serde_json::to_value(&ledger).unwrap();
        for value in [
            serde_json::json!(0),
            serde_json::json!("00"),
            serde_json::json!("+0"),
            serde_json::json!("340282366920938463463374607431768211456"),
        ] {
            let mut bad_json = encoded.clone();
            bad_json["m0_active_protocol"]["upgrade_sequence"] = value;
            assert!(serde_json::from_value::<Ledger>(bad_json).is_err());
        }
        let mut bad_manifest = serde_json::to_value(&manifest).unwrap();
        bad_manifest["declaration"]["unsigned_override"] = serde_json::json!(true);
        assert!(
            M0GenesisManifestFile::decode_json(&serde_json::to_vec(&bad_manifest).unwrap())
                .is_err()
        );
        let encoded = serde_json::to_string(&manifest).unwrap();
        let duplicate = encoded.replacen(
            "\"manifest_sha256\":",
            "\"manifest_sha256\":\"duplicate\",\"manifest_sha256\":",
            1,
        );
        assert!(M0GenesisManifestFile::decode_json(duplicate.as_bytes()).is_err());
        let nested_duplicate = encoded.replacen(
            "\"protocol_era\":",
            "\"protocol_era\":1,\"protocol_era\":",
            1,
        );
        assert!(M0GenesisManifestFile::decode_json(nested_duplicate.as_bytes()).is_err());
    }
}
