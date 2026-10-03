//! Finite candidate migration evaluator. No live role authorization,
//! external code loading or signing authority. Historical schedule support is
//! a separate finite registry; installed-build preflight remains exact.
use super::{
    upgrade_wire::ActivateUpgradeV1, M0ActiveProtocolStateV1, M0_ACTIVE_PROTOCOL_V2,
    M0_ADMISSION_CONSENSUS_PROFILE,
};
use crate::{hash_bytes, Ledger};
use serde::Serialize;

pub const FIRST_MIGRATION_ID: &str = "M0_HEARTBEAT_TO_ADMISSION_CHECKPOINT_V1";

#[derive(Clone, Debug, Serialize)]
pub struct CompiledMigrationDescriptor {
    pub migration_id: String,
    pub migration_code_hash: String,
    pub specification_hash: String,
    pub vector_root: String,
    pub required_capabilities: Vec<String>,
}

/// Describes exactly the compiled evaluator. These hashes bind artifacts; they
/// are not evidence of independent review or full multi-role qualification.
pub fn first_migration_descriptor() -> CompiledMigrationDescriptor {
    CompiledMigrationDescriptor {
        migration_id: FIRST_MIGRATION_ID.into(),
        migration_code_hash: hash_bytes(include_bytes!("upgrade_migration.rs")),
        specification_hash: hash_bytes(include_bytes!(
            "../../../../docs/spec/SAME-GENESIS-UPGRADE-CONTRACT.md"
        )),
        vector_root: hash_bytes(include_bytes!(
            "../../../../vectors/upgrade-migration-v1/vectors.json"
        )),
        required_capabilities: vec![M0_ADMISSION_CONSENSUS_PROFILE.into()],
    }
}

pub(crate) fn validate_first_schedule_artifacts(
    schedule: &super::upgrade_wire::ScheduleUpgradeV1,
) -> Result<(), String> {
    if super::upgrade_compatibility::supports_schedule(schedule) {
        return Ok(());
    }
    validate_current_schedule_artifacts(schedule)
}

pub(crate) fn validate_current_schedule_artifacts(
    schedule: &super::upgrade_wire::ScheduleUpgradeV1,
) -> Result<(), String> {
    let expected = first_migration_descriptor();
    if schedule.implementation_source_commitment.to_hex()
        != crate::implementation_source::IMPLEMENTATION_SOURCE_COMMITMENT
        || schedule.migration_id != expected.migration_id
        || schedule.migration_code_hash.to_hex() != expected.migration_code_hash
        || schedule.specification_hash.to_hex() != expected.specification_hash
        || schedule.vector_root.to_hex() != expected.vector_root
        || schedule.required_capabilities != expected.required_capabilities
    {
        return Err("schedule does not match this build's compiled migration artifacts".into());
    }
    Ok(())
}

impl Ledger {
    /// Executes the one compiled candidate migration on a clone. This is not
    /// finalized activation: callers cannot use the result as proof of committee
    /// approval, replace main-WAL state or bypass existing signer/witness guards.
    pub fn preview_first_upgrade_activation(
        &self,
        activation: &ActivateUpgradeV1,
    ) -> Result<Self, String> {
        self.inspect_upgrade_activation_for_current_build(activation)?;
        let schedule = &self
            .m0_pending_upgrade
            .as_ref()
            .ok_or("no pending upgrade")?
            .schedule;
        validate_current_schedule_artifacts(schedule).map_err(|_| {
            "schedule does not select the exact compiled first migration artifacts".to_owned()
        })?;
        self.preview_supported_upgrade_activation(activation)
    }

    /// Consensus semantics can reproduce a finite evidenced historical tuple.
    /// Live signing still needs separate installed-build preflight and policy.
    pub(crate) fn validate_supported_upgrade_activation(
        &self,
        activation: &ActivateUpgradeV1,
    ) -> Result<(), String> {
        self.validate_upgrade_activation_context(activation)?;
        let schedule = &self
            .m0_pending_upgrade
            .as_ref()
            .ok_or("no pending upgrade")?
            .schedule;
        if super::upgrade_compatibility::supports_activation(schedule)
            || validate_current_schedule_artifacts(schedule).is_ok()
        {
            Ok(())
        } else {
            Err("schedule is not a supported compiled activation tuple".into())
        }
    }

    pub(crate) fn preview_supported_upgrade_activation(
        &self,
        activation: &ActivateUpgradeV1,
    ) -> Result<Self, String> {
        self.validate_supported_upgrade_activation(activation)?;
        self.assert_conservation().map_err(|e| e.to_string())?;
        let pending = self
            .m0_pending_upgrade
            .as_ref()
            .ok_or("no pending upgrade")?;
        let schedule = &pending.schedule;
        let prior = self
            .m0_active_protocol
            .as_ref()
            .ok_or("missing prior active state")?;
        if prior.upgrade_sequence != 0 {
            return Err("first migration requires the initial active state".into());
        }
        let mut next = self.clone();
        next.height = next
            .height
            .checked_add(1)
            .ok_or("activation height overflow")?;
        next.m0_active_protocol = Some(M0ActiveProtocolStateV1 {
            format_version: M0_ACTIVE_PROTOCOL_V2.into(),
            constitution_commitment: prior.constitution_commitment.clone(),
            upgrade_sequence: 1,
            consensus_profile: M0_ADMISSION_CONSENSUS_PROFILE.into(),
            founder_special_slot_ceiling: prior.founder_special_slot_ceiling,
            last_activated_upgrade: Some(schedule.intent_id()?),
            prior_active_commitment: Some(hash_bytes(&prior.canonical_bytes()?)),
        });
        next.m0_pending_upgrade = None;
        next.assert_conservation().map_err(|e| e.to_string())?;
        next.state_root().map_err(|e| e.to_string())?;
        // Compare the whole serialized Ledger, including root-excluded locks
        // and bookkeeping. Equal asset roots alone are not preservation proof.
        let before = serde_json::to_value(self).map_err(|e| e.to_string())?;
        let mut normalized = serde_json::to_value(&next).map_err(|e| e.to_string())?;
        for field in ["height", "m0_active_protocol", "m0_pending_upgrade"] {
            normalized[field] = before[field].clone();
        }
        if normalized != before {
            return Err("migration changed protected Ledger state".into());
        }
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn active_state_successor_bytes_match_independent_vectors() {
        let corpus: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../vectors/upgrade-migration-v1/vectors.json"
        ))
        .unwrap();
        for case in corpus["cases"].as_array().unwrap() {
            let active: M0ActiveProtocolStateV1 =
                serde_json::from_value(case["value"].clone()).unwrap();
            let bytes = active.canonical_bytes().unwrap();
            assert_eq!(hex::encode(&bytes), case["bytes_hex"]);
            assert_eq!(hash_bytes(&bytes), case["sha256"]);
        }
    }
}
