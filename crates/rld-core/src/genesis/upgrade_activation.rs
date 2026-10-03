//! Live-build activation preflight. Not a historical replay compatibility
//! resolver, migration evaluator, certificate or signing authorization.
use super::upgrade_wire::ActivateUpgradeV1;
use crate::{hash_bytes, Ledger, ValueCap};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct UpgradeActivationPreflight {
    parent_height: String,
    parent_state_root: String,
    activation_height: String,
    intent_id: String,
    command_sha256: String,
    pending_state_sha256: String,
    implementation_source_commitment: String,
    migration_verified: bool,
    schedule_finality_verified: bool,
    signature_authorized: bool,
}

impl Ledger {
    /// Checks the exact activation boundary for this installed build. The caller
    /// must still authenticate the schedule via main-WAL replay and validate a
    /// compiled migration before any signature or state replacement. The report
    /// deliberately exposes no successor Ledger and no conversion to authority.
    pub fn inspect_upgrade_activation_for_current_build(
        &self,
        activation: &ActivateUpgradeV1,
    ) -> Result<UpgradeActivationPreflight, String> {
        self.validate_upgrade_activation_context(activation)?;
        let pending = self
            .m0_pending_upgrade
            .as_ref()
            .ok_or("no pending upgrade")?;
        let schedule = &pending.schedule;
        let intent_id = schedule.intent_id()?;
        let source = crate::implementation_source::IMPLEMENTATION_SOURCE_COMMITMENT;
        if schedule.implementation_source_commitment.to_hex() != source {
            return Err(
                "installed implementation source does not match scheduled activation".into(),
            );
        }
        Ok(UpgradeActivationPreflight {
            parent_height: self.height.to_string(),
            parent_state_root: self.state_root().map_err(|e| e.to_string())?,
            activation_height: schedule.activation_height.to_string(),
            intent_id,
            command_sha256: hash_bytes(&activation.candidate_command_bytes()?),
            pending_state_sha256: hash_bytes(&pending.canonical_bytes()?),
            implementation_source_commitment: source.into(),
            migration_verified: false,
            schedule_finality_verified: false,
            signature_authorized: false,
        })
    }
    /// Context validation shared by semantic historical replay and strict
    /// installed-build preflight. This does not select or authorize migration.
    pub(crate) fn validate_upgrade_activation_context(
        &self,
        activation: &ActivateUpgradeV1,
    ) -> Result<(), String> {
        activation.canonical_bytes()?;
        self.m0_admission_genesis().map_err(|e| e.to_string())?;
        if self.value_risk_policy.current_cap != ValueCap::ValueCap0
            || self.value_risk_policy.ever_enabled
            || self.value_risk_policy.pending_update.is_some()
        {
            return Err("bootstrap activation requires unchanged VALUE_CAP_0".into());
        }
        let pending = self
            .m0_pending_upgrade
            .as_ref()
            .ok_or("no pending upgrade to activate")?;
        let schedule = &pending.schedule;
        let intent_id = schedule.intent_id()?;
        if activation.network_domain != schedule.network_domain
            || activation.zone_id != schedule.zone_id
            || activation.currency_genesis != schedule.currency_genesis
            || activation.protocol_era != schedule.protocol_era
            || activation.crypto_era != schedule.crypto_era
            || activation.sequence != schedule.sequence
            || activation.activation_height != schedule.activation_height
            || activation.intent_id.to_hex() != intent_id
        {
            return Err("activation differs from the exact retained schedule".into());
        }
        let next = self
            .height
            .checked_add(1)
            .ok_or("activation exceeds current U64 Ledger height domain")?;
        if u128::from(next) != schedule.activation_height {
            return Err("activation is not the exact next scheduled height".into());
        }
        Ok(())
    }
}
