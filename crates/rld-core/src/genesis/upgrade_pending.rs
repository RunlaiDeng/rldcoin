//! Rooted pending-state evaluator. Creation remains a read-only preview until
//! compiled migration and finalized command authorization are connected.
use super::{upgrade_wire::ScheduleUpgradeV1, v3::decimal_u128};
use crate::{
    hash_bytes, AdmissionHash32, Ledger, M0ActiveProtocolStateV1, M0NetworkBirthStateV3,
    ZoneDescriptor,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingUpgradeV1 {
    pub format_version: String,
    #[serde(with = "decimal_u128")]
    pub scheduled_height: u128,
    pub scheduled_parent_root: AdmissionHash32,
    pub schedule: ScheduleUpgradeV1,
}

impl PendingUpgradeV1 {
    pub(crate) fn from_parent(
        parent: &Ledger,
        schedule: &ScheduleUpgradeV1,
    ) -> Result<Self, String> {
        if parent.m0_pending_upgrade.is_some() {
            return Err("an upgrade is already pending".into());
        }
        schedule.check_bootstrap_parent(parent)?;
        let scheduled_height = u128::from(parent.height)
            .checked_add(1)
            .ok_or("schedule height exhausted")?;
        Ok(Self {
            format_version: "RLD-PENDING-UPGRADE-V1".into(),
            scheduled_height,
            scheduled_parent_root: AdmissionHash32::from_hex(
                &parent.state_root().map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?,
            schedule: schedule.clone(),
        })
    }

    /// Structural restoration checks; parent ancestry is authenticated by WAL
    /// replay, never by this record's caller-supplied parent hash.
    pub fn validate(
        &self,
        descriptor: &ZoneDescriptor,
        birth: &M0NetworkBirthStateV3,
        active: &M0ActiveProtocolStateV1,
        height: u128,
    ) -> Result<(), String> {
        self.canonical_bytes()?;
        birth.validate_for_descriptor(descriptor)?;
        active.validate_for_birth(birth)?;
        let s = &self.schedule;
        if s.activation_height > u128::from(u64::MAX) {
            return Err("pending activation exceeds the current U64 Ledger height domain".into());
        }
        if active.upgrade_sequence != 0
            || s.network_domain != descriptor.network_domain
            || s.zone_id != descriptor.zone_id
            || s.currency_genesis.to_hex() != descriptor.currency_genesis_root
            || s.protocol_era != u128::from(descriptor.protocol_era)
            || s.crypto_era != u128::from(descriptor.crypto_era)
            || s.sequence != 1
            || s.prior_finalized_upgrade.is_some()
            || s.prior_active_commitment.to_hex() != hash_bytes(&active.canonical_bytes()?)
            || s.immutable_invariant_commitment.to_hex() != hash_bytes(&birth.canonical_bytes()?)
        {
            return Err("pending upgrade differs from immutable context or active state".into());
        }
        let delay = birth
            .admission_genesis
            .config
            .contribution_epoch_mapping
            .ledger_blocks_per_contribution_epoch
            .checked_mul(u128::from(
                birth.upgrade_constitution.minimum_activation_delay_epochs,
            ))
            .ok_or("upgrade delay overflow")?;
        let earliest = self
            .scheduled_height
            .checked_add(delay)
            .ok_or("activation height overflow")?;
        if s.activation_height < earliest
            || height < self.scheduled_height
            || height >= s.activation_height
        {
            return Err("pending upgrade delay or retained height is invalid".into());
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        if self.format_version != "RLD-PENDING-UPGRADE-V1"
            || self.scheduled_height == 0
            || self.scheduled_parent_root.is_zero()
        {
            return Err("invalid pending upgrade envelope".into());
        }
        let raw = self.schedule.canonical_bytes()?;
        let mut bytes = b"RLD-PENDING-UPGRADE-BYTES-V1\0".to_vec();
        bytes.extend_from_slice(&self.scheduled_height.to_be_bytes());
        bytes.extend_from_slice(&self.scheduled_parent_root.0);
        bytes.extend_from_slice(&(raw.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&raw);
        Ok(bytes)
    }
}
