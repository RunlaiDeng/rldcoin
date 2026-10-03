//! Finite compiled compatibility for evidenced upgrade transitions.
//! Entries pin complete historical artifact tuples. No runtime registry or
//! caller-provided compatibility declaration can add an accepted implementation.
use super::{upgrade_wire::ScheduleUpgradeV1, M0_ADMISSION_CONSENSUS_PROFILE};

struct HistoricalUpgradeArtifacts {
    source: &'static str,
    migration: &'static str,
    specification: &'static str,
    vectors: &'static str,
    activation: bool,
}

// Retained source snapshot b94a4d39b44dfa2c8f8239c47ea42352982010ee27af2b5a5b7b144157cfad60.
// Its signed schedule transcript and fixed successor root are retained in
// vectors/upgrade-history-v1. This first entry supports only pending creation.
const HISTORICAL_UPGRADES: &[HistoricalUpgradeArtifacts] = &[
    HistoricalUpgradeArtifacts {
        source: "b8e145ea013999720f7fe2ac161997493164d7938182f14a27a747cf940b973b",
        migration: "4769bac414b23616240d1bd284bf92747a434164b4bdfd4ba490a0419eb93e2a",
        specification: "0b334d8a03af6d7ce41a8e93ccc43b94116cfc874bd30be78a847dc4e37dd068",
        vectors: "6e0391084d6c611d1bc35dddf8a64962a1a2bf35a8a48c336527041be1e3b977",
        activation: false,
    },
    HistoricalUpgradeArtifacts {
        // Original snapshot d793a3139d534b89bd6cca5be7f03dcdee4b5706f3e8e43d58073b34a83e127b.
        // Its unmodified 130-block transcript and 132-record WAL are frozen in
        // vectors/upgrade-history-v1/activation-1c944737.
        source: "1c94473726631d13a546f5b2d2f4434e7beacb6aa550b85013d265f6a22bcab6",
        migration: "d74813090425d7954ef246cd6fdd408dc4440cb53d1e9f84d509d1284579d8e2",
        specification: "a307f7d4bd577b3e5934c7bbf5c2695346ec6f880ef0ffa89630e1bcedb28324",
        vectors: "6e0391084d6c611d1bc35dddf8a64962a1a2bf35a8a48c336527041be1e3b977",
        activation: true,
    },
];

pub(super) fn supports_schedule(schedule: &ScheduleUpgradeV1) -> bool {
    supports(schedule, false)
}

pub(super) fn supports_activation(schedule: &ScheduleUpgradeV1) -> bool {
    supports(schedule, true)
}

fn supports(schedule: &ScheduleUpgradeV1, activation: bool) -> bool {
    schedule.migration_id == super::upgrade_migration::FIRST_MIGRATION_ID
        && schedule.required_capabilities == [M0_ADMISSION_CONSENSUS_PROFILE]
        && HISTORICAL_UPGRADES.iter().any(|entry| {
            (!activation || entry.activation)
                && schedule.implementation_source_commitment.to_hex() == entry.source
                && schedule.migration_code_hash.to_hex() == entry.migration
                && schedule.specification_hash.to_hex() == entry.specification
                && schedule.vector_root.to_hex() == entry.vectors
        })
}
