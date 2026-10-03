use std::{fs, path::PathBuf};

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use rld_core::{
    AdmissionHash32, AdmissionLogConfigV1, AdmissionWork, ContributionEpochMappingV1, Identity,
    M0GenesisManifestFile, SignedM0GenesisManifest, SignedM0GenesisManifestV3,
};

#[path = "../candidate_history.rs"]
mod candidate_history;

#[derive(Parser)]
#[command(
    name = "rld-genesis",
    about = "Create and verify signed, content-addressed Rldcoin M0 genesis manifests"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
// This process parses exactly one command and exits; boxing individual
// ceremony arguments would complicate clap handling without reducing any
// retained runtime state.
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Show the compiled first-migration artifacts; grants no upgrade authority.
    UpgradeDescriptor,
    /// Print the build-embedded Rust source inventory; does not authorize upgrades.
    ImplementationSource,
    Create {
        /// Direct empty Earth genesis with Earth-specific signed domains.
        #[arg(long, conflicts_with = "candidate_v3")]
        earth: bool,
        /// Unreleased V3 candidate with a separate immutable upgrade constitution.
        #[arg(long)]
        candidate_v3: bool,
        #[arg(long)]
        zone_name: String,
        #[arg(long)]
        control_group_id: String,
        #[arg(long)]
        founder_key: PathBuf,
        #[arg(long = "validator-key", required = true)]
        validator_keys: Vec<PathBuf>,
        #[arg(long = "notary-key")]
        notary_keys: Vec<PathBuf>,
        #[arg(long)]
        admission_minimum_target: String,
        #[arg(long)]
        admission_maximum_target: String,
        #[arg(long)]
        admission_genesis_target: String,
        #[arg(long)]
        admission_confirmation_work_floor: String,
        #[arg(long)]
        admission_ledger_height_origin: u128,
        #[arg(long)]
        admission_contribution_epoch_origin: u128,
        #[arg(long)]
        admission_ledger_blocks_per_contribution_epoch: u128,
        #[arg(long)]
        admission_benchmark_sha256: String,
        #[arg(long)]
        out: PathBuf,
    },
    Verify {
        #[arg(long)]
        manifest: PathBuf,
    },
    /// Keyless, bounded replay of certified candidate history and raw Admission sources.
    VerifyCandidateHistory {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        manifest_sha256: String,
        #[arg(long)]
        history: PathBuf,
        /// Require the caller's expected final head, so a truncated prefix cannot pass.
        #[arg(long)]
        expected_height: u128,
        #[arg(long)]
        expected_state_root: String,
        /// Require exact finalized checkpoint membership, not merely received sources (max 64).
        #[arg(long = "require-admission-entry")]
        required_admission_entries: Vec<String>,
        /// Capture verified local Admission facts after this one-based history record.
        #[arg(long)]
        observe_admission_at_record: Option<usize>,
        /// Require every captured entry to have a finalized checkpoint inclusion.
        #[arg(long, requires = "observe_admission_at_record")]
        require_observed_inclusion: bool,
        /// Inspect a draft upgrade against the exact replayed final parent; no signing.
        #[arg(long, conflicts_with = "inspect_upgrade_schedule")]
        inspect_upgrade_intent: Option<PathBuf>,
        /// Inspect reserved schedule command bytes against authenticated final history.
        #[arg(long)]
        inspect_upgrade_schedule: Option<PathBuf>,
    },
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    match args.command {
        Command::UpgradeDescriptor => {
            println!(
                "{}",
                serde_json::json!({
                    "format": "RLD-COMPILED-UPGRADE-DESCRIPTOR-V1",
                    "scope": "LOCAL_PREVIEW_ONLY",
                    "implementation_source_commitment": rld_core::implementation_source::IMPLEMENTATION_SOURCE_COMMITMENT,
                    "migration": rld_core::genesis::upgrade_migration::first_migration_descriptor(),
                    "runtime_activation_enabled": false,
                    "signature_authorized": false,
                    "value_cap": "VALUE_CAP_0"
                })
            );
        }
        Command::ImplementationSource => {
            println!("{}", rld_core::implementation_source::manifest_json());
        }
        Command::Create {
            earth,
            candidate_v3,
            zone_name,
            control_group_id,
            founder_key,
            validator_keys,
            notary_keys,
            admission_minimum_target,
            admission_maximum_target,
            admission_genesis_target,
            admission_confirmation_work_floor,
            admission_ledger_height_origin,
            admission_contribution_epoch_origin,
            admission_ledger_blocks_per_contribution_epoch,
            admission_benchmark_sha256,
            out,
        } => {
            if out.exists() {
                bail!("refusing to overwrite existing manifest: {}", out.display());
            }
            if validator_keys.len() != 4 {
                bail!("M0 requires exactly four --validator-key arguments");
            }
            let founder = read_identity(&founder_key)?;
            let validators = validator_keys
                .iter()
                .map(|path| read_identity(path).map(|identity| identity.public_key))
                .collect::<anyhow::Result<Vec<_>>>()?;
            let notaries = notary_keys
                .iter()
                .map(|path| read_identity(path).map(|identity| identity.public_key))
                .collect::<anyhow::Result<Vec<_>>>()?;
            let admission_config = AdmissionLogConfigV1 {
                minimum_target: parse_admission_work(
                    "--admission-minimum-target",
                    &admission_minimum_target,
                )?,
                maximum_target: parse_admission_work(
                    "--admission-maximum-target",
                    &admission_maximum_target,
                )?,
                genesis_target: parse_admission_work(
                    "--admission-genesis-target",
                    &admission_genesis_target,
                )?,
                confirmation_work_floor: parse_admission_work(
                    "--admission-confirmation-work-floor",
                    &admission_confirmation_work_floor,
                )?,
                contribution_epoch_mapping: ContributionEpochMappingV1 {
                    ledger_height_origin: admission_ledger_height_origin,
                    contribution_epoch_origin: admission_contribution_epoch_origin,
                    ledger_blocks_per_contribution_epoch:
                        admission_ledger_blocks_per_contribution_epoch,
                },
            };
            let admission_benchmark = AdmissionHash32::from_hex(&admission_benchmark_sha256)
                .map_err(|error| {
                    anyhow::anyhow!("invalid --admission-benchmark-sha256: {error}")
                })?;
            let manifest = if earth {
                M0GenesisManifestFile::V3(
                    SignedM0GenesisManifestV3::create_earth(
                        zone_name,
                        validators,
                        notaries,
                        control_group_id,
                        admission_config,
                        admission_benchmark,
                        &founder,
                    )
                    .map_err(anyhow::Error::msg)?,
                )
            } else if candidate_v3 {
                M0GenesisManifestFile::V3(
                    SignedM0GenesisManifestV3::create(
                        zone_name,
                        validators,
                        notaries,
                        control_group_id,
                        admission_config,
                        admission_benchmark,
                        &founder,
                    )
                    .map_err(anyhow::Error::msg)?,
                )
            } else {
                M0GenesisManifestFile::V2(
                    SignedM0GenesisManifest::create(
                        zone_name,
                        validators,
                        notaries,
                        control_group_id,
                        admission_config,
                        admission_benchmark,
                        &founder,
                    )
                    .map_err(anyhow::Error::msg)?,
                )
            };
            fs::write(&out, serde_json::to_vec_pretty(&manifest)?)?;
            println!("manifest: {}", out.display());
            println!("manifest_sha256: {}", manifest.manifest_sha256());
            println!("zone_id: {}", manifest.descriptor().zone_id);
            println!("genesis_root: {}", manifest.descriptor().genesis_root);
            println!("genesis_state_root: {}", manifest.genesis_state_root());
            println!(
                "admission_genesis_header: {}",
                manifest.admission_genesis().genesis_header.to_hex()
            );
            println!(
                "admission_benchmark_sha256: {}",
                manifest
                    .admission_genesis()
                    .benchmark_report_sha256
                    .to_hex()
            );
            print_epoch_mapping(&manifest);
        }
        Command::Verify { manifest } => {
            let manifest = read_manifest(&manifest)?;
            manifest.verify().map_err(anyhow::Error::msg)?;
            println!("VERIFIED");
            println!("manifest_sha256: {}", manifest.manifest_sha256());
            println!("zone_id: {}", manifest.descriptor().zone_id);
            println!("value_cap: VALUE_CAP_0");
            println!("control_group_count: 1");
            println!(
                "admission_genesis_header: {}",
                manifest.admission_genesis().genesis_header.to_hex()
            );
            print_epoch_mapping(&manifest);
        }
        Command::VerifyCandidateHistory {
            manifest,
            manifest_sha256,
            history,
            expected_height,
            expected_state_root,
            required_admission_entries,
            observe_admission_at_record,
            require_observed_inclusion,
            inspect_upgrade_intent,
            inspect_upgrade_schedule,
        } => {
            candidate_history::verify(
                &manifest,
                &manifest_sha256,
                &history,
                expected_height,
                &expected_state_root,
                candidate_history::HistoryQueries {
                    required_admission_entries: &required_admission_entries,
                    observe_admission_at_record,
                    require_observed_inclusion,
                    inspect_upgrade_intent: inspect_upgrade_intent.as_deref(),
                    inspect_upgrade_schedule: inspect_upgrade_schedule.as_deref(),
                },
            )?;
        }
    }
    Ok(())
}

fn print_epoch_mapping(manifest: &M0GenesisManifestFile) {
    let mapping = &manifest
        .admission_genesis()
        .config
        .contribution_epoch_mapping;
    println!(
        "admission_ledger_height_origin: {}",
        mapping.ledger_height_origin
    );
    println!(
        "admission_contribution_epoch_origin: {}",
        mapping.contribution_epoch_origin
    );
    println!(
        "admission_ledger_blocks_per_contribution_epoch: {}",
        mapping.ledger_blocks_per_contribution_epoch
    );
}

fn parse_admission_work(argument: &str, value: &str) -> anyhow::Result<AdmissionWork> {
    AdmissionWork::from_hex(value).map_err(|error| anyhow::anyhow!("invalid {argument}: {error}"))
}

fn read_identity(path: &PathBuf) -> anyhow::Result<Identity> {
    let bytes = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("invalid identity {}", path.display()))
}

fn read_manifest(path: &PathBuf) -> anyhow::Result<M0GenesisManifestFile> {
    use std::io::Read;
    let mut bytes = Vec::new();
    fs::File::open(path)
        .with_context(|| format!("cannot read {}", path.display()))?
        .take(65_537)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 65_536 {
        bail!("M0 genesis manifest exceeds 64 KiB");
    }
    M0GenesisManifestFile::decode_json(&bytes)
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("invalid manifest {}", path.display()))
}
