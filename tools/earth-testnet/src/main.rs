//! Public fixture keys, fresh empty ledgers and no mainnet mode.
use anyhow::{ensure, Result};
use ed25519_dalek::SigningKey;
use rld_core::{header_work, sign_bytes, AdmissionHash32 as Hash, Amount};
use rld_pow::transition::{Adoption, AdoptionStatement, Approval, FORMAT};
use rld_value_successor::{
    adoption::{EarthSuccessorAdoption, EarthSuccessorAdoptionStatement},
    chain::ObservationPolicy,
    destination::pow::{
        authorization::{
            DestinationGenesisAuthorization, DestinationGenesisAuthorizationStatement,
        },
        Context as DestinationContext, SourceFinalityTrust,
    },
    transition::TransitionPreview,
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

fn hash(bytes: &[u8]) -> Hash {
    Hash(Sha256::digest(bytes).into())
}
fn public(seed: u8) -> String {
    hex::encode(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
}
fn approvals(bytes: &[u8]) -> Result<Vec<Approval>> {
    let mut result = Vec::new();
    for seed in 2..=5 {
        result.push(Approval {
            public_key: public(seed),
            signature: sign_bytes(&hex::encode([seed; 32]), bytes)
                .map_err(|e| anyhow::anyhow!(e))?,
        });
    }
    result.sort_by(|a, b| a.public_key.cmp(&b.public_key));
    Ok(result)
}
fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let dir = PathBuf::from(
        args.next()
            .ok_or_else(|| anyhow::anyhow!("supply a NEW absolute testnet directory"))
            .map_err(|e| anyhow::anyhow!(e))?,
    );
    ensure!(
        args.next().is_none(),
        "no production mode or additional input is accepted"
    );
    ensure!(
        dir.is_absolute() && !dir.exists(),
        "test directory must be new and absolute"
    );
    let parent = dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("missing parent"))
        .map_err(|e| anyhow::anyhow!(e))?;
    ensure!(
        fs::symlink_metadata(parent)
            .map_err(|e| anyhow::anyhow!(e))?
            .is_dir()
            && !fs::symlink_metadata(parent)
                .map_err(|e| anyhow::anyhow!(e))?
                .file_type()
                .is_symlink(),
        "unsafe parent"
    );
    let genesis = include_bytes!("../../../vectors/m0-genesis-v3/manifest.json");
    let manifest =
        rld_core::M0GenesisManifestFile::decode_json(genesis).map_err(|e| anyhow::anyhow!(e))?;
    let descriptor = manifest.descriptor();
    let pin = Hash::from_hex(manifest.manifest_sha256()).map_err(|e| anyhow::anyhow!(e))?;
    let source = Hash::from_hex(rld_core::implementation_source::IMPLEMENTATION_SOURCE_COMMITMENT)
        .map_err(|e| anyhow::anyhow!(e))?;
    let started = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| anyhow::anyhow!(e))?
        .as_secs();
    // This is a qualification profile, not a selected production interval.
    let timing = rld_regional_rules::RegionTiming::new(600).map_err(|e| anyhow::anyhow!(e))?;
    let statement = AdoptionStatement {
        format: FORMAT.into(),
        manifest_pin: pin,
        network_domain: descriptor.network_domain.clone(),
        zone_id: descriptor.zone_id.clone(),
        currency_genesis: Hash::from_hex(&descriptor.currency_genesis_root)
            .map_err(|e| anyhow::anyhow!(e))?,
        legacy_height: 0,
        legacy_state_root: Hash::from_hex(manifest.genesis_state_root())
            .map_err(|e| anyhow::anyhow!(e))?,
        legacy_history_sha256: hash(b"[]"),
        rules_sha256: rld_pow::transition::regional_rules_hash(&timing)
            .map_err(|e| anyhow::anyhow!(e))?,
        implementation_source_sha256: source,
        started_at: started,
        initial_target: rld_pow::target_limit(),
        regional: Some(timing.clone()),
        old_service_reserves_reassigned: Amount::TOTAL_SUPPLY,
        personal_allocation: Amount::ZERO,
        incompatible_with_m0_constitution: true,
    };
    let signed = Adoption {
        approvals: approvals(&statement.signing_bytes().map_err(|e| anyhow::anyhow!(e))?)
            .map_err(|e| anyhow::anyhow!(e))?,
        statement,
    };
    let adoption_id = signed.statement.id().map_err(|e| anyhow::anyhow!(e))?;
    let context = signed
        .verify(genesis, b"[]", pin, adoption_id)
        .map_err(|e| anyhow::anyhow!(e))?;
    let chain = rld_pow::Chain::new(context).map_err(|e| anyhow::anyhow!(e))?;
    ensure!(chain.height() == 0, "fresh genesis required");
    let preview =
        TransitionPreview::from_replayed_v1(&chain, source).map_err(|e| anyhow::anyhow!(e))?;
    let statement = EarthSuccessorAdoptionStatement::from_replayed_fresh_chain(&chain, &preview)
        .map_err(|e| anyhow::anyhow!(e))?;
    let earth = EarthSuccessorAdoption {
        approvals: approvals(&statement.signing_bytes().map_err(|e| anyhow::anyhow!(e))?)
            .map_err(|e| anyhow::anyhow!(e))?,
        statement,
    };
    let earth_id = earth.statement.id().map_err(|e| anyhow::anyhow!(e))?;
    earth
        .verify(genesis, b"[]", &signed, &chain, &preview, earth_id)
        .map_err(|e| anyhow::anyhow!(e))?;
    let mut destination = DestinationContext {
        chain_id: Hash([99; 32]),
        source_policy: ObservationPolicy {
            source_chain_id: chain.context.chain_id().map_err(|e| anyhow::anyhow!(e))?,
            accepted_v1_tip: chain.tip(),
            minimum_confirmations: timing.finality_confirmations.into(),
            minimum_cumulative_work: chain
                .chainwork()
                .checked_add(header_work(rld_pow::target_limit()))
                .ok_or_else(|| anyhow::anyhow!("work overflow"))
                .map_err(|e| anyhow::anyhow!(e))?,
        },
        started_at: started,
        initial_target: rld_pow::target_limit(),
        regional: Some(timing),
        migration: None,
        source_finality: Some(SourceFinalityTrust {
            earth_adoption_id: earth_id,
            validator_keys: earth
                .approvals
                .iter()
                .map(|a| a.public_key.clone())
                .collect(),
        }),
    };
    destination.chain_id = destination
        .regional_chain_id(source)
        .map_err(|e| anyhow::anyhow!(e))?;
    let statement = DestinationGenesisAuthorizationStatement::from_context(&destination, &preview)
        .map_err(|e| anyhow::anyhow!(e))?;
    let auth_id = statement.id().map_err(|e| anyhow::anyhow!(e))?;
    let auth = DestinationGenesisAuthorization {
        signature: sign_bytes(
            &hex::encode([61; 32]),
            &statement.signing_bytes().map_err(|e| anyhow::anyhow!(e))?,
        )
        .map_err(|e| anyhow::anyhow!(e))?,
        signer_public_key: public(61),
        statement,
    };
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(|e| anyhow::anyhow!(e))?;
    fs::write(dir.join("genesis.json"), genesis).map_err(|e| anyhow::anyhow!(e))?;
    fs::write(dir.join("history.json"), b"[]").map_err(|e| anyhow::anyhow!(e))?;
    fs::write(
        dir.join("adoption.json"),
        serde_json::to_vec(&signed).map_err(|e| anyhow::anyhow!(e))?,
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    fs::write(
        dir.join("transition-preview.json"),
        preview.canonical_bytes().map_err(|e| anyhow::anyhow!(e))?,
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    fs::write(
        dir.join("earth-adoption.json"),
        serde_json::to_vec(&earth).map_err(|e| anyhow::anyhow!(e))?,
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    fs::write(
        dir.join("destination-context.json"),
        serde_json::to_vec(&destination).map_err(|e| anyhow::anyhow!(e))?,
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    fs::write(
        dir.join("destination-authorization.json"),
        auth.canonical_bytes().map_err(|e| anyhow::anyhow!(e))?,
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    let pins = serde_json::json!({
        "format":"RLD-EARTH-FRESH-TESTNET-V1", "test_only":true, "has_monetary_value":false,
        "mainnet_authorized":false, "old_balances_migrate":false, "initial_source_height":"0", "initial_source_issued":"0",
        "manifest_pin":pin.to_hex(), "adoption_id":adoption_id.to_hex(),
        "implementation_source":source.to_hex(), "preview_id":preview.id().map_err(|e| anyhow::anyhow!(e))?.to_hex(), "earth_adoption_id":earth_id.to_hex(),
        "source_chain_id":chain.context.chain_id().map_err(|e| anyhow::anyhow!(e))?.to_hex(), "destination_chain_id":destination.chain_id.to_hex(),
        "destination_authorization_id":auth_id.to_hex(), "destination_signer":public(61), "miner":public(60),
        "public_fixture_validator_seeds":[2,3,4,5], "public_fixture_miner_seed":60,
        "qualification_target_seconds":600, "production_interval_selected":false,
    });
    fs::write(
        dir.join("testnet.json"),
        serde_json::to_vec_pretty(&pins).map_err(|e| anyhow::anyhow!(e))?,
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&pins).map_err(|e| anyhow::anyhow!(e))?
    );
    Ok(())
}
