//! Offline four-key finality signing with durable local anti-equivocation locks.
//! The source node independently replays and verifies the result on install.

use anyhow::{anyhow, bail, Result};
use clap::Parser;
use rld_core::{sign_bytes, verify_bytes, AdmissionHash32 as Hash, Identity};
use rld_pow::transition::{Adoption, Approval};
use rld_value_successor::{
    adoption::EarthSuccessorAdoption,
    chain::finality::{FinalityCertificate, FinalityStatement, FORMAT},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    statement: PathBuf,
    #[arg(long)]
    pow_adoption: PathBuf,
    #[arg(long)]
    earth_adoption: PathBuf,
    #[arg(long, required = true, num_args = 4)]
    validator_key: Vec<PathBuf>,
    #[arg(long)]
    lock_dir: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    confirm_reviewed_source: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignerLock {
    source_chain_id: Hash,
    earth_adoption_id: Hash,
    certificate_id: Hash,
    #[serde(with = "rld_pow::decimal")]
    height: u128,
    block: Hash,
}

fn read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > limit as u64 {
        bail!("unsafe or oversized finality input");
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        bail!("finality input exceeded bound");
    }
    Ok(bytes)
}

fn canonical<T: DeserializeOwned + Serialize>(path: &Path, limit: usize) -> Result<T> {
    let bytes = read(path, limit)?;
    let value: T = serde_json::from_slice(&bytes)?;
    if serde_json::to_vec(&value)? != bytes {
        bail!("noncanonical finality input");
    }
    Ok(value)
}

fn durable_write(path: &Path, bytes: &[u8], replace: bool) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("missing finality output directory"))?;
    let pending = path.with_extension("pending");
    if pending.exists() {
        bail!("unfinished finality write requires operator recovery");
    }
    if !replace && path.exists() {
        bail!("finality output already exists");
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&pending)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&pending, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    if !args.confirm_reviewed_source {
        bail!("reviewed source checkpoint confirmation required");
    }
    if args.output.exists() {
        bail!("finality output already exists");
    }
    let statement: FinalityStatement = canonical(&args.statement, 4096)?;
    let pow: Adoption = serde_json::from_slice(&read(&args.pow_adoption, 65_536)?)?;
    let earth: EarthSuccessorAdoption = canonical(&args.earth_adoption, 8192)?;
    if statement.format != FORMAT
        || statement.source_chain_id != earth.statement.fresh_chain_id
        || statement.source_v1_tip != earth.statement.v1_tip
        || statement.earth_adoption_id != earth.statement.id().map_err(|e| anyhow!(e))?
        || pow.approvals.len() != 4
        || earth.approvals.len() != 4
    {
        bail!("finality statement differs from four-key Earth adoption");
    }
    let expected = pow
        .approvals
        .iter()
        .map(|a| a.public_key.as_str())
        .collect::<Vec<_>>();
    if expected.windows(2).any(|pair| pair[0] >= pair[1]) {
        bail!("unsorted PoW validator set");
    }
    if earth
        .approvals
        .iter()
        .map(|a| a.public_key.as_str())
        .collect::<Vec<_>>()
        != expected
    {
        bail!("successor adoption validators differ from PoW validators");
    }
    let mut keys = args
        .validator_key
        .iter()
        .map(|path| Ok(serde_json::from_slice::<Identity>(&read(path, 16_384)?)?))
        .collect::<Result<Vec<_>>>()?;
    keys.sort_by(|left, right| left.public_key.cmp(&right.public_key));
    if keys
        .iter()
        .map(|key| key.public_key.as_str())
        .collect::<Vec<_>>()
        != expected
    {
        bail!("finality signing keys differ from adopted validator set");
    }
    if args.lock_dir.exists() {
        let meta = fs::symlink_metadata(&args.lock_dir)?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            bail!("unsafe finality lock directory");
        }
    } else {
        fs::create_dir(&args.lock_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&args.lock_dir, fs::Permissions::from_mode(0o700))?;
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&args.lock_dir)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            bail!("finality lock directory must be private (0700)");
        }
    }
    let ceremony_path = args.lock_dir.join(".ceremony.lock");
    if ceremony_path.exists()
        && fs::symlink_metadata(&ceremony_path)?
            .file_type()
            .is_symlink()
    {
        bail!("unsafe finality ceremony lock");
    }
    let ceremony = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(ceremony_path)?;
    ceremony.try_lock()?;
    let id = statement.id().map_err(|e| anyhow!(e))?;
    let mut lock_paths = Vec::new();
    for key in &keys {
        let path = args.lock_dir.join(format!("{}.json", key.public_key));
        if path.exists() {
            let prior: SignerLock = canonical(&path, 4096)?;
            let retry = prior.certificate_id == id
                && prior.height == statement.height
                && prior.block == statement.block;
            let advance = statement.previous_certificate == Some(prior.certificate_id)
                && statement.height > prior.height
                && statement.block != prior.block;
            if prior.source_chain_id != statement.source_chain_id
                || prior.earth_adoption_id != statement.earth_adoption_id
                || (!retry && !advance)
            {
                bail!("validator finality lock rejects conflicting or skipped checkpoint");
            }
        } else if statement.previous_certificate.is_some() {
            bail!("missing durable validator predecessor lock");
        }
        lock_paths.push(path);
    }
    let next = SignerLock {
        source_chain_id: statement.source_chain_id,
        earth_adoption_id: statement.earth_adoption_id,
        certificate_id: id,
        height: statement.height,
        block: statement.block,
    };
    let lock_bytes = serde_json::to_vec(&next)?;
    for path in &lock_paths {
        durable_write(path, &lock_bytes, true)?;
    }
    let bytes = statement.signing_bytes().map_err(|e| anyhow!(e))?;
    let mut approvals = Vec::new();
    for key in keys {
        let signature = sign_bytes(&key.secret_key, &bytes).map_err(|e| anyhow!(e))?;
        verify_bytes(&key.public_key, &bytes, &signature).map_err(|e| anyhow!(e))?;
        approvals.push(Approval {
            public_key: key.public_key,
            signature,
        });
    }
    let certificate = FinalityCertificate {
        statement,
        approvals,
    };
    durable_write(&args.output, &serde_json::to_vec(&certificate)?, false)?;
    println!(
        "{}",
        serde_json::json!({
            "result":"SIGNED_EARTH_SOURCE_FINALITY",
            "certificate_id":id,
            "height":certificate.statement.height.to_string(),
            "source_install_required":true
        })
    );
    Ok(())
}
