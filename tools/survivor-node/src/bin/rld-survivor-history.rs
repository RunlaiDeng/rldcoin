//! Bounded ordinary-store history measurement. Public NO-VALUE owner derivation;
//! logical chain time and actual nonce search/storage are reported separately.
use ed25519_dalek::SigningKey;
use rld_survivor_node::{
    kernel::{genesis_id, Result},
    store::{CommitBoundary, Limits, Store},
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::Path,
    time::{Duration, Instant},
};
fn emit(value: serde_json::Value) -> Result<()> {
    println!("{value}");
    std::io::stdout().flush().map_err(|e| e.to_string())
}
fn private_file(path: &Path, raw: &[u8]) -> Result<()> {
    let mut o = OpenOptions::new();
    o.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path).map_err(|e| e.to_string())?;
    f.write_all(raw)
        .and_then(|_| f.sync_all())
        .map_err(|e| e.to_string())
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if !(4..=5).contains(&args.len()) {
        return Err("Usage: rld-survivor-history FRESH_DIRECTORY BLOCKS BUDGET_SECONDS [GROUP_SIZE_1_TO_32]".into());
    }
    let target: u64 = args[2].parse().map_err(|_| "INVALID block count")?;
    let seconds: u64 = args[3].parse().map_err(|_| "INVALID budget")?;
    let group: u64 = args
        .get(4)
        .map(|x| x.parse())
        .transpose()
        .map_err(|_| "INVALID group size")?
        .unwrap_or(1);
    if target == 0 || !(1..=3600).contains(&seconds) || !(1..=32).contains(&group) {
        return Err("INVALID positive target or 1..3600-second observation budget".into());
    }
    let started = Instant::now();
    let budget = Duration::from_secs(seconds);
    let check = || {
        if started.elapsed() < budget {
            Ok(())
        } else {
            Err("RESOURCE_WAIT original observation budget exhausted".to_string())
        }
    };
    let root = Path::new(&args[1]);
    fs::create_dir(root).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    }
    File::open(
        root.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )
    .and_then(|f| f.sync_all())
    .map_err(|e| e.to_string())?;
    let start = 1_000_000u64;
    start
        .checked_add(
            target
                .checked_mul(600)
                .ok_or("INVALID logical time range")?,
        )
        .ok_or("INVALID logical time range")?;
    let mut genesis = b"RLDSGEN1".to_vec();
    genesis.extend(1u16.to_be_bytes());
    genesis.extend(1u16.to_be_bytes());
    genesis.push(0);
    let mut discriminator = [0; 32];
    getrandom::getrandom(&mut discriminator).map_err(|e| e.to_string())?;
    genesis.extend(discriminator);
    genesis.extend(start.to_be_bytes());
    genesis.push(0);
    genesis.extend([255; 31]);
    let pin = genesis_id(&genesis);
    private_file(&root.join("genesis.bin"), &genesis)?;
    let mut store = Store::open(&root.join("node"), &genesis, pin, Limits::default())?;
    let owners: Vec<_> = (0u16..256)
        .map(|i| {
            let seed: [u8; 32] = Sha256::digest(
                [
                    b"PUBLIC NO-VALUE HISTORY OWNER ".as_slice(),
                    &i.to_be_bytes(),
                ]
                .concat(),
            )
            .into();
            SigningKey::from_bytes(&seed).verifying_key().to_bytes()
        })
        .collect();
    emit(
        json!({"event":"BEGIN","profile":"RLD-SURVIVOR-1","chain_id":hex::encode(pin),"target_blocks":target.to_string(),"budget_seconds":seconds.to_string(),"group_size":group.to_string(),"clock_model":"LOGICAL_600_SECOND_BLOCKS","nonce_search":"ACTUAL","storage":"ORDINARY_STORE","owners":"256","workload":"GROWING_UNSPENT_REWARDS","network_kind":"NO_VALUE_ONLY","limits":{"database_bytes":Limits::default().database_bytes.to_string(),"coins":Limits::default().coins.to_string()}}),
    )?;
    let mut phases = [Duration::ZERO; 6];
    let mut height = 0;
    while height < target {
        check()?;
        let mut blocks = Vec::new();
        let mut candidate = (group > 1).then(|| store.ledger().clone());
        let end = height + group.min(target - height);
        while height < end {
            height += 1;
            let now = start + height * 600;
            let at = Instant::now();
            let mut job = candidate.as_ref().unwrap_or(store.ledger()).mining_job(
                owners[(height as usize - 1) % owners.len()],
                vec![],
                now,
                now,
            )?;
            phases[0] += at.elapsed();
            let at = Instant::now();
            let raw = loop {
                check()?;
                if let Some(raw) = job.attempt(4096) {
                    break raw;
                }
            };
            phases[1] += at.elapsed();
            if let Some(candidate) = &mut candidate {
                let at = Instant::now();
                candidate.execute(&raw)?;
                phases[5] += at.elapsed();
            }
            blocks.push(raw);
        }
        let now = start + height * 600;
        let mut operation = [0; 32];
        operation[24..].copy_from_slice(&height.to_be_bytes());
        let mut at = Instant::now();
        let observe = |boundary| {
            let index = match boundary {
                CommitBoundary::Validated => 2,
                CommitBoundary::IntentDurable => 3,
                CommitBoundary::CommittedDurable => 4,
            };
            phases[index] += at.elapsed();
            at = Instant::now();
        };
        if group == 1 {
            store.accept_observed(operation, &blocks[0], now, observe)?;
        } else {
            store.accept_history_observed(operation, &blocks, now, observe)?;
        }
        if height / 100 != (height - blocks.len() as u64) / 100 || height == target {
            emit(
                json!({"event":"PROGRESS","height":height.to_string(),"elapsed_ms":started.elapsed().as_millis().to_string(),"utxos":store.ledger().coins().len().to_string(),"database_bytes":fs::metadata(root.join("node/ledger.sqlite3")).map_err(|e|e.to_string())?.len().to_string(),"phase_ms":{"template":phases[0].as_millis().to_string(),"nonce_search":phases[1].as_millis().to_string(),"validation_and_change":phases[2].as_millis().to_string(),"intent_commit":phases[3].as_millis().to_string(),"selection_commit":phases[4].as_millis().to_string(),"group_preparation_execution":phases[5].as_millis().to_string()}}),
            )?;
        }
    }
    check()?;
    let tip = store.ledger().tip().clone();
    let issued = store.ledger().issued();
    drop(store);
    emit(
        json!({"event":"COLD_REPLAY_BEGIN","elapsed_ms":started.elapsed().as_millis().to_string()}),
    )?;
    let at = Instant::now();
    let store = Store::open(&root.join("node"), &genesis, pin, Limits::default())?;
    let replay = at.elapsed();
    check()?;
    let sum = store.ledger().coins().values().try_fold(0u128, |n, c| {
        n.checked_add(c.amount).ok_or("INVALID sum overflow")
    })?;
    if store.ledger().tip() != &tip
        || store.ledger().issued() != issued
        || sum != issued
        || store.revision() != target.div_ceil(group) as u128
    {
        return Err("INVALID cold replay or conservation".into());
    }
    emit(
        json!({"event":"COMPLETE","height":tip.height().to_string(),"selected_tip":hex::encode(tip.id()),"state_root":hex::encode(tip.root()),"issued":issued.to_string(),"utxos":store.ledger().coins().len().to_string(),"cold_replay_ms":replay.as_millis().to_string(),"elapsed_ms":started.elapsed().as_millis().to_string(),"independent_qualification":false,"physical_route_qualification":false}),
    )
}
fn main() {
    if let Err(error) = run() {
        let _ = emit(json!({"event":"INCOMPLETE","diagnostic":error}));
        std::process::exit(1);
    }
}
