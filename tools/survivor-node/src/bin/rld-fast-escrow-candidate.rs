//! Read-only full native replay of the incompatible NO_VALUE_ONLY escrow profile.
//! No snapshot, serialized ledger, signing key, live node or activation fallback.
use rld_survivor_node::kernel::fast;
use serde_json::json;
use std::{
    fs::{self, File},
    io::Read,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
fn file(path: &Path, limit: u64) -> Result<File, String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err("RESOURCE_WAIT regular bounded input required".into());
    }
    let file = File::open(path).map_err(|e| e.to_string())?;
    let opened = file.metadata().map_err(|e| e.to_string())?;
    if !opened.is_file() || opened.len() > limit {
        return Err("RESOURCE_WAIT opened input bound".into());
    }
    Ok(file)
}
fn exact(file: &mut File, bytes: &mut [u8]) -> Result<(), String> {
    file.read_exact(bytes)
        .map_err(|e| format!("WAITING_FOR_HISTORY {e}"))
}
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 {
        return Err(
            "Usage: rld-fast-escrow-candidate GENESIS_FILE EXPECTED_CHAIN_HEX BLOCK_ARCHIVE".into(),
        );
    }
    let pin = hex::decode(&args[2])
        .map_err(|_| "INVALID chain hex")?
        .try_into()
        .map_err(|_| "INVALID chain length")?;
    let mut genesis = Vec::new();
    file(Path::new(&args[1]), 113)?
        .take(114)
        .read_to_end(&mut genesis)
        .map_err(|e| e.to_string())?;
    let mut ledger = fast::Ledger::from_genesis(&genesis, pin, 100_000)?;
    let mut archive = file(Path::new(&args[3]), 256 * 1024 * 1024)?;
    let declared = archive.metadata().map_err(|e| e.to_string())?.len();
    let mut bytes = 0u64;
    let mut blocks = 0u64;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "CLOCK_WAIT")?
        .as_secs();
    loop {
        let mut prefix = [0; 4];
        let n = archive.read(&mut prefix[..1]).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        exact(&mut archive, &mut prefix[1..])?;
        let size = u32::from_be_bytes(prefix) as usize;
        if !(270..=262144).contains(&size) {
            return Err("INVALID archive block length".into());
        }
        blocks += 1;
        bytes = bytes
            .checked_add(4 + size as u64)
            .ok_or("RESOURCE_WAIT archive length overflow")?;
        if blocks > 262144 || bytes > declared {
            return Err("RESOURCE_WAIT archive bound or changed input".into());
        }
        let mut raw = vec![0; size];
        exact(&mut archive, &mut raw)?;
        ledger.execute(&raw, now)?;
    }
    if bytes != declared {
        return Err("WAITING_FOR_HISTORY changed archive".into());
    }
    let liquid = ledger
        .coins()
        .values()
        .map(|coin| coin.amount)
        .sum::<u128>();
    println!(
        "{}",
        json!({"profile":"RLD-FAST-ESCROW-1","network_kind":"NO_VALUE_ONLY",
        "chain_id":hex::encode(ledger.chain_id()),"selected_tip":hex::encode(ledger.tip().id()),
        "height":ledger.tip().height().to_string(),"state_root":hex::encode(ledger.tip().root()),
        "work":hex::encode(ledger.tip().work_bytes()),"issued":ledger.issued().to_string(),
        "liquid":liquid.to_string(),"locked":ledger.locked().to_string(),"active_channels":ledger.active_channels(),
        "blocks":blocks,"bytes":bytes,"native_history_verified":true,"read_only":true,
        "independent_freshness":false,"wallet_custody_qualified":false,"fast_service_qualified":false,
        "mainnet":false,"actual_clock_observed_at":now.to_string()})
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
