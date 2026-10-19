//! Exact keyless recovery only. No key/password input, first signing, native
//! selection or new receipt acknowledgment is available in this entry point.
use rld_survivor_node::{fast_retainer::Journal, kernel::Hash};
use serde_json::json;
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
fn hash(text: &str) -> Result<Hash, String> {
    hex::decode(text)
        .map_err(|_| "INVALID recovery hex")?
        .try_into()
        .map_err(|_| "INVALID recovery hash length".into())
}
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 5 {
        return Err("Usage: rld-fast-retainer-recover JOURNAL EXPECTED_CHAIN EXPECTED_PRIOR_HEAD RECEIPT_ID".into());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "CLOCK_WAIT")?
        .as_secs();
    let receipt = hash(&args[4])?;
    let result = Journal::recover(
        Path::new(&args[1]),
        hash(&args[2])?,
        hash(&args[3])?,
        receipt,
        now,
        256 * 1024 * 1024,
    )?;
    println!(
        "{}",
        json!({"profile":"RLD-FAST-PAYMENT-1","network_kind":"NO_VALUE_ONLY",
        "journal_head":hex::encode(result.head),"receipt_id":hex::encode(receipt),
        "receipt_hex":hex::encode(result.receipt),"state":if result.acknowledgment.is_some(){"ALREADY_SIGNED"}else{"PREPARED_NO_ACK"},
        "acknowledgment_hex":result.acknowledgment.map(hex::encode),"key_loaded":false,
        "backing_currentness_known":false,"fast_completion_authorized":false,"mainnet":false})
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
