//! Historical owner evidence recovery. This binary takes no key or password.
use rld_survivor_node::{fast_owner::Journal, kernel::Hash};
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
    if args.len() != 6 || !matches!(args[1].as_str(), "partial" | "complete") {
        return Err("Usage: rld-fast-owner-recover partial|complete JOURNAL EXPECTED_CHAIN EXPECTED_PRIOR_HEAD INVOICE_OR_RECEIPT_ID".into());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "CLOCK_WAIT")?
        .as_secs();
    let path = Path::new(&args[2]);
    let chain = hash(&args[3])?;
    let prior = hash(&args[4])?;
    let id = hash(&args[5])?;
    let mut value = json!({"profile":"RLD-FAST-OWNER-1", "network_kind":"NO_VALUE_ONLY", "key_loaded":false, "backing_currentness_known":false, "fast_completion_authorized":false, "mainnet":false});
    if args[1] == "partial" {
        let r = Journal::recover(path, chain, prior, id, now, 256 * 1024 * 1024)?;
        value["journal_head"] = hex::encode(r.head).into();
        value["invoice_hex"] = hex::encode(r.invoice).into();
        value["state"] = if r.partial.is_some() {
            "ALREADY_SIGNED"
        } else {
            "PREPARED_NO_SIGNATURE"
        }
        .into();
        value["partial_hex"] = r.partial.map(hex::encode).into();
    } else {
        let (head, receipt, ack) =
            Journal::recover_complete(path, chain, prior, id, now, 256 * 1024 * 1024)?;
        value["journal_head"] = hex::encode(head).into();
        value["state"] = "COMPLETE_PROOF_RETAINED".into();
        value["receipt_hex"] = hex::encode(receipt).into();
        value["acknowledgment_hex"] = hex::encode(ack).into();
    }
    println!("{value}");
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
