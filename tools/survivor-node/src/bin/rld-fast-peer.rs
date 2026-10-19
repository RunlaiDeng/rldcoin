//! Local transport provisioning only; no wallet key/password/value handling.
use rld_survivor_node::{fast_peer, fast_session::Id};
use std::{
    io::Read,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
fn run() -> Result<(), String> {
    let a: Vec<_> = std::env::args().collect();
    if a.len() < 2 {
        return Err("Usage: rld-fast-peer init ROOT CHAIN | bind ROOT CONFIG_FILE | recover ROOT CHAIN PRIOR_HEAD PACKET_OR_MESSAGE_ID".into());
    }
    let id = |s: &str| -> Result<Id, String> {
        serde_json::from_value(s.to_owned().into()).map_err(|_| "INVALID identifier".into())
    };
    let now = || -> Result<u64, String> {
        Ok(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "CLOCK_WAIT")?
            .as_secs())
    };
    let out = match (a[1].as_str(), a.len()) {
        ("init", 4) => {
            let id = id(&a[3])?;
            fast_peer::provision(Path::new(&a[2]), id.0)?
        }
        ("bind", 4) => {
            let mut raw = Vec::new();
            std::fs::File::open(&a[3])
                .map_err(|_| "MISSING peer config")?
                .take(65537)
                .read_to_end(&mut raw)
                .map_err(|_| "RESOURCE_WAIT peer config read")?;
            fast_peer::bind(Path::new(&a[2]), &raw, now()?)?
        }
        ("recover", 6) => fast_peer::recover(
            Path::new(&a[2]),
            id(&a[3])?.0,
            id(&a[4])?.0,
            id(&a[5])?.0,
            now()?,
        )?,
        _ => return Err("INVALID peer entry".into()),
    };
    println!("{out}");
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
