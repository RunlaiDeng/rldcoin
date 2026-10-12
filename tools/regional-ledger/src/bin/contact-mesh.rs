//! Rust transport operations; receipts never grant ledger or signing authority.
use clap::{Parser, Subcommand};
use rld_regional_ledger_candidate::{contact_runtime as runtime, storage, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    action: Action,
}
#[derive(Subcommand)]
enum Action {
    Init {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        network: String,
        #[arg(long)]
        region: String,
        #[arg(long)]
        label: String,
    },
    Inspect {
        #[arg(long)]
        config: PathBuf,
    },
    TlsIdentity {
        #[arg(long)]
        config: PathBuf,
    },
    Enqueue {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        destination: String,
    },
    Tick {
        #[arg(long)]
        config: PathBuf,
    },
}
fn read(path: &Path) -> Result<Value> {
    storage::read_json(path)
}
fn run() -> Result<()> {
    let result = match Args::parse().action {
        Action::Init {
            state,
            network,
            region,
            label,
        } => runtime::initialize(&state, &network, &region, &label)?,
        Action::Inspect { config } => runtime::Node::open(&read(&config)?)?.observation(),
        Action::TlsIdentity { config } => runtime::tls_identity(&read(&config)?)?,
        Action::Enqueue {
            config,
            file,
            destination,
        } => {
            let raw =
                storage::read_bytes(&file, rld_regional_ledger_candidate::contact::MAX_FRAME)?;
            json!({"packet_id":runtime::Node::open(&read(&config)?)?.enqueue(&raw,&destination)?,"ledger_authority":false})
        }
        Action::Tick { config } => runtime::tick_transport(&read(&config)?)?,
    };
    println!("{result}");
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("contact mesh refused: {error}");
        std::process::exit(1);
    }
}
