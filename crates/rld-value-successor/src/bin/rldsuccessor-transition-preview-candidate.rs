//! Unsigned local replay preview; no activation, secret key or network.
use anyhow::{anyhow, Result};
use clap::Parser;
use rld_value_successor::{
    candidate_inputs::{hash, SourceArgs},
    transition::TransitionPreview,
};
use std::io::Write;

#[derive(Parser)]
struct Args {
    #[command(flatten)]
    source: SourceArgs,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let v1 = args.source.replay()?;
    let preview =
        TransitionPreview::from_replayed_v1(v1.chain(), hash(&args.source.pinned_v1_source)?)
            .map_err(|error| anyhow!(error))?;
    eprintln!(
        "UNADOPTED_LOCAL_CANDIDATE_ONLY preview {}",
        preview.id().map_err(|error| anyhow!(error))?.to_hex()
    );
    std::io::stdout().write_all(&preview.canonical_bytes().map_err(|error| anyhow!(error))?)?;
    Ok(())
}
