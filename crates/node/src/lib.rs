pub mod custody;
pub mod runtime;
pub mod service;
pub mod store;
pub mod transport;

pub mod offline;

mod archive;

pub mod history;
pub mod proving;

pub mod state_index;

pub fn executable_profile() -> anyhow::Result<rld_protocol::model::ProofProfile> {
    let binding: serde_json::Value =
        serde_json::from_str(include_str!("../../../spec/EXECUTABLE_PROFILE.json"))?;
    Ok(serde_json::from_value(binding["proof_profile"].clone())?)
}
pub fn executable_source_digest() -> &'static str {
    env!("RLD_EXECUTABLE_SOURCE_DIGEST")
}

mod applied_store;
mod object_store;

pub mod receipts;

mod permanent_store;
mod state_storage;

mod utxo_store;

mod mint_store;
mod typed_paths;
