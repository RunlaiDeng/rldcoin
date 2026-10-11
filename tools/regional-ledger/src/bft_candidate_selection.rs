//! Ordered command scheduling; every trial still runs full ordinary execution.
use crate::{bft, require, storage::Store, wallet_client, Command, Hash, Result, MAX_BYTES};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const FORMAT: &str = "RLD-NATIVE-BFT-CANDIDATE-SELECTION-V1";
pub const SLOTS: usize = 4;
pub const BATCH: usize = 16;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub context: bft::Context,
    pub selected: Vec<Command>,
    pub seen: Vec<Hash>,
    pub commands: Vec<Command>,
}

#[derive(Serialize)]
pub struct Attempt {
    pub index: usize,
    pub command_id: Hash,
    pub selected: bool,
}

#[derive(Serialize)]
pub struct Output {
    pub format: &'static str,
    pub context: bft::Context,
    pub request_sha256: Hash,
    pub seen: Vec<Hash>,
    pub attempts: Vec<Attempt>,
    pub selected_count: usize,
    pub ledger_changed: bool,
    pub signing_authority: bool,
}

fn command_id(command: &Command) -> Result<Hash> {
    Ok(Hash(
        Sha256::digest(wallet_client::canonical(command)?).into(),
    ))
}

pub fn check_context(store: &Store, context: &bft::Context) -> Result<()> {
    require(
        bft::Context::current(store)? == *context,
        "candidate selection context changed",
    )
}

pub fn select(store: &Store, raw: &[u8], miner: String) -> Result<Output> {
    require(raw.len() <= MAX_BYTES, "candidate selection input bound")?;
    let input: Input = serde_json::from_value(crate::wallet_http::decode_unique(raw)?)
        .map_err(|e| e.to_string())?;
    require(
        input.selected.len() <= SLOTS && input.commands.len() <= BATCH,
        "candidate selection batch or selected bound",
    )?;
    require(
        input.seen.windows(2).all(|p| p[0] < p[1]),
        "candidate seen IDs must be distinct and ordered",
    )?;
    check_context(store, &input.context)?;
    let mut seen: BTreeSet<_> = input.seen.into_iter().collect();
    let mut selected_ids = BTreeSet::new();
    for command in &input.selected {
        let id = command_id(command)?;
        require(
            seen.contains(&id) && selected_ids.insert(id),
            "candidate selected prefix differs from seen IDs",
        )?;
    }
    let mut commands = input.selected;
    // Caller-carried selected commands are never authorization. Re-execute the
    // complete prefix under this invocation's independently replayed Store.
    store.bft_candidate(commands.clone(), miner.clone())?;
    let mut attempts = Vec::new();
    for (index, command) in input.commands.into_iter().enumerate() {
        if commands.len() == SLOTS {
            break;
        }
        let id = command_id(&command)?;
        if !seen.insert(id) {
            continue;
        }
        let mut trial = commands.clone();
        trial.push(command);
        let accepted = store.bft_candidate(trial.clone(), miner.clone()).is_ok();
        if accepted {
            commands = trial;
        }
        attempts.push(Attempt {
            index,
            command_id: id,
            selected: accepted,
        });
    }
    // A rejected trial cannot suppress a failure in the retained prefix or
    // current Native safety/material. Lock acquisition happened before select;
    // busy opens cannot produce an empty/partial scheduling response.
    store.bft_candidate(commands.clone(), miner)?;
    Ok(Output {
        format: FORMAT,
        context: input.context,
        request_sha256: Hash(Sha256::digest(raw).into()),
        seen: seen.into_iter().collect(),
        attempts,
        selected_count: commands.len(),
        ledger_changed: false,
        signing_authority: false,
    })
}
