//! Spend only publicly known fixture-key test rewards after independent replay.
use anyhow::{anyhow, ensure, Result};
use rld_core::{sign_bytes, AdmissionHash32 as Hash, Amount};
use rld_pow::{transition::Adoption, OutPoint, Output, Transfer};
use rld_value_successor::{
    candidate_client::{self, NodeMode},
    chain::{storage::CandidateStore, Command},
};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf, time::Duration};
fn native<T, E: std::fmt::Display>(v: std::result::Result<T, E>) -> Result<T> {
    v.map_err(|e| anyhow!(e.to_string()))
}
#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        args.len() == 3,
        "usage: records NEW-private-client-directory recipient-public-key"
    );
    let records = PathBuf::from(&args[0]);
    let root = PathBuf::from(&args[1]);
    ensure!(
        root.is_absolute() && !root.is_symlink(),
        "absolute private client directory required"
    );
    let pins: serde_json::Value = serde_json::from_slice(&fs::read(records.join("testnet.json"))?)?;
    ensure!(
        pins["test_only"] == true
            && pins["mainnet_authorized"] == false
            && pins["has_monetary_value"] == false,
        "testnet only"
    );
    ensure!(
        pins["implementation_source"]
            == rld_core::implementation_source::IMPLEMENTATION_SOURCE_COMMITMENT,
        "wrong source"
    );
    native(rld_core::validate_ed25519_public_key(&args[2]))?;
    let h = |key: &str| {
        native(Hash::from_hex(
            pins[key].as_str().ok_or_else(|| anyhow!("missing pin"))?,
        ))
    };
    let genesis = fs::read(records.join("genesis.json"))?;
    let history = fs::read(records.join("history.json"))?;
    ensure!(history == b"[]", "inherited history forbidden");
    let pow: Adoption = serde_json::from_slice(&fs::read(records.join("adoption.json"))?)?;
    let context = native(pow.verify(&genesis, &history, h("manifest_pin")?, h("adoption_id")?))?;
    let v1 = native(rld_pow::Chain::new(context))?;
    let mut store = native(CandidateStore::open_finalized(
        &root,
        &v1,
        candidate_client::now()?,
        h("earth_adoption_id")?,
        pow.approvals.iter().map(|a| a.public_key.clone()).collect(),
    ))?;
    let http = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(25))
        .build()?;
    let node = "http://127.0.0.1:48530";
    let saved = root.join("fund-command.json");
    if saved.exists() {
        let command: Command = serde_json::from_slice(&fs::read(&saved)?)?;
        if let Command::Transfer(ref transfer) = command {
            ensure!(
                transfer.chain_id == h("source_chain_id")? && transfer.outputs[0].owner == args[2],
                "saved decision differs"
            );
        } else {
            anyhow::bail!("unexpected saved command");
        }
        let response = http
            .post(format!("{node}/v1/earth/commands"))
            .json(&command)
            .send()
            .await?;
        ensure!(response.status().is_success(), "exact test retry rejected");
        println!(
            "{}",
            serde_json::json!({"test_only":true,"exact_retry":true,"command_id":native(rld_value_successor::chain::storage::command_id(&command))?.to_hex(),"confirmed":false})
        );
        return Ok(());
    }
    candidate_client::refresh_mode(
        &mut store,
        &http,
        "http://127.0.0.1:48520",
        h("preview_id")?,
        NodeMode::Adopted(h("earth_adoption_id")?),
    )
    .await?;
    let chain = store.chain();
    let owner = pins["miner"]
        .as_str()
        .ok_or_else(|| anyhow!("missing miner"))?;
    let amount = Amount(10u128.pow(24));
    let fee = Amount(10u128.pow(18));
    let mut chosen = None;
    for block in native(chain.best_blocks())? {
        let header = block.header;
        let mut bytes = b"RLD-EARTH-UNIFIED-SUCCESSOR-COINBASE\0".to_vec();
        bytes.extend(header.chain_id.0);
        bytes.extend(header.parent.0);
        bytes.extend(header.height.to_be_bytes());
        bytes.extend(hex::decode(&header.miner)?);
        bytes.extend(header.commands_root.0);
        let point = OutPoint {
            transaction: Hash(Sha256::digest(bytes).into()),
            index: 0,
        };
        if let Some(coin) = chain.state().coin(&point) {
            if coin.output.owner == owner
                && coin.spendable_height <= chain.height() + 1
                && coin.output.amount.0 > amount.0 + fee.0
            {
                chosen = Some((point, coin.output.amount));
                break;
            }
        }
    }
    let (point, balance) = chosen.ok_or_else(|| anyhow!("no mature test reward"))?;
    let mut transfer = Transfer {
        chain_id: chain.chain_id(),
        owner: owner.into(),
        inputs: vec![point],
        outputs: vec![
            Output {
                owner: args[2].clone(),
                amount,
            },
            Output {
                owner: owner.into(),
                amount: native(balance.checked_sub(Amount(amount.0 + fee.0)))?,
            },
        ],
        fee,
        valid_through_height: chain.height() + 1000,
        signature: String::new(),
    };
    transfer.signature = native(sign_bytes(
        &hex::encode([60; 32]),
        &native(transfer.signing_bytes())?,
    ))?;
    let command = Command::Transfer(transfer);
    let id = native(rld_value_successor::chain::storage::command_id(&command))?;
    fs::write(
        root.join("fund-command.json"),
        serde_json::to_vec(&command)?,
    )?;
    let response = http
        .post(format!("{node}/v1/earth/commands"))
        .json(&command)
        .send()
        .await?;
    ensure!(
        response.status().is_success(),
        "test funding rejected: {}",
        response.text().await?
    );
    println!(
        "{}",
        serde_json::json!({"test_only":true,"has_monetary_value":false,"command_id":id.to_hex(),"recipient":args[2],"amount_rld":"1","submitted":true,"confirmed":false})
    );
    Ok(())
}
