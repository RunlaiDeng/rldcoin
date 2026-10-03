//! Offline preparation of a small, real Earth channel from replayed mature coins.
//! This never sends commands or exports private keys.

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use rld_core::{sign_bytes, AdmissionHash32 as Hash, Amount, Identity};
use rld_cross_region::value::{ExportCommand, ExportIntent};
use rld_fast_payments::{
    successor::{OpenChannel, OpenIntent},
    ChannelState, SignedState,
};
use rld_pow::{storage::Store as V1Store, transition::Adoption, OutPoint, Output, Transfer};
use rld_value_successor::{
    candidate_client::{load_verified_transition_preview_file, verify_earth_adoption_file},
    chain::{storage::CandidateStore, Command, Header},
    signed_state_hash,
    wallet_guard::GuardedRecipient,
    ActionFee, ActionFeeIntent, ChallengeFeeReserve, ChallengeFeeReserveIntent, DisputeAction,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    genesis: PathBuf,
    #[arg(long)]
    history: PathBuf,
    #[arg(long)]
    pow_adoption: PathBuf,
    #[arg(long)]
    manifest_pin: String,
    #[arg(long)]
    accept_pow_adoption: String,
    #[arg(long)]
    pinned_pow_source: String,
    #[arg(long)]
    v1_data_dir: PathBuf,
    #[arg(long)]
    transition_preview: PathBuf,
    #[arg(long)]
    accept_transition_preview: String,
    #[arg(long)]
    earth_adoption: PathBuf,
    #[arg(long)]
    accept_earth_adoption: String,
    #[arg(long)]
    source_dir: PathBuf,
    #[arg(long)]
    payer_key: PathBuf,
    #[arg(long)]
    receiver_key: PathBuf,
    #[arg(long)]
    watcher_key: PathBuf,
    #[arg(long)]
    f_recipient_key: Option<PathBuf>,
    #[arg(long)]
    destination_chain_id: Option<String>,
    #[arg(long)]
    output_dir: PathBuf,
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn read(path: &Path, max: u64) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > max {
        bail!("unsafe or oversized ceremony input: {}", path.display());
    }
    let bytes = fs::read(path)?;
    if bytes.len() as u64 > max {
        bail!("ceremony input exceeded bound");
    }
    Ok(bytes)
}

fn key(path: &Path) -> Result<Identity> {
    if fs::symlink_metadata(path)?.permissions().mode() & 0o077 != 0 {
        bail!("ceremony key must be mode 0600");
    }
    Ok(serde_json::from_slice(&read(path, 16_384)?)?)
}

fn hash(bytes: &[u8]) -> Hash {
    Hash(Sha256::digest(bytes).into())
}

fn v1_coinbase_id(header: &rld_pow::Header) -> Result<Hash> {
    let mut bytes = b"RLD-EARTH-POW-COINBASE\0".to_vec();
    bytes.extend(header.chain_id.0);
    bytes.extend(header.parent.0);
    bytes.extend(header.height.to_be_bytes());
    bytes.extend(hex::decode(&header.miner)?);
    bytes.extend(header.transactions_root.0);
    Ok(hash(&bytes))
}

fn successor_coinbase_id(header: &Header) -> Result<Hash> {
    let mut bytes = b"RLD-EARTH-UNIFIED-SUCCESSOR-COINBASE\0".to_vec();
    bytes.extend(header.chain_id.0);
    bytes.extend(header.parent.0);
    bytes.extend(header.height.to_be_bytes());
    bytes.extend(hex::decode(&header.miner)?);
    bytes.extend(header.commands_root.0);
    Ok(hash(&bytes))
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn signed(secret: &str, bytes: &[u8]) -> Result<String> {
    sign_bytes(secret, bytes).map_err(|error| anyhow!(error))
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.output_dir.exists() {
        bail!("ceremony output must not exist");
    }
    let genesis = read(&args.genesis, 65_536)?;
    let history = read(&args.history, 32 * 1024 * 1024)?;
    let pow: Adoption = serde_json::from_slice(&read(&args.pow_adoption, 65_536)?)?;
    let pin = Hash::from_hex(&args.manifest_pin).map_err(|e| anyhow!(e))?;
    let pow_id = Hash::from_hex(&args.accept_pow_adoption).map_err(|e| anyhow!(e))?;
    let source_pin = Hash::from_hex(&args.pinned_pow_source).map_err(|e| anyhow!(e))?;
    let context = pow
        .verify_with_pinned_release_source(&genesis, &history, pin, pow_id, source_pin)
        .map_err(|e| anyhow!(e))?;
    let v1 = V1Store::open(&args.v1_data_dir, context, now()?).map_err(|e| anyhow!(e))?;
    let preview_id = Hash::from_hex(&args.accept_transition_preview).map_err(|e| anyhow!(e))?;
    let preview = load_verified_transition_preview_file(
        &args.transition_preview,
        v1.chain(),
        source_pin,
        preview_id,
    )?;
    let earth_id = Hash::from_hex(&args.accept_earth_adoption).map_err(|e| anyhow!(e))?;
    verify_earth_adoption_file(
        &args.earth_adoption,
        &genesis,
        &history,
        &pow,
        v1.chain(),
        &preview,
        earth_id,
    )?;
    let validators = pow
        .approvals
        .iter()
        .map(|approval| approval.public_key.clone())
        .collect();
    let source = CandidateStore::open_finalized(
        &args.source_dir,
        v1.chain(),
        now()?,
        earth_id,
        validators,
    )
    .map_err(|e| anyhow!(e))?;
    let chain = source.chain();
    if chain.height() < 102 || chain.finalized().is_none() {
        bail!("source lacks two mature early rewards or signed finality");
    }
    let payer = key(&args.payer_key)?;
    let receiver = key(&args.receiver_key)?;
    let watcher = key(&args.watcher_key)?;
    if payer.public_key == receiver.public_key || receiver.public_key == watcher.public_key {
        bail!("channel roles must use distinct keys");
    }
    let mut candidate_inputs = Vec::new();
    for block in v1.chain().best_blocks().map_err(|e| anyhow!(e))? {
        let id = v1_coinbase_id(&block.header)?;
        candidate_inputs.push(OutPoint { transaction: id, index: 0 });
    }
    for block in chain.best_blocks().map_err(|e| anyhow!(e))? {
        let id = successor_coinbase_id(&block.header)?;
        candidate_inputs.push(OutPoint { transaction: id, index: 0 });
    }
    let mature = candidate_inputs
        .into_iter()
        .filter_map(|input| {
            chain.state().coin(&input).and_then(|coin| {
                (coin.output.owner == payer.public_key
                    && coin.spendable_height <= chain.height() + 1)
                    .then_some((input, coin.clone()))
            })
        })
        .take(3)
        .collect::<Vec<_>>();
    if mature.len() < 2 {
        bail!("two mature, unspent payer rewards are required");
    }
    let (opening_input, opening_coin) = mature[0].clone();
    let (fee_input, fee_coin) = mature[1].clone();
    let capacity = Amount::from_rld_whole(1).map_err(|e| anyhow!(e))?;
    let opening_fee = Amount(1);
    let opening = OpenIntent {
        chain_id: chain.chain_id(),
        input: opening_input.clone(),
        party_a: payer.public_key.clone(),
        party_b: receiver.public_key.clone(),
        capacity,
        close_fee: Amount(1),
        opening_fee,
        change: opening_coin
            .output
            .amount
            .checked_sub(capacity.checked_add(opening_fee).map_err(|e| anyhow!(e))?)
            .map_err(|e| anyhow!(e))?,
        valid_through_height: u128::MAX,
    };
    let funding = opening.funding().map_err(|e| anyhow!(e))?;
    let state = ChannelState::initial(&funding).map_err(|e| anyhow!(e))?;
    let state_bytes = state.signing_bytes(&funding).map_err(|e| anyhow!(e))?;
    let initial = SignedState {
        state,
        signature_a: signed(&payer.secret_key, &state_bytes)?,
        signature_b: signed(&receiver.secret_key, &state_bytes)?,
    };
    initial.verify(&funding).map_err(|e| anyhow!(e))?;
    let open = Command::Open(OpenChannel {
        signature_a: signed(
            &payer.secret_key,
            &opening.signing_bytes().map_err(|e| anyhow!(e))?,
        )?,
        intent: opening,
        initial: initial.clone(),
    });
    let fee_balance = Amount(10);
    let mut transfer = Transfer {
        chain_id: chain.chain_id(),
        owner: payer.public_key.clone(),
        inputs: vec![fee_input],
        outputs: vec![
            Output {
                owner: receiver.public_key.clone(),
                amount: fee_balance,
            },
            Output {
                owner: payer.public_key.clone(),
                amount: fee_coin
                    .output
                    .amount
                    .checked_sub(Amount(11))
                    .map_err(|e| anyhow!(e))?,
            },
        ],
        fee: Amount(1),
        valid_through_height: u128::MAX,
        signature: String::new(),
    };
    transfer.signature = signed(
        &payer.secret_key,
        &transfer.signing_bytes().map_err(|e| anyhow!(e))?,
    )?;
    let fee_output = OutPoint {
        transaction: transfer.id().map_err(|e| anyhow!(e))?,
        index: 0,
    };
    let reservation = ChallengeFeeReserveIntent {
        chain_id: chain.chain_id(),
        channel: funding.id().map_err(|e| anyhow!(e))?,
        input: fee_output.clone(),
        owner: receiver.public_key.clone(),
    };
    let reserve = Command::ReserveChallengeFee(ChallengeFeeReserve {
        owner_signature: signed(
            &receiver.secret_key,
            &reservation.signing_bytes().map_err(|e| anyhow!(e))?,
        )?,
        intent: reservation,
    });
    let transfer_command = Command::Transfer(transfer);
    // All available inputs and signatures must pass the current replayed rules.
    let time = chain.template_time(now()?).map_err(|e| anyhow!(e))?;
    let export = match (&args.f_recipient_key, &args.destination_chain_id) {
        (Some(recipient_key), Some(destination_chain_id)) => {
            let (input, coin) = mature.get(2).cloned()
                .ok_or_else(|| anyhow!("third mature reward needed for regional export"))?;
            let recipient = key(recipient_key)?;
            let intent = ExportIntent {
                source_chain_id: chain.chain_id(),
                destination_chain_id: Hash::from_hex(destination_chain_id).map_err(|e| anyhow!(e))?,
                input,
                owner: payer.public_key.clone(),
                recipient: recipient.public_key,
                amount: Amount::from_rld_whole(1).map_err(|e| anyhow!(e))?,
                source_fee: Amount(1),
                destination_fee: Amount(1),
                change: coin.output.amount.checked_sub(
                    Amount::from_rld_whole(1).map_err(|e| anyhow!(e))?
                        .checked_add(Amount(1)).map_err(|e| anyhow!(e))?
                ).map_err(|e| anyhow!(e))?,
                valid_through_height: u128::MAX,
            };
            Some(Command::Export(ExportCommand {
                owner_signature: signed(&payer.secret_key, &intent.signing_bytes().map_err(|e| anyhow!(e))?)?,
                intent,
            }))
        }
        (None, None) => None,
        _ => bail!("recipient key and destination chain ID must be supplied together"),
    };
    let mut funding_commands = vec![open.clone(), transfer_command.clone()];
    if let Some(command) = export.clone() {
        funding_commands.push(command);
    }
    chain
        .template(
            payer.public_key.clone(),
            time,
            funding_commands,
        )
        .map_err(|e| anyhow!(e))
        .context("prepared funding commands fail current source rules")?;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(&args.output_dir)?;
    write_json(&args.output_dir.join("01-open.json"), &open)?;
    write_json(&args.output_dir.join("02-fee-transfer.json"), &transfer_command)?;
    write_json(&args.output_dir.join("03-reserve.json"), &reserve)?;
    if let Some(command) = &export {
        write_json(&args.output_dir.join("04-export.json"), command)?;
    }
    write_json(
        &args.output_dir.join("payer-config.json"),
        &serde_json::json!({"funding":funding,"initial":initial}),
    )?;
    write_json(
        &args.output_dir.join("receiver-config.json"),
        &serde_json::json!({
            "funding":funding,
            "initial":initial,
            "fee_input":fee_output,
            "fee_input_amount":fee_balance,
            "fee":Amount(1),
            "valid_through_height":u128::MAX.to_string(),
        }),
    )?;
    let fee_intent = ActionFeeIntent {
        chain_id: chain.chain_id(),
        action: DisputeAction::Challenge,
        channel: funding.id().map_err(|e| anyhow!(e))?,
        signed_state: signed_state_hash(&initial).map_err(|e| anyhow!(e))?,
        input: fee_output.clone(),
        owner: receiver.public_key.clone(),
        fee: Amount(1),
        change: Amount(9),
        valid_through_height: u128::MAX,
    };
    let initial_fee = ActionFee {
        owner_signature: signed(&receiver.secret_key, &fee_intent.signing_bytes().map_err(|e| anyhow!(e))?)?,
        intent: fee_intent,
    };
    let recipient_wallet = GuardedRecipient::open(
        &args.output_dir.join("receiver-wallet"),
        funding.clone(),
        receiver.public_key.clone(),
        initial.clone(),
        Some(initial_fee),
    )
    .map_err(|e| anyhow!(e))?;
    write_json(&args.output_dir.join("watch-package.json"), recipient_wallet.watch_package())?;
    write_json(
        &args.output_dir.join("summary.json"),
        &serde_json::json!({
            "chain_id":chain.chain_id(),
            "source_height":chain.height().to_string(),
            "source_tip":chain.tip(),
            "finalized":chain.finalized().map(|(block,height)| serde_json::json!({"block":block,"height":height.to_string()})),
            "channel":funding.id().map_err(|e| anyhow!(e))?,
            "payer":payer.public_key,
            "receiver":receiver.public_key,
            "watcher":watcher.public_key,
            "capacity_runlai":capacity,
            "opening_input":opening_input,
            "fee_output":fee_output,
            "submitted":false,
        }),
    )?;
    println!("{}", fs::read_to_string(args.output_dir.join("summary.json"))?);
    Ok(())
}
