//! Bounded ordinary-store history measurement. Public NO-VALUE owner derivation;
//! logical chain time and actual nonce search/storage are reported separately.
use ed25519_dalek::{Signer, SigningKey};
use rld_survivor_node::{
    kernel::{genesis_id, Hash, Ledger, Result},
    store::{CommitBoundary, Limits, Store},
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    fs::{self, File, OpenOptions},
    io::Write,
    path::Path,
    time::{Duration, Instant},
};
fn public_owners() -> Vec<SigningKey> {
    (0u16..256)
        .map(|i| {
            let seed: [u8; 32] = Sha256::digest(
                [
                    b"PUBLIC NO-VALUE HISTORY OWNER ".as_slice(),
                    &i.to_be_bytes(),
                ]
                .concat(),
            )
            .into();
            SigningKey::from_bytes(&seed)
        })
        .collect()
}
type PreparedPayment = (Vec<u8>, Vec<u8>);
#[derive(Default)]
struct Consolidation {
    rewards: VecDeque<Vec<u8>>,
    onward: Option<Vec<u8>>,
    transfers: u64,
}
impl Consolidation {
    fn prepare(&self, ledger: &Ledger, owners: &[SigningKey]) -> Result<Option<PreparedPayment>> {
        let height = ledger.tip().height() + 1;
        if height <= 100 {
            return Ok(None);
        }
        let mut inputs = vec![self
            .rewards
            .front()
            .ok_or("INVALID workload missing reward")?
            .clone()];
        if let Some(input) = &self.onward {
            inputs.push(input.clone());
        }
        inputs.sort();
        let key = &owners[((height - 101) % owners.len() as u128) as usize];
        let owner = key.verifying_key().to_bytes();
        let mut total = 0u128;
        for input in &inputs {
            let coin = ledger
                .coins()
                .get(input)
                .ok_or("INVALID workload missing input")?;
            if coin.owner != owner || coin.maturity > height {
                return Err("INVALID workload ownership/maturity".into());
            }
            total = total
                .checked_add(coin.amount)
                .ok_or("INVALID workload sum")?;
        }
        let recipient = owners[((height - 100) % owners.len() as u128) as usize]
            .verifying_key()
            .to_bytes();
        let amount = total
            .checked_sub(1)
            .filter(|n| *n > 0)
            .ok_or("INVALID workload amount")?;
        let mut raw = 1u16.to_be_bytes().to_vec();
        raw.extend(ledger.chain_id());
        raw.extend(owner);
        raw.extend((inputs.len() as u16).to_be_bytes());
        for input in inputs {
            raw.extend(input);
        }
        raw.extend(1u16.to_be_bytes());
        raw.extend(recipient);
        raw.extend(amount.to_be_bytes());
        raw.extend(1u128.to_be_bytes());
        raw.extend(u128::MAX.to_be_bytes());
        let signature = key.sign(&[b"RLD-SURVIVOR-1/TRANSFER\0".as_slice(), &raw].concat());
        raw.extend(signature.to_bytes());
        let id = ledger.validate_transfer(&raw)?;
        let mut outpoint = id.to_vec();
        outpoint.extend(0u16.to_be_bytes());
        Ok(Some((raw, outpoint)))
    }
    fn observe(
        &mut self,
        ledger: &Ledger,
        miner: Hash,
        payment: Option<&PreparedPayment>,
    ) -> Result<()> {
        let height = ledger.tip().height();
        if height > 100 {
            let old = self
                .rewards
                .pop_front()
                .ok_or("INVALID workload missing reward")?;
            if ledger.coins().contains_key(&old) {
                return Err("INVALID workload unconsumed reward".into());
            }
            let (_, output) = payment.ok_or("INVALID workload missing payment")?;
            if !ledger.coins().contains_key(output) {
                return Err("INVALID workload missing output".into());
            }
            self.onward = Some(output.clone());
            self.transfers += 1;
        }
        let reward = ledger
            .coins()
            .iter()
            .find(|(_, c)| c.owner == miner && c.maturity == height + 100)
            .ok_or("INVALID workload missing new reward")?
            .0
            .clone();
        self.rewards.push_back(reward);
        if self.rewards.len() != height.min(100) as usize
            || ledger.coins().len() != height.min(100) as usize + usize::from(height > 100)
        {
            return Err("INVALID workload coin inventory".into());
        }
        Ok(())
    }
}
fn emit(value: serde_json::Value) -> Result<()> {
    println!("{value}");
    std::io::stdout().flush().map_err(|e| e.to_string())
}
fn private_file(path: &Path, raw: &[u8]) -> Result<()> {
    let mut o = OpenOptions::new();
    o.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path).map_err(|e| e.to_string())?;
    f.write_all(raw)
        .and_then(|_| f.sync_all())
        .map_err(|e| e.to_string())
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if !(4..=6).contains(&args.len()) {
        return Err("Usage: rld-survivor-history FRESH_DIRECTORY BLOCKS BUDGET_SECONDS [GROUP_SIZE_1_TO_32] [growing-rewards|consolidating-payments]".into());
    }
    let target: u64 = args[2].parse().map_err(|_| "INVALID block count")?;
    let seconds: u64 = args[3].parse().map_err(|_| "INVALID budget")?;
    let group: u64 = args
        .get(4)
        .map(|x| x.parse())
        .transpose()
        .map_err(|_| "INVALID group size")?
        .unwrap_or(1);
    if target == 0 || !(1..=3600).contains(&seconds) || !(1..=32).contains(&group) {
        return Err("INVALID positive target or 1..3600-second observation budget".into());
    }
    let workload = args.get(5).map(String::as_str).unwrap_or("growing-rewards");
    if !matches!(workload, "growing-rewards" | "consolidating-payments") {
        return Err("INVALID workload".into());
    }
    let mut payments = (workload == "consolidating-payments").then(Consolidation::default);
    let started = Instant::now();
    let budget = Duration::from_secs(seconds);
    let check = || {
        if started.elapsed() < budget {
            Ok(())
        } else {
            Err("RESOURCE_WAIT original observation budget exhausted".to_string())
        }
    };
    let root = Path::new(&args[1]);
    fs::create_dir(root).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    }
    File::open(
        root.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )
    .and_then(|f| f.sync_all())
    .map_err(|e| e.to_string())?;
    let start = 1_000_000u64;
    start
        .checked_add(
            target
                .checked_mul(600)
                .ok_or("INVALID logical time range")?,
        )
        .ok_or("INVALID logical time range")?;
    let mut genesis = b"RLDSGEN1".to_vec();
    genesis.extend(1u16.to_be_bytes());
    genesis.extend(1u16.to_be_bytes());
    genesis.push(0);
    let mut discriminator = [0; 32];
    getrandom::getrandom(&mut discriminator).map_err(|e| e.to_string())?;
    genesis.extend(discriminator);
    genesis.extend(start.to_be_bytes());
    genesis.push(0);
    genesis.extend([255; 31]);
    let pin = genesis_id(&genesis);
    private_file(&root.join("genesis.bin"), &genesis)?;
    let mut store = Store::open(&root.join("node"), &genesis, pin, Limits::default())?;
    let owners = public_owners();
    emit(
        json!({"event":"BEGIN","profile":"RLD-SURVIVOR-1","chain_id":hex::encode(pin),"target_blocks":target.to_string(),"budget_seconds":seconds.to_string(),"group_size":group.to_string(),"clock_model":"LOGICAL_600_SECOND_BLOCKS","nonce_search":"ACTUAL","storage":"ORDINARY_STORE","owners":"256","workload":workload,"signing_model":if payments.is_some(){"PUBLIC_FIXTURE_DIRECT"}else{"NONE"},"wallet_custody_qualification":false,"network_kind":"NO_VALUE_ONLY","limits":{"database_bytes":Limits::default().database_bytes.to_string(),"coins":Limits::default().coins.to_string()}}),
    )?;
    let mut phases = [Duration::ZERO; 7];
    let mut height = 0;
    while height < target {
        check()?;
        let mut blocks = Vec::new();
        let mut candidate = (group > 1 || payments.is_some()).then(|| store.ledger().clone());
        let end = height + group.min(target - height);
        while height < end {
            height += 1;
            let now = start + height * 600;
            let miner = owners[((height - 1) % owners.len() as u64) as usize]
                .verifying_key()
                .to_bytes();
            let at = Instant::now();
            let transfer = payments
                .as_ref()
                .map(|p| p.prepare(candidate.as_ref().unwrap_or(store.ledger()), &owners))
                .transpose()?
                .flatten();
            phases[6] += at.elapsed();
            let txs = transfer
                .as_ref()
                .map(|(raw, _)| vec![raw.clone()])
                .unwrap_or_default();
            let at = Instant::now();
            let mut job = candidate
                .as_ref()
                .unwrap_or(store.ledger())
                .mining_job(miner, txs, now, now)?;
            phases[0] += at.elapsed();
            let at = Instant::now();
            let raw = loop {
                check()?;
                if let Some(raw) = job.attempt(4096) {
                    break raw;
                }
            };
            phases[1] += at.elapsed();
            if let Some(candidate) = &mut candidate {
                let at = Instant::now();
                candidate.execute(&raw)?;
                if let Some(p) = &mut payments {
                    p.observe(candidate, miner, transfer.as_ref())?;
                }
                phases[5] += at.elapsed();
            }
            blocks.push(raw);
        }
        let now = start + height * 600;
        let mut operation = [0; 32];
        operation[24..].copy_from_slice(&height.to_be_bytes());
        let mut at = Instant::now();
        let observe = |boundary| {
            let index = match boundary {
                CommitBoundary::Validated => 2,
                CommitBoundary::IntentDurable => 3,
                CommitBoundary::CommittedDurable => 4,
            };
            phases[index] += at.elapsed();
            at = Instant::now();
        };
        if group == 1 {
            store.accept_observed(operation, &blocks[0], now, observe)?;
        } else {
            store.accept_history_observed(operation, &blocks, now, observe)?;
        }
        if height / 100 != (height - blocks.len() as u64) / 100 || height == target {
            emit(
                json!({"event":"PROGRESS","height":height.to_string(),"elapsed_ms":started.elapsed().as_millis().to_string(),"utxos":store.ledger().coins().len().to_string(),"signed_transactions":payments.as_ref().map(|p|p.transfers.to_string()),"database_bytes":fs::metadata(root.join("node/ledger.sqlite3")).map_err(|e|e.to_string())?.len().to_string(),"phase_ms":{"template":phases[0].as_millis().to_string(),"nonce_search":phases[1].as_millis().to_string(),"validation_and_change":phases[2].as_millis().to_string(),"intent_commit":phases[3].as_millis().to_string(),"selection_commit":phases[4].as_millis().to_string(),"group_preparation_execution":phases[5].as_millis().to_string(),"fixture_payment_preparation":phases[6].as_millis().to_string()}}),
            )?;
        }
    }
    check()?;
    let tip = store.ledger().tip().clone();
    let issued = store.ledger().issued();
    drop(store);
    emit(
        json!({"event":"COLD_REPLAY_BEGIN","elapsed_ms":started.elapsed().as_millis().to_string()}),
    )?;
    let at = Instant::now();
    let store = Store::open(&root.join("node"), &genesis, pin, Limits::default())?;
    let replay = at.elapsed();
    check()?;
    let at = Instant::now();
    let signed_transactions = if let Some(payments) = &payments {
        let mut count = 0u64;
        for id in store.selected_ids()?.into_iter().skip(1) {
            check()?;
            let raw = store.get_block(id)?;
            count += u16::from_be_bytes(raw[268..270].try_into().unwrap()) as u64;
        }
        if count != payments.transfers || count != target.saturating_sub(100) {
            return Err("INVALID cold payment inventory".into());
        }
        Some(count.to_string())
    } else {
        None
    };
    let inventory = at.elapsed();
    let sum = store.ledger().coins().values().try_fold(0u128, |n, c| {
        n.checked_add(c.amount).ok_or("INVALID sum overflow")
    })?;
    if store.ledger().tip() != &tip
        || store.ledger().issued() != issued
        || sum != issued
        || store.revision() != target.div_ceil(group) as u128
    {
        return Err("INVALID cold replay or conservation".into());
    }
    check()?;
    emit(
        json!({"event":"COMPLETE","height":tip.height().to_string(),"selected_tip":hex::encode(tip.id()),"state_root":hex::encode(tip.root()),"issued":issued.to_string(),"utxos":store.ledger().coins().len().to_string(),"signed_transactions":signed_transactions,"cold_replay_ms":replay.as_millis().to_string(),"cold_inventory_ms":inventory.as_millis().to_string(),"elapsed_ms":started.elapsed().as_millis().to_string(),"independent_qualification":false,"wallet_custody_qualification":false,"physical_route_qualification":false}),
    )
}
fn main() {
    if let Err(error) = run() {
        let _ = emit(json!({"event":"INCOMPLETE","diagnostic":error}));
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn consolidation_spends_only_mature_rewards_and_preserves_actual_onward_signatures() {
        let mut g = b"RLDSGEN1".to_vec();
        g.extend(1u16.to_be_bytes());
        g.extend(1u16.to_be_bytes());
        g.push(0);
        g.extend([77; 32]);
        g.extend(1_000_000u64.to_be_bytes());
        g.push(0);
        g.extend([255; 31]);
        let mut ledger = Ledger::from_genesis(&g, genesis_id(&g), Limits::default().coins).unwrap();
        let owners = public_owners();
        let mut payments = Consolidation::default();
        let mut actual_owners = std::collections::BTreeSet::new();
        for h in 1u64..=360 {
            let prepared = payments.prepare(&ledger, &owners).unwrap();
            assert_eq!(prepared.is_some(), h > 100);
            if let Some((raw, _)) = &prepared {
                assert_eq!(payments.prepare(&ledger, &owners).unwrap(), prepared);
                assert_eq!(
                    u16::from_be_bytes(raw[66..68].try_into().unwrap()),
                    if h == 101 { 1 } else { 2 }
                );
                actual_owners.insert(<Hash>::try_from(&raw[34..66]).unwrap());
                let mut corrupt = raw.clone();
                let last = corrupt.len() - 1;
                corrupt[last] ^= 1;
                assert!(ledger.validate_transfer(&corrupt).is_err());
            }
            if h == 101 {
                assert!(Consolidation::default().prepare(&ledger, &owners).is_err());
            }
            let miner = owners[((h - 1) % 256) as usize].verifying_key().to_bytes();
            let now = 1_000_000 + h * 600;
            let txs = prepared
                .as_ref()
                .map(|(raw, _)| vec![raw.clone()])
                .unwrap_or_default();
            let mut job = ledger.mining_job(miner, txs, now, now).unwrap();
            let block = job.attempt(1_000_000).unwrap();
            ledger.execute(&block).unwrap();
            payments.observe(&ledger, miner, prepared.as_ref()).unwrap();
            assert_eq!(
                ledger.coins().values().map(|c| c.amount).sum::<u128>(),
                ledger.issued()
            );
        }
        assert_eq!(payments.transfers, 260);
        assert_eq!(actual_owners.len(), 256);
        assert_eq!(ledger.coins().len(), 101);
    }
}
