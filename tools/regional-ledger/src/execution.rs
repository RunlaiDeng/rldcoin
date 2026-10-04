//! One native owner/value execution kernel for full-history and bounded replay.
//! The caller supplies a previously natively derived state, never a decoded cache.
use super::*;
pub(crate) struct Execution<'a> {
    pub region: Hash,
    pub height: u64,
    pub tip: Hash,
    pub ledger: &'a Ledger,
}
impl Execution<'_> {
    pub fn execute(
        &self,
        commands: &[Command],
        miner: &str,
        trust: &Trust,
        evidence: &VerifiedEvidence,
        complete: bool,
        finalized: Option<Hash>,
    ) -> Result<Ledger> {
        evidence.check_trust(trust)?;
        require(commands.len() <= MAX_COMMANDS, "command bound")?;
        require(
            complete || (commands.len() == 1 && matches!(commands[0], Command::Spend(_))),
            "partial validation permits exactly one owner command",
        )?;
        validate_ed25519_public_key(miner)?;
        let height = self.height.checked_add(1).ok_or("height overflow")?;
        let maturity = height
            .checked_add(trust.currency.maturity)
            .ok_or("maturity overflow")?;
        require(
            commands
                .iter()
                .filter(|c| matches!(c, Command::Reconfigure(_)))
                .count()
                <= 1,
            "at most one joint plan per block",
        )?;
        let mut ledger = (*self.ledger).clone();
        for command in commands {
            match command {
                Command::Reconfigure(plan) => {
                    crate::joint_epoch::validate_command(
                        plan,
                        self.region,
                        height,
                        trust,
                        evidence,
                    )?;
                }
                Command::Spend(signed) => {
                    let intent = &signed.intent;
                    require(
                        intent.currency == trust.currency()?
                            && intent.region == self.region
                            && intent.valid_through >= height
                            && !intent.inputs.is_empty()
                            && intent.inputs.len() <= 16
                            && intent.inputs.windows(2).all(|v| v[0] < v[1])
                            && intent.outputs.len() <= 16,
                        "invalid spend identity, expiry or inputs",
                    )?;
                    let mut owners = BTreeSet::new();
                    let mut deps = BTreeSet::new();
                    let mut total = Amount::ZERO;
                    for input in &intent.inputs {
                        let coin = ledger.coins.get(input).ok_or("input absent or spent")?;
                        require(height >= coin.mature, "immature input")?;
                        owners.insert(coin.payment.owner.clone());
                        deps.extend(&coin.dependencies);
                        total = add(total, coin.payment.amount)?;
                    }
                    if complete {
                        require(
                            signed.approvals.len() == owners.len()
                                && signed.approvals.iter().map(|a| &a.key).eq(owners.iter()),
                            "every input owner must authorize in exact order",
                        )?;
                    } else {
                        require(
                            signed.approvals.len() == 1
                                && owners.contains(&signed.approvals[0].key),
                            "partial approval must belong to an actual input owner",
                        )?;
                    }
                    for approval in &signed.approvals {
                        verify_bytes(&approval.key, &intent.bytes()?, &approval.signature)?;
                    }
                    let mut used = add(sum(intent.outputs.iter().map(|p| p.amount))?, intent.fee)?;
                    let tx = intent.id()?;
                    match (&intent.destination, &intent.remote) {
                        (Some(destination), Some(remote)) => {
                            trust.region(*destination)?;
                            validate_ed25519_public_key(&remote.owner)?;
                            require(
                                *destination != self.region
                                    && remote.amount.0 > 0
                                    && intent.destination_fee < remote.amount,
                                "invalid export destination or fee",
                            )?;
                            let final_height = evidence
                                .snapshot(
                                    finalized.ok_or("onward export requires local finality")?,
                                )?
                                .statement
                                .height;
                            require(
                                intent
                                    .inputs
                                    .iter()
                                    .all(|i| ledger.coins[i].created <= final_height),
                                "export input is not locally finalized",
                            )?;
                            used = add(used, remote.amount)?;
                            require(!ledger.exports.contains_key(&tx), "duplicate export")?;
                            ledger.exports.insert(
                                tx,
                                Export {
                                    id: tx,
                                    source: self.region,
                                    destination: *destination,
                                    recipient: remote.clone(),
                                    destination_fee: intent.destination_fee,
                                    height,
                                    dependencies: deps.clone(),
                                },
                            );
                        }
                        (None, None) => require(
                            intent.destination_fee.is_zero(),
                            "local spend has remote fee",
                        )?,
                        _ => return Err("incomplete export intent".into()),
                    }
                    require(
                        used == total,
                        "inputs, change, fees and export do not conserve",
                    )?;
                    for input in &intent.inputs {
                        ledger.coins.remove(input);
                    }
                    for (i, payment) in intent.outputs.iter().enumerate() {
                        ledger.output(tx, i as u32, payment.clone(), height, height, &deps)?;
                    }
                    if !intent.fee.is_zero() {
                        ledger.output(
                            tx,
                            16,
                            Payment {
                                owner: miner.into(),
                                amount: intent.fee,
                            },
                            height,
                            maturity,
                            &deps,
                        )?;
                    }
                }
                Command::Import { snapshot, export } => {
                    let source = evidence.snapshot(*snapshot)?;
                    let record = evidence.export(*snapshot, *export)?;
                    require(
                        source.statement.currency == trust.currency()?
                            && source.statement.region == record.source
                            && record.destination == self.region
                            && record.source != self.region
                            && record.height <= source.statement.height,
                        "wrong source, destination or checkpoint",
                    )?;
                    require(
                        !ledger.imports.contains_key(export),
                        "permanent import tombstone rejects replay",
                    )?;
                    let mut deps = record.dependencies.clone();
                    deps.insert(*snapshot);
                    for dependency in &deps {
                        evidence.snapshot(*dependency)?;
                    }
                    let amount = record
                        .recipient
                        .amount
                        .checked_sub(record.destination_fee)
                        .map_err(|e| e.to_string())?;
                    ledger.output(
                        *export,
                        0,
                        Payment {
                            owner: record.recipient.owner.clone(),
                            amount,
                        },
                        height,
                        maturity,
                        &deps,
                    )?;
                    if !record.destination_fee.is_zero() {
                        ledger.output(
                            *export,
                            16,
                            Payment {
                                owner: miner.into(),
                                amount: record.destination_fee,
                            },
                            height,
                            maturity,
                            &deps,
                        )?;
                    }
                    ledger.received = add(ledger.received, record.recipient.amount)?;
                    ledger.imports.insert(*export, *snapshot);
                }
            }
        }
        if trust.region(self.region)?.region == trust.currency.origin {
            let remaining = trust
                .currency
                .cap
                .checked_sub(ledger.minted)
                .map_err(|e| e.to_string())?;
            let reward = remaining.min(trust.currency.block_reward);
            if !reward.is_zero() {
                let tx = id("issuance", &(self.region, height, self.tip))?;
                ledger.output(
                    tx,
                    0,
                    Payment {
                        owner: miner.into(),
                        amount: reward,
                    },
                    height,
                    maturity,
                    &BTreeSet::new(),
                )?;
                ledger.minted = add(ledger.minted, reward)?;
            }
        }
        ledger.audit()?;
        Ok(ledger)
    }
}
