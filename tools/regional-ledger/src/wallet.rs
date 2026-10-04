//! Recipient verification and reviewed-intent signing over a freshly replayed,
//! exclusively locked native store. No remote freshness or transport authority.
use super::*;
use crate::storage::Store;
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    pub currency: Hash,
    pub region: Hash,
    pub height: u64,
    pub tip: Hash,
    pub state: Hash,
    pub epoch: Hash,
    pub finality: Option<Hash>,
    pub local_journal_and_incidents: Hash,
}
impl Pin {
    pub fn current(store: &Store) -> Result<Self> {
        Ok(Self {
            currency: store.trust.currency()?,
            region: store.chain.region,
            height: store.chain.height(),
            tip: store.chain.tip()?,
            state: store.chain.ledger.root()?,
            epoch: store.chain.epoch,
            finality: store.chain.finalized,
            local_journal_and_incidents: id(
                "wallet-local-observation",
                &(
                    &store.journal,
                    store
                        .conflicts
                        .iter()
                        .map(|p| p.id())
                        .collect::<Result<Vec<_>>>()?,
                ),
            )?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Remote {
    pub destination: Hash,
    pub recipient: Payment,
    pub destination_fee: Amount,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub owner: String,
    /// Empty for one owner. Groups pin every actual input owner in sorted order;
    /// all inputs and all refund/payment outputs must be explicitly selected.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub participants: Vec<String>,
    pub inputs: Option<Vec<Hash>>,
    pub outputs: Vec<Payment>,
    pub remote: Option<Remote>,
    pub fee: Amount,
    pub valid_for_blocks: u64,
    /// Shared group proposals keep one absolute expiry across later reviews.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_through: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Draft {
    pub format: String,
    pub pin: Pin,
    pub request: Request,
    pub intent: Intent,
    pub intent_id: Hash,
    pub selected_input_total: Amount,
    pub change: Amount,
    pub input_owners: BTreeMap<Hash, String>,
    pub input_amounts: BTreeMap<Hash, Amount>,
}
#[derive(Debug, Serialize)]
pub struct OwnedCoin {
    pub id: Hash,
    pub amount: Amount,
    pub mature_height: u64,
    pub spendable_now: bool,
    pub eligible_for_onward_export: bool,
    pub quarantined: bool,
}
#[derive(Debug, Serialize)]
pub struct View {
    pub format: &'static str,
    pub pin: Pin,
    pub owner: String,
    pub coins: Vec<OwnedCoin>,
    pub spendable: Amount,
    pub immature: Amount,
    pub quarantined: Amount,
    pub onward_eligible: Amount,
    pub pending_signed_intents_tracked: bool,
    pub remote_current_state_known: bool,
    pub transport_receipt_is_payment_authority: bool,
    pub local_observation_is_external_rollback_anchor: bool,
    pub live_rld: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptExpectation {
    pub currency: Hash,
    pub source: Hash,
    pub destination: Hash,
    pub export: Hash,
    pub recipient: String,
    pub net_amount: Amount,
}
#[derive(Debug, Serialize)]
pub struct Receipt {
    pub format: &'static str,
    pub expected: ReceiptExpectation,
    pub pin: Pin,
    pub verified_source_checkpoint: Hash,
    pub evidence_verified: bool,
    pub import_accepted: bool,
    pub import_height: Option<u64>,
    pub mature_height: Option<u64>,
    pub maturity_reached: bool,
    pub original_output_remaining: Amount,
    pub original_output_spendable_now: bool,
    pub local_finality_covers_import: bool,
    pub quarantined: bool,
    pub state: &'static str,
    pub transport_receipt_checked: bool,
    pub remote_current_state_known: bool,
    pub live_rld: bool,
}

fn finalized_height(store: &Store) -> Result<u64> {
    store
        .chain
        .finalized
        .map(|s| store.evidence.snapshot(s).map(|p| p.statement.height))
        .unwrap_or(Ok(0))
}
pub fn view(store: &Store, owner: &str) -> Result<View> {
    validate_ed25519_public_key(owner)?;
    let exposure = store.safety.exposure(&store.chain, &store.evidence)?;
    let final_height = finalized_height(store)?;
    let mut result = View {
        format: "RLD-REGIONAL-WALLET-V1",
        pin: Pin::current(store)?,
        owner: owner.into(),
        coins: vec![],
        spendable: Amount::ZERO,
        immature: Amount::ZERO,
        quarantined: Amount::ZERO,
        onward_eligible: Amount::ZERO,
        pending_signed_intents_tracked: false,
        remote_current_state_known: false,
        transport_receipt_is_payment_authority: false,
        local_observation_is_external_rollback_anchor: false,
        live_rld: false,
    };
    for (key, coin) in &store.chain.ledger.coins {
        if coin.payment.owner != owner {
            continue;
        }
        let quarantined = exposure.quarantined_coins.contains(key);
        let mature = coin.mature <= store.chain.height();
        let onward = !quarantined && mature && coin.created <= final_height;
        if quarantined {
            result.quarantined = add(result.quarantined, coin.payment.amount)?;
        } else if mature {
            result.spendable = add(result.spendable, coin.payment.amount)?;
        } else {
            result.immature = add(result.immature, coin.payment.amount)?;
        }
        if onward {
            result.onward_eligible = add(result.onward_eligible, coin.payment.amount)?;
        }
        result.coins.push(OwnedCoin {
            id: *key,
            amount: coin.payment.amount,
            mature_height: coin.mature,
            spendable_now: mature && !quarantined,
            eligible_for_onward_export: onward,
            quarantined,
        });
    }
    Ok(result)
}

pub fn prepare(store: &Store, request: Request) -> Result<Draft> {
    prepare_with_reserved(store, request, &BTreeSet::new())
}
pub(crate) fn prepare_with_reserved(
    store: &Store,
    request: Request,
    reserved: &BTreeSet<Hash>,
) -> Result<Draft> {
    if !request.participants.is_empty() {
        return prepare_group(store, request, reserved);
    }
    store.safety.check_region(store.chain.region)?;
    require(
        store.chain.blocks.len() < MAX_BLOCKS,
        "wallet cannot spend past history capacity",
    )?;
    require(
        request.valid_through.is_none()
            && (1..=32).contains(&request.valid_for_blocks)
            && request.outputs.len() <= 15,
        "wallet expiry or output bound",
    )?;
    for output in &request.outputs {
        validate_ed25519_public_key(&output.owner)?;
        require(output.amount.0 > 0, "wallet zero output")?;
    }
    let mut required = add(sum(request.outputs.iter().map(|p| p.amount))?, request.fee)?;
    if let Some(remote) = &request.remote {
        store.trust.region(remote.destination)?;
        validate_ed25519_public_key(&remote.recipient.owner)?;
        require(
            remote.destination != store.chain.region
                && remote.recipient.amount.0 > 0
                && remote.destination_fee < remote.recipient.amount,
            "wallet invalid destination or fee",
        )?;
        required = add(required, remote.recipient.amount)?;
    }
    require(required.0 > 0, "wallet empty payment")?;
    let observed = view(store, &request.owner)?;
    let eligible = observed
        .coins
        .iter()
        .filter(|c| !reserved.contains(&c.id))
        .filter(|c| {
            if request.remote.is_some() {
                c.eligible_for_onward_export
            } else {
                c.spendable_now
            }
        })
        .map(|c| (c.id, c.amount))
        .collect::<BTreeMap<_, _>>();
    let mut inputs = vec![];
    let mut selected = Amount::ZERO;
    if let Some(chosen) = &request.inputs {
        require(
            !chosen.is_empty() && chosen.len() <= 16 && chosen.windows(2).all(|p| p[0] < p[1]),
            "wallet input selection must be ordered, unique and bounded",
        )?;
        for key in chosen {
            selected = add(
                selected,
                *eligible
                    .get(key)
                    .ok_or("wallet input is not owned, mature, finalized or safe")?,
            )?;
        }
        inputs = chosen.clone();
    } else {
        for (key, amount) in eligible {
            if selected >= required || inputs.len() == 16 {
                break;
            }
            inputs.push(key);
            selected = add(selected, amount)?;
        }
    }
    require(selected >= required, "wallet insufficient eligible funds")?;
    let change = selected.checked_sub(required).map_err(|e| e.to_string())?;
    let mut outputs = request.outputs.clone();
    if !change.is_zero() {
        outputs.push(Payment {
            owner: request.owner.clone(),
            amount: change,
        });
    }
    let intent = Intent {
        currency: observed.pin.currency,
        region: observed.pin.region,
        inputs,
        outputs,
        fee: request.fee,
        destination: request.remote.as_ref().map(|r| r.destination),
        remote: request.remote.as_ref().map(|r| r.recipient.clone()),
        destination_fee: request
            .remote
            .as_ref()
            .map(|r| r.destination_fee)
            .unwrap_or(Amount::ZERO),
        valid_through: store
            .chain
            .height()
            .checked_add(request.valid_for_blocks)
            .ok_or("wallet expiry overflow")?,
    };
    Ok(Draft {
        format: "RLD-REGIONAL-WALLET-DRAFT-V2".into(),
        pin: observed.pin,
        request,
        intent_id: intent.id()?,
        input_owners: intent
            .inputs
            .iter()
            .map(|i| (*i, store.chain.ledger.coins[i].payment.owner.clone()))
            .collect(),
        input_amounts: intent
            .inputs
            .iter()
            .map(|i| (*i, store.chain.ledger.coins[i].payment.amount))
            .collect(),
        intent,
        selected_input_total: selected,
        change,
    })
}

/// The separately reviewed draft must match current replay including incident
/// knowledge. Store remains locked until the CLI returns the signed command.
pub fn sign(
    store: &Store,
    draft: Draft,
    key_file: &Path,
    expected_review: Hash,
) -> Result<Command> {
    sign_with_reserved(store, draft, key_file, expected_review, &BTreeSet::new())
}
pub(crate) fn sign_with_reserved(
    store: &Store,
    draft: Draft,
    key_file: &Path,
    expected_review: Hash,
    reserved: &BTreeSet<Hash>,
) -> Result<Command> {
    sign_with_reserved_key(store, draft, key_file, expected_review, reserved, None)
}
pub(crate) fn sign_with_reserved_key(
    store: &Store,
    draft: Draft,
    key_file: &Path,
    expected_review: Hash,
    reserved: &BTreeSet<Hash>,
    passphrase: Option<&[u8]>,
) -> Result<Command> {
    require(
        id("wallet-reviewed-draft", &draft)? == expected_review,
        "wallet review commitment differs",
    )?;
    require(
        draft.pin == Pin::current(store)?,
        "wallet state changed; prepare and review again",
    )?;
    require(
        prepare_with_reserved(store, draft.request.clone(), reserved)? == draft,
        "wallet draft differs from verified request",
    )?;
    let approval = if let Some(pass) = passphrase {
        crate::keystore::sign(
            &crate::wallet_agent::Binding {
                currency: draft.pin.currency,
                region: draft.pin.region,
                owner: draft.request.owner.clone(),
            },
            key_file,
            pass,
            &draft.intent.bytes()?,
        )?
    } else {
        crate::signer::read_and_sign(key_file, &draft.request.owner, &draft.intent.bytes()?)?
    };
    let command = Command::Spend(Box::new(SignedIntent {
        intent: draft.intent,
        approvals: vec![approval],
    }));
    // Share the actual consensus execution, including conservation, signature,
    // finality, maturity and dependency quarantine, before returning any signature.
    if draft.request.participants.is_empty() {
        store.template(vec![command.clone()], draft.request.owner)?;
    } else {
        let Command::Spend(signed) = &command else {
            unreachable!()
        };
        store.validate_partial_owner((**signed).clone())?;
    }
    Ok(command)
}

pub fn required_owners(draft: &Draft) -> Vec<String> {
    draft
        .input_owners
        .values()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn prepare_group(store: &Store, request: Request, reserved: &BTreeSet<Hash>) -> Result<Draft> {
    store.safety.check_region(store.chain.region)?;
    require(
        store.chain.blocks.len() < MAX_BLOCKS,
        "wallet cannot spend past history capacity",
    )?;
    require(
        (2..=16).contains(&request.participants.len())
            && request.participants.windows(2).all(|p| p[0] < p[1])
            && request.participants.contains(&request.owner)
            && (1..=32).contains(&request.valid_for_blocks)
            && request.outputs.len() <= 16,
        "group participants, expiry or output bound",
    )?;
    for owner in &request.participants {
        validate_ed25519_public_key(owner)?;
    }
    let inputs = request
        .inputs
        .clone()
        .ok_or("group requires explicit inputs and refund outputs")?;
    require(
        !inputs.is_empty() && inputs.len() <= 16 && inputs.windows(2).all(|p| p[0] < p[1]),
        "group inputs must be ordered, unique and bounded",
    )?;
    let exposure = store.safety.exposure(&store.chain, &store.evidence)?;
    let final_height = finalized_height(store)?;
    let mut total = Amount::ZERO;
    let mut input_owners = BTreeMap::new();
    let mut input_amounts = BTreeMap::new();
    for input in &inputs {
        let coin = store
            .chain
            .ledger
            .coins
            .get(input)
            .ok_or("group input absent or spent")?;
        require(
            !reserved.contains(input)
                && !exposure.quarantined_coins.contains(input)
                && coin.mature <= store.chain.height()
                && (request.remote.is_none() || coin.created <= final_height),
            "group input is reserved, immature, unfinalized or quarantined",
        )?;
        total = add(total, coin.payment.amount)?;
        input_owners.insert(*input, coin.payment.owner.clone());
        input_amounts.insert(*input, coin.payment.amount);
    }
    let actual = input_owners
        .values()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    require(
        actual == request.participants,
        "group participants differ from actual input owners",
    )?;
    for output in &request.outputs {
        validate_ed25519_public_key(&output.owner)?;
        require(output.amount.0 > 0, "group zero output")?;
    }
    let mut used = add(sum(request.outputs.iter().map(|p| p.amount))?, request.fee)?;
    if let Some(remote) = &request.remote {
        store.trust.region(remote.destination)?;
        validate_ed25519_public_key(&remote.recipient.owner)?;
        require(
            remote.destination != store.chain.region
                && remote.recipient.amount.0 > 0
                && remote.destination_fee < remote.recipient.amount,
            "group invalid destination or fee",
        )?;
        used = add(used, remote.recipient.amount)?;
    }
    require(
        total == used && total.0 > 0,
        "group exact inputs, explicit refunds, fees and payment do not conserve",
    )?;
    let pin = Pin::current(store)?;
    let valid_through = request.valid_through.unwrap_or(
        pin.height
            .checked_add(request.valid_for_blocks)
            .ok_or("group expiry overflow")?,
    );
    require(
        valid_through > pin.height
            && valid_through <= pin.height.checked_add(32).ok_or("group expiry overflow")?,
        "group fixed expiry is past or outside the local review horizon",
    )?;
    let intent = Intent {
        currency: pin.currency,
        region: pin.region,
        inputs,
        outputs: request.outputs.clone(),
        fee: request.fee,
        destination: request.remote.as_ref().map(|r| r.destination),
        remote: request.remote.as_ref().map(|r| r.recipient.clone()),
        destination_fee: request
            .remote
            .as_ref()
            .map(|r| r.destination_fee)
            .unwrap_or(Amount::ZERO),
        valid_through,
    };
    Ok(Draft {
        format: "RLD-REGIONAL-WALLET-GROUP-DRAFT-V1".into(),
        pin,
        request,
        intent_id: intent.id()?,
        intent,
        selected_input_total: total,
        change: Amount::ZERO,
        input_owners,
        input_amounts,
    })
}

#[derive(Debug, Serialize)]
pub struct Combined {
    pub commands: Vec<Command>,
    pub intent_id: Hash,
    pub pin: Pin,
    pub complete_owner_authorization: bool,
}
pub fn combine(store: &Store, commands: Vec<Command>) -> Result<Combined> {
    require(
        !commands.is_empty() && commands.len() <= 16,
        "owner contribution bound",
    )?;
    let mut intent = None;
    let mut approvals = BTreeMap::new();
    for command in commands {
        let Command::Spend(signed) = command else {
            return Err("owner contribution must be a spend".into());
        };
        require(
            signed.approvals.len() == 1,
            "exactly one retained owner approval per contribution",
        )?;
        if let Some(old) = &intent {
            require(
                old == &signed.intent,
                "owner contributions sign different exact intents",
            )?;
        } else {
            intent = Some(signed.intent.clone());
        }
        let approval = signed.approvals.into_iter().next().unwrap();
        require(
            approvals.insert(approval.key.clone(), approval).is_none(),
            "duplicate owner contribution",
        )?;
    }
    let intent = intent.unwrap();
    let intent_id = intent.id()?;
    let miner = approvals.keys().next().unwrap().clone();
    let command = Command::Spend(Box::new(SignedIntent {
        intent,
        approvals: approvals.into_values().collect(),
    }));
    store.template(vec![command.clone()], miner)?;
    Ok(Combined {
        commands: vec![command],
        intent_id,
        pin: Pin::current(store)?,
        complete_owner_authorization: true,
    })
}

pub fn receipt(store: &Store, expected: ReceiptExpectation) -> Result<Receipt> {
    validate_ed25519_public_key(&expected.recipient)?;
    require(
        expected.currency == store.trust.currency()?
            && expected.destination == store.chain.region
            && expected.source != expected.destination
            && expected.net_amount.0 > 0,
        "wallet receipt domain mismatch",
    )?;
    store.trust.region(expected.source)?;
    let accepted = store.chain.ledger.imports.get(&expected.export).copied();
    let sid = accepted
        .or_else(|| {
            store
                .journal
                .contact_records
                .values()
                .find(|r| r.export == expected.export)
                .map(|r| r.snapshot)
        })
        .ok_or("wallet has no independently verified evidence for this export")?;
    let record = store.evidence.export(sid, expected.export)?;
    let source = store.evidence.snapshot(sid)?;
    require(
        source.statement.currency == expected.currency
            && source.statement.region == expected.source
            && record.source == expected.source
            && record.destination == expected.destination
            && record.recipient.owner == expected.recipient
            && record
                .recipient
                .amount
                .checked_sub(record.destination_fee)
                .map_err(|e| e.to_string())?
                == expected.net_amount,
        "wallet verified export differs from expected recipient or amount",
    )?;
    let height = store.import_height(expected.export)?;
    require(
        accepted.is_some() == height.is_some(),
        "wallet import index differs from native history",
    )?;
    let mature = height
        .map(|h| {
            h.checked_add(store.trust.currency.maturity)
                .ok_or("wallet maturity overflow")
        })
        .transpose()?;
    let quarantined = store
        .safety
        .check(
            &store.chain,
            &[Command::Import {
                snapshot: sid,
                export: expected.export,
            }],
            &store.evidence,
        )
        .is_err();
    let coin = store
        .chain
        .ledger
        .coins
        .get(&id("output", &(expected.export, 0u32))?);
    let reached = mature.is_some_and(|h| h <= store.chain.height());
    let spendable = reached && coin.is_some() && !quarantined;
    let state = if quarantined {
        "QUARANTINED"
    } else if height.is_none() {
        "VERIFIED_EVIDENCE_PENDING_IMPORT"
    } else if coin.is_none() {
        "ORIGINAL_OUTPUT_SPENT"
    } else if !reached {
        "IMPORT_ACCEPTED_IMMATURE"
    } else {
        "ORIGINAL_OUTPUT_SPENDABLE"
    };
    Ok(Receipt {
        format: "RLD-REGIONAL-WALLET-RECEIPT-V1",
        expected,
        pin: Pin::current(store)?,
        verified_source_checkpoint: sid,
        evidence_verified: true,
        import_accepted: accepted.is_some(),
        import_height: height,
        mature_height: mature,
        maturity_reached: reached,
        original_output_remaining: coin.map(|c| c.payment.amount).unwrap_or(Amount::ZERO),
        original_output_spendable_now: spendable,
        local_finality_covers_import: height
            .is_some_and(|h| finalized_height(store).is_ok_and(|f| f >= h)),
        quarantined,
        state,
        transport_receipt_checked: false,
        remote_current_state_known: false,
        live_rld: false,
    })
}
