//! Invoice-bound funded channel states, never new on-chain money.
//! Every acceptance is an ordered native journal event with a caller-pinned head.
use super::*;
use crate::{
    channels as c,
    storage::{Event, Store},
};
pub const FORMAT: &str = "RLD-NATIVE-CHANNEL-RECEIPT-V1";
/// Existing native challenge rule accepts positive integer fees. A receiver can
/// pin a larger amount; the parties sign that exact budget, never a peer quote.
pub const MIN_CHALLENGE_FEE: Amount = Amount(1);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Expectation {
    pub currency: Hash,
    pub region: Hash,
    pub channel: Hash,
    pub invoice: Hash,
    pub payer: String,
    pub recipient: String,
    pub amount: Amount,
    pub challenge_fee: Amount,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Statement {
    pub format: String,
    pub profile: Hash,
    pub expected: Expectation,
    pub checkpoint: Hash,
    pub reserve: Hash,
    pub previous_receipt: Option<Hash>,
    pub previous_state: Hash,
    pub next_state: Hash,
}
impl Statement {
    pub fn bytes(&self) -> Result<Vec<u8>> {
        encode("channel-invoice-receipt-v1", self)
    }
    pub fn id(&self) -> Result<Hash> {
        id("channel-invoice-receipt-v1", self)
    }
}
pub fn state_id(state: &c::SignedState) -> Result<Hash> {
    id("channel-receipt-state-v1", &state.statement)
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub statement: Statement,
    pub prior: c::SignedState,
    pub next: c::SignedState,
    pub approvals: Vec<Approval>,
}
impl Receipt {
    pub fn id(&self) -> Result<Hash> {
        self.statement.id()
    }
    /// Authenticates the complete already-native-replayed certified observation.
    /// Historical validity grants no present coverage, spendability or freshness.
    pub(crate) fn verify_anchor(&self, trust: &Trust, evidence: &VerifiedEvidence) -> Result<()> {
        self.verify_anchor_inner(trust, evidence, true, true)
    }
    /// Non-authorizing owner review only. Never used by receipt acceptance,
    /// history replay, block execution or conflict authentication.
    pub(crate) fn verify_unsigned_anchor(
        &self,
        trust: &Trust,
        evidence: &VerifiedEvidence,
    ) -> Result<()> {
        require(
            self.next.approvals.is_empty()
                && self.next.witness.is_none()
                && self.approvals.is_empty(),
            "owner draft must contain no next-state or invoice approvals",
        )?;
        self.verify_anchor_inner(trust, evidence, false, false)
    }
    /// Construction-only body authentication for the native witness sealer.
    pub(crate) fn verify_party_anchor(
        &self,
        trust: &Trust,
        evidence: &VerifiedEvidence,
    ) -> Result<()> {
        require(self.next.witness.is_none(), "unwitnessed draft required")?;
        self.verify_anchor_inner(trust, evidence, true, false)
    }
    fn verify_anchor_inner(
        &self,
        trust: &Trust,
        evidence: &VerifiedEvidence,
        complete: bool,
        witnessed: bool,
    ) -> Result<()> {
        encode("complete-channel-receipt", self)?;
        evidence.check_trust(trust)?;
        let s = &self.statement;
        let e = &s.expected;
        require(
            s.format == FORMAT
                && s.profile == c::profile_hash()?
                && e.currency == trust.currency()?
                && c::is_profile(&trust.region(e.region)?.rules)
                && !e.invoice.is_zero()
                && e.amount > Amount::ZERO
                && e.challenge_fee >= MIN_CHALLENGE_FEE,
            "channel receipt profile/domain/invoice/fee",
        )?;
        let (snapshot, ledger) = evidence
            .snapshots
            .get(&s.checkpoint)
            .ok_or("receipt funding checkpoint absent")?;
        require(
            snapshot.statement.region == e.region,
            "receipt checkpoint region",
        )?;
        ledger.audit()?;
        let native = ledger
            .channel_state
            .as_ref()
            .ok_or("receipt checkpoint has no channel funding")?;
        native.declaration.verify(trust, e.region)?;
        let escrow = native
            .book
            .channels
            .get(&e.channel)
            .ok_or("receipt channel absent")?;
        require(
            matches!(escrow.phase, c::Phase::Open) && escrow.opened <= snapshot.statement.height,
            "new fast receipt needs certified open funding",
        )?;
        let (parties, _, _) = escrow.terms()?;
        require(
            parties.contains(&e.payer) && parties.contains(&e.recipient) && e.payer != e.recipient,
            "receipt payer/recipient must be exact different channel parties",
        )?;
        escrow.verify_state(&self.prior, e.channel, &native.declaration)?;
        if complete && witnessed {
            escrow.verify_state(&self.next, e.channel, &native.declaration)?;
            require(
                self.prior
                    .witness
                    .as_ref()
                    .ok_or("prior witness absent")?
                    .statement
                    .inceptions
                    == self
                        .next
                        .witness
                        .as_ref()
                        .ok_or("next witness absent")?
                        .statement
                        .inceptions,
                "receipt replaces original witness owner inceptions",
            )?;
            require(
                self.next
                    .witness
                    .as_ref()
                    .ok_or("state witness absent")?
                    .statement
                    .invoice
                    .as_ref()
                    == Some(s),
                "witness invoice differs from exact receiver receipt",
            )?;
        } else if complete {
            escrow.verify_parties(&self.next, e.channel, &native.declaration)?;
        } else {
            escrow.verify_statement(&self.next.statement, e.channel, &native.declaration)?;
        }
        require(
            s.previous_state == state_id(&self.prior)?
                && s.next_state == state_id(&self.next)?
                && self.next.statement.sequence > self.prior.statement.sequence,
            "receipt state binding or increasing sequence",
        )?;
        let payer = parties
            .iter()
            .position(|p| p == &e.payer)
            .ok_or("payer absent")?;
        let recipient = 1 - payer;
        require(
            self.prior.statement.payouts[payer]
                .checked_sub(e.amount)
                .ok()
                == Some(self.next.statement.payouts[payer])
                && self.prior.statement.payouts[recipient]
                    .checked_add(e.amount)
                    .ok()
                    == Some(self.next.statement.payouts[recipient]),
            "invoice amount differs from exact conserved party allocation delta",
        )?;
        if complete {
            require(
                self.approvals.len() == 2
                    && self.approvals.iter().map(|a| &a.key).eq(parties.iter()),
                "complete ordered joint invoice receipt approvals required",
            )?;
            for approval in &self.approvals {
                verify_bytes(&approval.key, &s.bytes()?, &approval.signature)?;
            }
        }
        let reserve = native
            .book
            .reserves
            .get(&s.reserve)
            .ok_or("receipt fee reserve absent or consumed")?;
        reserve.receipt_coverage(e.challenge_fee)?;
        require(
            reserve.channel == e.channel
                && reserve.allocated <= snapshot.statement.height
                && reserve.coin.mature <= snapshot.statement.height
                && reserve.fee_limit >= e.challenge_fee
                && reserve.coin.payment.amount >= e.challenge_fee,
            "receipt needs one exact mature unconsumed adequately delegated fee reserve",
        )
    }
    pub(crate) fn verify_selected(
        &self,
        chain: &Chain,
        trust: &Trust,
        evidence: &VerifiedEvidence,
    ) -> Result<()> {
        self.verify_anchor(trust, evidence)?;
        self.check_selected(chain, evidence)
    }
    pub(crate) fn check_selected(&self, chain: &Chain, evidence: &VerifiedEvidence) -> Result<()> {
        let s = &self.statement;
        let checkpoint = evidence.snapshot(s.checkpoint)?;
        require(
            chain.region == s.expected.region
                && chain.finalized == Some(s.checkpoint)
                && checkpoint.statement.height == chain.height()
                && checkpoint.statement.block == chain.tip()?
                && checkpoint.statement.state == chain.ledger.root()?
                && checkpoint.statement.epoch == chain.epoch,
            "receipt requires exact currently selected certified native observation",
        )
    }
    pub(crate) fn check_safety(&self, node: &Store) -> Result<()> {
        let e = &self.statement.expected;
        node.safety.check_region(e.region)?;
        let native = node
            .chain
            .ledger
            .channel_state
            .as_ref()
            .ok_or("native channel missing")?;
        let escrow = native
            .book
            .channels
            .get(&e.channel)
            .ok_or("channel missing")?;
        node.safety.check_channels(&escrow.channel_dependencies)?;
        for dependency in &escrow.dependencies {
            node.safety
                .check_region(node.evidence.snapshot(*dependency)?.statement.region)?;
        }
        Ok(())
    }
}
#[derive(Default)]
pub(crate) struct Replay {
    accepted: BTreeMap<Hash, Receipt>,
    invoices: BTreeSet<Hash>,
    latest: BTreeMap<Hash, Hash>,
}
impl Replay {
    pub(crate) fn len(&self) -> usize {
        self.accepted.len()
    }
    pub(crate) fn record(&mut self, receipt: Receipt) -> Result<()> {
        let s = &receipt.statement;
        let e = &s.expected;
        let ident = receipt.id()?;
        require(
            self.accepted.len() < crate::contact::MAX_CONTACTS
                && !self.accepted.contains_key(&ident)
                && !self.invoices.contains(&e.invoice),
            "receipt count or duplicate ordered event/invoice",
        )?;
        if let Some(previous) = self.latest.get(&e.channel) {
            let old = &self.accepted[previous];
            require(
                s.previous_receipt == Some(*previous)
                    && receipt.prior.statement == old.next.statement
                    && receipt.prior.witness.as_ref().map(|p| &p.statement)
                        == old.next.witness.as_ref().map(|p| &p.statement),
                "receipt omits/replaces the exact latest accepted channel state",
            )?;
        } else {
            require(
                s.previous_receipt.is_none() && receipt.prior.statement.sequence == 0,
                "first receipt requires exact jointly signed initial state",
            )?;
        }
        self.invoices.insert(e.invoice);
        self.latest.insert(e.channel, ident);
        self.accepted.insert(ident, receipt);
        Ok(())
    }
}
#[derive(Debug, Serialize)]
pub struct Accepted {
    pub format: &'static str,
    pub receipt: Receipt,
    pub receipt_id: Hash,
    pub accepted_sequence: u64,
    pub history_head: Hash,
    pub exact_retry: bool,
    pub new_fast_payment_accepted: bool,
    pub historical_funded_state: bool,
    pub monetary_ledger_unchanged: bool,
    pub on_chain_balance_credit: bool,
    pub independent_latest_state_protection: bool,
    pub monitoring_or_inclusion_guarantee: bool,
    pub live_rld: bool,
}
fn index(node: &Store) -> Result<Replay> {
    if crate::paged_bft::is_profile(&node.trust.region(node.chain.region)?.rules) {
        return node.paged_receipt_history();
    }
    let mut chain = Chain::new(node.chain.region, &node.trust)?;
    let mut result = Replay::default();
    for event in node.events()? {
        let event = event?;
        if let Event::ChannelReceipt(receipt) = event {
            receipt.verify_selected(&chain, &node.trust, &node.evidence)?;
            result.record(*receipt)?;
        } else {
            node.journal
                .replay_event(&mut chain, &node.trust, &node.evidence, event)?;
        }
    }
    require(
        chain.ledger == node.chain.ledger
            && chain.tip()? == node.chain.tip()?
            && chain.finalized == node.chain.finalized
            && chain.epoch == node.chain.epoch,
        "receipt history differs from complete selected native replay",
    )?;
    Ok(result)
}

/// Read-only native observation for a caller-pinned current store. Complete
/// ordered history is replayed; neither a serialized plan nor a cached sequence
/// can authorize a challenge. Inclusion still needs ordinary block finality.
#[derive(Debug, Serialize)]
pub struct Watch {
    pub format: &'static str,
    pub currency: Hash,
    pub region: Hash,
    pub history_head: Hash,
    pub parent_height: u64,
    pub parent_block: Hash,
    pub commands: Vec<Command>,
    pub observations: Vec<WatchObservation>,
    pub ledger_unchanged: bool,
    pub signing_keys_used: bool,
    pub inclusion_guaranteed: bool,
    pub independent_latest_protection: bool,
    pub live_rld: bool,
}
#[derive(Debug, Serialize)]
pub struct WatchObservation {
    pub channel: Hash,
    pub accepted_receipt: Hash,
    pub accepted_sequence: u64,
    pub closing_sequence: u64,
    pub close_height: u64,
    pub deadline: u64,
    pub challenge_ready: bool,
    pub diagnostic: Option<String>,
}
/// Existing companion proposals have four command slots; preserve that budget.
pub const WATCH_SLOTS: usize = 4;
pub(crate) fn watch(node: &Store, miner: String, expected_head: Hash) -> Result<Watch> {
    node.require_storage_head(expected_head)?;
    require(
        c::is_profile(&node.trust.region(node.chain.region)?.rules),
        "channel watch requires explicit value-channel admission",
    )?;
    validate_ed25519_public_key(&miner)?;
    let history = index(node)?;
    let mut result = Watch {
        format: "RLD-NATIVE-CHANNEL-WATCH-V1",
        currency: node.trust.currency()?,
        region: node.chain.region,
        history_head: expected_head,
        parent_height: node.chain.height(),
        parent_block: node.chain.tip()?,
        commands: vec![],
        observations: vec![],
        ledger_unchanged: true,
        signing_keys_used: false,
        inclusion_guaranteed: false,
        independent_latest_protection: false,
        live_rld: false,
    };
    let Some(native) = &node.chain.ledger.channel_state else {
        return Ok(result);
    };
    native.declaration.verify(&node.trust, node.chain.region)?;
    let mut closing = native
        .book
        .channels
        .iter()
        .filter_map(|(channel, escrow)| {
            let c::Phase::Closing {
                state,
                close_height,
                deadline,
            } = &escrow.phase
            else {
                return None;
            };
            let receipt = history.latest.get(channel)?;
            let accepted = &history.accepted[receipt];
            (accepted.next.statement.sequence > state.statement.sequence).then_some((
                *deadline,
                *channel,
                *close_height,
                state.statement.sequence,
                *receipt,
            ))
        })
        .collect::<Vec<_>>();
    closing.sort(); // earliest absolute deadline first, then exact channel ID
    let next_height = node
        .chain
        .height()
        .checked_add(1)
        .ok_or("watch height overflow")?;
    let mut projected = node.chain.ledger.clone();
    for (deadline, channel, close_height, closing_sequence, receipt_id) in closing {
        let receipt = &history.accepted[&receipt_id];
        let attempted = (|| -> Result<Command> {
            require(
                next_height > close_height && next_height <= deadline,
                "absolute challenge window exhausted",
            )?;
            require(
                result.commands.len() < WATCH_SLOTS,
                "four watch slots occupied; retain evidence for next candidate",
            )?;
            receipt.check_safety(node)?;
            let current = projected
                .channel_state
                .as_ref()
                .ok_or("watch projected channel missing")?;
            let escrow = current
                .book
                .channels
                .get(&channel)
                .ok_or("watch channel missing")?;
            escrow.verify_state(&receipt.next, channel, &current.declaration)?;
            let reserve = current
                .book
                .reserves
                .get(&receipt.statement.reserve)
                .ok_or("accepted receipt reserve absent or consumed")?;
            let fee = receipt.statement.expected.challenge_fee;
            require(
                reserve.remaining_fee()? >= fee,
                "accepted receipt cumulative fee authority exhausted",
            )?;
            require(
                reserve.channel == channel
                    && reserve.allocated <= node.chain.height()
                    && reserve.coin.mature <= node.chain.height()
                    && fee >= MIN_CHALLENGE_FEE
                    && reserve.fee_limit >= fee
                    && reserve.coin.payment.amount >= fee,
                "accepted receipt reserve no longer adequately mature/delegated",
            )?;
            Ok(Command::Channel(Box::new(c::NativeCommand {
                declaration: current.declaration.clone(),
                action: c::SignedAction {
                    intent: c::Intent {
                        rules: current.declaration.rules,
                        currency: current.declaration.currency,
                        region: current.declaration.region,
                        nonce: node.chain.height(),
                        valid_through: next_height,
                        actor: None,
                        previous: Some(current.book.head(&projected, &current.declaration)?),
                        action: c::Action::Challenge {
                            channel,
                            state: Box::new(receipt.next.clone()),
                            reserve: receipt.statement.reserve,
                            fee,
                        },
                    },
                    approvals: vec![],
                },
            })))
        })()
        .and_then(|command| {
            let mut proposed = result.commands.clone();
            proposed.push(command.clone());
            node.safety.check(&node.chain, &proposed, &node.evidence)?;
            // Full shared owner/value/finality/domain execution, on copies only.
            node.chain
                .execute(&proposed, &miner, &node.trust, &node.evidence)?;
            // Next intent pins the prefix BEFORE the one block reward, not
            // Chain::execute's final ledger containing that reward.
            let Command::Channel(body) = &command else {
                return Err("watch command type".into());
            };
            projected = c::execute_native(
                &projected,
                body,
                &c::Context {
                    declaration: &body.declaration,
                    trust: &node.trust,
                    evidence: &node.evidence,
                    safety: &node.safety,
                    height: next_height,
                    miner: &miner,
                },
            )?;
            Ok(command)
        });
        let (challenge_ready, diagnostic) = match attempted {
            Ok(command) => {
                result.commands.push(command);
                (true, None)
            }
            Err(error) => (false, Some(error)),
        };
        result.observations.push(WatchObservation {
            channel,
            accepted_receipt: receipt_id,
            accepted_sequence: receipt.next.statement.sequence,
            closing_sequence,
            close_height,
            deadline,
            challenge_ready,
            diagnostic,
        });
    }
    // A bad/history/incident read cannot be turned into an empty passing plan.
    node.require_storage_head(expected_head)?;
    Ok(result)
}
/// No first signing, key input or ledger debit. Store checks its OS lock,
/// health and separately supplied current storage head before calling this.
pub(crate) fn accept(
    node: &mut Store,
    receipt: Receipt,
    expected: &Expectation,
) -> Result<(Receipt, bool)> {
    require(
        &receipt.statement.expected == expected,
        "receipt differs from caller's exact invoice/amount/fee expectation",
    )?;
    receipt.verify_anchor(&node.trust, &node.evidence)?;
    let mut history = index(node)?;
    let ident = receipt.id()?;
    if let Some(retained) = history.accepted.get(&ident) {
        // Every later full envelope has authenticated before this suppression.
        return Ok((retained.clone(), true));
    }
    if let Some(previous) = history.latest.get(&expected.channel) {
        let old = &history.accepted[previous];
        if old.next.statement.sequence == receipt.next.statement.sequence
            && old.next.statement != receipt.next.statement
        {
            let proof = channel_conflict::Conflict::canonical(
                expected.currency,
                expected.region,
                expected.channel,
                receipt.statement.checkpoint,
                node.journal.evidence.clone(),
                old.next.clone(),
                receipt.next.clone(),
            )?;
            node.observe_conflict(proof)?;
            return Err("complete same-sequence channel conflict retained; receipts and liabilities quarantined".into());
        }
    }
    receipt.verify_selected(&node.chain, &node.trust, &node.evidence)?;
    receipt.check_safety(node)?;
    history.record(receipt.clone())?;
    require(
        history
            .len()
            .checked_add(node.journal.contact_records.len())
            .is_some_and(|n| n <= crate::contact::MAX_CONTACTS),
        "combined native contact/receipt record bound",
    )?;
    let mut journal = node.journal.clone();
    journal
        .events
        .push(Event::ChannelReceipt(Box::new(receipt.clone())));
    node.commit(journal)?;
    Ok((receipt, false))
}
