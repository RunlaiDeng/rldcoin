//! Native typed signature/value kernel; no block/custody/storage activation.
//! Inputs must come from ordinary full native replay, never a decoded cache.
use super::*;
pub const FORMAT: &str = "RLD-REGIONAL-CHANNEL-KERNEL-V2";
pub const WINDOW: u64 = 2016;
pub const MAX_RESERVES: usize = 16;
pub const BFT_RULES: &str = "RLD-REGIONAL-BFT-VALUE-CHANNELS-FIXTURE-V2";
pub const SEGMENTED_RULES: &str = "RLD-REGIONAL-SEGMENTED-VALUE-CHANNELS-FIXTURE-V2";
pub fn is_profile(rules: &str) -> bool {
    rules == BFT_RULES || rules == SEGMENTED_RULES
}
pub fn profile_hash() -> Result<Hash> {
    id(
        "native-channel-profile-v1",
        &(
            include_str!("channel_profile.md"),
            rules_hash(),
            rld_pow::issuance_rules_hash(),
        ),
    )
}
pub fn rules_hash() -> Hash {
    let mut bytes = format!("{FORMAT}\0").into_bytes();
    bytes.extend(include_bytes!("channel_rules.md"));
    Hash(Sha256::digest(bytes).into())
}
pub(crate) fn dependency_bound(
    snapshots: &BTreeSet<Hash>,
    channels: &BTreeSet<Hash>,
) -> Result<()> {
    require(
        snapshots
            .len()
            .checked_add(channels.len())
            .is_some_and(|n| n <= MAX_SNAPSHOTS),
        "complete snapshot/channel dependency bound",
    )
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Declaration {
    pub format: String,
    pub currency: Hash,
    pub region: Hash,
    pub implementation: Hash,
    pub rules: Hash,
    pub authority_signature: String,
}
impl Declaration {
    pub fn bytes(&self) -> Result<Vec<u8>> {
        encode(
            "channel-kernel-declaration-v1",
            &(
                &self.format,
                self.currency,
                self.region,
                self.implementation,
                self.rules,
            ),
        )
    }
    pub fn verify(&self, trust: &Trust, region: Hash) -> Result<()> {
        trust.region(region)?;
        require(
            self.format == FORMAT
                && self.currency == trust.currency()?
                && self.region == region
                && self.implementation == implementation()?
                && self.rules == rules_hash(),
            "channel declaration exact source/rules/domain differ",
        )?;
        verify_bytes(
            &trust.currency.authority,
            &self.bytes()?,
            &self.authority_signature,
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StateStatement {
    pub currency: Hash,
    pub region: Hash,
    pub channel: Hash,
    pub sequence: u64,
    pub payouts: [Amount; 2],
}
impl StateStatement {
    pub fn bytes(&self) -> Result<Vec<u8>> {
        encode("channel-state-v1", self)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedState {
    pub statement: StateStatement,
    pub approvals: Vec<Approval>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum Action {
    Open {
        inputs: Vec<Hash>,
        parties: [String; 2],
        capacity: Amount,
        initial: [Amount; 2],
        change: Vec<Payment>,
        fee: Amount,
    },
    Reserve {
        channel: Hash,
        input: Hash,
        fee_limit: Amount,
    },
    Close {
        channel: Hash,
        state: Box<SignedState>,
        fee_input: Hash,
        fee: Amount,
    },
    Challenge {
        channel: Hash,
        state: Box<SignedState>,
        reserve: Hash,
        fee: Amount,
    },
    Settle {
        channel: Hash,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub rules: Hash,
    pub currency: Hash,
    pub region: Hash,
    pub nonce: u64,
    pub valid_through: u64,
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<Hash>,
    pub action: Action,
}
impl Intent {
    pub fn bytes(&self) -> Result<Vec<u8>> {
        encode("channel-action-v1", self)
    }
    pub fn id(&self) -> Result<Hash> {
        id("channel-action-v1", self)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedAction {
    pub intent: Intent,
    pub approvals: Vec<Approval>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeCommand {
    pub declaration: Declaration,
    pub action: SignedAction,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeState {
    pub declaration: Declaration,
    pub book: Book,
}
impl NativeState {
    pub fn commitment(&self) -> Result<Hash> {
        id("native-channel-state-v1", self)
    }
}
pub(crate) fn validate_profile(ledger: &Ledger, trust: &Trust, region: Hash) -> Result<()> {
    if let Some(state) = &ledger.channel_state {
        require(
            is_profile(&trust.region(region)?.rules),
            "legacy ledger cannot carry channel state",
        )?;
        state.declaration.verify(trust, region)?;
        state.book.audit(ledger, &state.declaration)?;
    }
    Ok(())
}
pub(crate) fn execute_native(
    ledger: &Ledger,
    command: &NativeCommand,
    context: &Context<'_>,
) -> Result<Ledger> {
    require(
        is_profile(&context.trust.region(command.declaration.region)?.rules)
            && context.declaration == &command.declaration,
        "channel command requires explicit value admission",
    )?;
    command
        .declaration
        .verify(context.trust, command.action.intent.region)?;
    validate_profile(ledger, context.trust, command.declaration.region)?;
    let empty = Book::default();
    let book = if let Some(state) = &ledger.channel_state {
        require(
            state.declaration == command.declaration,
            "retained channel declaration differs",
        )?;
        &state.book
    } else {
        &empty
    };
    let previous = command
        .action
        .intent
        .previous
        .ok_or("signed prior native channel head required")?;
    let (book, mut ledger, _) = book.execute(ledger, &command.action, context, previous)?;
    ledger.channel_state = Some(Box::new(NativeState {
        declaration: command.declaration.clone(),
        book,
    }));
    ledger.audit()?;
    Ok(ledger)
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum Phase {
    Open,
    Closing {
        state: Box<SignedState>,
        close_height: u64,
        deadline: u64,
    },
    Settled {
        state: Box<SignedState>,
        close_height: u64,
        deadline: u64,
        settled_height: u64,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Escrow {
    pub funding: Box<SignedAction>,
    pub opened: u64,
    pub dependencies: BTreeSet<Hash>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub channel_dependencies: BTreeSet<Hash>,
    pub phase: Phase,
}
impl Escrow {
    pub(crate) fn terms(&self) -> Result<(&[String; 2], Amount, [Amount; 2])> {
        match &self.funding.intent.action {
            Action::Open {
                parties,
                capacity,
                initial,
                ..
            } => Ok((parties, *capacity, *initial)),
            _ => Err("channel lacks complete funding terms".into()),
        }
    }
    pub(crate) fn verify_state(
        &self,
        state: &SignedState,
        channel: Hash,
        declaration: &Declaration,
    ) -> Result<()> {
        let (parties, capacity, initial) = self.terms()?;
        let statement = &state.statement;
        require(
            statement.currency == declaration.currency
                && statement.region == declaration.region
                && statement.channel == channel
                && (statement.sequence != 0 || statement.payouts == initial)
                && sum(statement.payouts.iter().copied())? == capacity,
            "channel state identity or capacity differs",
        )?;
        actors(
            &state.approvals,
            &parties.iter().cloned().collect(),
            &statement.bytes()?,
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Reservation {
    pub channel: Hash,
    pub coin: Coin,
    pub fee_limit: Amount,
    pub authorization: Box<SignedAction>,
    pub allocated: u64,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Book {
    pub channels: BTreeMap<Hash, Escrow>,
    pub reserves: BTreeMap<Hash, Reservation>,
}
pub struct Context<'a> {
    pub declaration: &'a Declaration,
    pub trust: &'a Trust,
    pub evidence: &'a VerifiedEvidence,
    pub safety: &'a conflict::Safety,
    pub height: u64,
    pub miner: &'a str,
}
fn actors(approvals: &[Approval], expected: &BTreeSet<String>, bytes: &[u8]) -> Result<()> {
    require(
        approvals.len() == expected.len() && approvals.iter().map(|a| &a.key).eq(expected.iter()),
        "exact complete ordered channel actors required",
    )?;
    for approval in approvals {
        verify_bytes(&approval.key, bytes, &approval.signature)?;
    }
    Ok(())
}
fn input(ledger: &Ledger, ident: Hash, height: u64) -> Result<&Coin> {
    let coin = ledger
        .coins
        .get(&ident)
        .ok_or("channel input absent or spent")?;
    require(height >= coin.mature, "immature channel input")?;
    Ok(coin)
}
impl Book {
    pub fn locked(&self) -> Result<Amount> {
        let mut value = Amount::ZERO;
        for escrow in self.channels.values() {
            if !matches!(escrow.phase, Phase::Settled { .. }) {
                value = add(value, escrow.terms()?.1)?;
            }
        }
        sum(self.reserves.values().map(|r| r.coin.payment.amount)).and_then(|r| add(value, r))
    }
    pub fn audit(&self, ledger: &Ledger, declaration: &Declaration) -> Result<()> {
        for coin in ledger.coins.values() {
            dependency_bound(&coin.dependencies, &coin.channel_dependencies)?;
        }
        for export in ledger.exports.values() {
            dependency_bound(&export.dependencies, &export.channel_dependencies)?;
        }
        require(
            self.channels
                .len()
                .checked_add(self.reserves.len())
                .is_some_and(|n| n <= MAX_COINS)
                && ledger.coins.len() <= MAX_COINS
                && ledger.exports.len() <= MAX_COINS
                && ledger.imports.len() <= MAX_COINS,
            "channel/permanent record bound",
        )?;
        for (channel, escrow) in &self.channels {
            dependency_bound(&escrow.dependencies, &escrow.channel_dependencies)?;
            require(
                escrow.channel_dependencies.contains(channel),
                "escrow omits its native channel identity",
            )?;
            require(
                escrow.funding.intent.id()? == *channel
                    && escrow.funding.intent.rules == declaration.rules
                    && escrow.funding.intent.currency == declaration.currency
                    && escrow.funding.intent.region == declaration.region
                    && escrow.dependencies.len() <= MAX_SNAPSHOTS,
                "channel funding/domain/dependency binding",
            )?;
            let (parties, capacity, initial) = escrow.terms()?;
            require(
                parties[0] < parties[1]
                    && capacity.0 > 0
                    && capacity <= Amount::TOTAL_SUPPLY
                    && sum(initial.into_iter())? == capacity,
                "channel terms",
            )?;
            for party in parties {
                validate_ed25519_public_key(party)?;
            }
            require(
                escrow.funding.intent.valid_through >= escrow.opened
                    && escrow.funding.approvals.len() <= 18
                    && escrow
                        .funding
                        .approvals
                        .windows(2)
                        .all(|p| p[0].key < p[1].key)
                    && parties
                        .iter()
                        .all(|p| escrow.funding.approvals.iter().any(|a| &a.key == p))
                    && escrow
                        .funding
                        .intent
                        .actor
                        .as_ref()
                        .is_some_and(|p| escrow.funding.approvals.iter().any(|a| &a.key == p)),
                "retained funding actors",
            )?;
            for approval in &escrow.funding.approvals {
                verify_bytes(
                    &approval.key,
                    &escrow.funding.intent.bytes()?,
                    &approval.signature,
                )?;
            }
            if let Phase::Closing {
                state,
                close_height,
                deadline,
            }
            | Phase::Settled {
                state,
                close_height,
                deadline,
                ..
            } = &escrow.phase
            {
                escrow.verify_state(state, *channel, declaration)?;
                require(
                    *close_height >= escrow.opened
                        && close_height.checked_add(WINDOW) == Some(*deadline),
                    "absolute channel deadline",
                )?;
            }
            if let Phase::Settled {
                deadline,
                settled_height,
                ..
            } = &escrow.phase
            {
                require(settled_height > deadline, "early settlement")?;
            }
        }
        let mut counts = BTreeMap::<Hash, usize>::new();
        for (ident, r) in &self.reserves {
            dependency_bound(&r.coin.dependencies, &r.coin.channel_dependencies)?;
            let escrow = self
                .channels
                .get(&r.channel)
                .ok_or("reservation channel missing")?;
            let (parties, _, _) = escrow.terms()?;
            require(
                !matches!(escrow.phase, Phase::Settled { .. })
                    && !ledger.coins.contains_key(ident)
                    && r.coin.payment.amount.0 > 0
                    && r.fee_limit.0 > 0
                    && r.fee_limit <= r.coin.payment.amount
                    && parties.contains(&r.coin.payment.owner)
                    && r.coin.dependencies.len() <= MAX_SNAPSHOTS,
                "reservation ownership/amount/index",
            )?;
            require(
                matches!(&r.authorization.intent.action, Action::Reserve { channel, input, fee_limit }
                if *channel == r.channel && *input == *ident && *fee_limit == r.fee_limit),
                "retained complete reservation authorization",
            )?;
            require(
                r.authorization.intent.rules == declaration.rules
                    && r.authorization.intent.currency == declaration.currency
                    && r.authorization.intent.region == declaration.region
                    && r.authorization.intent.actor.as_ref() == Some(&r.coin.payment.owner)
                    && r.authorization.intent.valid_through >= r.allocated
                    && r.allocated >= r.coin.mature
                    && r.allocated >= escrow.opened,
                "reservation purpose/height binding",
            )?;
            actors(
                &r.authorization.approvals,
                &[r.coin.payment.owner.clone()].into_iter().collect(),
                &r.authorization.intent.bytes()?,
            )?;
            let count = counts.entry(r.channel).or_default();
            *count += 1;
            require(*count <= MAX_RESERVES, "channel reservation count")?;
        }
        require(
            add(ledger.minted, ledger.received)?
                == add(
                    add(
                        sum(ledger.coins.values().map(|c| c.payment.amount))?,
                        self.locked()?,
                    )?,
                    sum(ledger.exports.values().map(|e| e.recipient.amount))?,
                )?,
            "native U/E/outbound conservation",
        )?;
        encode(
            "channel-kernel-complete-state",
            &(declaration, ledger, self),
        )?;
        Ok(())
    }
    pub fn head(&self, ledger: &Ledger, declaration: &Declaration) -> Result<Hash> {
        self.audit(ledger, declaration)?;
        id(
            "channel-kernel-latest-head-v1",
            &(declaration, ledger, self),
        )
    }
    /// Incident screening of the block's retained ancestors. References born
    /// earlier in this same ordered block are authenticated by shared native
    /// execution; their ancestors are screened at that earlier transition.
    /// Missing references here never authorize anything or waive execution.
    pub(crate) fn retained_dependencies(&self, ledger: &Ledger, action: &Action) -> BTreeSet<Hash> {
        let (channel, inputs): (Option<Hash>, Vec<Hash>) = match action {
            Action::Open { inputs, .. } => (None, inputs.clone()),
            Action::Reserve { channel, input, .. } => (Some(*channel), vec![*input]),
            Action::Close {
                channel, fee_input, ..
            } => (Some(*channel), vec![*fee_input]),
            Action::Challenge { channel, .. } | Action::Settle { channel } => {
                (Some(*channel), vec![])
            }
        };
        let mut deps = BTreeSet::new();
        for input in inputs {
            if let Some(coin) = ledger.coins.get(&input) {
                deps.extend(&coin.dependencies);
            }
        }
        if let Some(channel) = channel {
            if let Some(escrow) = self.channels.get(&channel) {
                deps.extend(&escrow.dependencies);
            }
            for r in self.reserves.values().filter(|r| r.channel == channel) {
                deps.extend(&r.coin.dependencies);
            }
        }
        deps
    }
    pub(crate) fn retained_channel_dependencies(
        &self,
        ledger: &Ledger,
        action: &Action,
    ) -> BTreeSet<Hash> {
        let (channel, inputs): (Option<Hash>, Vec<Hash>) = match action {
            Action::Open { inputs, .. } => (None, inputs.clone()),
            Action::Reserve { channel, input, .. } => (Some(*channel), vec![*input]),
            Action::Close {
                channel, fee_input, ..
            } => (Some(*channel), vec![*fee_input]),
            Action::Challenge { channel, .. } | Action::Settle { channel } => {
                (Some(*channel), vec![])
            }
        };
        let mut deps = BTreeSet::new();
        for input in inputs {
            if let Some(c) = ledger.coins.get(&input) {
                deps.extend(&c.channel_dependencies);
            }
        }
        if let Some(channel) = channel {
            deps.insert(channel);
            if let Some(c) = self.channels.get(&channel) {
                deps.extend(&c.channel_dependencies);
            }
            for r in self.reserves.values().filter(|r| r.channel == channel) {
                deps.extend(&r.coin.channel_dependencies);
            }
        }
        deps
    }
    pub(crate) fn dependencies(&self, ledger: &Ledger, action: &Action) -> Result<BTreeSet<Hash>> {
        let mut deps = BTreeSet::new();
        let mut coin_ids = vec![];
        let channel = match action {
            Action::Open { inputs, .. } => {
                coin_ids.extend(inputs.iter().copied());
                None
            }
            Action::Reserve { channel, input, .. } => {
                coin_ids.push(*input);
                Some(*channel)
            }
            Action::Close {
                channel, fee_input, ..
            } => {
                coin_ids.push(*fee_input);
                Some(*channel)
            }
            Action::Challenge { channel, .. } | Action::Settle { channel } => Some(*channel),
        };
        for ident in coin_ids {
            deps.extend(
                &ledger
                    .coins
                    .get(&ident)
                    .ok_or("missing channel value input")?
                    .dependencies,
            );
        }
        if let Some(channel) = channel {
            deps.extend(
                &self
                    .channels
                    .get(&channel)
                    .ok_or("unknown channel")?
                    .dependencies,
            );
            for r in self.reserves.values().filter(|r| r.channel == channel) {
                deps.extend(&r.coin.dependencies);
            }
        }
        require(
            deps.len() <= MAX_SNAPSHOTS,
            "complete channel dependency bound",
        )?;
        Ok(deps)
    }
    /// Stages a component result on copies. The caller supplies ordinary
    /// fully replayed inputs and an independently retained latest head; this
    /// method does not authorize a native block or accept a serialized cache.
    pub fn execute(
        &self,
        ledger: &Ledger,
        command: &SignedAction,
        context: &Context<'_>,
        expected_latest_head: Hash,
    ) -> Result<(Self, Ledger, Hash)> {
        context
            .declaration
            .verify(context.trust, context.declaration.region)?;
        context.evidence.check_trust(context.trust)?;
        require(
            !expected_latest_head.is_zero()
                && self.head(ledger, context.declaration)? == expected_latest_head,
            "separately retained latest channel head differs",
        )?;
        let intent = &command.intent;
        require(
            intent.rules == context.declaration.rules
                && intent.currency == context.declaration.currency
                && intent.region == context.declaration.region
                && intent.valid_through >= context.height,
            "channel action rules/domain/expiry",
        )?;
        validate_ed25519_public_key(context.miner)?;
        context.safety.check_region(intent.region)?;
        let deps = self.dependencies(ledger, &intent.action)?;
        let mut channel_deps = self.retained_channel_dependencies(ledger, &intent.action);
        if matches!(intent.action, Action::Open { .. }) {
            channel_deps.insert(intent.id()?);
        }
        dependency_bound(&deps, &channel_deps)?;
        context.safety.check_channels(&channel_deps)?;
        for dependency in &deps {
            context
                .safety
                .check_region(context.evidence.snapshot(*dependency)?.statement.region)?;
        }
        let mut book = self.clone();
        let mut value = ledger.clone();
        book.apply(&mut value, command, context, &deps, &channel_deps)?;
        let head = book.head(&value, context.declaration)?;
        Ok((book, value, head))
    }
    fn apply(
        &mut self,
        ledger: &mut Ledger,
        command: &SignedAction,
        context: &Context<'_>,
        deps: &BTreeSet<Hash>,
        channel_deps: &BTreeSet<Hash>,
    ) -> Result<()> {
        let intent = &command.intent;
        let tx = intent.id()?;
        let height = context.height;
        let maturity = height
            .checked_add(context.trust.currency.maturity)
            .ok_or("channel fee maturity overflow")?;
        match &intent.action {
            Action::Open {
                inputs,
                parties,
                capacity,
                initial,
                change,
                fee,
            } => {
                require(
                    !inputs.is_empty()
                        && inputs.len() <= 16
                        && inputs.windows(2).all(|p| p[0] < p[1])
                        && change.len() <= 16
                        && parties[0] < parties[1]
                        && capacity.0 > 0
                        && sum(initial.iter().copied())? == *capacity
                        && !self.channels.contains_key(&tx),
                    "channel open shape",
                )?;
                let mut owners: BTreeSet<String> = parties.iter().cloned().collect();
                for party in parties {
                    validate_ed25519_public_key(party)?;
                }
                let mut amount = Amount::ZERO;
                for ident in inputs {
                    let c = input(ledger, *ident, height)?;
                    owners.insert(c.payment.owner.clone());
                    amount = add(amount, c.payment.amount)?;
                }
                require(
                    intent.actor.as_ref().is_some_and(|a| owners.contains(a)),
                    "funding actor",
                )?;
                actors(&command.approvals, &owners, &intent.bytes()?)?;
                require(
                    amount == add(add(*capacity, *fee)?, sum(change.iter().map(|p| p.amount))?)?,
                    "channel funding conservation",
                )?;
                for ident in inputs {
                    ledger.coins.remove(ident);
                }
                for (i, p) in change.iter().enumerate() {
                    ledger.output_with_channels(
                        tx,
                        i as u32,
                        p.clone(),
                        height,
                        height,
                        deps,
                        channel_deps,
                    )?;
                }
                fee_output(ledger, tx, *fee, context, maturity, deps, channel_deps)?;
                self.channels.insert(
                    tx,
                    Escrow {
                        funding: Box::new(command.clone()),
                        opened: height,
                        dependencies: deps.clone(),
                        channel_dependencies: channel_deps.clone(),
                        phase: Phase::Open,
                    },
                );
            }
            Action::Reserve {
                channel,
                input: ident,
                fee_limit,
            } => {
                let escrow = self
                    .channels
                    .get(channel)
                    .ok_or("unknown reservation channel")?;
                let (parties, _, _) = escrow.terms()?;
                let coin = input(ledger, *ident, height)?.clone();
                require(
                    matches!(escrow.phase, Phase::Open)
                        && parties.contains(&coin.payment.owner)
                        && intent.actor.as_ref() == Some(&coin.payment.owner)
                        && fee_limit.0 > 0
                        && *fee_limit <= coin.payment.amount
                        && !self.reserves.contains_key(ident),
                    "exact owner fee reservation",
                )?;
                actors(
                    &command.approvals,
                    &[coin.payment.owner.clone()].into_iter().collect(),
                    &intent.bytes()?,
                )?;
                ledger.coins.remove(ident);
                let carried = self.channels.get_mut(channel).ok_or("missing channel")?;
                carried.dependencies = deps.clone();
                carried.channel_dependencies = channel_deps.clone();
                let mut retained = coin;
                retained.dependencies = deps.clone();
                retained.channel_dependencies = channel_deps.clone();
                self.reserves.insert(
                    *ident,
                    Reservation {
                        channel: *channel,
                        coin: retained,
                        fee_limit: *fee_limit,
                        authorization: Box::new(command.clone()),
                        allocated: height,
                    },
                );
            }
            Action::Close {
                channel,
                state,
                fee_input,
                fee,
            } => {
                let escrow = self
                    .channels
                    .get(channel)
                    .ok_or("unknown closing channel")?;
                let (parties, _, initial) = escrow.terms()?;
                let actor = intent
                    .actor
                    .as_ref()
                    .ok_or("unilateral close party missing")?;
                require(
                    matches!(escrow.phase, Phase::Open) && parties.contains(actor),
                    "close must be an open channel party",
                )?;
                escrow.verify_state(state, *channel, context.declaration)?;
                require(
                    state.statement.sequence != 0 || state.statement.payouts == initial,
                    "conflicting initial state",
                )?;
                let coin = input(ledger, *fee_input, height)?.clone();
                let owners = [actor.clone(), coin.payment.owner.clone()]
                    .into_iter()
                    .collect();
                actors(&command.approvals, &owners, &intent.bytes()?)?;
                require(
                    fee.0 > 0 && *fee <= coin.payment.amount,
                    "close fee must be funded",
                )?;
                let change = coin
                    .payment
                    .amount
                    .checked_sub(*fee)
                    .map_err(|e| e.to_string())?;
                let deadline = height
                    .checked_add(WINDOW)
                    .ok_or("channel deadline overflow")?;
                ledger.coins.remove(fee_input);
                fee_output(ledger, tx, *fee, context, maturity, deps, channel_deps)?;
                if !change.is_zero() {
                    ledger.output_with_channels(
                        tx,
                        0,
                        Payment {
                            owner: coin.payment.owner,
                            amount: change,
                        },
                        height,
                        height,
                        deps,
                        channel_deps,
                    )?;
                }
                let escrow = self.channels.get_mut(channel).ok_or("unknown channel")?;
                escrow.dependencies = deps.clone();
                escrow.channel_dependencies = channel_deps.clone();
                escrow.phase = Phase::Closing {
                    state: state.clone(),
                    close_height: height,
                    deadline,
                };
            }
            Action::Challenge {
                channel,
                state,
                reserve,
                fee,
            } => {
                require(
                    intent.actor.is_none() && command.approvals.is_empty(),
                    "challenge uses exact predelegated reserve and two-party state only",
                )?;
                let escrow = self
                    .channels
                    .get(channel)
                    .ok_or("unknown challenged channel")?;
                let Phase::Closing {
                    state: old,
                    close_height,
                    deadline,
                } = &escrow.phase
                else {
                    return Err("channel not closing".into());
                };
                require(
                    height > *close_height
                        && height <= *deadline
                        && state.statement.sequence > old.statement.sequence,
                    "higher state on a close successor through absolute deadline",
                )?;
                escrow.verify_state(state, *channel, context.declaration)?;
                let r = self
                    .reserves
                    .get(reserve)
                    .ok_or("fee reserve absent or used")?
                    .clone();
                require(
                    r.channel == *channel && fee.0 > 0 && *fee <= r.fee_limit,
                    "fee exceeds exact channel delegation",
                )?;
                let change = r
                    .coin
                    .payment
                    .amount
                    .checked_sub(*fee)
                    .map_err(|e| e.to_string())?;
                self.reserves.remove(reserve);
                fee_output(ledger, tx, *fee, context, maturity, deps, channel_deps)?;
                if !change.is_zero() {
                    ledger.output_with_channels(
                        tx,
                        0,
                        Payment {
                            owner: r.coin.payment.owner,
                            amount: change,
                        },
                        height,
                        height,
                        deps,
                        channel_deps,
                    )?;
                }
                let escrow = self.channels.get_mut(channel).ok_or("unknown channel")?;
                escrow.dependencies = deps.clone();
                escrow.channel_dependencies = channel_deps.clone();
                if let Phase::Closing { state: best, .. } = &mut escrow.phase {
                    *best = state.clone();
                }
            }
            Action::Settle { channel } => {
                require(
                    intent.actor.is_none() && command.approvals.is_empty(),
                    "settlement is the exact retained script",
                )?;
                let escrow = self
                    .channels
                    .get(channel)
                    .ok_or("unknown settling channel")?
                    .clone();
                let Phase::Closing {
                    state,
                    close_height,
                    deadline,
                } = &escrow.phase
                else {
                    return Err("channel not closing".into());
                };
                require(height > *deadline, "settlement strictly after deadline")?;
                escrow.verify_state(state, *channel, context.declaration)?;
                let (parties, _, _) = escrow.terms()?;
                for (i, (owner, amount)) in parties.iter().zip(&state.statement.payouts).enumerate()
                {
                    if !amount.is_zero() {
                        ledger.output_with_channels(
                            tx,
                            i as u32,
                            Payment {
                                owner: owner.clone(),
                                amount: *amount,
                            },
                            height,
                            height,
                            deps,
                            channel_deps,
                        )?;
                    }
                }
                let reserves: Vec<_> = self
                    .reserves
                    .iter()
                    .filter(|(_, r)| r.channel == *channel)
                    .map(|(id, r)| (*id, r.clone()))
                    .collect();
                for (i, (ident, r)) in reserves.iter().enumerate() {
                    ledger.output_with_channels(
                        tx,
                        32 + i as u32,
                        r.coin.payment.clone(),
                        height,
                        height,
                        deps,
                        channel_deps,
                    )?;
                    self.reserves.remove(ident);
                }
                let retained = self.channels.get_mut(channel).ok_or("unknown channel")?;
                retained.dependencies = deps.clone();
                retained.channel_dependencies = channel_deps.clone();
                retained.phase = Phase::Settled {
                    state: state.clone(),
                    close_height: *close_height,
                    deadline: *deadline,
                    settled_height: height,
                };
            }
        }
        Ok(())
    }
}
fn fee_output(
    ledger: &mut Ledger,
    tx: Hash,
    fee: Amount,
    context: &Context<'_>,
    maturity: u64,
    deps: &BTreeSet<Hash>,
    channel_deps: &BTreeSet<Hash>,
) -> Result<()> {
    if !fee.is_zero() {
        ledger.output_with_channels(
            tx,
            16,
            Payment {
                owner: context.miner.into(),
                amount: fee,
            },
            context.height,
            maturity,
            deps,
            channel_deps,
        )?;
    }
    Ok(())
}
