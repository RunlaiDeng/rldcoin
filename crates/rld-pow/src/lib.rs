//! Regional proof-of-work v1 rules and separately versioned local tooling.
//!
//! The Earth v1 network was adopted under its frozen release source identity.
//! Later wallet/observer additions do not change or reauthorize that consensus
//! adoption; node startup still checks exact implementation binding.
use rld_core::{
    validate_ed25519_public_key, verify_bytes, AdmissionHash32 as Hash, AdmissionWork as Work,
    Amount, TOTAL_SUPPLY_RUNLAI,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub mod storage;
#[cfg(test)]
mod tests;
pub mod transition;
pub type Result<T> = std::result::Result<T, String>;
pub const BLOCK_SECONDS: u64 = 600;
pub const RETARGET_BLOCKS: usize = 144;
pub const HALVING_BLOCKS: u128 = 200_000;
pub const ISSUANCE_RULES: &str = "RLD-ISSUANCE-RESERVE-ERA-V1";
pub const COINBASE_MATURITY: u128 = 100;
pub const MAX_TRANSACTIONS: usize = 128;
pub const MAX_BLOCK_BYTES: usize = 256 * 1024;
pub const MAX_TRACKED_BLOCKS: usize = 100_000;

pub mod decimal {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(n: &u128, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&n.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<u128, D::Error> {
        let s = String::deserialize(d)?;
        if s.is_empty()
            || (s.len() > 1 && s.starts_with('0'))
            || !s.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(serde::de::Error::custom(
                "canonical unsigned decimal string required",
            ));
        }
        s.parse().map_err(serde::de::Error::custom)
    }
}
fn hash(bytes: &[u8]) -> Hash {
    Hash(Sha256::digest(bytes).into())
}
fn check(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn key_bytes(key: &str) -> Result<[u8; 32]> {
    validate_ed25519_public_key(key)?;
    hex::decode(key)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "key length".into())
}
fn json_hash(domain: &[u8], value: &impl Serialize) -> Result<Hash> {
    let mut bytes = domain.to_vec();
    bytes.extend(serde_json::to_vec(value).map_err(|e| e.to_string())?);
    Ok(hash(&bytes))
}

/// Immutable configuration committed by the transition ID. Monetary/timing
/// constants are compiled, not caller-selected or inherited from server flags.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub network_domain: String,
    pub zone_id: String,
    pub currency_genesis: Hash,
    pub manifest_pin: Hash,
    pub transition_id: Hash,
    #[serde(with = "decimal")]
    pub legacy_height: u128,
    pub legacy_state_root: Hash,
    pub started_at: u64,
    pub initial_target: Work,
}
impl Context {
    pub fn validate(&self) -> Result<()> {
        check(
            !self.network_domain.is_empty()
                && self.network_domain.len() <= 128
                && !self.zone_id.is_empty()
                && self.zone_id.len() <= 128,
            "invalid regional context",
        )?;
        check(
            !self.currency_genesis.is_zero()
                && !self.manifest_pin.is_zero()
                && !self.transition_id.is_zero()
                && !self.legacy_state_root.is_zero(),
            "missing pinned ancestry",
        )?;
        check(
            !self.initial_target.is_zero() && self.initial_target <= target_limit(),
            "invalid initial target",
        )?;
        check(
            self.legacy_height.checked_add(1).is_some(),
            "height exhausted",
        )
    }
    pub fn chain_id(&self) -> Result<Hash> {
        self.validate()?;
        json_hash(b"RLD-EARTH-POW-CONTEXT\0", self)
    }
}
pub fn target_limit() -> Work {
    Work([u64::MAX, u64::MAX, u64::MAX, 0x00ff_ffff_ffff_ffff])
}

/// Content identity of the separately specified issuance component. A digest
/// alone grants no genesis, issuance, finality or migration authority.
pub fn issuance_rules_hash() -> Hash {
    let mut bytes = ISSUANCE_RULES.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend(include_bytes!(
        "../../../docs/spec/RESERVE-ERA-ISSUANCE-V1.md"
    ));
    hash(&bytes)
}

/// Section-6 budget: floor-half, except the final zero/one-unit reserve.
pub fn era_budget(reserve: Amount) -> Result<Amount> {
    check(
        reserve.0 <= TOTAL_SUPPLY_RUNLAI,
        "issuance reserve exceeds cap",
    )?;
    Ok(Amount(if reserve.0 < 2 {
        reserve.0
    } else {
        reserve.0 / 2
    }))
}

/// The first remainder slots get one extra unit. A reserve is an era-start
/// quantity, never a wall-clock balance or a remote issuance observation.
pub fn era_reward(reserve: Amount, slot: u128) -> Result<Amount> {
    check(slot < HALVING_BLOCKS, "issuance slot exceeds era")?;
    let budget = era_budget(reserve)?.0;
    let extra = u128::from(slot < budget % HALVING_BLOCKS);
    (budget / HALVING_BLOCKS)
        .checked_add(extra)
        .map(Amount)
        .ok_or_else(|| "issuance reward overflow".into())
}

/// Cumulative issuance for the actually selected origin block count. Fixed
/// constants bound all arithmetic by the cap; no decoded ledger seeds this
/// calculation. At most 118 era steps are needed for the fixed 10^35 reserve,
/// even for a u128::MAX height. Genesis and completed zero-reserve eras mint 0.
pub fn cumulative_emission(blocks: u128) -> u128 {
    let era = blocks / HALVING_BLOCKS;
    let offset = blocks % HALVING_BLOCKS;
    let mut remaining = TOTAL_SUPPLY_RUNLAI;
    for _ in 0..era {
        if remaining == 0 {
            break;
        }
        let budget = era_budget(Amount(remaining))
            .expect("fixed reserve is bounded")
            .0;
        remaining = remaining
            .checked_sub(budget)
            .expect("budget cannot exceed reserve");
    }
    let budget = era_budget(Amount(remaining))
        .expect("fixed reserve is bounded")
        .0;
    let partial = (budget / HALVING_BLOCKS)
        .checked_mul(offset)
        .and_then(|value| value.checked_add(offset.min(budget % HALVING_BLOCKS)))
        .expect("partial era cannot exceed its bounded budget");
    TOTAL_SUPPLY_RUNLAI
        .checked_sub(remaining)
        .and_then(|value| value.checked_add(partial))
        .expect("cumulative issuance cannot exceed fixed cap")
}
pub fn subsidy(sequence: u128) -> Result<Amount> {
    let previous = sequence.checked_sub(1).ok_or("no reward at transition")?;
    Ok(Amount(
        cumulative_emission(sequence)
            .checked_sub(cumulative_emission(previous))
            .ok_or("nonmonotonic issuance")?,
    ))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct OutPoint {
    pub transaction: Hash,
    pub index: u16,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Output {
    pub owner: String,
    pub amount: Amount,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Coin {
    pub output: Output,
    #[serde(with = "decimal")]
    pub spendable_height: u128,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Transfer {
    pub chain_id: Hash,
    pub owner: String,
    pub inputs: Vec<OutPoint>,
    pub outputs: Vec<Output>,
    pub fee: Amount,
    #[serde(with = "decimal")]
    pub valid_through_height: u128,
    pub signature: String,
}
impl Transfer {
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        check(
            (1..=32).contains(&self.inputs.len()) && (1..=8).contains(&self.outputs.len()),
            "transaction resource bound",
        )?;
        check(
            self.inputs.windows(2).all(|w| w[0] < w[1]),
            "inputs must be sorted and unique",
        )?;
        let mut b = b"RLD-EARTH-POW-TRANSFER\0".to_vec();
        b.extend(self.chain_id.0);
        b.extend(key_bytes(&self.owner)?);
        b.extend((self.inputs.len() as u16).to_be_bytes());
        for i in &self.inputs {
            b.extend(i.transaction.0);
            b.extend(i.index.to_be_bytes());
        }
        b.extend((self.outputs.len() as u16).to_be_bytes());
        for o in &self.outputs {
            check(!o.amount.is_zero(), "zero output")?;
            b.extend(key_bytes(&o.owner)?);
            b.extend(o.amount.0.to_be_bytes());
        }
        b.extend(self.fee.0.to_be_bytes());
        b.extend(self.valid_through_height.to_be_bytes());
        Ok(b)
    }
    pub fn id(&self) -> Result<Hash> {
        Ok(hash(&self.signing_bytes()?))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub chain_id: Hash,
    pub parent: Hash,
    #[serde(with = "decimal")]
    pub height: u128,
    pub timestamp: u64,
    pub target: Work,
    pub miner: String,
    pub transactions_root: Hash,
    pub state_root: Hash,
    #[serde(with = "decimal")]
    pub nonce: u128,
}
impl Header {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut b = b"RLD-EARTH-POW-HEADER\0".to_vec();
        b.extend(self.chain_id.0);
        b.extend(self.parent.0);
        b.extend(self.height.to_be_bytes());
        b.extend(self.timestamp.to_be_bytes());
        b.extend(self.target.to_be_bytes());
        b.extend(key_bytes(&self.miner)?);
        b.extend(self.transactions_root.0);
        b.extend(self.state_root.0);
        b.extend(self.nonce.to_be_bytes());
        Ok(b)
    }
    pub fn id(&self) -> Result<Hash> {
        Ok(hash(&Sha256::digest(self.canonical_bytes()?)))
    }
    pub fn work_valid(&self) -> Result<bool> {
        Ok(Work::from_be_bytes(self.id()?.0) <= self.target)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Block {
    pub header: Header,
    pub transactions: Vec<Transfer>,
}
fn transactions_root(txs: &[Transfer]) -> Result<Hash> {
    check(txs.len() <= MAX_TRANSACTIONS, "too many transactions")?;
    // Commit signatures as well as transaction IDs, preventing alternate-body
    // encodings under one header. Typed JSON field order is fixed by this schema.
    json_hash(b"RLD-EARTH-POW-TRANSACTIONS\0", &txs)
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct State {
    pub coins: BTreeMap<OutPoint, Coin>,
    pub emitted: Amount,
}
impl State {
    pub fn root(&self) -> Result<Hash> {
        let mut digest = Sha256::new();
        digest.update(b"RLD-EARTH-POW-UTXO\0");
        digest.update(self.emitted.0.to_be_bytes());
        let mut total = Amount::ZERO;
        let mut owner_bytes = BTreeMap::new();
        for (p, c) in &self.coins {
            total = total
                .checked_add(c.output.amount)
                .map_err(|e| e.to_string())?;
            digest.update(p.transaction.0);
            digest.update(p.index.to_be_bytes());
            let key = match owner_bytes.get(&c.output.owner) {
                Some(key) => *key,
                None => {
                    let key = key_bytes(&c.output.owner)?;
                    owner_bytes.insert(c.output.owner.clone(), key);
                    key
                }
            };
            digest.update(key);
            digest.update(c.output.amount.0.to_be_bytes());
            digest.update(c.spendable_height.to_be_bytes());
        }
        check(
            total == self.emitted && total.0 <= TOTAL_SUPPLY_RUNLAI,
            "supply conservation failed",
        )?;
        Ok(Hash(digest.finalize().into()))
    }
    pub fn balance(&self, owner: &str, next_height: u128) -> (Amount, Amount) {
        let mut ready = 0;
        let mut immature = 0;
        for c in self.coins.values().filter(|c| c.output.owner == owner) {
            if c.spendable_height <= next_height {
                ready += c.output.amount.0;
            } else {
                immature += c.output.amount.0;
            }
        }
        (Amount(ready), Amount(immature))
    }
    fn execute(&self, context: &Context, header: &Header, txs: &[Transfer]) -> Result<Self> {
        self.clone().execute_owned(context, header, txs)
    }
    /// Consume a private candidate state so block validation and historical
    /// replay do not clone the entire UTXO map a second time.
    fn execute_owned(self, context: &Context, header: &Header, txs: &[Transfer]) -> Result<Self> {
        let chain_id = context.chain_id()?;
        check(header.chain_id == chain_id, "wrong chain")?;
        let sequence = header
            .height
            .checked_sub(context.legacy_height)
            .ok_or("height before transition")?;
        let reward = subsidy(sequence)?;
        let mut next = self;
        let mut fees = Amount::ZERO;
        let mut ids = BTreeSet::new();
        for tx in txs {
            check(
                tx.chain_id == chain_id && tx.valid_through_height >= header.height,
                "transaction context or expiry",
            )?;
            check(tx.fee.0 >= 1, "minimum fee is one runlai")?;
            let bytes = tx.signing_bytes()?;
            verify_bytes(&tx.owner, &bytes, &tx.signature)?;
            let id = tx.id()?;
            check(ids.insert(id), "duplicate transaction")?;
            let mut input = Amount::ZERO;
            for p in &tx.inputs {
                let c = next.coins.get(p).ok_or("unknown or spent input")?;
                check(
                    c.output.owner == tx.owner && c.spendable_height <= header.height,
                    "owner or maturity mismatch",
                )?;
                input = input
                    .checked_add(c.output.amount)
                    .map_err(|e| e.to_string())?;
            }
            let output = tx
                .outputs
                .iter()
                .try_fold(tx.fee, |a, o| a.checked_add(o.amount))
                .map_err(|e| e.to_string())?;
            check(
                input == output,
                "transaction must conserve inputs, outputs and fee",
            )?;
            for p in &tx.inputs {
                next.coins.remove(p);
            }
            for (i, o) in tx.outputs.iter().enumerate() {
                let p = OutPoint {
                    transaction: id,
                    index: i as u16,
                };
                check(
                    next.coins
                        .insert(
                            p,
                            Coin {
                                output: o.clone(),
                                spendable_height: header.height,
                            },
                        )
                        .is_none(),
                    "output collision",
                )?;
            }
            fees = fees.checked_add(tx.fee).map_err(|e| e.to_string())?;
        }
        let coinbase = reward.checked_add(fees).map_err(|e| e.to_string())?;
        if !coinbase.is_zero() {
            let mut id = b"RLD-EARTH-POW-COINBASE\0".to_vec();
            id.extend(chain_id.0);
            id.extend(header.parent.0);
            id.extend(header.height.to_be_bytes());
            id.extend(key_bytes(&header.miner)?);
            id.extend(header.transactions_root.0);
            let p = OutPoint {
                transaction: hash(&id),
                index: 0,
            };
            let maturity = header
                .height
                .checked_add(COINBASE_MATURITY)
                .ok_or("maturity height overflow")?;
            check(
                next.coins
                    .insert(
                        p,
                        Coin {
                            output: Output {
                                owner: header.miner.clone(),
                                amount: coinbase,
                            },
                            spendable_height: maturity,
                        },
                    )
                    .is_none(),
                "coinbase collision",
            )?;
        }
        next.emitted = next
            .emitted
            .checked_add(reward)
            .map_err(|e| e.to_string())?;
        check(
            next.emitted.0 == cumulative_emission(sequence),
            "noncanonical emission",
        )?;
        next.root()?;
        Ok(next)
    }
}

/// Integer wide multiply then divide, preserving high limbs before clamping.
fn scale_target(target: Work, numerator: u64, denominator: u64) -> Result<Work> {
    check(denominator > 0, "zero retarget denominator")?;
    let mut wide = [0u64; 5];
    let mut carry = 0u128;
    for (i, limb) in target.0.iter().enumerate() {
        let p = *limb as u128 * numerator as u128 + carry;
        wide[i] = p as u64;
        carry = p >> 64;
    }
    wide[4] = carry as u64;
    let mut remainder = 0u128;
    for i in (0..5).rev() {
        let n = (remainder << 64) | wide[i] as u128;
        wide[i] = (n / denominator as u128) as u64;
        remainder = n % denominator as u128;
    }
    Ok(if wide[4] > 0 {
        target_limit()
    } else {
        Work(wide[..4].try_into().unwrap())
            .min(target_limit())
            .max(Work([1, 0, 0, 0]))
    })
}
#[derive(Clone, Debug)]
struct Entry {
    block: Block,
    work: Work,
}
struct Prepared {
    id: Hash,
    entry: Entry,
    state: State,
    preferred: bool,
}

#[derive(Clone, Debug)]
pub struct Chain {
    pub context: Context,
    blocks: BTreeMap<Hash, Entry>,
    tip: Hash,
    state: State,
    side_state: Option<(Hash, State)>,
}

/// An internally replayed best-chain state and its exact PoW header anchor.
/// The caller must separately verify the signed adoption and chosen network;
/// this type does not turn a claimed chain into an authorized successor.
pub struct ReplayedPowAnchor<'a> {
    chain_id: Hash,
    tip: Hash,
    state_root: Hash,
    height: u128,
    state: &'a State,
}
impl<'a> ReplayedPowAnchor<'a> {
    pub fn chain_id(&self) -> Hash {
        self.chain_id
    }
    pub fn tip(&self) -> Hash {
        self.tip
    }
    pub fn state_root(&self) -> Hash {
        self.state_root
    }
    pub fn height(&self) -> u128 {
        self.height
    }
    pub fn state(&self) -> &'a State {
        self.state
    }
}
impl Chain {
    pub fn new(context: Context) -> Result<Self> {
        context.validate()?;
        let tip = context.chain_id()?;
        Ok(Self {
            context,
            blocks: BTreeMap::new(),
            tip,
            state: State::default(),
            side_state: None,
        })
    }
    pub fn tip(&self) -> Hash {
        self.tip
    }
    pub fn state(&self) -> &State {
        &self.state
    }
    pub fn replay_anchor(&self) -> Result<ReplayedPowAnchor<'_>> {
        let chain_id = self.context.chain_id()?;
        // A fresh Earth value chain can begin directly from its empty,
        // signed genesis. No preliminary PoW reward or predecessor block is
        // needed to establish a value-state anchor.
        if self.context.legacy_height == 0 && self.blocks.is_empty() {
            check(
                self.tip == chain_id
                    && self.state.emitted == Amount::ZERO
                    && self.state.coins.is_empty(),
                "fresh Earth genesis is not empty",
            )?;
            return Ok(ReplayedPowAnchor {
                chain_id,
                tip: chain_id,
                state_root: self.state.root()?,
                height: 0,
                state: &self.state,
            });
        }
        let block = self
            .block(self.tip)
            .ok_or("PoW anchor needs an accepted block")?;
        check(
            block.header.chain_id == chain_id
                && block.header.id()? == self.tip
                && block.header.height == self.height()
                && block.header.state_root == self.state.root()?,
            "PoW anchor does not match replayed best state",
        )?;
        Ok(ReplayedPowAnchor {
            chain_id,
            tip: self.tip,
            state_root: block.header.state_root,
            height: block.header.height,
            state: &self.state,
        })
    }
    pub fn capacity_available(&self) -> bool {
        self.blocks.len() < MAX_TRACKED_BLOCKS
    }
    /// Producer clock choice only; received headers still face strict validation.
    pub fn template_time(&self, clock: u64) -> Result<u64> {
        let mut times = Vec::new();
        let mut id = self.tip;
        while let Some(entry) = self.blocks.get(&id) {
            times.push(entry.block.header.timestamp);
            if times.len() == 11 {
                break;
            }
            id = entry.block.header.parent;
        }
        if times.len() < 11 {
            times.push(self.context.started_at);
        }
        times.sort_unstable();
        Ok(clock.max(
            times[times.len() / 2]
                .checked_add(1)
                .ok_or("timestamp overflow")?,
        ))
    }
    pub fn height(&self) -> u128 {
        self.blocks
            .get(&self.tip)
            .map_or(self.context.legacy_height, |e| e.block.header.height)
    }
    pub fn chainwork(&self) -> Work {
        self.blocks.get(&self.tip).map_or(Work::ZERO, |e| e.work)
    }
    pub fn block(&self, id: Hash) -> Option<&Block> {
        self.blocks.get(&id).map(|e| &e.block)
    }
    pub fn state_root(&self) -> Result<Hash> {
        match self.blocks.get(&self.tip) {
            Some(e) => Ok(e.block.header.state_root),
            None => self.state.root(),
        }
    }
    pub fn best_ids(&self) -> Result<Vec<Hash>> {
        let root = self.context.chain_id()?;
        let mut id = self.tip;
        let mut result = Vec::new();
        while id != root {
            result.push(id);
            id = self
                .blocks
                .get(&id)
                .ok_or("missing ancestry")?
                .block
                .header
                .parent;
        }
        result.reverse();
        Ok(result)
    }
    pub fn best_blocks(&self) -> Result<Vec<&Block>> {
        self.ancestry(self.tip)
    }
    fn ancestry(&self, mut parent: Hash) -> Result<Vec<&Block>> {
        let root = self.context.chain_id()?;
        let mut path = Vec::new();
        while parent != root {
            let e = self.blocks.get(&parent).ok_or("unknown block parent")?;
            path.push(&e.block);
            parent = e.block.header.parent;
        }
        path.reverse();
        Ok(path)
    }
    fn state_at(&self, parent: Hash) -> Result<State> {
        if parent == self.tip {
            return Ok(self.state.clone());
        }
        if let Some((id, state)) = &self.side_state {
            if *id == parent {
                return Ok(state.clone());
            }
        }
        let mut state = State::default();
        for b in self.ancestry(parent)? {
            state = state.execute_owned(&self.context, &b.header, &b.transactions)?;
        }
        Ok(state)
    }
    fn next_header(
        &self,
        parent: Hash,
        miner: String,
        timestamp: u64,
        txs: &[Transfer],
    ) -> Result<Header> {
        let root = self.context.chain_id()?;
        let mut cursor = parent;
        let mut recent = Vec::with_capacity(RETARGET_BLOCKS);
        while cursor != root && recent.len() < RETARGET_BLOCKS {
            let entry = self.blocks.get(&cursor).ok_or("unknown block parent")?;
            recent.push(&entry.block.header);
            cursor = entry.block.header.parent;
        }
        let parent_height = recent
            .first()
            .map_or(self.context.legacy_height, |header| header.height);
        let height = parent_height.checked_add(1).ok_or("height overflow")?;
        let parent_depth = parent_height
            .checked_sub(self.context.legacy_height)
            .ok_or("parent precedes transition")?;
        let mut timestamps: Vec<_> = recent
            .iter()
            .take(11)
            .map(|header| header.timestamp)
            .collect();
        if timestamps.len() < 11 {
            timestamps.push(self.context.started_at);
        }
        timestamps.sort_unstable();
        let median = timestamps[timestamps.len() / 2];
        check(
            timestamp > median,
            "timestamp must exceed median of predecessors",
        )?;
        let mut target = recent
            .first()
            .map_or(self.context.initial_target, |header| header.target);
        if parent_depth != 0 && parent_depth % RETARGET_BLOCKS as u128 == 0 {
            check(recent.len() == RETARGET_BLOCKS, "missing retarget ancestry")?;
            let end = recent[0].timestamp;
            let begin = recent[RETARGET_BLOCKS - 1].timestamp;
            let expected = (RETARGET_BLOCKS as u64 - 1) * BLOCK_SECONDS;
            let elapsed = end.saturating_sub(begin).clamp(expected / 4, expected * 4);
            target = scale_target(target, elapsed, expected)?;
        }
        Ok(Header {
            chain_id: self.context.chain_id()?,
            parent,
            height,
            timestamp,
            target,
            miner,
            transactions_root: transactions_root(txs)?,
            state_root: Hash([0; 32]),
            nonce: 0,
        })
    }
    pub fn template(
        &self,
        miner: String,
        timestamp: u64,
        transactions: Vec<Transfer>,
    ) -> Result<Block> {
        let mut h = self.next_header(self.tip, miner, timestamp, &transactions)?;
        h.state_root = self
            .state
            .execute(&self.context, &h, &transactions)?
            .root()?;
        let b = Block {
            header: h,
            transactions,
        };
        check(
            serde_json::to_vec(&b).map_err(|e| e.to_string())?.len() <= MAX_BLOCK_BYTES,
            "block byte bound",
        )?;
        Ok(b)
    }
    /// Failure atomic: all validation and candidate state computation precede
    /// insertion or preferred-tip mutation. Durable callers must persist before
    /// exposing the staged Chain as their active state.
    pub fn accept(&mut self, block: Block, now: u64) -> Result<bool> {
        match self.prepare(block, now)? {
            Some(prepared) => Ok(self.commit(prepared)),
            None => Ok(false),
        }
    }
    fn prepare(&self, block: Block, now: u64) -> Result<Option<Prepared>> {
        check(
            self.blocks.len() < MAX_TRACKED_BLOCKS,
            "local block capacity reached; preserve history",
        )?;
        check(
            serde_json::to_vec(&block).map_err(|e| e.to_string())?.len() <= MAX_BLOCK_BYTES,
            "block byte bound",
        )?;
        check(
            block.header.timestamp <= now.checked_add(7200).ok_or("clock overflow")?,
            "block too far in future",
        )?;
        let id = block.header.id()?;
        if self.blocks.contains_key(&id) {
            return Ok(None);
        }
        let expected = self.next_header(
            block.header.parent,
            block.header.miner.clone(),
            block.header.timestamp,
            &block.transactions,
        )?;
        check(
            block.header.chain_id == expected.chain_id
                && block.header.height == expected.height
                && block.header.target == expected.target
                && block.header.transactions_root == expected.transactions_root,
            "header context, target or body mismatch",
        )?;
        check(block.header.work_valid()?, "insufficient proof of work")?;
        let state = self.state_at(block.header.parent)?.execute_owned(
            &self.context,
            &block.header,
            &block.transactions,
        )?;
        check(
            state.root()? == block.header.state_root,
            "state root mismatch",
        )?;
        // Exact consensus work convention shared with the existing U256 math:
        // floor((2^256 - 1)/(target + 1)). It is never a block-count surrogate.
        let target_work = rld_core::header_work(block.header.target);
        check(!target_work.is_zero(), "zero-work target")?;
        let parent_work = self
            .blocks
            .get(&block.header.parent)
            .map_or(Work::ZERO, |e| e.work);
        let work = parent_work
            .checked_add(target_work)
            .ok_or("cumulative work overflow")?;
        let preferred = work > self.chainwork();
        Ok(Some(Prepared {
            id,
            entry: Entry { block, work },
            state,
            preferred,
        }))
    }
    fn commit(&mut self, p: Prepared) -> bool {
        self.blocks.insert(p.id, p.entry);
        if p.preferred {
            let previous = std::mem::replace(&mut self.state, p.state);
            self.side_state = Some((self.tip, previous));
            self.tip = p.id;
        } else {
            self.side_state = Some((p.id, p.state));
        }
        p.preferred
    }
}

/// Bounded mining batch; callers refresh templates/cancellation between batches.
/// Verification and mining hash the same canonical bytes. No reward exists until
/// the completed block passes full validation and is durably recorded.
pub fn mine_batch(block: &mut Block, attempts: u64) -> Result<bool> {
    let mut bytes = block.header.canonical_bytes()?;
    let offset = bytes.len() - 16;
    for _ in 0..attempts {
        bytes[offset..].copy_from_slice(&block.header.nonce.to_be_bytes());
        let proof = hash(&Sha256::digest(&bytes));
        if Work::from_be_bytes(proof.0) <= block.header.target {
            return Ok(true);
        }
        block.header.nonce = block
            .header
            .nonce
            .checked_add(1)
            .ok_or("nonce exhausted; refresh template")?;
    }
    Ok(false)
}
