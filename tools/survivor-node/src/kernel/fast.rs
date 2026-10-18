//! Incompatible NO_VALUE_ONLY native escrow candidate. Ordinary Survivor-1 is
//! unchanged; no decoded balance or component certificate initializes this ledger.
use super::*;
use crate::fast_fee_claims::{Contract, FeeFloors};
mod codec;
use codec::{Action, Open, Operation};

const WINDOW_BLOCKS: u64 = 2016;
const WINDOW_SECONDS: u64 = 172800;
const MAX_CHANNELS: u32 = 1024;
const MAX_SLOTS: u64 = 1_000_000;
fn window_passed(close_height: u128, close_time: u64, height: u128, time: u64) -> bool {
    height > close_height + WINDOW_BLOCKS as u128 && time > close_time + WINDOW_SECONDS
}
fn ftag(s: &str) -> Vec<u8> {
    [b"RLD-FAST-ESCROW-1/".as_slice(), s.as_bytes(), &[0]].concat()
}
fn fh(s: &str, raw: &[u8]) -> Hash {
    Sha256::digest([ftag(s), raw.to_vec()].concat()).into()
}
fn header_id(raw: &[u8]) -> Hash {
    Sha256::digest(fh("HEADER", &raw[..268])).into()
}
pub fn genesis_id(raw: &[u8]) -> Hash {
    fh("GENESIS", raw)
}
pub fn operation_id(raw: &[u8]) -> Hash {
    fh("OP", raw)
}
/// Decode/signature validation only, not monetary admission or funding proof.
pub fn validate_operation(raw: &[u8], chain: Hash) -> Result<()> {
    codec::decode(raw, chain).map(|_| ())
}

#[derive(Clone)]
struct Closing {
    height: u128,
    time: u64,
    principal: Vec<u8>,
    slots: [u64; 2],
    proofs: [Option<Vec<u8>>; 2],
}
#[derive(Clone)]
struct Escrow {
    opening: Vec<u8>,
    terms: Open,
    parent: Hash,
    height: u128,
    miner: Hash,
    birth: Hash,
    closing: Option<Closing>,
}
type Book = BTreeMap<Hash, Escrow>;
impl Escrow {
    fn locked(&self) -> u128 {
        self.terms.principal.iter().sum::<u128>()
            + (0..2)
                .map(|i| self.terms.limits[i] as u128 * self.terms.rates[i])
                .sum::<u128>()
    }
    fn context(&self, chain: Hash, id: Hash) -> Vec<u8> {
        let funding = fh(
            "FUNDING",
            &[chain.as_slice(), self.birth.as_slice(), id.as_slice()].concat(),
        );
        let mut raw = vec![0, 1, 0, 1];
        raw.extend(chain);
        raw.extend(funding);
        for owner in self.terms.owners {
            raw.extend(owner);
        }
        raw.extend(self.miner);
        raw.extend(self.terms.principal.iter().sum::<u128>().to_be_bytes());
        for i in 0..2 {
            raw.extend(self.terms.limits[i].to_be_bytes());
            raw.extend(self.terms.rates[i].to_be_bytes());
        }
        raw
    }
    fn certificate(
        &self,
        chain: Hash,
        id: Hash,
        raw: &[u8],
    ) -> Result<crate::fast_fee_claims::Claim> {
        let claim = Contract::decode(&self.context(chain, id))?.verify(raw)?;
        require(
            claim.slots[0].checked_add(claim.slots[1]) == Some(claim.sequence),
            "INVALID fast state sequence",
        )?;
        require(
            claim.sequence != 0 || claim.balances == self.terms.principal,
            "INVALID fast initial allocation",
        )?;
        Ok(claim)
    }
    fn floors(&self, chain: Hash, id: Hash) -> Result<FeeFloors> {
        let mut floors = FeeFloors::new(Contract::decode(&self.context(chain, id))?);
        if let Some(c) = &self.closing {
            for proof in c.proofs.iter().flatten() {
                self.certificate(chain, id, proof)?;
                floors.observe(proof)?;
            }
            require(floors.slots() == c.slots, "INVALID fast retained fee proof")?;
        }
        Ok(floors)
    }
    fn record(&self, id: Hash) -> Vec<u8> {
        let mut v = id.to_vec();
        v.extend((self.opening.len() as u32).to_be_bytes());
        v.extend(&self.opening);
        v.extend(self.parent);
        v.extend(self.height.to_be_bytes());
        v.extend(self.miner);
        v.push(u8::from(self.closing.is_some()));
        if let Some(c) = &self.closing {
            v.extend(c.height.to_be_bytes());
            v.extend(c.time.to_be_bytes());
            v.extend((c.principal.len() as u16).to_be_bytes());
            v.extend(&c.principal);
            for n in c.slots {
                v.extend(n.to_be_bytes());
            }
            for proof in &c.proofs {
                let p = proof.as_deref().unwrap_or(&[]);
                v.extend((p.len() as u16).to_be_bytes());
                v.extend(p);
            }
        }
        v
    }
}
fn root(chain: Hash, issued: u128, coins: &Coins, book: &Book) -> Hash {
    let mut raw = chain.to_vec();
    raw.extend(issued.to_be_bytes());
    raw.extend((coins.len() as u128).to_be_bytes());
    raw.extend(tree(coins));
    raw.extend((book.len() as u32).to_be_bytes());
    for (id, e) in book {
        let record = e.record(*id);
        raw.extend((record.len() as u32).to_be_bytes());
        raw.extend(record);
    }
    fh("STATE", &raw)
}
fn put(
    coins: &mut Coins,
    id: Hash,
    index: u16,
    owner: Hash,
    amount: u128,
    maturity: u128,
) -> Result<()> {
    if amount > 0 {
        require(
            coins
                .insert(
                    outpoint(id, index),
                    Coin {
                        owner,
                        amount,
                        maturity,
                    },
                )
                .is_none(),
            "INVALID fast output collision",
        )?;
    }
    Ok(())
}
fn debit(
    parent: &Coins,
    next: &mut Coins,
    inputs: &[Vec<u8>],
    owner: Hash,
    height: u128,
    expected: u128,
) -> Result<()> {
    let mut total = 0u128;
    for input in inputs {
        let coin = parent.get(input).ok_or("WAITING_FOR_INPUT fast parent")?;
        require(
            coin.owner == owner && coin.maturity <= height,
            "INVALID fast input ownership/maturity",
        )?;
        total = total
            .checked_add(coin.amount)
            .ok_or("INVALID fast input sum")?;
        require(next.remove(input).is_some(), "INVALID fast double spend")?;
    }
    require(
        total == expected && total <= CAP,
        "INVALID fast input conservation",
    )
}

/// Full genesis/PoW/owner/value execution. No service, archive or wallet custody
/// qualification is implied by constructing this separate candidate engine.
#[derive(Clone)]
pub struct Ledger {
    chain: Hash,
    tip: Tip,
    recent: VecDeque<Tip>,
    coins: Coins,
    book: Book,
    max_coins: usize,
}
impl Ledger {
    pub fn from_genesis(raw: &[u8], pin: Hash, max_coins: usize) -> Result<Self> {
        require(raw.len() == 113, "INVALID fast genesis length")?;
        let mut r = Reader::new(raw);
        require(
            r.take(8)? == b"RLDFAST1" && r.u16()? == 1 && r.u16()? == 1,
            "UNSUPPORTED fast genesis",
        )?;
        require(r.take(1)? == [0], "UNSUPPORTED fast monetary activation")?;
        require(r.fixed::<32>()? != [0; 32], "INVALID fast discriminator")?;
        let time = r.u64()?;
        require(
            time <= u64::MAX - WINDOW_SECONDS,
            "INVALID fast genesis time",
        )?;
        require(
            Big::from32(r.take(32)?) == limit(),
            "INVALID fast initial target",
        )?;
        require(
            r.u64()? == WINDOW_BLOCKS
                && r.u64()? == WINDOW_SECONDS
                && r.u32()? == MAX_CHANNELS
                && r.u64()? == MAX_SLOTS,
            "UNSUPPORTED fast parameters",
        )?;
        r.end()?;
        let chain = genesis_id(raw);
        require(chain == pin && max_coins > 0, "INVALID fast pin/resource")?;
        let coins = Coins::new();
        let book = Book::new();
        let tip = Tip {
            id: chain,
            height: 0,
            time,
            base: limit(),
            work: Big::zero(),
            root: root(chain, 0, &coins, &book),
        };
        Ok(Self {
            chain,
            tip: tip.clone(),
            recent: VecDeque::from([tip]),
            coins,
            book,
            max_coins,
        })
    }
    pub fn chain_id(&self) -> Hash {
        self.chain
    }
    pub fn tip(&self) -> &Tip {
        &self.tip
    }
    pub fn coins(&self) -> &Coins {
        &self.coins
    }
    pub fn issued(&self) -> u128 {
        emission(self.tip.height).1
    }
    pub fn locked(&self) -> u128 {
        self.book.values().map(Escrow::locked).sum()
    }
    pub fn active_channels(&self) -> usize {
        self.book.len()
    }
    pub fn fee_context(&self, id: Hash) -> Result<Vec<u8>> {
        Ok(self
            .book
            .get(&id)
            .ok_or("MISSING fast escrow")?
            .context(self.chain, id))
    }
    fn timing(&self, time: u64) -> Result<(Big, Big)> {
        let mut times: Vec<_> = self.recent.iter().rev().take(11).map(|t| t.time).collect();
        times.sort_unstable();
        require(
            time > self.tip.time && time > times[times.len() / 2],
            "INVALID fast timestamp",
        )?;
        let base = if self.tip.height == 0 {
            limit()
        } else if self.tip.height.is_multiple_of(144) {
            scaled(self.tip.base, self.tip.time - self.recent[0].time)
        } else {
            self.tip.base
        };
        Ok((
            base,
            if time - self.tip.time >= 14400 {
                limit()
            } else {
                base
            },
        ))
    }
    fn apply(
        &self,
        height: u128,
        time: u64,
        miner: Hash,
        ops: &[Vec<u8>],
    ) -> Result<(Coins, Book)> {
        require(
            valid_point(miner) && height > 0 && height <= u128::MAX - 100,
            "INVALID fast height/miner",
        )?;
        let mut coins = self.coins.clone();
        let mut book = self.book.clone();
        let mut fees = 0u128;
        let mut touched = std::collections::BTreeSet::new();
        for raw in ops {
            let id = operation_id(raw);
            match codec::decode(raw, self.chain)? {
                Operation::Ordinary(tx) => {
                    require(height <= tx.expiry, "INVALID fast ordinary expiry")?;
                    let total = tx.outputs.iter().try_fold(tx.fee, |s, (_, v)| {
                        s.checked_add(*v).ok_or("INVALID fast transfer sum")
                    })?;
                    debit(&self.coins, &mut coins, &tx.inputs, tx.owner, height, total)?;
                    for (i, (owner, amount)) in tx.outputs.iter().enumerate() {
                        put(&mut coins, tx.id, i as u16, *owner, *amount, height)?;
                    }
                    fees = fees.checked_add(tx.fee).ok_or("INVALID fast fee sum")?;
                }
                Operation::Open(terms) => {
                    require(
                        height <= terms.expiry
                            && !book.contains_key(&id)
                            && book.len() < (MAX_CHANNELS as usize),
                        "INVALID fast opening expiry/capacity",
                    )?;
                    for i in 0..2 {
                        let total = terms.principal[i]
                            .checked_add(terms.limits[i] as u128 * terms.rates[i])
                            .and_then(|n| n.checked_add(terms.fees[i]))
                            .and_then(|n| n.checked_add(terms.change[i]))
                            .ok_or("INVALID fast opening sum")?;
                        debit(
                            &self.coins,
                            &mut coins,
                            &terms.inputs[i],
                            terms.owners[i],
                            height,
                            total,
                        )?;
                        put(
                            &mut coins,
                            id,
                            i as u16,
                            terms.owners[i],
                            terms.change[i],
                            height,
                        )?;
                        fees = fees
                            .checked_add(terms.fees[i])
                            .ok_or("INVALID fast fee sum")?;
                    }
                    book.insert(
                        id,
                        Escrow {
                            opening: raw.clone(),
                            terms,
                            parent: self.tip.id,
                            height,
                            miner,
                            birth: [0; 32],
                            closing: None,
                        },
                    );
                }
                Operation::Action(action) => {
                    require(
                        touched.insert(action.channel),
                        "INVALID fast repeated channel action",
                    )?;
                    require(height <= action.expiry, "INVALID fast action expiry")?;
                    let total = action
                        .fee
                        .checked_add(action.change)
                        .ok_or("INVALID fast action sum")?;
                    debit(
                        &self.coins,
                        &mut coins,
                        &action.inputs,
                        action.actor,
                        height,
                        total,
                    )?;
                    put(&mut coins, id, 0, action.actor, action.change, height)?;
                    fees = fees.checked_add(action.fee).ok_or("INVALID fast fee sum")?;
                    let parent = self
                        .book
                        .get(&action.channel)
                        .ok_or("MISSING fast parent escrow")?;
                    let mut escrow = parent.clone();
                    if action.kind == 2 {
                        require(
                            escrow.closing.is_none() && escrow.terms.owners.contains(&action.actor),
                            "INVALID fast close authority/state",
                        )?;
                        height
                            .checked_add(WINDOW_BLOCKS as u128)
                            .ok_or("INVALID fast close height overflow")?;
                        time.checked_add(WINDOW_SECONDS)
                            .ok_or("INVALID fast close time overflow")?;
                        escrow.closing = Some(Closing {
                            height,
                            time,
                            principal: Vec::new(),
                            slots: [0; 2],
                            proofs: [None, None],
                        });
                    } else {
                        let c = escrow.closing.as_ref().ok_or("MISSING fast close")?;
                        let eligible = window_passed(c.height, c.time, height, time);
                        if action.kind == 5 {
                            require(eligible, "WAITING fast challenge window")?;
                        } else {
                            require(
                                height > c.height && !eligible,
                                "INVALID fast challenge window",
                            )?;
                        }
                    }
                    if action.kind == 5 {
                        let c = escrow.closing.as_ref().unwrap();
                        let balances = if c.principal.is_empty() {
                            escrow.terms.principal
                        } else {
                            escrow
                                .certificate(self.chain, action.channel, &c.principal)?
                                .balances
                        };
                        let accounting = escrow.floors(self.chain, action.channel)?.accounting();
                        for (i, balance) in balances.into_iter().enumerate() {
                            put(
                                &mut coins,
                                id,
                                1 + i as u16,
                                escrow.terms.owners[i],
                                balance,
                                height,
                            )?;
                            put(
                                &mut coins,
                                id,
                                3 + i as u16,
                                escrow.terms.owners[i],
                                accounting.unused[i],
                                height,
                            )?;
                        }
                        let fee = accounting.fee_ranges[0] + accounting.fee_ranges[1];
                        put(&mut coins, id, 5, escrow.miner, fee, height + 100)?;
                        require(
                            book.remove(&action.channel).is_some(),
                            "MISSING fast consumed escrow",
                        )?;
                    } else {
                        self.update(&mut escrow, &action)?;
                        book.insert(action.channel, escrow);
                    }
                }
            }
        }
        let txroot = fh("TRANSACTIONS", &body(ops));
        let reward = fh(
            "REWARD",
            &[
                self.chain.to_vec(),
                self.tip.id.to_vec(),
                height.to_be_bytes().to_vec(),
                miner.to_vec(),
                txroot.to_vec(),
            ]
            .concat(),
        );
        let (subsidy, issued) = emission(height);
        put(
            &mut coins,
            reward,
            0,
            miner,
            subsidy.checked_add(fees).ok_or("INVALID fast reward sum")?,
            height + 100,
        )?;
        let liquid = coins.values().try_fold(0u128, |s, c| {
            s.checked_add(c.amount).ok_or("INVALID fast liquid sum")
        })?;
        let locked = book.values().try_fold(0u128, |s, e| {
            s.checked_add(e.locked()).ok_or("INVALID fast locked sum")
        })?;
        require(
            liquid.checked_add(locked) == Some(issued),
            "INVALID fast whole supply conservation",
        )?;
        require(
            coins.len() <= self.max_coins,
            "RESOURCE_WAIT fast coin budget",
        )?;
        Ok((coins, book))
    }
    fn update(&self, escrow: &mut Escrow, action: &Action) -> Result<()> {
        if action.certificate.is_empty() {
            return Ok(());
        }
        let claim = escrow.certificate(self.chain, action.channel, &action.certificate)?;
        let mut floors = escrow.floors(self.chain, action.channel)?;
        floors.observe(&action.certificate)?;
        let c = escrow.closing.as_mut().unwrap();
        if action.kind == 2 || action.kind == 3 {
            let previous = if c.principal.is_empty() {
                0
            } else {
                u64::from_be_bytes(c.principal[68..76].try_into().unwrap())
            };
            require(
                action.kind == 2 || claim.sequence > previous,
                "INVALID fast principal sequence",
            )?;
            c.principal = action.certificate.clone();
        }
        c.slots = floors.slots();
        c.proofs = floors.proofs().map(|p| p.map(<[u8]>::to_vec));
        Ok(())
    }
    pub fn execute(&mut self, raw: &[u8], now: u64) -> Result<()> {
        require(
            (270..=262144).contains(&raw.len()),
            "INVALID fast block size",
        )?;
        let mut r = Reader::new(raw);
        require(
            r.u16()? == 2 && r.u16()? == 1,
            "UNSUPPORTED fast block version",
        )?;
        require(
            r.fixed::<32>()? == self.chain && r.fixed::<32>()? == self.tip.id,
            "WAITING_FOR_HISTORY fast chain/parent",
        )?;
        let height = r.u128()?;
        require(
            height == self.tip.height + 1 && height <= u128::MAX - 100,
            "INVALID fast block height",
        )?;
        let time = r.u64()?;
        require(
            time <= now.saturating_add(7200),
            "CLOCK_WAIT fast future block",
        )?;
        let base = Big::from32(r.take(32)?);
        let target = Big::from32(r.take(32)?);
        require((base, target) == self.timing(time)?, "INVALID fast target")?;
        let miner = r.fixed()?;
        let transactions = r.fixed::<32>()?;
        let state = r.fixed::<32>()?;
        r.u128()?;
        let id = header_id(raw);
        require(Big::from32(&id) <= target, "INVALID fast proof of work")?;
        let count = r.u16()?;
        require(count <= 128, "INVALID fast operation count")?;
        let mut ops = Vec::new();
        let mut last = None;
        for _ in 0..count {
            let n = r.u32()? as usize;
            require((1..=4096).contains(&n), "INVALID fast operation size")?;
            let op = r.take(n)?.to_vec();
            let id = operation_id(&op);
            require(
                last.is_none_or(|old| old < id),
                "INVALID fast operation ordering",
            )?;
            last = Some(id);
            ops.push(op);
        }
        r.end()?;
        require(
            fh("TRANSACTIONS", &raw[268..]) == transactions,
            "INVALID fast transaction root",
        )?;
        let (coins, mut book) = self.apply(height, time, miner, &ops)?;
        require(
            root(self.chain, emission(height).1, &coins, &book) == state,
            "INVALID fast state root",
        )?;
        for escrow in book.values_mut() {
            if escrow.height == height {
                escrow.birth = id;
            }
        }
        let tip = Tip {
            id,
            height,
            time,
            base,
            work: self.tip.work.add(work(target)),
            root: state,
        };
        self.coins = coins;
        self.book = book;
        self.tip = tip.clone();
        self.recent.push_back(tip);
        if self.recent.len() > 144 {
            self.recent.pop_front();
        }
        Ok(())
    }
    pub fn mining_job(
        &self,
        miner: Hash,
        mut ops: Vec<Vec<u8>>,
        time: u64,
        now: u64,
    ) -> Result<MiningJob> {
        require(
            self.tip.eligible(now) && time <= now.saturating_add(7200),
            "CLOCK_WAIT fast mining",
        )?;
        require(ops.len() <= 128, "INVALID fast operation count")?;
        ops.sort_by_key(|op| operation_id(op));
        let height = self
            .tip
            .height
            .checked_add(1)
            .ok_or("INVALID fast height")?;
        let (base, target) = self.timing(time)?;
        let (coins, book) = self.apply(height, time, miner, &ops)?;
        let body = body(&ops);
        let mut raw = vec![0, 2, 0, 1];
        raw.extend(self.chain);
        raw.extend(self.tip.id);
        raw.extend(height.to_be_bytes());
        raw.extend(time.to_be_bytes());
        raw.extend(base.target());
        raw.extend(target.target());
        raw.extend(miner);
        raw.extend(fh("TRANSACTIONS", &body));
        raw.extend(root(self.chain, emission(height).1, &coins, &book));
        raw.extend(0u128.to_be_bytes());
        raw.extend(body);
        require(raw.len() <= 262144, "RESOURCE_WAIT fast block bytes")?;
        Ok(MiningJob {
            raw,
            target,
            next: Some(0),
        })
    }
}
pub struct MiningJob {
    raw: Vec<u8>,
    target: Big,
    next: Option<u128>,
}
impl MiningJob {
    pub fn search(&mut self, attempts: u64) -> (Option<Vec<u8>>, u64) {
        let mut tried = 0;
        while tried < attempts {
            let Some(n) = self.next else { break };
            self.next = n.checked_add(1);
            self.raw[252..268].copy_from_slice(&n.to_be_bytes());
            tried += 1;
            if Big::from32(&header_id(&self.raw)) <= self.target {
                return (Some(self.raw.clone()), tried);
            }
        }
        (None, tried)
    }
}

#[cfg(test)]
mod window_tests {
    use super::*;
    #[test]
    fn rapid_blocks_and_elapsed_time_each_cannot_alone_exhaust_challenge_rights() {
        let (h, t) = (10u128, 100u64);
        assert!(!window_passed(h, t, h + 2016, t + 172801));
        assert!(!window_passed(h, t, h + 2017, t + 172800));
        assert!(!window_passed(h, t, h + 500000, t + 1));
        assert!(!window_passed(h, t, h + 1, t + 500000));
        assert!(window_passed(h, t, h + 2017, t + 172801));
    }
}
