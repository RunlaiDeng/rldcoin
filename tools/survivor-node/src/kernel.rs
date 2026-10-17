//! Survivor-1 native execution. Arithmetic/crypto codecs adapted from the public
//! vector oracle; this is not an independently authored validation implementation.
use curve25519_dalek::{edwards::CompressedEdwardsY, traits::IsIdentity};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
pub type Hash = [u8; 32];
pub const CAP: u128 = 10u128.pow(35);
pub type Result<T> = std::result::Result<T, String>;
fn require(ok: bool, why: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(why.into())
    }
}
pub(crate) fn tag(s: &str) -> Vec<u8> {
    [b"RLD-SURVIVOR-1/".as_slice(), s.as_bytes(), &[0]].concat()
}
pub(crate) fn hash(s: &str, x: &[u8]) -> Hash {
    digest_parts(domain(s), &[x])
}
fn domain(s: &str) -> Sha256 {
    let mut h = Sha256::new();
    h.update(b"RLD-SURVIVOR-1/");
    h.update(s.as_bytes());
    h.update([0]);
    h
}
fn digest_parts(mut h: Sha256, parts: &[&[u8]]) -> Hash {
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}
fn double(s: &str, x: &[u8]) -> Hash {
    Sha256::digest(hash(s, x)).into()
}

// Fixed-width mathematical arithmetic for the public work/target examples.
// No floating-point target or library-dependent compact integer encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Big([u8; 48]);
impl Big {
    fn zero() -> Self {
        Self([0; 48])
    }
    fn small(n: u128) -> Self {
        let mut a = [0; 48];
        a[32..].copy_from_slice(&n.to_be_bytes());
        Self(a)
    }
    fn power(n: usize) -> Self {
        let mut a = [0; 48];
        a[47 - n / 8] = 1 << (n % 8);
        Self(a)
    }
    fn from32(x: &[u8]) -> Self {
        assert_eq!(x.len(), 32);
        let mut a = [0; 48];
        a[16..].copy_from_slice(x);
        Self(a)
    }
    fn add(self, b: Self) -> Self {
        let mut a = [0; 48];
        let mut c = 0u16;
        for i in (0..48).rev() {
            c += self.0[i] as u16 + b.0[i] as u16;
            a[i] = c as u8;
            c >>= 8;
        }
        assert_eq!(c, 0);
        Self(a)
    }
    fn sub(self, b: Self) -> Self {
        assert!(self >= b);
        let mut a = [0; 48];
        let mut borrow = 0i16;
        for i in (0..48).rev() {
            let v = self.0[i] as i16 - b.0[i] as i16 - borrow;
            a[i] = v as u8;
            borrow = if v < 0 { 1 } else { 0 };
        }
        Self(a)
    }
    fn mul(self, n: u32) -> Self {
        let mut a = [0; 48];
        let mut c = 0u64;
        for i in (0..48).rev() {
            c += self.0[i] as u64 * n as u64;
            a[i] = c as u8;
            c >>= 8;
        }
        assert_eq!(c, 0);
        Self(a)
    }
    fn div_small(self, n: u32) -> Self {
        assert_ne!(n, 0);
        let mut a = [0; 48];
        let mut r = 0u64;
        for (i, v) in a.iter_mut().enumerate() {
            r = (r << 8) + self.0[i] as u64;
            *v = (r / n as u64) as u8;
            r %= n as u64;
        }
        Self(a)
    }
    fn div(self, b: Self) -> Self {
        assert_ne!(b, Self::zero());
        let mut q = Self::zero();
        let mut r = Self::zero();
        for bit in (0..384).rev() {
            r = r.mul(2);
            if self.0[47 - bit / 8] & (1 << (bit % 8)) != 0 {
                r = r.add(Self::small(1));
            }
            if r >= b {
                r = r.sub(b);
                q.0[47 - bit / 8] |= 1 << (bit % 8);
            }
        }
        q
    }
    fn target(self) -> Vec<u8> {
        assert_eq!(&self.0[..16], &[0; 16]);
        self.0[16..].to_vec()
    }
}
fn limit() -> Big {
    Big::power(248).sub(Big::small(1))
}
fn work(t: Big) -> Big {
    Big::power(256).div(t.add(Big::small(1)))
}
fn scaled(t: Big, elapsed: u64) -> Big {
    t.mul(elapsed.clamp(21450, 343200) as u32)
        .div_small(85800)
        .max(Big::small(1))
        .min(limit())
}
fn emission(h: u128) -> (u128, u128) {
    if h == 0 {
        return (0, 0);
    }
    let era = (h - 1) / 200000;
    let slot = (h - 1) % 200000;
    let mut reserve = CAP;
    let mut e = 0;
    while e < era && reserve > 0 {
        reserve -= if reserve == 1 { 1 } else { reserve / 2 };
        e += 1;
    }
    let budget = if reserve < 2 { reserve } else { reserve / 2 };
    let q = budget / 200000;
    let r = budget % 200000;
    (
        q + u128::from(slot < r),
        CAP - reserve + (slot + 1) * q + (slot + 1).min(r),
    )
}
pub(crate) fn valid_point(x: Hash) -> bool {
    CompressedEdwardsY(x)
        .decompress()
        .is_some_and(|p| p.compress().to_bytes() == x && p.is_torsion_free() && !p.is_identity())
}
pub(crate) fn verify(key: Hash, msg: &[u8], sig: &[u8]) -> Result<()> {
    require(sig.len() == 64, "signature length")?;
    require(
        valid_point(key) && valid_point(sig[..32].try_into().unwrap()),
        "signature point",
    )?;
    VerifyingKey::from_bytes(&key)
        .map_err(|_| "public key")?
        .verify_strict(msg, &Signature::from_slice(sig).map_err(|_| "signature")?)
        .map_err(|_| "signature".into())
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coin {
    pub owner: Hash,
    pub amount: u128,
    pub maturity: u128,
}
type Coins = BTreeMap<Vec<u8>, Coin>;
pub(crate) fn outpoint(id: Hash, i: u16) -> Vec<u8> {
    [id.to_vec(), i.to_be_bytes().to_vec()].concat()
}
fn tree(coins: &Coins) -> Hash {
    let leaf_domain = domain("UTXO-LEAF");
    let node_domain = domain("UTXO-NODE");
    let mut frontier: [Option<Hash>; usize::BITS as usize] = [None; usize::BITS as usize];
    for (count, (key, coin)) in coins.iter().enumerate() {
        // Keys can only enter this private map through canonical outpoint().
        let mut record = [0; 98];
        record[..34].copy_from_slice(key);
        record[34..66].copy_from_slice(&coin.owner);
        record[66..82].copy_from_slice(&coin.amount.to_be_bytes());
        record[82..].copy_from_slice(&coin.maturity.to_be_bytes());
        let mut carry = digest_parts(leaf_domain.clone(), &[&record]);
        let mut occupied = count;
        let mut level = 0;
        while occupied & 1 != 0 {
            let left = frontier[level].take().expect("complete left subtree");
            carry = digest_parts(node_domain.clone(), &[&left, &carry]);
            occupied >>= 1;
            level += 1;
        }
        frontier[level] = Some(carry);
    }
    // Smaller right subtrees are folded first. This is exactly the C09 largest
    // power-of-two split, including non-power-of-two counts; no padded leaves,
    // persistent witness or cached ledger is introduced.
    let mut root: Option<Hash> = None;
    for left in frontier.into_iter().flatten() {
        root = Some(match root {
            Some(right) => digest_parts(node_domain.clone(), &[&left, &right]),
            None => left,
        });
    }
    root.unwrap_or_else(|| hash("UTXO-EMPTY", &[]))
}
fn state(chain: Hash, issued: u128, coins: &Coins) -> Hash {
    digest_parts(
        domain("STATE"),
        &[
            &chain,
            &issued.to_be_bytes(),
            &(coins.len() as u128).to_be_bytes(),
            &tree(coins),
        ],
    )
}
struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, at: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(n).ok_or("length overflow")?;
        require(end <= self.data.len(), "truncated")?;
        let x = &self.data[self.at..end];
        self.at = end;
        Ok(x)
    }
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }
    fn u128(&mut self) -> Result<u128> {
        Ok(u128::from_be_bytes(self.fixed()?))
    }
    fn end(&self) -> Result<()> {
        require(self.at == self.data.len(), "trailing bytes")
    }
}
#[derive(Clone)]
pub(crate) struct Tx {
    pub(crate) id: Hash,
    pub(crate) owner: Hash,
    pub(crate) inputs: Vec<Vec<u8>>,
    pub(crate) outputs: Vec<(Hash, u128)>,
    pub(crate) fee: u128,
    pub(crate) expiry: u128,
}
pub(crate) fn decode_unsigned(raw: &[u8], chain: Hash) -> Result<Tx> {
    require((184..=1574).contains(&raw.len()), "transaction size")?;
    let mut r = Reader::new(raw);
    require(r.u16()? == 1, "version")?;
    require(r.fixed::<32>()? == chain, "chain")?;
    let owner = r.fixed()?;
    require(valid_point(owner), "owner")?;
    let n = r.u16()?;
    require((1..=32).contains(&n), "inputs")?;
    let mut inputs = Vec::new();
    for _ in 0..n {
        inputs.push(r.take(34)?.to_vec())
    }
    require(inputs.windows(2).all(|w| w[0] < w[1]), "input ordering")?;
    let n = r.u16()?;
    require((1..=8).contains(&n), "outputs")?;
    let mut outputs = Vec::new();
    for _ in 0..n {
        let k = r.fixed()?;
        let v = r.u128()?;
        require(valid_point(k) && v > 0 && v <= CAP, "output")?;
        outputs.push((k, v));
    }
    let fee = r.u128()?;
    let expiry = r.u128()?;
    require(fee > 0 && fee <= CAP, "fee")?;
    let u = &raw[..r.at];
    r.end()?;
    Ok(Tx {
        id: hash("TXID", u),
        owner,
        inputs,
        outputs,
        fee,
        expiry,
    })
}
pub(crate) fn decode_tx(raw: &[u8], chain: Hash) -> Result<Tx> {
    require(
        (248..=1638).contains(&raw.len()),
        "INVALID transaction size",
    )?;
    let u = &raw[..raw.len() - 64];
    let tx = decode_unsigned(u, chain)?;
    verify(
        tx.owner,
        &[tag("TRANSFER"), u.to_vec()].concat(),
        &raw[raw.len() - 64..],
    )?;
    Ok(tx)
}

fn body(txs: &[Vec<u8>]) -> Vec<u8> {
    let mut b = (txs.len() as u16).to_be_bytes().to_vec();
    for x in txs {
        b.extend((x.len() as u32).to_be_bytes());
        b.extend(x)
    }
    b
}
fn apply(
    chain: Hash,
    parent: Hash,
    h: u128,
    miner: Hash,
    txs: &[Vec<u8>],
    coins: &Coins,
) -> Result<Coins> {
    require(
        valid_point(miner) && h > 0 && h <= u128::MAX - 100,
        "height/miner",
    )?;
    let mut next = coins.clone();
    let mut fees = 0u128;
    let mut last = None;
    for raw in txs {
        let t = decode_tx(raw, chain)?;
        require(last.is_none_or(|id| id < t.id), "transaction ordering")?;
        last = Some(t.id);
        require(h <= t.expiry, "expiry")?;
        let mut total = 0u128;
        for input in &t.inputs {
            let c = coins.get(input).ok_or("missing parent input")?;
            require(c.owner == t.owner && c.maturity <= h, "ownership/maturity")?;
            require(next.remove(input).is_some(), "double spend")?;
            total = total.checked_add(c.amount).ok_or("sum overflow")?;
        }
        let mut output = t.fee;
        for (_, v) in &t.outputs {
            output = output.checked_add(*v).ok_or("sum overflow")?;
        }
        require(total == output && output <= CAP, "conservation")?;
        fees = fees.checked_add(t.fee).ok_or("fee overflow")?;
        for (i, (owner, amount)) in t.outputs.iter().enumerate() {
            require(
                next.insert(
                    outpoint(t.id, i as u16),
                    Coin {
                        owner: *owner,
                        amount: *amount,
                        maturity: h,
                    },
                )
                .is_none(),
                "collision",
            )?;
        }
    }
    let root = hash("TRANSACTIONS", &body(txs));
    let reward = hash(
        "REWARD",
        &[
            chain.to_vec(),
            parent.to_vec(),
            h.to_be_bytes().to_vec(),
            miner.to_vec(),
            root.to_vec(),
        ]
        .concat(),
    );
    let (subsidy, issued) = emission(h);
    let amount = subsidy.checked_add(fees).ok_or("reward overflow")?;
    if amount > 0 {
        require(
            next.insert(
                outpoint(reward, 0),
                Coin {
                    owner: miner,
                    amount,
                    maturity: h + 100,
                },
            )
            .is_none(),
            "reward collision",
        )?;
    }
    let sum = next.values().try_fold(0u128, |sum, c| {
        sum.checked_add(c.amount).ok_or("sum overflow")
    })?;
    require(sum == issued, "issued sum")?;
    Ok(next)
}

/// An intrinsically validated, genesis-rooted branch tip. Fields are read-only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tip {
    id: Hash,
    height: u128,
    time: u64,
    base: Big,
    work: Big,
    root: Hash,
}
impl Tip {
    pub fn id(&self) -> Hash {
        self.id
    }
    pub fn height(&self) -> u128 {
        self.height
    }
    pub fn timestamp(&self) -> u64 {
        self.time
    }
    pub fn root(&self) -> Hash {
        self.root
    }
    pub fn work_bytes(&self) -> [u8; 48] {
        self.work.0
    }
    pub fn eligible(&self, now: u64) -> bool {
        self.time <= now.saturating_add(7200)
    }
    pub fn preferred_to(&self, other: &Self) -> bool {
        self.work > other.work || (self.work == other.work && self.id < other.id)
    }
}

/// Constructed exclusively by exact genesis decoding and full native execution.
/// Retains one UTXO state and 144 timing observations, never a state per block.
#[derive(Clone)]
pub struct Ledger {
    chain: Hash,
    tip: Tip,
    recent: VecDeque<Tip>,
    coins: Coins,
    max_coins: usize,
}
impl Ledger {
    pub fn from_genesis(raw: &[u8], expected_chain: Hash, max_coins: usize) -> Result<Self> {
        require(raw.len() == 85, "INVALID genesis length")?;
        let mut r = Reader::new(raw);
        require(r.take(8)? == b"RLDSGEN1", "INVALID genesis magic")?;
        require(r.u16()? == 1 && r.u16()? == 1, "UNSUPPORTED version/suite")?;
        // This executable intentionally refuses monetary network activation.
        require(r.take(1)? == [0], "UNSUPPORTED monetary activation")?;
        require(r.fixed::<32>()? != [0; 32], "INVALID zero discriminator")?;
        let time = r.u64()?;
        require(time <= u64::MAX - 14400, "INVALID genesis time")?;
        require(
            Big::from32(r.take(32)?) == limit(),
            "INVALID initial target",
        )?;
        r.end()?;
        let chain = hash("GENESIS", raw);
        require(chain == expected_chain, "INVALID pinned genesis")?;
        require(max_coins > 0, "RESOURCE_WAIT coin budget")?;
        let coins = Coins::new();
        let tip = Tip {
            id: chain,
            height: 0,
            time,
            base: limit(),
            work: Big::zero(),
            root: state(chain, 0, &coins),
        };
        Ok(Self {
            chain,
            recent: VecDeque::from([tip.clone()]),
            tip,
            coins,
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
    fn next_base(&self) -> Big {
        if self.tip.height == 0 {
            limit()
        } else if !self.tip.height.is_multiple_of(144) {
            self.tip.base
        } else {
            scaled(self.tip.base, self.tip.time - self.recent[0].time)
        }
    }
    fn timing(&self, time: u64) -> Result<(Big, Big)> {
        let mut times: Vec<_> = self.recent.iter().rev().take(11).map(|b| b.time).collect();
        times.sort_unstable();
        require(
            time > self.tip.time && time > times[times.len() / 2],
            "INVALID timestamp",
        )?;
        let base = self.next_base();
        Ok((
            base,
            if time - self.tip.time >= 14400 {
                limit()
            } else {
                base
            },
        ))
    }
    /// Full intrinsic validation; local clock selection is deliberately separate.
    /// An error leaves this ledger byte-for-byte logically unchanged.
    pub fn execute(&mut self, raw: &[u8]) -> Result<()> {
        require((270..=262144).contains(&raw.len()), "INVALID block size")?;
        let mut r = Reader::new(raw);
        require(r.u16()? == 1 && r.u16()? == 1, "UNSUPPORTED version/suite")?;
        require(r.fixed::<32>()? == self.chain, "INVALID chain")?;
        require(
            r.fixed::<32>()? == self.tip.id,
            "WAITING_FOR_HISTORY parent",
        )?;
        let height = r.u128()?;
        require(
            height > 0 && height <= u128::MAX - 100 && height == self.tip.height + 1,
            "INVALID height",
        )?;
        let time = r.u64()?;
        let b = Big::from32(r.take(32)?);
        let target = Big::from32(r.take(32)?);
        require((b, target) == self.timing(time)?, "INVALID target")?;
        let miner = r.fixed()?;
        let txroot = r.fixed::<32>()?;
        let root = r.fixed::<32>()?;
        r.u128()?;
        let id = double("HEADER", &raw[..268]);
        require(Big::from32(&id) <= target, "INVALID proof of work")?;
        let n = r.u16()?;
        require(n <= 128, "INVALID transaction count")?;
        let mut txs = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let length = r.u32()? as usize;
            require((248..=1638).contains(&length), "INVALID transaction length")?;
            txs.push(r.take(length)?.to_vec());
        }
        r.end()?;
        require(
            hash("TRANSACTIONS", &raw[268..]) == txroot,
            "INVALID transaction root",
        )?;
        let coins = apply(self.chain, self.tip.id, height, miner, &txs, &self.coins)?;
        require(coins.len() <= self.max_coins, "RESOURCE_WAIT coin budget")?;
        require(
            state(self.chain, emission(height).1, &coins) == root,
            "INVALID state root",
        )?;
        let tip = Tip {
            id,
            height,
            time,
            base: b,
            work: self.tip.work.add(work(target)),
            root,
        };
        // All fallible validation precedes this in-memory commit. The durable layer
        // must commit exact raw bytes and selected tip before acknowledging it.
        self.coins = coins;
        self.tip = tip.clone();
        self.recent.push_back(tip);
        if self.recent.len() > 144 {
            self.recent.pop_front();
        }
        Ok(())
    }
    /// Builds a finite mining job. Actual nonce attempts and cancellation belong to
    /// the caller; this never advances the ledger or claims mining income.
    pub fn mining_job(
        &self,
        miner: Hash,
        mut txs: Vec<Vec<u8>>,
        time: u64,
        now: u64,
    ) -> Result<MiningJob> {
        require(
            self.tip.eligible(now) && time <= now.saturating_add(7200),
            "CLOCK_WAIT",
        )?;
        require(txs.len() <= 128, "INVALID transaction count")?;
        let (base, target) = self.timing(time)?;
        let height = self.tip.height.checked_add(1).ok_or("INVALID height")?;
        let mut ordered = Vec::with_capacity(txs.len());
        for raw in txs.drain(..) {
            ordered.push((decode_tx(&raw, self.chain)?.id, raw));
        }
        ordered.sort_by_key(|(id, _)| *id);
        txs = ordered.into_iter().map(|(_, raw)| raw).collect();
        let coins = apply(self.chain, self.tip.id, height, miner, &txs, &self.coins)?;
        require(coins.len() <= self.max_coins, "RESOURCE_WAIT coin budget")?;
        let payload = body(&txs);
        require(268 + payload.len() <= 262144, "INVALID block size")?;
        let mut raw = Vec::with_capacity(268 + payload.len());
        raw.extend(1u16.to_be_bytes());
        raw.extend(1u16.to_be_bytes());
        raw.extend(self.chain);
        raw.extend(self.tip.id);
        raw.extend(height.to_be_bytes());
        raw.extend(time.to_be_bytes());
        raw.extend(base.target());
        raw.extend(target.target());
        raw.extend(miner);
        raw.extend(hash("TRANSACTIONS", &payload));
        raw.extend(state(self.chain, emission(height).1, &coins));
        raw.extend(0u128.to_be_bytes());
        raw.extend(payload);
        Ok(MiningJob {
            raw,
            target,
            next: Some(0),
        })
    }
    pub fn validate_transfer(&self, raw: &[u8]) -> Result<Hash> {
        let tx = decode_tx(raw, self.chain)?;
        self.check_inputs(&tx)
    }
    /// Non-authorizing review only; block execution always verifies a signature.
    pub(crate) fn validate_unsigned(&self, raw: &[u8]) -> Result<Hash> {
        self.check_inputs(&decode_unsigned(raw, self.chain)?)
    }
    fn check_inputs(&self, tx: &Tx) -> Result<Hash> {
        let h = self.tip.height.checked_add(1).ok_or("INVALID height")?;
        require(h <= tx.expiry, "INVALID expiry")?;
        let mut sum = 0u128;
        for i in &tx.inputs {
            let c = self.coins.get(i).ok_or("WAITING_FOR_INPUT")?;
            require(c.owner == tx.owner, "INVALID owner")?;
            require(c.maturity <= h, "WAITING_FOR_MATURITY")?;
            sum = sum.checked_add(c.amount).ok_or("INVALID sum")?;
        }
        let output = tx
            .outputs
            .iter()
            .try_fold(tx.fee, |n, (_, v)| n.checked_add(*v).ok_or("INVALID sum"))?;
        require(sum == output && output <= CAP, "INVALID conservation")?;
        Ok(tx.id)
    }
}

pub struct MiningJob {
    raw: Vec<u8>,
    target: Big,
    next: Option<u128>,
}
impl MiningJob {
    /// At most `attempts` distinct trials. None means budget/nonce exhaustion;
    /// resume the same job to avoid repeating already attempted nonces.
    pub fn attempt(&mut self, attempts: u64) -> Option<Vec<u8>> {
        for _ in 0..attempts {
            let n = self.next?;
            self.next = n.checked_add(1);
            self.raw[252..268].copy_from_slice(&n.to_be_bytes());
            if Big::from32(&double("HEADER", &self.raw[..268])) <= self.target {
                return Some(self.raw.clone());
            }
        }
        None
    }
}
pub fn genesis_id(raw: &[u8]) -> Hash {
    hash("GENESIS", raw)
}
pub fn block_id(raw: &[u8]) -> Result<Hash> {
    require((270..=262144).contains(&raw.len()), "INVALID block size")?;
    Ok(double("HEADER", &raw[..268]))
}
pub fn issuance(height: u128) -> (u128, u128) {
    emission(height)
}

#[cfg(test)]
mod commitment_tests {
    use super::*;

    // Retained allocating/recursive reference. It deliberately uses the old
    // concatenating digest expression, independently of the streaming helper.
    fn reference_hash(tag: &str, bytes: &[u8]) -> Hash {
        Sha256::digest([super::tag(tag), bytes.to_vec()].concat()).into()
    }
    fn reference_tree(records: &[Vec<u8>]) -> Hash {
        match records.len() {
            0 => reference_hash("UTXO-EMPTY", &[]),
            1 => reference_hash("UTXO-LEAF", &records[0]),
            n => {
                let mut k = 1;
                while k * 2 < n {
                    k *= 2;
                }
                reference_hash(
                    "UTXO-NODE",
                    &[reference_tree(&records[..k]), reference_tree(&records[k..])].concat(),
                )
            }
        }
    }
    fn reference_state(chain: Hash, issued: u128, coins: &Coins) -> Hash {
        let records: Vec<Vec<u8>> = coins
            .iter()
            .map(|(key, c)| {
                [
                    key.clone(),
                    c.owner.to_vec(),
                    c.amount.to_be_bytes().to_vec(),
                    c.maturity.to_be_bytes().to_vec(),
                ]
                .concat()
            })
            .collect();
        reference_hash(
            "STATE",
            &[
                chain.to_vec(),
                issued.to_be_bytes().to_vec(),
                (coins.len() as u128).to_be_bytes().to_vec(),
                reference_tree(&records).to_vec(),
            ]
            .concat(),
        )
    }
    fn check(coins: &Coins) {
        let issued = coins.values().map(|c| c.amount).sum();
        assert_eq!(
            state([7; 32], issued, coins),
            reference_state([7; 32], issued, coins)
        );
    }
    #[test]
    fn streamed_commitments_preserve_binary_boundaries_and_ordered_map_edits() {
        // Explicit public NO-VALUE owner derivation, never asset custody.
        let owner = ed25519_dalek::SigningKey::from_bytes(&[11; 32])
            .verifying_key()
            .to_bytes();
        let mut coins = Coins::new();
        check(&coins);
        let counts = [
            1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256,
            257, 511, 512, 513, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097, 8191, 8192,
            8193,
        ];
        for i in 0u64..8193 {
            let id = reference_hash("TEST-OUTPOINT", &i.to_be_bytes());
            coins.insert(
                outpoint(id, (i % 8) as u16),
                Coin {
                    owner,
                    amount: i as u128 + 1,
                    maturity: i as u128,
                },
            );
            if counts.contains(&coins.len()) {
                check(&coins);
            }
        }
        // Randomized key order, nonappend insertion, deletion, amount and maturity
        // edits all change ranks; a retained frontier must never be reused.
        let removed: Vec<_> = coins.keys().step_by(3).cloned().collect();
        for key in &removed {
            coins.remove(key);
        }
        check(&coins);
        for key in removed {
            coins.insert(
                key,
                Coin {
                    owner,
                    amount: 17,
                    maturity: 100_000,
                },
            );
        }
        check(&coins);
        let coin = coins.values_mut().nth(1024).unwrap();
        coin.amount += 1;
        coin.maturity += 7;
        check(&coins);
        assert_ne!(state([7; 32], 1, &coins), state([8; 32], 1, &coins));
        assert_ne!(state([7; 32], 1, &coins), state([7; 32], 2, &coins));
    }
    #[test]
    fn multipart_hashing_preserves_exact_domain_and_message_bytes() {
        for len in [0, 1, 63, 64, 65, 127, 128, 129, 268, 4096] {
            let bytes: Vec<_> = (0..len).map(|n| n as u8).collect();
            for tag in [
                "HEADER",
                "STATE",
                "UTXO-LEAF",
                "UTXO-NODE",
                "TRANSACTIONS",
                "PACKET",
                "GENESIS",
            ] {
                assert_eq!(hash(tag, &bytes), reference_hash(tag, &bytes));
                for split in [0, len / 2, len] {
                    assert_eq!(
                        digest_parts(domain(tag), &[&bytes[..split], &bytes[split..]]),
                        reference_hash(tag, &bytes)
                    );
                }
            }
        }
    }
}
