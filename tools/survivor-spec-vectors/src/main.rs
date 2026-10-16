//! Public NO-VALUE specification oracle. Never use the RFC8032 fixture keys for assets.
use curve25519_dalek::{edwards::CompressedEdwardsY, traits::IsIdentity};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs::OpenOptions, io::Write};

type Hash = [u8; 32];
const CAP: u128 = 10u128.pow(35);
const START: u64 = 1_800_000_000;
type Result<T> = std::result::Result<T, String>;

fn require(ok: bool, why: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(why.into())
    }
}
fn tag(s: &str) -> Vec<u8> {
    [b"RLD-SURVIVOR-1/".as_slice(), s.as_bytes(), &[0]].concat()
}
fn hash(s: &str, x: &[u8]) -> Hash {
    Sha256::digest([tag(s), x.to_vec()].concat()).into()
}
fn double(s: &str, x: &[u8]) -> Hash {
    Sha256::digest(hash(s, x)).into()
}
fn bytes<const N: usize>(s: &str) -> [u8; N] {
    hex::decode(s).unwrap().try_into().unwrap()
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
    fn hex(self) -> String {
        hex::encode(self.target())
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
fn valid_point(x: Hash) -> bool {
    CompressedEdwardsY(x)
        .decompress()
        .is_some_and(|p| p.compress().to_bytes() == x && p.is_torsion_free() && !p.is_identity())
}
fn verify(key: Hash, msg: &[u8], sig: &[u8]) -> Result<()> {
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
fn keys() -> [SigningKey; 3] {
    // RFC8032 section 7.1 tests 1, 2 and 3: deliberately public NO-VALUE inputs.
    [
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
    ]
    .map(|s| SigningKey::from_bytes(&bytes::<32>(s)))
}
#[derive(Clone, Debug)]
struct Coin {
    owner: Hash,
    amount: u128,
    maturity: u128,
}
type Coins = BTreeMap<Vec<u8>, Coin>;
fn outpoint(id: Hash, i: u16) -> Vec<u8> {
    [id.to_vec(), i.to_be_bytes().to_vec()].concat()
}
fn tree(records: &[Vec<u8>]) -> Hash {
    match records.len() {
        0 => hash("UTXO-EMPTY", &[]),
        1 => hash("UTXO-LEAF", &records[0]),
        n => {
            let mut k = 1;
            while k * 2 < n {
                k *= 2
            }
            hash(
                "UTXO-NODE",
                &[
                    tree(&records[..k]).as_slice(),
                    tree(&records[k..]).as_slice(),
                ]
                .concat(),
            )
        }
    }
}
fn state(chain: Hash, issued: u128, coins: &Coins) -> Hash {
    let records: Vec<Vec<u8>> = coins
        .iter()
        .map(|(k, c)| {
            [
                k.clone(),
                c.owner.to_vec(),
                c.amount.to_be_bytes().to_vec(),
                c.maturity.to_be_bytes().to_vec(),
            ]
            .concat()
        })
        .collect();
    hash(
        "STATE",
        &[
            chain.to_vec(),
            issued.to_be_bytes().to_vec(),
            (coins.len() as u128).to_be_bytes().to_vec(),
            tree(&records).to_vec(),
        ]
        .concat(),
    )
}
fn genesis() -> (Vec<u8>, Hash) {
    let raw = [
        b"RLDSGEN1".to_vec(),
        1u16.to_be_bytes().to_vec(),
        1u16.to_be_bytes().to_vec(),
        vec![0],
        vec![1; 32],
        START.to_be_bytes().to_vec(),
        limit().target(),
    ]
    .concat();
    assert_eq!(raw.len(), 85);
    let id = hash("GENESIS", &raw);
    (raw, id)
}
fn transfer(
    chain: Hash,
    key: &SigningKey,
    inputs: &[Vec<u8>],
    outputs: &[(Hash, u128)],
    fee: u128,
    expiry: u128,
) -> Vec<u8> {
    let mut u = [
        1u16.to_be_bytes().to_vec(),
        chain.to_vec(),
        key.verifying_key().to_bytes().to_vec(),
        (inputs.len() as u16).to_be_bytes().to_vec(),
    ]
    .concat();
    for i in inputs {
        u.extend(i)
    }
    u.extend((outputs.len() as u16).to_be_bytes());
    for (owner, amount) in outputs {
        u.extend(owner);
        u.extend(amount.to_be_bytes());
    }
    u.extend(fee.to_be_bytes());
    u.extend(expiry.to_be_bytes());
    let message = [tag("TRANSFER"), u.clone()].concat();
    u.extend(key.sign(&message).to_bytes());
    u
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
struct Tx {
    id: Hash,
    owner: Hash,
    inputs: Vec<Vec<u8>>,
    outputs: Vec<(Hash, u128)>,
    fee: u128,
    expiry: u128,
}
fn decode_tx(raw: &[u8], chain: Hash) -> Result<Tx> {
    require((248..=1638).contains(&raw.len()), "transaction size")?;
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
    let sig = r.take(64)?;
    r.end()?;
    verify(owner, &[tag("TRANSFER"), u.to_vec()].concat(), sig)?;
    Ok(Tx {
        id: hash("TXID", u),
        owner,
        inputs,
        outputs,
        fee,
        expiry,
    })
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
#[derive(Clone)]
struct Block {
    id: Hash,
    height: u128,
    time: u64,
    base: Big,
    target: Big,
    work: Big,
    coins: Coins,
    raw: Vec<u8>,
}
fn base(history: &[Block]) -> Big {
    let p = history.last().unwrap();
    if p.height == 0 {
        limit()
    } else if !p.height.is_multiple_of(144) {
        p.base
    } else {
        scaled(p.base, p.time - history[history.len() - 144].time)
    }
}
fn mine(chain: Hash, history: &[Block], miner: Hash, mut txs: Vec<Vec<u8>>, time: u64) -> Block {
    txs.sort_by_key(|x| decode_tx(x, chain).unwrap().id);
    let p = history.last().unwrap();
    let height = p.height + 1;
    let b = base(history);
    let target = if time - p.time >= 14400 { limit() } else { b };
    let coins = apply(chain, p.id, height, miner, &txs, &p.coins).unwrap();
    let txbody = body(&txs);
    let txroot = hash("TRANSACTIONS", &txbody);
    let root = state(chain, emission(height).1, &coins);
    let prefix = [
        1u16.to_be_bytes().to_vec(),
        1u16.to_be_bytes().to_vec(),
        chain.to_vec(),
        p.id.to_vec(),
        height.to_be_bytes().to_vec(),
        time.to_be_bytes().to_vec(),
        b.target(),
        target.target(),
        miner.to_vec(),
        txroot.to_vec(),
        root.to_vec(),
    ]
    .concat();
    assert_eq!(prefix.len(), 252);
    let mut nonce = 0u128;
    loop {
        let header = [prefix.clone(), nonce.to_be_bytes().to_vec()].concat();
        let id = double("HEADER", &header);
        if Big::from32(&id) <= target {
            return Block {
                id,
                height,
                time,
                base: b,
                target,
                work: p.work.add(work(target)),
                coins,
                raw: [header, txbody].concat(),
            };
        }
        nonce += 1;
    }
}
fn replay(chain: Hash, history: &[Block], raw: &[u8], now: u64) -> Result<Block> {
    require((270..=262144).contains(&raw.len()), "block size")?;
    let p = history.last().ok_or("parent")?;
    let mut r = Reader::new(raw);
    require(r.u16()? == 1 && r.u16()? == 1, "version/suite")?;
    require(
        r.fixed::<32>()? == chain && r.fixed::<32>()? == p.id,
        "chain/parent",
    )?;
    let height = r.u128()?;
    let time = r.u64()?;
    let b = Big::from32(r.take(32)?);
    let target = Big::from32(r.take(32)?);
    let miner = r.fixed()?;
    let txroot = r.fixed::<32>()?;
    let root = r.fixed::<32>()?;
    r.u128()?;
    require(
        height == p.height + 1 && height <= u128::MAX - 100,
        "height",
    )?;
    let mut times: Vec<_> = history.iter().rev().take(11).map(|b| b.time).collect();
    times.sort();
    require(time > p.time && time > times[times.len() / 2], "time")?;
    require(b == base(history), "base target")?;
    require(
        target == if time - p.time >= 14400 { limit() } else { b },
        "target",
    )?;
    let id = double("HEADER", &raw[..268]);
    require(Big::from32(&id) <= target, "proof of work")?;
    require(time <= now.saturating_add(7200), "CLOCK_WAIT")?;
    let n = r.u16()?;
    require(n <= 128, "transaction count")?;
    let mut txs = Vec::new();
    for _ in 0..n {
        let length = r.u32()? as usize;
        txs.push(r.take(length)?.to_vec())
    }
    r.end()?;
    require(
        hash("TRANSACTIONS", &body(&txs)) == txroot,
        "transaction root",
    )?;
    let coins = apply(chain, p.id, height, miner, &txs, &p.coins)?;
    require(
        state(chain, emission(height).1, &coins) == root,
        "state root",
    )?;
    Ok(Block {
        id,
        height,
        time,
        base: b,
        target,
        work: p.work.add(work(target)),
        coins,
        raw: raw.to_vec(),
    })
}
fn winner(a: &Block, b: &Block) -> Hash {
    if a.work > b.work || (a.work == b.work && a.id < b.id) {
        a.id
    } else {
        b.id
    }
}
fn view(b: &Block) -> Value {
    json!({"height":b.height.to_string(),"block_id":hex::encode(b.id),"block_hex":hex::encode(&b.raw),"state_root":hex::encode(&b.raw[220..252]),"base_target_hex":b.base.hex(),"target_hex":b.target.hex(),"cumulative_work_hex":hex::encode(b.work.0),"issued":emission(b.height).1.to_string()})
}

fn signed(label: &str, fields: Vec<u8>, key: &SigningKey) -> Vec<u8> {
    let sig = key.sign(&[tag(label), fields.clone()].concat());
    [fields, sig.to_bytes().to_vec()].concat()
}
fn frame(kind: u8, fields: Vec<u8>) -> Vec<u8> {
    let b = [vec![kind], fields].concat();
    [
        b"RLDSFRM1".to_vec(),
        (b.len() as u32).to_be_bytes().to_vec(),
        b,
    ]
    .concat()
}
fn contact_vectors(chain: Hash, transaction: &[u8]) -> Value {
    // Public deterministic contact fixtures, separate from the published wallet keys.
    let wallet = keys();
    let a = SigningKey::from_bytes(&hash(
        "PUBLIC-CONTACT-A",
        &wallet[0].verifying_key().to_bytes(),
    ));
    let b = SigningKey::from_bytes(&hash(
        "PUBLIC-CONTACT-B",
        &wallet[1].verifying_key().to_bytes(),
    ));
    let ka = a.verifying_key().to_bytes();
    let kb = b.verifying_key().to_bytes();
    let ia = hash("PEER", &ka);
    let ib = hash("PEER", &kb);
    let p = [
        b"RLDSPKT1".to_vec(),
        1u16.to_be_bytes().to_vec(),
        1u16.to_be_bytes().to_vec(),
        chain.to_vec(),
        ka.to_vec(),
        ib.to_vec(),
        1u128.to_be_bytes().to_vec(),
        vec![2],
        (transaction.len() as u32).to_be_bytes().to_vec(),
        transaction.to_vec(),
    ]
    .concat();
    let id = hash("PACKET", &p);
    let packet = signed("PACKET-SIGN", p.clone(), &a);
    assert_eq!(packet.len(), transaction.len() + 193);
    verify(
        ka,
        &[tag("PACKET-SIGN"), p].concat(),
        &packet[packet.len() - 64..],
    )
    .unwrap();
    let challenge = [chain.to_vec(), kb.to_vec(), ia.to_vec(), vec![7; 32]].concat();
    let delivery = [
        chain.to_vec(),
        ka.to_vec(),
        ib.to_vec(),
        vec![7; 32],
        vec![8; 32],
        (packet.len() as u32).to_be_bytes().to_vec(),
        packet.clone(),
    ]
    .concat();
    let receipt = [
        chain.to_vec(),
        kb.to_vec(),
        ia.to_vec(),
        vec![7; 32],
        vec![8; 32],
        id.to_vec(),
        vec![1],
    ]
    .concat();
    for (label, fields, key) in [
        ("CHALLENGE", &challenge, &b),
        ("DELIVER", &delivery, &a),
        ("RECEIPT", &receipt, &b),
    ] {
        let s = signed(label, fields.clone(), key);
        verify(
            key.verifying_key().to_bytes(),
            &[tag(label), fields.clone()].concat(),
            &s[s.len() - 64..],
        )
        .unwrap();
        let mut bad = fields.clone();
        bad[0] ^= 1;
        assert!(verify(
            key.verifying_key().to_bytes(),
            &[tag(label), bad].concat(),
            &s[s.len() - 64..]
        )
        .is_err());
    }
    let delivery_frame = frame(2, signed("DELIVER", delivery, &a));
    assert_eq!(delivery_frame.len(), 12 + 229 + packet.len());
    let receipt_frame = frame(3, signed("RECEIPT", receipt, &b));
    let returned = [
        b"RLDSPKT1".to_vec(),
        1u16.to_be_bytes().to_vec(),
        1u16.to_be_bytes().to_vec(),
        chain.to_vec(),
        kb.to_vec(),
        ia.to_vec(),
        1u128.to_be_bytes().to_vec(),
        vec![9],
        (receipt_frame.len() as u32).to_be_bytes().to_vec(),
        receipt_frame.clone(),
    ]
    .concat();
    json!({"origin_public_key":hex::encode(ka),"destination_public_key":hex::encode(kb),"packet_id":hex::encode(id),"packet_hex":hex::encode(packet),
        "challenge_frame_hex":hex::encode(frame(1,signed("CHALLENGE",challenge,&b))),"delivery_frame_hex":hex::encode(delivery_frame),
        "destination_receipt_frame_hex":hex::encode(receipt_frame),"return_receipt_packet_hex":hex::encode(signed("PACKET-SIGN",returned,&b)),"receipt_authorizes_ledger_credit":false})
}
fn build() -> Value {
    let (manifest, chain) = genesis();
    let keys = keys();
    let owners = keys.each_ref().map(|k| k.verifying_key().to_bytes());
    let zero = Block {
        id: chain,
        height: 0,
        time: START,
        base: limit(),
        target: limit(),
        work: Big::zero(),
        coins: Coins::new(),
        raw: Vec::new(),
    };
    let mut main = vec![zero.clone()];
    let mut payment = Vec::new();
    let mut onward = Vec::new();
    let mut reward_input = Vec::new();
    for h in 1..=145u128 {
        let txs = if h == 101 {
            reward_input = main[1].coins.keys().next().unwrap().clone();
            let amount = main[1].coins[&reward_input].amount;
            payment = transfer(
                chain,
                &keys[0],
                &[reward_input.clone()],
                &[(owners[1], 100), (owners[0], amount - 101)],
                1,
                u128::MAX,
            );
            vec![payment.clone()]
        } else if h == 102 {
            let id = decode_tx(&payment, chain).unwrap().id;
            onward = transfer(
                chain,
                &keys[1],
                &[outpoint(id, 0)],
                &[(owners[2], 99)],
                1,
                u128::MAX,
            );
            vec![onward.clone()]
        } else {
            vec![]
        };
        let block = mine(chain, &main, owners[0], txs, START + h as u64 * 600);
        let parsed = replay(chain, &main, &block.raw, block.time).unwrap();
        assert_eq!(parsed.id, block.id);
        assert_eq!(
            state(chain, emission(h).1, &parsed.coins),
            state(chain, emission(h).1, &block.coins)
        );
        main.push(parsed);
    }
    let mut alternate = main[..=100].to_vec();
    let amount = main[1].coins[&reward_input].amount;
    let conflict = transfer(
        chain,
        &keys[0],
        &[reward_input.clone()],
        &[(owners[2], 97), (owners[0], amount - 98)],
        1,
        u128::MAX,
    );
    for h in 101..=146u128 {
        let txs = if h == 101 {
            vec![conflict.clone()]
        } else {
            vec![]
        };
        let block = mine(chain, &alternate, owners[2], txs, START + h as u64 * 600);
        let parsed = replay(chain, &alternate, &block.raw, block.time).unwrap();
        assert_eq!(parsed.id, block.id);
        alternate.push(parsed);
    }
    let pay_id = decode_tx(&payment, chain).unwrap().id;
    let onward_id = decode_tx(&onward, chain).unwrap().id;
    let conflict_id = decode_tx(&conflict, chain).unwrap().id;
    assert!(!alternate[146].coins.contains_key(&outpoint(onward_id, 0)));
    assert!(!alternate[146].coins.contains_key(&outpoint(pay_id, 0)));
    assert_eq!(winner(&main[145], &alternate[146]), alternate[146].id);
    assert_eq!(alternate[146].coins[&outpoint(conflict_id, 0)].amount, 97);
    assert!(apply(
        chain,
        main[99].id,
        100,
        owners[0],
        &[payment.clone()],
        &main[99].coins
    )
    .is_err());
    assert!(apply(
        chain,
        main[100].id,
        101,
        owners[0],
        &[payment.clone()],
        &main[100].coins
    )
    .is_ok());
    let mut both = vec![payment.clone(), onward.clone()];
    both.sort_by_key(|t| decode_tx(t, chain).unwrap().id);
    assert!(apply(chain, main[100].id, 101, owners[0], &both, &main[100].coins).is_err());
    let mut negatives = Vec::new();
    for (name, offset) in [
        ("wrong_version", 1),
        ("wrong_chain", 2),
        ("altered_signature", payment.len() - 1),
        ("changed_output_amount", 151),
    ] {
        let mut raw = payment.clone();
        raw[offset] ^= 1;
        assert!(decode_tx(&raw, chain).is_err());
        negatives
            .push(json!({"name":name,"transaction_hex":hex::encode(raw),"expected":"INVALID"}));
    }
    let mut raw = payment.clone();
    raw.push(0);
    assert!(decode_tx(&raw, chain).is_err());
    negatives.push(
        json!({"name":"trailing_byte","transaction_hex":hex::encode(raw),"expected":"INVALID"}),
    );
    let duplicate = transfer(
        chain,
        &keys[0],
        &[reward_input.clone(), reward_input.clone()],
        &[(owners[1], 1)],
        1,
        u128::MAX,
    );
    assert!(decode_tx(&duplicate, chain).is_err());
    negatives.push(json!({"name":"duplicate_input","transaction_hex":hex::encode(duplicate),"expected":"INVALID"}));
    let expired = transfer(
        chain,
        &keys[0],
        &[reward_input],
        &[(owners[1], amount - 1)],
        1,
        100,
    );
    assert!(apply(
        chain,
        main[100].id,
        101,
        owners[0],
        std::slice::from_ref(&expired),
        &main[100].coins
    )
    .is_err());
    negatives.push(json!({"name":"expired_at_inclusion","transaction_hex":hex::encode(expired),"parent_height":"100","candidate_height":"101","expected":"EXPIRED"}));
    let mut issuance = Vec::new();
    let mut r = CAP;
    let mut era = 0u128;
    while r > 0 {
        for h in [era * 200000 + 1, (era + 1) * 200000] {
            let (s, i) = emission(h);
            issuance.push(
                json!({"height":h.to_string(),"subsidy":s.to_string(),"issued":i.to_string()}),
            );
        }
        r -= if r == 1 { 1 } else { r / 2 };
        era += 1;
    }
    for h in [0, 2, 100, 101, 200001, era * 200000 + 1, u128::MAX - 100] {
        let (s, i) = emission(h);
        issuance
            .push(json!({"height":h.to_string(),"subsidy":s.to_string(),"issued":i.to_string()}));
    }
    assert_eq!(emission(u128::MAX - 100), (0, CAP));
    let mut arithmetic = Vec::new();
    for t in [
        Big::small(1),
        Big::small(2),
        Big::small(255),
        limit().div_small(4),
        limit(),
    ] {
        for elapsed in [1u64, 21449, 21450, 85800, 343200, 343201] {
            arithmetic.push(json!({"prior_base_hex":t.hex(),"elapsed":elapsed.to_string(),"next_base_hex":scaled(t,elapsed).hex()}));
        }
    }
    let work_vectors: Vec<_> = [
        Big::small(1),
        Big::small(2),
        Big::small(255),
        limit().div_small(4),
        limit(),
    ]
    .into_iter()
    .map(|t| json!({"target_hex":t.hex(),"work_hex":hex::encode(work(t).0)}))
    .collect();
    assert_eq!(work(limit()), Big::small(256));
    assert_eq!(work(Big::small(1)), Big::power(255));
    let easy = mine(
        chain,
        std::slice::from_ref(&zero),
        owners[0],
        vec![],
        START + 600,
    );
    assert!(replay(
        chain,
        std::slice::from_ref(&zero),
        &easy.raw,
        START + 600 - 600
    )
    .is_ok());
    let future = mine(
        chain,
        std::slice::from_ref(&zero),
        owners[0],
        vec![],
        START + 7201,
    );
    assert_eq!(
        replay(chain, std::slice::from_ref(&zero), &future.raw, START)
            .err()
            .unwrap(),
        "CLOCK_WAIT"
    );
    assert!(replay(chain, std::slice::from_ref(&zero), &future.raw, START + 1).is_ok());
    let recovery_base = Big::small(1);
    let recovery:Vec<_>=[14399u64,14400,14401].into_iter().map(|gap|{
        let target=if gap>=14400{limit()}else{recovery_base};json!({"base_hex":recovery_base.hex(),"gap":gap.to_string(),"target_hex":target.hex(),"work_hex":hex::encode(work(target).0)})}).collect();
    let empty_root = state(chain, 0, &Coins::new());
    let mut recovery_chain = vec![zero.clone()];
    for h in 1..=146u128 {
        let previous = recovery_chain.last().unwrap().time;
        let gap = if h <= 144 {
            1
        } else if h == 145 {
            14400
        } else {
            600
        };
        let block = mine(chain, &recovery_chain, owners[0], vec![], previous + gap);
        let checked = replay(chain, &recovery_chain, &block.raw, block.time).unwrap();
        recovery_chain.push(checked);
    }
    assert_eq!(recovery_chain[145].base, limit().div_small(4));
    assert_eq!(recovery_chain[145].target, limit());
    assert_eq!(
        recovery_chain[145].work.sub(recovery_chain[144].work),
        Big::small(256)
    );
    assert_eq!(recovery_chain[146].target, limit().div_small(4));
    assert_eq!(
        recovery_chain[146].work.sub(recovery_chain[145].work),
        Big::small(1024)
    );
    let tree_records: Vec<_> = main[3]
        .coins
        .iter()
        .map(|(k, c)| {
            [
                k.clone(),
                c.owner.to_vec(),
                c.amount.to_be_bytes().to_vec(),
                c.maturity.to_be_bytes().to_vec(),
            ]
            .concat()
        })
        .collect();
    json!({"profile":"RLD-SURVIVOR-1","classification":"PUBLIC NO-VALUE SPECIFICATION VECTORS; NEVER USE THESE PUBLIC TEST KEYS FOR ASSETS",
        "fixture_key_origin":"RFC8032 section 7.1 tests 1-3; contact fixtures derive from their public keys and public domain labels",
        "genesis":{"manifest_hex":hex::encode(manifest),"chain_id":hex::encode(chain),"empty_state_root":hex::encode(empty_root)},
        "wallet_public_keys":owners.map(hex::encode),"issuance":issuance,"target_scaling":arithmetic,"work":work_vectors,"recovery":recovery,
        "tree":{"ordered_records_hex":tree_records.iter().map(hex::encode).collect::<Vec<_>>(),"three_leaf_root":hex::encode(tree(&tree_records))},
        "payment":{"transaction_hex":hex::encode(&payment),"transaction_id":hex::encode(pay_id),"signing_message_hex":hex::encode([tag("TRANSFER"),payment[..payment.len()-64].to_vec()].concat()),"first_spendable_height":"101"},
        "onward":{"transaction_hex":hex::encode(&onward),"transaction_id":hex::encode(onward_id),"included_height":"102"},
        "main_branch":main[1..].iter().map(view).collect::<Vec<_>>(),"alternative_from_height":"101","alternative_branch":alternate[101..].iter().map(view).collect::<Vec<_>>(),
        "recovery_branch_from_genesis":recovery_chain[1..].iter().map(view).collect::<Vec<_>>(),
        "selection":{"equal_work_height":"101","equal_work_winner":hex::encode(winner(&main[101],&alternate[101])),"greater_work_winner":hex::encode(alternate[146].id),"detached_payment":hex::encode(pay_id),"detached_onward":hex::encode(onward_id),"replacement_payment":hex::encode(conflict_id),"replacement_recipient_amount":"97"},
        "future_block":{"block_hex":hex::encode(future.raw),"at_local_time":START.to_string(),"expected":"CLOCK_WAIT","eligible_at_local_time":(START+1).to_string()},
        "negative_transfers":negatives,"contact":contact_vectors(chain,&payment)})
}
fn check_manifest(vector_path: &str) {
    let directory = std::path::Path::new(vector_path)
        .parent()
        .expect("vector directory");
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(directory.join("SPECIFICATION.json")).expect("specification manifest"),
    )
    .expect("manifest JSON");
    assert_eq!(manifest["format"], "RLD-SURVIVOR-SPEC-MANIFEST-1");
    assert_eq!(manifest["profile"], "RLD-SURVIVOR-1");
    assert_eq!(manifest["adopted"], false);
    let files = manifest["normative_files"]
        .as_object()
        .expect("normative files");
    let expected = [
        "README.md",
        "CONSENSUS.md",
        "OPERATIONS.md",
        "CONFORMANCE.md",
        "vectors.json",
    ];
    assert_eq!(files.len(), expected.len());
    for name in expected {
        let raw = std::fs::read(directory.join(name)).expect("normative file");
        assert_eq!(
            files[name],
            hex::encode(Sha256::digest(raw)),
            "specification commitment differs for {name}"
        );
    }
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 || !["generate", "check"].contains(&args[1].as_str()) {
        eprintln!("usage: rld-survivor-spec-vectors generate|check PATH");
        std::process::exit(2)
    }
    let expected = build();
    if args[1] == "generate" {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&args[2])
            .expect("new output file required");
        let mut bytes = serde_json::to_vec_pretty(&expected).unwrap();
        bytes.push(b'\n');
        f.write_all(&bytes).unwrap();
        f.sync_all().unwrap();
        println!("wrote public no-value vectors");
    } else {
        check_manifest(&args[2]);
        let actual: Value = serde_json::from_slice(&std::fs::read(&args[2]).expect("vector file"))
            .expect("vector JSON");
        assert_eq!(
            actual, expected,
            "published vectors disagree with specification oracle"
        );
        println!("all published vector bytes and expected outcomes agree");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn published_key_origin_and_openssl_signature_interop() {
        let k = keys();
        assert_eq!(
            hex::encode(k[0].verifying_key().to_bytes()),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        assert_eq!(
            hex::encode(k[1].verifying_key().to_bytes()),
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        );
        assert_eq!(
            hex::encode(k[2].verifying_key().to_bytes()),
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
        );
        let (_, chain) = genesis();
        let tx = transfer(
            chain,
            &k[0],
            &[outpoint([1; 32], 0)],
            &[(k[1].verifying_key().to_bytes(), 1)],
            1,
            u128::MAX,
        );
        let message = [tag("TRANSFER"), tx[..tx.len() - 64].to_vec()].concat();
        let der = [
            hex::decode("302a300506032b6570032100").unwrap(),
            k[0].verifying_key().to_bytes().to_vec(),
        ]
        .concat();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("rld-public-vector-{}-{unique}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        for (name, data) in [
            ("public.der", der),
            ("message.bin", message.clone()),
            ("signature.bin", tx[tx.len() - 64..].to_vec()),
        ] {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(dir.join(name))
                .unwrap();
            f.write_all(&data).unwrap();
        }
        let run = || {
            std::process::Command::new("openssl")
                .current_dir(&dir)
                .args([
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-keyform",
                    "DER",
                    "-inkey",
                    "public.der",
                    "-rawin",
                    "-in",
                    "message.bin",
                    "-sigfile",
                    "signature.bin",
                ])
                .output()
                .expect("OpenSSL with Ed25519 support is required for the interoperability test")
        };
        assert!(run().status.success());
        let mut altered = message;
        altered[0] ^= 1;
        std::fs::write(dir.join("message.bin"), altered).unwrap();
        assert!(!run().status.success());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn full_vectors_and_replay() {
        let v = build();
        assert_eq!(v["main_branch"].as_array().unwrap().len(), 145);
        assert_eq!(v["alternative_branch"].as_array().unwrap().len(), 46);
    }
    #[test]
    fn integers_and_work() {
        for a in 0..100u128 {
            for b in 1..30u128 {
                assert_eq!(Big::small(a).div(Big::small(b)), Big::small(a / b));
                assert_eq!(Big::small(a).mul(b as u32), Big::small(a * b));
            }
        }
        assert_eq!(work(limit()), Big::small(256));
        assert_eq!(work(Big::small(255)), Big::power(248));
    }
    #[test]
    fn crypto_rejects_torsion_identity_and_noncanonical_scalar() {
        let k = keys();
        assert!(!valid_point([0; 32]));
        let mut identity = [0; 32];
        identity[0] = 1;
        assert!(!valid_point(identity));
        let msg = b"public no-value check";
        let mut s = k[0].sign(msg).to_bytes();
        s[32..].fill(255);
        assert!(verify(k[0].verifying_key().to_bytes(), msg, &s).is_err());
        let mut s = k[0].sign(msg).to_bytes();
        s[..32].copy_from_slice(&identity);
        assert!(verify(k[0].verifying_key().to_bytes(), msg, &s).is_err());
    }
    #[test]
    fn malformed_blocks_and_wrong_roots_refuse() {
        let (_, chain) = genesis();
        let zero = Block {
            id: chain,
            height: 0,
            time: START,
            base: limit(),
            target: limit(),
            work: Big::zero(),
            coins: Coins::new(),
            raw: vec![],
        };
        let b = mine(
            chain,
            std::slice::from_ref(&zero),
            keys()[0].verifying_key().to_bytes(),
            vec![],
            START + 600,
        );
        for n in [0, 1, 84, 267, 269] {
            assert!(replay(chain, std::slice::from_ref(&zero), &b.raw[..n], START + 600).is_err());
        }
        for offset in [1, 35, 67, 83, 91, 123, 155, 219, 251] {
            let mut raw = b.raw.clone();
            raw[offset] ^= 1;
            assert!(replay(chain, std::slice::from_ref(&zero), &raw, START + 600).is_err());
        }
        let mut raw = b.raw.clone();
        raw.push(0);
        assert!(replay(chain, &[zero], &raw, START + 600).is_err());
    }
    #[test]
    fn transaction_length_extremes() {
        let (_, c) = genesis();
        let k = keys();
        let p = k[0].verifying_key().to_bytes();
        let input = outpoint([1; 32], 0);
        assert_eq!(
            transfer(c, &k[0], &[input], &[(p, 1)], 1, u128::MAX).len(),
            248
        );
        let inputs: Vec<_> = (0..32).map(|i| outpoint([1; 32], i)).collect();
        let outputs = vec![(p, 1); 8];
        let raw = transfer(c, &k[0], &inputs, &outputs, 1, u128::MAX);
        assert_eq!(raw.len(), 1638);
        assert!(decode_tx(&raw, c).is_ok());
    }
    #[test]
    fn supply_and_target_edges() {
        assert_eq!(emission(0), (0, 0));
        assert_eq!(emission(200000).1, CAP / 2);
        assert_eq!(emission(u128::MAX - 100), (0, CAP));
        assert_eq!(scaled(limit(), 343200), limit());
        assert_eq!(scaled(Big::small(1), 1), Big::small(1));
        assert_eq!(scaled(limit(), 21449), scaled(limit(), 21450));
        assert_eq!(scaled(limit(), 343200), scaled(limit(), 343201));
    }
}
