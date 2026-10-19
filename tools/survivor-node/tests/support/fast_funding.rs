//! PUBLIC NO-VALUE keys. Every amount comes from fresh native PoW/maturity,
//! never a serialized balance, mocked funding flag or retained failed fixture.
use ed25519_dalek::{Signer, SigningKey};
use rld_survivor_node::{
    fast_payment::{Delegation, Payment},
    kernel::{fast, Hash},
};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
pub struct Fixture {
    pub genesis: Vec<u8>,
    pub history: Vec<u8>,
    pub ledger: fast::Ledger,
    pub channel: Hash,
    pub owners: [SigningKey; 2],
    pub miner: SigningKey,
    pub retainer: SigningKey,
    pub now: u64,
    pub before: fast::Ledger,
}
pub fn tag(label: &str) -> Vec<u8> {
    [b"RLD-FAST-PAYMENT-1/".as_slice(), label.as_bytes(), &[0]].concat()
}
fn op_tag(label: &str) -> Vec<u8> {
    [b"RLD-FAST-ESCROW-1/".as_slice(), label.as_bytes(), &[0]].concat()
}
pub fn out(id: Hash, index: u16) -> Vec<u8> {
    [id.to_vec(), index.to_be_bytes().to_vec()].concat()
}
pub fn mine(ledger: &mut fast::Ledger, miner: Hash, ops: Vec<Vec<u8>>, now: u64) -> Vec<u8> {
    mine_until(
        ledger,
        miner,
        ops,
        now,
        Instant::now() + Duration::from_secs(180),
    )
}
pub fn mine_until(
    ledger: &mut fast::Ledger,
    miner: Hash,
    ops: Vec<Vec<u8>>,
    now: u64,
    deadline: Instant,
) -> Vec<u8> {
    let mut job = ledger
        .mining_job(miner, ops, ledger.tip().timestamp() + 600, now)
        .unwrap();
    loop {
        assert!(Instant::now() < deadline);
        if let (Some(raw), _) = job.search(4096) {
            ledger.execute(&raw, now).unwrap();
            return raw;
        }
    }
}
pub fn fixture() -> Fixture {
    let deadline = Instant::now() + Duration::from_secs(180);
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../docs/protocol/native-fast-escrow-v1-vectors.json"
    ))
    .unwrap();
    let mut genesis = hex::decode(v["genesis_hex"].as_str().unwrap()).unwrap();
    getrandom::getrandom(&mut genesis[13..45]).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    genesis[45..53].copy_from_slice(&(now - 61200).to_be_bytes());
    let chain = fast::genesis_id(&genesis);
    let mut ledger = fast::Ledger::from_genesis(&genesis, chain, 100_000).unwrap();
    let mut owners = [
        SigningKey::from_bytes(&[101; 32]),
        SigningKey::from_bytes(&[102; 32]),
    ];
    owners.sort_by_key(|k| k.verifying_key().to_bytes());
    let miner = SigningKey::from_bytes(&[103; 32]);
    let retainer = SigningKey::from_bytes(&[104; 32]);
    let a = owners[0].verifying_key().to_bytes();
    let b = owners[1].verifying_key().to_bytes();
    let mut history = Vec::new();
    let mut append = |raw: Vec<u8>| {
        history.extend((raw.len() as u32).to_be_bytes());
        history.extend(raw);
    };
    for _ in 0..100 {
        append(mine_until(&mut ledger, a, vec![], now, deadline));
    }
    let (input, coin) = ledger
        .coins()
        .iter()
        .find(|(_, c)| c.maturity <= 101)
        .unwrap();
    let mut u = 1u16.to_be_bytes().to_vec();
    u.extend(chain);
    u.extend(a);
    u.extend(1u16.to_be_bytes());
    u.extend(input);
    u.extend(3u16.to_be_bytes());
    for (key, value) in [(a, 2000u128), (b, 2000), (a, coin.amount - 4001)] {
        u.extend(key);
        u.extend(value.to_be_bytes());
    }
    u.extend(1u128.to_be_bytes());
    u.extend(u128::MAX.to_be_bytes());
    let splitid: Hash = Sha256::digest([b"RLD-SURVIVOR-1/TXID\0".as_slice(), &u].concat()).into();
    let signature = owners[0].sign(&[b"RLD-SURVIVOR-1/TRANSFER\0".as_slice(), &u].concat());
    let mut op = vec![0];
    op.extend(u);
    op.extend(signature.to_bytes());
    append(mine_until(&mut ledger, a, vec![op], now, deadline));
    let before = ledger.clone();
    let mut u = vec![0, 1, 0, 1];
    u.extend(chain);
    u.extend([19; 32]);
    u.extend(a);
    u.extend(b);
    u.extend(600u128.to_be_bytes());
    u.extend(400u128.to_be_bytes());
    for (n, f) in [(6u64, 2u128), (5, 3)] {
        u.extend(n.to_be_bytes());
        u.extend(f.to_be_bytes());
    }
    for value in [1u128, 1, 1387, 1584, u128::MAX] {
        u.extend(value.to_be_bytes());
    }
    for i in 0..2 {
        u.extend(1u16.to_be_bytes());
        u.extend(out(splitid, i));
    }
    let msg = [op_tag("OPEN"), u.clone()].concat();
    let mut op = vec![1];
    op.extend(u);
    for key in &owners {
        op.extend(key.sign(&msg).to_bytes());
    }
    let channel = fast::operation_id(&op);
    append(mine_until(
        &mut ledger,
        miner.verifying_key().to_bytes(),
        vec![op],
        now,
        deadline,
    ));
    Fixture {
        genesis,
        history,
        ledger,
        channel,
        owners,
        miner,
        retainer,
        now,
        before,
    }
}
pub fn delegation(f: &Fixture) -> Vec<u8> {
    let origin = f.ledger.funding_origin(f.channel).unwrap();
    let mut raw = Delegation::unsigned(&origin, f.retainer.verifying_key().to_bytes()).unwrap();
    let sig = f.miner.sign(&[tag("DELEGATION"), raw.clone()].concat());
    raw.extend(sig.to_bytes());
    raw
}
pub fn payment(
    f: &Fixture,
    previous: Option<&Payment>,
    payer: u8,
    value: u128,
    invoice: u8,
) -> Vec<u8> {
    let origin = f.ledger.funding_origin(f.channel).unwrap();
    let ctx = origin.context();
    let (q, mut balances, mut slots) = if let Some(p) = previous {
        let c = origin.verify_certificate(p.after_certificate()).unwrap();
        (c.sequence, c.balances, c.slots)
    } else {
        (0, origin.initial(), [0; 2])
    };
    balances[payer as usize] -= value;
    balances[1 - payer as usize] += value;
    slots[payer as usize] += 1;
    let mut after = ctx[..68].to_vec();
    after.extend((q + 1).to_be_bytes());
    for n in balances {
        after.extend(n.to_be_bytes());
    }
    for n in slots {
        after.extend(n.to_be_bytes());
    }
    let mut body = vec![0, 1, 0, 1];
    body.extend(origin.chain());
    body.extend(f.channel);
    body.extend(origin.context_commitment());
    body.extend([invoice; 32]);
    body.extend(previous.map_or([0; 32], Payment::id));
    body.push(payer);
    body.extend(value.to_be_bytes());
    body.extend(origin.rate(payer as usize).unwrap().to_be_bytes());
    let before = previous.map_or(&[][..], Payment::after_certificate);
    body.extend((before.len() as u16).to_be_bytes());
    body.extend(before);
    body.extend(&after);
    let msg = [
        b"RLD-FAST-FEE-CLAIM-1/STATE\0".as_slice(),
        origin.context_commitment().as_slice(),
        after.as_slice(),
    ]
    .concat();
    let mut raw = body.clone();
    for key in &f.owners {
        raw.extend(key.sign(&msg).to_bytes());
    }
    for key in &f.owners {
        raw.extend(
            key.sign(&[tag("INVOICE"), body.clone()].concat())
                .to_bytes(),
        );
    }
    raw
}
pub fn resign(f: &Fixture, raw: &mut [u8]) {
    let n = raw.len() - 256;
    let after = raw[n - 124..n].to_vec();
    let origin = f.ledger.funding_origin(f.channel).unwrap();
    let state = [
        b"RLD-FAST-FEE-CLAIM-1/STATE\0".as_slice(),
        origin.context_commitment().as_slice(),
        after.as_slice(),
    ]
    .concat();
    let invoice = [tag("INVOICE"), raw[..n].to_vec()].concat();
    for i in 0..2 {
        raw[n + i * 64..n + (i + 1) * 64].copy_from_slice(&f.owners[i].sign(&state).to_bytes());
        raw[n + 128 + i * 64..n + 192 + i * 64]
            .copy_from_slice(&f.owners[i].sign(&invoice).to_bytes());
    }
}
pub fn closed(f: &Fixture) -> fast::Ledger {
    let mut ledger = f.ledger.clone();
    let mut u = vec![0, 1, 0, 1];
    u.extend(ledger.chain_id());
    u.extend([29; 32]);
    u.extend(f.channel);
    u.extend(f.owners[0].verifying_key().to_bytes());
    for v in [1u128, 1386, u128::MAX] {
        u.extend(v.to_be_bytes());
    }
    u.extend(1u16.to_be_bytes());
    u.extend(out(f.channel, 0));
    u.extend(0u16.to_be_bytes());
    let sig = f.owners[0].sign(&[op_tag("ACTION"), vec![2], u.clone()].concat());
    let mut raw = vec![2];
    raw.extend(u);
    raw.extend(sig.to_bytes());
    mine(
        &mut ledger,
        f.miner.verifying_key().to_bytes(),
        vec![raw],
        f.now,
    );
    ledger
}

pub fn ordinary(
    chain: Hash,
    key: &SigningKey,
    input: &[u8],
    outputs: &[(Hash, u128)],
) -> (Vec<u8>, Hash) {
    let mut u = 1u16.to_be_bytes().to_vec();
    u.extend(chain);
    u.extend(key.verifying_key().to_bytes());
    u.extend(1u16.to_be_bytes());
    u.extend(input);
    u.extend((outputs.len() as u16).to_be_bytes());
    for (k, v) in outputs {
        u.extend(k);
        u.extend(v.to_be_bytes());
    }
    u.extend(1u128.to_be_bytes());
    u.extend(u128::MAX.to_be_bytes());
    let id = Sha256::digest([b"RLD-SURVIVOR-1/TXID\0".as_slice(), &u].concat()).into();
    let sig = key.sign(&[b"RLD-SURVIVOR-1/TRANSFER\0".as_slice(), &u].concat());
    let mut op = vec![0];
    op.extend(u);
    op.extend(sig.to_bytes());
    (op, id)
}
pub fn action(
    f: &Fixture,
    kind: u8,
    key: &SigningKey,
    fee_input: (&[u8], u128),
    certificate: &[u8],
    nonce: u8,
) -> Vec<u8> {
    let mut u = vec![0, 1, 0, 1];
    u.extend(f.ledger.chain_id());
    u.extend([nonce; 32]);
    u.extend(f.channel);
    u.extend(key.verifying_key().to_bytes());
    for v in [1u128, fee_input.1, u128::MAX] {
        u.extend(v.to_be_bytes());
    }
    u.extend(1u16.to_be_bytes());
    u.extend(fee_input.0);
    u.extend((certificate.len() as u16).to_be_bytes());
    u.extend(certificate);
    let sig = key.sign(&[op_tag("ACTION"), vec![kind], u.clone()].concat());
    let mut raw = vec![kind];
    raw.extend(u);
    raw.extend(sig.to_bytes());
    raw
}
