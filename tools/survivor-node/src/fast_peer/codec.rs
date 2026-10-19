//! Data carriage only: a peer signature/response grants no wallet or ledger right.
use crate::{
    fast_payment::ensure,
    kernel::{self, Hash, Result},
};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
pub const MAX_PACKET: usize = 262345;
pub const MAX_BLOCK_BATCH: usize = 32;
pub const BATCH_HEADER: usize = 54;
/// Sender journal ordinals are custody coordinates only. Every complete block
/// still requires recipient-native execution from independently pinned genesis.
pub fn block_batch(chain: Hash, first: u64, blocks: &[Vec<u8>]) -> Result<Vec<u8>> {
    let mut raw = b"RLDFBLK1".to_vec();
    raw.extend([0, 1, 0, 1]);
    raw.extend(chain);
    raw.extend(first.to_be_bytes());
    ensure(
        (1..=MAX_BLOCK_BATCH).contains(&blocks.len()),
        "INVALID native batch count",
    )?;
    raw.extend((blocks.len() as u16).to_be_bytes());
    for block in blocks {
        ensure(
            raw.len()
                .checked_add(4 + block.len())
                .is_some_and(|n| n <= 262144),
            "RESOURCE_WAIT native batch payload",
        )?;
        raw.extend((block.len() as u32).to_be_bytes());
        raw.extend(block);
    }
    decode_block_batch(&raw, chain)?;
    Ok(raw)
}
pub fn decode_block_batch(raw: &[u8], chain: Hash) -> Result<(u64, Vec<&[u8]>)> {
    ensure(
        (328..=262144).contains(&raw.len())
            && &raw[..8] == b"RLDFBLK1"
            && raw[8..12] == [0, 1, 0, 1]
            && raw[12..44] == chain,
        "INVALID native batch header",
    )?;
    let first = u64::from_be_bytes(raw[44..52].try_into().unwrap());
    let count = u16::from_be_bytes(raw[52..54].try_into().unwrap()) as usize;
    ensure(
        first > 0
            && (1..=MAX_BLOCK_BATCH).contains(&count)
            && first.checked_add(count as u64 - 1).is_some(),
        "INVALID native batch ordinal/count",
    )?;
    let mut reader = crate::fast_retainer::Reader {
        raw,
        at: BATCH_HEADER,
    };
    let mut blocks = vec![];
    let mut ids = std::collections::BTreeSet::new();
    for _ in 0..count {
        let n = reader.u32()? as usize;
        ensure(
            (270..=262144).contains(&n),
            "INVALID native batch block size",
        )?;
        let block = reader.take(n)?;
        let id = kernel::fast::block_id(block)?;
        ensure(
            block[4..36] == chain && ids.insert(id),
            "INVALID native batch block scope/duplicate",
        )?;
        blocks.push(block);
    }
    ensure(reader.at == raw.len(), "INVALID native batch tail")?;
    Ok((first, blocks))
}
pub fn tag(s: &str) -> Vec<u8> {
    [b"RLD-FAST-PEER-1/".as_slice(), s.as_bytes(), &[0]].concat()
}
pub fn hash(s: &str, b: &[u8]) -> Hash {
    Sha256::digest([tag(s), b.to_vec()].concat()).into()
}
pub fn nonce() -> Result<Hash> {
    let mut n = [0; 32];
    getrandom::getrandom(&mut n).map_err(|_| "RESOURCE_WAIT peer entropy")?;
    ensure(n != [0; 32], "RESOURCE_WAIT peer entropy")?;
    Ok(n)
}
fn sign(key: &SigningKey, domain: &str, raw: &[u8]) -> [u8; 64] {
    key.sign(&[tag(domain), raw.to_vec()].concat()).to_bytes()
}
fn verify(key: Hash, domain: &str, body: &[u8], sig: &[u8]) -> Result<()> {
    kernel::verify(key, &[tag(domain), body.to_vec()].concat(), sig)
}
#[derive(Clone)]
pub struct Packet {
    pub raw: Vec<u8>,
    pub id: Hash,
    pub sender: Hash,
    pub destination: Hash,
    pub kind: u8,
    pub payload: Vec<u8>,
}
/// Versioned carriage only; a complete actor signature is not native inclusion.
pub fn operation_payload(chain: Hash, operation: &[u8]) -> Result<Vec<u8>> {
    kernel::fast::validate_operation(operation, chain)?;
    let mut raw = vec![0, 1, 0, 1];
    raw.extend(chain);
    raw.extend((operation.len() as u16).to_be_bytes());
    raw.extend(operation);
    Ok(raw)
}
pub fn operation(raw: &[u8], chain: Hash) -> Result<&[u8]> {
    ensure(
        (39..=4134).contains(&raw.len()) && raw[..4] == [0, 1, 0, 1] && raw[4..36] == chain,
        "INVALID native operation carriage header",
    )?;
    let n = u16::from_be_bytes(raw[36..38].try_into().unwrap()) as usize;
    ensure(
        (1..=4096).contains(&n) && raw.len() == 38 + n,
        "INVALID native operation carriage size",
    )?;
    kernel::fast::validate_operation(&raw[38..], chain)?;
    Ok(&raw[38..])
}
pub fn payload(kind: u8, raw: &[u8], chain: Hash) -> Result<()> {
    match kind {
        1 => {
            kernel::fast::block_id(raw)?;
            ensure(raw[4..36] == chain, "INVALID peer block chain")?;
        }
        2 => ensure(
            (raw.len() == 323 || raw.len() == 575)
                && raw[..4] == [0, 1, 0, 1]
                && raw[4..36] == chain,
            "INVALID peer invoice shape",
        )?,
        3 => ensure(
            raw.len() == 161 && raw[32] < 2 && raw[..32] != [0; 32],
            "INVALID peer partial shape",
        )?,
        4 => ensure(
            (raw.len() == 579 || raw.len() == 831)
                && raw[..4] == [0, 1, 0, 1]
                && raw[4..36] == chain,
            "INVALID peer receipt shape",
        )?,
        5 => ensure(
            raw.len() == 340 && raw[..4] == [0, 1, 0, 1] && raw[4..36] == chain,
            "INVALID peer acknowledgment shape",
        )?,
        6 => {
            operation(raw, chain)?;
        }
        7 => {
            opening_frame(raw, chain, false)?;
        }
        8 => {
            opening_frame(raw, chain, true)?;
        }
        9 => {
            decode_block_batch(raw, chain)?;
        }
        _ => return Err("UNSUPPORTED peer payload kind".into()),
    }
    Ok(())
}
pub fn opening_payload(chain: Hash, proposal: &[u8], partial: Option<&[u8]>) -> Result<Vec<u8>> {
    kernel::fast::opening::proposal_id(proposal, chain)?;
    if let Some(partial) = partial {
        kernel::fast::opening::verify_partial(proposal, partial, chain)?;
    }
    let mut raw = vec![0, 1, 0, 1];
    raw.extend(chain);
    raw.extend((proposal.len() as u16).to_be_bytes());
    raw.extend(proposal);
    if let Some(partial) = partial {
        raw.extend(partial);
    }
    Ok(raw)
}
pub fn opening_frame(raw: &[u8], chain: Hash, partial: bool) -> Result<(&[u8], Option<&[u8]>)> {
    let tail = if partial { 65 } else { 0 };
    ensure(
        (403 + tail..=2511 + tail).contains(&raw.len())
            && raw[..4] == [0, 1, 0, 1]
            && raw[4..36] == chain,
        "INVALID opening carriage header",
    )?;
    let n = u16::from_be_bytes(raw[36..38].try_into().unwrap()) as usize;
    ensure(
        (365..=2473).contains(&n) && raw.len() == 38 + n + tail,
        "INVALID opening carriage length",
    )?;
    let proposal = &raw[38..38 + n];
    kernel::fast::opening::proposal_id(proposal, chain)?;
    let own = partial.then_some(&raw[38 + n..]);
    if let Some(partial) = own {
        kernel::fast::opening::verify_partial(proposal, partial, chain)?;
    }
    Ok((proposal, own))
}
impl Packet {
    pub fn create(
        chain: Hash,
        key: &SigningKey,
        destination: Hash,
        kind: u8,
        data: &[u8],
    ) -> Result<Self> {
        payload(kind, data, chain)?;
        let mut b = vec![0, 1, 0, 1];
        b.extend(chain);
        b.extend(key.verifying_key().to_bytes());
        b.extend(destination);
        b.push(kind);
        let message = hash("MESSAGE", &[b.as_slice(), data].concat());
        b.extend(message);
        b.extend((data.len() as u32).to_be_bytes());
        b.extend(data);
        let s = sign(key, "PACKET", &b);
        b.extend(s);
        Self::decode(&b, chain)
    }
    pub fn decode(raw: &[u8], chain: Hash) -> Result<Self> {
        ensure(
            (201..=MAX_PACKET).contains(&raw.len())
                && raw[..4] == [0, 1, 0, 1]
                && raw[4..36] == chain,
            "INVALID peer packet header",
        )?;
        let sender = raw[36..68].try_into().unwrap();
        let destination = raw[68..100].try_into().unwrap();
        ensure(
            kernel::valid_point(sender)
                && kernel::valid_point(destination)
                && sender != destination
                && raw[101..133] != [0; 32],
            "INVALID peer packet roles/nonce",
        )?;
        let n = u32::from_be_bytes(raw[133..137].try_into().unwrap()) as usize;
        ensure(
            n <= MAX_PACKET - 201 && raw.len() == 201 + n,
            "INVALID peer packet length",
        )?;
        payload(raw[100], &raw[137..137 + n], chain)?;
        ensure(
            raw[101..133] == hash("MESSAGE", &[&raw[..101], &raw[137..137 + n]].concat()),
            "INVALID stable peer message tag",
        )?;
        verify(sender, "PACKET", &raw[..137 + n], &raw[137 + n..])?;
        Ok(Self {
            raw: raw.to_vec(),
            id: hash("PACKET-ID", raw),
            sender,
            destination,
            kind: raw[100],
            payload: raw[137..137 + n].to_vec(),
        })
    }
}
pub fn challenge(chain: Hash, key: &SigningKey, s: Hash) -> Vec<u8> {
    let mut b = vec![0, 1, 0, 1];
    b.extend(chain);
    b.extend(key.verifying_key().to_bytes());
    b.extend(s);
    let sig = sign(key, "CHALLENGE", &b);
    b.extend(sig);
    b
}
pub fn check_challenge(raw: &[u8], chain: Hash, peer: Hash) -> Result<Hash> {
    ensure(
        raw.len() == 164
            && raw[..4] == [0, 1, 0, 1]
            && raw[4..36] == chain
            && raw[36..68] == peer
            && raw[68..100] != [0; 32],
        "INVALID peer challenge binding",
    )?;
    verify(peer, "CHALLENGE", &raw[..100], &raw[100..])?;
    Ok(raw[68..100].try_into().unwrap())
}
pub fn delivery(
    chain: Hash,
    key: &SigningKey,
    peer: Hash,
    s: Hash,
    c: Hash,
    p: &Packet,
) -> Vec<u8> {
    let mut b = vec![0, 1, 0, 1];
    b.extend(chain);
    b.extend(key.verifying_key().to_bytes());
    b.extend(peer);
    b.extend(s);
    b.extend(c);
    b.extend((p.raw.len() as u32).to_be_bytes());
    b.extend(&p.raw);
    let sig = sign(key, "DELIVERY", &b);
    b.extend(sig);
    b
}
pub fn check_delivery(
    raw: &[u8],
    chain: Hash,
    peer: Hash,
    local: Hash,
    s: Hash,
) -> Result<(Packet, Hash)> {
    ensure(
        (232 + 201..=232 + MAX_PACKET).contains(&raw.len())
            && raw[..4] == [0, 1, 0, 1]
            && raw[4..36] == chain
            && raw[36..68] == peer
            && raw[68..100] == local
            && raw[100..132] == s
            && s != [0; 32]
            && raw[132..164] != [0; 32],
        "INVALID peer delivery binding",
    )?;
    let n = u32::from_be_bytes(raw[164..168].try_into().unwrap()) as usize;
    ensure(
        n <= MAX_PACKET && raw.len() == 232 + n,
        "INVALID peer delivery length",
    )?;
    verify(peer, "DELIVERY", &raw[..168 + n], &raw[168 + n..])?;
    let p = Packet::decode(&raw[168..168 + n], chain)?;
    ensure(
        p.sender == peer && p.destination == local,
        "INVALID direct peer packet role",
    )?;
    Ok((p, raw[132..164].try_into().unwrap()))
}
pub fn response(
    chain: Hash,
    key: &SigningKey,
    peer: Hash,
    s: Hash,
    c: Hash,
    id: Hash,
    head: Hash,
) -> Vec<u8> {
    let mut b = vec![0, 1, 0, 1];
    b.extend(chain);
    b.extend(key.verifying_key().to_bytes());
    b.extend(peer);
    b.extend(s);
    b.extend(c);
    b.extend(id);
    b.extend(head);
    b.push(0);
    let sig = sign(key, "RESPONSE", &b);
    b.extend(sig);
    b
}
pub fn check_response(
    raw: &[u8],
    chain: Hash,
    local: Hash,
    peer: Hash,
    id: Hash,
    nonces: Option<(Hash, Hash)>,
) -> Result<()> {
    ensure(
        raw.len() == 293
            && raw[..4] == [0, 1, 0, 1]
            && raw[4..36] == chain
            && raw[36..68] == peer
            && raw[68..100] == local
            && raw[164..196] == id
            && raw[196..228] != [0; 32]
            && raw[228] == 0
            && raw[100..132] != [0; 32]
            && raw[132..164] != [0; 32],
        "INVALID peer custody response binding",
    )?;
    if let Some((s, c)) = nonces {
        ensure(
            raw[100..132] == s && raw[132..164] == c,
            "INVALID peer response connection nonces",
        )?;
    }
    verify(peer, "RESPONSE", &raw[..229], &raw[229..])
}
