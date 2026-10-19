//! Data carriage only: a peer signature/response grants no wallet or ledger right.
use crate::{
    fast_payment::ensure,
    kernel::{self, Hash, Result},
};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
pub const MAX_PACKET: usize = 262345;
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
        _ => return Err("UNSUPPORTED peer payload kind".into()),
    }
    Ok(())
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
