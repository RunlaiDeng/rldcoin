//! Exact O07/O08 signed contact bytes. Custody and ledger execution are separate.
use crate::kernel::{
    block_id, decode_tx, genesis_id, hash, tag, valid_point, verify, Hash, Ledger, Result,
};
use ed25519_dalek::{Signer, SigningKey};
use std::collections::BTreeSet;
pub const PACKET_MAX: usize = 1_048_347;
pub const FRAME_MAX: usize = 1_048_576;
fn ensure(ok: bool, why: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(why.into())
    }
}
struct Read<'a> {
    raw: &'a [u8],
    at: usize,
}
impl<'a> Read<'a> {
    fn new(raw: &'a [u8]) -> Self {
        Self { raw, at: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(n).ok_or("INVALID_ENCODING overflow")?;
        ensure(end <= self.raw.len(), "INVALID_ENCODING truncated")?;
        let b = &self.raw[self.at..end];
        self.at = end;
        Ok(b)
    }
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }
    fn end(&self) -> Result<()> {
        ensure(self.at == self.raw.len(), "INVALID_ENCODING trailing")
    }
}
pub fn peer_id(key: Hash) -> Hash {
    hash("PEER", &key)
}
#[derive(Clone, Debug)]
pub struct Packet {
    pub(crate) id: Hash,
    pub(crate) chain: Hash,
    pub(crate) origin: Hash,
    pub(crate) destination: Hash,
    pub(crate) sequence: u128,
    pub(crate) kind: u8,
    pub(crate) payload: Vec<u8>,
    pub(crate) raw: Vec<u8>,
}
impl Packet {
    pub fn id(&self) -> Hash {
        self.id
    }
    pub fn destination(&self) -> Hash {
        self.destination
    }
    pub fn kind(&self) -> u8 {
        self.kind
    }
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    pub fn origin(&self) -> Hash {
        self.origin
    }
    pub fn sequence(&self) -> u128 {
        self.sequence
    }
    pub fn chain(&self) -> Hash {
        self.chain
    }
    pub fn decode(raw: &[u8], chain: Hash) -> Result<Self> {
        ensure(
            (193..=PACKET_MAX).contains(&raw.len()),
            "INVALID_ENCODING packet size",
        )?;
        let mut r = Read::new(raw);
        ensure(r.take(8)? == b"RLDSPKT1", "INVALID_ENCODING packet magic")?;
        ensure(r.u16()? == 1 && r.u16()? == 1, "UNSUPPORTED_VERSION packet")?;
        ensure(r.fixed::<32>()? == chain, "WRONG_CHAIN packet")?;
        let origin = r.fixed()?;
        let destination = r.fixed()?;
        let sequence = u128::from_be_bytes(r.fixed()?);
        let kind = r.u8()?;
        let n = r.u32()? as usize;
        let payload = r.take(n)?.to_vec();
        let unsigned = &raw[..r.at];
        verify(
            origin,
            &[tag("PACKET-SIGN"), unsigned.to_vec()].concat(),
            r.take(64)?,
        )?;
        r.end()?;
        validate_payload(kind, &payload, chain)?;
        Ok(Self {
            id: hash("PACKET", unsigned),
            chain,
            origin,
            destination,
            sequence,
            kind,
            payload,
            raw: raw.to_vec(),
        })
    }
    pub fn sign(
        chain: Hash,
        key: &SigningKey,
        destination: Hash,
        sequence: u128,
        kind: u8,
        payload: &[u8],
    ) -> Result<Self> {
        ensure(
            payload.len() <= PACKET_MAX - 193,
            "INVALID_ENCODING packet payload",
        )?;
        let mut raw = b"RLDSPKT1".to_vec();
        raw.extend(1u16.to_be_bytes());
        raw.extend(1u16.to_be_bytes());
        raw.extend(chain);
        raw.extend(key.verifying_key().to_bytes());
        raw.extend(destination);
        raw.extend(sequence.to_be_bytes());
        raw.push(kind);
        raw.extend((payload.len() as u32).to_be_bytes());
        raw.extend(payload);
        let sig = key.sign(&[tag("PACKET-SIGN"), raw.clone()].concat());
        raw.extend(sig.to_bytes());
        Self::decode(&raw, chain)
    }
}
fn validate_payload(kind: u8, p: &[u8], chain: Hash) -> Result<()> {
    match kind {
        1 => {
            ensure(genesis_id(p) == chain, "WRONG_CHAIN manifest")?;
            Ledger::from_genesis(p, chain, 1)?;
        }
        2 => {
            decode_tx(p, chain)?;
        }
        3 => {
            block_syntax(p, chain)?;
        }
        4 => {
            ensure(p.len() == 96, "INVALID_ENCODING HEAD")?;
        }
        5 | 7 => {
            let mut r = Read::new(p);
            let n = r.u16()?;
            ensure(
                n <= 128 && (kind == 7 || n > 0),
                "INVALID_ENCODING inventory count",
            )?;
            let mut previous = None;
            for _ in 0..n {
                let k = r.u8()?;
                ensure((1..=3).contains(&k), "UNSUPPORTED_VERSION object kind")?;
                let id = r.fixed::<32>()?;
                let pair = (k, id);
                ensure(
                    previous.is_none_or(|x| x < pair),
                    "INVALID_ENCODING inventory order",
                )?;
                previous = Some(pair);
            }
            r.end()?;
        }
        6 => {
            let mut r = Read::new(p);
            let n = r.u16()?;
            ensure((1..=128).contains(&n), "INVALID_ENCODING locator count")?;
            let mut seen = BTreeSet::new();
            let mut last = [0; 32];
            for _ in 0..n {
                last = r.fixed()?;
                ensure(seen.insert(last), "INVALID_ENCODING locator duplicate")?;
            }
            ensure(last == chain, "WRONG_CHAIN locator genesis")?;
            r.end()?;
        }
        8 => {
            let mut r = Read::new(p);
            let n = r.u16()?;
            ensure(n <= 64, "INVALID_ENCODING peers count")?;
            let mut previous = None;
            for _ in 0..n {
                let k = r.fixed()?;
                ensure(
                    valid_point(k) && previous.is_none_or(|x| x < k),
                    "INVALID_CRYPTO peer/order",
                )?;
                previous = Some(k);
            }
            r.end()?;
        }
        9 => {
            let f = Frame::decode(p, chain)?;
            ensure(
                f.kind == 3 && f.result == Some(1),
                "INVALID_ENCODING returned receipt",
            )?;
        }
        _ => return Err("UNSUPPORTED_VERSION packet kind".into()),
    }
    Ok(())
}
/// Intrinsic bytes/signatures/root/PoW only. Parent timing, state and value still
/// require full Ledger::execute; this function never returns ledger authority.
pub fn block_syntax(raw: &[u8], chain: Hash) -> Result<()> {
    let id = block_id(raw)?;
    let mut r = Read::new(raw);
    ensure(r.u16()? == 1 && r.u16()? == 1, "UNSUPPORTED_VERSION block")?;
    ensure(r.fixed::<32>()? == chain, "WRONG_CHAIN block")?;
    r.take(32)?;
    let h = u128::from_be_bytes(r.fixed()?);
    ensure(h > 0 && h <= u128::MAX - 100, "INVALID_CONSENSUS height")?;
    r.take(8)?;
    let base = r.fixed::<32>()?;
    let target = r.fixed::<32>()?;
    ensure(
        base > [0; 32] && base[0] == 0 && target > [0; 32] && target[0] == 0 && id <= target,
        "INVALID_CONSENSUS target/PoW",
    )?;
    ensure(valid_point(r.fixed()?), "INVALID_CRYPTO miner")?;
    let txroot = r.fixed::<32>()?;
    r.take(48)?;
    let n = r.u16()?;
    ensure(n <= 128, "INVALID_ENCODING transaction count")?;
    let mut previous = None;
    for _ in 0..n {
        let len = r.u32()? as usize;
        let tx = decode_tx(r.take(len)?, chain)?;
        ensure(
            previous.is_none_or(|id| id < tx.id),
            "INVALID_ENCODING transaction order",
        )?;
        previous = Some(tx.id);
    }
    r.end()?;
    ensure(
        hash("TRANSACTIONS", &raw[268..]) == txroot,
        "INVALID_CONSENSUS transaction root",
    )
}
#[derive(Clone, Debug)]
pub struct Frame {
    pub(crate) kind: u8,
    pub(crate) sender: Hash,
    pub(crate) receiver: Hash,
    pub(crate) challenge: Hash,
    pub(crate) nonce: Hash,
    pub(crate) packet: Option<Packet>,
    pub(crate) packet_id: Option<Hash>,
    pub(crate) result: Option<u8>,
    pub(crate) raw: Vec<u8>,
}
impl Frame {
    pub fn sender(&self) -> Hash {
        self.sender
    }
    pub fn receiver(&self) -> Hash {
        self.receiver
    }
    pub fn challenge_nonce(&self) -> Hash {
        self.challenge
    }
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
    pub fn decode(raw: &[u8], chain: Hash) -> Result<Self> {
        ensure(
            (13..=12 + FRAME_MAX).contains(&raw.len()),
            "INVALID_ENCODING frame size",
        )?;
        let mut r = Read::new(raw);
        ensure(r.take(8)? == b"RLDSFRM1", "INVALID_ENCODING frame magic")?;
        let len = r.u32()? as usize;
        ensure(len == raw.len() - 12, "INVALID_ENCODING frame length")?;
        let kind = r.u8()?;
        ensure((1..=3).contains(&kind), "UNSUPPORTED_VERSION frame")?;
        ensure(r.fixed::<32>()? == chain, "WRONG_CHAIN frame")?;
        let sender = r.fixed()?;
        let receiver = r.fixed()?;
        let challenge = r.fixed()?;
        let mut nonce = [0; 32];
        let mut packet = None;
        let mut packet_id = None;
        let mut result = None;
        if kind != 1 {
            nonce = r.fixed()?;
            if kind == 2 {
                let len = r.u32()? as usize;
                packet = Some(Packet::decode(r.take(len)?, chain)?);
            } else {
                packet_id = Some(r.fixed()?);
                let code = r.u8()?;
                ensure(code <= 4, "INVALID_ENCODING receipt result")?;
                result = Some(code)
            }
        }
        let end = r.at;
        let label = match kind {
            1 => "CHALLENGE",
            2 => "DELIVER",
            _ => "RECEIPT",
        };
        verify(
            sender,
            &[tag(label), raw[13..end].to_vec()].concat(),
            r.take(64)?,
        )?;
        r.end()?;
        Ok(Self {
            kind,
            sender,
            receiver,
            challenge,
            nonce,
            packet,
            packet_id,
            result,
            raw: raw.to_vec(),
        })
    }
    fn signed(kind: u8, fields: Vec<u8>, key: &SigningKey, chain: Hash) -> Result<Self> {
        let label = match kind {
            1 => "CHALLENGE",
            2 => "DELIVER",
            3 => "RECEIPT",
            _ => return Err("UNSUPPORTED_VERSION frame".into()),
        };
        let signature = key.sign(&[tag(label), fields.clone()].concat());
        let mut raw = b"RLDSFRM1".to_vec();
        raw.extend((1 + fields.len() as u32 + 64).to_be_bytes());
        raw.push(kind);
        raw.extend(fields);
        raw.extend(signature.to_bytes());
        Self::decode(&raw, chain)
    }
    pub fn challenge(chain: Hash, key: &SigningKey, receiver: Hash, nonce: Hash) -> Result<Self> {
        ensure(nonce != [0; 32], "INVALID_ENCODING zero challenge")?;
        Self::signed(
            1,
            [chain, key.verifying_key().to_bytes(), receiver, nonce].concat(),
            key,
            chain,
        )
    }
    pub fn delivery(
        chain: Hash,
        key: &SigningKey,
        receiver: Hash,
        challenge: Hash,
        nonce: Hash,
        packet: &Packet,
    ) -> Result<Self> {
        ensure(nonce != [0; 32], "INVALID_ENCODING zero nonce")?;
        let mut f = [
            chain,
            key.verifying_key().to_bytes(),
            receiver,
            challenge,
            nonce,
        ]
        .concat();
        f.extend((packet.raw.len() as u32).to_be_bytes());
        f.extend(&packet.raw);
        Self::signed(2, f, key, chain)
    }
    pub fn receipt(chain: Hash, key: &SigningKey, delivery: &Self, result: u8) -> Result<Self> {
        ensure(delivery.kind == 2, "INVALID_ENCODING receipt source")?;
        let packet = delivery
            .packet
            .as_ref()
            .ok_or("INVALID_ENCODING missing packet")?;
        let mut f = [
            chain,
            key.verifying_key().to_bytes(),
            peer_id(delivery.sender),
            delivery.challenge,
            delivery.nonce,
            packet.id,
        ]
        .concat();
        f.push(result);
        Self::signed(3, f, key, chain)
    }
    pub fn authenticate_delivery(
        &self,
        expected_sender: Hash,
        receiver: Hash,
        challenge: Hash,
        offline: bool,
    ) -> Result<&Packet> {
        ensure(
            self.kind == 2 && self.sender == expected_sender && self.receiver == receiver,
            "INVALID_CRYPTO delivery roles",
        )?;
        ensure(
            self.nonce != [0; 32]
                && self.challenge == challenge
                && ((offline && challenge == [0; 32]) || (!offline && challenge != [0; 32])),
            "INVALID_CRYPTO session binding",
        )?;
        self.packet
            .as_ref()
            .ok_or_else(|| "INVALID_ENCODING packet".into())
    }
    pub fn authenticate_receipt(&self, delivery: &Self, expected_custodian: Hash) -> Result<u8> {
        ensure(
            self.kind == 3
                && self.sender == expected_custodian
                && self.receiver == peer_id(delivery.sender)
                && self.challenge == delivery.challenge
                && self.nonce == delivery.nonce
                && self.packet_id == delivery.packet.as_ref().map(|p| p.id),
            "INVALID_CRYPTO receipt binding",
        )?;
        self.result.ok_or_else(|| "INVALID_ENCODING receipt".into())
    }
    pub fn discharges(&self, packet: &Packet) -> bool {
        self.kind == 3
            && self.result == Some(1)
            && self.packet_id == Some(packet.id)
            && packet.destination != [0; 32]
            && peer_id(self.sender) == packet.destination
    }
}
