//! Full invoice/state authorization over a native-derived historical origin.
//! Cryptographic validity is separate from current backing, custody and completion.
use crate::kernel::{fast::FundingOrigin, valid_point, verify, Hash, Result};
use sha2::{Digest, Sha256};
pub(crate) fn ensure(ok: bool, why: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(why.into())
    }
}
pub(crate) fn tag(label: &str) -> Vec<u8> {
    [b"RLD-FAST-PAYMENT-1/".as_slice(), label.as_bytes(), &[0]].concat()
}
pub(crate) fn hash(label: &str, raw: &[u8]) -> Hash {
    Sha256::digest([tag(label), raw.to_vec()].concat()).into()
}
fn u64v(raw: &[u8]) -> u64 {
    u64::from_be_bytes(raw.try_into().unwrap())
}
fn amount(raw: &[u8]) -> u128 {
    u128::from_be_bytes(raw.try_into().unwrap())
}

#[derive(Clone)]
pub struct Payment {
    pub(crate) raw: Vec<u8>,
    pub(crate) before: Vec<u8>,
    pub(crate) after: Vec<u8>,
    pub(crate) previous: Hash,
    pub(crate) id: Hash,
    pub(crate) logical: Hash,
    pub(crate) sequence: u64,
    pub(crate) fee: u128,
}
impl Payment {
    pub fn verify(origin: &FundingOrigin, raw: &[u8]) -> Result<Self> {
        ensure(
            raw.len() == 579 || raw.len() == 831,
            "INVALID fast payment size",
        )?;
        ensure(raw[..4] == [0, 1, 0, 1], "UNSUPPORTED fast payment version")?;
        ensure(
            raw[4..36] == origin.chain()
                && raw[36..68] == origin.channel()
                && raw[68..100] == origin.context_commitment(),
            "INVALID fast payment native context",
        )?;
        ensure(raw[100..132] != [0; 32], "INVALID fast invoice")?;
        let previous: Hash = raw[132..164].try_into().unwrap();
        let payer = raw[164] as usize;
        ensure(payer < 2, "INVALID fast payer")?;
        let value = amount(&raw[165..181]);
        let fee = amount(&raw[181..197]);
        ensure(
            value > 0 && fee == origin.rate(payer)?,
            "INVALID fast amount/fee",
        )?;
        let n = u16::from_be_bytes(raw[197..199].try_into().unwrap()) as usize;
        ensure(
            (n == 0 || n == 252) && raw.len() == 579 + n,
            "INVALID fast prior certificate size",
        )?;
        let before = raw[199..199 + n].to_vec();
        let prior = if n == 0 {
            ensure(previous == [0; 32], "INVALID fast initial receipt link")?;
            crate::fast_fee_claims::Claim {
                sequence: 0,
                balances: origin.initial(),
                slots: [0; 2],
            }
        } else {
            ensure(previous != [0; 32], "INVALID fast prior receipt link")?;
            let claim = origin.verify_certificate(&before)?;
            ensure(
                claim.sequence > 0,
                "INVALID fast noncanonical initial certificate",
            )?;
            claim
        };
        let end = 323 + n;
        let mut after = raw[199 + n..end].to_vec();
        after.extend(&raw[end..end + 128]);
        let next = origin.verify_certificate(&after)?;
        ensure(
            prior.sequence.checked_add(1) == Some(next.sequence),
            "INVALID fast skipped sequence",
        )?;
        let mut slots = prior.slots;
        slots[payer] = slots[payer]
            .checked_add(1)
            .ok_or("INVALID fast slot overflow")?;
        ensure(next.slots == slots, "INVALID fast payer slot transition")?;
        let mut balances = prior.balances;
        balances[payer] = balances[payer]
            .checked_sub(value)
            .ok_or("INVALID fast unfunded payment")?;
        balances[1 - payer] = balances[1 - payer]
            .checked_add(value)
            .ok_or("INVALID fast balance overflow")?;
        ensure(
            next.balances == balances,
            "INVALID fast principal transition",
        )?;
        let message = [tag("INVOICE"), raw[..end].to_vec()].concat();
        let owners = origin.owners();
        verify(owners[0], &message, &raw[end + 128..end + 192])?;
        verify(owners[1], &message, &raw[end + 192..])?;
        let logical = hash(
            "PAYMENT-ID",
            &[
                origin.context()[4..68].to_vec(),
                vec![payer as u8],
                next.slots[payer].to_be_bytes().to_vec(),
            ]
            .concat(),
        );
        Ok(Self {
            raw: raw.to_vec(),
            before,
            after,
            previous,
            id: hash("RECEIPT", raw),
            logical,
            sequence: next.sequence,
            fee,
        })
    }
    pub fn combine(origin: &FundingOrigin, invoice: &[u8], a: &[u8], b: &[u8]) -> Result<Self> {
        ensure(
            (invoice.len() == 323 || invoice.len() == 575)
                && a.len() == 129
                && b.len() == 129
                && a[0] == 0
                && b[0] == 1,
            "INVALID fast partial roles/length",
        )?;
        let raw = [invoice, &a[1..65], &b[1..65], &a[65..], &b[65..]].concat();
        Self::verify(origin, &raw)
    }
    pub fn bytes(&self) -> &[u8] {
        &self.raw
    }
    pub fn id(&self) -> Hash {
        self.id
    }
    pub fn logical_id(&self) -> Hash {
        self.logical
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn fee(&self) -> u128 {
        self.fee
    }
    pub fn after_certificate(&self) -> &[u8] {
        &self.after
    }
}

#[derive(Clone)]
pub struct Delegation {
    pub(crate) raw: Vec<u8>,
    pub(crate) id: Hash,
    pub(crate) retainer: Hash,
}
impl Delegation {
    pub fn unsigned(origin: &FundingOrigin, retainer: Hash) -> Result<Vec<u8>> {
        ensure(
            valid_point(retainer)
                && !origin.owners().contains(&retainer)
                && retainer != origin.miner(),
            "INVALID fast retainer role",
        )?;
        let mut raw = vec![0, 1, 0, 1];
        raw.extend(origin.chain());
        raw.extend(origin.channel());
        raw.extend(origin.context_commitment());
        raw.extend(origin.miner());
        raw.extend(retainer);
        raw.extend(7200u64.to_be_bytes());
        raw.extend(3600u64.to_be_bytes());
        raw.push(1);
        Ok(raw)
    }
    pub fn verify(origin: &FundingOrigin, raw: &[u8]) -> Result<Self> {
        ensure(raw.len() == 245, "INVALID fast delegation length")?;
        let retainer = raw[132..164].try_into().unwrap();
        ensure(
            raw[..181] == Self::unsigned(origin, retainer)?,
            "INVALID fast delegation context/policy",
        )?;
        verify(
            origin.miner(),
            &[tag("DELEGATION"), raw[..181].to_vec()].concat(),
            &raw[181..],
        )?;
        Ok(Self {
            raw: raw.to_vec(),
            id: hash("DELEGATION-ID", raw),
            retainer,
        })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.raw
    }
    pub fn id(&self) -> Hash {
        self.id
    }
    pub fn retainer(&self) -> Hash {
        self.retainer
    }
}

#[derive(Clone)]
pub struct Acknowledgment {
    pub(crate) raw: Vec<u8>,
    pub(crate) time: u64,
    pub(crate) native: Hash,
    pub(crate) prepared: Hash,
}
impl Acknowledgment {
    pub(crate) fn unsigned(
        origin: &FundingOrigin,
        delegation: &Delegation,
        payment: &Payment,
        native: Hash,
        prepared: Hash,
        now: u64,
    ) -> Vec<u8> {
        let mut raw = vec![0, 1, 0, 1];
        raw.extend(origin.chain());
        raw.extend(origin.channel());
        raw.extend(origin.context_commitment());
        raw.extend(delegation.id);
        raw.extend(payment.id);
        raw.extend(payment.logical);
        raw.extend(native);
        raw.extend(prepared);
        raw.extend(payment.sequence.to_be_bytes());
        raw.extend(now.to_be_bytes());
        raw
    }
    pub fn verify(
        origin: &FundingOrigin,
        delegation: &Delegation,
        payment: &Payment,
        raw: &[u8],
    ) -> Result<Self> {
        ensure(raw.len() == 340, "INVALID fast acknowledgment length")?;
        let native = raw[196..228].try_into().unwrap();
        let prepared = raw[228..260].try_into().unwrap();
        let time = u64v(&raw[268..276]);
        ensure(
            raw[..276] == Self::unsigned(origin, delegation, payment, native, prepared, time),
            "INVALID fast acknowledgment binding",
        )?;
        verify(
            delegation.retainer,
            &[tag("ACK"), raw[..276].to_vec()].concat(),
            &raw[276..],
        )?;
        Ok(Self {
            raw: raw.to_vec(),
            time,
            native,
            prepared,
        })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.raw
    }
    pub fn prepared_head(&self) -> Hash {
        self.prepared
    }
    pub fn observed_native_tip(&self) -> Hash {
        self.native
    }
    pub fn observed_at(&self) -> u64 {
        self.time
    }
}
pub fn review_digest(native: Hash, prepared: Hash, receipt: Hash, delegation: Hash) -> Hash {
    hash("REVIEW", &[native, prepared, receipt, delegation].concat())
}
