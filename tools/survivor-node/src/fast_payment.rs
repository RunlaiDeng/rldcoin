//! Full invoice/state authorization over a native-derived historical origin.
//! Cryptographic validity is separate from current backing, custody and completion.
use crate::kernel::{fast::FundingOrigin, valid_point, verify, Hash, Result};
use ed25519_dalek::{Signer, SigningKey};
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

/// Fully checked unsigned transition. It grants no signature or payment rights.
#[derive(Clone)]
pub struct Invoice {
    raw: Vec<u8>,
    pub(crate) before: Vec<u8>,
    pub(crate) previous: Hash,
    logical: Hash,
    sequence: u64,
    payer: usize,
    amount: u128,
    fee: u128,
}
impl Invoice {
    /// Construct bytes for explicit owner review. This never signs or reserves.
    pub fn propose(
        origin: &FundingOrigin,
        previous: Option<&Payment>,
        payer: u8,
        value: u128,
        invoice: Hash,
    ) -> Result<Self> {
        ensure(payer < 2, "INVALID fast payer")?;
        let previous = previous
            .map(|p| Payment::verify(origin, p.bytes()))
            .transpose()?;
        let prior = if let Some(p) = &previous {
            origin.verify_certificate(p.after_certificate())?
        } else {
            crate::fast_fee_claims::Claim {
                sequence: 0,
                balances: origin.initial(),
                slots: [0; 2],
            }
        };
        let mut balances = prior.balances;
        balances[payer as usize] = balances[payer as usize]
            .checked_sub(value)
            .ok_or("INVALID fast unfunded payment")?;
        balances[1 - payer as usize] = balances[1 - payer as usize]
            .checked_add(value)
            .ok_or("INVALID fast principal overflow")?;
        let mut slots = prior.slots;
        slots[payer as usize] = slots[payer as usize]
            .checked_add(1)
            .ok_or("INVALID fast slot overflow")?;
        let sequence = prior
            .sequence
            .checked_add(1)
            .ok_or("INVALID fast sequence overflow")?;
        let mut next = origin.context()[..68].to_vec();
        next.extend(sequence.to_be_bytes());
        for v in balances {
            next.extend(v.to_be_bytes());
        }
        for v in slots {
            next.extend(v.to_be_bytes());
        }
        let mut raw = vec![0, 1, 0, 1];
        raw.extend(origin.chain());
        raw.extend(origin.channel());
        raw.extend(origin.context_commitment());
        raw.extend(invoice);
        raw.extend(previous.as_ref().map_or([0; 32], Payment::id));
        raw.push(payer);
        raw.extend(value.to_be_bytes());
        raw.extend(origin.rate(payer as usize)?.to_be_bytes());
        let certificate = previous
            .as_ref()
            .map_or(&[][..], Payment::after_certificate);
        raw.extend((certificate.len() as u16).to_be_bytes());
        raw.extend(certificate);
        raw.extend(next);
        Self::verify(origin, &raw)
    }
    pub fn verify(origin: &FundingOrigin, raw: &[u8]) -> Result<Self> {
        ensure(
            raw.len() == 323 || raw.len() == 575,
            "INVALID fast invoice size",
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
            (n == 0 || n == 252) && raw.len() == 323 + n,
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
        let sequence = prior
            .sequence
            .checked_add(1)
            .ok_or("INVALID fast sequence overflow")?;
        let mut slots = prior.slots;
        slots[payer] = slots[payer]
            .checked_add(1)
            .ok_or("INVALID fast slot overflow")?;
        let at = if payer == 0 { 180 } else { 204 };
        ensure(
            slots[payer] <= u64v(&origin.context()[at..at + 8]),
            "INVALID fast payer slot bound",
        )?;
        let mut balances = prior.balances;
        balances[payer] = balances[payer]
            .checked_sub(value)
            .ok_or("INVALID fast unfunded payment")?;
        balances[1 - payer] = balances[1 - payer]
            .checked_add(value)
            .ok_or("INVALID fast balance overflow")?;
        let mut next = origin.context()[..68].to_vec();
        next.extend(sequence.to_be_bytes());
        for balance in balances {
            next.extend(balance.to_be_bytes());
        }
        for slot in slots {
            next.extend(slot.to_be_bytes());
        }
        ensure(
            raw[199 + n..] == next,
            "INVALID fast exact state transition",
        )?;
        let logical = hash(
            "PAYMENT-ID",
            &[
                origin.context()[4..68].to_vec(),
                vec![payer as u8],
                slots[payer].to_be_bytes().to_vec(),
            ]
            .concat(),
        );
        Ok(Self {
            raw: raw.to_vec(),
            before,
            previous,
            logical,
            sequence,
            payer,
            amount: value,
            fee,
        })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.raw
    }
    pub fn id(&self) -> Hash {
        hash("INVOICE-ID", &self.raw)
    }
    pub fn payer(&self) -> usize {
        self.payer
    }
    pub fn amount(&self) -> u128 {
        self.amount
    }
    pub fn fee(&self) -> u128 {
        self.fee
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn logical_id(&self) -> Hash {
        self.logical
    }
    pub fn unsigned_state(&self) -> &[u8] {
        &self.raw[self.raw.len() - 124..]
    }
    pub fn verify_partial(&self, origin: &FundingOrigin, raw: &[u8]) -> Result<()> {
        ensure(
            self.raw[4..36] == origin.chain()
                && self.raw[36..68] == origin.channel()
                && self.raw[68..100] == origin.context_commitment(),
            "INVALID fast partial native context",
        )?;
        ensure(
            raw.len() == 129 && raw[0] < 2,
            "INVALID fast partial size/role",
        )?;
        let owner = origin.owners()[raw[0] as usize];
        verify(owner, &self.state_message(origin), &raw[1..65])?;
        verify(
            owner,
            &[tag("INVOICE"), self.raw.clone()].concat(),
            &raw[65..],
        )
    }
    fn state_message(&self, origin: &FundingOrigin) -> Vec<u8> {
        [
            b"RLD-FAST-FEE-CLAIM-1/STATE\0".as_slice(),
            &origin.context_commitment(),
            self.unsigned_state(),
        ]
        .concat()
    }
    pub(crate) fn sign(
        &self,
        origin: &FundingOrigin,
        owner: u8,
        key: &SigningKey,
    ) -> Result<Vec<u8>> {
        ensure(
            owner < 2 && key.verifying_key().to_bytes() == origin.owners()[owner as usize],
            "INVALID fast signing owner",
        )?;
        let mut raw = vec![owner];
        raw.extend(key.sign(&self.state_message(origin)).to_bytes());
        raw.extend(
            key.sign(&[tag("INVOICE"), self.raw.clone()].concat())
                .to_bytes(),
        );
        self.verify_partial(origin, &raw)?;
        Ok(raw)
    }
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
        let end = raw.len() - 256;
        let invoice = Invoice::verify(origin, &raw[..end])?;
        let mut after = invoice.unsigned_state().to_vec();
        after.extend(&raw[end..end + 128]);
        origin.verify_certificate(&after)?;
        let message = [tag("INVOICE"), invoice.raw.clone()].concat();
        for i in 0..2 {
            verify(
                origin.owners()[i],
                &message,
                &raw[end + 128 + i * 64..end + 192 + i * 64],
            )?;
        }
        Ok(Self {
            raw: raw.to_vec(),
            before: invoice.before,
            after,
            previous: invoice.previous,
            id: hash("RECEIPT", raw),
            logical: invoice.logical,
            sequence: invoice.sequence,
            fee: invoice.fee,
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
