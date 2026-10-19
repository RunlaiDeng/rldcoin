//! Exact existing kind1 review and independent owner signatures, never adoption.
use super::*;
use ed25519_dalek::{Signer, SigningKey};
pub struct OpeningTerms {
    pub nonce: Hash,
    pub owners: [Hash; 2],
    pub principal: [u128; 2],
    pub limits: [u64; 2],
    pub rates: [u128; 2],
    pub fees: [u128; 2],
    pub expiry: u128,
    pub inputs: [Vec<Vec<u8>>; 2],
}
pub struct OpeningPlan {
    unsigned: Vec<u8>,
    terms: codec::Open,
    chain: Hash,
    tip: Hash,
    timestamp: u64,
    pub input_values: [u128; 2],
}
pub fn proposal_inputs(raw: &[u8], owner: u8, chain: Hash) -> Result<Vec<Vec<u8>>> {
    require(owner < 2, "INVALID opening own inputs")?;
    Ok(codec::unsigned_open(raw, chain)?.inputs[usize::from(owner)].clone())
}
pub fn proposal_id(raw: &[u8], chain: Hash) -> Result<Hash> {
    codec::unsigned_open(raw, chain)?;
    Ok(fh("OPEN-PROPOSAL", raw))
}
pub fn verify_partial(raw: &[u8], partial: &[u8], chain: Hash) -> Result<u8> {
    let terms = codec::unsigned_open(raw, chain)?;
    require(
        partial.len() == 65 && partial[0] < 2,
        "INVALID opening partial shape",
    )?;
    verify(
        terms.owners[usize::from(partial[0])],
        &[ftag("OPEN"), raw[1..].to_vec()].concat(),
        &partial[1..],
    )?;
    Ok(partial[0])
}
impl OpeningPlan {
    pub fn selected_tip(&self) -> Hash {
        self.tip
    }
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
    pub fn unsigned(&self) -> &[u8] {
        &self.unsigned
    }
    pub fn proposal(&self) -> Hash {
        fh("OPEN-PROPOSAL", &self.unsigned)
    }
    pub fn review(&self, owner: u8) -> Result<Hash> {
        require(owner < 2, "INVALID opening reviewing owner")?;
        Ok(fh(
            "OPEN-REVIEW",
            &[
                self.tip.to_vec(),
                self.timestamp.to_be_bytes().to_vec(),
                vec![owner],
                self.unsigned.clone(),
            ]
            .concat(),
        ))
    }
    pub fn owners(&self) -> [Hash; 2] {
        self.terms.owners
    }
    pub fn principal(&self) -> [u128; 2] {
        self.terms.principal
    }
    pub fn limits(&self) -> [u64; 2] {
        self.terms.limits
    }
    pub fn rates(&self) -> [u128; 2] {
        self.terms.rates
    }
    pub fn fees(&self) -> [u128; 2] {
        self.terms.fees
    }
    pub fn change(&self) -> [u128; 2] {
        self.terms.change
    }
    pub fn inputs(&self) -> &[Vec<Vec<u8>>; 2] {
        &self.terms.inputs
    }
    pub fn expiry(&self) -> u128 {
        self.terms.expiry
    }
    pub fn sign(&self, owner: u8, key: &SigningKey) -> Result<Vec<u8>> {
        require(
            owner < 2 && key.verifying_key().to_bytes() == self.terms.owners[usize::from(owner)],
            "INVALID opening spending key",
        )?;
        let mut partial = vec![owner];
        partial.extend(
            key.sign(&[ftag("OPEN"), self.unsigned[1..].to_vec()].concat())
                .to_bytes(),
        );
        self.verify_own(owner, &partial)?;
        Ok(partial)
    }
    pub fn verify_own(&self, owner: u8, partial: &[u8]) -> Result<()> {
        require(
            verify_partial(&self.unsigned, partial, self.chain)? == owner,
            "INVALID opening partial owner",
        )
    }
    pub fn combine(&self, a: &[u8], b: &[u8]) -> Result<Vec<u8>> {
        let ai = verify_partial(&self.unsigned, a, self.chain)?;
        let bi = verify_partial(&self.unsigned, b, self.chain)?;
        require(ai != bi, "INVALID duplicate opening owner")?;
        let mut raw = self.unsigned.clone();
        if ai == 0 {
            raw.extend(&a[1..]);
            raw.extend(&b[1..]);
        } else {
            raw.extend(&b[1..]);
            raw.extend(&a[1..]);
        }
        validate_operation(&raw, self.chain)?;
        Ok(raw)
    }
}
impl Ledger {
    pub fn plan_opening(
        &self,
        tip: Hash,
        raw: &[u8],
        timestamp: u64,
        now: u64,
    ) -> Result<OpeningPlan> {
        require(
            self.tip.id == tip && self.tip.eligible(now) && timestamp <= now.saturating_add(7200),
            "CLOCK_WAIT or INVALID opening context",
        )?;
        self.timing(timestamp)?;
        let terms = codec::unsigned_open(raw, self.chain)?;
        let mut input_values = [0u128; 2];
        for (i, value) in input_values.iter_mut().enumerate() {
            for input in &terms.inputs[i] {
                *value = value
                    .checked_add(self.coins.get(input).ok_or("MISSING opening input")?.amount)
                    .ok_or("INVALID opening input sum")?;
            }
        }
        let height = self
            .tip
            .height
            .checked_add(1)
            .ok_or("INVALID opening height")?;
        let mut preview = raw.to_vec();
        preview.extend([0; 128]);
        self.apply_decoded(
            height,
            timestamp,
            terms.owners[0],
            vec![(preview, Operation::Open(terms.clone()))],
        )?;
        Ok(OpeningPlan {
            unsigned: raw.to_vec(),
            terms,
            chain: self.chain,
            tip,
            timestamp,
            input_values,
        })
    }
    pub fn propose_opening(
        &self,
        tip: Hash,
        terms: &OpeningTerms,
        timestamp: u64,
        now: u64,
    ) -> Result<OpeningPlan> {
        require(
            terms
                .inputs
                .iter()
                .all(|v| (1..=32).contains(&v.len()) && v.iter().all(|i| i.len() == 34)),
            "INVALID opening input bound",
        )?;
        let mut raw = vec![1, 0, 1, 0, 1];
        raw.extend(self.chain);
        raw.extend(terms.nonce);
        for owner in terms.owners {
            raw.extend(owner);
        }
        for value in terms.principal {
            raw.extend(value.to_be_bytes());
        }
        for i in 0..2 {
            raw.extend(terms.limits[i].to_be_bytes());
            raw.extend(terms.rates[i].to_be_bytes());
        }
        for value in terms.fees {
            raw.extend(value.to_be_bytes());
        }
        for i in 0..2 {
            let value = terms.inputs[i].iter().try_fold(0u128, |v, input| {
                v.checked_add(self.coins.get(input).ok_or("MISSING opening input")?.amount)
                    .ok_or("INVALID opening input sum")
            })?;
            let debit = terms.principal[i]
                .checked_add(
                    u128::from(terms.limits[i])
                        .checked_mul(terms.rates[i])
                        .ok_or("INVALID opening reserve")?,
                )
                .and_then(|v| v.checked_add(terms.fees[i]))
                .ok_or("INVALID opening budget")?;
            let change = value.checked_sub(debit).ok_or("INVALID opening funds")?;
            raw.extend(change.to_be_bytes());
        }
        raw.extend(terms.expiry.to_be_bytes());
        for inputs in &terms.inputs {
            raw.extend((inputs.len() as u16).to_be_bytes());
            for input in inputs {
                raw.extend(input);
            }
        }
        self.plan_opening(tip, &raw, timestamp, now)
    }
}
