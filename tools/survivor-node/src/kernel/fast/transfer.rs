//! Nonmutating ordinary-transfer review over the actual fast native ledger.
use super::*;
use ed25519_dalek::{Signer, SigningKey};

pub struct TransferRequest {
    pub owner: Hash,
    pub inputs: Vec<Vec<u8>>,
    pub outputs: Vec<(Hash, u128)>,
    pub fee: u128,
    pub expiry: u128,
    pub timestamp: u64,
}
pub struct TransferPlan {
    unsigned: Vec<u8>,
    chain: Hash,
    owner: Hash,
    review: Hash,
    pub transaction: Hash,
    pub input_value: u128,
}
impl TransferPlan {
    pub fn unsigned(&self) -> &[u8] {
        &self.unsigned
    }
    pub fn review(&self) -> Hash {
        self.review
    }
    pub fn sign(&self, key: &SigningKey) -> Result<Vec<u8>> {
        require(
            key.verifying_key().to_bytes() == self.owner,
            "INVALID native transfer spending key",
        )?;
        let mut raw = self.unsigned.clone();
        raw.extend(
            key.sign(&[tag("TRANSFER"), self.unsigned[1..].to_vec()].concat())
                .to_bytes(),
        );
        self.verify_signed(&raw)?;
        Ok(raw)
    }
    pub fn verify_signed(&self, raw: &[u8]) -> Result<()> {
        require(
            raw.len() == self.unsigned.len() + 64 && raw[..self.unsigned.len()] == self.unsigned,
            "INVALID native transfer changed authorization",
        )?;
        validate_operation(raw, self.chain)
    }
}
impl Ledger {
    pub fn plan_transfer(
        &self,
        tip: Hash,
        request: &TransferRequest,
        now: u64,
    ) -> Result<TransferPlan> {
        require(
            self.tip.id == tip
                && self.tip.eligible(now)
                && request.timestamp <= now.saturating_add(7200),
            "CLOCK_WAIT or INVALID native transfer selected context",
        )?;
        self.timing(request.timestamp)?;
        require(
            (1..=32).contains(&request.inputs.len())
                && (1..=8).contains(&request.outputs.len())
                && request.inputs.iter().all(|input| input.len() == 34),
            "INVALID native transfer shape",
        )?;
        let mut u = 1u16.to_be_bytes().to_vec();
        u.extend(self.chain);
        u.extend(request.owner);
        u.extend((request.inputs.len() as u16).to_be_bytes());
        for input in &request.inputs {
            u.extend(input);
        }
        u.extend((request.outputs.len() as u16).to_be_bytes());
        for (owner, amount) in &request.outputs {
            u.extend(owner);
            u.extend(amount.to_be_bytes());
        }
        u.extend(request.fee.to_be_bytes());
        u.extend(request.expiry.to_be_bytes());
        let tx = decode_unsigned(&u, self.chain)?;
        let transaction = tx.id;
        let input_value = tx.inputs.iter().try_fold(0u128, |value, input| {
            value
                .checked_add(
                    self.coins
                        .get(input)
                        .ok_or("MISSING native transfer input")?
                        .amount,
                )
                .ok_or("INVALID native transfer input sum")
        })?;
        let mut unsigned = vec![0];
        unsigned.extend(u);
        let mut preview = unsigned.clone();
        preview.extend([0; 64]);
        let height = self
            .tip
            .height
            .checked_add(1)
            .ok_or("INVALID native transfer height")?;
        // The result is discarded. Only normal signed decode admits ledger bytes.
        self.apply_decoded(
            height,
            request.timestamp,
            request.owner,
            vec![(preview, Operation::Ordinary(tx))],
        )?;
        let review = fh(
            "TRANSFER-REVIEW",
            &[
                tip.to_vec(),
                request.timestamp.to_be_bytes().to_vec(),
                unsigned.clone(),
            ]
            .concat(),
        );
        Ok(TransferPlan {
            unsigned,
            chain: self.chain,
            owner: request.owner,
            review,
            transaction,
            input_value,
        })
    }
}
