//! Nonmutating native escrow action review. Unsigned plans grant no ledger
//! authority: actual blocks still use complete ordinary actor authentication.
use super::*;
use ed25519_dalek::{Signer, SigningKey};

pub struct Request {
    pub kind: u8,
    pub channel: Hash,
    pub actor: Hash,
    pub inputs: Vec<Vec<u8>>,
    pub fee: u128,
    pub expiry: u128,
    pub nonce: Hash,
    pub certificate: Vec<u8>,
    pub timestamp: u64,
}
pub struct Plan {
    unsigned: Vec<u8>,
    chain: Hash,
    actor: Hash,
    review: Hash,
    pub input_value: u128,
    pub change: u128,
    pub miner: Hash,
    pub principal: [u128; 2],
    pub fee_ranges: [u128; 2],
    pub unused_reserves: [u128; 2],
    pub deadline_height: u128,
    pub deadline_time: u64,
}
impl Plan {
    pub fn unsigned(&self) -> &[u8] {
        &self.unsigned
    }
    pub fn review(&self) -> Hash {
        self.review
    }
    pub fn sign(&self, key: &SigningKey) -> Result<Vec<u8>> {
        require(
            key.verifying_key().to_bytes() == self.actor,
            "INVALID native action spending key",
        )?;
        let message = [ftag("ACTION"), self.unsigned.clone()].concat();
        let mut raw = self.unsigned.clone();
        raw.extend(key.sign(&message).to_bytes());
        self.verify_signed(&raw)?;
        Ok(raw)
    }
    pub fn verify_signed(&self, raw: &[u8]) -> Result<()> {
        require(
            raw.len() == self.unsigned.len() + 64 && raw[..self.unsigned.len()] == self.unsigned,
            "INVALID native action changed authorization",
        )?;
        validate_operation(raw, self.chain)
    }
}
impl Ledger {
    pub fn plan_action(&self, tip: Hash, request: &Request, now: u64) -> Result<Plan> {
        require(
            self.tip.id == tip
                && self.tip.eligible(now)
                && request.timestamp <= now.saturating_add(7200),
            "CLOCK_WAIT or INVALID native action selected context",
        )?;
        self.timing(request.timestamp)?;
        require(
            (1..=32).contains(&request.inputs.len()) && request.certificate.len() <= 252,
            "INVALID native action input/certificate bound",
        )?;
        let mut value = 0u128;
        for input in &request.inputs {
            let coin = self.coins.get(input).ok_or("MISSING native action input")?;
            value = value
                .checked_add(coin.amount)
                .ok_or("INVALID native action input sum")?;
        }
        let change = value
            .checked_sub(request.fee)
            .ok_or("INVALID native action fee budget")?;
        let mut unsigned = vec![request.kind, 0, 1, 0, 1];
        unsigned.extend(self.chain);
        unsigned.extend(request.nonce);
        unsigned.extend(request.channel);
        unsigned.extend(request.actor);
        unsigned.extend(request.fee.to_be_bytes());
        unsigned.extend(change.to_be_bytes());
        unsigned.extend(request.expiry.to_be_bytes());
        unsigned.extend((request.inputs.len() as u16).to_be_bytes());
        for input in &request.inputs {
            unsigned.extend(input);
        }
        unsigned.extend((request.certificate.len() as u16).to_be_bytes());
        unsigned.extend(&request.certificate);
        let action = codec::unsigned_action(&unsigned, self.chain)?;
        let height = self
            .tip
            .height
            .checked_add(1)
            .ok_or("INVALID native action height")?;
        // Full shared ownership, input maturity, fee conservation, window,
        // certificate and escrow execution. Result is discarded, never adopted.
        let mut preview = unsigned.clone();
        preview.extend([0; 64]);
        let (_, book) = self.apply_decoded(
            height,
            request.timestamp,
            request.actor,
            vec![(preview, Operation::Action(action))],
        )?;
        let state = book
            .get(&request.channel)
            .or_else(|| self.book.get(&request.channel))
            .ok_or("MISSING reviewed escrow")?;
        let closing = state.closing.as_ref().ok_or("MISSING reviewed close")?;
        let principal = if closing.principal.is_empty() {
            state.terms.principal
        } else {
            state
                .certificate(self.chain, request.channel, &closing.principal)?
                .balances
        };
        let accounting = state.floors(self.chain, request.channel)?.accounting();
        let review = fh(
            "ACTION-REVIEW",
            &[
                tip.to_vec(),
                request.timestamp.to_be_bytes().to_vec(),
                unsigned.clone(),
            ]
            .concat(),
        );
        Ok(Plan {
            unsigned,
            chain: self.chain,
            actor: request.actor,
            review,
            input_value: value,
            change,
            miner: state.miner,
            principal,
            fee_ranges: accounting.fee_ranges,
            unused_reserves: accounting.unused,
            deadline_height: closing.height + WINDOW_BLOCKS as u128,
            deadline_time: closing.time + WINDOW_SECONDS,
        })
    }
}
