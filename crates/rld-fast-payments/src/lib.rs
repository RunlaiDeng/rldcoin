//! Reference model for a *candidate* two-party fast-payment protocol.
//!
//! No deployed RLD ledger supports channel escrow or these settlement rules.
//! In particular, a valid [`PaymentReceipt`] is not a spendable mainnet coin.
//! Production use requires a separately adopted consensus upgrade, an
//! independently verified funding source, durable wallet state and monitoring.

use rld_core::{
    sign_bytes, validate_ed25519_public_key, verify_bytes, AdmissionHash32 as Hash, Amount,
    TOTAL_SUPPLY_RUNLAI,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub mod successor;
pub mod wallet;

pub type Result<T> = std::result::Result<T, String>;
/// 2,016 expected ten-minute blocks, about two weeks on a healthy Earth chain.
/// This is a candidate security parameter, not a wall-clock guarantee.
pub const CONTEST_BLOCKS: u128 = 2016;

fn require(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn hash(bytes: &[u8]) -> Hash {
    Hash(Sha256::digest(bytes).into())
}

fn key_bytes(key: &str) -> Result<[u8; 32]> {
    validate_ed25519_public_key(key)?;
    hex::decode(key)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "public key length".into())
}

/// Identifies the single output replaced by a future channel escrow output.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct FundingOutpoint {
    pub transaction: Hash,
    pub index: u16,
}

/// The exact on-chain lock that a future consensus implementation must prove.
/// A v1 single-key UTXO is not a valid instance of this escrow.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Funding {
    pub chain_id: Hash,
    pub outpoint: FundingOutpoint,
    pub party_a: String,
    pub party_b: String,
    pub capacity: Amount,
    /// Reserved for the final settlement transaction; challenge fees need
    /// separate funding and are not silently subtracted from payments.
    pub close_fee: Amount,
}

impl Funding {
    pub fn validate(&self) -> Result<()> {
        require(
            !self.chain_id.is_zero() && !self.outpoint.transaction.is_zero(),
            "missing chain or funding outpoint",
        )?;
        key_bytes(&self.party_a)?;
        key_bytes(&self.party_b)?;
        require(self.party_a != self.party_b, "channel parties must differ")?;
        require(
            self.capacity.0 <= TOTAL_SUPPLY_RUNLAI
                && self.close_fee.0 > 0
                && self.close_fee.0 < self.capacity.0,
            "invalid channel capacity or close fee",
        )
    }

    pub fn spendable(&self) -> Result<Amount> {
        self.validate()?;
        self.capacity
            .checked_sub(self.close_fee)
            .map_err(|e| e.to_string())
    }

    pub fn id(&self) -> Result<Hash> {
        self.validate()?;
        let mut b = b"RLD-EARTH-FAST-CHANNEL-ID\0".to_vec();
        b.extend(self.chain_id.0);
        b.extend(self.outpoint.transaction.0);
        b.extend(self.outpoint.index.to_be_bytes());
        b.extend(key_bytes(&self.party_a)?);
        b.extend(key_bytes(&self.party_b)?);
        b.extend(self.capacity.0.to_be_bytes());
        b.extend(self.close_fee.0.to_be_bytes());
        Ok(hash(&b))
    }
}

/// Both signatures bind the network, escrow, sequence and complete allocation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChannelState {
    pub channel_id: Hash,
    pub sequence: u64,
    pub payment_id: Hash,
    pub balance_a: Amount,
    pub balance_b: Amount,
}

impl ChannelState {
    pub fn initial(funding: &Funding) -> Result<Self> {
        Ok(Self {
            channel_id: funding.id()?,
            sequence: 0,
            payment_id: Hash::ZERO,
            balance_a: funding.spendable()?,
            balance_b: Amount::ZERO,
        })
    }

    pub fn validate(&self, funding: &Funding) -> Result<()> {
        require(self.channel_id == funding.id()?, "wrong channel")?;
        require(
            (self.sequence == 0 && self.payment_id.is_zero())
                || (self.sequence > 0 && !self.payment_id.is_zero()),
            "invalid payment ID for sequence",
        )?;
        require(
            self.balance_a
                .checked_add(self.balance_b)
                .map_err(|e| e.to_string())?
                == funding.spendable()?,
            "channel balances do not conserve funding",
        )?;
        if self.sequence == 0 {
            require(
                self.balance_a == funding.spendable()? && self.balance_b.is_zero(),
                "invalid initial allocation",
            )?;
        }
        Ok(())
    }

    pub fn signing_bytes(&self, funding: &Funding) -> Result<Vec<u8>> {
        self.validate(funding)?;
        let mut b = b"RLD-EARTH-FAST-CHANNEL-STATE\0".to_vec();
        b.extend(self.channel_id.0);
        b.extend(self.sequence.to_be_bytes());
        b.extend(self.payment_id.0);
        b.extend(self.balance_a.0.to_be_bytes());
        b.extend(self.balance_b.0.to_be_bytes());
        Ok(b)
    }

    /// Builds an unsigned proposal; no balance changes until both parties sign.
    pub fn propose_payment(
        &self,
        funding: &Funding,
        sender: &str,
        amount: Amount,
        payment_id: Hash,
    ) -> Result<Self> {
        self.validate(funding)?;
        require(!amount.is_zero() && !payment_id.is_zero(), "empty payment")?;
        let sequence = self.sequence.checked_add(1).ok_or("sequence exhausted")?;
        let (balance_a, balance_b) = if sender == funding.party_a {
            (
                self.balance_a
                    .checked_sub(amount)
                    .map_err(|e| e.to_string())?,
                self.balance_b
                    .checked_add(amount)
                    .map_err(|e| e.to_string())?,
            )
        } else if sender == funding.party_b {
            (
                self.balance_a
                    .checked_add(amount)
                    .map_err(|e| e.to_string())?,
                self.balance_b
                    .checked_sub(amount)
                    .map_err(|e| e.to_string())?,
            )
        } else {
            return Err("sender is not a channel party".into());
        };
        let next = Self {
            channel_id: self.channel_id,
            sequence,
            payment_id,
            balance_a,
            balance_b,
        };
        next.validate(funding)?;
        Ok(next)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedState {
    pub state: ChannelState,
    pub signature_a: String,
    pub signature_b: String,
}

impl SignedState {
    pub fn verify(&self, funding: &Funding) -> Result<()> {
        let message = self.state.signing_bytes(funding)?;
        verify_bytes(&funding.party_a, &message, &self.signature_a)?;
        verify_bytes(&funding.party_b, &message, &self.signature_b)
    }
}

/// A merchant can check the requested payment against the preceding and new
/// fully signed allocations. This is only a conditional candidate receipt:
/// without confirmed consensus escrow and a timely contest path it is not paid.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PaymentReceipt {
    pub previous: SignedState,
    pub updated: SignedState,
    pub sender: String,
    pub amount: Amount,
    pub payment_id: Hash,
}

/// First signed message in a direct payment exchange. The receiver must check
/// its own latest state before co-signing; a payer signature alone is not paid.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PaymentOffer {
    pub previous: SignedState,
    pub proposed: ChannelState,
    pub sender: String,
    pub amount: Amount,
    pub payment_id: Hash,
    pub sender_signature: String,
}

impl PaymentOffer {
    pub fn new(
        funding: &Funding,
        previous: SignedState,
        sender: String,
        sender_secret: &str,
        amount: Amount,
        payment_id: Hash,
    ) -> Result<Self> {
        previous.verify(funding)?;
        let proposed = previous
            .state
            .propose_payment(funding, &sender, amount, payment_id)?;
        let sender_signature = sign_bytes(sender_secret, &proposed.signing_bytes(funding)?)?;
        let offer = Self {
            previous,
            proposed,
            sender,
            amount,
            payment_id,
            sender_signature,
        };
        offer.verify(funding)?;
        Ok(offer)
    }

    pub fn verify(&self, funding: &Funding) -> Result<()> {
        self.previous.verify(funding)?;
        require(
            self.proposed
                == self.previous.state.propose_payment(
                    funding,
                    &self.sender,
                    self.amount,
                    self.payment_id,
                )?,
            "offer is not an exact one-step payment",
        )?;
        verify_bytes(
            &self.sender,
            &self.proposed.signing_bytes(funding)?,
            &self.sender_signature,
        )
    }

    pub fn cosign(&self, funding: &Funding, receiver_secret: &str) -> Result<PaymentReceipt> {
        self.verify(funding)?;
        let receiver = if self.sender == funding.party_a {
            &funding.party_b
        } else {
            &funding.party_a
        };
        let receiver_signature =
            sign_bytes(receiver_secret, &self.proposed.signing_bytes(funding)?)?;
        verify_bytes(
            receiver,
            &self.proposed.signing_bytes(funding)?,
            &receiver_signature,
        )?;
        let (signature_a, signature_b) = if self.sender == funding.party_a {
            (self.sender_signature.clone(), receiver_signature)
        } else {
            (receiver_signature, self.sender_signature.clone())
        };
        let receipt = PaymentReceipt {
            previous: self.previous.clone(),
            updated: SignedState {
                state: self.proposed.clone(),
                signature_a,
                signature_b,
            },
            sender: self.sender.clone(),
            amount: self.amount,
            payment_id: self.payment_id,
        };
        receipt.verify(funding, receiver)?;
        Ok(receipt)
    }
}

impl PaymentReceipt {
    pub fn verify(&self, funding: &Funding, expected_receiver: &str) -> Result<()> {
        self.previous.verify(funding)?;
        self.updated.verify(funding)?;
        require(
            !self.payment_id.is_zero() && self.payment_id == self.updated.state.payment_id,
            "wrong payment ID",
        )?;
        require(
            (self.sender == funding.party_a && expected_receiver == funding.party_b)
                || (self.sender == funding.party_b && expected_receiver == funding.party_a),
            "wrong sender or receiver",
        )?;
        require(
            self.updated.state
                == self.previous.state.propose_payment(
                    funding,
                    &self.sender,
                    self.amount,
                    self.payment_id,
                )?,
            "not the requested one-step payment",
        )
    }
}

/// Tracks one recipient's accepted state and invoice IDs in memory. A real
/// wallet must atomically persist this state and its signing decisions before
/// returning a receipt; this reference tracker is not crash-safe.
#[derive(Clone, Debug)]
pub struct RecipientTracker {
    funding: Funding,
    receiver: String,
    latest: SignedState,
    used_payment_ids: BTreeSet<Hash>,
}

impl RecipientTracker {
    pub fn new(funding: Funding, receiver: String, initial: SignedState) -> Result<Self> {
        require(
            receiver == funding.party_a || receiver == funding.party_b,
            "receiver is not a channel party",
        )?;
        initial.verify(&funding)?;
        require(
            initial.state.sequence == 0,
            "tracker must start from opening state",
        )?;
        Ok(Self {
            funding,
            receiver,
            latest: initial,
            used_payment_ids: BTreeSet::new(),
        })
    }

    pub fn latest(&self) -> &SignedState {
        &self.latest
    }

    pub fn apply_receipt(&mut self, receipt: PaymentReceipt) -> Result<()> {
        require(
            receipt.previous == self.latest,
            "receipt does not extend latest local state",
        )?;
        require(
            !self.used_payment_ids.contains(&receipt.payment_id),
            "payment ID already accepted",
        )?;
        receipt.verify(&self.funding, &self.receiver)?;
        self.used_payment_ids.insert(receipt.payment_id);
        self.latest = receipt.updated;
        Ok(())
    }
}

/// A future consensus adapter must authenticate an escrow output against the
/// selected chain, verify adequate confirmation depth, and reject reorged or
/// already-spent funding. This crate deliberately provides no mainnet adapter.
pub trait ConfirmedEscrow {
    fn verify_confirmed_escrow(&self, funding: &Funding) -> Result<()>;
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum Phase {
    Open,
    Closing {
        best: SignedState,
        #[serde(with = "rld_pow::decimal")]
        close_height: u128,
        #[serde(with = "rld_pow::decimal")]
        deadline_height: u128,
    },
    Settled,
}

#[derive(Clone, Debug)]
struct Channel {
    funding: Funding,
    phase: Phase,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payout {
    pub party_a: String,
    pub amount_a: Amount,
    pub party_b: String,
    pub amount_b: Amount,
    pub miner_fee: Amount,
}

/// In-memory reference state machine for a proposed consensus rule. It has no
/// persistence, UTXO integration or production activation path.
#[derive(Clone, Debug, Default)]
pub struct Registry {
    channels: BTreeMap<Hash, Channel>,
    funding_outpoints: BTreeSet<FundingOutpoint>,
}

impl Registry {
    pub fn open<V: ConfirmedEscrow>(
        &mut self,
        verifier: &V,
        funding: Funding,
        initial: SignedState,
    ) -> Result<Hash> {
        initial.verify(&funding)?;
        require(initial.state.sequence == 0, "opening state must be initial")?;
        verifier.verify_confirmed_escrow(&funding)?;
        let id = funding.id()?;
        require(
            !self.funding_outpoints.contains(&funding.outpoint) && !self.channels.contains_key(&id),
            "funding already locked",
        )?;
        self.funding_outpoints.insert(funding.outpoint.clone());
        self.channels.insert(
            id,
            Channel {
                funding,
                phase: Phase::Open,
            },
        );
        Ok(id)
    }

    pub fn phase(&self, id: Hash) -> Option<&Phase> {
        self.channels.get(&id).map(|c| &c.phase)
    }

    pub fn request_close(&mut self, id: Hash, state: SignedState, height: u128) -> Result<()> {
        let channel = self.channels.get_mut(&id).ok_or("unknown channel")?;
        require(channel.phase == Phase::Open, "channel is not open")?;
        state.verify(&channel.funding)?;
        let deadline_height = height
            .checked_add(CONTEST_BLOCKS)
            .ok_or("contest height overflow")?;
        channel.phase = Phase::Closing {
            best: state,
            close_height: height,
            deadline_height,
        };
        Ok(())
    }

    pub fn challenge(&mut self, id: Hash, state: SignedState, height: u128) -> Result<()> {
        let channel = self.channels.get_mut(&id).ok_or("unknown channel")?;
        state.verify(&channel.funding)?;
        match &mut channel.phase {
            Phase::Closing {
                best,
                close_height,
                deadline_height,
            } => {
                require(
                    height >= *close_height && height <= *deadline_height,
                    "challenge outside contest window",
                )?;
                require(
                    state.state.sequence > best.state.sequence,
                    "challenge must have a newer sequence",
                )?;
                *best = state;
                Ok(())
            }
            _ => Err("channel is not closing".into()),
        }
    }

    pub fn finalize(&mut self, id: Hash, height: u128) -> Result<Payout> {
        let channel = self.channels.get_mut(&id).ok_or("unknown channel")?;
        let (best, deadline_height) = match &channel.phase {
            Phase::Closing {
                best,
                deadline_height,
                ..
            } => (best, *deadline_height),
            _ => return Err("channel is not closing".into()),
        };
        require(height > deadline_height, "contest window remains open")?;
        let payout = Payout {
            party_a: channel.funding.party_a.clone(),
            amount_a: best.state.balance_a,
            party_b: channel.funding.party_b.clone(),
            amount_b: best.state.balance_b,
            miner_fee: channel.funding.close_fee,
        };
        require(
            payout
                .amount_a
                .checked_add(payout.amount_b)
                .and_then(|v| v.checked_add(payout.miner_fee))
                .map_err(|e| e.to_string())?
                == channel.funding.capacity,
            "settlement does not conserve funding",
        )?;
        channel.phase = Phase::Settled;
        Ok(payout)
    }
}

#[cfg(test)]
mod tests;
