//! Candidate successor ledger rules for two-party channel escrow.
//!
//! This is a deterministic state transition model, not part of PoW v1 block
//! execution or a mainnet funding verifier. Its anchor must be authenticated
//! by a future rule-adoption/replay path before any value is entrusted to it.

use crate::{
    hash, key_bytes, require, Funding, FundingOutpoint, Payout, Phase, Result, SignedState,
    CONTEST_BLOCKS,
};
use rld_core::{verify_bytes, AdmissionHash32 as Hash, Amount};
use rld_pow::{Chain, Coin, OutPoint, Output, State as V1State};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A candidate successor opening consumes one mature, single-owner v1 coin. The
/// escrow outpoint is index zero of this intent ID; change and the opening fee
/// occupy indices one and two. The second party signs the initial state before
/// the source coin can be consumed, so opening cannot strand an unwitting peer.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OpenIntent {
    pub chain_id: Hash,
    pub input: OutPoint,
    pub party_a: String,
    pub party_b: String,
    pub capacity: Amount,
    pub close_fee: Amount,
    pub opening_fee: Amount,
    pub change: Amount,
    #[serde(with = "rld_pow::decimal")]
    pub valid_through_height: u128,
}

impl OpenIntent {
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        require(
            !self.chain_id.is_zero() && !self.input.transaction.is_zero(),
            "missing opening identity",
        )?;
        require(self.opening_fee.0 >= 1, "opening fee below minimum")?;
        let funding = Funding {
            chain_id: self.chain_id,
            outpoint: FundingOutpoint {
                transaction: Hash([1; 32]),
                index: 0,
            },
            party_a: self.party_a.clone(),
            party_b: self.party_b.clone(),
            capacity: self.capacity,
            close_fee: self.close_fee,
        };
        funding.validate()?;
        let mut bytes = b"RLD-EARTH-CHANNEL-OPEN-SUCCESSOR\0".to_vec();
        bytes.extend(self.chain_id.0);
        bytes.extend(self.input.transaction.0);
        bytes.extend(self.input.index.to_be_bytes());
        bytes.extend(key_bytes(&self.party_a)?);
        bytes.extend(key_bytes(&self.party_b)?);
        bytes.extend(funding.capacity.0.to_be_bytes());
        bytes.extend(funding.close_fee.0.to_be_bytes());
        bytes.extend(self.opening_fee.0.to_be_bytes());
        bytes.extend(self.change.0.to_be_bytes());
        bytes.extend(self.valid_through_height.to_be_bytes());
        Ok(bytes)
    }

    pub fn id(&self) -> Result<Hash> {
        Ok(hash(&self.signing_bytes()?))
    }

    pub fn funding(&self) -> Result<Funding> {
        let id = self.id()?;
        let funding = Funding {
            chain_id: self.chain_id,
            outpoint: FundingOutpoint {
                transaction: id,
                index: 0,
            },
            party_a: self.party_a.clone(),
            party_b: self.party_b.clone(),
            capacity: self.capacity,
            close_fee: self.close_fee,
        };
        funding.validate()?;
        Ok(funding)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OpenChannel {
    pub intent: OpenIntent,
    pub signature_a: String,
    pub initial: SignedState,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Escrow {
    pub funding: Funding,
    pub initial: SignedState,
    #[serde(with = "rld_pow::decimal")]
    pub opened_height: u128,
    pub phase: Phase,
}

/// Successor-only state. The v1 UTXO map is copied at an explicitly supplied
/// anchor. There is no activation path and no change to the live v1 state root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ledger {
    chain_id: Hash,
    v1_tip: Hash,
    v1_anchor: Hash,
    anchor_height: u128,
    coins: BTreeMap<OutPoint, Coin>,
    escrows: BTreeMap<Hash, Escrow>,
    emitted: Amount,
}

impl Ledger {
    /// Anchor the candidate state to an actually replayed v1 best-chain tip.
    /// Signed adoption and successor activation are still separate gates.
    pub fn from_replayed_pow_chain(chain: &Chain) -> Result<Self> {
        let anchor = chain.replay_anchor()?;
        Self::from_v1_snapshot(
            anchor.chain_id(),
            anchor.state(),
            anchor.tip(),
            anchor.state_root(),
            anchor.height(),
        )
    }

    pub fn from_v1_snapshot(
        chain_id: Hash,
        v1: &V1State,
        v1_tip: Hash,
        expected_root: Hash,
        anchor_height: u128,
    ) -> Result<Self> {
        require(
            !chain_id.is_zero() && !v1_tip.is_zero() && v1.root()? == expected_root,
            "unmatched v1 snapshot",
        )?;
        let ledger = Self {
            chain_id,
            v1_tip,
            v1_anchor: expected_root,
            anchor_height,
            coins: v1.coins.clone(),
            escrows: BTreeMap::new(),
            emitted: v1.emitted,
        };
        ledger.root()?;
        Ok(ledger)
    }

    pub fn coin(&self, point: &OutPoint) -> Option<&Coin> {
        self.coins.get(point)
    }

    pub fn escrow(&self, id: Hash) -> Option<&Escrow> {
        self.escrows.get(&id)
    }

    pub fn root(&self) -> Result<Hash> {
        let mut total = Amount::ZERO;
        for coin in self.coins.values() {
            require(!coin.output.amount.is_zero(), "zero liquid coin")?;
            key_bytes(&coin.output.owner)?;
            total = total
                .checked_add(coin.output.amount)
                .map_err(|e| e.to_string())?;
        }
        for (id, escrow) in &self.escrows {
            require(
                escrow.funding.chain_id == self.chain_id && escrow.funding.id()? == *id,
                "escrow identity mismatch",
            )?;
            require(
                escrow.opened_height > self.anchor_height,
                "escrow predates anchor",
            )?;
            let locked = OutPoint {
                transaction: escrow.funding.outpoint.transaction,
                index: escrow.funding.outpoint.index,
            };
            require(
                !self.coins.contains_key(&locked),
                "escrow also exists as liquid coin",
            )?;
            escrow.initial.verify(&escrow.funding)?;
            require(
                escrow.initial.state.sequence == 0,
                "invalid opening allocation",
            )?;
            match &escrow.phase {
                Phase::Open => {}
                Phase::Closing {
                    best,
                    close_height,
                    deadline_height,
                } => {
                    best.verify(&escrow.funding)?;
                    require(
                        *close_height > escrow.opened_height
                            && close_height.checked_add(CONTEST_BLOCKS) == Some(*deadline_height),
                        "invalid contest deadline",
                    )?;
                }
                Phase::Settled => continue,
            }
            total = total
                .checked_add(escrow.funding.capacity)
                .map_err(|e| e.to_string())?;
        }
        require(
            total == self.emitted,
            "successor supply conservation failed",
        )?;
        #[derive(Serialize)]
        struct Commitment<'a> {
            chain_id: &'a Hash,
            v1_tip: &'a Hash,
            v1_anchor: &'a Hash,
            #[serde(with = "rld_pow::decimal")]
            anchor_height: u128,
            emitted: &'a Amount,
            coins: Vec<(&'a OutPoint, &'a Coin)>,
            escrows: Vec<(&'a Hash, &'a Escrow)>,
        }
        let commitment = Commitment {
            chain_id: &self.chain_id,
            v1_tip: &self.v1_tip,
            v1_anchor: &self.v1_anchor,
            anchor_height: self.anchor_height,
            emitted: &self.emitted,
            coins: self.coins.iter().collect(),
            escrows: self.escrows.iter().collect(),
        };
        let mut bytes = b"RLD-EARTH-CHANNEL-SUCCESSOR-STATE\0".to_vec();
        bytes.extend(serde_json::to_vec(&commitment).map_err(|e| e.to_string())?);
        Ok(hash(&bytes))
    }

    pub fn open(&mut self, command: OpenChannel, height: u128, miner: &str) -> Result<Hash> {
        let intent = &command.intent;
        require(
            intent.chain_id == self.chain_id
                && height > self.anchor_height
                && height <= intent.valid_through_height,
            "opening network or expiry mismatch",
        )?;
        key_bytes(miner)?;
        verify_bytes(
            &intent.party_a,
            &intent.signing_bytes()?,
            &command.signature_a,
        )?;
        let funding = intent.funding()?;
        require(
            command.initial.state.sequence == 0,
            "opening needs initial state",
        )?;
        command.initial.verify(&funding)?;
        let id = funding.id()?;
        require(!self.escrows.contains_key(&id), "channel already exists")?;
        let source = self
            .coins
            .get(&intent.input)
            .ok_or("opening input missing or spent")?;
        require(
            source.output.owner == intent.party_a && source.spendable_height <= height,
            "opening input owner or maturity mismatch",
        )?;
        let needed = intent
            .capacity
            .checked_add(intent.opening_fee)
            .and_then(|n| n.checked_add(intent.change))
            .map_err(|e| e.to_string())?;
        require(
            needed == source.output.amount,
            "opening does not conserve input",
        )?;
        let tx_id = intent.id()?;
        let mut next = self.clone();
        next.coins.remove(&intent.input);
        if !intent.change.is_zero() {
            require(
                next.coins
                    .insert(
                        OutPoint {
                            transaction: tx_id,
                            index: 1,
                        },
                        Coin {
                            output: Output {
                                owner: intent.party_a.clone(),
                                amount: intent.change,
                            },
                            spendable_height: height,
                        },
                    )
                    .is_none(),
                "change output collision",
            )?;
        }
        require(
            next.coins
                .insert(
                    OutPoint {
                        transaction: tx_id,
                        index: 2,
                    },
                    Coin {
                        output: Output {
                            owner: miner.into(),
                            amount: intent.opening_fee,
                        },
                        spendable_height: height,
                    },
                )
                .is_none(),
            "fee output collision",
        )?;
        next.escrows.insert(
            id,
            Escrow {
                funding,
                initial: command.initial,
                opened_height: height,
                phase: Phase::Open,
            },
        );
        next.root()?;
        *self = next;
        Ok(id)
    }

    pub fn request_close(&mut self, id: Hash, state: SignedState, height: u128) -> Result<()> {
        let mut next = self.clone();
        let escrow = next.escrows.get_mut(&id).ok_or("unknown channel")?;
        require(escrow.phase == Phase::Open, "channel is not open")?;
        require(height > escrow.opened_height, "opening not yet confirmed")?;
        state.verify(&escrow.funding)?;
        let deadline_height = height
            .checked_add(CONTEST_BLOCKS)
            .ok_or("contest height overflow")?;
        escrow.phase = Phase::Closing {
            best: state,
            close_height: height,
            deadline_height,
        };
        next.root()?;
        *self = next;
        Ok(())
    }

    pub fn challenge(&mut self, id: Hash, state: SignedState, height: u128) -> Result<()> {
        let mut next = self.clone();
        let escrow = next.escrows.get_mut(&id).ok_or("unknown channel")?;
        state.verify(&escrow.funding)?;
        match &mut escrow.phase {
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
                    "challenge requires a newer state",
                )?;
                *best = state;
            }
            _ => return Err("channel is not closing".into()),
        }
        next.root()?;
        *self = next;
        Ok(())
    }

    pub fn finalize(&mut self, id: Hash, height: u128, miner: &str) -> Result<Payout> {
        key_bytes(miner)?;
        let mut next = self.clone();
        let escrow = next.escrows.get_mut(&id).ok_or("unknown channel")?;
        let (best, deadline_height) = match &escrow.phase {
            Phase::Closing {
                best,
                deadline_height,
                ..
            } => (best.clone(), *deadline_height),
            _ => return Err("channel is not closing".into()),
        };
        require(height > deadline_height, "contest window remains open")?;
        let payout = Payout {
            party_a: escrow.funding.party_a.clone(),
            amount_a: best.state.balance_a,
            party_b: escrow.funding.party_b.clone(),
            amount_b: best.state.balance_b,
            miner_fee: escrow.funding.close_fee,
        };
        require(
            payout
                .amount_a
                .checked_add(payout.amount_b)
                .and_then(|n| n.checked_add(payout.miner_fee))
                .map_err(|e| e.to_string())?
                == escrow.funding.capacity,
            "settlement does not conserve escrow",
        )?;
        let mut bytes = b"RLD-EARTH-CHANNEL-SETTLEMENT-SUCCESSOR\0".to_vec();
        bytes.extend(id.0);
        bytes.extend(best.state.signing_bytes(&escrow.funding)?);
        bytes.extend(height.to_be_bytes());
        let tx_id = hash(&bytes);
        escrow.phase = Phase::Settled;
        for (index, owner, amount) in [
            (0, payout.party_a.clone(), payout.amount_a),
            (1, payout.party_b.clone(), payout.amount_b),
            (2, miner.into(), payout.miner_fee),
        ] {
            if amount.is_zero() {
                continue;
            }
            require(
                next.coins
                    .insert(
                        OutPoint {
                            transaction: tx_id,
                            index,
                        },
                        Coin {
                            output: Output { owner, amount },
                            spendable_height: height,
                        },
                    )
                    .is_none(),
                "settlement output collision",
            )?;
        }
        next.root()?;
        *self = next;
        Ok(payout)
    }
}

#[cfg(test)]
mod tests;
