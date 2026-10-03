//! Isolated, unified candidate state for regional channels and source exports.
//!
//! Ordinary transfers, channels, and exports consume the same UTXO set. The
//! candidate chain can replay and check local source checkpoints; adopted
//! Earth nodes additionally enforce signed finality before destination credit.
//! None of these rules belongs to the old PoW v1 chain.

use rld_core::{
    validate_ed25519_public_key, verify_bytes, AdmissionHash32 as Hash, Amount, TOTAL_SUPPLY_RUNLAI,
};
use rld_cross_region::value::{ExportCommand, ExportRecord};
use rld_fast_payments::{
    successor::{Escrow, OpenChannel},
    Payout, Phase, SignedState, CONTEST_BLOCKS,
};
use rld_pow::{Chain, Coin, OutPoint, Output, State as V1State, Transfer, COINBASE_MATURITY};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub type Result<T> = std::result::Result<T, String>;
const MAX_EXPORTS: usize = 1_000_000;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum DisputeAction {
    Close,
    Challenge,
}

/// A fee spend signed for exactly one close or challenge. It cannot be lifted
/// into an ordinary transfer or used to pay for another dispute state.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActionFeeIntent {
    pub chain_id: Hash,
    pub action: DisputeAction,
    pub channel: Hash,
    pub signed_state: Hash,
    pub input: OutPoint,
    pub owner: String,
    pub fee: Amount,
    pub change: Amount,
    #[serde(with = "rld_pow::decimal")]
    pub valid_through_height: u128,
}

impl ActionFeeIntent {
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        require(
            !self.chain_id.is_zero()
                && !self.channel.is_zero()
                && !self.signed_state.is_zero()
                && !self.input.transaction.is_zero()
                && self.fee.0 >= 1,
            "invalid dispute fee identity or amount",
        )?;
        key(&self.owner)?;
        let mut bytes = b"RLD-EARTH-SUCCESSOR-DISPUTE-FEE\0".to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|error| error.to_string())?);
        Ok(bytes)
    }

    pub fn id(&self) -> Result<Hash> {
        Ok(hash(&self.signing_bytes()?))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActionFee {
    pub intent: ActionFeeIntent,
    pub owner_signature: String,
}

/// Lock one mature coin to fund challenges of a specific channel. The owner
/// cannot spend it as a normal UTXO until settlement returns it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChallengeFeeReserveIntent {
    pub chain_id: Hash,
    pub channel: Hash,
    pub input: OutPoint,
    pub owner: String,
}

impl ChallengeFeeReserveIntent {
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        require(
            !self.chain_id.is_zero()
                && !self.channel.is_zero()
                && !self.input.transaction.is_zero(),
            "invalid challenge fee reservation identity",
        )?;
        key(&self.owner)?;
        let mut bytes = b"RLD-EARTH-SUCCESSOR-CHALLENGE-FEE-RESERVE\0".to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|error| error.to_string())?);
        Ok(bytes)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChallengeFeeReserve {
    pub intent: ChallengeFeeReserveIntent,
    pub owner_signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReservedChallengeFee {
    pub channel: Hash,
    pub coin: Coin,
    #[serde(with = "rld_pow::decimal")]
    pub reserved_height: u128,
}

pub fn signed_state_hash(state: &SignedState) -> Result<Hash> {
    let mut bytes = b"RLD-EARTH-SUCCESSOR-DISPUTE-STATE\0".to_vec();
    bytes.extend(serde_json::to_vec(state).map_err(|error| error.to_string())?);
    Ok(hash(&bytes))
}

pub mod adoption;
pub mod candidate_client;
pub mod chain;
pub mod destination;
pub mod transition;
pub mod wallet_guard;
pub mod wallet_payer;
pub mod watchtower;

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
fn checked_add(a: Amount, b: Amount) -> Result<Amount> {
    a.checked_add(b).map_err(|e| e.to_string())
}
fn key(key: &str) -> Result<()> {
    validate_ed25519_public_key(key)
}

fn export_leaf(id: Hash, record: &ExportRecord) -> Result<Hash> {
    require(record.id()? == id, "export leaf identity mismatch")?;
    let mut bytes = b"RLD-EARTH-UNIFIED-EXPORT-LEAF\0".to_vec();
    bytes.extend(id.0);
    bytes.extend(serde_json::to_vec(record).map_err(|e| e.to_string())?);
    Ok(hash(&bytes))
}
fn export_parent(left: Hash, right: Hash) -> Hash {
    let mut bytes = b"RLD-EARTH-UNIFIED-EXPORT-PARENT\0".to_vec();
    bytes.extend(left.0);
    bytes.extend(right.0);
    hash(&bytes)
}
fn export_tree_root(mut level: Vec<Hash>) -> Hash {
    if level.is_empty() {
        return hash(b"RLD-EARTH-UNIFIED-EXPORT-EMPTY\0");
    }
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| export_parent(pair[0], *pair.get(1).unwrap_or(&pair[0])))
            .collect();
    }
    level[0]
}

/// Claims one unified candidate state. A fully replayed candidate source chain
/// can check this against a checkpoint; the commitment alone cannot authorize
/// a destination.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Commitment {
    pub chain_id: Hash,
    pub v1_tip: Hash,
    pub v1_root: Hash,
    #[serde(with = "rld_pow::decimal")]
    pub anchor_height: u128,
    pub emitted: Amount,
    pub liquid: Amount,
    pub locked: Amount,
    pub retired: Amount,
    pub coins_hash: Hash,
    pub escrows_hash: Hash,
    pub reserved_fees_hash: Hash,
    pub export_root: Hash,
    pub export_count: u32,
}

impl Commitment {
    pub fn root(&self) -> Result<Hash> {
        require(
            !self.chain_id.is_zero()
                && !self.v1_tip.is_zero()
                && !self.v1_root.is_zero()
                && !self.coins_hash.is_zero()
                && !self.escrows_hash.is_zero()
                && !self.reserved_fees_hash.is_zero()
                && !self.export_root.is_zero()
                && self.export_count as usize <= MAX_EXPORTS
                && self.emitted.0 <= TOTAL_SUPPLY_RUNLAI,
            "invalid unified commitment",
        )?;
        require(
            checked_add(checked_add(self.liquid, self.locked)?, self.retired)? == self.emitted,
            "unified commitment supply mismatch",
        )?;
        let mut bytes = b"RLD-EARTH-UNIFIED-VALUE-SUCCESSOR\0".to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|e| e.to_string())?);
        Ok(hash(&bytes))
    }
}

/// Membership in a *claimed* unified source state. Alone this is neither a
/// replayed PoW checkpoint nor permission to mint an import at a destination.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExportMembershipProof {
    pub state: Commitment,
    pub record: ExportRecord,
    pub leaf_index: u32,
    pub leaf_count: u32,
    pub siblings: Vec<Hash>,
}

impl ExportMembershipProof {
    pub fn verify_in_claimed_state(&self, expected_root: Hash) -> Result<ExportRecord> {
        require(
            self.state.root()? == expected_root,
            "unified state root mismatch",
        )?;
        require(
            self.leaf_count == self.state.export_count
                && self.leaf_count > 0
                && self.leaf_index < self.leaf_count
                && self.siblings.len() <= 20,
            "invalid export proof shape",
        )?;
        let id = self.record.id()?;
        require(
            self.record.command.intent.source_chain_id == self.state.chain_id
                && self.record.export_height > self.state.anchor_height,
            "export record outside unified source state",
        )?;
        let mut current = export_leaf(id, &self.record)?;
        let mut width = self.leaf_count as usize;
        let mut index = self.leaf_index as usize;
        for sibling in &self.siblings {
            require(width > 1, "excess export siblings")?;
            if index.is_multiple_of(2) {
                if index + 1 == width {
                    require(*sibling == current, "odd leaf duplication mismatch")?;
                }
                current = export_parent(current, *sibling);
            } else {
                current = export_parent(*sibling, current);
            }
            index /= 2;
            width = width.div_ceil(2);
        }
        require(
            width == 1 && current == self.state.export_root,
            "export membership mismatch",
        )?;
        Ok(self.record.clone())
    }
}

/// A single candidate value state, anchored to one fully replayed PoW v1 tip.
/// There is no public constructor that accepts a caller-provided snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ledger {
    chain_id: Hash,
    v1_tip: Hash,
    v1_root: Hash,
    anchor_height: u128,
    emitted: Amount,
    coins: BTreeMap<OutPoint, Coin>,
    escrows: BTreeMap<Hash, Escrow>,
    reserved_fees: BTreeMap<OutPoint, ReservedChallengeFee>,
    exports: BTreeMap<Hash, ExportRecord>,
}

impl Ledger {
    pub fn from_replayed_pow_chain(chain: &Chain) -> Result<Self> {
        let anchor = chain.replay_anchor()?;
        Self::from_verified_anchor(
            anchor.chain_id(),
            anchor.state(),
            anchor.tip(),
            anchor.state_root(),
            anchor.height(),
        )
    }

    fn from_verified_anchor(
        chain_id: Hash,
        v1: &V1State,
        v1_tip: Hash,
        v1_root: Hash,
        anchor_height: u128,
    ) -> Result<Self> {
        require(
            !chain_id.is_zero() && !v1_tip.is_zero() && v1.root()? == v1_root,
            "unmatched PoW replay anchor",
        )?;
        let next = Self {
            chain_id,
            v1_tip,
            v1_root,
            anchor_height,
            emitted: v1.emitted,
            coins: v1.coins.clone(),
            escrows: BTreeMap::new(),
            reserved_fees: BTreeMap::new(),
            exports: BTreeMap::new(),
        };
        next.root()?;
        Ok(next)
    }

    pub fn coin(&self, input: &OutPoint) -> Option<&Coin> {
        self.coins.get(input)
    }
    pub fn escrow(&self, id: Hash) -> Option<&Escrow> {
        self.escrows.get(&id)
    }
    pub fn reserved_challenge_fee(&self, input: &OutPoint) -> Option<&ReservedChallengeFee> {
        self.reserved_fees.get(input)
    }
    pub fn export_record(&self, id: Hash) -> Option<&ExportRecord> {
        self.exports.get(&id)
    }

    pub fn totals(&self) -> Result<(Amount, Amount, Amount)> {
        let mut liquid = Amount::ZERO;
        let mut locked = Amount::ZERO;
        let mut retired = Amount::ZERO;
        for coin in self.coins.values() {
            require(!coin.output.amount.is_zero(), "zero liquid coin")?;
            // The fully replayed v1 anchor verifies every inherited key, and
            // output() verifies every newly created key before insertion.
            // Rechecking every curve point on every state root is quadratic
            // over an otherwise steadily growing chain.
            liquid = checked_add(liquid, coin.output.amount)?;
        }
        for (input, reservation) in &self.reserved_fees {
            require(
                !input.transaction.is_zero()
                    && !self.coins.contains_key(input)
                    && reservation.reserved_height > self.anchor_height
                    && !reservation.coin.output.amount.is_zero(),
                "invalid reserved challenge fee coin",
            )?;
            // A reservation moves a previously validated liquid coin.
            let escrow = self
                .escrows
                .get(&reservation.channel)
                .ok_or("reservation channel missing")?;
            require(
                escrow.phase != Phase::Settled
                    && (reservation.coin.output.owner == escrow.funding.party_a
                        || reservation.coin.output.owner == escrow.funding.party_b),
                "invalid reservation channel or owner",
            )?;
            locked = checked_add(locked, reservation.coin.output.amount)?;
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
            let point = OutPoint {
                transaction: escrow.funding.outpoint.transaction,
                index: escrow.funding.outpoint.index,
            };
            require(!self.coins.contains_key(&point), "escrow also liquid")?;
            escrow.initial.verify(&escrow.funding)?;
            require(escrow.initial.state.sequence == 0, "invalid initial state")?;
            match &escrow.phase {
                Phase::Open => locked = checked_add(locked, escrow.funding.capacity)?,
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
                    locked = checked_add(locked, escrow.funding.capacity)?;
                }
                Phase::Settled => {}
            }
        }
        require(
            self.exports.len() <= MAX_EXPORTS,
            "export index capacity reached",
        )?;
        for (id, record) in &self.exports {
            require(
                record.id()? == *id
                    && record.command.intent.source_chain_id == self.chain_id
                    && record.export_height > self.anchor_height,
                "invalid export record",
            )?;
            retired = checked_add(retired, record.command.intent.amount)?;
        }
        require(
            checked_add(checked_add(liquid, locked)?, retired)? == self.emitted
                && self.emitted.0 <= TOTAL_SUPPLY_RUNLAI,
            "unified supply conservation failed",
        )?;
        Ok((liquid, locked, retired))
    }

    pub fn root(&self) -> Result<Hash> {
        self.commitment()?.root()
    }

    pub fn commitment(&self) -> Result<Commitment> {
        let (liquid, locked, retired) = self.totals()?;
        let mut coin_bytes = b"RLD-EARTH-UNIFIED-LIQUID-COINS\0".to_vec();
        coin_bytes.extend(
            serde_json::to_vec(&self.coins.iter().collect::<Vec<_>>())
                .map_err(|e| e.to_string())?,
        );
        let mut escrow_bytes = b"RLD-EARTH-UNIFIED-ESCROWS\0".to_vec();
        escrow_bytes.extend(
            serde_json::to_vec(&self.escrows.iter().collect::<Vec<_>>())
                .map_err(|e| e.to_string())?,
        );
        let mut reserved_bytes = b"RLD-EARTH-UNIFIED-RESERVED-FEES\0".to_vec();
        reserved_bytes.extend(
            serde_json::to_vec(&self.reserved_fees.iter().collect::<Vec<_>>())
                .map_err(|e| e.to_string())?,
        );
        let leaves = self
            .exports
            .iter()
            .map(|(id, record)| export_leaf(*id, record))
            .collect::<Result<Vec<_>>>()?;
        Ok(Commitment {
            chain_id: self.chain_id,
            v1_tip: self.v1_tip,
            v1_root: self.v1_root,
            anchor_height: self.anchor_height,
            emitted: self.emitted,
            liquid,
            locked,
            retired,
            coins_hash: hash(&coin_bytes),
            escrows_hash: hash(&escrow_bytes),
            reserved_fees_hash: hash(&reserved_bytes),
            export_root: export_tree_root(leaves),
            export_count: self.exports.len() as u32,
        })
    }

    pub fn membership_proof(&self, id: Hash) -> Result<ExportMembershipProof> {
        let index = self
            .exports
            .keys()
            .position(|key| *key == id)
            .ok_or("unknown unified export")?;
        let record = self
            .exports
            .get(&id)
            .ok_or("unknown unified export")?
            .clone();
        let mut level = self
            .exports
            .iter()
            .map(|(key, value)| export_leaf(*key, value))
            .collect::<Result<Vec<_>>>()?;
        let mut position = index;
        let mut siblings = Vec::new();
        while level.len() > 1 {
            let sibling_index = if position.is_multiple_of(2) {
                (position + 1).min(level.len() - 1)
            } else {
                position - 1
            };
            siblings.push(level[sibling_index]);
            level = level
                .chunks(2)
                .map(|pair| export_parent(pair[0], *pair.get(1).unwrap_or(&pair[0])))
                .collect();
            position /= 2;
        }
        let proof = ExportMembershipProof {
            state: self.commitment()?,
            record,
            leaf_index: index as u32,
            leaf_count: self.exports.len() as u32,
            siblings,
        };
        proof.verify_in_claimed_state(self.root()?)?;
        Ok(proof)
    }

    fn input(&self, point: &OutPoint, owner: &str, height: u128) -> Result<&Coin> {
        let coin = self
            .coins
            .get(point)
            .ok_or("input missing or already spent")?;
        require(
            coin.output.owner == owner && coin.spendable_height <= height,
            "input owner or maturity mismatch",
        )?;
        Ok(coin)
    }
    fn output(
        &mut self,
        id: Hash,
        index: u16,
        owner: String,
        amount: Amount,
        height: u128,
    ) -> Result<()> {
        if amount.is_zero() {
            return Ok(());
        }
        key(&owner)?;
        require(
            self.coins
                .insert(
                    OutPoint {
                        transaction: id,
                        index,
                    },
                    Coin {
                        output: Output { owner, amount },
                        spendable_height: height,
                    },
                )
                .is_none(),
            "output collision",
        )
    }

    /// Candidate continuation of the ordinary signed v1 transfer format.
    /// It consumes the same coins as channel opening and export. Unlike a v1
    /// block coinbase, this isolated model credits the fee to a reserved
    /// outpoint of the transfer, with miner-reward maturity.
    pub fn transfer(&mut self, tx: Transfer, height: u128, miner: &str) -> Result<Hash> {
        require(
            tx.chain_id == self.chain_id
                && height > self.anchor_height
                && height <= tx.valid_through_height,
            "transfer network or expiry mismatch",
        )?;
        key(miner)?;
        require(tx.fee.0 >= 1, "transfer fee below minimum")?;
        verify_bytes(&tx.owner, &tx.signing_bytes()?, &tx.signature)?;
        let id = tx.id()?;
        let input_total = tx.inputs.iter().try_fold(Amount::ZERO, |sum, input| {
            checked_add(sum, self.input(input, &tx.owner, height)?.output.amount)
        })?;
        let output_total = tx
            .outputs
            .iter()
            .try_fold(tx.fee, |sum, output| checked_add(sum, output.amount))?;
        require(
            input_total == output_total,
            "transfer does not conserve input",
        )?;
        let reward_height = height
            .checked_add(COINBASE_MATURITY)
            .ok_or("fee maturity overflow")?;
        let mut next = self.clone();
        for input in &tx.inputs {
            next.coins.remove(input);
        }
        for (index, output) in tx.outputs.into_iter().enumerate() {
            next.output(id, index as u16, output.owner, output.amount, height)?;
        }
        next.output(id, u16::MAX, miner.into(), tx.fee, reward_height)?;
        next.root()?;
        *self = next;
        Ok(id)
    }

    pub fn open(&mut self, command: OpenChannel, height: u128, miner: &str) -> Result<Hash> {
        let intent = &command.intent;
        require(
            intent.chain_id == self.chain_id
                && height > self.anchor_height
                && height <= intent.valid_through_height,
            "opening network or expiry mismatch",
        )?;
        key(miner)?;
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
        let source = self.input(&intent.input, &intent.party_a, height)?;
        require(
            checked_add(
                checked_add(intent.capacity, intent.opening_fee)?,
                intent.change,
            )? == source.output.amount,
            "opening does not conserve input",
        )?;
        let mut next = self.clone();
        next.coins.remove(&intent.input);
        next.output(id, 1, intent.party_a.clone(), intent.change, height)?;
        next.output(
            id,
            2,
            miner.into(),
            intent.opening_fee,
            height
                .checked_add(COINBASE_MATURITY)
                .ok_or("fee maturity overflow")?,
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

    pub fn reserve_challenge_fee(
        &mut self,
        command: ChallengeFeeReserve,
        height: u128,
    ) -> Result<()> {
        let intent = &command.intent;
        require(
            intent.chain_id == self.chain_id && height > self.anchor_height,
            "reservation network or height mismatch",
        )?;
        verify_bytes(
            &intent.owner,
            &intent.signing_bytes()?,
            &command.owner_signature,
        )?;
        let escrow = self
            .escrow(intent.channel)
            .ok_or("reservation channel missing")?;
        require(
            escrow.phase == Phase::Open
                && height > escrow.opened_height
                && (intent.owner == escrow.funding.party_a
                    || intent.owner == escrow.funding.party_b),
            "reservation requires a confirmed open channel party",
        )?;
        require(
            self.reserved_fees.len() < 100_000,
            "challenge fee reservation capacity reached",
        )?;
        let coin = self.input(&intent.input, &intent.owner, height)?.clone();
        let mut next = self.clone();
        next.coins.remove(&intent.input);
        next.reserved_fees.insert(
            intent.input.clone(),
            ReservedChallengeFee {
                channel: intent.channel,
                coin,
                reserved_height: height,
            },
        );
        next.root()?;
        *self = next;
        Ok(())
    }

    /// Consume a separately funded, action-bound fee. This is private so a
    /// caller cannot commit the fee without its matching dispute transition.
    fn pay_dispute_fee(
        &mut self,
        payment: ActionFee,
        action: DisputeAction,
        channel: Hash,
        state: &SignedState,
        height: u128,
        miner: &str,
    ) -> Result<Hash> {
        let intent = &payment.intent;
        require(
            intent.chain_id == self.chain_id
                && intent.action == action
                && intent.channel == channel
                && intent.signed_state == signed_state_hash(state)?
                && height > self.anchor_height
                && height <= intent.valid_through_height,
            "dispute fee action, state, network or expiry mismatch",
        )?;
        key(miner)?;
        verify_bytes(
            &intent.owner,
            &intent.signing_bytes()?,
            &payment.owner_signature,
        )?;
        let input_amount = if action == DisputeAction::Challenge {
            let reservation = self
                .reserved_fees
                .get(&intent.input)
                .ok_or("challenge fee is not reserved")?;
            require(
                reservation.channel == channel
                    && reservation.coin.output.owner == intent.owner
                    && reservation.reserved_height <= height,
                "challenge fee reservation mismatch",
            )?;
            reservation.coin.output.amount
        } else {
            self.input(&intent.input, &intent.owner, height)?
                .output
                .amount
        };
        require(
            checked_add(intent.fee, intent.change)? == input_amount,
            "dispute fee does not conserve input",
        )?;
        let id = intent.id()?;
        let mut next = self.clone();
        if action == DisputeAction::Challenge {
            next.reserved_fees.remove(&intent.input);
        } else {
            next.coins.remove(&intent.input);
        }
        next.output(id, 0, intent.owner.clone(), intent.change, height)?;
        next.output(
            id,
            1,
            miner.into(),
            intent.fee,
            height
                .checked_add(COINBASE_MATURITY)
                .ok_or("dispute fee maturity overflow")?,
        )?;
        next.root()?;
        *self = next;
        Ok(id)
    }

    pub fn request_close_with_fee(
        &mut self,
        id: Hash,
        state: SignedState,
        payment: ActionFee,
        height: u128,
        miner: &str,
    ) -> Result<()> {
        let mut next = self.clone();
        next.pay_dispute_fee(payment, DisputeAction::Close, id, &state, height, miner)?;
        next.request_close(id, state, height)?;
        *self = next;
        Ok(())
    }

    pub fn challenge_with_fee(
        &mut self,
        id: Hash,
        state: SignedState,
        payment: ActionFee,
        height: u128,
        miner: &str,
    ) -> Result<()> {
        let mut next = self.clone();
        next.pay_dispute_fee(payment, DisputeAction::Challenge, id, &state, height, miner)?;
        next.challenge(id, state, height)?;
        *self = next;
        Ok(())
    }

    pub fn request_close(&mut self, id: Hash, state: SignedState, height: u128) -> Result<()> {
        let mut next = self.clone();
        let escrow = next.escrows.get_mut(&id).ok_or("unknown channel")?;
        require(
            escrow.phase == Phase::Open && height > escrow.opened_height,
            "channel is not confirmed and open",
        )?;
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
                    "challenge needs newer state",
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
        key(miner)?;
        let mut next = self.clone();
        let escrow = next.escrows.get_mut(&id).ok_or("unknown channel")?;
        let (best, deadline) = match &escrow.phase {
            Phase::Closing {
                best,
                deadline_height,
                ..
            } => (best.clone(), *deadline_height),
            _ => return Err("channel is not closing".into()),
        };
        require(height > deadline, "contest window remains open")?;
        let payout = Payout {
            party_a: escrow.funding.party_a.clone(),
            amount_a: best.state.balance_a,
            party_b: escrow.funding.party_b.clone(),
            amount_b: best.state.balance_b,
            miner_fee: escrow.funding.close_fee,
        };
        require(
            checked_add(
                checked_add(payout.amount_a, payout.amount_b)?,
                payout.miner_fee,
            )? == escrow.funding.capacity,
            "settlement does not conserve escrow",
        )?;
        let mut bytes = b"RLD-EARTH-UNIFIED-CHANNEL-SETTLEMENT\0".to_vec();
        bytes.extend(id.0);
        bytes.extend(best.state.signing_bytes(&escrow.funding)?);
        bytes.extend(height.to_be_bytes());
        let tx_id = hash(&bytes);
        escrow.phase = Phase::Settled;
        let refunds = next
            .reserved_fees
            .iter()
            .filter(|(_, reservation)| reservation.channel == id)
            .map(|(input, reservation)| (input.clone(), reservation.coin.clone()))
            .collect::<Vec<_>>();
        for (input, coin) in refunds {
            next.reserved_fees.remove(&input);
            let mut refund_bytes = b"RLD-EARTH-UNIFIED-CHALLENGE-FEE-REFUND\0".to_vec();
            refund_bytes.extend(id.0);
            refund_bytes.extend(input.transaction.0);
            refund_bytes.extend(input.index.to_be_bytes());
            next.output(
                hash(&refund_bytes),
                0,
                coin.output.owner,
                coin.output.amount,
                height,
            )?;
        }
        next.output(tx_id, 0, payout.party_a.clone(), payout.amount_a, height)?;
        next.output(tx_id, 1, payout.party_b.clone(), payout.amount_b, height)?;
        next.output(
            tx_id,
            2,
            miner.into(),
            payout.miner_fee,
            height
                .checked_add(COINBASE_MATURITY)
                .ok_or("fee maturity overflow")?,
        )?;
        next.root()?;
        *self = next;
        Ok(payout)
    }

    pub fn export(
        &mut self,
        command: ExportCommand,
        height: u128,
        miner: &str,
    ) -> Result<ExportRecord> {
        let intent = &command.intent;
        require(
            intent.source_chain_id == self.chain_id
                && height > self.anchor_height
                && height <= intent.valid_through_height,
            "export network or expiry mismatch",
        )?;
        key(miner)?;
        verify_bytes(
            &intent.owner,
            &intent.signing_bytes()?,
            &command.owner_signature,
        )?;
        let id = intent.id()?;
        require(
            !self.exports.contains_key(&id) && self.exports.len() < MAX_EXPORTS,
            "duplicate export or capacity reached",
        )?;
        let source = self.input(&intent.input, &intent.owner, height)?;
        require(
            checked_add(
                checked_add(intent.amount, intent.source_fee)?,
                intent.change,
            )? == source.output.amount,
            "export does not conserve input",
        )?;
        let mut next = self.clone();
        next.coins.remove(&intent.input);
        next.output(id, 1, intent.owner.clone(), intent.change, height)?;
        next.output(
            id,
            2,
            miner.into(),
            intent.source_fee,
            height
                .checked_add(COINBASE_MATURITY)
                .ok_or("fee maturity overflow")?,
        )?;
        let record = ExportRecord {
            command,
            export_height: height,
        };
        next.exports.insert(id, record.clone());
        next.root()?;
        *self = next;
        Ok(record)
    }
}

#[cfg(test)]
mod tests;
