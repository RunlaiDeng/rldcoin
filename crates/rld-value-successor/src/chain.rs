//! PoW successor candidate that commits the unified value state.
//!
//! A verified v1 replay is the starting point. Adopted Earth nodes additionally
//! pin the fresh-chain successor adoption and enforce signed source finality.
//! These blocks are never accepted by the old deployed PoW v1 node.

use crate::{
    hash, key, require, ActionFee, ChallengeFeeReserve, ExportMembershipProof, Ledger, Result,
};
use rld_core::{header_work, AdmissionHash32 as Hash, AdmissionWork as Work, Amount};
use rld_cross_region::{
    value::{ExportCommand, ExportRecord},
    ProofBundle,
};
use rld_fast_payments::{
    successor::OpenChannel, ConfirmedEscrow, Funding, Phase, SignedState, CONTEST_BLOCKS,
};
use rld_pow::{
    cumulative_emission, subsidy, target_limit, Chain, OutPoint, Transfer, BLOCK_SECONDS,
    COINBASE_MATURITY, MAX_BLOCK_BYTES, MAX_TRACKED_BLOCKS, MAX_TRANSACTIONS, RETARGET_BLOCKS,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum Command {
    Transfer(Transfer),
    Open(OpenChannel),
    ReserveChallengeFee(ChallengeFeeReserve),
    Close {
        channel: Hash,
        state: SignedState,
        fee: ActionFee,
    },
    Challenge {
        channel: Hash,
        state: SignedState,
        fee: ActionFee,
    },
    Finalize {
        channel: Hash,
    },
    Export(ExportCommand),
}

fn commands_root(commands: &[Command]) -> Result<Hash> {
    require(
        commands.len() <= MAX_TRANSACTIONS,
        "successor command count bound",
    )?;
    let mut bytes = b"RLD-EARTH-UNIFIED-COMMANDS\0".to_vec();
    bytes.extend(serde_json::to_vec(commands).map_err(|e| e.to_string())?);
    Ok(hash(&bytes))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub chain_id: Hash,
    pub parent: Hash,
    #[serde(with = "rld_pow::decimal")]
    pub height: u128,
    pub timestamp: u64,
    pub target: Work,
    pub miner: String,
    pub commands_root: Hash,
    pub state_root: Hash,
    #[serde(with = "rld_pow::decimal")]
    pub nonce: u128,
}

impl Header {
    fn canonical_bytes(&self) -> Result<Vec<u8>> {
        key(&self.miner)?;
        let mut bytes = b"RLD-EARTH-UNIFIED-SUCCESSOR-HEADER\0".to_vec();
        bytes.extend(self.chain_id.0);
        bytes.extend(self.parent.0);
        bytes.extend(self.height.to_be_bytes());
        bytes.extend(self.timestamp.to_be_bytes());
        bytes.extend(self.target.to_be_bytes());
        bytes.extend(hex::decode(&self.miner).map_err(|e| e.to_string())?);
        bytes.extend(self.commands_root.0);
        bytes.extend(self.state_root.0);
        bytes.extend(self.nonce.to_be_bytes());
        Ok(bytes)
    }
    pub fn id(&self) -> Result<Hash> {
        Ok(hash(&Sha256::digest(self.canonical_bytes()?)))
    }
    pub fn work_valid(&self) -> Result<bool> {
        Ok(Work::from_be_bytes(self.id()?.0) <= self.target)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Block {
    pub header: Header,
    pub commands: Vec<Command>,
}

pub fn mine_batch(block: &mut Block, attempts: u64) -> Result<bool> {
    // The miner key and all other header fields are fixed for one batch.
    // Canonicalize and validate them once; only the nonce bytes change.
    let mut bytes = block.header.canonical_bytes()?;
    let nonce_offset = bytes.len() - 16;
    for _ in 0..attempts {
        bytes[nonce_offset..].copy_from_slice(&block.header.nonce.to_be_bytes());
        let proof = hash(&Sha256::digest(&bytes));
        if Work::from_be_bytes(proof.0) <= block.header.target {
            return Ok(true);
        }
        block.header.nonce = block.header.nonce.checked_add(1).ok_or("nonce exhausted")?;
    }
    Ok(false)
}

#[derive(Clone, Copy, Debug)]
struct Predecessor {
    height: u128,
    timestamp: u64,
    target: Work,
}

#[derive(Clone, Debug)]
struct Entry {
    block: Block,
    cumulative_work: Work,
}

/// Fully validated but not yet published. Durable stores write the block and
/// selected head before committing this result to the in-memory chain.
pub(super) struct Prepared {
    id: Hash,
    entry: Entry,
    state: Ledger,
    preferred: bool,
}

/// Explicitly supplied source-chain observation requirements. This is a local
/// candidate test policy, not a trust agreement adopted by a destination.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObservationPolicy {
    pub source_chain_id: Hash,
    pub accepted_v1_tip: Hash,
    #[serde(with = "rld_pow::decimal")]
    pub minimum_confirmations: u128,
    pub minimum_cumulative_work: Work,
}

/// Replayed source-chain evidence for one courier package. This is not a
/// destination consensus certificate, finality claim or import permission.
#[derive(Clone, Debug)]
pub struct ObservedExport {
    pub record: ExportRecord,
    pub checkpoint: Hash,
    pub checkpoint_height: u128,
    pub checkpoint_work: Work,
    pub confirmations: u128,
}

#[derive(Clone, Debug)]
pub struct CandidateChain {
    chain_id: Hash,
    v1_manifest_pin: Hash,
    v1_adoption_id: Hash,
    v1_tip: Hash,
    anchor_height: u128,
    legacy_height: u128,
    started_at: u64,
    base_work: Work,
    base_state: Ledger,
    base_history: Vec<Predecessor>,
    entries: BTreeMap<Hash, Entry>,
    tip: Hash,
    selected_state: Option<Ledger>,
    side_state: Option<(Hash, Ledger)>,
    finalized: Option<(Hash, u128)>,
}

/// Read-only observation of a channel lock on the selected branch. Adopted
/// payments additionally require an installed signed source checkpoint.
pub struct CandidateEscrowObservation<'a> {
    chain: &'a CandidateChain,
    minimum_confirmations: u128,
    require_finality: bool,
}

impl<'a> CandidateEscrowObservation<'a> {
    pub fn new(chain: &'a CandidateChain, minimum_confirmations: u128) -> Result<Self> {
        require(
            (2..=MAX_TRACKED_BLOCKS as u128).contains(&minimum_confirmations),
            "candidate escrow confirmation policy bound",
        )?;
        Ok(Self {
            chain,
            minimum_confirmations,
            require_finality: false,
        })
    }

    pub fn new_finalized(chain: &'a CandidateChain, minimum_confirmations: u128) -> Result<Self> {
        let mut observation = Self::new(chain, minimum_confirmations)?;
        observation.require_finality = true;
        Ok(observation)
    }

    fn require_finalized_height(&self, height: u128) -> Result<()> {
        if self.require_finality {
            require(
                self.chain
                    .finalized()
                    .is_some_and(|(_, finalized)| finalized >= height),
                "adopted payment funding lacks signed source finality",
            )?;
        }
        Ok(())
    }

    /// Point-in-time readiness for a candidate recipient receipt. The fee
    /// coin is locked on this branch; a later reorganization can remove it.
    pub fn verify_payment_readiness(
        &self,
        funding: &Funding,
        receiver: &str,
        fee_input: &OutPoint,
        input_amount: Amount,
        fee: Amount,
        valid_through_height: u128,
    ) -> Result<()> {
        self.verify_confirmed_escrow(funding)?;
        require(
            receiver == funding.party_a || receiver == funding.party_b,
            "recipient is not a channel party",
        )?;
        let next_height = self
            .chain
            .height()
            .checked_add(1)
            .ok_or("candidate height overflow")?;
        let contest_end = next_height
            .checked_add(CONTEST_BLOCKS)
            .ok_or("candidate contest horizon overflow")?;
        require(
            valid_through_height >= contest_end,
            "challenge fee expires before contest horizon",
        )?;
        require(
            valid_through_height == u128::MAX,
            "protected receipt requires an unexpired challenge authorization",
        )?;
        require(!fee.is_zero(), "challenge fee must be positive")?;
        input_amount
            .checked_sub(fee)
            .map_err(|error| error.to_string())?;
        let reservation = self
            .chain
            .state()
            .reserved_challenge_fee(fee_input)
            .ok_or("challenge fee reservation absent on selected branch")?;
        let confirmations = self
            .chain
            .height()
            .checked_sub(reservation.reserved_height)
            .and_then(|n| n.checked_add(1))
            .ok_or("challenge fee reservation height mismatch")?;
        require(
            reservation.channel == funding.id()? && confirmations >= self.minimum_confirmations,
            "challenge fee reservation channel or confirmations mismatch",
        )?;
        self.require_finalized_height(reservation.reserved_height)?;
        let coin = &reservation.coin;
        require(
            coin.output.owner == receiver
                && coin.output.amount == input_amount
                && coin.spendable_height <= next_height,
            "challenge fee coin owner, amount or maturity mismatch",
        )
    }
}

impl ConfirmedEscrow for CandidateEscrowObservation<'_> {
    fn verify_confirmed_escrow(&self, funding: &Funding) -> Result<()> {
        require(
            funding.chain_id == self.chain.chain_id,
            "candidate escrow network mismatch",
        )?;
        let id = funding.id()?;
        let escrow = self
            .chain
            .state()
            .escrow(id)
            .ok_or("candidate escrow absent on selected branch")?;
        require(
            escrow.funding == *funding && escrow.phase == Phase::Open,
            "candidate escrow funding differs or has entered close",
        )?;
        let confirmations = self
            .chain
            .height()
            .checked_sub(escrow.opened_height)
            .and_then(|n| n.checked_add(1))
            .ok_or("candidate escrow height mismatch")?;
        require(
            confirmations >= self.minimum_confirmations,
            "candidate escrow below confirmation policy",
        )?;
        self.require_finalized_height(escrow.opened_height)
    }
}

pub mod checkpoint;
pub mod finality;
pub mod storage;

impl CandidateChain {
    pub fn from_replayed_pow_chain(v1: &Chain) -> Result<Self> {
        let anchor = v1.replay_anchor()?;
        let history = v1.best_blocks()?;
        let base_history = history
            .iter()
            .rev()
            .take(RETARGET_BLOCKS)
            .rev()
            .map(|block| Predecessor {
                height: block.header.height,
                timestamp: block.header.timestamp,
                target: block.header.target,
            })
            .collect::<Vec<_>>();
        let base_history = if base_history.is_empty() {
            require(
                v1.context.legacy_height == 0
                    && anchor.height() == 0
                    && v1.state().emitted == Amount::ZERO,
                "empty anchor must be a fresh zero-balance genesis",
            )?;
            vec![Predecessor {
                height: 0,
                timestamp: v1.context.started_at,
                target: v1.context.initial_target,
            }]
        } else {
            require(!v1.chainwork().is_zero(), "missing replayed PoW work")?;
            base_history
        };
        let base_state = Ledger::from_replayed_pow_chain(v1)?;
        Ok(Self {
            chain_id: anchor.chain_id(),
            v1_manifest_pin: v1.context.manifest_pin,
            v1_adoption_id: v1.context.transition_id,
            v1_tip: anchor.tip(),
            anchor_height: anchor.height(),
            legacy_height: v1.context.legacy_height,
            started_at: v1.context.started_at,
            base_work: v1.chainwork(),
            base_state,
            base_history,
            entries: BTreeMap::new(),
            tip: anchor.tip(),
            selected_state: None,
            side_state: None,
            finalized: None,
        })
    }

    pub fn tip(&self) -> Hash {
        self.tip
    }
    pub fn chain_id(&self) -> Hash {
        self.chain_id
    }
    /// Immutable value handoff derived from a fully replayed v1 selected tip.
    /// Candidate blocks cannot rewrite this base commitment.
    pub fn anchor_commitment(&self) -> Result<crate::Commitment> {
        self.base_state.commitment()
    }
    pub fn v1_tip(&self) -> Hash {
        self.v1_tip
    }
    pub fn height(&self) -> u128 {
        self.entries
            .get(&self.tip)
            .map_or(self.anchor_height, |e| e.block.header.height)
    }
    pub fn chainwork(&self) -> Work {
        self.entries
            .get(&self.tip)
            .map_or(self.base_work, |e| e.cumulative_work)
    }
    pub fn state(&self) -> &Ledger {
        self.selected_state.as_ref().unwrap_or(&self.base_state)
    }
    pub fn block(&self, id: Hash) -> Option<&Block> {
        self.entries.get(&id).map(|e| &e.block)
    }
    pub fn finalized(&self) -> Option<(Hash, u128)> {
        self.finalized
    }

    fn ancestor_at(&self, mut id: Hash, height: u128) -> Result<Hash> {
        loop {
            if id == self.v1_tip {
                require(
                    height == self.anchor_height,
                    "ancestor before successor cut",
                )?;
                return Ok(id);
            }
            let block = &self
                .entries
                .get(&id)
                .ok_or("missing successor ancestor")?
                .block;
            if block.header.height == height {
                return Ok(id);
            }
            require(
                block.header.height > height,
                "ancestor height exceeds branch",
            )?;
            id = block.header.parent;
        }
    }

    pub fn is_selected_ancestor(&self, id: Hash) -> Result<bool> {
        let height = self
            .entries
            .get(&id)
            .ok_or("unknown successor ancestor")?
            .block
            .header
            .height;
        Ok(self.ancestor_at(self.tip, height)? == id)
    }
    pub fn is_ancestor_of(&self, ancestor: Hash, descendant: Hash) -> Result<bool> {
        let height = self
            .entries
            .get(&ancestor)
            .ok_or("unknown source ancestor")?
            .block
            .header
            .height;
        Ok(self.ancestor_at(descendant, height)? == ancestor)
    }

    pub fn install_finality(&mut self, block: Hash) -> Result<()> {
        let height = self
            .entries
            .get(&block)
            .ok_or("unknown finality block")?
            .block
            .header
            .height;
        require(
            self.is_selected_ancestor(block)?,
            "finality block is not selected",
        )?;
        if let Some((prior, prior_height)) = self.finalized {
            require(
                height > prior_height && self.ancestor_at(block, prior_height)? == prior,
                "finality must extend prior immutable checkpoint",
            )?;
        }
        self.finalized = Some((block, height));
        Ok(())
    }
    pub fn best_blocks(&self) -> Result<Vec<&Block>> {
        let mut path = Vec::new();
        let mut current = self.tip;
        while current != self.v1_tip {
            let block = &self
                .entries
                .get(&current)
                .ok_or("missing best successor block")?
                .block;
            path.push(block);
            require(path.len() <= MAX_TRACKED_BLOCKS, "successor ancestry bound")?;
            current = block.header.parent;
        }
        path.reverse();
        Ok(path)
    }
    pub fn template_time(&self, now: u64) -> Result<u64> {
        let mut times = self
            .history_at(self.tip)?
            .iter()
            .rev()
            .take(11)
            .map(|entry| entry.timestamp)
            .collect::<Vec<_>>();
        if times.len() < 11 {
            times.push(self.started_at);
        }
        times.sort_unstable();
        Ok(now.max(times[times.len() / 2].saturating_add(1)))
    }

    fn state_at(&self, parent: Hash) -> Result<Ledger> {
        if parent == self.tip {
            return Ok(self.state().clone());
        }
        if parent == self.v1_tip {
            return Ok(self.base_state.clone());
        }
        if let Some((id, state)) = &self.side_state {
            if *id == parent {
                return Ok(state.clone());
            }
        }
        // Historical checkpoint queries and distant side branches reconstruct
        // their state from the fixed v1 anchor. Each retained block is checked
        // against its committed root; no old balance map is kept per entry.
        let mut path = Vec::new();
        let mut cursor = parent;
        while cursor != self.v1_tip {
            let entry = self
                .entries
                .get(&cursor)
                .ok_or("unknown successor parent")?;
            path.push(&entry.block);
            require(path.len() <= MAX_TRACKED_BLOCKS, "successor replay bound")?;
            cursor = entry.block.header.parent;
        }
        let mut state = self.base_state.clone();
        for block in path.into_iter().rev() {
            state = self.execute_from(state, &block.header, &block.commands)?;
            require(
                state.root()? == block.header.state_root,
                "replayed successor state root mismatch",
            )?;
        }
        Ok(state)
    }
    fn work_at(&self, parent: Hash) -> Result<Work> {
        if parent == self.v1_tip {
            return Ok(self.base_work);
        }
        self.entries
            .get(&parent)
            .map(|e| e.cumulative_work)
            .ok_or("unknown successor parent".into())
    }
    fn history_at(&self, mut parent: Hash) -> Result<Vec<Predecessor>> {
        let mut extension = Vec::new();
        while parent != self.v1_tip && extension.len() < RETARGET_BLOCKS {
            let entry = self
                .entries
                .get(&parent)
                .ok_or("unknown successor parent")?;
            extension.push(Predecessor {
                height: entry.block.header.height,
                timestamp: entry.block.header.timestamp,
                target: entry.block.header.target,
            });
            parent = entry.block.header.parent;
        }
        extension.reverse();
        let base_needed = RETARGET_BLOCKS - extension.len();
        let base_start = self.base_history.len().saturating_sub(base_needed);
        let mut result = self.base_history[base_start..].to_vec();
        result.extend(extension);
        Ok(result)
    }
    fn next_header(
        &self,
        parent: Hash,
        miner: String,
        timestamp: u64,
        commands: &[Command],
    ) -> Result<Header> {
        key(&miner)?;
        let history = self.history_at(parent)?;
        let last = history.last().ok_or("missing predecessor header")?;
        let height = last
            .height
            .checked_add(1)
            .ok_or("successor height overflow")?;
        let mut times = history
            .iter()
            .rev()
            .take(11)
            .map(|h| h.timestamp)
            .collect::<Vec<_>>();
        if times.len() < 11 {
            times.push(self.started_at);
        }
        times.sort_unstable();
        require(timestamp > times[times.len() / 2], "timestamp below median")?;
        let previous_count = last
            .height
            .checked_sub(self.legacy_height)
            .ok_or("height before PoW transition")?;
        let mut target = last.target;
        if previous_count > 0 && previous_count % RETARGET_BLOCKS as u128 == 0 {
            require(history.len() == RETARGET_BLOCKS, "missing retarget history")?;
            let begin = history[0].timestamp;
            let expected = (RETARGET_BLOCKS as u64 - 1) * BLOCK_SECONDS;
            let elapsed = last
                .timestamp
                .saturating_sub(begin)
                .clamp(expected / 4, expected * 4);
            target = scale_target(target, elapsed, expected)?;
        }
        Ok(Header {
            chain_id: self.chain_id,
            parent,
            height,
            timestamp,
            target,
            miner,
            commands_root: commands_root(commands)?,
            state_root: Hash::ZERO,
            nonce: 0,
        })
    }

    fn execute(&self, parent: Hash, header: &Header, commands: &[Command]) -> Result<Ledger> {
        self.execute_from(self.state_at(parent)?, header, commands)
    }

    fn execute_from(
        &self,
        mut next: Ledger,
        header: &Header,
        commands: &[Command],
    ) -> Result<Ledger> {
        for command in commands {
            match command {
                Command::Transfer(tx) => {
                    next.transfer(tx.clone(), header.height, &header.miner)?;
                }
                Command::Open(open) => {
                    next.open(open.clone(), header.height, &header.miner)?;
                }
                Command::ReserveChallengeFee(reservation) => {
                    next.reserve_challenge_fee(reservation.clone(), header.height)?;
                }
                Command::Close {
                    channel,
                    state,
                    fee,
                } => {
                    next.request_close_with_fee(
                        *channel,
                        state.clone(),
                        fee.clone(),
                        header.height,
                        &header.miner,
                    )?;
                }
                Command::Challenge {
                    channel,
                    state,
                    fee,
                } => {
                    next.challenge_with_fee(
                        *channel,
                        state.clone(),
                        fee.clone(),
                        header.height,
                        &header.miner,
                    )?;
                }
                Command::Finalize { channel } => {
                    next.finalize(*channel, header.height, &header.miner)?;
                }
                Command::Export(export) => {
                    next.export(export.clone(), header.height, &header.miner)?;
                }
            }
        }
        let sequence = header
            .height
            .checked_sub(self.legacy_height)
            .ok_or("height before PoW transition")?;
        require(
            next.emitted == Amount(cumulative_emission(sequence - 1)),
            "pre-reward emission mismatch",
        )?;
        let reward = subsidy(sequence)?;
        let coinbase_id = coinbase_id(header)?;
        next.output(
            coinbase_id,
            0,
            header.miner.clone(),
            reward,
            header
                .height
                .checked_add(COINBASE_MATURITY)
                .ok_or("reward maturity overflow")?,
        )?;
        next.emitted = next
            .emitted
            .checked_add(reward)
            .map_err(|e| e.to_string())?;
        require(
            next.emitted == Amount(cumulative_emission(sequence)),
            "noncanonical successor emission",
        )?;
        // Every caller checks the resulting root against a template or block
        // header. Recomputing it here would scan and validate the full UTXO
        // set twice for every new block.
        Ok(next)
    }

    pub fn template(&self, miner: String, timestamp: u64, commands: Vec<Command>) -> Result<Block> {
        let mut header = self.next_header(self.tip, miner, timestamp, &commands)?;
        header.state_root = self.execute(self.tip, &header, &commands)?.root()?;
        let block = Block { header, commands };
        require(
            serde_json::to_vec(&block).map_err(|e| e.to_string())?.len() <= MAX_BLOCK_BYTES,
            "successor block byte bound",
        )?;
        Ok(block)
    }

    /// Validate an entire candidate block before changing the in-memory best
    /// branch. Ties retain the already selected branch, as in PoW v1.
    pub fn accept(&mut self, block: Block, now: u64) -> Result<bool> {
        match self.prepare(block, now)? {
            Some(prepared) => Ok(self.commit(prepared)),
            None => Ok(false),
        }
    }

    pub(super) fn prepare(&self, block: Block, now: u64) -> Result<Option<Prepared>> {
        require(
            self.entries.len() < MAX_TRACKED_BLOCKS,
            "successor block capacity reached",
        )?;
        require(
            serde_json::to_vec(&block).map_err(|e| e.to_string())?.len() <= MAX_BLOCK_BYTES,
            "successor block byte bound",
        )?;
        require(
            block.header.timestamp <= now.checked_add(7200).ok_or("clock overflow")?,
            "future block timestamp",
        )?;
        let id = block.header.id()?;
        if self.entries.contains_key(&id) {
            return Ok(None);
        }
        let expected = self.next_header(
            block.header.parent,
            block.header.miner.clone(),
            block.header.timestamp,
            &block.commands,
        )?;
        if let Some((finalized, height)) = self.finalized {
            require(
                block.header.height > height
                    && self.ancestor_at(block.header.parent, height)? == finalized,
                "source fork conflicts with finalized checkpoint",
            )?;
        }
        require(
            block.header.chain_id == expected.chain_id
                && block.header.height == expected.height
                && block.header.target == expected.target
                && block.header.commands_root == expected.commands_root,
            "successor header or body mismatch",
        )?;
        require(block.header.work_valid()?, "insufficient successor work")?;
        let state = self.execute(block.header.parent, &block.header, &block.commands)?;
        require(
            state.root()? == block.header.state_root,
            "successor state root mismatch",
        )?;
        let work = self
            .work_at(block.header.parent)?
            .checked_add(header_work(block.header.target))
            .ok_or("successor chainwork overflow")?;
        require(
            work > self.work_at(block.header.parent)?,
            "zero successor work",
        )?;
        let preferred = work > self.chainwork();
        Ok(Some(Prepared {
            id,
            entry: Entry {
                block,
                cumulative_work: work,
            },
            state,
            preferred,
        }))
    }

    pub(super) fn commit(&mut self, prepared: Prepared) -> bool {
        self.entries.insert(prepared.id, prepared.entry);
        if prepared.preferred {
            self.side_state = self
                .selected_state
                .replace(prepared.state)
                .map(|state| (self.tip, state));
            self.tip = prepared.id;
        } else {
            self.side_state = Some((prepared.id, prepared.state));
        }
        prepared.preferred
    }

    fn best_ids(&self) -> Result<BTreeSet<Hash>> {
        let mut ids = BTreeSet::new();
        let mut current = self.tip;
        while current != self.v1_tip {
            require(ids.insert(current), "successor ancestry cycle")?;
            current = self
                .entries
                .get(&current)
                .ok_or("missing best successor block")?
                .block
                .header
                .parent;
        }
        Ok(ids)
    }

    /// Recheck one export against a fully replayed candidate source chain and
    /// an explicitly supplied observation policy. Returns no import authority.
    pub fn verify_export_on_best_chain(
        &self,
        proof: &ExportMembershipProof,
        checkpoint: Hash,
        policy: &ObservationPolicy,
    ) -> Result<()> {
        require(
            policy.source_chain_id == self.chain_id
                && policy.accepted_v1_tip == self.v1_tip
                && policy.minimum_confirmations >= 2
                && policy.minimum_cumulative_work > self.base_work,
            "unaccepted source observation policy",
        )?;
        require(
            self.best_ids()?.contains(&checkpoint),
            "checkpoint not on best candidate chain",
        )?;
        let entry = self
            .entries
            .get(&checkpoint)
            .ok_or("unknown successor checkpoint")?;
        let confirmations = self
            .height()
            .checked_sub(entry.block.header.height)
            .and_then(|n| n.checked_add(1))
            .ok_or("checkpoint height mismatch")?;
        require(
            confirmations >= policy.minimum_confirmations
                && entry.cumulative_work >= policy.minimum_cumulative_work,
            "insufficient source confirmations or work",
        )?;
        let record = proof.verify_in_claimed_state(entry.block.header.state_root)?;
        require(
            record.export_height <= entry.block.header.height
                && record.export_height > self.anchor_height,
            "export outside candidate checkpoint history",
        )?;
        require(
            self.state_at(checkpoint)?.export_record(record.id()?) == Some(&record),
            "export absent from replayed checkpoint state",
        )
    }

    /// Wrap one export from a replayed candidate checkpoint for bounded
    /// store-and-forward transport. The package itself is never proof of
    /// destination credit or of a stable source checkpoint.
    pub fn export_bundle(&self, export_id: Hash, checkpoint: Hash) -> Result<ProofBundle> {
        require(
            self.best_ids()?.contains(&checkpoint),
            "export checkpoint is not on best candidate chain",
        )?;
        let entry = self
            .entries
            .get(&checkpoint)
            .ok_or("unknown candidate export checkpoint")?;
        let proof = self.state_at(checkpoint)?.membership_proof(export_id)?;
        let intent = &proof.record.command.intent;
        let bytes = serde_json::to_vec(&proof).map_err(|error| error.to_string())?;
        ProofBundle::from_proof(
            self.chain_id,
            intent.destination_chain_id,
            export_id,
            checkpoint,
            entry.block.header.height,
            &bytes,
        )
    }

    /// Parse a courier package and recheck every route and checkpoint claim
    /// against a locally replayed source chain and caller-supplied policy.
    /// Returns only an observation; no destination balance is modified.
    pub fn observe_export_bundle(
        &self,
        bundle: &ProofBundle,
        policy: &ObservationPolicy,
    ) -> Result<ObservedExport> {
        let (proof, entry) = self.decode_export_bundle(bundle)?;
        self.verify_export_on_best_chain(&proof, bundle.source_checkpoint, policy)?;
        Ok(ObservedExport {
            record: proof.record,
            checkpoint: bundle.source_checkpoint,
            checkpoint_height: entry.block.header.height,
            checkpoint_work: entry.cumulative_work,
            confirmations: self.height() - entry.block.header.height + 1,
        })
    }

    fn decode_export_bundle(
        &self,
        bundle: &ProofBundle,
    ) -> Result<(ExportMembershipProof, &Entry)> {
        let bytes = bundle.proof()?;
        let proof: ExportMembershipProof =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        require(
            bytes == serde_json::to_vec(&proof).map_err(|error| error.to_string())?,
            "noncanonical unified export proof",
        )?;
        let entry = self
            .entries
            .get(&bundle.source_checkpoint)
            .ok_or("unknown bundled source checkpoint")?;
        let intent = &proof.record.command.intent;
        require(
            bundle.source_chain_id == self.chain_id
                && bundle.destination_chain_id == intent.destination_chain_id
                && bundle.export_id == proof.record.id()?
                && bundle.source_height == entry.block.header.height,
            "courier claims do not match replayed export",
        )?;
        Ok((proof, entry))
    }

    /// Check a stored historical checkpoint even if it has since been
    /// orphaned. Only durable import-log replay may use this; new credits
    /// must use `observe_export_bundle` on the current best branch.
    pub(crate) fn replay_known_export_bundle(&self, bundle: &ProofBundle) -> Result<ExportRecord> {
        let (proof, entry) = self.decode_export_bundle(bundle)?;
        let record = proof.verify_in_claimed_state(entry.block.header.state_root)?;
        require(
            record.export_height <= entry.block.header.height
                && record.export_height > self.anchor_height
                && self
                    .state_at(bundle.source_checkpoint)?
                    .export_record(record.id()?)
                    == Some(&record),
            "historical source export absent from replayed checkpoint",
        )?;
        Ok(record)
    }
}

fn coinbase_id(header: &Header) -> Result<Hash> {
    key(&header.miner)?;
    let mut bytes = b"RLD-EARTH-UNIFIED-SUCCESSOR-COINBASE\0".to_vec();
    bytes.extend(header.chain_id.0);
    bytes.extend(header.parent.0);
    bytes.extend(header.height.to_be_bytes());
    bytes.extend(hex::decode(&header.miner).map_err(|e| e.to_string())?);
    bytes.extend(header.commands_root.0);
    Ok(hash(&bytes))
}

/// Same bounded integer retarget arithmetic as regional PoW v1, applied to
/// the full v1-plus-candidate ancestry instead of resetting difficulty.
pub(crate) fn scale_target(target: Work, numerator: u64, denominator: u64) -> Result<Work> {
    require(denominator > 0, "zero retarget denominator")?;
    let mut wide = [0u64; 5];
    let mut carry = 0u128;
    for (index, limb) in target.0.iter().enumerate() {
        let product = *limb as u128 * numerator as u128 + carry;
        wide[index] = product as u64;
        carry = product >> 64;
    }
    wide[4] = carry as u64;
    let mut remainder = 0u128;
    for index in (0..5).rev() {
        let value = (remainder << 64) | wide[index] as u128;
        wide[index] = (value / denominator as u128) as u64;
        remainder = value % denominator as u128;
    }
    Ok(if wide[4] > 0 {
        target_limit()
    } else {
        Work(wide[..4].try_into().map_err(|_| "target limbs")?)
            .min(target_limit())
            .max(Work([1, 0, 0, 0]))
    })
}

#[cfg(test)]
mod tests;
