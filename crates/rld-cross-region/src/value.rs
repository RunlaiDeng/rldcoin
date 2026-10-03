//! Isolated successor rule model for one-way cross-region value movement.
//!
//! A source export permanently removes spendability and records the debit.
//! Destination import is deliberately private until a source-chain PoW proof
//! verifier exists. A courier bundle by itself never permits an import.

use crate::{hash, require, ProofBundle, Result};
use rld_core::{
    validate_ed25519_public_key, verify_bytes, AdmissionHash32 as Hash, Amount, TOTAL_SUPPLY_RUNLAI,
};
use rld_pow::{Chain, Coin, OutPoint, Output, State as V1State};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const MAX_EXPORT_RECORDS: usize = 1_000_000;

fn export_leaf(id: Hash, record: &ExportRecord) -> Result<Hash> {
    require(record.id()? == id, "export leaf identity mismatch")?;
    let mut bytes = b"RLD-EARTH-EXPORT-LEAF\0".to_vec();
    bytes.extend(id.0);
    bytes.extend(serde_json::to_vec(record).map_err(|e| e.to_string())?);
    Ok(hash(&bytes))
}

fn export_parent(left: Hash, right: Hash) -> Hash {
    let mut bytes = b"RLD-EARTH-EXPORT-PARENT\0".to_vec();
    bytes.extend(left.0);
    bytes.extend(right.0);
    hash(&bytes)
}

fn export_tree_root(mut level: Vec<Hash>) -> Hash {
    if level.is_empty() {
        return hash(b"RLD-EARTH-EXPORT-EMPTY\0");
    }
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| export_parent(pair[0], *pair.get(1).unwrap_or(&pair[0])))
            .collect();
    }
    level[0]
}

/// The state commitment can be compared with a source PoW header's state
/// root only after a separate light client has authenticated that header.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceCommitment {
    pub chain_id: Hash,
    pub v1_tip: Hash,
    pub v1_root: Hash,
    #[serde(with = "rld_pow::decimal")]
    pub anchor_height: u128,
    pub native_emitted: Amount,
    pub liquid: Amount,
    pub retired: Amount,
    pub coins_hash: Hash,
    pub export_root: Hash,
    pub export_count: u32,
}

impl SourceCommitment {
    pub fn root(&self) -> Result<Hash> {
        require(
            !self.chain_id.is_zero()
                && !self.v1_tip.is_zero()
                && !self.v1_root.is_zero()
                && !self.coins_hash.is_zero()
                && !self.export_root.is_zero()
                && self.native_emitted.0 <= TOTAL_SUPPLY_RUNLAI
                && self.export_count as usize <= MAX_EXPORT_RECORDS,
            "invalid source state commitment",
        )?;
        require(
            self.liquid
                .checked_add(self.retired)
                .map_err(|e| e.to_string())?
                == self.native_emitted,
            "source commitment supply mismatch",
        )?;
        let mut bytes = b"RLD-EARTH-EXPORT-STATE-SUCCESSOR\0".to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|e| e.to_string())?);
        Ok(hash(&bytes))
    }
}

/// A compact membership proof in a *claimed* source state. It verifies record
/// inclusion, not PoW chainwork, checkpoint adoption or reorg finality.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExportMembershipProof {
    pub state: SourceCommitment,
    pub record: ExportRecord,
    pub leaf_index: u32,
    pub leaf_count: u32,
    pub siblings: Vec<Hash>,
}

impl ExportMembershipProof {
    pub fn verify_in_claimed_state(&self, expected_state_root: Hash) -> Result<ExportRecord> {
        require(
            self.state.root()? == expected_state_root,
            "source state root mismatch",
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
            "export record outside source state",
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

fn public_key_bytes(key: &str) -> Result<[u8; 32]> {
    validate_ed25519_public_key(key)?;
    hex::decode(key)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "public key length".into())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExportIntent {
    pub source_chain_id: Hash,
    pub destination_chain_id: Hash,
    pub input: OutPoint,
    pub owner: String,
    pub recipient: String,
    pub amount: Amount,
    pub source_fee: Amount,
    pub destination_fee: Amount,
    pub change: Amount,
    #[serde(with = "rld_pow::decimal")]
    pub valid_through_height: u128,
}

impl ExportIntent {
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        require(
            !self.source_chain_id.is_zero()
                && !self.destination_chain_id.is_zero()
                && self.source_chain_id != self.destination_chain_id
                && !self.input.transaction.is_zero(),
            "invalid export route or input",
        )?;
        require(
            self.source_fee.0 >= 1
                && self.destination_fee.0 >= 1
                && self.amount.0 > self.destination_fee.0,
            "invalid export or fee",
        )?;
        let mut bytes = b"RLD-EARTH-EXPORT-SUCCESSOR\0".to_vec();
        bytes.extend(self.source_chain_id.0);
        bytes.extend(self.destination_chain_id.0);
        bytes.extend(self.input.transaction.0);
        bytes.extend(self.input.index.to_be_bytes());
        bytes.extend(public_key_bytes(&self.owner)?);
        bytes.extend(public_key_bytes(&self.recipient)?);
        bytes.extend(self.amount.0.to_be_bytes());
        bytes.extend(self.source_fee.0.to_be_bytes());
        bytes.extend(self.destination_fee.0.to_be_bytes());
        bytes.extend(self.change.0.to_be_bytes());
        bytes.extend(self.valid_through_height.to_be_bytes());
        Ok(bytes)
    }

    pub fn id(&self) -> Result<Hash> {
        Ok(hash(&self.signing_bytes()?))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExportCommand {
    pub intent: ExportIntent,
    pub owner_signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExportRecord {
    pub command: ExportCommand,
    #[serde(with = "rld_pow::decimal")]
    pub export_height: u128,
}

impl ExportRecord {
    pub fn id(&self) -> Result<Hash> {
        let intent = &self.command.intent;
        verify_bytes(
            &intent.owner,
            &intent.signing_bytes()?,
            &self.command.owner_signature,
        )?;
        require(
            self.export_height <= intent.valid_through_height,
            "export height past signed expiry",
        )?;
        intent.id()
    }
}

/// The source's `retired` amount is a permanent, nonspendable debit. There is
/// intentionally no timeout refund: delayed or lost proofs cannot make a
/// source coin spendable again while a destination import remains possible.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceLedger {
    chain_id: Hash,
    v1_tip: Hash,
    v1_root: Hash,
    anchor_height: u128,
    coins: BTreeMap<OutPoint, Coin>,
    exports: BTreeMap<Hash, ExportRecord>,
    native_emitted: Amount,
}

impl SourceLedger {
    /// Start from a replayed PoW best-chain state and its exact header root.
    /// This does not authenticate a future export checkpoint or activate value.
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
            "unmatched source snapshot",
        )?;
        let next = Self {
            chain_id,
            v1_tip,
            v1_root: expected_root,
            anchor_height,
            coins: v1.coins.clone(),
            exports: BTreeMap::new(),
            native_emitted: v1.emitted,
        };
        next.root()?;
        Ok(next)
    }

    pub fn coin(&self, point: &OutPoint) -> Option<&Coin> {
        self.coins.get(point)
    }
    pub fn export_record(&self, id: Hash) -> Option<&ExportRecord> {
        self.exports.get(&id)
    }
    pub fn retired(&self) -> Result<Amount> {
        self.exports.values().try_fold(Amount::ZERO, |sum, record| {
            sum.checked_add(record.command.intent.amount)
                .map_err(|e| e.to_string())
        })
    }
    pub fn liquid(&self) -> Result<Amount> {
        self.coins.values().try_fold(Amount::ZERO, |sum, coin| {
            sum.checked_add(coin.output.amount)
                .map_err(|e| e.to_string())
        })
    }

    pub fn root(&self) -> Result<Hash> {
        self.commitment()?.root()
    }

    pub fn commitment(&self) -> Result<SourceCommitment> {
        let liquid = self.liquid()?;
        for coin in self.coins.values() {
            require(!coin.output.amount.is_zero(), "zero source coin")?;
            public_key_bytes(&coin.output.owner)?;
        }
        for (id, record) in &self.exports {
            require(
                record.id()? == *id
                    && record.command.intent.source_chain_id == self.chain_id
                    && record.export_height > self.anchor_height,
                "invalid source export record",
            )?;
        }
        require(
            liquid
                .checked_add(self.retired()?)
                .map_err(|e| e.to_string())?
                == self.native_emitted,
            "source supply conservation failed",
        )?;
        require(
            self.exports.len() <= MAX_EXPORT_RECORDS,
            "export index capacity reached",
        )?;
        let mut coin_bytes = b"RLD-EARTH-EXPORT-LIQUID-COINS\0".to_vec();
        coin_bytes.extend(
            serde_json::to_vec(&self.coins.iter().collect::<Vec<_>>())
                .map_err(|e| e.to_string())?,
        );
        let leaves = self
            .exports
            .iter()
            .map(|(id, record)| export_leaf(*id, record))
            .collect::<Result<Vec<_>>>()?;
        Ok(SourceCommitment {
            chain_id: self.chain_id,
            v1_tip: self.v1_tip,
            v1_root: self.v1_root,
            anchor_height: self.anchor_height,
            native_emitted: self.native_emitted,
            liquid,
            retired: self.retired()?,
            coins_hash: hash(&coin_bytes),
            export_root: export_tree_root(leaves),
            export_count: self.exports.len() as u32,
        })
    }

    pub fn membership_proof(&self, id: Hash) -> Result<ExportMembershipProof> {
        let index = self
            .exports
            .keys()
            .position(|key| *key == id)
            .ok_or("unknown source export")?;
        let record = self
            .exports
            .get(&id)
            .ok_or("unknown source export")?
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
            "source chain, height or expiry mismatch",
        )?;
        public_key_bytes(miner)?;
        verify_bytes(
            &intent.owner,
            &intent.signing_bytes()?,
            &command.owner_signature,
        )?;
        let id = intent.id()?;
        require(!self.exports.contains_key(&id), "duplicate export")?;
        let coin = self
            .coins
            .get(&intent.input)
            .ok_or("export input missing or spent")?;
        require(
            coin.output.owner == intent.owner && coin.spendable_height <= height,
            "export input owner or maturity mismatch",
        )?;
        let needed = intent
            .amount
            .checked_add(intent.source_fee)
            .and_then(|n| n.checked_add(intent.change))
            .map_err(|e| e.to_string())?;
        require(
            needed == coin.output.amount,
            "export does not conserve input",
        )?;
        let mut next = self.clone();
        next.coins.remove(&intent.input);
        if !intent.change.is_zero() {
            require(
                next.coins
                    .insert(
                        OutPoint {
                            transaction: id,
                            index: 1,
                        },
                        Coin {
                            output: Output {
                                owner: intent.owner.clone(),
                                amount: intent.change,
                            },
                            spendable_height: height,
                        },
                    )
                    .is_none(),
                "source change collision",
            )?;
        }
        require(
            next.coins
                .insert(
                    OutPoint {
                        transaction: id,
                        index: 2,
                    },
                    Coin {
                        output: Output {
                            owner: miner.into(),
                            amount: intent.source_fee,
                        },
                        spendable_height: height,
                    },
                )
                .is_none(),
            "source fee collision",
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

/// Import rules remain inaccessible to external callers: there is no
/// production source-header/checkpoint verifier to create `CertifiedExport`.
#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct DestinationLedger {
    chain_id: Hash,
    v1_tip: Hash,
    v1_root: Hash,
    anchor_height: u128,
    coins: BTreeMap<OutPoint, Coin>,
    imported: BTreeMap<(Hash, Hash), CertifiedExport>,
    native_emitted: Amount,
    imported_total: Amount,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct CertifiedExport {
    record: ExportRecord,
    source_checkpoint: Hash,
    source_state_root: Hash,
    #[serde(with = "rld_pow::decimal")]
    checkpoint_height: u128,
    proof_sha256: Hash,
}

impl CertifiedExport {
    /// `trusted_state_root` must come from a future authenticated source PoW
    /// checkpoint. This private constructor does not authenticate that root.
    fn from_membership(
        proof: &ExportMembershipProof,
        trusted_state_root: Hash,
        source_checkpoint: Hash,
        checkpoint_height: u128,
        proof_sha256: Hash,
    ) -> Result<Self> {
        require(
            !source_checkpoint.is_zero()
                && !proof_sha256.is_zero()
                && checkpoint_height >= proof.record.export_height,
            "invalid source checkpoint claim",
        )?;
        let record = proof.verify_in_claimed_state(trusted_state_root)?;
        Ok(Self {
            record,
            source_checkpoint,
            source_state_root: trusted_state_root,
            checkpoint_height,
            proof_sha256,
        })
    }
}

#[allow(dead_code)]
impl DestinationLedger {
    fn from_v1_snapshot(
        chain_id: Hash,
        v1: &V1State,
        v1_tip: Hash,
        expected_root: Hash,
        anchor_height: u128,
    ) -> Result<Self> {
        require(
            !chain_id.is_zero() && !v1_tip.is_zero() && v1.root()? == expected_root,
            "unmatched destination snapshot",
        )?;
        require(
            v1.emitted == Amount::ZERO && v1.coins.is_empty(),
            "destination cannot duplicate the Earth issuance reserve",
        )?;
        let ledger = Self {
            chain_id,
            v1_tip,
            v1_root: expected_root,
            anchor_height,
            coins: v1.coins.clone(),
            imported: BTreeMap::new(),
            native_emitted: v1.emitted,
            imported_total: Amount::ZERO,
        };
        ledger.root()?;
        Ok(ledger)
    }

    fn root(&self) -> Result<Hash> {
        let total = self.coins.values().try_fold(Amount::ZERO, |sum, coin| {
            require(!coin.output.amount.is_zero(), "zero destination coin")?;
            public_key_bytes(&coin.output.owner)?;
            sum.checked_add(coin.output.amount)
                .map_err(|e| e.to_string())
        })?;
        require(
            self.native_emitted
                .checked_add(self.imported_total)
                .map_err(|e| e.to_string())?
                == total
                && total.0 <= TOTAL_SUPPLY_RUNLAI,
            "destination supply conservation failed",
        )?;
        let recorded = self
            .imported
            .iter()
            .try_fold(Amount::ZERO, |sum, (key, certificate)| {
                let intent = &certificate.record.command.intent;
                require(
                    *key == (intent.source_chain_id, certificate.record.id()?)
                        && intent.destination_chain_id == self.chain_id
                        && certificate.checkpoint_height >= certificate.record.export_height
                        && !certificate.source_checkpoint.is_zero()
                        && !certificate.source_state_root.is_zero()
                        && !certificate.proof_sha256.is_zero(),
                    "invalid import record",
                )?;
                sum.checked_add(certificate.record.command.intent.amount)
                    .map_err(|e| e.to_string())
            })?;
        require(recorded == self.imported_total, "imported amount mismatch")?;
        #[derive(Serialize)]
        struct Commitment<'a> {
            chain_id: &'a Hash,
            v1_tip: &'a Hash,
            v1_root: &'a Hash,
            #[serde(with = "rld_pow::decimal")]
            anchor_height: u128,
            native_emitted: &'a Amount,
            imported_total: &'a Amount,
            coins: Vec<(&'a OutPoint, &'a Coin)>,
            imports: Vec<(&'a (Hash, Hash), &'a CertifiedExport)>,
        }
        let value = Commitment {
            chain_id: &self.chain_id,
            v1_tip: &self.v1_tip,
            v1_root: &self.v1_root,
            anchor_height: self.anchor_height,
            native_emitted: &self.native_emitted,
            imported_total: &self.imported_total,
            coins: self.coins.iter().collect(),
            imports: self.imported.iter().collect(),
        };
        let mut bytes = b"RLD-EARTH-IMPORT-STATE-SUCCESSOR\0".to_vec();
        bytes.extend(serde_json::to_vec(&value).map_err(|e| e.to_string())?);
        Ok(hash(&bytes))
    }

    fn import_certified(
        &mut self,
        bundle: &ProofBundle,
        certificate: CertifiedExport,
        height: u128,
        miner: &str,
    ) -> Result<()> {
        bundle.validate()?;
        public_key_bytes(miner)?;
        let proof_bytes = bundle.proof()?;
        let membership: ExportMembershipProof =
            serde_json::from_slice(&proof_bytes).map_err(|e| e.to_string())?;
        require(
            proof_bytes == serde_json::to_vec(&membership).map_err(|e| e.to_string())?,
            "noncanonical export membership proof",
        )?;
        let checked = CertifiedExport::from_membership(
            &membership,
            certificate.source_state_root,
            certificate.source_checkpoint,
            certificate.checkpoint_height,
            certificate.proof_sha256,
        )?;
        let intent = &certificate.record.command.intent;
        let id = certificate.record.id()?;
        require(
            height > self.anchor_height
                && checked == certificate
                && bundle.proof_sha256 == certificate.proof_sha256
                && bundle.source_chain_id == intent.source_chain_id
                && bundle.destination_chain_id == self.chain_id
                && intent.destination_chain_id == self.chain_id
                && bundle.export_id == id
                && bundle.source_checkpoint == certificate.source_checkpoint
                && bundle.source_height == certificate.checkpoint_height
                && certificate.checkpoint_height >= certificate.record.export_height
                && !certificate.source_checkpoint.is_zero(),
            "import certificate mismatch",
        )?;
        let key = (intent.source_chain_id, id);
        require(!self.imported.contains_key(&key), "export already imported")?;
        let recipient_amount = intent
            .amount
            .checked_sub(intent.destination_fee)
            .map_err(|e| e.to_string())?;
        require(!recipient_amount.is_zero(), "empty recipient import")?;
        let mut bytes = b"RLD-EARTH-IMPORT-OUTPUT-SUCCESSOR\0".to_vec();
        bytes.extend(intent.source_chain_id.0);
        bytes.extend(id.0);
        bytes.extend(self.chain_id.0);
        let tx_id = hash(&bytes);
        let mut next = self.clone();
        require(
            next.coins
                .insert(
                    OutPoint {
                        transaction: tx_id,
                        index: 0,
                    },
                    Coin {
                        output: Output {
                            owner: intent.recipient.clone(),
                            amount: recipient_amount,
                        },
                        spendable_height: height,
                    },
                )
                .is_none(),
            "recipient import collision",
        )?;
        require(
            next.coins
                .insert(
                    OutPoint {
                        transaction: tx_id,
                        index: 1,
                    },
                    Coin {
                        output: Output {
                            owner: miner.into(),
                            amount: intent.destination_fee,
                        },
                        spendable_height: height,
                    },
                )
                .is_none(),
            "destination fee collision",
        )?;
        next.imported_total = next
            .imported_total
            .checked_add(intent.amount)
            .map_err(|e| e.to_string())?;
        next.imported.insert(key, certificate);
        next.root()?;
        *self = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
