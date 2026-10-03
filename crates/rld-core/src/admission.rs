//! Assetless, rewardless R7.2 permissionless-admission log primitives.
//!
//! This module deliberately has no `Amount`, `Coin`, reward, stake, validator
//! weight, or `ConsensusCommand` dependency.  It validates the three admission
//! wire objects, cumulative-work fork choice, confirmed checkpoint batches and
//! the local fail-closed `CENSORSHIP_STALLED` guard.  Tags 28 through 35 remain
//! absent from runtime dispatch; later gates must integrate these primitives
//! atomically with Ledger, WAL, signer and witness state.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

use crate::{
    crypto::{validate_ed25519_public_key, verify_bytes},
    ZoneDescriptor,
};

pub const BASELINE_ACCESS_WORK_SCHEMA_V1: u16 = 0x1064;
pub const PERMISSIONLESS_ADMISSION_ENTRY_SCHEMA_V1: u16 = 0x1065;
pub const PERMISSIONLESS_ADMISSION_HEADER_SCHEMA_V1: u16 = 0x1066;
pub const ADMISSION_CHECKPOINT_SCHEMA_V1: u16 = 0x106e;
pub const ADMISSION_CHECKPOINT_PROOF_SCHEMA_V1: u16 = 0x1071;

#[cfg(test)]
#[path = "admission/censorship_recovery_tests.rs"]
mod censorship_recovery_tests;

pub const ADMISSION_ACCESS_WORK_SUITE_V1: u16 = 1;
pub const MAX_ADMISSION_HEADER_WIRE_BYTES: usize = 4 * 1024;
pub const MAX_ADMISSION_ENTRY_WIRE_BYTES: usize = 2 * 1024;
pub const MAX_ADMISSION_ENTRIES_PER_HEADER: usize = 256;
pub const MAX_ADMISSION_BATCH_BODY_BYTES: usize = 512 * 1024;
pub const MAX_ADMISSION_SIDECAR_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_ADMISSION_CHECKPOINT_AVAILABILITY_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_PENDING_ADMISSION_ENTRIES: usize = 65_536;
pub const MAX_CHECKPOINT_ENTRIES_PER_LEDGER_BLOCK: usize = 512;
pub const MIN_ADMISSION_CONFIRMATIONS: usize = 32;
pub const MAX_ADMISSION_CONFIRMATION_HEADERS: usize = 512;
pub const MAX_ADMISSION_CHECKPOINT_PROOF_WIRE_BYTES: usize = 1024 * 1024;
pub const MAX_ADMISSION_LAG_EPOCHS: u128 = 2;
pub const MAX_PENDING_ADMISSION_TARGETS: usize = 4;

const RLD_WIRE_MAGIC: &[u8; 4] = b"RLDW";
const RLD_WIRE_VERSION_V1: u16 = 1;
const KIND_TEXT: u8 = 1;
const KIND_U8: u8 = 2;
const KIND_U16: u8 = 3;
const KIND_U64: u8 = 4;
const KIND_U128: u8 = 5;
const KIND_HASH32: u8 = 6;
const KIND_BYTES32: u8 = 7;
const KIND_BYTES: u8 = 9;
const SUBJECT_DOMAIN: &[u8] = b"RLD-SUBJECT-HASH-PREIMAGE-V1";
const ACCESS_WORK_DOMAIN: &[u8] = b"RLD-ADMISSION-ACCESS-WORK-V1";
const EMPTY_ENTRY_ROOT_DOMAIN: &[u8] = b"RLD-EMPTY-ADMISSION-MERKLE-V1";
const EMPTY_AVAILABILITY_ROOT_DOMAIN: &[u8] = b"RLD-EMPTY-ADMISSION-AVAILABILITY-MERKLE-V1";
const CENSORSHIP_EVENT_DOMAIN: &[u8] = b"RLD-CENSORSHIP-EVENT-V1";
const ADMISSION_GENESIS_DOMAIN: &[u8] = b"RLD-PERMISSIONLESS-ADMISSION-GENESIS-V1";
const EMPTY_CHECKPOINT_ACCUMULATOR_DOMAIN: &[u8] = b"RLD-EMPTY-ADMISSION-CHECKPOINT-ACCUMULATOR-V1";
const CHECKPOINT_ACCUMULATOR_SUCCESSOR_DOMAIN: &[u8] =
    b"RLD-ADMISSION-CHECKPOINT-ACCUMULATOR-SUCCESSOR-V1";
const EMPTY_LEDGER_CONTROL_ACCUMULATOR_DOMAIN: &[u8] =
    b"RLD-EMPTY-ADMISSION-LEDGER-CONTROL-ACCUMULATOR-V1";
const LEDGER_CONTROL_FACT_DOMAIN: &[u8] = b"RLD-ADMISSION-LEDGER-CONTROL-FACT-V1";
const LEDGER_CONTROL_ACCUMULATOR_SUCCESSOR_DOMAIN: &[u8] =
    b"RLD-ADMISSION-LEDGER-CONTROL-ACCUMULATOR-SUCCESSOR-V1";
const CHECKPOINT_BATCH_SEGMENT_DOMAIN: &[u8] = b"RLD-ADMISSION-CHECKPOINT-BATCH-SEGMENT-V1";
const CHECKPOINT_CONFIRMATION_SEGMENT_DOMAIN: &[u8] =
    b"RLD-ADMISSION-CHECKPOINT-CONFIRMATION-SEGMENT-V1";
const SIDECAR_PAYLOAD_DOMAIN: &[u8] = b"RLD-ADMISSION-SIDECAR-PAYLOAD-V1";
const SIDECAR_LOCATOR_DOMAIN: &[u8] = b"RLD-ADMISSION-CONTENT-LOCATOR-V1";
pub const LEDGER_ADMISSION_STATE_VERSION_V1: &str = "RLD-LEDGER-ADMISSION-STATE-V1";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AdmissionHash32(pub [u8; 32]);

impl AdmissionHash32 {
    pub const ZERO: Self = Self([0; 32]);

    pub fn from_hex(value: &str) -> Result<Self, AdmissionError> {
        let decoded = hex::decode(value).map_err(|_| {
            AdmissionError::NonCanonicalWire("expected lowercase 32-byte hexadecimal value".into())
        })?;
        let bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|_| AdmissionError::NonCanonicalWire("expected exactly 32 bytes".into()))?;
        if hex::encode(bytes) != value {
            return Err(AdmissionError::NonCanonicalWire(
                "hexadecimal value must be lowercase canonical text".into(),
            ));
        }
        Ok(Self(bytes))
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    pub fn is_zero(self) -> bool {
        self == Self::ZERO
    }
}

impl Serialize for AdmissionHash32 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for AdmissionHash32 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_hex(&value).map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AdmissionSignature64(pub [u8; 64]);

impl Serialize for AdmissionSignature64 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for AdmissionSignature64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let decoded = hex::decode(&value).map_err(de::Error::custom)?;
        let bytes: [u8; 64] = decoded
            .try_into()
            .map_err(|_| de::Error::custom("expected exactly 64 signature bytes"))?;
        if hex::encode(bytes) != value {
            return Err(de::Error::custom(
                "signature hexadecimal value must be lowercase canonical text",
            ));
        }
        Ok(Self(bytes))
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct AdmissionWork(pub [u64; 4]);

impl Ord for AdmissionWork {
    fn cmp(&self, other: &Self) -> Ordering {
        for index in (0..4).rev() {
            match self.0[index].cmp(&other.0[index]) {
                Ordering::Equal => {}
                ordering => return ordering,
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for AdmissionWork {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl AdmissionWork {
    pub const ZERO: Self = Self([0; 4]);
    pub const MAX: Self = Self([u64::MAX; 4]);

    pub fn from_be_bytes(bytes: [u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for (index, chunk) in bytes.as_chunks::<8>().0.iter().enumerate() {
            limbs[3 - index] = u64::from_be_bytes(*chunk);
        }
        Self(limbs)
    }

    pub fn to_be_bytes(self) -> [u8; 32] {
        let mut result = [0u8; 32];
        for (index, limb) in self.0.iter().rev().enumerate() {
            result[index * 8..(index + 1) * 8].copy_from_slice(&limb.to_be_bytes());
        }
        result
    }

    pub fn from_hex(value: &str) -> Result<Self, AdmissionError> {
        let hash = AdmissionHash32::from_hex(value)?;
        Ok(Self::from_be_bytes(hash.0))
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.to_be_bytes())
    }

    pub fn is_zero(self) -> bool {
        self == Self::ZERO
    }

    pub fn checked_add(self, other: Self) -> Option<Self> {
        let mut result = [0u64; 4];
        let mut carry = 0u128;
        for (index, slot) in result.iter_mut().enumerate() {
            let sum = self.0[index] as u128 + other.0[index] as u128 + carry;
            *slot = sum as u64;
            carry = sum >> 64;
        }
        (carry == 0).then_some(Self(result))
    }

    fn checked_add_one(self) -> Option<Self> {
        self.checked_add(Self([1, 0, 0, 0]))
    }

    fn div_u64(self, denominator: u64) -> Self {
        debug_assert_ne!(denominator, 0);
        let mut quotient = [0u64; 4];
        let mut remainder = 0u128;
        for index in (0..4).rev() {
            let dividend = (remainder << 64) | self.0[index] as u128;
            quotient[index] = (dividend / denominator as u128) as u64;
            remainder = dividend % denominator as u128;
        }
        Self(quotient)
    }

    fn set_bit(&mut self, index: usize) {
        self.0[index / 64] |= 1u64 << (index % 64);
    }
}

impl Serialize for AdmissionWork {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for AdmissionWork {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_hex(&value).map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct WideWork([u64; 8]);

impl Ord for WideWork {
    fn cmp(&self, other: &Self) -> Ordering {
        for index in (0..8).rev() {
            match self.0[index].cmp(&other.0[index]) {
                Ordering::Equal => {}
                ordering => return ordering,
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for WideWork {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl WideWork {
    fn from_u256(value: AdmissionWork) -> Self {
        let mut result = [0u64; 8];
        result[..4].copy_from_slice(&value.0);
        Self(result)
    }

    fn multiply_u64(value: AdmissionWork, multiplier: u64) -> Self {
        let mut result = [0u64; 8];
        let mut carry = 0u128;
        for (index, limb) in value.0.iter().enumerate() {
            let product = *limb as u128 * multiplier as u128 + carry;
            result[index] = product as u64;
            carry = product >> 64;
        }
        result[4] = carry as u64;
        Self(result)
    }

    fn div_u64(self, denominator: u64) -> Self {
        debug_assert_ne!(denominator, 0);
        let mut result = [0u64; 8];
        let mut remainder = 0u128;
        for index in (0..8).rev() {
            let dividend = (remainder << 64) | self.0[index] as u128;
            result[index] = (dividend / denominator as u128) as u64;
            remainder = dividend % denominator as u128;
        }
        Self(result)
    }

    fn to_u256(self) -> Option<AdmissionWork> {
        if self.0[4..].iter().any(|limb| *limb != 0) {
            return None;
        }
        Some(AdmissionWork(self.0[..4].try_into().expect("four limbs")))
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AdmissionError {
    #[error("ERR_ENVELOPE_LIMIT: {0}")]
    EnvelopeLimit(String),
    #[error("ERR_NON_CANONICAL_WIRE: {0}")]
    NonCanonicalWire(String),
    #[error("ERR_CONTEXT_MISMATCH: {0}")]
    ContextMismatch(String),
    #[error("ERR_PARENT_OR_PRESTATE: {0}")]
    ParentOrPrestate(String),
    #[error("ERR_AUTHENTICATION: {0}")]
    Authentication(String),
    #[error("ERR_RESOURCE_OR_AVAILABILITY: {0}")]
    ResourceOrAvailability(String),
    #[error("ERR_DUPLICATE_OR_NULLIFIER: {0}")]
    DuplicateOrNullifier(String),
    #[error("ERR_PROGRAM_OR_WINDOW: {0}")]
    ProgramOrWindow(String),
    #[error("ERR_WORK_OR_PROOF: {0}")]
    WorkOrProof(String),
    #[error("ERR_TRANSITION_OR_VALUE_CAP: {0}")]
    TransitionOrValueCap(String),
}

impl AdmissionError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::EnvelopeLimit(_) => "ERR_ENVELOPE_LIMIT",
            Self::NonCanonicalWire(_) => "ERR_NON_CANONICAL_WIRE",
            Self::ContextMismatch(_) => "ERR_CONTEXT_MISMATCH",
            Self::ParentOrPrestate(_) => "ERR_PARENT_OR_PRESTATE",
            Self::Authentication(_) => "ERR_AUTHENTICATION",
            Self::ResourceOrAvailability(_) => "ERR_RESOURCE_OR_AVAILABILITY",
            Self::DuplicateOrNullifier(_) => "ERR_DUPLICATE_OR_NULLIFIER",
            Self::ProgramOrWindow(_) => "ERR_PROGRAM_OR_WINDOW",
            Self::WorkOrProof(_) => "ERR_WORK_OR_PROOF",
            Self::TransitionOrValueCap(_) => "ERR_TRANSITION_OR_VALUE_CAP",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdmissionContextV1 {
    pub network_domain: String,
    pub zone_id: String,
    pub currency_genesis: AdmissionHash32,
    pub protocol_era: u128,
    pub crypto_era: u128,
}

impl AdmissionContextV1 {
    pub fn validate(&self) -> Result<(), AdmissionError> {
        validate_text(&self.network_domain, "network_domain")?;
        validate_text(&self.zone_id, "zone_id")?;
        if self.network_domain.len() > 255 || self.zone_id.len() > 255 {
            return Err(AdmissionError::EnvelopeLimit(
                "network_domain and zone_id are limited to 255 UTF-8 bytes".into(),
            ));
        }
        if self.currency_genesis.is_zero() {
            return Err(AdmissionError::ContextMismatch(
                "currency genesis cannot be zero".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdmissionEntryKindV1 {
    Participation,
    Result,
    AvailabilityRefresh,
}

impl AdmissionEntryKindV1 {
    const fn code(self) -> u8 {
        match self {
            Self::Participation => 1,
            Self::Result => 2,
            Self::AvailabilityRefresh => 3,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PermissionlessAdmissionEntryV1 {
    pub context: AdmissionContextV1,
    pub kind: AdmissionEntryKindV1,
    pub participant_key: AdmissionHash32,
    pub owner_commitment: AdmissionHash32,
    pub program_id: AdmissionHash32,
    pub challenge_id: Option<AdmissionHash32>,
    pub payload_commitment: AdmissionHash32,
    pub locator_commitment: AdmissionHash32,
    pub declared_bytes: u64,
    pub expiry_height: u128,
    pub entry_signature: AdmissionSignature64,
}

impl PermissionlessAdmissionEntryV1 {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.encode(true)
    }

    pub fn signing_subject(&self) -> AdmissionHash32 {
        subject_id(&self.encode(false))
    }

    pub fn entry_id(&self) -> AdmissionHash32 {
        subject_id(&self.canonical_bytes())
    }

    pub fn validate(
        &self,
        expected: &AdmissionContextV1,
        anchor_height: u128,
    ) -> Result<(), AdmissionError> {
        validate_context(&self.context, expected)?;
        match (self.kind, self.challenge_id) {
            (AdmissionEntryKindV1::Participation, None)
            | (AdmissionEntryKindV1::Result, Some(_))
            | (AdmissionEntryKindV1::AvailabilityRefresh, Some(_)) => {}
            _ => {
                return Err(AdmissionError::NonCanonicalWire(
                    "entry kind and challenge_id conditional presence disagree".into(),
                ));
            }
        }
        if self.participant_key.is_zero()
            || self.owner_commitment.is_zero()
            || self.program_id.is_zero()
            || self.payload_commitment.is_zero()
            || self.locator_commitment.is_zero()
        {
            return Err(AdmissionError::NonCanonicalWire(
                "entry commitments and participant key must be nonzero".into(),
            ));
        }
        if self.declared_bytes > MAX_ADMISSION_SIDECAR_BYTES {
            return Err(AdmissionError::EnvelopeLimit(
                "declared entry sidecar exceeds 8 MiB".into(),
            ));
        }
        if self.expiry_height < anchor_height {
            return Err(AdmissionError::ProgramOrWindow(
                "admission entry expired before its ledger anchor".into(),
            ));
        }
        let wire = self.canonical_bytes();
        if wire.len() > MAX_ADMISSION_ENTRY_WIRE_BYTES {
            return Err(AdmissionError::EnvelopeLimit(
                "admission entry wire exceeds 2 KiB".into(),
            ));
        }
        let key_hex = self.participant_key.to_hex();
        validate_ed25519_public_key(&key_hex).map_err(AdmissionError::Authentication)?;
        verify_bytes(
            &key_hex,
            &self.signing_subject().0,
            &hex::encode(self.entry_signature.0),
        )
        .map_err(AdmissionError::Authentication)
    }

    fn encode(&self, include_signature: bool) -> Vec<u8> {
        let mut fields = common_fields(&self.context);
        fields.push(field(10, KIND_U8, vec![self.kind.code()]));
        fields.push(field(11, KIND_BYTES32, self.participant_key.0.to_vec()));
        fields.push(field(12, KIND_HASH32, self.owner_commitment.0.to_vec()));
        fields.push(field(13, KIND_HASH32, self.program_id.0.to_vec()));
        if let Some(challenge_id) = self.challenge_id {
            fields.push(field(14, KIND_HASH32, challenge_id.0.to_vec()));
        }
        fields.push(field(15, KIND_HASH32, self.payload_commitment.0.to_vec()));
        fields.push(field(16, KIND_HASH32, self.locator_commitment.0.to_vec()));
        fields.push(field(
            17,
            KIND_U64,
            self.declared_bytes.to_be_bytes().to_vec(),
        ));
        fields.push(field(
            18,
            KIND_U128,
            self.expiry_height.to_be_bytes().to_vec(),
        ));
        if include_signature {
            fields.push(field(19, KIND_BYTES, self.entry_signature.0.to_vec()));
        }
        wire_object(PERMISSIONLESS_ADMISSION_ENTRY_SCHEMA_V1, fields)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BaselineAccessWorkV1 {
    pub context: AdmissionContextV1,
    pub parent_header: AdmissionHash32,
    pub ledger_anchor_block: AdmissionHash32,
    pub ledger_anchor_height: u128,
    pub entries_root: AdmissionHash32,
    pub entries_count: u16,
    pub suite_id: u16,
    pub target: AdmissionWork,
    pub nonce: u128,
    pub output_hash: AdmissionHash32,
    pub expiry_anchor_height: u128,
}

impl BaselineAccessWorkV1 {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.encode(true)
    }

    pub fn work_id(&self) -> AdmissionHash32 {
        subject_id(&self.canonical_bytes())
    }

    pub fn recompute_output_hash(&self) -> AdmissionHash32 {
        let mut hasher = Sha256::new();
        hasher.update(ACCESS_WORK_DOMAIN);
        hasher.update([0]);
        hasher.update(self.encode(false));
        AdmissionHash32(hasher.finalize().into())
    }

    pub fn header_work(&self) -> AdmissionWork {
        header_work(self.target)
    }

    fn encode(&self, include_output: bool) -> Vec<u8> {
        let mut fields = common_fields(&self.context);
        fields.push(field(10, KIND_HASH32, self.parent_header.0.to_vec()));
        fields.push(field(11, KIND_HASH32, self.ledger_anchor_block.0.to_vec()));
        fields.push(field(
            12,
            KIND_U128,
            self.ledger_anchor_height.to_be_bytes().to_vec(),
        ));
        fields.push(field(13, KIND_HASH32, self.entries_root.0.to_vec()));
        fields.push(field(
            14,
            KIND_U16,
            self.entries_count.to_be_bytes().to_vec(),
        ));
        fields.push(field(15, KIND_U16, self.suite_id.to_be_bytes().to_vec()));
        fields.push(field(16, KIND_BYTES32, self.target.to_be_bytes().to_vec()));
        fields.push(field(17, KIND_U128, self.nonce.to_be_bytes().to_vec()));
        if include_output {
            fields.push(field(18, KIND_HASH32, self.output_hash.0.to_vec()));
        }
        fields.push(field(
            19,
            KIND_U128,
            self.expiry_anchor_height.to_be_bytes().to_vec(),
        ));
        wire_object(BASELINE_ACCESS_WORK_SCHEMA_V1, fields)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PermissionlessAdmissionHeaderV1 {
    pub context: AdmissionContextV1,
    pub admission_era: u128,
    pub log_height: u128,
    pub parent_header: AdmissionHash32,
    pub ledger_anchor_block: AdmissionHash32,
    pub access_work_id: AdmissionHash32,
    pub entries_root: AdmissionHash32,
    pub entries_count: u16,
    pub cumulative_work: AdmissionWork,
    pub prior_era_terminal: Option<AdmissionHash32>,
}

impl PermissionlessAdmissionHeaderV1 {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut fields = common_fields(&self.context);
        fields.push(field(
            10,
            KIND_U128,
            self.admission_era.to_be_bytes().to_vec(),
        ));
        fields.push(field(11, KIND_U128, self.log_height.to_be_bytes().to_vec()));
        fields.push(field(12, KIND_HASH32, self.parent_header.0.to_vec()));
        fields.push(field(13, KIND_HASH32, self.ledger_anchor_block.0.to_vec()));
        fields.push(field(14, KIND_HASH32, self.access_work_id.0.to_vec()));
        fields.push(field(15, KIND_HASH32, self.entries_root.0.to_vec()));
        fields.push(field(
            16,
            KIND_U16,
            self.entries_count.to_be_bytes().to_vec(),
        ));
        fields.push(field(
            17,
            KIND_BYTES32,
            self.cumulative_work.to_be_bytes().to_vec(),
        ));
        if let Some(prior) = self.prior_era_terminal {
            fields.push(field(18, KIND_HASH32, prior.0.to_vec()));
        }
        wire_object(PERMISSIONLESS_ADMISSION_HEADER_SCHEMA_V1, fields)
    }

    pub fn header_id(&self) -> AdmissionHash32 {
        subject_id(&self.canonical_bytes())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdmissionCheckpointV1 {
    pub context: AdmissionContextV1,
    pub admission_era: u128,
    pub header_id: AdmissionHash32,
    pub log_height: u128,
    pub cumulative_work: AdmissionWork,
    pub confirmations: u16,
    pub descendant_work: AdmissionWork,
    pub entries_root: AdmissionHash32,
    pub availability_root: AdmissionHash32,
    pub observed_ledger_epoch: u128,
    pub committed_ledger_epoch: u128,
}

impl AdmissionCheckpointV1 {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut fields = common_fields(&self.context);
        fields.push(field(
            10,
            KIND_U128,
            self.admission_era.to_be_bytes().to_vec(),
        ));
        fields.push(field(11, KIND_HASH32, self.header_id.0.to_vec()));
        fields.push(field(12, KIND_U128, self.log_height.to_be_bytes().to_vec()));
        fields.push(field(
            13,
            KIND_BYTES32,
            self.cumulative_work.to_be_bytes().to_vec(),
        ));
        fields.push(field(
            14,
            KIND_U16,
            self.confirmations.to_be_bytes().to_vec(),
        ));
        fields.push(field(
            15,
            KIND_BYTES32,
            self.descendant_work.to_be_bytes().to_vec(),
        ));
        fields.push(field(16, KIND_HASH32, self.entries_root.0.to_vec()));
        fields.push(field(17, KIND_HASH32, self.availability_root.0.to_vec()));
        fields.push(field(
            18,
            KIND_U128,
            self.observed_ledger_epoch.to_be_bytes().to_vec(),
        ));
        fields.push(field(
            19,
            KIND_U128,
            self.committed_ledger_epoch.to_be_bytes().to_vec(),
        ));
        wire_object(ADMISSION_CHECKPOINT_SCHEMA_V1, fields)
    }

    pub fn checkpoint_id(&self) -> AdmissionHash32 {
        subject_id(&self.canonical_bytes())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdmissionAvailableEntryV1 {
    pub entry_id: AdmissionHash32,
    pub locator_commitment: AdmissionHash32,
    pub declared_bytes: u64,
}

pub fn admission_entry_root<I>(entries: I) -> Result<AdmissionHash32, AdmissionError>
where
    I: IntoIterator<Item = AdmissionHash32>,
{
    let mut ids: Vec<_> = entries.into_iter().collect();
    ids.sort_unstable();
    if ids.windows(2).any(|window| window[0] == window[1]) {
        return Err(AdmissionError::DuplicateOrNullifier(
            "duplicate admission entry id".into(),
        ));
    }
    merkle_root(
        ids.into_iter()
            .map(|id| sha256_parts_raw(&[&[0], &id.0]))
            .collect(),
        EMPTY_ENTRY_ROOT_DOMAIN,
        1,
    )
}

pub fn admission_availability_root(
    entries: &[AdmissionAvailableEntryV1],
) -> Result<AdmissionHash32, AdmissionError> {
    let mut records = entries.to_vec();
    records.sort_unstable_by_key(|record| record.entry_id);
    if records
        .windows(2)
        .any(|window| window[0].entry_id == window[1].entry_id)
    {
        return Err(AdmissionError::DuplicateOrNullifier(
            "duplicate availability entry id".into(),
        ));
    }
    merkle_root(
        records
            .iter()
            .map(|record| {
                sha256_parts_raw(&[
                    &[2],
                    &record.entry_id.0,
                    &record.locator_commitment.0,
                    &record.declared_bytes.to_be_bytes(),
                ])
            })
            .collect(),
        EMPTY_AVAILABILITY_ROOT_DOMAIN,
        3,
    )
}

/// Derives the content commitment for the exact raw admission sidecar bytes.
/// The caller must retain those exact bytes; a URL, success boolean or caller
/// supplied digest is not availability evidence.
pub fn admission_sidecar_payload_commitment(
    payload: &[u8],
) -> Result<AdmissionHash32, AdmissionError> {
    if payload.len() > usize::try_from(MAX_ADMISSION_SIDECAR_BYTES).unwrap_or(usize::MAX) {
        return Err(AdmissionError::EnvelopeLimit(
            "admission sidecar payload exceeds 8 MiB".into(),
        ));
    }
    Ok(framed_hash(&[SIDECAR_PAYLOAD_DOMAIN, payload]))
}

/// Derives the transport-independent content locator committed by an entry.
/// Provider addresses are mutable P2P inventory and are deliberately excluded
/// so an entry never authorizes an implementation to fetch an arbitrary URL.
pub fn admission_sidecar_locator_commitment(
    payload_commitment: AdmissionHash32,
    declared_bytes: u64,
) -> AdmissionHash32 {
    framed_hash(&[
        SIDECAR_LOCATOR_DOMAIN,
        &payload_commitment.0,
        &declared_bytes.to_be_bytes(),
    ])
}

pub fn verify_admission_sidecar(
    entry: &PermissionlessAdmissionEntryV1,
    payload: &[u8],
) -> Result<(), AdmissionError> {
    let declared_bytes = u64::try_from(payload.len()).map_err(|_| {
        AdmissionError::EnvelopeLimit("admission sidecar length does not fit U64".into())
    })?;
    let payload_commitment = admission_sidecar_payload_commitment(payload)?;
    if declared_bytes != entry.declared_bytes
        || payload_commitment != entry.payload_commitment
        || admission_sidecar_locator_commitment(payload_commitment, declared_bytes)
            != entry.locator_commitment
    {
        return Err(AdmissionError::ResourceOrAvailability(
            "admission sidecar bytes do not match the signed content locator".into(),
        ));
    }
    Ok(())
}

pub fn header_work(target: AdmissionWork) -> AdmissionWork {
    let Some(denominator) = target.checked_add_one() else {
        return AdmissionWork::ZERO;
    };
    divide_max_u256(denominator)
}

pub fn adjusted_admission_target(
    previous_target: AdmissionWork,
    completed_epoch_header_counts: [u64; 4],
    minimum_target: AdmissionWork,
    maximum_target: AdmissionWork,
) -> Result<AdmissionWork, AdmissionError> {
    if minimum_target > maximum_target
        || previous_target < minimum_target
        || previous_target > maximum_target
    {
        return Err(AdmissionError::ContextMismatch(
            "target bounds or previous target are invalid".into(),
        ));
    }
    let mut counts = completed_epoch_header_counts;
    counts.sort_unstable();
    let median_sum = counts[1] as u128 + counts[2] as u128;
    let median = u64::try_from(median_sum / 2)
        .expect("u64 median cannot overflow")
        .max(1);
    let raw = WideWork::multiply_u64(previous_target, 64).div_u64(median);
    let lower = WideWork::from_u256(previous_target.div_u64(4));
    let upper = WideWork::multiply_u64(previous_target, 4);
    let bounded = raw.max(lower).min(upper);
    let bounded = bounded
        .max(WideWork::from_u256(minimum_target))
        .min(WideWork::from_u256(maximum_target));
    bounded.to_u256().ok_or_else(|| {
        AdmissionError::WorkOrProof("target adjustment did not fit U256 after clamps".into())
    })
}

fn validate_text(value: &str, field_name: &str) -> Result<(), AdmissionError> {
    if value.is_empty()
        || value.nfc().ne(value.chars())
        || value.chars().any(|character| {
            let code = character as u32;
            code <= 0x1f || (0x7f..=0x9f).contains(&code)
        })
    {
        return Err(AdmissionError::NonCanonicalWire(format!(
            "{field_name} must be nonempty NFC without C0/C1 controls"
        )));
    }
    Ok(())
}

fn validate_context(
    actual: &AdmissionContextV1,
    expected: &AdmissionContextV1,
) -> Result<(), AdmissionError> {
    actual.validate()?;
    if actual != expected {
        return Err(AdmissionError::ContextMismatch(
            "admission object context does not match this log".into(),
        ));
    }
    Ok(())
}

fn common_fields(context: &AdmissionContextV1) -> Vec<Vec<u8>> {
    vec![
        field(1, KIND_TEXT, context.network_domain.as_bytes().to_vec()),
        field(2, KIND_TEXT, context.zone_id.as_bytes().to_vec()),
        field(3, KIND_HASH32, context.currency_genesis.0.to_vec()),
        field(4, KIND_U128, context.protocol_era.to_be_bytes().to_vec()),
        field(5, KIND_U128, context.crypto_era.to_be_bytes().to_vec()),
    ]
}

fn field(id: u16, kind: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut result = Vec::with_capacity(7 + payload.len());
    result.extend_from_slice(&id.to_be_bytes());
    result.push(kind);
    result.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    result.extend_from_slice(&payload);
    result
}

fn wire_object(schema: u16, fields: Vec<Vec<u8>>) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(RLD_WIRE_MAGIC);
    result.extend_from_slice(&RLD_WIRE_VERSION_V1.to_be_bytes());
    result.extend_from_slice(&schema.to_be_bytes());
    result.extend_from_slice(&(fields.len() as u16).to_be_bytes());
    for field in fields {
        result.extend_from_slice(&field);
    }
    result
}

fn push_u32_framed(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), AdmissionError> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| AdmissionError::EnvelopeLimit("checkpoint proof frame exceeds U32".into()))?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn encode_checkpoint_batch_segment(
    batches: &[AdmissionCheckpointBatchProofV1],
) -> Result<Vec<u8>, AdmissionError> {
    let count = u16::try_from(batches.len())
        .map_err(|_| AdmissionError::EnvelopeLimit("checkpoint batch count exceeds U16".into()))?;
    let mut out = Vec::new();
    out.extend_from_slice(CHECKPOINT_BATCH_SEGMENT_DOMAIN);
    out.extend_from_slice(&count.to_be_bytes());
    for batch in batches {
        let entry_count = u16::try_from(batch.entries.len()).map_err(|_| {
            AdmissionError::EnvelopeLimit("checkpoint header entry count exceeds U16".into())
        })?;
        let mut frame = Vec::new();
        frame.extend_from_slice(&entry_count.to_be_bytes());
        for entry in &batch.entries {
            push_u32_framed(&mut frame, &entry.canonical_bytes())?;
        }
        push_u32_framed(&mut frame, &batch.access_work.canonical_bytes())?;
        push_u32_framed(&mut frame, &batch.header.canonical_bytes())?;
        frame.extend_from_slice(&batch.ledger_anchor.block_id.0);
        frame.extend_from_slice(&batch.ledger_anchor.height.to_be_bytes());
        push_u32_framed(&mut out, &frame)?;
    }
    Ok(out)
}

fn encode_checkpoint_confirmation_segment(
    confirmations: &[AdmissionCheckpointConfirmationProofV1],
) -> Result<Vec<u8>, AdmissionError> {
    let count = u16::try_from(confirmations.len()).map_err(|_| {
        AdmissionError::EnvelopeLimit("checkpoint confirmation count exceeds U16".into())
    })?;
    let mut out = Vec::new();
    out.extend_from_slice(CHECKPOINT_CONFIRMATION_SEGMENT_DOMAIN);
    out.extend_from_slice(&count.to_be_bytes());
    for confirmation in confirmations {
        let mut frame = Vec::new();
        push_u32_framed(&mut frame, &confirmation.access_work.canonical_bytes())?;
        push_u32_framed(&mut frame, &confirmation.header.canonical_bytes())?;
        frame.extend_from_slice(&confirmation.ledger_anchor.block_id.0);
        frame.extend_from_slice(&confirmation.ledger_anchor.height.to_be_bytes());
        push_u32_framed(&mut out, &frame)?;
    }
    Ok(out)
}

#[derive(Clone, Copy)]
struct CanonicalAdmissionField<'a> {
    id: u16,
    kind: u8,
    payload: &'a [u8],
}

fn parse_canonical_admission_object<'a>(
    wire: &'a [u8],
    expected_schema: u16,
    maximum_fields: usize,
    label: &str,
) -> Result<Vec<CanonicalAdmissionField<'a>>, AdmissionError> {
    if wire.len() < 10 {
        return Err(AdmissionError::NonCanonicalWire(format!(
            "{label} header is truncated"
        )));
    }
    if &wire[..4] != RLD_WIRE_MAGIC {
        return Err(AdmissionError::NonCanonicalWire(format!(
            "{label} magic is invalid"
        )));
    }
    let version = u16::from_be_bytes([wire[4], wire[5]]);
    if version != RLD_WIRE_VERSION_V1 {
        return Err(AdmissionError::NonCanonicalWire(format!(
            "{label} version is unsupported"
        )));
    }
    let schema = u16::from_be_bytes([wire[6], wire[7]]);
    if schema != expected_schema {
        return Err(AdmissionError::NonCanonicalWire(format!(
            "{label} schema is not 0x{expected_schema:04x}"
        )));
    }
    let count = usize::from(u16::from_be_bytes([wire[8], wire[9]]));
    if count > maximum_fields {
        return Err(AdmissionError::EnvelopeLimit(format!(
            "{label} field count exceeds {maximum_fields}"
        )));
    }
    let mut fields = Vec::with_capacity(count);
    let mut offset = 10usize;
    let mut previous_id = None;
    for _ in 0..count {
        let header_end = offset.checked_add(7).ok_or_else(|| {
            AdmissionError::EnvelopeLimit(format!("{label} field-header offset overflow"))
        })?;
        let header = wire.get(offset..header_end).ok_or_else(|| {
            AdmissionError::NonCanonicalWire(format!("{label} field header is truncated"))
        })?;
        let id = u16::from_be_bytes([header[0], header[1]]);
        if previous_id.is_some_and(|previous| id <= previous) {
            return Err(AdmissionError::NonCanonicalWire(format!(
                "{label} field IDs are not strictly increasing"
            )));
        }
        previous_id = Some(id);
        let kind = header[2];
        let length = u32::from_be_bytes([header[3], header[4], header[5], header[6]]) as usize;
        offset = header_end;
        let end = offset.checked_add(length).ok_or_else(|| {
            AdmissionError::EnvelopeLimit(format!("{label} field length overflows"))
        })?;
        let payload = wire.get(offset..end).ok_or_else(|| {
            AdmissionError::NonCanonicalWire(format!("{label} field payload is truncated"))
        })?;
        fields.push(CanonicalAdmissionField { id, kind, payload });
        offset = end;
    }
    if offset != wire.len() {
        return Err(AdmissionError::NonCanonicalWire(format!(
            "{label} has trailing bytes"
        )));
    }
    Ok(fields)
}

fn require_admission_field_layout(
    fields: &[CanonicalAdmissionField<'_>],
    expected: &[(u16, u8)],
    label: &str,
) -> Result<(), AdmissionError> {
    if fields.len() != expected.len()
        || fields
            .iter()
            .zip(expected)
            .any(|(actual, expected)| (actual.id, actual.kind) != *expected)
    {
        return Err(AdmissionError::NonCanonicalWire(format!(
            "{label} has missing, unknown or wrongly typed fields"
        )));
    }
    Ok(())
}

fn decode_admission_text(payload: &[u8], label: &str) -> Result<String, AdmissionError> {
    if payload.len() > 255 {
        return Err(AdmissionError::EnvelopeLimit(format!(
            "{label} exceeds 255 UTF-8 bytes"
        )));
    }
    let value = std::str::from_utf8(payload)
        .map_err(|_| AdmissionError::NonCanonicalWire(format!("{label} is not UTF-8")))?;
    validate_text(value, label)?;
    Ok(value.to_owned())
}

fn decode_admission_hash32(payload: &[u8], label: &str) -> Result<AdmissionHash32, AdmissionError> {
    let bytes = payload.try_into().map_err(|_| {
        AdmissionError::NonCanonicalWire(format!("{label} must occupy exactly 32 bytes"))
    })?;
    Ok(AdmissionHash32(bytes))
}

fn decode_admission_work(payload: &[u8], label: &str) -> Result<AdmissionWork, AdmissionError> {
    let bytes = payload.try_into().map_err(|_| {
        AdmissionError::NonCanonicalWire(format!("{label} must occupy exactly 32 bytes"))
    })?;
    Ok(AdmissionWork::from_be_bytes(bytes))
}

fn decode_admission_u128(payload: &[u8], label: &str) -> Result<u128, AdmissionError> {
    let bytes = payload.try_into().map_err(|_| {
        AdmissionError::NonCanonicalWire(format!("{label} must occupy exactly 16 bytes"))
    })?;
    Ok(u128::from_be_bytes(bytes))
}

fn decode_admission_u64(payload: &[u8], label: &str) -> Result<u64, AdmissionError> {
    let bytes = payload.try_into().map_err(|_| {
        AdmissionError::NonCanonicalWire(format!("{label} must occupy exactly 8 bytes"))
    })?;
    Ok(u64::from_be_bytes(bytes))
}

fn decode_admission_u16(payload: &[u8], label: &str) -> Result<u16, AdmissionError> {
    let bytes = payload.try_into().map_err(|_| {
        AdmissionError::NonCanonicalWire(format!("{label} must occupy exactly 2 bytes"))
    })?;
    Ok(u16::from_be_bytes(bytes))
}

fn decode_admission_context(
    fields: &[CanonicalAdmissionField<'_>],
) -> Result<AdmissionContextV1, AdmissionError> {
    Ok(AdmissionContextV1 {
        network_domain: decode_admission_text(fields[0].payload, "network_domain")?,
        zone_id: decode_admission_text(fields[1].payload, "zone_id")?,
        currency_genesis: decode_admission_hash32(fields[2].payload, "currency_genesis")?,
        protocol_era: decode_admission_u128(fields[3].payload, "protocol_era")?,
        crypto_era: decode_admission_u128(fields[4].payload, "crypto_era")?,
    })
}

fn take_admission_bytes<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    length: usize,
    label: &str,
) -> Result<&'a [u8], AdmissionError> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| AdmissionError::EnvelopeLimit(format!("{label} offset overflows")))?;
    let value = bytes
        .get(*offset..end)
        .ok_or_else(|| AdmissionError::NonCanonicalWire(format!("{label} is truncated")))?;
    *offset = end;
    Ok(value)
}

fn take_admission_frame<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    maximum: usize,
    label: &str,
) -> Result<&'a [u8], AdmissionError> {
    let length_bytes = take_admission_bytes(bytes, offset, 4, label)?;
    let length = u32::from_be_bytes(length_bytes.try_into().expect("four-byte slice")) as usize;
    if length > maximum {
        return Err(AdmissionError::EnvelopeLimit(format!(
            "{label} exceeds {maximum} bytes"
        )));
    }
    take_admission_bytes(bytes, offset, length, label)
}

fn decode_admission_entry_wire(
    wire: &[u8],
) -> Result<PermissionlessAdmissionEntryV1, AdmissionError> {
    if wire.len() > MAX_ADMISSION_ENTRY_WIRE_BYTES {
        return Err(AdmissionError::EnvelopeLimit(
            "admission entry wire exceeds 2 KiB".into(),
        ));
    }
    let fields = parse_canonical_admission_object(
        wire,
        PERMISSIONLESS_ADMISSION_ENTRY_SCHEMA_V1,
        16,
        "admission entry",
    )?;
    let has_challenge = fields.iter().any(|field| field.id == 14);
    let expected_without_challenge = [
        (1, KIND_TEXT),
        (2, KIND_TEXT),
        (3, KIND_HASH32),
        (4, KIND_U128),
        (5, KIND_U128),
        (10, KIND_U8),
        (11, KIND_BYTES32),
        (12, KIND_HASH32),
        (13, KIND_HASH32),
        (15, KIND_HASH32),
        (16, KIND_HASH32),
        (17, KIND_U64),
        (18, KIND_U128),
        (19, KIND_BYTES),
    ];
    let expected_with_challenge = [
        (1, KIND_TEXT),
        (2, KIND_TEXT),
        (3, KIND_HASH32),
        (4, KIND_U128),
        (5, KIND_U128),
        (10, KIND_U8),
        (11, KIND_BYTES32),
        (12, KIND_HASH32),
        (13, KIND_HASH32),
        (14, KIND_HASH32),
        (15, KIND_HASH32),
        (16, KIND_HASH32),
        (17, KIND_U64),
        (18, KIND_U128),
        (19, KIND_BYTES),
    ];
    require_admission_field_layout(
        &fields,
        if has_challenge {
            &expected_with_challenge
        } else {
            &expected_without_challenge
        },
        "admission entry",
    )?;
    let kind = match fields[5].payload {
        [1] => AdmissionEntryKindV1::Participation,
        [2] => AdmissionEntryKindV1::Result,
        [3] => AdmissionEntryKindV1::AvailabilityRefresh,
        _ => {
            return Err(AdmissionError::NonCanonicalWire(
                "admission entry kind is unsupported".into(),
            ))
        }
    };
    let challenge_index = has_challenge.then_some(9);
    let tail = if has_challenge { 10 } else { 9 };
    let signature: [u8; 64] = fields[tail + 4].payload.try_into().map_err(|_| {
        AdmissionError::NonCanonicalWire(
            "admission entry signature must occupy exactly 64 bytes".into(),
        )
    })?;
    let entry = PermissionlessAdmissionEntryV1 {
        context: decode_admission_context(&fields)?,
        kind,
        participant_key: decode_admission_hash32(fields[6].payload, "participant_key")?,
        owner_commitment: decode_admission_hash32(fields[7].payload, "owner_commitment")?,
        program_id: decode_admission_hash32(fields[8].payload, "program_id")?,
        challenge_id: challenge_index
            .map(|index| decode_admission_hash32(fields[index].payload, "challenge_id"))
            .transpose()?,
        payload_commitment: decode_admission_hash32(fields[tail].payload, "payload_commitment")?,
        locator_commitment: decode_admission_hash32(
            fields[tail + 1].payload,
            "locator_commitment",
        )?,
        declared_bytes: decode_admission_u64(fields[tail + 2].payload, "declared_bytes")?,
        expiry_height: decode_admission_u128(fields[tail + 3].payload, "expiry_height")?,
        entry_signature: AdmissionSignature64(signature),
    };
    if entry.canonical_bytes() != wire {
        return Err(AdmissionError::NonCanonicalWire(
            "admission entry does not re-encode byte-for-byte".into(),
        ));
    }
    Ok(entry)
}

fn decode_access_work_wire(wire: &[u8]) -> Result<BaselineAccessWorkV1, AdmissionError> {
    if wire.len() > MAX_ADMISSION_HEADER_WIRE_BYTES {
        return Err(AdmissionError::EnvelopeLimit(
            "admission access-work wire exceeds 4 KiB".into(),
        ));
    }
    let fields = parse_canonical_admission_object(
        wire,
        BASELINE_ACCESS_WORK_SCHEMA_V1,
        15,
        "admission access work",
    )?;
    require_admission_field_layout(
        &fields,
        &[
            (1, KIND_TEXT),
            (2, KIND_TEXT),
            (3, KIND_HASH32),
            (4, KIND_U128),
            (5, KIND_U128),
            (10, KIND_HASH32),
            (11, KIND_HASH32),
            (12, KIND_U128),
            (13, KIND_HASH32),
            (14, KIND_U16),
            (15, KIND_U16),
            (16, KIND_BYTES32),
            (17, KIND_U128),
            (18, KIND_HASH32),
            (19, KIND_U128),
        ],
        "admission access work",
    )?;
    let work = BaselineAccessWorkV1 {
        context: decode_admission_context(&fields)?,
        parent_header: decode_admission_hash32(fields[5].payload, "parent_header")?,
        ledger_anchor_block: decode_admission_hash32(fields[6].payload, "ledger_anchor_block")?,
        ledger_anchor_height: decode_admission_u128(fields[7].payload, "ledger_anchor_height")?,
        entries_root: decode_admission_hash32(fields[8].payload, "entries_root")?,
        entries_count: decode_admission_u16(fields[9].payload, "entries_count")?,
        suite_id: decode_admission_u16(fields[10].payload, "suite_id")?,
        target: decode_admission_work(fields[11].payload, "target")?,
        nonce: decode_admission_u128(fields[12].payload, "nonce")?,
        output_hash: decode_admission_hash32(fields[13].payload, "output_hash")?,
        expiry_anchor_height: decode_admission_u128(fields[14].payload, "expiry_anchor_height")?,
    };
    if work.canonical_bytes() != wire {
        return Err(AdmissionError::NonCanonicalWire(
            "admission access work does not re-encode byte-for-byte".into(),
        ));
    }
    Ok(work)
}

fn decode_admission_header_wire(
    wire: &[u8],
) -> Result<PermissionlessAdmissionHeaderV1, AdmissionError> {
    if wire.len() > MAX_ADMISSION_HEADER_WIRE_BYTES {
        return Err(AdmissionError::EnvelopeLimit(
            "admission header wire exceeds 4 KiB".into(),
        ));
    }
    let fields = parse_canonical_admission_object(
        wire,
        PERMISSIONLESS_ADMISSION_HEADER_SCHEMA_V1,
        14,
        "admission header",
    )?;
    let has_prior_terminal = fields.iter().any(|field| field.id == 18);
    let expected_without_prior = [
        (1, KIND_TEXT),
        (2, KIND_TEXT),
        (3, KIND_HASH32),
        (4, KIND_U128),
        (5, KIND_U128),
        (10, KIND_U128),
        (11, KIND_U128),
        (12, KIND_HASH32),
        (13, KIND_HASH32),
        (14, KIND_HASH32),
        (15, KIND_HASH32),
        (16, KIND_U16),
        (17, KIND_BYTES32),
    ];
    let expected_with_prior = [
        (1, KIND_TEXT),
        (2, KIND_TEXT),
        (3, KIND_HASH32),
        (4, KIND_U128),
        (5, KIND_U128),
        (10, KIND_U128),
        (11, KIND_U128),
        (12, KIND_HASH32),
        (13, KIND_HASH32),
        (14, KIND_HASH32),
        (15, KIND_HASH32),
        (16, KIND_U16),
        (17, KIND_BYTES32),
        (18, KIND_HASH32),
    ];
    require_admission_field_layout(
        &fields,
        if has_prior_terminal {
            &expected_with_prior
        } else {
            &expected_without_prior
        },
        "admission header",
    )?;
    let header = PermissionlessAdmissionHeaderV1 {
        context: decode_admission_context(&fields)?,
        admission_era: decode_admission_u128(fields[5].payload, "admission_era")?,
        log_height: decode_admission_u128(fields[6].payload, "log_height")?,
        parent_header: decode_admission_hash32(fields[7].payload, "parent_header")?,
        ledger_anchor_block: decode_admission_hash32(fields[8].payload, "ledger_anchor_block")?,
        access_work_id: decode_admission_hash32(fields[9].payload, "access_work_id")?,
        entries_root: decode_admission_hash32(fields[10].payload, "entries_root")?,
        entries_count: decode_admission_u16(fields[11].payload, "entries_count")?,
        cumulative_work: decode_admission_work(fields[12].payload, "cumulative_work")?,
        prior_era_terminal: has_prior_terminal
            .then(|| decode_admission_hash32(fields[13].payload, "prior_era_terminal"))
            .transpose()?,
    };
    if header.canonical_bytes() != wire {
        return Err(AdmissionError::NonCanonicalWire(
            "admission header does not re-encode byte-for-byte".into(),
        ));
    }
    Ok(header)
}

fn decode_checkpoint_batch_segment(
    segment: &[u8],
) -> Result<Vec<AdmissionCheckpointBatchProofV1>, AdmissionError> {
    let minimum = CHECKPOINT_BATCH_SEGMENT_DOMAIN
        .len()
        .checked_add(2)
        .expect("fixed domain length");
    if segment.len() < minimum || !segment.starts_with(CHECKPOINT_BATCH_SEGMENT_DOMAIN) {
        return Err(AdmissionError::NonCanonicalWire(
            "checkpoint batch segment domain is invalid or truncated".into(),
        ));
    }
    let mut offset = CHECKPOINT_BATCH_SEGMENT_DOMAIN.len();
    let count = usize::from(u16::from_be_bytes(
        take_admission_bytes(segment, &mut offset, 2, "checkpoint batch count")?
            .try_into()
            .expect("two-byte slice"),
    ));
    if count > MAX_CHECKPOINT_ENTRIES_PER_LEDGER_BLOCK {
        return Err(AdmissionError::EnvelopeLimit(
            "checkpoint batch count exceeds 512".into(),
        ));
    }
    let mut batches = Vec::with_capacity(count);
    let mut total_entries = 0usize;
    for _ in 0..count {
        let frame = take_admission_frame(
            segment,
            &mut offset,
            MAX_ADMISSION_CHECKPOINT_PROOF_WIRE_BYTES,
            "checkpoint batch frame",
        )?;
        let mut frame_offset = 0usize;
        let entry_count = usize::from(u16::from_be_bytes(
            take_admission_bytes(frame, &mut frame_offset, 2, "checkpoint entry count")?
                .try_into()
                .expect("two-byte slice"),
        ));
        if entry_count > MAX_ADMISSION_ENTRIES_PER_HEADER {
            return Err(AdmissionError::EnvelopeLimit(
                "checkpoint header entry count exceeds 256".into(),
            ));
        }
        total_entries = total_entries.checked_add(entry_count).ok_or_else(|| {
            AdmissionError::EnvelopeLimit("checkpoint total entry count overflows".into())
        })?;
        if total_entries > MAX_CHECKPOINT_ENTRIES_PER_LEDGER_BLOCK {
            return Err(AdmissionError::EnvelopeLimit(
                "checkpoint proof exceeds 512 processed entries".into(),
            ));
        }
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            let entry = take_admission_frame(
                frame,
                &mut frame_offset,
                MAX_ADMISSION_ENTRY_WIRE_BYTES,
                "checkpoint entry wire",
            )?;
            entries.push(decode_admission_entry_wire(entry)?);
        }
        let access_work = decode_access_work_wire(take_admission_frame(
            frame,
            &mut frame_offset,
            MAX_ADMISSION_HEADER_WIRE_BYTES,
            "checkpoint access-work wire",
        )?)?;
        let header = decode_admission_header_wire(take_admission_frame(
            frame,
            &mut frame_offset,
            MAX_ADMISSION_HEADER_WIRE_BYTES,
            "checkpoint admission-header wire",
        )?)?;
        let anchor =
            take_admission_bytes(frame, &mut frame_offset, 48, "checkpoint ledger anchor")?;
        if frame_offset != frame.len() {
            return Err(AdmissionError::NonCanonicalWire(
                "checkpoint batch frame has trailing bytes".into(),
            ));
        }
        batches.push(AdmissionCheckpointBatchProofV1 {
            entries,
            access_work,
            header,
            ledger_anchor: AdmissionLedgerAnchorV1 {
                block_id: decode_admission_hash32(&anchor[..32], "ledger anchor block")?,
                height: decode_admission_u128(&anchor[32..], "ledger anchor height")?,
            },
        });
    }
    if offset != segment.len() {
        return Err(AdmissionError::NonCanonicalWire(
            "checkpoint batch segment has trailing bytes".into(),
        ));
    }
    Ok(batches)
}

fn decode_checkpoint_confirmation_segment(
    segment: &[u8],
) -> Result<Vec<AdmissionCheckpointConfirmationProofV1>, AdmissionError> {
    let minimum = CHECKPOINT_CONFIRMATION_SEGMENT_DOMAIN
        .len()
        .checked_add(2)
        .expect("fixed domain length");
    if segment.len() < minimum || !segment.starts_with(CHECKPOINT_CONFIRMATION_SEGMENT_DOMAIN) {
        return Err(AdmissionError::NonCanonicalWire(
            "checkpoint confirmation segment domain is invalid or truncated".into(),
        ));
    }
    let mut offset = CHECKPOINT_CONFIRMATION_SEGMENT_DOMAIN.len();
    let count = usize::from(u16::from_be_bytes(
        take_admission_bytes(segment, &mut offset, 2, "checkpoint confirmation count")?
            .try_into()
            .expect("two-byte slice"),
    ));
    if count > MAX_ADMISSION_CONFIRMATION_HEADERS {
        return Err(AdmissionError::EnvelopeLimit(
            "checkpoint confirmation count exceeds 512".into(),
        ));
    }
    let mut confirmations = Vec::with_capacity(count);
    for _ in 0..count {
        let frame = take_admission_frame(
            segment,
            &mut offset,
            MAX_ADMISSION_HEADER_WIRE_BYTES * 2 + 56,
            "checkpoint confirmation frame",
        )?;
        let mut frame_offset = 0usize;
        let access_work = decode_access_work_wire(take_admission_frame(
            frame,
            &mut frame_offset,
            MAX_ADMISSION_HEADER_WIRE_BYTES,
            "confirmation access-work wire",
        )?)?;
        let header = decode_admission_header_wire(take_admission_frame(
            frame,
            &mut frame_offset,
            MAX_ADMISSION_HEADER_WIRE_BYTES,
            "confirmation admission-header wire",
        )?)?;
        let anchor =
            take_admission_bytes(frame, &mut frame_offset, 48, "confirmation ledger anchor")?;
        if frame_offset != frame.len() {
            return Err(AdmissionError::NonCanonicalWire(
                "checkpoint confirmation frame has trailing bytes".into(),
            ));
        }
        confirmations.push(AdmissionCheckpointConfirmationProofV1 {
            access_work,
            header,
            ledger_anchor: AdmissionLedgerAnchorV1 {
                block_id: decode_admission_hash32(&anchor[..32], "ledger anchor block")?,
                height: decode_admission_u128(&anchor[32..], "ledger anchor height")?,
            },
        });
    }
    if offset != segment.len() {
        return Err(AdmissionError::NonCanonicalWire(
            "checkpoint confirmation segment has trailing bytes".into(),
        ));
    }
    Ok(confirmations)
}

fn subject_id(wire: &[u8]) -> AdmissionHash32 {
    sha256_parts_raw(&[SUBJECT_DOMAIN, &[0], wire])
}

fn sha256_parts_raw(parts: &[&[u8]]) -> AdmissionHash32 {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    AdmissionHash32(hasher.finalize().into())
}

fn merkle_root(
    mut level: Vec<AdmissionHash32>,
    empty_domain: &[u8],
    inner_prefix: u8,
) -> Result<AdmissionHash32, AdmissionError> {
    if level.is_empty() {
        return Ok(sha256_parts_raw(&[empty_domain]));
    }
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().expect("nonempty level"));
        }
        level = level
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| sha256_parts_raw(&[&[inner_prefix], &pair[0].0, &pair[1].0]))
            .collect();
    }
    Ok(level[0])
}

fn divide_max_u256(denominator: AdmissionWork) -> AdmissionWork {
    debug_assert!(!denominator.is_zero());
    let mut quotient = AdmissionWork::ZERO;
    let mut remainder = WideWork::default();
    let denominator = WideWork::from_u256(denominator);
    for bit in (0..256).rev() {
        let mut carry = 1u64;
        for limb in &mut remainder.0 {
            let next = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = next;
        }
        if remainder >= denominator {
            let mut borrow = 0u128;
            for index in 0..8 {
                let minuend = remainder.0[index] as u128;
                let subtrahend = denominator.0[index] as u128 + borrow;
                if minuend >= subtrahend {
                    remainder.0[index] = (minuend - subtrahend) as u64;
                    borrow = 0;
                } else {
                    remainder.0[index] = ((1u128 << 64) + minuend - subtrahend) as u64;
                    borrow = 1;
                }
            }
            quotient.set_bit(bit);
        }
    }
    quotient
}

fn rollover_threshold() -> AdmissionWork {
    AdmissionWork::from_be_bytes([
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ])
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ContributionEpochMappingV1 {
    pub ledger_height_origin: u128,
    pub contribution_epoch_origin: u128,
    pub ledger_blocks_per_contribution_epoch: u128,
}

impl ContributionEpochMappingV1 {
    pub fn validate(&self) -> Result<(), AdmissionError> {
        if self.ledger_blocks_per_contribution_epoch < 2 {
            return Err(AdmissionError::ContextMismatch(
                "ledger_blocks_per_contribution_epoch must be at least two".into(),
            ));
        }
        let maximum_offset =
            (u128::MAX - self.ledger_height_origin) / self.ledger_blocks_per_contribution_epoch;
        if self
            .contribution_epoch_origin
            .checked_add(maximum_offset)
            .is_none()
        {
            return Err(AdmissionError::ContextMismatch(
                "contribution Epoch mapping overflows before the maximum Ledger height".into(),
            ));
        }
        Ok(())
    }

    /// Maps a finalized Ledger height into the sole contribution Epoch used by
    /// admission checkpoints. The mapping is founder-signed in admission
    /// genesis and deliberately contains no wall-clock input.
    pub fn epoch_at_height(&self, ledger_height: u128) -> Result<u128, AdmissionError> {
        self.validate()?;
        let relative_height = ledger_height
            .checked_sub(self.ledger_height_origin)
            .ok_or_else(|| {
                AdmissionError::TransitionOrValueCap(
                    "Ledger height precedes the signed contribution Epoch origin".into(),
                )
            })?;
        self.contribution_epoch_origin
            .checked_add(relative_height / self.ledger_blocks_per_contribution_epoch)
            .ok_or_else(|| {
                AdmissionError::TransitionOrValueCap(
                    "derived contribution Epoch overflows U128".into(),
                )
            })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdmissionLogConfigV1 {
    pub minimum_target: AdmissionWork,
    pub maximum_target: AdmissionWork,
    pub genesis_target: AdmissionWork,
    pub confirmation_work_floor: AdmissionWork,
    pub contribution_epoch_mapping: ContributionEpochMappingV1,
}

/// Immutable, founder-signed trust root for the permissionless admission log.
///
/// The benchmark digest is a content hash of the externally retained report
/// that justified the immutable target range.  It is intentionally not a
/// free-form label: the exact report bytes must be available to operators and
/// auditors independently of a runtime snapshot.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdmissionGenesisV1 {
    pub context: AdmissionContextV1,
    pub config: AdmissionLogConfigV1,
    pub benchmark_report_sha256: AdmissionHash32,
    pub genesis_header: AdmissionHash32,
}

impl AdmissionGenesisV1 {
    pub fn new(
        context: AdmissionContextV1,
        config: AdmissionLogConfigV1,
        benchmark_report_sha256: AdmissionHash32,
    ) -> Result<Self, AdmissionError> {
        context.validate()?;
        config.validate()?;
        if benchmark_report_sha256.is_zero() {
            return Err(AdmissionError::ContextMismatch(
                "admission benchmark report SHA-256 cannot be zero".into(),
            ));
        }
        let genesis_header =
            admission_genesis_header_id(&context, &config, benchmark_report_sha256)?;
        Ok(Self {
            context,
            config,
            benchmark_report_sha256,
            genesis_header,
        })
    }

    pub fn for_descriptor(
        descriptor: &ZoneDescriptor,
        config: AdmissionLogConfigV1,
        benchmark_report_sha256: AdmissionHash32,
    ) -> Result<Self, AdmissionError> {
        let currency_genesis = AdmissionHash32::from_hex(&descriptor.currency_genesis_root)?;
        Self::new(
            AdmissionContextV1 {
                network_domain: descriptor.network_domain.clone(),
                zone_id: descriptor.zone_id.clone(),
                currency_genesis,
                protocol_era: u128::from(descriptor.protocol_era),
                crypto_era: u128::from(descriptor.crypto_era),
            },
            config,
            benchmark_report_sha256,
        )
    }

    pub fn validate(&self) -> Result<(), AdmissionError> {
        self.context.validate()?;
        self.config.validate()?;
        if self.benchmark_report_sha256.is_zero() {
            return Err(AdmissionError::ContextMismatch(
                "admission benchmark report SHA-256 cannot be zero".into(),
            ));
        }
        let expected =
            admission_genesis_header_id(&self.context, &self.config, self.benchmark_report_sha256)?;
        if self.genesis_header != expected {
            return Err(AdmissionError::ContextMismatch(
                "admission genesis header does not match its immutable context, targets and benchmark report"
                    .into(),
            ));
        }
        Ok(())
    }

    pub fn validate_for_descriptor(
        &self,
        descriptor: &ZoneDescriptor,
    ) -> Result<(), AdmissionError> {
        self.validate()?;
        let expected_currency = AdmissionHash32::from_hex(&descriptor.currency_genesis_root)?;
        if self.context.network_domain != descriptor.network_domain
            || self.context.zone_id != descriptor.zone_id
            || self.context.currency_genesis != expected_currency
            || self.context.protocol_era != u128::from(descriptor.protocol_era)
            || self.context.crypto_era != u128::from(descriptor.crypto_era)
        {
            return Err(AdmissionError::ContextMismatch(
                "admission genesis context does not exactly match the currency genesis descriptor"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// Derive the one and only root header identifier for an admission log.
/// Every variable-width field is length framed before hashing, while all
/// integers and U256 values use fixed-width big-endian encoding.
pub fn admission_genesis_header_id(
    context: &AdmissionContextV1,
    config: &AdmissionLogConfigV1,
    benchmark_report_sha256: AdmissionHash32,
) -> Result<AdmissionHash32, AdmissionError> {
    context.validate()?;
    config.validate()?;
    if benchmark_report_sha256.is_zero() {
        return Err(AdmissionError::ContextMismatch(
            "admission benchmark report SHA-256 cannot be zero".into(),
        ));
    }
    Ok(framed_hash(&[
        ADMISSION_GENESIS_DOMAIN,
        context.network_domain.as_bytes(),
        context.zone_id.as_bytes(),
        &context.currency_genesis.0,
        &context.protocol_era.to_be_bytes(),
        &context.crypto_era.to_be_bytes(),
        &config.minimum_target.to_be_bytes(),
        &config.maximum_target.to_be_bytes(),
        &config.genesis_target.to_be_bytes(),
        &config.confirmation_work_floor.to_be_bytes(),
        &config
            .contribution_epoch_mapping
            .ledger_height_origin
            .to_be_bytes(),
        &config
            .contribution_epoch_mapping
            .contribution_epoch_origin
            .to_be_bytes(),
        &config
            .contribution_epoch_mapping
            .ledger_blocks_per_contribution_epoch
            .to_be_bytes(),
        &benchmark_report_sha256.0,
    ]))
}

pub fn empty_admission_checkpoint_accumulator() -> AdmissionHash32 {
    sha256_parts_raw(&[EMPTY_CHECKPOINT_ACCUMULATOR_DOMAIN])
}

/// Extends the constant-size checkpoint audit chain with the exact proof that
/// justified the next checkpoint. `prior_checkpoint_count` is committed as the
/// predecessor index, so truncation, reordering and alternate-proof replay all
/// produce a different successor.
pub fn admission_checkpoint_accumulator_successor(
    prior_accumulator: AdmissionHash32,
    prior_checkpoint_count: u128,
    checkpoint_id: AdmissionHash32,
    proof_id: AdmissionHash32,
) -> Result<AdmissionHash32, AdmissionError> {
    if prior_accumulator.is_zero() || checkpoint_id.is_zero() || proof_id.is_zero() {
        return Err(AdmissionError::ParentOrPrestate(
            "checkpoint accumulator inputs must be nonzero".into(),
        ));
    }
    let successor_count = prior_checkpoint_count.checked_add(1).ok_or_else(|| {
        AdmissionError::ParentOrPrestate("checkpoint accumulator count overflow".into())
    })?;
    Ok(framed_hash(&[
        CHECKPOINT_ACCUMULATOR_SUCCESSOR_DOMAIN,
        &prior_accumulator.0,
        &successor_count.to_be_bytes(),
        &checkpoint_id.0,
        &proof_id.0,
    ]))
}

impl AdmissionLogConfigV1 {
    pub fn validate(&self) -> Result<(), AdmissionError> {
        self.contribution_epoch_mapping.validate()?;
        if self.minimum_target > self.maximum_target
            || self.genesis_target < self.minimum_target
            || self.genesis_target > self.maximum_target
        {
            return Err(AdmissionError::ContextMismatch(
                "genesis admission target is outside its immutable bounds".into(),
            ));
        }
        // Work is defined as floor((2^256 - 1) / (target + 1)).  A target of
        // U256::MAX therefore contributes zero cumulative work and would let an
        // attacker fill the bounded pending inventory without performing any
        // work.  Exclude it from every target reachable through the immutable
        // range, not just from the genesis value.
        if header_work(self.maximum_target).is_zero() {
            return Err(AdmissionError::ContextMismatch(
                "maximum_target permits zero-work admission headers".into(),
            ));
        }
        if self.confirmation_work_floor.is_zero() {
            return Err(AdmissionError::ContextMismatch(
                "confirmation_work_floor must be nonzero".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdmissionLedgerAnchorV1 {
    pub block_id: AdmissionHash32,
    pub height: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdmissionBatchEntryV1 {
    pub entry: PermissionlessAdmissionEntryV1,
    pub body_bytes: u64,
    pub sidecar_bytes: u64,
    pub availability_verified: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdmissionHeaderBatchV1 {
    pub entries: Vec<AdmissionBatchEntryV1>,
    pub access_work: BaselineAccessWorkV1,
    pub header: PermissionlessAdmissionHeaderV1,
    pub ledger_anchor: AdmissionLedgerAnchorV1,
}

/// Ingress object for a header whose sidecars are verified from exact bytes.
/// The raw payloads are intentionally not part of the admission header wire;
/// a node persists them in its content-addressed availability store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionSidecarSubmissionV1 {
    pub entry: PermissionlessAdmissionEntryV1,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionVerifiedHeaderSubmissionV1 {
    pub entries: Vec<AdmissionSidecarSubmissionV1>,
    pub access_work: BaselineAccessWorkV1,
    pub header: PermissionlessAdmissionHeaderV1,
    pub ledger_anchor: AdmissionLedgerAnchorV1,
}

/// The complete, newly checkpointed portion of one admission header.
///
/// Unlike `AdmissionHeaderBatchV1`, this proof object contains no caller
/// supplied byte counters or availability boolean.  Entry wire sizes are
/// derived locally and external history/sidecar availability is accepted only
/// through the verifier callbacks below.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdmissionCheckpointBatchProofV1 {
    pub entries: Vec<PermissionlessAdmissionEntryV1>,
    pub access_work: BaselineAccessWorkV1,
    pub header: PermissionlessAdmissionHeaderV1,
    pub ledger_anchor: AdmissionLedgerAnchorV1,
}

/// One successor header proving confirmation work after the checkpoint head.
/// Entry bodies may be omitted because they are not consumed by this
/// checkpoint; the durable admission store must still independently validate
/// the complete header through `verify_confirmation_header`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdmissionCheckpointConfirmationProofV1 {
    pub access_work: BaselineAccessWorkV1,
    pub header: PermissionlessAdmissionHeaderV1,
    pub ledger_anchor: AdmissionLedgerAnchorV1,
}

/// Direct, bounded tag-28 proof candidate.
///
/// This is deliberately not `PreparedAdmissionCheckpointV1`: it contains the
/// source headers and work from which every checkpoint field must be derived.
/// Its canonical bytes use schema 0x1071 and are suitable for direct inclusion
/// in a future top-level command commitment.  Runtime dispatch remains closed
/// until Ledger, WAL, node, signer and witness adoption is atomic.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdmissionCheckpointProofV1 {
    pub context: AdmissionContextV1,
    pub prior_committed_header: AdmissionHash32,
    pub prior_checkpoint_accumulator: AdmissionHash32,
    pub batch_segment: Vec<AdmissionCheckpointBatchProofV1>,
    pub confirmation_segment: Vec<AdmissionCheckpointConfirmationProofV1>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdmissionCommittedPositionV1 {
    pub header_id: AdmissionHash32,
    pub admission_era: u128,
    pub log_height: u128,
    pub cumulative_work: AdmissionWork,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAdmissionCheckpointTransitionV1 {
    pub checkpoint: AdmissionCheckpointV1,
    pub prior_committed_header: AdmissionHash32,
    pub entry_ids: Vec<AdmissionHash32>,
    pub observed_ledger_height: u128,
    pub committing_ledger_height: u128,
    pub proof_id: AdmissionHash32,
    pub next_checkpoint_accumulator: AdmissionHash32,
}

/// In-memory capability binding one formal tag-28 proof to the exact Ledger
/// prestate from which a proposer may calculate its successor commitment.
///
/// Fields are private and the type is not serializable or deserializable. Only
/// `Ledger::plan_admission_checkpoint_proposal` can construct a production
/// instance, so callers cannot inject a parent height, state root, successor
/// height or proof identifier. This capability does not claim that the proof
/// is valid: node-local Admission history must still verify it before signing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionCheckpointProposalPlanV1 {
    command_hash: String,
    proof_id: AdmissionHash32,
    parent_height: u64,
    parent_state_root: String,
    expected_height: u64,
}

impl AdmissionCheckpointProposalPlanV1 {
    pub fn command_hash(&self) -> &str {
        &self.command_hash
    }

    pub fn proof_id(&self) -> AdmissionHash32 {
        self.proof_id
    }

    pub fn parent_height(&self) -> u64 {
        self.parent_height
    }

    pub fn parent_state_root(&self) -> &str {
        &self.parent_state_root
    }

    pub fn expected_height(&self) -> u64 {
        self.expected_height
    }

    pub fn committing_ledger_height(&self) -> u128 {
        u128::from(self.expected_height)
    }

    pub(crate) fn from_ledger_prestate(
        command_hash: String,
        proof_id: AdmissionHash32,
        parent_height: u64,
        parent_state_root: String,
        expected_height: u64,
    ) -> Result<Self, AdmissionError> {
        if command_hash.is_empty()
            || proof_id.is_zero()
            || parent_state_root.is_empty()
            || expected_height
                != parent_height.checked_add(1).ok_or_else(|| {
                    AdmissionError::ParentOrPrestate(
                        "tag-28 proposal-plan parent height overflows U64".into(),
                    )
                })?
        {
            return Err(AdmissionError::ParentOrPrestate(
                "tag-28 proposal plan is incomplete or not an exact Ledger successor".into(),
            ));
        }
        Ok(Self {
            command_hash,
            proof_id,
            parent_height,
            parent_state_root,
            expected_height,
        })
    }
}

/// In-memory capability proving that a signed consensus proposal authenticated
/// one exact tag-28 proof and its exact Ledger successor height.
///
/// The fields are deliberately private and the type is not deserializable. A
/// node cannot turn a caller-supplied height, JSON object, or checkpoint proof
/// into this capability. Production construction is confined to
/// `Ledger::authenticate_admission_checkpoint_proposal`, which verifies the
/// proposal signature, deterministic leader, current Ledger prestate and the
/// formal tag-28 command commitment. Pure Ledger dispatch remains closed
/// because proof verification also requires node-local retained history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedAdmissionCheckpointProposalV1 {
    proposal_hash: String,
    command_hash: String,
    proof_id: AdmissionHash32,
    parent_height: u64,
    parent_state_root: String,
    committing_ledger_height: u128,
    expected_state_root: String,
}

impl AuthenticatedAdmissionCheckpointProposalV1 {
    pub fn proposal_hash(&self) -> &str {
        &self.proposal_hash
    }

    pub fn command_hash(&self) -> &str {
        &self.command_hash
    }

    pub fn proof_id(&self) -> AdmissionHash32 {
        self.proof_id
    }

    pub fn parent_height(&self) -> u64 {
        self.parent_height
    }

    pub fn parent_state_root(&self) -> &str {
        &self.parent_state_root
    }

    pub fn committing_ledger_height(&self) -> u128 {
        self.committing_ledger_height
    }

    pub fn expected_state_root(&self) -> &str {
        &self.expected_state_root
    }

    pub(crate) fn from_authenticated_proposal(
        proposal_hash: String,
        command_hash: String,
        proof_id: AdmissionHash32,
        parent_height: u64,
        parent_state_root: String,
        expected_height: u64,
        expected_state_root: String,
    ) -> Result<Self, AdmissionError> {
        if proposal_hash.is_empty()
            || command_hash.is_empty()
            || proof_id.is_zero()
            || parent_state_root.is_empty()
            || expected_state_root.is_empty()
            || expected_height
                != parent_height.checked_add(1).ok_or_else(|| {
                    AdmissionError::ParentOrPrestate(
                        "authenticated proposal parent height overflows U64".into(),
                    )
                })?
        {
            return Err(AdmissionError::ParentOrPrestate(
                "authenticated tag-28 proposal context is incomplete or not an exact successor"
                    .into(),
            ));
        }
        Ok(Self {
            proposal_hash,
            command_hash,
            proof_id,
            parent_height,
            parent_state_root,
            committing_ledger_height: u128::from(expected_height),
            expected_state_root,
        })
    }
}

mod admission_checkpoint_proof_context_seal {
    pub trait Sealed {}
}

/// Sealed context accepted by bounded tag-28 proof verification. The two
/// implementations are minted before signing by the Ledger or after signature
/// authentication by the Ledger; external crates cannot supply an arbitrary
/// committing height or proof identifier.
pub trait AdmissionCheckpointProofContextV1:
    admission_checkpoint_proof_context_seal::Sealed
{
    fn checkpoint_proof_id(&self) -> AdmissionHash32;
    fn checkpoint_committing_ledger_height(&self) -> u128;
}

impl admission_checkpoint_proof_context_seal::Sealed for AdmissionCheckpointProposalPlanV1 {}

impl AdmissionCheckpointProofContextV1 for AdmissionCheckpointProposalPlanV1 {
    fn checkpoint_proof_id(&self) -> AdmissionHash32 {
        self.proof_id
    }

    fn checkpoint_committing_ledger_height(&self) -> u128 {
        u128::from(self.expected_height)
    }
}

impl admission_checkpoint_proof_context_seal::Sealed
    for AuthenticatedAdmissionCheckpointProposalV1
{
}

impl AdmissionCheckpointProofContextV1 for AuthenticatedAdmissionCheckpointProposalV1 {
    fn checkpoint_proof_id(&self) -> AdmissionHash32 {
        self.proof_id
    }

    fn checkpoint_committing_ledger_height(&self) -> u128 {
        self.committing_ledger_height
    }
}

impl AdmissionCheckpointProofV1 {
    /// Strictly decodes one canonical schema-`0x1071` proof object.
    ///
    /// The outer 1 MiB limit and every nested count/frame limit are enforced
    /// before allocating their corresponding vectors. Every nested entry,
    /// access-work object and header is parsed from the binary wire format and
    /// re-encoded byte-for-byte; JSON is never used as a fallback. This proves
    /// canonical transport only. Callers must still verify retained history,
    /// sidecars, finalized Ledger anchors and the sealed proposal prestate.
    pub fn from_canonical_bytes(wire: &[u8]) -> Result<Self, AdmissionError> {
        if wire.len() > MAX_ADMISSION_CHECKPOINT_PROOF_WIRE_BYTES {
            return Err(AdmissionError::EnvelopeLimit(
                "admission checkpoint proof wire exceeds 1 MiB".into(),
            ));
        }
        let fields = parse_canonical_admission_object(
            wire,
            ADMISSION_CHECKPOINT_PROOF_SCHEMA_V1,
            9,
            "admission checkpoint proof",
        )?;
        require_admission_field_layout(
            &fields,
            &[
                (1, KIND_TEXT),
                (2, KIND_TEXT),
                (3, KIND_HASH32),
                (4, KIND_U128),
                (5, KIND_U128),
                (10, KIND_HASH32),
                (11, KIND_HASH32),
                (12, KIND_BYTES),
                (13, KIND_BYTES),
            ],
            "admission checkpoint proof",
        )?;
        let proof = Self {
            context: decode_admission_context(&fields)?,
            prior_committed_header: decode_admission_hash32(
                fields[5].payload,
                "prior_committed_header",
            )?,
            prior_checkpoint_accumulator: decode_admission_hash32(
                fields[6].payload,
                "prior_checkpoint_accumulator",
            )?,
            batch_segment: decode_checkpoint_batch_segment(fields[7].payload)?,
            confirmation_segment: decode_checkpoint_confirmation_segment(fields[8].payload)?,
        };
        proof.validate_encoding_bounds()?;
        if proof.canonical_bytes()? != wire {
            return Err(AdmissionError::NonCanonicalWire(
                "admission checkpoint proof does not re-encode byte-for-byte".into(),
            ));
        }
        Ok(proof)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AdmissionError> {
        self.validate_encoding_bounds()?;
        let batch_segment = encode_checkpoint_batch_segment(&self.batch_segment)?;
        let confirmation_segment =
            encode_checkpoint_confirmation_segment(&self.confirmation_segment)?;
        let mut fields = common_fields(&self.context);
        fields.push(field(
            10,
            KIND_HASH32,
            self.prior_committed_header.0.to_vec(),
        ));
        fields.push(field(
            11,
            KIND_HASH32,
            self.prior_checkpoint_accumulator.0.to_vec(),
        ));
        fields.push(field(12, KIND_BYTES, batch_segment));
        fields.push(field(13, KIND_BYTES, confirmation_segment));
        let wire = wire_object(ADMISSION_CHECKPOINT_PROOF_SCHEMA_V1, fields);
        if wire.len() > MAX_ADMISSION_CHECKPOINT_PROOF_WIRE_BYTES {
            return Err(AdmissionError::EnvelopeLimit(
                "admission checkpoint proof wire exceeds 1 MiB".into(),
            ));
        }
        Ok(wire)
    }

    pub fn proof_id(&self) -> Result<AdmissionHash32, AdmissionError> {
        Ok(subject_id(&self.canonical_bytes()?))
    }

    /// Recomputes a checkpoint from bounded source evidence.
    ///
    /// `verify_anchor` must resolve each anchor from locally finalized ledger
    /// history. `verify_batch_entry` must use the durable admission store to
    /// reject an entry already present in prior ancestry and to verify its
    /// sidecar availability. `verify_confirmation_header` must verify omitted
    /// confirmation bodies against that same store. A caller-provided boolean
    /// or a caller-provided `PreparedAdmissionCheckpointV1` is never accepted.
    /// The committing height is read only from a sealed proposal-plan or
    /// authenticated-proposal capability produced by the Ledger; it is never
    /// accepted as a bare caller parameter or proof field. Both checkpoint
    /// Epochs are derived from heights with the founder-signed mapping.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_bounded<C, FA, FE, FC>(
        &self,
        genesis: &AdmissionGenesisV1,
        prior_position: AdmissionCommittedPositionV1,
        prior_checkpoint_count: u128,
        expected_prior_checkpoint_accumulator: AdmissionHash32,
        proposal_context: &C,
        expected_target: AdmissionWork,
        rollover_authorizations: &BTreeMap<AdmissionHash32, AdmissionRolloverAuthorizationV1>,
        mut verify_anchor: FA,
        mut verify_batch_entry: FE,
        mut verify_confirmation_header: FC,
    ) -> Result<VerifiedAdmissionCheckpointTransitionV1, AdmissionError>
    where
        C: AdmissionCheckpointProofContextV1,
        FA: FnMut(&AdmissionLedgerAnchorV1) -> Result<(), AdmissionError>,
        FE: FnMut(&PermissionlessAdmissionEntryV1) -> Result<(), AdmissionError>,
        FC: FnMut(
            &PermissionlessAdmissionHeaderV1,
            &BaselineAccessWorkV1,
            &AdmissionLedgerAnchorV1,
        ) -> Result<(), AdmissionError>,
    {
        genesis.validate()?;
        validate_context(&self.context, &genesis.context)?;
        let proof_id = self.proof_id()?;
        if proposal_context.checkpoint_proof_id() != proof_id {
            return Err(AdmissionError::ParentOrPrestate(
                "checkpoint proof differs from the authenticated tag-28 proposal commitment".into(),
            ));
        }
        let committing_ledger_height = proposal_context.checkpoint_committing_ledger_height();
        if self.prior_committed_header != prior_position.header_id
            || self.prior_checkpoint_accumulator != expected_prior_checkpoint_accumulator
            || self.prior_checkpoint_accumulator.is_zero()
        {
            return Err(AdmissionError::ParentOrPrestate(
                "checkpoint proof does not extend the exact committed header and accumulator"
                    .into(),
            ));
        }
        if expected_target < genesis.config.minimum_target
            || expected_target > genesis.config.maximum_target
            || header_work(expected_target).is_zero()
        {
            return Err(AdmissionError::WorkOrProof(
                "expected checkpoint target is outside signed nonzero-work bounds".into(),
            ));
        }
        self.validate_encoding_bounds()?;
        if self.batch_segment.is_empty() {
            return Err(AdmissionError::ParentOrPrestate(
                "checkpoint proof has no complete header to advance".into(),
            ));
        }
        if self.confirmation_segment.len() < MIN_ADMISSION_CONFIRMATIONS {
            return Err(AdmissionError::WorkOrProof(
                "checkpoint proof has fewer than 32 successor headers".into(),
            ));
        }

        let mut position = prior_position;
        let mut seen_headers = BTreeSet::from([prior_position.header_id]);
        let mut seen_entries = BTreeSet::new();
        let mut entry_ids = Vec::new();
        let mut availability = Vec::new();

        for batch in &self.batch_segment {
            let ids: Vec<_> = batch
                .entries
                .iter()
                .map(PermissionlessAdmissionEntryV1::entry_id)
                .collect();
            if ids.windows(2).any(|window| window[0] == window[1]) {
                return Err(AdmissionError::DuplicateOrNullifier(
                    "checkpoint batch repeats an entry id".into(),
                ));
            }
            if ids.windows(2).any(|window| window[0] > window[1]) {
                return Err(AdmissionError::NonCanonicalWire(
                    "checkpoint batch entries must be strictly ordered by raw entry id".into(),
                ));
            }
            let body_bytes = batch.entries.iter().try_fold(0usize, |total, entry| {
                entry.validate(&genesis.context, batch.ledger_anchor.height)?;
                let encoded = entry.canonical_bytes();
                total.checked_add(encoded.len()).ok_or_else(|| {
                    AdmissionError::EnvelopeLimit("checkpoint entry body bytes overflow".into())
                })
            })?;
            if body_bytes > MAX_ADMISSION_BATCH_BODY_BYTES {
                return Err(AdmissionError::EnvelopeLimit(
                    "checkpoint header body exceeds 512 KiB".into(),
                ));
            }
            for entry in &batch.entries {
                let entry_id = entry.entry_id();
                if !seen_entries.insert(entry_id) {
                    return Err(AdmissionError::DuplicateOrNullifier(
                        "checkpoint proof repeats an entry id".into(),
                    ));
                }
                verify_batch_entry(entry)?;
                entry_ids.push(entry_id);
                availability.push(AdmissionAvailableEntryV1 {
                    entry_id,
                    locator_commitment: entry.locator_commitment,
                    declared_bytes: entry.declared_bytes,
                });
            }
            position = verify_checkpoint_proof_header(
                &genesis.context,
                position,
                &batch.header,
                &batch.access_work,
                &batch.ledger_anchor,
                Some(&ids),
                expected_target,
                rollover_authorizations,
                &mut verify_anchor,
                &mut seen_headers,
            )?;
        }
        let checkpoint_position = position;
        let observed_ledger_height = self
            .batch_segment
            .last()
            .expect("checkpoint batch segment is nonempty")
            .ledger_anchor
            .height;
        if self.confirmation_segment.len() > MIN_ADMISSION_CONFIRMATIONS {
            let next_confirmed_count = usize::from(
                self.confirmation_segment
                    .first()
                    .expect("confirmation segment is nonempty")
                    .header
                    .entries_count,
            );
            if entry_ids
                .len()
                .checked_add(next_confirmed_count)
                .is_some_and(|count| count <= MAX_CHECKPOINT_ENTRIES_PER_LEDGER_BLOCK)
            {
                return Err(AdmissionError::ParentOrPrestate(
                    "checkpoint proof stopped before a complete confirmed header that still fits the 512-entry bound"
                        .into(),
                ));
            }
        }
        let mut descendant_work = AdmissionWork::ZERO;
        for confirmation in &self.confirmation_segment {
            position = verify_checkpoint_proof_header(
                &genesis.context,
                position,
                &confirmation.header,
                &confirmation.access_work,
                &confirmation.ledger_anchor,
                None,
                expected_target,
                rollover_authorizations,
                &mut verify_anchor,
                &mut seen_headers,
            )?;
            verify_confirmation_header(
                &confirmation.header,
                &confirmation.access_work,
                &confirmation.ledger_anchor,
            )?;
            let this_work = confirmation.access_work.header_work();
            descendant_work = descendant_work.checked_add(this_work).ok_or_else(|| {
                AdmissionError::WorkOrProof("descendant confirmation work overflow".into())
            })?;
        }
        if descendant_work < genesis.config.confirmation_work_floor {
            return Err(AdmissionError::WorkOrProof(
                "checkpoint descendants are below confirmation_work_floor".into(),
            ));
        }
        if committing_ledger_height < observed_ledger_height {
            return Err(AdmissionError::TransitionOrValueCap(
                "tag-28 successor height precedes the checkpoint head Ledger anchor".into(),
            ));
        }
        let mapping = &genesis.config.contribution_epoch_mapping;
        let observed_ledger_epoch = mapping.epoch_at_height(observed_ledger_height)?;
        let committed_ledger_epoch = mapping.epoch_at_height(committing_ledger_height)?;
        if committed_ledger_epoch < observed_ledger_epoch
            || committed_ledger_epoch - observed_ledger_epoch > MAX_ADMISSION_LAG_EPOCHS
        {
            return Err(AdmissionError::TransitionOrValueCap(
                "derived checkpoint epochs exceed the two-Epoch admission lag".into(),
            ));
        }
        entry_ids.sort_unstable();
        availability.sort_unstable_by_key(|record| record.entry_id);
        let checkpoint = AdmissionCheckpointV1 {
            context: genesis.context.clone(),
            admission_era: checkpoint_position.admission_era,
            header_id: checkpoint_position.header_id,
            log_height: checkpoint_position.log_height,
            cumulative_work: checkpoint_position.cumulative_work,
            confirmations: u16::try_from(self.confirmation_segment.len()).map_err(|_| {
                AdmissionError::EnvelopeLimit("confirmation count exceeds U16".into())
            })?,
            descendant_work,
            entries_root: admission_entry_root(entry_ids.iter().copied())?,
            availability_root: admission_availability_root(&availability)?,
            observed_ledger_epoch,
            committed_ledger_epoch,
        };
        let next_checkpoint_accumulator = admission_checkpoint_accumulator_successor(
            self.prior_checkpoint_accumulator,
            prior_checkpoint_count,
            checkpoint.checkpoint_id(),
            proof_id,
        )?;
        Ok(VerifiedAdmissionCheckpointTransitionV1 {
            checkpoint,
            prior_committed_header: prior_position.header_id,
            entry_ids,
            observed_ledger_height,
            committing_ledger_height,
            proof_id,
            next_checkpoint_accumulator,
        })
    }

    fn validate_encoding_bounds(&self) -> Result<(), AdmissionError> {
        self.context.validate()?;
        if self.prior_committed_header.is_zero() || self.prior_checkpoint_accumulator.is_zero() {
            return Err(AdmissionError::ParentOrPrestate(
                "checkpoint proof predecessor and accumulator must be nonzero".into(),
            ));
        }
        if self.batch_segment.len() > MAX_CHECKPOINT_ENTRIES_PER_LEDGER_BLOCK
            || self.confirmation_segment.len() > MAX_ADMISSION_CONFIRMATION_HEADERS
        {
            return Err(AdmissionError::EnvelopeLimit(
                "checkpoint proof contains too many batch or confirmation headers".into(),
            ));
        }
        let mut entries = 0usize;
        let mut availability_bytes = 0u64;
        for batch in &self.batch_segment {
            validate_context(&batch.header.context, &self.context)?;
            validate_context(&batch.access_work.context, &self.context)?;
            if batch.entries.len() > MAX_ADMISSION_ENTRIES_PER_HEADER {
                return Err(AdmissionError::EnvelopeLimit(
                    "checkpoint proof header exceeds 256 entries".into(),
                ));
            }
            entries = entries.checked_add(batch.entries.len()).ok_or_else(|| {
                AdmissionError::EnvelopeLimit("checkpoint entry count overflow".into())
            })?;
            for entry in &batch.entries {
                validate_context(&entry.context, &self.context)?;
                availability_bytes = availability_bytes
                    .checked_add(entry.declared_bytes)
                    .ok_or_else(|| {
                        AdmissionError::EnvelopeLimit(
                            "checkpoint sidecar availability bytes overflow".into(),
                        )
                    })?;
                if availability_bytes > MAX_ADMISSION_CHECKPOINT_AVAILABILITY_BYTES {
                    return Err(AdmissionError::EnvelopeLimit(
                        "checkpoint sidecar availability exceeds 64 MiB".into(),
                    ));
                }
            }
        }
        if entries > MAX_CHECKPOINT_ENTRIES_PER_LEDGER_BLOCK {
            return Err(AdmissionError::EnvelopeLimit(
                "checkpoint proof exceeds 512 processed entries".into(),
            ));
        }
        for confirmation in &self.confirmation_segment {
            validate_context(&confirmation.header.context, &self.context)?;
            validate_context(&confirmation.access_work.context, &self.context)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdmissionRolloverAuthorizationV1 {
    pub terminal_header: AdmissionHash32,
    pub terminal_cumulative_work: AdmissionWork,
    pub successor_era: u128,
    pub finalized_ledger_state_root: AdmissionHash32,
}

/// Exact, consensus-rooted evidence used to derive a delayed admission target.
/// The derived fields are retained so recovery can reject a caller or WAL that
/// changes the arithmetic while preserving the source counts.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdmissionTargetScheduleFactV1 {
    pub decision_epoch: u128,
    pub completed_epoch_header_counts: [u64; 4],
    pub activation_epoch: u128,
    pub target: AdmissionWork,
}

/// Exact activation produced by consuming every delayed target whose epoch is
/// no later than the progressing Ledger epoch.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdmissionTargetActivationFactV1 {
    pub ledger_epoch: u128,
    pub prior_target: AdmissionWork,
    pub active_target: AdmissionWork,
    pub consumed_schedule_count: u8,
}

/// One of the three admission-control facts that must be rooted by the main
/// Ledger before the node-local admission WAL may trust it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "fact", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdmissionLedgerControlFactV1 {
    TargetSchedule(AdmissionTargetScheduleFactV1),
    TargetActivation(AdmissionTargetActivationFactV1),
    RolloverAuthorization(AdmissionRolloverAuthorizationV1),
}

impl AdmissionLedgerControlFactV1 {
    /// Protocol-stable fact hash. JSON and Rust enum layout are deliberately
    /// excluded from this accumulator.
    pub fn fact_hash(&self) -> AdmissionHash32 {
        match self {
            Self::TargetSchedule(fact) => framed_hash(&[
                LEDGER_CONTROL_FACT_DOMAIN,
                &[1],
                &fact.decision_epoch.to_be_bytes(),
                &fact.completed_epoch_header_counts[0].to_be_bytes(),
                &fact.completed_epoch_header_counts[1].to_be_bytes(),
                &fact.completed_epoch_header_counts[2].to_be_bytes(),
                &fact.completed_epoch_header_counts[3].to_be_bytes(),
                &fact.activation_epoch.to_be_bytes(),
                &fact.target.to_be_bytes(),
            ]),
            Self::TargetActivation(fact) => framed_hash(&[
                LEDGER_CONTROL_FACT_DOMAIN,
                &[2],
                &fact.ledger_epoch.to_be_bytes(),
                &fact.prior_target.to_be_bytes(),
                &fact.active_target.to_be_bytes(),
                &[fact.consumed_schedule_count],
            ]),
            Self::RolloverAuthorization(authorization) => framed_hash(&[
                LEDGER_CONTROL_FACT_DOMAIN,
                &[3],
                &authorization.terminal_header.0,
                &authorization.terminal_cumulative_work.to_be_bytes(),
                &authorization.successor_era.to_be_bytes(),
                &authorization.finalized_ledger_state_root.0,
            ]),
        }
    }
}

pub fn empty_admission_ledger_control_accumulator() -> AdmissionHash32 {
    sha256_parts_raw(&[EMPTY_LEDGER_CONTROL_ACCUMULATOR_DOMAIN])
}

pub fn admission_ledger_control_accumulator_successor(
    prior_accumulator: AdmissionHash32,
    prior_fact_count: u128,
    fact_hash: AdmissionHash32,
) -> Result<AdmissionHash32, AdmissionError> {
    if prior_accumulator.is_zero() || fact_hash.is_zero() {
        return Err(AdmissionError::ParentOrPrestate(
            "admission Ledger-control accumulator inputs must be nonzero".into(),
        ));
    }
    let successor_count = prior_fact_count.checked_add(1).ok_or_else(|| {
        AdmissionError::ParentOrPrestate("admission Ledger-control fact count overflow".into())
    })?;
    Ok(framed_hash(&[
        LEDGER_CONTROL_ACCUMULATOR_SUCCESSOR_DOMAIN,
        &prior_accumulator.0,
        &successor_count.to_be_bytes(),
        &fact_hash.0,
    ]))
}

/// Constant-size consensus state for target and rollover control. The full
/// fact history remains in authenticated main-WAL commits; this state retains
/// the exact chain tip plus the small delayed-target working set needed for
/// deterministic execution.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdmissionLedgerControlStateV1 {
    pub active_target: AdmissionWork,
    pub scheduled_targets: BTreeMap<u128, AdmissionTargetScheduleFactV1>,
    pub latest_target_schedule: Option<AdmissionTargetScheduleFactV1>,
    pub latest_target_activation: Option<AdmissionTargetActivationFactV1>,
    pub latest_rollover_authorization: Option<AdmissionRolloverAuthorizationV1>,
    pub fact_count: u128,
    pub fact_accumulator: AdmissionHash32,
    pub prior_fact_accumulator: Option<AdmissionHash32>,
    pub last_fact: Option<AdmissionLedgerControlFactV1>,
}

impl AdmissionLedgerControlStateV1 {
    pub fn new(config: &AdmissionLogConfigV1) -> Result<Self, AdmissionError> {
        config.validate()?;
        let state = Self {
            active_target: config.genesis_target,
            scheduled_targets: BTreeMap::new(),
            latest_target_schedule: None,
            latest_target_activation: None,
            latest_rollover_authorization: None,
            fact_count: 0,
            fact_accumulator: empty_admission_ledger_control_accumulator(),
            prior_fact_accumulator: None,
            last_fact: None,
        };
        state.validate_recovered(config)?;
        Ok(state)
    }

    pub fn schedule_target(
        &mut self,
        decision_epoch: u128,
        completed_epoch_header_counts: [u64; 4],
        config: &AdmissionLogConfigV1,
    ) -> Result<AdmissionTargetScheduleFactV1, AdmissionError> {
        self.validate_recovered(config)?;
        let activation_epoch = decision_epoch.checked_add(2).ok_or_else(|| {
            AdmissionError::ParentOrPrestate("target activation epoch overflow".into())
        })?;
        if self.scheduled_targets.contains_key(&activation_epoch) {
            return Err(AdmissionError::DuplicateOrNullifier(
                "target activation epoch is already scheduled".into(),
            ));
        }
        if self.scheduled_targets.len() >= MAX_PENDING_ADMISSION_TARGETS {
            return Err(AdmissionError::EnvelopeLimit(
                "too many delayed admission targets are pending".into(),
            ));
        }
        let target = adjusted_admission_target(
            self.active_target,
            completed_epoch_header_counts,
            config.minimum_target,
            config.maximum_target,
        )?;
        let schedule = AdmissionTargetScheduleFactV1 {
            decision_epoch,
            completed_epoch_header_counts,
            activation_epoch,
            target,
        };
        let fact = AdmissionLedgerControlFactV1::TargetSchedule(schedule.clone());
        self.preflight_fact(&fact)?;
        self.scheduled_targets
            .insert(schedule.activation_epoch, schedule.clone());
        self.latest_target_schedule = Some(schedule.clone());
        self.append_fact(fact)?;
        self.validate_recovered(config)?;
        Ok(schedule)
    }

    pub fn activate_target(
        &mut self,
        ledger_epoch: u128,
        config: &AdmissionLogConfigV1,
    ) -> Result<AdmissionTargetActivationFactV1, AdmissionError> {
        self.validate_recovered(config)?;
        let eligible = self
            .scheduled_targets
            .range(..=ledger_epoch)
            .map(|(epoch, schedule)| (*epoch, schedule.target))
            .collect::<Vec<_>>();
        if eligible.is_empty() {
            return Err(AdmissionError::ParentOrPrestate(
                "no delayed admission target is eligible for activation".into(),
            ));
        }
        let prior_target = self.active_target;
        let active_target = eligible.last().expect("eligible targets are nonempty").1;
        let activation = AdmissionTargetActivationFactV1 {
            ledger_epoch,
            prior_target,
            active_target,
            consumed_schedule_count: u8::try_from(eligible.len()).map_err(|_| {
                AdmissionError::EnvelopeLimit("activated admission target count exceeds U8".into())
            })?,
        };
        let fact = AdmissionLedgerControlFactV1::TargetActivation(activation.clone());
        self.preflight_fact(&fact)?;
        for (epoch, _) in &eligible {
            self.scheduled_targets.remove(epoch);
        }
        self.active_target = active_target;
        self.latest_target_activation = Some(activation.clone());
        self.append_fact(fact)?;
        self.validate_recovered(config)?;
        Ok(activation)
    }

    pub fn authorize_rollover(
        &mut self,
        authorization: AdmissionRolloverAuthorizationV1,
        config: &AdmissionLogConfigV1,
    ) -> Result<AdmissionLedgerControlFactV1, AdmissionError> {
        self.validate_recovered(config)?;
        if authorization.terminal_header.is_zero()
            || authorization.terminal_cumulative_work < rollover_threshold()
            || authorization.successor_era == 0
            || authorization.finalized_ledger_state_root.is_zero()
        {
            return Err(AdmissionError::TransitionOrValueCap(
                "rollover Ledger fact lacks terminal threshold, successor Era, or state root"
                    .into(),
            ));
        }
        if self.latest_rollover_authorization.as_ref() == Some(&authorization) {
            return Err(AdmissionError::DuplicateOrNullifier(
                "rollover authorization is already the latest Ledger fact".into(),
            ));
        }
        let fact = AdmissionLedgerControlFactV1::RolloverAuthorization(authorization.clone());
        self.preflight_fact(&fact)?;
        self.latest_rollover_authorization = Some(authorization);
        self.append_fact(fact.clone())?;
        self.validate_recovered(config)?;
        Ok(fact)
    }

    pub fn apply_exact_fact(
        &mut self,
        fact: &AdmissionLedgerControlFactV1,
        config: &AdmissionLogConfigV1,
    ) -> Result<(), AdmissionError> {
        let mut candidate = self.clone();
        let derived = match fact {
            AdmissionLedgerControlFactV1::TargetSchedule(schedule) => {
                AdmissionLedgerControlFactV1::TargetSchedule(candidate.schedule_target(
                    schedule.decision_epoch,
                    schedule.completed_epoch_header_counts,
                    config,
                )?)
            }
            AdmissionLedgerControlFactV1::TargetActivation(activation) => {
                AdmissionLedgerControlFactV1::TargetActivation(
                    candidate.activate_target(activation.ledger_epoch, config)?,
                )
            }
            AdmissionLedgerControlFactV1::RolloverAuthorization(authorization) => {
                candidate.authorize_rollover(authorization.clone(), config)?
            }
        };
        if &derived != fact {
            return Err(AdmissionError::ParentOrPrestate(
                "admission Ledger-control fact contains caller-selected derived output".into(),
            ));
        }
        *self = candidate;
        Ok(())
    }

    pub fn validate_recovered(&self, config: &AdmissionLogConfigV1) -> Result<(), AdmissionError> {
        config.validate()?;
        if self.active_target < config.minimum_target
            || self.active_target > config.maximum_target
            || header_work(self.active_target).is_zero()
            || self.scheduled_targets.len() > MAX_PENDING_ADMISSION_TARGETS
        {
            return Err(AdmissionError::ParentOrPrestate(
                "recovered admission Ledger-control target state is invalid".into(),
            ));
        }
        for (activation_epoch, schedule) in &self.scheduled_targets {
            if *activation_epoch != schedule.activation_epoch
                || schedule.activation_epoch
                    != schedule.decision_epoch.checked_add(2).ok_or_else(|| {
                        AdmissionError::ParentOrPrestate(
                            "recovered target decision epoch overflow".into(),
                        )
                    })?
                || schedule.target < config.minimum_target
                || schedule.target > config.maximum_target
            {
                return Err(AdmissionError::ParentOrPrestate(
                    "recovered delayed admission target fact is invalid".into(),
                ));
            }
        }
        if let Some(schedule) = &self.latest_target_schedule {
            self.validate_fact_shape(&AdmissionLedgerControlFactV1::TargetSchedule(
                schedule.clone(),
            ))?;
        }
        if let Some(activation) = &self.latest_target_activation {
            self.validate_fact_shape(&AdmissionLedgerControlFactV1::TargetActivation(
                activation.clone(),
            ))?;
            if activation.consumed_schedule_count == 0
                || activation.active_target < config.minimum_target
                || activation.active_target > config.maximum_target
            {
                return Err(AdmissionError::ParentOrPrestate(
                    "recovered target activation fact is invalid".into(),
                ));
            }
        }
        if let Some(authorization) = &self.latest_rollover_authorization {
            if authorization.terminal_header.is_zero()
                || authorization.terminal_cumulative_work < rollover_threshold()
                || authorization.successor_era == 0
                || authorization.finalized_ledger_state_root.is_zero()
            {
                return Err(AdmissionError::ParentOrPrestate(
                    "recovered rollover authorization fact is invalid".into(),
                ));
            }
        }
        match (self.fact_count, &self.last_fact) {
            (0, None) => {
                if self.fact_accumulator != empty_admission_ledger_control_accumulator()
                    || self.prior_fact_accumulator.is_some()
                    || self.latest_target_schedule.is_some()
                    || self.latest_target_activation.is_some()
                    || self.latest_rollover_authorization.is_some()
                    || !self.scheduled_targets.is_empty()
                    || self.active_target != config.genesis_target
                {
                    return Err(AdmissionError::ParentOrPrestate(
                        "empty admission Ledger-control state is not its exact genesis".into(),
                    ));
                }
            }
            (count, Some(last_fact)) if count > 0 => {
                self.validate_fact_shape(last_fact)?;
                let prior_accumulator = self.prior_fact_accumulator.ok_or_else(|| {
                    AdmissionError::ParentOrPrestate(
                        "nonempty admission Ledger-control state lacks its prior accumulator"
                            .into(),
                    )
                })?;
                if (count == 1 && prior_accumulator != empty_admission_ledger_control_accumulator())
                    || (count > 1
                        && prior_accumulator == empty_admission_ledger_control_accumulator())
                    || self.fact_accumulator
                        != admission_ledger_control_accumulator_successor(
                            prior_accumulator,
                            count - 1,
                            last_fact.fact_hash(),
                        )?
                {
                    return Err(AdmissionError::ParentOrPrestate(
                        "nonempty admission Ledger-control state has an invalid final accumulator transition"
                            .into(),
                    ));
                }
            }
            _ => {
                return Err(AdmissionError::ParentOrPrestate(
                    "admission Ledger-control count and last fact disagree".into(),
                ));
            }
        }
        Ok(())
    }

    fn append_fact(&mut self, fact: AdmissionLedgerControlFactV1) -> Result<(), AdmissionError> {
        self.validate_fact_shape(&fact)?;
        let prior_accumulator = self.fact_accumulator;
        self.fact_accumulator = admission_ledger_control_accumulator_successor(
            prior_accumulator,
            self.fact_count,
            fact.fact_hash(),
        )?;
        self.fact_count = self.fact_count.checked_add(1).ok_or_else(|| {
            AdmissionError::ParentOrPrestate("admission Ledger-control fact count overflow".into())
        })?;
        self.prior_fact_accumulator = Some(prior_accumulator);
        self.last_fact = Some(fact);
        Ok(())
    }

    fn preflight_fact(&self, fact: &AdmissionLedgerControlFactV1) -> Result<(), AdmissionError> {
        self.validate_fact_shape(fact)?;
        admission_ledger_control_accumulator_successor(
            self.fact_accumulator,
            self.fact_count,
            fact.fact_hash(),
        )?;
        Ok(())
    }

    fn validate_fact_shape(
        &self,
        fact: &AdmissionLedgerControlFactV1,
    ) -> Result<(), AdmissionError> {
        if fact.fact_hash().is_zero() {
            return Err(AdmissionError::ParentOrPrestate(
                "admission Ledger-control fact is structurally invalid".into(),
            ));
        }
        match fact {
            AdmissionLedgerControlFactV1::TargetSchedule(schedule) => {
                if schedule.activation_epoch
                    != schedule.decision_epoch.checked_add(2).ok_or_else(|| {
                        AdmissionError::ParentOrPrestate(
                            "target schedule decision epoch overflow".into(),
                        )
                    })?
                {
                    return Err(AdmissionError::ParentOrPrestate(
                        "target schedule activation epoch is not delayed by two".into(),
                    ));
                }
            }
            AdmissionLedgerControlFactV1::TargetActivation(activation) => {
                if activation.consumed_schedule_count == 0 {
                    return Err(AdmissionError::ParentOrPrestate(
                        "target activation consumed no delayed schedule".into(),
                    ));
                }
            }
            AdmissionLedgerControlFactV1::RolloverAuthorization(authorization) => {
                if authorization.terminal_header.is_zero()
                    || authorization.terminal_cumulative_work < rollover_threshold()
                    || authorization.successor_era == 0
                    || authorization.finalized_ledger_state_root.is_zero()
                {
                    return Err(AdmissionError::ParentOrPrestate(
                        "rollover authorization fact is structurally invalid".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_checkpoint_proof_header<FA>(
    expected_context: &AdmissionContextV1,
    parent: AdmissionCommittedPositionV1,
    header: &PermissionlessAdmissionHeaderV1,
    access_work: &BaselineAccessWorkV1,
    ledger_anchor: &AdmissionLedgerAnchorV1,
    complete_entry_ids: Option<&[AdmissionHash32]>,
    expected_target: AdmissionWork,
    rollover_authorizations: &BTreeMap<AdmissionHash32, AdmissionRolloverAuthorizationV1>,
    verify_anchor: &mut FA,
    seen_headers: &mut BTreeSet<AdmissionHash32>,
) -> Result<AdmissionCommittedPositionV1, AdmissionError>
where
    FA: FnMut(&AdmissionLedgerAnchorV1) -> Result<(), AdmissionError>,
{
    validate_context(&header.context, expected_context)?;
    validate_context(&access_work.context, expected_context)?;
    if header.parent_header != parent.header_id || access_work.parent_header != parent.header_id {
        return Err(AdmissionError::ParentOrPrestate(
            "checkpoint proof header does not extend the preceding header".into(),
        ));
    }
    let expected_height = parent
        .log_height
        .checked_add(1)
        .ok_or_else(|| AdmissionError::ParentOrPrestate("admission log height overflow".into()))?;
    if header.log_height != expected_height {
        return Err(AdmissionError::ParentOrPrestate(
            "checkpoint proof log height is not the exact successor".into(),
        ));
    }
    if ledger_anchor.block_id.is_zero()
        || header.ledger_anchor_block != ledger_anchor.block_id
        || access_work.ledger_anchor_block != ledger_anchor.block_id
        || access_work.ledger_anchor_height != ledger_anchor.height
        || access_work.expiry_anchor_height < ledger_anchor.height
    {
        return Err(AdmissionError::ParentOrPrestate(
            "checkpoint proof ledger anchor is inconsistent or expired".into(),
        ));
    }
    verify_anchor(ledger_anchor)?;
    if usize::from(header.entries_count) > MAX_ADMISSION_ENTRIES_PER_HEADER
        || header.entries_count != access_work.entries_count
        || header.entries_root != access_work.entries_root
    {
        return Err(AdmissionError::EnvelopeLimit(
            "checkpoint proof header count/root is inconsistent or exceeds 256".into(),
        ));
    }
    if let Some(entry_ids) = complete_entry_ids {
        if usize::from(header.entries_count) != entry_ids.len()
            || admission_entry_root(entry_ids.iter().copied())? != header.entries_root
        {
            return Err(AdmissionError::ParentOrPrestate(
                "complete checkpoint batch does not match its header entry commitment".into(),
            ));
        }
    }
    if access_work.suite_id != ADMISSION_ACCESS_WORK_SUITE_V1
        || access_work.target != expected_target
        || access_work.output_hash != access_work.recompute_output_hash()
        || AdmissionWork::from_be_bytes(access_work.output_hash.0) > access_work.target
        || header.access_work_id != access_work.work_id()
    {
        return Err(AdmissionError::WorkOrProof(
            "checkpoint proof access work, target, output or address is invalid".into(),
        ));
    }
    if header.canonical_bytes().len() > MAX_ADMISSION_HEADER_WIRE_BYTES
        || access_work.canonical_bytes().len() > MAX_ADMISSION_HEADER_WIRE_BYTES
    {
        return Err(AdmissionError::EnvelopeLimit(
            "checkpoint proof header or work wire exceeds 4 KiB".into(),
        ));
    }
    let this_work = access_work.header_work();
    if this_work.is_zero() {
        return Err(AdmissionError::WorkOrProof(
            "checkpoint proof header contributes zero work".into(),
        ));
    }
    if header.admission_era == parent.admission_era {
        let cumulative = parent
            .cumulative_work
            .checked_add(this_work)
            .ok_or_else(|| {
                AdmissionError::WorkOrProof("cumulative admission work overflow".into())
            })?;
        if header.prior_era_terminal.is_some() || header.cumulative_work != cumulative {
            return Err(AdmissionError::ParentOrPrestate(
                "same-Era checkpoint proof has an invalid rollover field or cumulative work".into(),
            ));
        }
    } else {
        let successor_era = parent
            .admission_era
            .checked_add(1)
            .ok_or_else(|| AdmissionError::ParentOrPrestate("admission Era overflow".into()))?;
        let authorization = rollover_authorizations
            .get(&parent.header_id)
            .ok_or_else(|| {
                AdmissionError::TransitionOrValueCap(
                    "checkpoint proof has no locally finalized rollover authorization".into(),
                )
            })?;
        if parent.cumulative_work < rollover_threshold()
            || header.admission_era != successor_era
            || header.prior_era_terminal != Some(parent.header_id)
            || header.cumulative_work != this_work
            || authorization.terminal_header != parent.header_id
            || authorization.terminal_cumulative_work != parent.cumulative_work
            || authorization.successor_era != successor_era
            || authorization.finalized_ledger_state_root.is_zero()
        {
            return Err(AdmissionError::TransitionOrValueCap(
                "checkpoint proof admission Era rollover is not the unique finalized successor"
                    .into(),
            ));
        }
    }
    let header_id = header.header_id();
    if !seen_headers.insert(header_id) {
        return Err(AdmissionError::ParentOrPrestate(
            "checkpoint proof repeats an admission header".into(),
        ));
    }
    Ok(AdmissionCommittedPositionV1 {
        header_id,
        admission_era: header.admission_era,
        log_height: header.log_height,
        cumulative_work: header.cumulative_work,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct StoredAdmissionHeaderV1 {
    header: Option<PermissionlessAdmissionHeaderV1>,
    access_work: Option<BaselineAccessWorkV1>,
    entries: Vec<AdmissionBatchEntryV1>,
    header_work: AdmissionWork,
    entry_ids: Vec<AdmissionHash32>,
    available_entries: Vec<AdmissionAvailableEntryV1>,
    all_available: bool,
}

impl StoredAdmissionHeaderV1 {
    fn admission_era(&self) -> u128 {
        self.header
            .as_ref()
            .map_or(0, |header| header.admission_era)
    }

    fn log_height(&self) -> u128 {
        self.header.as_ref().map_or(0, |header| header.log_height)
    }

    fn cumulative_work(&self) -> AdmissionWork {
        self.header
            .as_ref()
            .map_or(AdmissionWork::ZERO, |header| header.cumulative_work)
    }

    fn parent(&self) -> Option<AdmissionHash32> {
        self.header.as_ref().map(|header| header.parent_header)
    }
}

pub(crate) struct ConfirmedAdmissionPrefix {
    pub prior_committed_header: AdmissionHash32,
    pub selected_header: PermissionlessAdmissionHeaderV1,
    pub canonical_tip: AdmissionHash32,
    pub source_headers: Vec<AdmissionHash32>,
    pub entry_ids: Vec<AdmissionHash32>,
    pub availability: Vec<AdmissionAvailableEntryV1>,
    pub confirmations: u16,
    pub descendant_work: AdmissionWork,
    pub observed_ledger_height: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedAdmissionCheckpointV1 {
    pub checkpoint: AdmissionCheckpointV1,
    pub prior_committed_header: AdmissionHash32,
    pub entry_ids: Vec<AdmissionHash32>,
    pub observed_ledger_height: u128,
    pub committing_ledger_height: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PermissionlessAdmissionLogV1 {
    context: AdmissionContextV1,
    config: AdmissionLogConfigV1,
    genesis_header: AdmissionHash32,
    committed_header: AdmissionHash32,
    canonical_tip: AdmissionHash32,
    active_target: AdmissionWork,
    scheduled_targets: BTreeMap<u128, AdmissionWork>,
    headers: BTreeMap<AdmissionHash32, StoredAdmissionHeaderV1>,
    entry_headers: BTreeMap<AdmissionHash32, BTreeSet<AdmissionHash32>>,
    rollover_authorizations: BTreeMap<AdmissionHash32, AdmissionRolloverAuthorizationV1>,
}

impl PermissionlessAdmissionLogV1 {
    pub fn new(
        context: AdmissionContextV1,
        config: AdmissionLogConfigV1,
        genesis_header: AdmissionHash32,
    ) -> Result<Self, AdmissionError> {
        context.validate()?;
        config.validate()?;
        if genesis_header.is_zero() {
            return Err(AdmissionError::ParentOrPrestate(
                "admission genesis header id cannot be zero".into(),
            ));
        }
        let mut headers = BTreeMap::new();
        headers.insert(
            genesis_header,
            StoredAdmissionHeaderV1 {
                header: None,
                access_work: None,
                entries: Vec::new(),
                header_work: AdmissionWork::ZERO,
                entry_ids: Vec::new(),
                available_entries: Vec::new(),
                all_available: true,
            },
        );
        Ok(Self {
            context,
            active_target: config.genesis_target,
            config,
            genesis_header,
            committed_header: genesis_header,
            canonical_tip: genesis_header,
            scheduled_targets: BTreeMap::new(),
            headers,
            entry_headers: BTreeMap::new(),
            rollover_authorizations: BTreeMap::new(),
        })
    }

    pub fn context(&self) -> &AdmissionContextV1 {
        &self.context
    }

    pub fn canonical_tip(&self) -> AdmissionHash32 {
        self.canonical_tip
    }

    pub fn genesis_header(&self) -> AdmissionHash32 {
        self.genesis_header
    }

    pub fn committed_header(&self) -> AdmissionHash32 {
        self.committed_header
    }

    pub fn active_target(&self) -> AdmissionWork {
        self.active_target
    }

    pub fn scheduled_target_count(&self) -> usize {
        self.scheduled_targets.len()
    }

    pub fn rollover_authorization_count(&self) -> usize {
        self.rollover_authorizations.len()
    }

    pub fn contains_header(&self, header_id: AdmissionHash32) -> bool {
        self.headers.contains_key(&header_id)
    }

    /// Verifies a formal tag-28 proof against both bounded Ledger state and
    /// this exact locally recovered Admission history. The Ledger supplies the
    /// committed predecessor, accumulator, target and authenticated proposal
    /// height; this log supplies the full rollover set and retained-history
    /// callbacks. Neither side can silently substitute the other's state.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_checkpoint_proof_against_ledger_state<C, FA, FE, FC>(
        &self,
        proof: &AdmissionCheckpointProofV1,
        ledger_state: &LedgerAdmissionStateV1,
        proposal_context: &C,
        verify_anchor: FA,
        verify_batch_entry: FE,
        verify_confirmation_header: FC,
    ) -> Result<VerifiedAdmissionCheckpointTransitionV1, AdmissionError>
    where
        C: AdmissionCheckpointProofContextV1,
        FA: FnMut(&AdmissionLedgerAnchorV1) -> Result<(), AdmissionError>,
        FE: FnMut(&PermissionlessAdmissionEntryV1) -> Result<(), AdmissionError>,
        FC: FnMut(
            &PermissionlessAdmissionHeaderV1,
            &BaselineAccessWorkV1,
            &AdmissionLedgerAnchorV1,
        ) -> Result<(), AdmissionError>,
    {
        self.validate_recovered()?;
        ledger_state.validate_recovered()?;
        let ledger_scheduled_targets = ledger_state
            .control
            .scheduled_targets
            .iter()
            .map(|(epoch, schedule)| (*epoch, schedule.target))
            .collect::<BTreeMap<_, _>>();
        let latest_rollover_is_retained = ledger_state
            .control
            .latest_rollover_authorization
            .as_ref()
            .is_none_or(|authorization| {
                self.rollover_authorizations
                    .get(&authorization.terminal_header)
                    == Some(authorization)
            });
        if self.context != ledger_state.genesis.context
            || self.config != ledger_state.genesis.config
            || self.genesis_header != ledger_state.genesis.genesis_header
            || self.committed_header != ledger_state.committed_header
            || self.active_target != ledger_state.control.active_target
            || self.scheduled_targets != ledger_scheduled_targets
            || !latest_rollover_is_retained
        {
            return Err(AdmissionError::ParentOrPrestate(
                "local Admission history does not match the bounded Ledger checkpoint/control prestate"
                    .into(),
            ));
        }
        proof.verify_bounded(
            &ledger_state.genesis,
            ledger_state.committed_position()?,
            ledger_state.checkpoint_count,
            ledger_state.checkpoint_accumulator,
            proposal_context,
            ledger_state.control.active_target,
            &self.rollover_authorizations,
            verify_anchor,
            verify_batch_entry,
            verify_confirmation_header,
        )
    }

    /// Returns the exact retained source data for one non-genesis header.
    /// Durable stores use this to validate omitted confirmation bodies rather
    /// than trusting a proposal's header-only claim.
    pub fn retained_header_batch(
        &self,
        header_id: AdmissionHash32,
    ) -> Result<AdmissionCheckpointBatchProofV1, AdmissionError> {
        let stored = self.headers.get(&header_id).ok_or_else(|| {
            AdmissionError::ParentOrPrestate("admission header is not retained locally".into())
        })?;
        let header = stored.header.clone().ok_or_else(|| {
            AdmissionError::ParentOrPrestate("admission genesis has no header body".into())
        })?;
        let access_work = stored.access_work.clone().ok_or_else(|| {
            AdmissionError::ParentOrPrestate("admission header has no retained access work".into())
        })?;
        Ok(AdmissionCheckpointBatchProofV1 {
            entries: stored
                .entries
                .iter()
                .map(|record| record.entry.clone())
                .collect(),
            ledger_anchor: AdmissionLedgerAnchorV1 {
                block_id: header.ledger_anchor_block,
                height: access_work.ledger_anchor_height,
            },
            access_work,
            header,
        })
    }

    pub fn entry_appears_in_ancestry_of(
        &self,
        entry_id: AdmissionHash32,
        head: AdmissionHash32,
    ) -> Result<bool, AdmissionError> {
        self.entry_appears_in_ancestry(entry_id, head)
    }

    pub fn schedule_target_from_completed_window(
        &mut self,
        decision_epoch: u128,
        completed_epoch_header_counts: [u64; 4],
    ) -> Result<(u128, AdmissionWork), AdmissionError> {
        let activation_epoch = decision_epoch.checked_add(2).ok_or_else(|| {
            AdmissionError::ParentOrPrestate("target activation epoch overflow".into())
        })?;
        let next = adjusted_admission_target(
            self.active_target,
            completed_epoch_header_counts,
            self.config.minimum_target,
            self.config.maximum_target,
        )?;
        if self
            .scheduled_targets
            .get(&activation_epoch)
            .is_some_and(|existing| *existing != next)
        {
            return Err(AdmissionError::ParentOrPrestate(
                "conflicting delayed target already scheduled".into(),
            ));
        }
        self.scheduled_targets.insert(activation_epoch, next);
        Ok((activation_epoch, next))
    }

    pub fn activate_scheduled_target(
        &mut self,
        ledger_epoch: u128,
        ledger_progressing: bool,
    ) -> AdmissionWork {
        if !ledger_progressing {
            return self.active_target;
        }
        let eligible: Vec<_> = self
            .scheduled_targets
            .range(..=ledger_epoch)
            .map(|(epoch, target)| (*epoch, *target))
            .collect();
        for (epoch, target) in eligible {
            self.active_target = target;
            self.scheduled_targets.remove(&epoch);
        }
        self.active_target
    }

    pub fn record_rollover_authorization(
        &mut self,
        authorization: AdmissionRolloverAuthorizationV1,
    ) -> Result<(), AdmissionError> {
        let terminal = self
            .headers
            .get(&authorization.terminal_header)
            .ok_or_else(|| {
                AdmissionError::ParentOrPrestate("rollover terminal is unknown".into())
            })?;
        if terminal.cumulative_work() != authorization.terminal_cumulative_work
            || terminal.cumulative_work() < rollover_threshold()
            || authorization.successor_era
                != terminal.admission_era().checked_add(1).ok_or_else(|| {
                    AdmissionError::ParentOrPrestate("admission era overflow".into())
                })?
            || authorization.finalized_ledger_state_root.is_zero()
        {
            return Err(AdmissionError::TransitionOrValueCap(
                "rollover lacks exact finalized terminal threshold evidence".into(),
            ));
        }
        if let Some(existing) = self
            .rollover_authorizations
            .get(&authorization.terminal_header)
        {
            if existing != &authorization {
                return Err(AdmissionError::DuplicateOrNullifier(
                    "conflicting rollover authorization".into(),
                ));
            }
            return Ok(());
        }
        self.rollover_authorizations
            .insert(authorization.terminal_header, authorization);
        Ok(())
    }

    /// Accepts a header only after recomputing every sidecar content locator
    /// from exact locally held bytes. This is the only append API intended for
    /// node/runtime use.
    pub fn append_verified_header(
        &mut self,
        submission: AdmissionVerifiedHeaderSubmissionV1,
    ) -> Result<AdmissionHash32, AdmissionError> {
        self.append_verified_header_ref(&submission)
    }

    /// Borrowing ingress used by durable/network adapters so exact sidecar
    /// bytes do not need to be cloned merely to validate the candidate log.
    pub fn append_verified_header_ref(
        &mut self,
        submission: &AdmissionVerifiedHeaderSubmissionV1,
    ) -> Result<AdmissionHash32, AdmissionError> {
        let mut availability_bytes = 0u64;
        let mut entries = Vec::with_capacity(submission.entries.len());
        for submitted in &submission.entries {
            verify_admission_sidecar(&submitted.entry, &submitted.payload)?;
            availability_bytes = availability_bytes
                .checked_add(submitted.entry.declared_bytes)
                .ok_or_else(|| {
                    AdmissionError::EnvelopeLimit(
                        "admission header sidecar byte total overflow".into(),
                    )
                })?;
            if availability_bytes > MAX_ADMISSION_CHECKPOINT_AVAILABILITY_BYTES {
                return Err(AdmissionError::EnvelopeLimit(
                    "admission header sidecar availability exceeds 64 MiB".into(),
                ));
            }
            entries.push(AdmissionBatchEntryV1 {
                body_bytes: u64::try_from(submitted.entry.canonical_bytes().len()).map_err(
                    |_| {
                        AdmissionError::EnvelopeLimit(
                            "admission entry body length does not fit U64".into(),
                        )
                    },
                )?,
                sidecar_bytes: submitted.entry.declared_bytes,
                entry: submitted.entry.clone(),
                availability_verified: true,
            });
        }
        self.append_header(AdmissionHeaderBatchV1 {
            entries,
            access_work: submission.access_work.clone(),
            header: submission.header.clone(),
            ledger_anchor: submission.ledger_anchor.clone(),
        })
    }

    pub(crate) fn append_header(
        &mut self,
        batch: AdmissionHeaderBatchV1,
    ) -> Result<AdmissionHash32, AdmissionError> {
        self.validate_batch_envelope(&batch)?;
        let mut canonical_entries = batch.entries.clone();
        canonical_entries.sort_unstable_by_key(|item| item.entry.entry_id());
        let parent = self
            .headers
            .get(&batch.header.parent_header)
            .ok_or_else(|| AdmissionError::ParentOrPrestate("unknown admission parent".into()))?
            .clone();
        validate_context(&batch.access_work.context, &self.context)?;
        validate_context(&batch.header.context, &self.context)?;
        if batch.ledger_anchor.block_id.is_zero()
            || batch.access_work.ledger_anchor_block != batch.ledger_anchor.block_id
            || batch.header.ledger_anchor_block != batch.ledger_anchor.block_id
            || batch.access_work.ledger_anchor_height != batch.ledger_anchor.height
        {
            return Err(AdmissionError::ParentOrPrestate(
                "ledger anchor block or height mismatch".into(),
            ));
        }
        if batch.access_work.parent_header != batch.header.parent_header {
            return Err(AdmissionError::ParentOrPrestate(
                "access work and header do not share the exact parent".into(),
            ));
        }

        let mut entry_ids = Vec::with_capacity(canonical_entries.len());
        let mut available_entries = Vec::with_capacity(canonical_entries.len());
        for item in &canonical_entries {
            item.entry
                .validate(&self.context, batch.ledger_anchor.height)?;
            let entry_id = item.entry.entry_id();
            if entry_ids.contains(&entry_id)
                || self.entry_appears_in_ancestry(entry_id, batch.header.parent_header)?
            {
                return Err(AdmissionError::DuplicateOrNullifier(
                    "admission entry already appears in this log".into(),
                ));
            }
            if item.body_bytes != item.entry.canonical_bytes().len() as u64
                || item.sidecar_bytes != item.entry.declared_bytes
                || item.sidecar_bytes > MAX_ADMISSION_SIDECAR_BYTES
            {
                return Err(AdmissionError::ResourceOrAvailability(
                    "entry body/sidecar byte accounting mismatch".into(),
                ));
            }
            entry_ids.push(entry_id);
            available_entries.push(AdmissionAvailableEntryV1 {
                entry_id,
                locator_commitment: item.entry.locator_commitment,
                declared_bytes: item.entry.declared_bytes,
            });
        }
        let entries_root = admission_entry_root(entry_ids.iter().copied())?;
        if batch.access_work.entries_root != entries_root
            || batch.header.entries_root != entries_root
            || usize::from(batch.access_work.entries_count) != entry_ids.len()
            || usize::from(batch.header.entries_count) != entry_ids.len()
        {
            return Err(AdmissionError::ParentOrPrestate(
                "entry count or root does not match the complete header batch".into(),
            ));
        }
        if batch.access_work.suite_id != ADMISSION_ACCESS_WORK_SUITE_V1
            || batch.access_work.target != self.active_target
            || batch.access_work.expiry_anchor_height < batch.ledger_anchor.height
            || batch.access_work.output_hash != batch.access_work.recompute_output_hash()
            || AdmissionWork::from_be_bytes(batch.access_work.output_hash.0)
                > batch.access_work.target
        {
            return Err(AdmissionError::WorkOrProof(
                "baseline access work is invalid, expired, or uses the wrong target".into(),
            ));
        }
        if batch.header.access_work_id != batch.access_work.work_id() {
            return Err(AdmissionError::ParentOrPrestate(
                "header access_work_id does not address the supplied work".into(),
            ));
        }

        let expected_height = parent.log_height().checked_add(1).ok_or_else(|| {
            AdmissionError::ParentOrPrestate("admission log height overflow".into())
        })?;
        if batch.header.log_height != expected_height {
            return Err(AdmissionError::ParentOrPrestate(
                "admission log height must increase by exactly one".into(),
            ));
        }
        let this_work = batch.access_work.header_work();
        if batch.header.admission_era == parent.admission_era() {
            if batch.header.prior_era_terminal.is_some()
                || batch.header.cumulative_work
                    != parent
                        .cumulative_work()
                        .checked_add(this_work)
                        .ok_or_else(|| {
                            AdmissionError::WorkOrProof("cumulative admission work overflow".into())
                        })?
            {
                return Err(AdmissionError::ParentOrPrestate(
                    "continuing header has wrong cumulative work or rollover field".into(),
                ));
            }
        } else {
            let successor = parent
                .admission_era()
                .checked_add(1)
                .ok_or_else(|| AdmissionError::ParentOrPrestate("admission era overflow".into()))?;
            let authorization = self
                .rollover_authorizations
                .get(&batch.header.parent_header);
            if batch.header.admission_era != successor
                || batch.header.prior_era_terminal != Some(batch.header.parent_header)
                || batch.header.cumulative_work != this_work
                || authorization.is_none_or(|value| value.successor_era != successor)
            {
                return Err(AdmissionError::TransitionOrValueCap(
                    "admission era rollover is not the unique finalized successor".into(),
                ));
            }
        }
        let header_wire = batch.header.canonical_bytes();
        if header_wire.len() > MAX_ADMISSION_HEADER_WIRE_BYTES {
            return Err(AdmissionError::EnvelopeLimit(
                "admission header wire exceeds 4 KiB".into(),
            ));
        }
        let header_id = batch.header.header_id();
        if self.headers.contains_key(&header_id) {
            return Err(AdmissionError::DuplicateOrNullifier(
                "admission header already exists".into(),
            ));
        }

        let all_available = canonical_entries
            .iter()
            .all(|entry| entry.availability_verified);
        self.headers.insert(
            header_id,
            StoredAdmissionHeaderV1 {
                header: Some(batch.header),
                access_work: Some(batch.access_work),
                entries: canonical_entries,
                header_work: this_work,
                entry_ids: entry_ids.clone(),
                available_entries,
                all_available,
            },
        );
        for entry_id in entry_ids {
            self.entry_headers
                .entry(entry_id)
                .or_default()
                .insert(header_id);
        }
        if self.is_descendant_of(header_id, self.committed_header)?
            && self.header_precedes_in_fork_choice(header_id, self.canonical_tip)?
        {
            self.canonical_tip = header_id;
        }
        Ok(header_id)
    }

    /// Structural selection only. Its crate-private output is not a finalized
    /// checkpoint, an authenticated observation or permission to waive lag.
    pub(crate) fn confirmed_prefix_for_observation(
        &self,
    ) -> Result<Option<ConfirmedAdmissionPrefix>, AdmissionError> {
        let source_headers = self.path_after(self.committed_header, self.canonical_tip)?;
        // A valid, still-short history is normal for a read-only observation.
        // The ordinary builder below continues to reject an absent prefix.
        if source_headers.len() <= MIN_ADMISSION_CONFIRMATIONS {
            return Ok(None);
        }
        let confirmed_head = self.highest_confirmed_header()?;
        if confirmed_head == self.committed_header {
            return Ok(None);
        }
        let path = self.path_after(self.committed_header, confirmed_head)?;
        let mut selected = Vec::new();
        let mut entry_count = 0usize;
        for header_id in path {
            let node = self.headers.get(&header_id).expect("path header exists");
            let proposed = entry_count
                .checked_add(node.entry_ids.len())
                .ok_or_else(|| {
                    AdmissionError::EnvelopeLimit("checkpoint entry count overflow".into())
                })?;
            if proposed > MAX_CHECKPOINT_ENTRIES_PER_LEDGER_BLOCK {
                break;
            }
            if !node.all_available {
                return Err(AdmissionError::ResourceOrAvailability(
                    "confirmed checkpoint batch has unavailable entry data".into(),
                ));
            }
            entry_count = proposed;
            selected.push(header_id);
        }
        let selected_header = *selected.last().ok_or_else(|| {
            AdmissionError::EnvelopeLimit(
                "next complete header cannot fit the 512-entry checkpoint limit".into(),
            )
        })?;
        let (confirmations, descendant_work) = self.confirmation_metrics(selected_header)?;
        let mut entry_ids = Vec::with_capacity(entry_count);
        let mut availability = Vec::with_capacity(entry_count);
        for header_id in &selected {
            let node = self.headers.get(header_id).expect("selected header exists");
            entry_ids.extend(node.entry_ids.iter().copied());
            availability.extend(node.available_entries.iter().cloned());
        }
        entry_ids.sort_unstable();
        availability.sort_unstable_by_key(|record| record.entry_id);
        let selected_node = self
            .headers
            .get(&selected_header)
            .expect("selected header exists");
        let selected_header_value = selected_node.header.as_ref().expect("not genesis");
        let observed_ledger_height = selected_node
            .access_work
            .as_ref()
            .expect("not genesis")
            .ledger_anchor_height;
        Ok(Some(ConfirmedAdmissionPrefix {
            prior_committed_header: self.committed_header,
            selected_header: selected_header_value.clone(),
            canonical_tip: self.canonical_tip,
            source_headers,
            entry_ids,
            availability,
            confirmations: u16::try_from(confirmations).map_err(|_| {
                AdmissionError::EnvelopeLimit("confirmation count exceeds U16".into())
            })?,
            descendant_work,
            observed_ledger_height,
        }))
    }

    pub fn build_confirmed_checkpoint(
        &self,
        committing_ledger_height: u128,
    ) -> Result<PreparedAdmissionCheckpointV1, AdmissionError> {
        let prefix = self.confirmed_prefix_for_observation()?.ok_or_else(|| {
            AdmissionError::ParentOrPrestate(
                "no new confirmed admission header is available".into(),
            )
        })?;
        let observed_ledger_height = prefix.observed_ledger_height;
        if committing_ledger_height < observed_ledger_height {
            return Err(AdmissionError::TransitionOrValueCap(
                "checkpoint commit height precedes its authenticated Ledger anchor".into(),
            ));
        }
        let mapping = &self.config.contribution_epoch_mapping;
        let observed_ledger_epoch = mapping.epoch_at_height(observed_ledger_height)?;
        let committed_ledger_epoch = mapping.epoch_at_height(committing_ledger_height)?;
        if committed_ledger_epoch < observed_ledger_epoch
            || committed_ledger_epoch - observed_ledger_epoch > MAX_ADMISSION_LAG_EPOCHS
        {
            return Err(AdmissionError::TransitionOrValueCap(
                "admission checkpoint exceeds the two-Epoch ledger lag".into(),
            ));
        }
        let checkpoint = AdmissionCheckpointV1 {
            context: self.context.clone(),
            admission_era: prefix.selected_header.admission_era,
            header_id: prefix.selected_header.header_id(),
            log_height: prefix.selected_header.log_height,
            cumulative_work: prefix.selected_header.cumulative_work,
            confirmations: prefix.confirmations,
            descendant_work: prefix.descendant_work,
            entries_root: admission_entry_root(prefix.entry_ids.iter().copied())?,
            availability_root: admission_availability_root(&prefix.availability)?,
            observed_ledger_epoch,
            committed_ledger_epoch,
        };
        Ok(PreparedAdmissionCheckpointV1 {
            checkpoint,
            prior_committed_header: self.committed_header,
            entry_ids: prefix.entry_ids,
            observed_ledger_height,
            committing_ledger_height,
        })
    }

    pub fn apply_finalized_checkpoint(
        &mut self,
        prepared: &PreparedAdmissionCheckpointV1,
    ) -> Result<(), AdmissionError> {
        if prepared.prior_committed_header != self.committed_header {
            return Err(AdmissionError::ParentOrPrestate(
                "checkpoint predecessor is not the last finalized admission header".into(),
            ));
        }
        let expected = self.build_confirmed_checkpoint(prepared.committing_ledger_height)?;
        if &expected != prepared {
            return Err(AdmissionError::ParentOrPrestate(
                "checkpoint does not match the canonical bounded confirmed prefix".into(),
            ));
        }
        self.committed_header = prepared.checkpoint.header_id;
        if !self.is_descendant_of(self.canonical_tip, self.committed_header)? {
            self.canonical_tip = self.committed_header;
        }
        Ok(())
    }

    /// Rebuilds and applies the Admission-log projection of a checkpoint that
    /// was already verified while replaying an authenticated main-WAL tag-28
    /// commit. The Admission WAL must not store a second commit decision: its
    /// retained headers and sidecars are source evidence, while the certified
    /// main WAL is the sole durable checkpoint authority.
    ///
    /// This method still reconstructs the canonical bounded prefix from local
    /// history and compares every prepared field before advancing
    /// `committed_header`; a transition cannot rewrite fork choice merely
    /// because its outer Ledger proof was previously verified.
    pub fn apply_replayed_main_wal_checkpoint_projection(
        &mut self,
        transition: &VerifiedAdmissionCheckpointTransitionV1,
    ) -> Result<(), AdmissionError> {
        if transition.proof_id.is_zero() || transition.next_checkpoint_accumulator.is_zero() {
            return Err(AdmissionError::ParentOrPrestate(
                "replayed checkpoint projection has no proof or accumulator commitment".into(),
            ));
        }
        self.apply_finalized_checkpoint(&PreparedAdmissionCheckpointV1 {
            checkpoint: transition.checkpoint.clone(),
            prior_committed_header: transition.prior_committed_header,
            entry_ids: transition.entry_ids.clone(),
            observed_ledger_height: transition.observed_ledger_height,
            committing_ledger_height: transition.committing_ledger_height,
        })
    }

    pub fn validate_recovered(&self) -> Result<(), AdmissionError> {
        self.context.validate()?;
        self.config.validate()?;
        if self.active_target < self.config.minimum_target
            || self.active_target > self.config.maximum_target
            || header_work(self.active_target).is_zero()
            || self.scheduled_targets.values().any(|target| {
                *target < self.config.minimum_target
                    || *target > self.config.maximum_target
                    || header_work(*target).is_zero()
            })
        {
            return Err(AdmissionError::WorkOrProof(
                "recovered active or scheduled target is outside immutable nonzero-work bounds"
                    .into(),
            ));
        }
        if !self.headers.contains_key(&self.genesis_header)
            || !self.headers.contains_key(&self.committed_header)
            || !self.headers.contains_key(&self.canonical_tip)
            || !self.is_descendant_of(self.canonical_tip, self.committed_header)?
        {
            return Err(AdmissionError::ParentOrPrestate(
                "recovered admission anchors are missing or inconsistent".into(),
            ));
        }
        let genesis = self.headers.get(&self.genesis_header).expect("checked");
        if genesis.header.is_some()
            || genesis.access_work.is_some()
            || !genesis.entries.is_empty()
            || !genesis.entry_ids.is_empty()
            || !genesis.available_entries.is_empty()
            || !genesis.all_available
            || genesis.header_work != AdmissionWork::ZERO
            || genesis.cumulative_work() != AdmissionWork::ZERO
        {
            return Err(AdmissionError::ParentOrPrestate(
                "recovered admission genesis record is invalid".into(),
            ));
        }
        if self
            .headers
            .iter()
            .any(|(header_id, node)| node.header.is_none() != (*header_id == self.genesis_header))
        {
            return Err(AdmissionError::ParentOrPrestate(
                "recovered admission log has an alternate root or a non-genesis null header".into(),
            ));
        }
        let mut rebuilt_entries: BTreeMap<AdmissionHash32, BTreeSet<AdmissionHash32>> =
            BTreeMap::new();
        for (header_id, node) in &self.headers {
            let Some(header) = &node.header else {
                continue;
            };
            let access_work = node.access_work.as_ref().ok_or_else(|| {
                AdmissionError::ParentOrPrestate(
                    "recovered admission header has no retained access work".into(),
                )
            })?;
            let parent = self.headers.get(&header.parent_header).ok_or_else(|| {
                AdmissionError::ParentOrPrestate(
                    "recovered admission header has an unknown parent".into(),
                )
            })?;
            let rebuilt_ids: Vec<_> = node
                .entries
                .iter()
                .map(|item| item.entry.entry_id())
                .collect();
            let rebuilt_availability: Vec<_> = node
                .entries
                .iter()
                .map(|item| AdmissionAvailableEntryV1 {
                    entry_id: item.entry.entry_id(),
                    locator_commitment: item.entry.locator_commitment,
                    declared_bytes: item.entry.declared_bytes,
                })
                .collect();
            let batch_body_bytes = node.entries.iter().try_fold(0usize, |total, item| {
                let body = usize::try_from(item.body_bytes).map_err(|_| {
                    AdmissionError::EnvelopeLimit(
                        "recovered entry body length does not fit usize".into(),
                    )
                })?;
                total.checked_add(body).ok_or_else(|| {
                    AdmissionError::EnvelopeLimit(
                        "recovered admission batch body length overflow".into(),
                    )
                })
            })?;
            if !self.is_descendant_of(*header_id, self.genesis_header)?
                || header.context != self.context
                || access_work.context != self.context
                || header.header_id() != *header_id
                || access_work.work_id() != header.access_work_id
                || access_work.header_work() != node.header_work
                || node.header_work.is_zero()
                || access_work.output_hash != access_work.recompute_output_hash()
                || AdmissionWork::from_be_bytes(access_work.output_hash.0) > access_work.target
                || access_work.suite_id != ADMISSION_ACCESS_WORK_SUITE_V1
                || access_work.target < self.config.minimum_target
                || access_work.target > self.config.maximum_target
                || access_work.ledger_anchor_block.is_zero()
                || access_work.expiry_anchor_height < access_work.ledger_anchor_height
                || access_work.parent_header != header.parent_header
                || access_work.ledger_anchor_block != header.ledger_anchor_block
                || access_work.entries_root != header.entries_root
                || access_work.entries_count != header.entries_count
                || header.canonical_bytes().len() > MAX_ADMISSION_HEADER_WIRE_BYTES
                || node.entries.len() > MAX_ADMISSION_ENTRIES_PER_HEADER
                || batch_body_bytes > MAX_ADMISSION_BATCH_BODY_BYTES
                || rebuilt_ids != node.entry_ids
                || rebuilt_ids.windows(2).any(|window| window[0] >= window[1])
                || rebuilt_availability != node.available_entries
                || node.all_available
                    != node.entries.iter().all(|entry| entry.availability_verified)
                || admission_entry_root(rebuilt_ids.iter().copied())? != header.entries_root
                || usize::from(header.entries_count) != rebuilt_ids.len()
                || header.log_height
                    != parent.log_height().checked_add(1).ok_or_else(|| {
                        AdmissionError::ParentOrPrestate(
                            "recovered admission log height overflow".into(),
                        )
                    })?
            {
                return Err(AdmissionError::ParentOrPrestate(
                    "recovered admission header or entry index is invalid".into(),
                ));
            }
            for item in &node.entries {
                item.entry
                    .validate(&self.context, access_work.ledger_anchor_height)?;
                if item.body_bytes != item.entry.canonical_bytes().len() as u64
                    || item.sidecar_bytes != item.entry.declared_bytes
                    || item.sidecar_bytes > MAX_ADMISSION_SIDECAR_BYTES
                {
                    return Err(AdmissionError::ResourceOrAvailability(
                        "recovered entry resource accounting is invalid".into(),
                    ));
                }
            }
            if header.admission_era == parent.admission_era() {
                if header.prior_era_terminal.is_some()
                    || header.cumulative_work
                        != parent
                            .cumulative_work()
                            .checked_add(node.header_work)
                            .ok_or_else(|| {
                                AdmissionError::WorkOrProof(
                                    "recovered cumulative admission work overflow".into(),
                                )
                            })?
                {
                    return Err(AdmissionError::ParentOrPrestate(
                        "recovered continuing header work is invalid".into(),
                    ));
                }
            } else if header.admission_era
                != parent.admission_era().checked_add(1).ok_or_else(|| {
                    AdmissionError::ParentOrPrestate("recovered admission era overflow".into())
                })?
                || header.prior_era_terminal != Some(header.parent_header)
                || header.cumulative_work != node.header_work
                || self
                    .rollover_authorizations
                    .get(&header.parent_header)
                    .is_none_or(|authorization| authorization.successor_era != header.admission_era)
            {
                return Err(AdmissionError::TransitionOrValueCap(
                    "recovered admission rollover is invalid".into(),
                ));
            }
            for entry_id in &node.entry_ids {
                rebuilt_entries
                    .entry(*entry_id)
                    .or_default()
                    .insert(*header_id);
            }
        }
        if rebuilt_entries != self.entry_headers {
            return Err(AdmissionError::ParentOrPrestate(
                "recovered admission entry index does not rebuild".into(),
            ));
        }
        let pending = self.pending_entry_count()?;
        if pending > MAX_PENDING_ADMISSION_ENTRIES {
            return Err(AdmissionError::EnvelopeLimit(
                "recovered pending admission inventory exceeds 65,536 entries".into(),
            ));
        }
        for containing_headers in rebuilt_entries.values() {
            for left in containing_headers {
                for right in containing_headers {
                    if left != right && self.is_descendant_of(*left, *right)? {
                        return Err(AdmissionError::DuplicateOrNullifier(
                            "recovered admission ancestry repeats one entry".into(),
                        ));
                    }
                }
            }
        }
        for (terminal_header, authorization) in &self.rollover_authorizations {
            let terminal = self.headers.get(terminal_header).ok_or_else(|| {
                AdmissionError::TransitionOrValueCap(
                    "recovered rollover authorization references an unknown terminal".into(),
                )
            })?;
            if authorization.terminal_header != *terminal_header
                || authorization.terminal_cumulative_work != terminal.cumulative_work()
                || authorization.terminal_cumulative_work < rollover_threshold()
                || authorization.successor_era
                    != terminal.admission_era().checked_add(1).ok_or_else(|| {
                        AdmissionError::TransitionOrValueCap(
                            "recovered rollover successor era overflow".into(),
                        )
                    })?
                || authorization.finalized_ledger_state_root.is_zero()
            {
                return Err(AdmissionError::TransitionOrValueCap(
                    "recovered rollover authorization is not exact threshold evidence".into(),
                ));
            }
        }
        let mut expected_tip = self.committed_header;
        for header_id in self.headers.keys().copied() {
            if self.is_descendant_of(header_id, self.committed_header)?
                && self.header_precedes_in_fork_choice(header_id, expected_tip)?
            {
                expected_tip = header_id;
            }
        }
        if self.canonical_tip != expected_tip {
            return Err(AdmissionError::ParentOrPrestate(
                "recovered canonical tip does not match deterministic fork choice".into(),
            ));
        }
        Ok(())
    }

    fn validate_batch_envelope(
        &self,
        batch: &AdmissionHeaderBatchV1,
    ) -> Result<(), AdmissionError> {
        if batch.entries.len() > MAX_ADMISSION_ENTRIES_PER_HEADER
            || batch.entries.len() > usize::from(u16::MAX)
        {
            return Err(AdmissionError::EnvelopeLimit(
                "admission header exceeds 256 entries".into(),
            ));
        }
        let body_bytes = batch.entries.iter().try_fold(0usize, |total, item| {
            let body = usize::try_from(item.body_bytes).map_err(|_| {
                AdmissionError::EnvelopeLimit("entry body length does not fit usize".into())
            })?;
            total.checked_add(body).ok_or_else(|| {
                AdmissionError::EnvelopeLimit("admission batch body length overflow".into())
            })
        })?;
        if body_bytes > MAX_ADMISSION_BATCH_BODY_BYTES {
            return Err(AdmissionError::EnvelopeLimit(
                "admission header body batch exceeds 512 KiB".into(),
            ));
        }
        let pending = self.pending_entry_count()?;
        if pending
            .checked_add(batch.entries.len())
            .is_none_or(|count| count > MAX_PENDING_ADMISSION_ENTRIES)
        {
            return Err(AdmissionError::EnvelopeLimit(
                "pending confirmed admission inventory exceeds 65,536 entries".into(),
            ));
        }
        Ok(())
    }

    fn pending_entry_count(&self) -> Result<usize, AdmissionError> {
        let path = self.path_after(self.committed_header, self.canonical_tip)?;
        path.into_iter().try_fold(0usize, |total, header_id| {
            total
                .checked_add(
                    self.headers
                        .get(&header_id)
                        .expect("path header")
                        .entry_ids
                        .len(),
                )
                .ok_or_else(|| {
                    AdmissionError::EnvelopeLimit("pending admission inventory overflow".into())
                })
        })
    }

    fn entry_appears_in_ancestry(
        &self,
        entry_id: AdmissionHash32,
        parent: AdmissionHash32,
    ) -> Result<bool, AdmissionError> {
        let Some(headers) = self.entry_headers.get(&entry_id) else {
            return Ok(false);
        };
        for containing_header in headers {
            if self.is_descendant_of(parent, *containing_header)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn highest_confirmed_header(&self) -> Result<AdmissionHash32, AdmissionError> {
        let mut current = self.canonical_tip;
        for _ in 0..MIN_ADMISSION_CONFIRMATIONS {
            current = self
                .headers
                .get(&current)
                .and_then(StoredAdmissionHeaderV1::parent)
                .ok_or_else(|| {
                    AdmissionError::ParentOrPrestate(
                        "canonical admission tip has fewer than 32 successors".into(),
                    )
                })?;
        }
        let (_, descendant_work) = self.confirmation_metrics(current)?;
        if descendant_work < self.config.confirmation_work_floor {
            return Err(AdmissionError::WorkOrProof(
                "confirmed admission prefix is below confirmation_work_floor".into(),
            ));
        }
        if !self.is_descendant_of(current, self.committed_header)? {
            return Err(AdmissionError::ParentOrPrestate(
                "confirmed admission prefix would roll back a finalized checkpoint".into(),
            ));
        }
        Ok(current)
    }

    fn confirmation_metrics(
        &self,
        header_id: AdmissionHash32,
    ) -> Result<(usize, AdmissionWork), AdmissionError> {
        let path = self.path_after(header_id, self.canonical_tip)?;
        let work = path.iter().try_fold(AdmissionWork::ZERO, |total, child| {
            total
                .checked_add(self.headers.get(child).expect("path child").header_work)
                .ok_or_else(|| {
                    AdmissionError::WorkOrProof("descendant confirmation work overflow".into())
                })
        })?;
        Ok((path.len(), work))
    }

    fn path_after(
        &self,
        ancestor: AdmissionHash32,
        descendant: AdmissionHash32,
    ) -> Result<Vec<AdmissionHash32>, AdmissionError> {
        if ancestor == descendant {
            return Ok(Vec::new());
        }
        let mut reverse = Vec::new();
        let mut cursor = descendant;
        let mut visited = BTreeSet::new();
        while cursor != ancestor {
            if !visited.insert(cursor) {
                return Err(AdmissionError::ParentOrPrestate(
                    "admission header ancestry contains a cycle".into(),
                ));
            }
            reverse.push(cursor);
            cursor = self
                .headers
                .get(&cursor)
                .and_then(StoredAdmissionHeaderV1::parent)
                .ok_or_else(|| {
                    AdmissionError::ParentOrPrestate(
                        "header is not a descendant of the required admission anchor".into(),
                    )
                })?;
        }
        reverse.reverse();
        Ok(reverse)
    }

    fn is_descendant_of(
        &self,
        descendant: AdmissionHash32,
        ancestor: AdmissionHash32,
    ) -> Result<bool, AdmissionError> {
        match self.path_after(ancestor, descendant) {
            Ok(_) => Ok(true),
            Err(AdmissionError::ParentOrPrestate(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn header_precedes_in_fork_choice(
        &self,
        candidate: AdmissionHash32,
        current: AdmissionHash32,
    ) -> Result<bool, AdmissionError> {
        let candidate_node = self.headers.get(&candidate).ok_or_else(|| {
            AdmissionError::ParentOrPrestate("fork-choice candidate is unknown".into())
        })?;
        let current_node = self.headers.get(&current).ok_or_else(|| {
            AdmissionError::ParentOrPrestate("fork-choice incumbent is unknown".into())
        })?;
        Ok(
            match candidate_node
                .admission_era()
                .cmp(&current_node.admission_era())
            {
                Ordering::Greater => true,
                Ordering::Less => false,
                Ordering::Equal => match candidate_node
                    .cumulative_work()
                    .cmp(&current_node.cumulative_work())
                {
                    Ordering::Greater => true,
                    Ordering::Less => false,
                    Ordering::Equal => candidate < current,
                },
            },
        )
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdmissionCensorshipStatusV1 {
    Healthy,
    CensorshipStalled,
    RecoveryChallenge,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdmissionCensorshipEventKindV1 {
    Stalled,
    RecoveryStarted,
    RecoveryReopened,
    ClearedAfterChallenge,
}

impl AdmissionCensorshipEventKindV1 {
    const fn code(self) -> u8 {
        match self {
            Self::Stalled => 1,
            Self::RecoveryStarted => 2,
            Self::RecoveryReopened => 3,
            Self::ClearedAfterChallenge => 4,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdmissionCensorshipEventV1 {
    pub sequence: u64,
    pub prior_event_hash: AdmissionHash32,
    pub kind: AdmissionCensorshipEventKindV1,
    pub ledger_epoch: u128,
    pub checkpoint_id: AdmissionHash32,
    pub unresolved_root: AdmissionHash32,
    pub protected_asset_root: AdmissionHash32,
    pub event_hash: AdmissionHash32,
}

impl AdmissionCensorshipEventV1 {
    fn expected_hash(&self) -> AdmissionHash32 {
        framed_hash(&[
            CENSORSHIP_EVENT_DOMAIN,
            &self.sequence.to_be_bytes(),
            &self.prior_event_hash.0,
            &[self.kind.code()],
            &self.ledger_epoch.to_be_bytes(),
            &self.checkpoint_id.0,
            &self.unresolved_root.0,
            &self.protected_asset_root.0,
        ])
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdmissionLedgerResolutionV1 {
    pub ledger_epoch: u128,
    pub checkpoint_id: AdmissionHash32,
    pub included_entries: BTreeSet<AdmissionHash32>,
    pub rejection_proofs: BTreeMap<AdmissionHash32, AdmissionHash32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdmissionCensorshipGuardV1 {
    context: AdmissionContextV1,
    status: AdmissionCensorshipStatusV1,
    last_ledger_epoch: u128,
    last_confirmed_checkpoint: AdmissionHash32,
    last_confirmed_admission_era: Option<u128>,
    last_confirmed_log_height: Option<u128>,
    last_confirmed_cumulative_work: Option<AdmissionWork>,
    last_value_eligible_asset_root: AdmissionHash32,
    pending_entries: BTreeMap<AdmissionHash32, u128>,
    stalled_scope: BTreeSet<AdmissionHash32>,
    recovery_started_epoch: Option<u128>,
    history: Vec<AdmissionCensorshipEventV1>,
}

impl AdmissionCensorshipGuardV1 {
    pub fn new(
        context: AdmissionContextV1,
        initial_ledger_epoch: u128,
        initial_asset_root: AdmissionHash32,
    ) -> Result<Self, AdmissionError> {
        context.validate()?;
        if initial_asset_root.is_zero() {
            return Err(AdmissionError::ParentOrPrestate(
                "initial value-eligible asset root cannot be zero".into(),
            ));
        }
        Ok(Self {
            context,
            status: AdmissionCensorshipStatusV1::Healthy,
            last_ledger_epoch: initial_ledger_epoch,
            last_confirmed_checkpoint: AdmissionHash32::ZERO,
            last_confirmed_admission_era: None,
            last_confirmed_log_height: None,
            last_confirmed_cumulative_work: None,
            last_value_eligible_asset_root: initial_asset_root,
            pending_entries: BTreeMap::new(),
            stalled_scope: BTreeSet::new(),
            recovery_started_epoch: None,
            history: Vec::new(),
        })
    }

    pub fn status(&self) -> AdmissionCensorshipStatusV1 {
        self.status
    }

    pub fn context(&self) -> &AdmissionContextV1 {
        &self.context
    }

    pub fn last_ledger_epoch(&self) -> u128 {
        self.last_ledger_epoch
    }

    pub fn may_sign_consensus(&self) -> bool {
        self.status == AdmissionCensorshipStatusV1::Healthy
    }

    pub fn may_accept_value_eligible_finality(&self) -> bool {
        self.status == AdmissionCensorshipStatusV1::Healthy
    }

    pub fn may_raise_value_cap(&self) -> bool {
        self.status == AdmissionCensorshipStatusV1::Healthy
    }

    pub fn last_value_eligible_asset_root(&self) -> AdmissionHash32 {
        self.last_value_eligible_asset_root
    }

    pub fn pending_entries(&self) -> &BTreeMap<AdmissionHash32, u128> {
        &self.pending_entries
    }

    pub fn history(&self) -> &[AdmissionCensorshipEventV1] {
        &self.history
    }

    pub fn observe_confirmed_prefix(
        &mut self,
        ledger_epoch: u128,
        prepared: &PreparedAdmissionCheckpointV1,
        current_asset_root: AdmissionHash32,
    ) -> Result<(), AdmissionError> {
        self.validate_recovered()?;
        let mut candidate = self.clone();
        candidate.observe_confirmed_prefix_inner(ledger_epoch, prepared, current_asset_root)?;
        candidate.validate_recovered()?;
        *self = candidate;
        Ok(())
    }

    fn observe_confirmed_prefix_inner(
        &mut self,
        ledger_epoch: u128,
        prepared: &PreparedAdmissionCheckpointV1,
        current_asset_root: AdmissionHash32,
    ) -> Result<(), AdmissionError> {
        self.ensure_monotonic_epoch(ledger_epoch)?;
        let checkpoint = &prepared.checkpoint;
        let checkpoint_id = checkpoint.checkpoint_id();
        if current_asset_root.is_zero() {
            return Err(AdmissionError::ParentOrPrestate(
                "confirmed checkpoint and asset root must be nonzero".into(),
            ));
        }
        validate_context(&checkpoint.context, &self.context)?;
        if prepared.entry_ids.len() > MAX_CHECKPOINT_ENTRIES_PER_LEDGER_BLOCK {
            return Err(AdmissionError::EnvelopeLimit(
                "confirmed observation exceeds 512 entries".into(),
            ));
        }
        if admission_entry_root(prepared.entry_ids.iter().copied())? != checkpoint.entries_root {
            return Err(AdmissionError::ParentOrPrestate(
                "confirmed observation entries do not match its checkpoint root".into(),
            ));
        }
        if let (Some(previous_era), Some(previous_height), Some(previous_work)) = (
            self.last_confirmed_admission_era,
            self.last_confirmed_log_height,
            self.last_confirmed_cumulative_work,
        ) {
            let position_order = checkpoint.admission_era.cmp(&previous_era).then_with(|| {
                checkpoint
                    .log_height
                    .cmp(&previous_height)
                    .then_with(|| checkpoint.cumulative_work.cmp(&previous_work))
            });
            if position_order == Ordering::Less
                || (position_order == Ordering::Equal
                    && checkpoint_id != self.last_confirmed_checkpoint)
            {
                return Err(AdmissionError::ParentOrPrestate(
                    "confirmed admission observation moved backward or equivocated".into(),
                ));
            }
        }
        let mut unique = BTreeSet::new();
        for entry_id in &prepared.entry_ids {
            if entry_id.is_zero() || !unique.insert(*entry_id) {
                return Err(AdmissionError::DuplicateOrNullifier(
                    "confirmed observation has zero or duplicate entry id".into(),
                ));
            }
        }
        if checkpoint_id == self.last_confirmed_checkpoint {
            // The identical observation may be delivered again after entries
            // were resolved. Its commitments cannot create new obligations.
            return self.advance_epoch_inner(ledger_epoch, current_asset_root);
        }
        for entry_id in &prepared.entry_ids {
            self.pending_entries
                .entry(*entry_id)
                .or_insert(ledger_epoch);
        }
        self.last_confirmed_checkpoint = checkpoint_id;
        self.last_confirmed_admission_era = Some(checkpoint.admission_era);
        self.last_confirmed_log_height = Some(checkpoint.log_height);
        self.last_confirmed_cumulative_work = Some(checkpoint.cumulative_work);
        self.advance_epoch_inner(ledger_epoch, current_asset_root)
    }

    pub fn record_ledger_resolution(
        &mut self,
        resolution: &AdmissionLedgerResolutionV1,
        current_asset_root: AdmissionHash32,
    ) -> Result<(), AdmissionError> {
        self.validate_recovered()?;
        let mut candidate = self.clone();
        candidate.record_ledger_resolution_inner(resolution, current_asset_root)?;
        candidate.validate_recovered()?;
        *self = candidate;
        Ok(())
    }

    fn record_ledger_resolution_inner(
        &mut self,
        resolution: &AdmissionLedgerResolutionV1,
        current_asset_root: AdmissionHash32,
    ) -> Result<(), AdmissionError> {
        self.ensure_monotonic_epoch(resolution.ledger_epoch)?;
        if resolution.checkpoint_id.is_zero()
            || resolution.checkpoint_id != self.last_confirmed_checkpoint
            || current_asset_root.is_zero()
        {
            return Err(AdmissionError::ParentOrPrestate(
                "ledger resolution must bind the exact latest confirmed checkpoint and a nonzero asset root"
                    .into(),
            ));
        }
        if resolution.included_entries.len() + resolution.rejection_proofs.len()
            > MAX_CHECKPOINT_ENTRIES_PER_LEDGER_BLOCK
        {
            return Err(AdmissionError::EnvelopeLimit(
                "ledger resolution exceeds 512 entries".into(),
            ));
        }
        for (entry_id, proof_id) in &resolution.rejection_proofs {
            if proof_id.is_zero() || resolution.included_entries.contains(entry_id) {
                return Err(AdmissionError::DuplicateOrNullifier(
                    "resolution overlaps inclusion and rejection or has zero proof".into(),
                ));
            }
        }
        let resolved: BTreeSet<_> = resolution
            .included_entries
            .iter()
            .copied()
            .chain(resolution.rejection_proofs.keys().copied())
            .collect();
        if resolved
            .iter()
            .any(|entry_id| !self.pending_entries.contains_key(entry_id))
        {
            return Err(AdmissionError::ParentOrPrestate(
                "resolution references an entry not awaiting ledger treatment".into(),
            ));
        }
        for entry_id in resolved {
            self.pending_entries.remove(&entry_id);
            self.stalled_scope.remove(&entry_id);
        }
        if self.status == AdmissionCensorshipStatusV1::CensorshipStalled
            && self.stalled_scope.is_empty()
        {
            self.status = AdmissionCensorshipStatusV1::RecoveryChallenge;
            self.recovery_started_epoch = Some(resolution.ledger_epoch);
            self.record_event(
                AdmissionCensorshipEventKindV1::RecoveryStarted,
                resolution.ledger_epoch,
                resolution.checkpoint_id,
            )?;
        }
        self.advance_epoch_inner(resolution.ledger_epoch, current_asset_root)
    }

    pub fn advance_epoch(
        &mut self,
        ledger_epoch: u128,
        current_asset_root: AdmissionHash32,
    ) -> Result<(), AdmissionError> {
        self.validate_recovered()?;
        let mut candidate = self.clone();
        candidate.advance_epoch_inner(ledger_epoch, current_asset_root)?;
        candidate.validate_recovered()?;
        *self = candidate;
        Ok(())
    }

    fn advance_epoch_inner(
        &mut self,
        ledger_epoch: u128,
        current_asset_root: AdmissionHash32,
    ) -> Result<(), AdmissionError> {
        self.ensure_monotonic_epoch(ledger_epoch)?;
        if current_asset_root.is_zero() {
            return Err(AdmissionError::ParentOrPrestate(
                "current asset root cannot be zero".into(),
            ));
        }
        let overdue: BTreeSet<_> = self
            .pending_entries
            .iter()
            .filter_map(|(entry_id, first_seen)| {
                (ledger_epoch.saturating_sub(*first_seen) > MAX_ADMISSION_LAG_EPOCHS)
                    .then_some(*entry_id)
            })
            .collect();
        if !overdue.is_empty() {
            let was_recovery = self.status == AdmissionCensorshipStatusV1::RecoveryChallenge;
            if self.status != AdmissionCensorshipStatusV1::CensorshipStalled {
                self.status = AdmissionCensorshipStatusV1::CensorshipStalled;
                self.recovery_started_epoch = None;
                self.stalled_scope
                    .extend(self.pending_entries.keys().copied());
                self.record_event(
                    if was_recovery {
                        AdmissionCensorshipEventKindV1::RecoveryReopened
                    } else {
                        AdmissionCensorshipEventKindV1::Stalled
                    },
                    ledger_epoch,
                    self.last_confirmed_checkpoint,
                )?;
            } else {
                self.stalled_scope.extend(overdue);
            }
        } else if self.status == AdmissionCensorshipStatusV1::RecoveryChallenge {
            let started = self.recovery_started_epoch.ok_or_else(|| {
                AdmissionError::ParentOrPrestate(
                    "recovery challenge has no durable start epoch".into(),
                )
            })?;
            if complete_recovery_challenge(started, ledger_epoch) {
                self.status = AdmissionCensorshipStatusV1::Healthy;
                self.recovery_started_epoch = None;
                self.record_event(
                    AdmissionCensorshipEventKindV1::ClearedAfterChallenge,
                    ledger_epoch,
                    self.last_confirmed_checkpoint,
                )?;
            }
        }
        if self.status == AdmissionCensorshipStatusV1::Healthy {
            self.last_value_eligible_asset_root = current_asset_root;
        }
        self.last_ledger_epoch = ledger_epoch;
        Ok(())
    }

    pub fn validate_recovered(&self) -> Result<(), AdmissionError> {
        self.context.validate()?;
        let confirmed_position_fields = [
            self.last_confirmed_admission_era.is_some(),
            self.last_confirmed_log_height.is_some(),
            self.last_confirmed_cumulative_work.is_some(),
        ];
        if confirmed_position_fields.iter().any(|present| *present)
            != confirmed_position_fields.iter().all(|present| *present)
            || (self.last_confirmed_checkpoint.is_zero()
                == self.last_confirmed_admission_era.is_some())
            || (self.last_confirmed_checkpoint.is_zero()
                && (!self.pending_entries.is_empty() || !self.history.is_empty()))
            || self.last_confirmed_log_height == Some(0)
            || self.last_confirmed_cumulative_work == Some(AdmissionWork::ZERO)
            || self.last_value_eligible_asset_root.is_zero()
            || self.pending_entries.keys().any(|id| id.is_zero())
            || self
                .pending_entries
                .values()
                .any(|first_seen| *first_seen > self.last_ledger_epoch)
        {
            return Err(AdmissionError::ParentOrPrestate(
                "recovered censorship guard has invalid roots or epochs".into(),
            ));
        }
        match self.status {
            AdmissionCensorshipStatusV1::Healthy => {
                if !self.stalled_scope.is_empty()
                    || self.recovery_started_epoch.is_some()
                    || self.pending_entries.values().any(|first_seen| {
                        self.last_ledger_epoch.saturating_sub(*first_seen)
                            > MAX_ADMISSION_LAG_EPOCHS
                    })
                {
                    return Err(AdmissionError::ParentOrPrestate(
                        "healthy guard retains unresolved or overdue stall state".into(),
                    ));
                }
            }
            AdmissionCensorshipStatusV1::CensorshipStalled => {
                if self.stalled_scope.is_empty()
                    || self.recovery_started_epoch.is_some()
                    || !self.stalled_scope.is_subset(
                        &self
                            .pending_entries
                            .keys()
                            .copied()
                            .collect::<BTreeSet<_>>(),
                    )
                {
                    return Err(AdmissionError::ParentOrPrestate(
                        "stalled guard lacks immutable unresolved scope".into(),
                    ));
                }
            }
            AdmissionCensorshipStatusV1::RecoveryChallenge => {
                if !self.stalled_scope.is_empty()
                    || self.recovery_started_epoch.is_none_or(|epoch| {
                        epoch > self.last_ledger_epoch
                            || complete_recovery_challenge(epoch, self.last_ledger_epoch)
                    })
                    || self.pending_entries.values().any(|first_seen| {
                        self.last_ledger_epoch.saturating_sub(*first_seen)
                            > MAX_ADMISSION_LAG_EPOCHS
                    })
                {
                    return Err(AdmissionError::ParentOrPrestate(
                        "recovery challenge state is inconsistent".into(),
                    ));
                }
            }
        }
        let mut prior = AdmissionHash32::ZERO;
        let mut prior_epoch = None;
        let mut replayed_status = AdmissionCensorshipStatusV1::Healthy;
        let mut replayed_recovery_epoch = None;
        let mut protected_root = None;
        let empty_scope = admission_entry_root([])?;
        for (index, event) in self.history.iter().enumerate() {
            let sequence = u64::try_from(index).map_err(|_| {
                AdmissionError::EnvelopeLimit("censorship event sequence exceeds U64".into())
            })?;
            if event.sequence != sequence
                || event.prior_event_hash != prior
                || event.event_hash != event.expected_hash()
                || event.ledger_epoch > self.last_ledger_epoch
                || prior_epoch.is_some_and(|epoch| event.ledger_epoch < epoch)
                || event.checkpoint_id.is_zero()
                || event.protected_asset_root.is_zero()
            {
                return Err(AdmissionError::ParentOrPrestate(
                    "censorship event history does not verify".into(),
                ));
            }
            let unresolved = matches!(
                event.kind,
                AdmissionCensorshipEventKindV1::Stalled
                    | AdmissionCensorshipEventKindV1::RecoveryReopened
            );
            if (event.unresolved_root == empty_scope) == unresolved
                || event.unresolved_root.is_zero()
                || (event.kind != AdmissionCensorshipEventKindV1::Stalled
                    && protected_root != Some(event.protected_asset_root))
            {
                return Err(AdmissionError::ParentOrPrestate(
                    "censorship recovery changed its protected root or unresolved scope".into(),
                ));
            }
            match (replayed_status, event.kind) {
                (AdmissionCensorshipStatusV1::Healthy, AdmissionCensorshipEventKindV1::Stalled)
                | (
                    AdmissionCensorshipStatusV1::RecoveryChallenge,
                    AdmissionCensorshipEventKindV1::RecoveryReopened,
                ) => {
                    replayed_status = AdmissionCensorshipStatusV1::CensorshipStalled;
                    replayed_recovery_epoch = None;
                }
                (
                    AdmissionCensorshipStatusV1::CensorshipStalled,
                    AdmissionCensorshipEventKindV1::RecoveryStarted,
                ) => {
                    replayed_status = AdmissionCensorshipStatusV1::RecoveryChallenge;
                    replayed_recovery_epoch = Some(event.ledger_epoch);
                }
                (
                    AdmissionCensorshipStatusV1::RecoveryChallenge,
                    AdmissionCensorshipEventKindV1::ClearedAfterChallenge,
                ) => {
                    if replayed_recovery_epoch.is_none_or(|started| {
                        !complete_recovery_challenge(started, event.ledger_epoch)
                    }) {
                        return Err(AdmissionError::ParentOrPrestate(
                            "censorship recovery cleared before a complete challenge Epoch".into(),
                        ));
                    }
                    replayed_status = AdmissionCensorshipStatusV1::Healthy;
                    replayed_recovery_epoch = None;
                }
                _ => {
                    return Err(AdmissionError::ParentOrPrestate(
                        "censorship event history contains an impossible state transition".into(),
                    ));
                }
            }
            protected_root = Some(event.protected_asset_root);
            prior_epoch = Some(event.ledger_epoch);
            prior = event.event_hash;
        }
        if replayed_status != self.status
            || replayed_recovery_epoch != self.recovery_started_epoch
            || (self.status != AdmissionCensorshipStatusV1::Healthy
                && protected_root != Some(self.last_value_eligible_asset_root))
        {
            return Err(AdmissionError::ParentOrPrestate(
                "censorship event history does not reproduce the recovered guard state".into(),
            ));
        }
        Ok(())
    }

    fn ensure_monotonic_epoch(&self, ledger_epoch: u128) -> Result<(), AdmissionError> {
        if ledger_epoch < self.last_ledger_epoch {
            return Err(AdmissionError::ParentOrPrestate(
                "ledger epoch cannot move backward".into(),
            ));
        }
        Ok(())
    }

    fn record_event(
        &mut self,
        kind: AdmissionCensorshipEventKindV1,
        ledger_epoch: u128,
        checkpoint_id: AdmissionHash32,
    ) -> Result<(), AdmissionError> {
        let unresolved_root = admission_entry_root(self.stalled_scope.iter().copied())?;
        let mut event = AdmissionCensorshipEventV1 {
            sequence: u64::try_from(self.history.len()).map_err(|_| {
                AdmissionError::EnvelopeLimit("censorship event sequence exceeds U64".into())
            })?,
            prior_event_hash: self
                .history
                .last()
                .map_or(AdmissionHash32::ZERO, |event| event.event_hash),
            kind,
            ledger_epoch,
            checkpoint_id,
            unresolved_root,
            protected_asset_root: self.last_value_eligible_asset_root,
            event_hash: AdmissionHash32::ZERO,
        };
        event.event_hash = event.expected_hash();
        self.history.push(event);
        Ok(())
    }
}

// A resolution can finalize at any block within its Epoch. With only an Epoch
// index retained, the whole following Epoch must elapse before clearance. This
// checked difference cannot wrap at U128::MAX or accept a backward clock.
fn complete_recovery_challenge(started: u128, current: u128) -> bool {
    current
        .checked_sub(started)
        .is_some_and(|elapsed| elapsed >= 2)
}

/// Bounded consensus state for permissionless admission.
///
/// The unfinalized fork graph and entry sidecars remain outside the currency
/// ledger.  The ledger retains only the immutable signed genesis, the latest
/// finalized position, a constant-size checkpoint accumulator, and the
/// censorship guard needed to fail closed.  Tag 28 is still intentionally
/// absent from runtime dispatch until a bounded proof can derive every update.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LedgerAdmissionStateV1 {
    pub format_version: String,
    pub genesis: AdmissionGenesisV1,
    pub control: AdmissionLedgerControlStateV1,
    pub committed_header: AdmissionHash32,
    pub latest_checkpoint: Option<AdmissionCheckpointV1>,
    pub checkpoint_count: u128,
    pub checkpoint_accumulator: AdmissionHash32,
    pub latest_checkpoint_proof_id: Option<AdmissionHash32>,
    pub prior_checkpoint_accumulator: Option<AdmissionHash32>,
    pub censorship_guard: AdmissionCensorshipGuardV1,
}

impl LedgerAdmissionStateV1 {
    pub fn new(
        genesis: AdmissionGenesisV1,
        initial_asset_root: AdmissionHash32,
    ) -> Result<Self, AdmissionError> {
        genesis.validate()?;
        let censorship_guard =
            AdmissionCensorshipGuardV1::new(genesis.context.clone(), 0, initial_asset_root)?;
        let control = AdmissionLedgerControlStateV1::new(&genesis.config)?;
        let state = Self {
            format_version: LEDGER_ADMISSION_STATE_VERSION_V1.into(),
            committed_header: genesis.genesis_header,
            control,
            genesis,
            latest_checkpoint: None,
            checkpoint_count: 0,
            checkpoint_accumulator: empty_admission_checkpoint_accumulator(),
            latest_checkpoint_proof_id: None,
            prior_checkpoint_accumulator: None,
            censorship_guard,
        };
        state.validate_recovered()?;
        Ok(state)
    }

    pub fn committed_position(&self) -> Result<AdmissionCommittedPositionV1, AdmissionError> {
        self.validate_recovered()?;
        Ok(self.latest_checkpoint.as_ref().map_or(
            AdmissionCommittedPositionV1 {
                header_id: self.genesis.genesis_header,
                admission_era: 0,
                log_height: 0,
                cumulative_work: AdmissionWork::ZERO,
            },
            |checkpoint| AdmissionCommittedPositionV1 {
                header_id: checkpoint.header_id,
                admission_era: checkpoint.admission_era,
                log_height: checkpoint.log_height,
                cumulative_work: checkpoint.cumulative_work,
            },
        ))
    }

    /// Applies the exact output of bounded admission-proof verification to the
    /// constant-size Ledger extension. This is intentionally not a proof
    /// verifier or a command route: callers must first verify the complete
    /// proof against finalized main-Ledger anchors and the durable local
    /// admission store. Recomputing every retained projection here prevents a
    /// forged `VerifiedAdmissionCheckpointTransitionV1` from bypassing those
    /// future runtime boundaries.
    pub(crate) fn apply_verified_checkpoint_transition(
        &mut self,
        transition: &VerifiedAdmissionCheckpointTransitionV1,
        current_asset_root: AdmissionHash32,
    ) -> Result<(), AdmissionError> {
        self.validate_recovered()?;
        let checkpoint = &transition.checkpoint;
        let prior_position = self.committed_position()?;
        let position_advances = checkpoint.admission_era > prior_position.admission_era
            || (checkpoint.admission_era == prior_position.admission_era
                && checkpoint.log_height > prior_position.log_height
                && checkpoint.cumulative_work > prior_position.cumulative_work);
        let mapping = &self.genesis.config.contribution_epoch_mapping;
        let derived_observed_epoch = mapping.epoch_at_height(transition.observed_ledger_height)?;
        let derived_committed_epoch =
            mapping.epoch_at_height(transition.committing_ledger_height)?;
        validate_context(&checkpoint.context, &self.genesis.context)?;
        if transition.prior_committed_header != self.committed_header
            || !position_advances
            || transition.proof_id.is_zero()
            || checkpoint.header_id.is_zero()
            || checkpoint.confirmations < MIN_ADMISSION_CONFIRMATIONS as u16
            || checkpoint.descendant_work < self.genesis.config.confirmation_work_floor
            || transition.committing_ledger_height < transition.observed_ledger_height
            || checkpoint.observed_ledger_epoch != derived_observed_epoch
            || checkpoint.committed_ledger_epoch != derived_committed_epoch
            || checkpoint.committed_ledger_epoch < checkpoint.observed_ledger_epoch
            || checkpoint.committed_ledger_epoch - checkpoint.observed_ledger_epoch
                > MAX_ADMISSION_LAG_EPOCHS
            || transition.entry_ids.len() > MAX_CHECKPOINT_ENTRIES_PER_LEDGER_BLOCK
            || transition
                .entry_ids
                .iter()
                .any(|entry_id| entry_id.is_zero())
            || transition
                .entry_ids
                .windows(2)
                .any(|window| window[0] >= window[1])
            || admission_entry_root(transition.entry_ids.iter().copied())?
                != checkpoint.entries_root
        {
            return Err(AdmissionError::ParentOrPrestate(
                "verified checkpoint transition does not match the exact bounded Ledger prestate"
                    .into(),
            ));
        }
        let expected_accumulator = admission_checkpoint_accumulator_successor(
            self.checkpoint_accumulator,
            self.checkpoint_count,
            checkpoint.checkpoint_id(),
            transition.proof_id,
        )?;
        if transition.next_checkpoint_accumulator != expected_accumulator {
            return Err(AdmissionError::ParentOrPrestate(
                "verified checkpoint transition has a forged accumulator successor".into(),
            ));
        }
        let next_count = self.checkpoint_count.checked_add(1).ok_or_else(|| {
            AdmissionError::ParentOrPrestate("admission checkpoint count overflow".into())
        })?;
        let prepared = PreparedAdmissionCheckpointV1 {
            checkpoint: checkpoint.clone(),
            prior_committed_header: transition.prior_committed_header,
            entry_ids: transition.entry_ids.clone(),
            observed_ledger_height: transition.observed_ledger_height,
            committing_ledger_height: transition.committing_ledger_height,
        };
        let mut candidate = self.clone();
        candidate.censorship_guard.observe_confirmed_prefix(
            checkpoint.committed_ledger_epoch,
            &prepared,
            current_asset_root,
        )?;
        candidate.committed_header = checkpoint.header_id;
        candidate.latest_checkpoint = Some(checkpoint.clone());
        candidate.checkpoint_count = next_count;
        candidate.latest_checkpoint_proof_id = Some(transition.proof_id);
        candidate.prior_checkpoint_accumulator = Some(self.checkpoint_accumulator);
        candidate.checkpoint_accumulator = expected_accumulator;
        candidate.validate_recovered()?;
        *self = candidate;
        Ok(())
    }

    pub fn validate_recovered(&self) -> Result<(), AdmissionError> {
        if self.format_version != LEDGER_ADMISSION_STATE_VERSION_V1 {
            return Err(AdmissionError::ContextMismatch(
                "unsupported ledger admission-state version".into(),
            ));
        }
        self.genesis.validate()?;
        self.control.validate_recovered(&self.genesis.config)?;
        self.censorship_guard.validate_recovered()?;
        if self.censorship_guard.context() != &self.genesis.context {
            return Err(AdmissionError::ContextMismatch(
                "censorship guard context differs from admission genesis".into(),
            ));
        }
        match (&self.latest_checkpoint, self.checkpoint_count) {
            (None, 0) => {
                if self.committed_header != self.genesis.genesis_header
                    || self.checkpoint_accumulator != empty_admission_checkpoint_accumulator()
                    || self.latest_checkpoint_proof_id.is_some()
                    || self.prior_checkpoint_accumulator.is_some()
                    || !self.censorship_guard.last_confirmed_checkpoint.is_zero()
                {
                    return Err(AdmissionError::ParentOrPrestate(
                        "empty ledger admission state does not match its signed genesis".into(),
                    ));
                }
            }
            (Some(checkpoint), count) if count > 0 => {
                let proof_id = self.latest_checkpoint_proof_id.ok_or_else(|| {
                    AdmissionError::ParentOrPrestate(
                        "latest admission checkpoint has no retained proof id".into(),
                    )
                })?;
                let prior_accumulator = self.prior_checkpoint_accumulator.ok_or_else(|| {
                    AdmissionError::ParentOrPrestate(
                        "latest admission checkpoint has no retained prior accumulator".into(),
                    )
                })?;
                let expected_accumulator = admission_checkpoint_accumulator_successor(
                    prior_accumulator,
                    count - 1,
                    checkpoint.checkpoint_id(),
                    proof_id,
                )?;
                validate_context(&checkpoint.context, &self.genesis.context)?;
                if checkpoint.header_id.is_zero()
                    || checkpoint.confirmations < MIN_ADMISSION_CONFIRMATIONS as u16
                    || checkpoint.descendant_work < self.genesis.config.confirmation_work_floor
                    || self.committed_header != checkpoint.header_id
                    || self.checkpoint_accumulator.is_zero()
                    || self.checkpoint_accumulator != expected_accumulator
                    || (count == 1 && prior_accumulator != empty_admission_checkpoint_accumulator())
                    || (count > 1 && prior_accumulator == empty_admission_checkpoint_accumulator())
                    || self.censorship_guard.last_confirmed_checkpoint != checkpoint.checkpoint_id()
                    || self.censorship_guard.last_ledger_epoch() < checkpoint.committed_ledger_epoch
                {
                    return Err(AdmissionError::ParentOrPrestate(
                        "latest admission checkpoint or accumulator is inconsistent".into(),
                    ));
                }
            }
            _ => {
                return Err(AdmissionError::ParentOrPrestate(
                    "admission checkpoint count and latest checkpoint disagree".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn validate_for_descriptor(
        &self,
        descriptor: &ZoneDescriptor,
    ) -> Result<(), AdmissionError> {
        self.validate_recovered()?;
        self.genesis.validate_for_descriptor(descriptor)
    }
}

fn framed_hash(parts: &[&[u8]]) -> AdmissionHash32 {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    AdmissionHash32(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;
    use crate::crypto::{generate_identity, sign_bytes};

    fn label(value: &str) -> AdmissionHash32 {
        sha256_parts_raw(&[value.as_bytes()])
    }

    fn work_u64(value: u64) -> AdmissionWork {
        AdmissionWork([value, 0, 0, 0])
    }

    fn context() -> AdmissionContextV1 {
        AdmissionContextV1 {
            network_domain: "rldcoin:mainnet:v1".into(),
            zone_id: "earth-0".into(),
            currency_genesis: label("currency-genesis"),
            protocol_era: 7,
            crypto_era: 1,
        }
    }

    fn config() -> AdmissionLogConfigV1 {
        let target = AdmissionWork::from_be_bytes([
            0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
        ]);
        AdmissionLogConfigV1 {
            minimum_target: target,
            maximum_target: target,
            genesis_target: target,
            confirmation_work_floor: work_u64(32),
            contribution_epoch_mapping: ContributionEpochMappingV1 {
                ledger_height_origin: 0,
                contribution_epoch_origin: 0,
                ledger_blocks_per_contribution_epoch: 2,
            },
        }
    }

    fn authenticated_proposal_context(
        proof: &AdmissionCheckpointProofV1,
        committing_ledger_height: u128,
    ) -> AuthenticatedAdmissionCheckpointProposalV1 {
        let expected_height = u64::try_from(committing_ledger_height).unwrap();
        let parent_height = expected_height.checked_sub(1).unwrap();
        AuthenticatedAdmissionCheckpointProposalV1::from_authenticated_proposal(
            label("authenticated-proposal").to_hex(),
            label("authenticated-command").to_hex(),
            proof
                .proof_id()
                .unwrap_or_else(|_| label("unencodable-proof")),
            parent_height,
            label("authenticated-parent-state").to_hex(),
            expected_height,
            label("authenticated-expected-state").to_hex(),
        )
        .unwrap()
    }

    #[test]
    fn admission_genesis_and_empty_ledger_state_are_deterministic_and_strict() {
        let benchmark = label("retained benchmark report bytes");
        let genesis = AdmissionGenesisV1::new(context(), config(), benchmark).unwrap();
        let repeated = AdmissionGenesisV1::new(context(), config(), benchmark).unwrap();
        assert_eq!(genesis, repeated);
        assert!(!genesis.genesis_header.is_zero());

        let mut different_config = config();
        different_config.confirmation_work_floor = work_u64(33);
        let different = AdmissionGenesisV1::new(context(), different_config, benchmark).unwrap();
        assert_ne!(genesis.genesis_header, different.genesis_header);
        let mut different_mapping = config();
        different_mapping
            .contribution_epoch_mapping
            .ledger_blocks_per_contribution_epoch = 3;
        let different_mapping =
            AdmissionGenesisV1::new(context(), different_mapping, benchmark).unwrap();
        assert_ne!(genesis.genesis_header, different_mapping.genesis_header);
        let different_benchmark =
            AdmissionGenesisV1::new(context(), config(), label("other report")).unwrap();
        assert_ne!(genesis.genesis_header, different_benchmark.genesis_header);

        let mut tampered = genesis.clone();
        tampered.benchmark_report_sha256 = label("tampered report");
        assert_eq!(
            tampered.validate().unwrap_err().code(),
            "ERR_CONTEXT_MISMATCH"
        );

        let initial_asset_root = label("M0 root before admission extension");
        let state = LedgerAdmissionStateV1::new(genesis.clone(), initial_asset_root).unwrap();
        state.validate_recovered().unwrap();
        assert_eq!(state.committed_header, genesis.genesis_header);
        assert_eq!(state.checkpoint_count, 0);
        assert_eq!(
            state.censorship_guard.last_value_eligible_asset_root(),
            initial_asset_root
        );

        let mut broken_state = state.clone();
        broken_state.committed_header = label("unproven committed header");
        assert_eq!(
            broken_state.validate_recovered().unwrap_err().code(),
            "ERR_PARENT_OR_PRESTATE"
        );

        let mut unknown_genesis_field = serde_json::to_value(&genesis).unwrap();
        unknown_genesis_field["uncommitted"] = serde_json::json!(true);
        assert!(serde_json::from_value::<AdmissionGenesisV1>(unknown_genesis_field).is_err());
        let mut unknown_state_field = serde_json::to_value(&state).unwrap();
        unknown_state_field["uncommitted"] = serde_json::json!(true);
        assert!(serde_json::from_value::<LedgerAdmissionStateV1>(unknown_state_field).is_err());
    }

    #[test]
    fn contribution_epoch_mapping_is_total_from_its_signed_origin_and_overflow_safe() {
        let mapping = ContributionEpochMappingV1 {
            ledger_height_origin: 10,
            contribution_epoch_origin: 3,
            ledger_blocks_per_contribution_epoch: 4,
        };
        mapping.validate().unwrap();
        assert_eq!(mapping.epoch_at_height(10).unwrap(), 3);
        assert_eq!(mapping.epoch_at_height(13).unwrap(), 3);
        assert_eq!(mapping.epoch_at_height(14).unwrap(), 4);
        assert_eq!(
            mapping.epoch_at_height(9).unwrap_err().code(),
            "ERR_TRANSITION_OR_VALUE_CAP"
        );
        assert!(mapping.epoch_at_height(u128::MAX).is_ok());

        let mut invalid_span = mapping.clone();
        invalid_span.ledger_blocks_per_contribution_epoch = 1;
        assert_eq!(
            invalid_span.validate().unwrap_err().code(),
            "ERR_CONTEXT_MISMATCH"
        );

        let overflowing = ContributionEpochMappingV1 {
            ledger_height_origin: 0,
            contribution_epoch_origin: u128::MAX,
            ledger_blocks_per_contribution_epoch: 2,
        };
        assert_eq!(
            overflowing.validate().unwrap_err().code(),
            "ERR_CONTEXT_MISMATCH"
        );
    }

    #[test]
    fn ledger_control_facts_are_derived_accumulated_and_failure_atomic() {
        let config = config();
        let mut control = AdmissionLedgerControlStateV1::new(&config).unwrap();
        let empty_accumulator = control.fact_accumulator;
        assert_eq!(
            empty_accumulator,
            empty_admission_ledger_control_accumulator()
        );

        let schedule = control.schedule_target(5, [64; 4], &config).unwrap();
        assert_eq!(schedule.activation_epoch, 7);
        assert_eq!(schedule.target, config.genesis_target);
        assert_eq!(control.fact_count, 1);
        assert_ne!(control.fact_accumulator, empty_accumulator);

        let mut fresh = AdmissionLedgerControlStateV1::new(&config).unwrap();
        let fresh_before = fresh.clone();
        let mut caller_selected_output = schedule.clone();
        caller_selected_output.target = AdmissionWork::ZERO;
        assert_eq!(
            fresh
                .apply_exact_fact(
                    &AdmissionLedgerControlFactV1::TargetSchedule(caller_selected_output),
                    &config,
                )
                .unwrap_err()
                .code(),
            "ERR_PARENT_OR_PRESTATE"
        );
        assert_eq!(fresh, fresh_before);

        let before_tamper = control.clone();
        let mut forged_schedule = schedule.clone();
        forged_schedule.target = AdmissionWork::ZERO;
        assert_eq!(
            control
                .apply_exact_fact(
                    &AdmissionLedgerControlFactV1::TargetSchedule(forged_schedule),
                    &config,
                )
                .unwrap_err()
                .code(),
            "ERR_DUPLICATE_OR_NULLIFIER"
        );
        assert_eq!(control, before_tamper);

        let mut overflowing_activation = control.clone();
        overflowing_activation.fact_count = u128::MAX;
        let prior_accumulator = label("maximum-count prior control accumulator");
        overflowing_activation.prior_fact_accumulator = Some(prior_accumulator);
        overflowing_activation.fact_accumulator = admission_ledger_control_accumulator_successor(
            prior_accumulator,
            u128::MAX - 1,
            overflowing_activation
                .last_fact
                .as_ref()
                .unwrap()
                .fact_hash(),
        )
        .unwrap();
        overflowing_activation.validate_recovered(&config).unwrap();
        let before_overflow = overflowing_activation.clone();
        assert_eq!(
            overflowing_activation
                .activate_target(7, &config)
                .unwrap_err()
                .code(),
            "ERR_PARENT_OR_PRESTATE"
        );
        assert_eq!(overflowing_activation, before_overflow);

        let activation = control.activate_target(7, &config).unwrap();
        assert_eq!(activation.prior_target, schedule.target);
        assert_eq!(activation.active_target, schedule.target);
        assert_eq!(activation.consumed_schedule_count, 1);
        assert!(control.scheduled_targets.is_empty());

        let authorization = AdmissionRolloverAuthorizationV1 {
            terminal_header: label("threshold-terminal-header"),
            terminal_cumulative_work: rollover_threshold(),
            successor_era: 1,
            finalized_ledger_state_root: label("finalized-rollover-ledger-root"),
        };
        let rollover_fact = control
            .authorize_rollover(authorization.clone(), &config)
            .unwrap();
        assert_eq!(control.fact_count, 3);
        assert_eq!(control.last_fact.as_ref(), Some(&rollover_fact));
        assert_eq!(
            control.latest_rollover_authorization.as_ref(),
            Some(&authorization)
        );
        control.validate_recovered(&config).unwrap();

        let restored: AdmissionLedgerControlStateV1 =
            serde_json::from_slice(&serde_json::to_vec(&control).unwrap()).unwrap();
        assert_eq!(restored, control);
        restored.validate_recovered(&config).unwrap();

        let mut rollback = restored.clone();
        rollback.fact_count = 0;
        assert_eq!(
            rollback.validate_recovered(&config).unwrap_err().code(),
            "ERR_PARENT_OR_PRESTATE"
        );

        let mut forged_accumulator = restored.clone();
        forged_accumulator.fact_accumulator = label("attacker control accumulator");
        assert_eq!(
            forged_accumulator
                .validate_recovered(&config)
                .unwrap_err()
                .code(),
            "ERR_PARENT_OR_PRESTATE"
        );

        let mut low_work = authorization;
        low_work.terminal_cumulative_work =
            AdmissionWork([u64::MAX, u64::MAX, u64::MAX, u64::MAX - 1]);
        assert!(low_work.terminal_cumulative_work < rollover_threshold());
        let before_low_work = control.clone();
        assert_eq!(
            control
                .authorize_rollover(low_work, &config)
                .unwrap_err()
                .code(),
            "ERR_TRANSITION_OR_VALUE_CAP"
        );
        assert_eq!(control, before_low_work);
    }

    #[test]
    fn rust_matches_independent_python_ledger_control_facts_and_rejections() {
        fn string_u128(value: &Value) -> u128 {
            value.as_str().unwrap().parse().unwrap()
        }

        fn work(value: &Value) -> AdmissionWork {
            AdmissionWork::from_hex(value.as_str().unwrap()).unwrap()
        }

        fn hash(value: &Value) -> AdmissionHash32 {
            AdmissionHash32::from_hex(value.as_str().unwrap()).unwrap()
        }

        let vector_bytes =
            include_bytes!("../../../vectors/admission-ledger-control-v1/vectors.json");
        let pinned =
            include_str!("../../../vectors/admission-ledger-control-v1/vectors.json.sha256")
                .split_whitespace()
                .next()
                .unwrap();
        assert_eq!(hex::encode(Sha256::digest(vector_bytes)), pinned);
        let document: Value = serde_json::from_slice(vector_bytes).unwrap();
        assert_eq!(document["format"], "rld-admission-ledger-control-v1");
        let payload = &document["payload"];
        assert_eq!(
            payload["status"],
            "CONTROL_FACT_HASH_AND_STATE_ONLY_RUNTIME_TAG28_DISABLED_VALUE_CAP_0"
        );
        assert_eq!(payload["claims"]["runtime_tag28"], false);
        assert_eq!(payload["claims"]["formal_command_route"], false);
        assert_eq!(payload["claims"]["main_wal_commit_association"], false);
        assert_eq!(payload["claims"]["value_cap"], 0);
        assert_eq!(
            hex::encode(Sha256::digest(serde_json::to_vec(payload).unwrap())),
            document["payload_sha256"].as_str().unwrap()
        );

        let config = AdmissionLogConfigV1 {
            minimum_target: work(&payload["config"]["minimum_target"]),
            maximum_target: work(&payload["config"]["maximum_target"]),
            genesis_target: work(&payload["config"]["genesis_target"]),
            confirmation_work_floor: AdmissionWork::from_be_bytes([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 1,
            ]),
            contribution_epoch_mapping: ContributionEpochMappingV1 {
                ledger_height_origin: 0,
                contribution_epoch_origin: 0,
                ledger_blocks_per_contribution_epoch: 2,
            },
        };
        config.validate().unwrap();
        assert_eq!(
            empty_admission_ledger_control_accumulator(),
            hash(&payload["empty_accumulator"])
        );
        assert_eq!(rollover_threshold(), work(&payload["rollover_threshold"]));

        let mut control = AdmissionLedgerControlStateV1::new(&config).unwrap();
        for step in payload["steps"].as_array().unwrap() {
            let expected = &step["expected_fact"];
            let fact = match step["kind"].as_str().unwrap() {
                "TARGET_SCHEDULE" => {
                    let counts: [u64; 4] = step["completed_epoch_header_counts"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|value| value.as_u64().unwrap())
                        .collect::<Vec<_>>()
                        .try_into()
                        .unwrap();
                    let schedule = control
                        .schedule_target(string_u128(&step["decision_epoch"]), counts, &config)
                        .unwrap();
                    assert_eq!(
                        schedule.decision_epoch,
                        string_u128(&expected["decision_epoch"])
                    );
                    assert_eq!(schedule.completed_epoch_header_counts, counts);
                    assert_eq!(
                        schedule.activation_epoch,
                        string_u128(&expected["activation_epoch"])
                    );
                    assert_eq!(schedule.target, work(&expected["target"]));
                    AdmissionLedgerControlFactV1::TargetSchedule(schedule)
                }
                "TARGET_ACTIVATION" => {
                    let activation = control
                        .activate_target(string_u128(&step["ledger_epoch"]), &config)
                        .unwrap();
                    assert_eq!(
                        activation.ledger_epoch,
                        string_u128(&expected["ledger_epoch"])
                    );
                    assert_eq!(activation.prior_target, work(&expected["prior_target"]));
                    assert_eq!(activation.active_target, work(&expected["active_target"]));
                    assert_eq!(
                        activation.consumed_schedule_count,
                        expected["consumed_schedule_count"].as_u64().unwrap() as u8
                    );
                    AdmissionLedgerControlFactV1::TargetActivation(activation)
                }
                "ROLLOVER_AUTHORIZATION" => {
                    let authorization = AdmissionRolloverAuthorizationV1 {
                        terminal_header: hash(&expected["terminal_header"]),
                        terminal_cumulative_work: work(&expected["terminal_cumulative_work"]),
                        successor_era: string_u128(&expected["successor_era"]),
                        finalized_ledger_state_root: hash(&expected["finalized_ledger_state_root"]),
                    };
                    control.authorize_rollover(authorization, &config).unwrap()
                }
                kind => panic!("unknown frozen control step {kind}"),
            };
            assert_eq!(fact.fact_hash(), hash(&step["expected_fact_hash"]));
            assert_eq!(
                control.fact_accumulator,
                hash(&step["expected_accumulator"])
            );
            assert_eq!(
                control.active_target,
                work(&step["expected_state"]["active_target"])
            );
            assert_eq!(
                control.scheduled_targets.len() as u64,
                step["expected_state"]["scheduled_target_count"]
                    .as_u64()
                    .unwrap()
            );
            assert_eq!(
                control.fact_count,
                string_u128(&step["expected_state"]["fact_count"])
            );
            assert_eq!(
                control.prior_fact_accumulator,
                Some(hash(&step["expected_state"]["prior_fact_accumulator"]))
            );
        }
        assert_eq!(
            control.active_target,
            work(&payload["expected_final_state"]["active_target"])
        );
        assert_eq!(
            control.fact_accumulator,
            hash(&payload["expected_final_state"]["fact_accumulator"])
        );
        assert_eq!(
            control.prior_fact_accumulator,
            Some(hash(
                &payload["expected_final_state"]["prior_fact_accumulator"]
            ))
        );

        let mut observed_errors = BTreeMap::new();

        let mut malformed_schedule_state = AdmissionLedgerControlStateV1::new(&config).unwrap();
        let valid_schedule = malformed_schedule_state
            .clone()
            .schedule_target(40, [16, 32, 64, 128], &config)
            .unwrap();
        let mut wrong_epoch = valid_schedule.clone();
        wrong_epoch.activation_epoch = 43;
        let before = malformed_schedule_state.clone();
        observed_errors.insert(
            "schedule_activation_epoch",
            malformed_schedule_state
                .apply_exact_fact(
                    &AdmissionLedgerControlFactV1::TargetSchedule(wrong_epoch),
                    &config,
                )
                .unwrap_err()
                .code(),
        );
        assert_eq!(malformed_schedule_state, before);

        let mut wrong_target = valid_schedule;
        wrong_target.target = AdmissionWork::ZERO;
        observed_errors.insert(
            "schedule_target",
            malformed_schedule_state
                .apply_exact_fact(
                    &AdmissionLedgerControlFactV1::TargetSchedule(wrong_target),
                    &config,
                )
                .unwrap_err()
                .code(),
        );
        assert_eq!(malformed_schedule_state, before);

        let mut activation_state = AdmissionLedgerControlStateV1::new(&config).unwrap();
        activation_state
            .schedule_target(40, [16, 32, 64, 128], &config)
            .unwrap();
        activation_state
            .schedule_target(41, [0, 0, 0, 0], &config)
            .unwrap();
        let valid_activation = activation_state
            .clone()
            .activate_target(42, &config)
            .unwrap();
        let activation_before = activation_state.clone();
        let mut wrong_active = valid_activation.clone();
        wrong_active.active_target = config.genesis_target;
        observed_errors.insert(
            "activation_active_target",
            activation_state
                .apply_exact_fact(
                    &AdmissionLedgerControlFactV1::TargetActivation(wrong_active),
                    &config,
                )
                .unwrap_err()
                .code(),
        );
        assert_eq!(activation_state, activation_before);
        let mut wrong_consumed = valid_activation;
        wrong_consumed.consumed_schedule_count = 2;
        observed_errors.insert(
            "activation_consumed_count",
            activation_state
                .apply_exact_fact(
                    &AdmissionLedgerControlFactV1::TargetActivation(wrong_consumed),
                    &config,
                )
                .unwrap_err()
                .code(),
        );
        assert_eq!(activation_state, activation_before);

        let valid_rollover = AdmissionRolloverAuthorizationV1 {
            terminal_header: label("vector-rollover-terminal"),
            terminal_cumulative_work: rollover_threshold(),
            successor_era: 9,
            finalized_ledger_state_root: label("vector-rollover-prestate"),
        };
        let mut below_threshold = valid_rollover.clone();
        below_threshold.terminal_cumulative_work = AdmissionWork::from_be_bytes([
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
        ]);
        let mut rollover_state = AdmissionLedgerControlStateV1::new(&config).unwrap();
        let rollover_before = rollover_state.clone();
        observed_errors.insert(
            "rollover_below_threshold",
            rollover_state
                .authorize_rollover(below_threshold, &config)
                .unwrap_err()
                .code(),
        );
        assert_eq!(rollover_state, rollover_before);
        let mut zero_root = valid_rollover;
        zero_root.finalized_ledger_state_root = AdmissionHash32::ZERO;
        observed_errors.insert(
            "rollover_zero_state_root",
            rollover_state
                .authorize_rollover(zero_root, &config)
                .unwrap_err()
                .code(),
        );
        assert_eq!(rollover_state, rollover_before);
        observed_errors.insert(
            "zero_accumulator_input",
            admission_ledger_control_accumulator_successor(
                AdmissionHash32::ZERO,
                0,
                label("nonzero-fact"),
            )
            .unwrap_err()
            .code(),
        );

        for case in payload["cases"].as_array().unwrap() {
            let mutation = case["mutation"].as_str().unwrap();
            if mutation == "accept" {
                assert_eq!(case["expected_accept"], true);
                continue;
            }
            assert_eq!(case["expected_accept"], false);
            assert_eq!(
                observed_errors.get(mutation).copied().unwrap(),
                case["expected_first_error"].as_str().unwrap(),
                "{}",
                case["case_id"].as_str().unwrap()
            );
        }
    }

    fn signed_entry(
        identity: &crate::crypto::Identity,
        payload_label: &str,
    ) -> PermissionlessAdmissionEntryV1 {
        let participant_key = AdmissionHash32::from_hex(&identity.public_key).unwrap();
        let payload = payload_label.as_bytes();
        let payload_commitment = admission_sidecar_payload_commitment(payload).unwrap();
        let declared_bytes = u64::try_from(payload.len()).unwrap();
        let mut entry = PermissionlessAdmissionEntryV1 {
            context: context(),
            kind: AdmissionEntryKindV1::Participation,
            participant_key,
            owner_commitment: label("owner"),
            program_id: label("program"),
            challenge_id: None,
            payload_commitment,
            locator_commitment: admission_sidecar_locator_commitment(
                payload_commitment,
                declared_bytes,
            ),
            declared_bytes,
            expiry_height: 100,
            entry_signature: AdmissionSignature64([0; 64]),
        };
        let signature = sign_bytes(&identity.secret_key, &entry.signing_subject().0).unwrap();
        entry.entry_signature = AdmissionSignature64(
            hex::decode(signature)
                .unwrap()
                .try_into()
                .expect("64-byte signature"),
        );
        entry
    }

    fn make_batch(
        log: &PermissionlessAdmissionLogV1,
        parent_header: AdmissionHash32,
        entries: Vec<PermissionlessAdmissionEntryV1>,
        mut nonce: u128,
        availability_verified: bool,
    ) -> AdmissionHeaderBatchV1 {
        let entry_ids: Vec<_> = entries
            .iter()
            .map(PermissionlessAdmissionEntryV1::entry_id)
            .collect();
        let root = admission_entry_root(entry_ids).unwrap();
        let parent = log.headers.get(&parent_header).unwrap();
        let anchor = AdmissionLedgerAnchorV1 {
            block_id: label("ledger-anchor"),
            height: 1,
        };
        let mut access_work = BaselineAccessWorkV1 {
            context: log.context.clone(),
            parent_header,
            ledger_anchor_block: anchor.block_id,
            ledger_anchor_height: anchor.height,
            entries_root: root,
            entries_count: u16::try_from(entries.len()).unwrap(),
            suite_id: ADMISSION_ACCESS_WORK_SUITE_V1,
            target: log.active_target,
            nonce,
            output_hash: AdmissionHash32::ZERO,
            expiry_anchor_height: 100,
        };
        loop {
            access_work.nonce = nonce;
            access_work.output_hash = access_work.recompute_output_hash();
            if AdmissionWork::from_be_bytes(access_work.output_hash.0) <= access_work.target {
                break;
            }
            nonce = nonce.checked_add(1).unwrap();
        }
        let header_work = access_work.header_work();
        let header = PermissionlessAdmissionHeaderV1 {
            context: log.context.clone(),
            admission_era: parent.admission_era(),
            log_height: parent.log_height() + 1,
            parent_header,
            ledger_anchor_block: anchor.block_id,
            access_work_id: access_work.work_id(),
            entries_root: root,
            entries_count: u16::try_from(entries.len()).unwrap(),
            cumulative_work: parent.cumulative_work().checked_add(header_work).unwrap(),
            prior_era_terminal: None,
        };
        let entries = entries
            .into_iter()
            .map(|entry| AdmissionBatchEntryV1 {
                body_bytes: entry.canonical_bytes().len() as u64,
                sidecar_bytes: entry.declared_bytes,
                entry,
                availability_verified,
            })
            .collect();
        AdmissionHeaderBatchV1 {
            entries,
            access_work,
            header,
            ledger_anchor: anchor,
        }
    }

    fn checkpoint_proof_fixture() -> (
        AdmissionGenesisV1,
        AdmissionCheckpointProofV1,
        PreparedAdmissionCheckpointV1,
        PermissionlessAdmissionLogV1,
    ) {
        let genesis =
            AdmissionGenesisV1::new(context(), config(), label("checkpoint-proof-benchmark"))
                .unwrap();
        let mut log = PermissionlessAdmissionLogV1::new(
            genesis.context.clone(),
            genesis.config.clone(),
            genesis.genesis_header,
        )
        .unwrap();
        let identity = generate_identity();
        let entry = signed_entry(&identity, "checkpoint-proof-entry");
        let mut parent = genesis.genesis_header;
        let mut batch_segment = Vec::new();
        let mut confirmation_segment = Vec::new();
        for height in 1..=33u128 {
            let entries = if height == 1 {
                vec![entry.clone()]
            } else {
                Vec::new()
            };
            let batch = make_batch(&log, parent, entries, height, true);
            if height == 1 {
                batch_segment.push(AdmissionCheckpointBatchProofV1 {
                    entries: batch
                        .entries
                        .iter()
                        .map(|record| record.entry.clone())
                        .collect(),
                    access_work: batch.access_work.clone(),
                    header: batch.header.clone(),
                    ledger_anchor: batch.ledger_anchor.clone(),
                });
            } else {
                confirmation_segment.push(AdmissionCheckpointConfirmationProofV1 {
                    access_work: batch.access_work.clone(),
                    header: batch.header.clone(),
                    ledger_anchor: batch.ledger_anchor.clone(),
                });
            }
            parent = log.append_header(batch).unwrap();
        }
        let prepared = log.build_confirmed_checkpoint(5).unwrap();
        (
            genesis.clone(),
            AdmissionCheckpointProofV1 {
                context: genesis.context,
                prior_committed_header: genesis.genesis_header,
                prior_checkpoint_accumulator: empty_admission_checkpoint_accumulator(),
                batch_segment,
                confirmation_segment,
            },
            prepared,
            log,
        )
    }

    #[test]
    fn bounded_checkpoint_proof_recomputes_every_checkpoint_field_and_accumulator() {
        let (genesis, proof, prepared, _) = checkpoint_proof_fixture();
        let expected_anchor = label("ledger-anchor");
        let transition = proof
            .verify_bounded(
                &genesis,
                AdmissionCommittedPositionV1 {
                    header_id: genesis.genesis_header,
                    admission_era: 0,
                    log_height: 0,
                    cumulative_work: AdmissionWork::ZERO,
                },
                0,
                empty_admission_checkpoint_accumulator(),
                &authenticated_proposal_context(&proof, 5),
                genesis.config.genesis_target,
                &BTreeMap::new(),
                |anchor| {
                    if anchor.block_id == expected_anchor && anchor.height == 1 {
                        Ok(())
                    } else {
                        Err(AdmissionError::ParentOrPrestate(
                            "anchor is not in finalized local history".into(),
                        ))
                    }
                },
                |entry| verify_admission_sidecar(entry, b"checkpoint-proof-entry"),
                |_header, _work, anchor| {
                    if anchor.block_id == expected_anchor {
                        Ok(())
                    } else {
                        Err(AdmissionError::ResourceOrAvailability(
                            "confirmation body is unavailable".into(),
                        ))
                    }
                },
            )
            .unwrap();
        assert_eq!(transition.checkpoint, prepared.checkpoint);
        assert_eq!(transition.entry_ids, prepared.entry_ids);
        assert_eq!(transition.prior_committed_header, genesis.genesis_header);
        assert!(!transition.proof_id.is_zero());
        assert!(!transition.next_checkpoint_accumulator.is_zero());
        assert_ne!(
            transition.next_checkpoint_accumulator,
            empty_admission_checkpoint_accumulator()
        );

        let wire = proof.canonical_bytes().unwrap();
        assert_eq!(&wire[..4], RLD_WIRE_MAGIC);
        assert_eq!(
            u16::from_be_bytes([wire[6], wire[7]]),
            ADMISSION_CHECKPOINT_PROOF_SCHEMA_V1
        );
        let restored: AdmissionCheckpointProofV1 =
            serde_json::from_slice(&serde_json::to_vec(&proof).unwrap()).unwrap();
        assert_eq!(restored.canonical_bytes().unwrap(), wire);
        assert_eq!(restored.proof_id().unwrap(), transition.proof_id);

        let payload =
            crate::command_wire::encode_admission_checkpoint_candidate_payload_v1(&proof).unwrap();
        assert_eq!(&payload[..4], b"RLDP");
        let command = crate::command_wire::encode_admission_checkpoint_candidate_command_v1(
            &genesis.context.network_domain,
            &proof,
        )
        .unwrap();
        let decoded =
            crate::wire::decode_wire(crate::wire::WireSchema::CommandCommitment, &command).unwrap();
        assert_eq!(decoded["consensus_tag"], "28");
        assert_eq!(decoded["network_domain"], genesis.context.network_domain);
        assert_ne!(
            crate::command_wire::admission_checkpoint_candidate_command_hash_v1(
                &genesis.context.network_domain,
                &proof,
            )
            .unwrap(),
            crate::command_wire::admission_checkpoint_candidate_command_hash_v1(
                "rldcoin:testnet:v1",
                &proof,
            )
            .unwrap()
        );
    }

    #[test]
    fn main_wal_checkpoint_projection_is_rebuilt_only_from_base_and_failure_atomic() {
        let (_genesis, proof, prepared, log) = checkpoint_proof_fixture();
        let proof_id = proof.proof_id().unwrap();
        let transition = VerifiedAdmissionCheckpointTransitionV1 {
            checkpoint: prepared.checkpoint.clone(),
            prior_committed_header: prepared.prior_committed_header,
            entry_ids: prepared.entry_ids.clone(),
            observed_ledger_height: prepared.observed_ledger_height,
            committing_ledger_height: prepared.committing_ledger_height,
            proof_id,
            next_checkpoint_accumulator: admission_checkpoint_accumulator_successor(
                empty_admission_checkpoint_accumulator(),
                0,
                prepared.checkpoint.checkpoint_id(),
                proof_id,
            )
            .unwrap(),
        };

        let mut projected = log.clone();
        projected
            .apply_replayed_main_wal_checkpoint_projection(&transition)
            .unwrap();
        assert_eq!(
            projected.committed_header(),
            transition.checkpoint.header_id
        );
        let mut replayed_after_restart = log.clone();
        replayed_after_restart
            .apply_replayed_main_wal_checkpoint_projection(&transition)
            .unwrap();
        assert_eq!(replayed_after_restart, projected);
        assert!(projected
            .apply_replayed_main_wal_checkpoint_projection(&transition)
            .is_err());

        let mut forged = transition.clone();
        forged.checkpoint.header_id = label("forged-main-wal-projection-head");
        let mut rejected = log.clone();
        let before = rejected.clone();
        assert!(rejected
            .apply_replayed_main_wal_checkpoint_projection(&forged)
            .is_err());
        assert_eq!(rejected, before);

        let mut missing_proof = transition;
        missing_proof.proof_id = AdmissionHash32::ZERO;
        assert!(rejected
            .apply_replayed_main_wal_checkpoint_projection(&missing_proof)
            .is_err());
        assert_eq!(rejected, before);
    }

    #[test]
    fn verified_checkpoint_transition_enters_bounded_ledger_state_failure_atomically() {
        let (genesis, proof, prepared, _) = checkpoint_proof_fixture();
        let expected_anchor = label("ledger-anchor");
        let transition = proof
            .verify_bounded(
                &genesis,
                AdmissionCommittedPositionV1 {
                    header_id: genesis.genesis_header,
                    admission_era: 0,
                    log_height: 0,
                    cumulative_work: AdmissionWork::ZERO,
                },
                0,
                empty_admission_checkpoint_accumulator(),
                &authenticated_proposal_context(&proof, 5),
                genesis.config.genesis_target,
                &BTreeMap::new(),
                |anchor| {
                    (anchor.block_id == expected_anchor && anchor.height == 1)
                        .then_some(())
                        .ok_or_else(|| {
                            AdmissionError::ParentOrPrestate(
                                "anchor is not in finalized local history".into(),
                            )
                        })
                },
                |entry| verify_admission_sidecar(entry, b"checkpoint-proof-entry"),
                |_header, _work, anchor| {
                    (anchor.block_id == expected_anchor)
                        .then_some(())
                        .ok_or_else(|| {
                            AdmissionError::ResourceOrAvailability(
                                "confirmation body is unavailable".into(),
                            )
                        })
                },
            )
            .unwrap();
        let initial_asset_root = label("checkpoint-ledger-initial-asset-root");
        let current_asset_root = label("checkpoint-ledger-current-asset-root");
        let mut state = LedgerAdmissionStateV1::new(genesis.clone(), initial_asset_root).unwrap();

        let mut forged_accumulator = transition.clone();
        forged_accumulator.next_checkpoint_accumulator = label("forged-checkpoint-accumulator");
        let pristine = state.clone();
        assert_eq!(
            state
                .apply_verified_checkpoint_transition(&forged_accumulator, current_asset_root,)
                .unwrap_err()
                .code(),
            "ERR_PARENT_OR_PRESTATE"
        );
        assert_eq!(state, pristine);

        let mut forged_epoch = transition.clone();
        forged_epoch.checkpoint.committed_ledger_epoch = 1;
        forged_epoch.next_checkpoint_accumulator = admission_checkpoint_accumulator_successor(
            state.checkpoint_accumulator,
            state.checkpoint_count,
            forged_epoch.checkpoint.checkpoint_id(),
            forged_epoch.proof_id,
        )
        .unwrap();
        assert_eq!(
            state
                .apply_verified_checkpoint_transition(&forged_epoch, current_asset_root)
                .unwrap_err()
                .code(),
            "ERR_PARENT_OR_PRESTATE"
        );
        assert_eq!(state, pristine);

        let mut zero_entry = transition.clone();
        zero_entry.entry_ids.push(AdmissionHash32::ZERO);
        assert_eq!(
            state
                .apply_verified_checkpoint_transition(&zero_entry, current_asset_root)
                .unwrap_err()
                .code(),
            "ERR_PARENT_OR_PRESTATE"
        );
        assert_eq!(state, pristine);

        let mut nonprogressing = transition.clone();
        nonprogressing.checkpoint.log_height = 0;
        nonprogressing.checkpoint.cumulative_work = AdmissionWork::ZERO;
        nonprogressing.next_checkpoint_accumulator = admission_checkpoint_accumulator_successor(
            state.checkpoint_accumulator,
            state.checkpoint_count,
            nonprogressing.checkpoint.checkpoint_id(),
            nonprogressing.proof_id,
        )
        .unwrap();
        assert_eq!(
            state
                .apply_verified_checkpoint_transition(&nonprogressing, current_asset_root)
                .unwrap_err()
                .code(),
            "ERR_PARENT_OR_PRESTATE"
        );
        assert_eq!(state, pristine);

        state
            .apply_verified_checkpoint_transition(&transition, current_asset_root)
            .unwrap();
        assert_eq!(state.committed_header, transition.checkpoint.header_id);
        assert_eq!(
            state.latest_checkpoint.as_ref(),
            Some(&transition.checkpoint)
        );
        assert_eq!(state.checkpoint_count, 1);
        assert_eq!(
            state.checkpoint_accumulator,
            transition.next_checkpoint_accumulator
        );
        assert_eq!(state.censorship_guard.last_ledger_epoch(), 2);
        assert_eq!(
            state.censorship_guard.last_value_eligible_asset_root(),
            current_asset_root
        );
        assert_eq!(
            state
                .censorship_guard
                .pending_entries()
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            prepared.entry_ids
        );
        assert!(state.censorship_guard.may_sign_consensus());
        state.validate_recovered().unwrap();

        let restored: LedgerAdmissionStateV1 =
            serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
        assert_eq!(restored, state);
        restored.validate_recovered().unwrap();

        let finalized = state.clone();
        assert_eq!(
            state
                .apply_verified_checkpoint_transition(&transition, current_asset_root)
                .unwrap_err()
                .code(),
            "ERR_PARENT_OR_PRESTATE"
        );
        assert_eq!(state, finalized);
    }

    #[test]
    fn bounded_checkpoint_proof_rejects_untrusted_prestate_work_and_external_facts() {
        let (genesis, proof, _, _) = checkpoint_proof_fixture();
        let verify = |candidate: &AdmissionCheckpointProofV1,
                      expected_accumulator: AdmissionHash32,
                      anchor_ok: bool,
                      entry_ok: bool,
                      confirmation_ok: bool| {
            candidate.verify_bounded(
                &genesis,
                AdmissionCommittedPositionV1 {
                    header_id: genesis.genesis_header,
                    admission_era: 0,
                    log_height: 0,
                    cumulative_work: AdmissionWork::ZERO,
                },
                0,
                expected_accumulator,
                &authenticated_proposal_context(candidate, 5),
                genesis.config.genesis_target,
                &BTreeMap::new(),
                |_anchor| {
                    anchor_ok.then_some(()).ok_or_else(|| {
                        AdmissionError::ParentOrPrestate("unknown finalized anchor".into())
                    })
                },
                |_entry| {
                    entry_ok.then_some(()).ok_or_else(|| {
                        AdmissionError::ResourceOrAvailability(
                            "entry ancestry or sidecar rejected".into(),
                        )
                    })
                },
                |_header, _work, _anchor| {
                    confirmation_ok.then_some(()).ok_or_else(|| {
                        AdmissionError::ResourceOrAvailability(
                            "confirmation header body rejected".into(),
                        )
                    })
                },
            )
        };

        let mut wrong_accumulator = proof.clone();
        wrong_accumulator.prior_checkpoint_accumulator = label("attacker accumulator");
        assert_eq!(
            verify(
                &wrong_accumulator,
                empty_admission_checkpoint_accumulator(),
                true,
                true,
                true,
            )
            .unwrap_err()
            .code(),
            "ERR_PARENT_OR_PRESTATE"
        );

        let mut shallow = proof.clone();
        shallow.confirmation_segment.pop();
        assert_eq!(
            verify(
                &shallow,
                empty_admission_checkpoint_accumulator(),
                true,
                true,
                true,
            )
            .unwrap_err()
            .code(),
            "ERR_WORK_OR_PROOF"
        );

        let mut broken_parent = proof.clone();
        broken_parent.confirmation_segment[0].header.parent_header = label("wrong parent");
        assert_eq!(
            verify(
                &broken_parent,
                empty_admission_checkpoint_accumulator(),
                true,
                true,
                true,
            )
            .unwrap_err()
            .code(),
            "ERR_PARENT_OR_PRESTATE"
        );

        let mut forged_work = proof.clone();
        forged_work.confirmation_segment[0].access_work.output_hash = label("forged work");
        assert_eq!(
            verify(
                &forged_work,
                empty_admission_checkpoint_accumulator(),
                true,
                true,
                true,
            )
            .unwrap_err()
            .code(),
            "ERR_WORK_OR_PROOF"
        );

        assert_eq!(
            verify(
                &proof,
                empty_admission_checkpoint_accumulator(),
                false,
                true,
                true,
            )
            .unwrap_err()
            .code(),
            "ERR_PARENT_OR_PRESTATE"
        );
        assert_eq!(
            verify(
                &proof,
                empty_admission_checkpoint_accumulator(),
                true,
                false,
                true,
            )
            .unwrap_err()
            .code(),
            "ERR_RESOURCE_OR_AVAILABILITY"
        );
        assert_eq!(
            verify(
                &proof,
                empty_admission_checkpoint_accumulator(),
                true,
                true,
                false,
            )
            .unwrap_err()
            .code(),
            "ERR_RESOURCE_OR_AVAILABILITY"
        );

        let mut unknown = serde_json::to_value(&proof).unwrap();
        unknown["prepared_checkpoint"] = serde_json::json!({});
        assert!(serde_json::from_value::<AdmissionCheckpointProofV1>(unknown).is_err());
    }

    #[test]
    fn checkpoint_proof_wire_is_hard_bounded_before_runtime_adoption() {
        let (_, proof, _, _) = checkpoint_proof_fixture();
        let mut oversized = proof.clone();
        oversized.batch_segment = vec![proof.batch_segment[0].clone(); 512];
        oversized.confirmation_segment =
            vec![proof.confirmation_segment[0].clone(); MAX_ADMISSION_CONFIRMATION_HEADERS];
        assert_eq!(
            oversized.canonical_bytes().unwrap_err().code(),
            "ERR_ENVELOPE_LIMIT"
        );
    }

    #[test]
    fn verified_header_ingress_derives_availability_from_exact_sidecar_bytes() {
        let genesis =
            AdmissionGenesisV1::new(context(), config(), label("verified-ingress-benchmark"))
                .unwrap();
        let mut log = PermissionlessAdmissionLogV1::new(
            genesis.context,
            genesis.config,
            genesis.genesis_header,
        )
        .unwrap();
        let identity = generate_identity();
        let entry = signed_entry(&identity, "verified-ingress-sidecar");
        let batch = make_batch(&log, genesis.genesis_header, vec![entry.clone()], 1, false);
        let initial = log.clone();
        let mut wrong = AdmissionVerifiedHeaderSubmissionV1 {
            entries: vec![AdmissionSidecarSubmissionV1 {
                entry: entry.clone(),
                payload: b"wrong-sidecar".to_vec(),
            }],
            access_work: batch.access_work.clone(),
            header: batch.header.clone(),
            ledger_anchor: batch.ledger_anchor.clone(),
        };
        assert_eq!(
            log.append_verified_header(wrong.clone())
                .unwrap_err()
                .code(),
            "ERR_RESOURCE_OR_AVAILABILITY"
        );
        assert_eq!(log, initial);

        wrong.entries[0].payload = b"verified-ingress-sidecar".to_vec();
        let header_id = log.append_verified_header(wrong).unwrap();
        assert_eq!(header_id, batch.header.header_id());
        log.validate_recovered().unwrap();
    }

    #[test]
    fn rust_matches_independent_python_checkpoint_proof_bytes_and_rejections() {
        let vector_bytes =
            include_bytes!("../../../vectors/admission-checkpoint-proof-v1/vectors.json");
        let pinned =
            include_str!("../../../vectors/admission-checkpoint-proof-v1/vectors.json.sha256")
                .split_whitespace()
                .next()
                .unwrap();
        assert_eq!(hex::encode(Sha256::digest(vector_bytes)), pinned);
        let document: Value = serde_json::from_slice(vector_bytes).unwrap();
        let payload = &document["payload"];
        assert_eq!(
            payload["status"],
            "CODEC_AND_BOUNDED_PROOF_ONLY_RUNTIME_TAG28_DISABLED_VALUE_CAP_0"
        );
        assert_eq!(payload["claims"]["runtime_tag28"], false);
        assert_eq!(
            payload["claims"]["caller_prepared_checkpoint_trusted"],
            false
        );
        assert_eq!(
            payload["claims"]["checkpoint_epochs_derived_from_signed_height_mapping"],
            true
        );
        assert_eq!(
            payload["claims"]["sidecar_content_addressed_and_locally_verified"],
            true
        );

        let mut genesis_json = payload["genesis"].clone();
        let empty_accumulator =
            AdmissionHash32::from_hex(genesis_json["empty_accumulator"].as_str().unwrap()).unwrap();
        genesis_json
            .as_object_mut()
            .unwrap()
            .remove("empty_accumulator");
        let genesis: AdmissionGenesisV1 = serde_json::from_value(genesis_json).unwrap();
        let proof: AdmissionCheckpointProofV1 =
            serde_json::from_value(payload["proof"].clone()).unwrap();
        assert_eq!(
            hex::encode(proof.canonical_bytes().unwrap()),
            payload["canonical_proof_wire_hex"]
        );
        assert_eq!(proof.proof_id().unwrap().to_hex(), payload["proof_id"]);
        let canonical_proof_wire = hex::decode(
            payload["canonical_proof_wire_hex"]
                .as_str()
                .expect("frozen proof wire"),
        )
        .unwrap();
        let decoded = AdmissionCheckpointProofV1::from_canonical_bytes(&canonical_proof_wire)
            .expect("production decoder accepts the independent canonical wire");
        assert_eq!(decoded, proof);
        assert_eq!(decoded.canonical_bytes().unwrap(), canonical_proof_wire);
        assert_eq!(
            hex::encode(
                crate::command_wire::encode_admission_checkpoint_candidate_payload_v1(&proof)
                    .unwrap()
            ),
            payload["canonical_payload_hex"]
        );
        assert_eq!(
            hex::encode(
                crate::command_wire::encode_admission_checkpoint_candidate_command_v1(
                    &genesis.context.network_domain,
                    &proof,
                )
                .unwrap()
            ),
            payload["canonical_command_wire_hex"]
        );
        assert_eq!(
            crate::command_wire::admission_checkpoint_candidate_command_hash_v1(
                &genesis.context.network_domain,
                &proof,
            )
            .unwrap(),
            payload["command_hash"]
        );
        let formal_command =
            crate::ConsensusCommand::CommitAdmissionCheckpoint(Box::new(proof.clone()));
        assert_eq!(formal_command.wire_v1_tag(), 28);
        assert_eq!(
            hex::encode(formal_command.wire_v1_command_payload_bytes().unwrap()),
            payload["canonical_payload_hex"]
        );
        assert_eq!(
            hex::encode(
                formal_command
                    .wire_v1_command_bytes(&genesis.context.network_domain)
                    .unwrap()
            ),
            payload["canonical_command_wire_hex"]
        );
        assert_eq!(
            formal_command
                .wire_v1_command_hash(&genesis.context.network_domain)
                .unwrap(),
            payload["command_hash"]
        );
        let decoded: crate::ConsensusCommand =
            serde_json::from_slice(&serde_json::to_vec(&formal_command).unwrap()).unwrap();
        assert_eq!(decoded, formal_command);
        let sidecars = payload["available_sidecars_hex"].as_object().unwrap();
        assert_eq!(sidecars.len(), 1);
        let available_sidecar = hex::decode(sidecars.values().next().unwrap().as_str().unwrap())
            .expect("frozen sidecar is hexadecimal");
        let committing_ledger_height =
            payload["committing_ledger_height"].as_u64().unwrap() as u128;

        let verify = |candidate: &AdmissionCheckpointProofV1,
                      candidate_genesis: &AdmissionGenesisV1,
                      candidate_committing_ledger_height: u128,
                      anchor_ok: bool,
                      entry_ok: bool,
                      confirmation_ok: bool| {
            candidate.verify_bounded(
                candidate_genesis,
                AdmissionCommittedPositionV1 {
                    header_id: candidate_genesis.genesis_header,
                    admission_era: 0,
                    log_height: 0,
                    cumulative_work: AdmissionWork::ZERO,
                },
                0,
                empty_accumulator,
                &authenticated_proposal_context(candidate, candidate_committing_ledger_height),
                candidate_genesis.config.genesis_target,
                &BTreeMap::new(),
                |_anchor| {
                    anchor_ok.then_some(()).ok_or_else(|| {
                        AdmissionError::ParentOrPrestate("unknown finalized anchor".into())
                    })
                },
                |entry| {
                    if entry_ok {
                        verify_admission_sidecar(entry, &available_sidecar)
                    } else {
                        Err(AdmissionError::ResourceOrAvailability(
                            "entry unavailable or content-mismatched".into(),
                        ))
                    }
                },
                |_header, _work, _anchor| {
                    confirmation_ok.then_some(()).ok_or_else(|| {
                        AdmissionError::ResourceOrAvailability("confirmation unavailable".into())
                    })
                },
            )
        };
        let accepted =
            verify(&proof, &genesis, committing_ledger_height, true, true, true).unwrap();
        assert_eq!(
            serde_json::to_value(&accepted.checkpoint).unwrap(),
            payload["expected_transition"]["checkpoint"]
        );
        assert_eq!(
            accepted.checkpoint.checkpoint_id().to_hex(),
            payload["expected_transition"]["checkpoint_id"]
        );
        assert_eq!(
            accepted.proof_id.to_hex(),
            payload["expected_transition"]["proof_id"]
        );
        assert_eq!(
            accepted.next_checkpoint_accumulator.to_hex(),
            payload["expected_transition"]["next_checkpoint_accumulator"]
        );
        assert_eq!(
            accepted.observed_ledger_height.to_string(),
            payload["expected_transition"]["observed_ledger_height"].to_string()
        );
        assert_eq!(
            accepted.committing_ledger_height.to_string(),
            payload["expected_transition"]["committing_ledger_height"].to_string()
        );

        for case in payload["cases"].as_array().unwrap() {
            let mutation = case["mutation"].as_str().unwrap();
            if mutation == "accept" {
                assert!(case["expected_accept"].as_bool().unwrap());
                continue;
            }
            let mut candidate = proof.clone();
            let mut anchor_ok = true;
            let mut entry_ok = true;
            let mut confirmation_ok = true;
            let mut candidate_genesis = genesis.clone();
            let mut candidate_committing_ledger_height = committing_ledger_height;
            match mutation {
                "wrong_accumulator" => {
                    candidate.prior_checkpoint_accumulator = label("wrong-accumulator")
                }
                "shallow_confirmation" => {
                    candidate.confirmation_segment.pop();
                }
                "broken_parent" => {
                    candidate.confirmation_segment[0].header.parent_header = label("wrong-parent")
                }
                "forged_work" => {
                    candidate.confirmation_segment[0].access_work.output_hash = label("forged-work")
                }
                "unknown_anchor" => anchor_ok = false,
                "entry_unavailable" | "sidecar_content_mismatch" => entry_ok = false,
                "confirmation_unavailable" => confirmation_ok = false,
                "nonmaximal_prefix" => {
                    let second = candidate.batch_segment.pop().unwrap();
                    candidate.confirmation_segment.insert(
                        0,
                        AdmissionCheckpointConfirmationProofV1 {
                            access_work: second.access_work,
                            header: second.header,
                            ledger_anchor: second.ledger_anchor,
                        },
                    );
                }
                "duplicate_entry" => {
                    let duplicate = candidate.batch_segment[0].entries[0].clone();
                    candidate.batch_segment[0].entries.push(duplicate);
                }
                "aggregate_sidecar_limit" => {
                    let source = candidate.batch_segment[0].entries[0].clone();
                    candidate.batch_segment[0].entries = (0..9)
                        .map(|index| {
                            let mut entry = source.clone();
                            entry.payload_commitment = label(&format!("aggregate-sidecar-{index}"));
                            entry.declared_bytes = MAX_ADMISSION_SIDECAR_BYTES;
                            entry
                        })
                        .collect();
                }
                "commit_before_observed_anchor" => {
                    candidate_committing_ledger_height = 511;
                }
                "epoch_lag_exceeded" => {
                    candidate_committing_ledger_height = 704;
                }
                "zero_epoch_span" => {
                    candidate_genesis
                        .config
                        .contribution_epoch_mapping
                        .ledger_blocks_per_contribution_epoch = 0;
                }
                "uncommitted_epoch_mapping" => {
                    candidate_genesis
                        .config
                        .contribution_epoch_mapping
                        .ledger_blocks_per_contribution_epoch = 65;
                }
                other => panic!("unknown independent proof mutation {other}"),
            }
            let error = verify(
                &candidate,
                &candidate_genesis,
                candidate_committing_ledger_height,
                anchor_ok,
                entry_ok,
                confirmation_ok,
            )
            .unwrap_err();
            assert_eq!(
                error.code(),
                case["expected_first_error"].as_str().unwrap(),
                "{}",
                case["case_id"]
            );
        }
    }

    #[test]
    fn checkpoint_proof_decoder_bounds_nested_counts_before_allocation_and_rejects_framing() {
        let document: Value = serde_json::from_slice(include_bytes!(
            "../../../vectors/admission-checkpoint-proof-v1/vectors.json"
        ))
        .unwrap();
        let mut wire = hex::decode(
            document["payload"]["canonical_proof_wire_hex"]
                .as_str()
                .unwrap(),
        )
        .unwrap();

        let mut trailing = wire.clone();
        trailing.push(0);
        assert_eq!(
            AdmissionCheckpointProofV1::from_canonical_bytes(&trailing)
                .unwrap_err()
                .code(),
            "ERR_NON_CANONICAL_WIRE"
        );

        let batch_domain = wire
            .windows(CHECKPOINT_BATCH_SEGMENT_DOMAIN.len())
            .position(|window| window == CHECKPOINT_BATCH_SEGMENT_DOMAIN)
            .expect("batch segment domain");
        let batch_count = batch_domain + CHECKPOINT_BATCH_SEGMENT_DOMAIN.len();
        wire[batch_count..batch_count + 2].copy_from_slice(&513u16.to_be_bytes());
        assert_eq!(
            AdmissionCheckpointProofV1::from_canonical_bytes(&wire)
                .unwrap_err()
                .code(),
            "ERR_ENVELOPE_LIMIT"
        );

        let mut wire = hex::decode(
            document["payload"]["canonical_proof_wire_hex"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let confirmation_domain = wire
            .windows(CHECKPOINT_CONFIRMATION_SEGMENT_DOMAIN.len())
            .position(|window| window == CHECKPOINT_CONFIRMATION_SEGMENT_DOMAIN)
            .expect("confirmation segment domain");
        let confirmation_count = confirmation_domain + CHECKPOINT_CONFIRMATION_SEGMENT_DOMAIN.len();
        wire[confirmation_count..confirmation_count + 2].copy_from_slice(&513u16.to_be_bytes());
        assert_eq!(
            AdmissionCheckpointProofV1::from_canonical_bytes(&wire)
                .unwrap_err()
                .code(),
            "ERR_ENVELOPE_LIMIT"
        );

        let oversized = vec![0; MAX_ADMISSION_CHECKPOINT_PROOF_WIRE_BYTES + 1];
        assert_eq!(
            AdmissionCheckpointProofV1::from_canonical_bytes(&oversized)
                .unwrap_err()
                .code(),
            "ERR_ENVELOPE_LIMIT"
        );
    }

    #[test]
    fn runtime_codec_matches_the_first_three_frozen_object_vectors() {
        let bundle: Value = serde_json::from_str(include_str!(
            "../../../vectors/open-contribution-v1/vectors.json"
        ))
        .unwrap();
        let objects = bundle["payload"]["object_vectors"].as_array().unwrap();
        let find = |schema: &str| {
            objects
                .iter()
                .find(|object| object["schema"] == schema)
                .unwrap()
        };
        let parse_context = |source: &Value| AdmissionContextV1 {
            network_domain: source["network_domain"].as_str().unwrap().into(),
            zone_id: source["zone_id"].as_str().unwrap().into(),
            currency_genesis: AdmissionHash32::from_hex(
                source["currency_genesis"].as_str().unwrap(),
            )
            .unwrap(),
            protocol_era: source["protocol_era"].as_str().unwrap().parse().unwrap(),
            crypto_era: source["crypto_era"].as_str().unwrap().parse().unwrap(),
        };

        let work_vector = find("BaselineAccessWorkV1");
        let source = &work_vector["source"];
        let work = BaselineAccessWorkV1 {
            context: parse_context(source),
            parent_header: AdmissionHash32::from_hex(source["parent_header"].as_str().unwrap())
                .unwrap(),
            ledger_anchor_block: AdmissionHash32::from_hex(
                source["ledger_anchor_block"].as_str().unwrap(),
            )
            .unwrap(),
            ledger_anchor_height: source["ledger_anchor_height"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
            entries_root: AdmissionHash32::from_hex(source["entries_root"].as_str().unwrap())
                .unwrap(),
            entries_count: source["entries_count"].as_str().unwrap().parse().unwrap(),
            suite_id: source["suite_id"].as_str().unwrap().parse().unwrap(),
            target: AdmissionWork::from_hex(source["target"].as_str().unwrap()).unwrap(),
            nonce: source["nonce"].as_str().unwrap().parse().unwrap(),
            output_hash: AdmissionHash32::from_hex(source["output_hash"].as_str().unwrap())
                .unwrap(),
            expiry_anchor_height: source["expiry_anchor_height"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
        };
        assert_eq!(work.output_hash, work.recompute_output_hash());
        assert_eq!(hex::encode(work.canonical_bytes()), work_vector["wire_hex"]);
        assert_eq!(work.work_id().to_hex(), work_vector["subject_id"]);

        let entry_vector = find("PermissionlessAdmissionEntryV1");
        let source = &entry_vector["source"];
        let signature: [u8; 64] = hex::decode(source["entry_signature"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let entry = PermissionlessAdmissionEntryV1 {
            context: parse_context(source),
            kind: AdmissionEntryKindV1::Participation,
            participant_key: AdmissionHash32::from_hex(source["participant_key"].as_str().unwrap())
                .unwrap(),
            owner_commitment: AdmissionHash32::from_hex(
                source["owner_commitment"].as_str().unwrap(),
            )
            .unwrap(),
            program_id: AdmissionHash32::from_hex(source["program_id"].as_str().unwrap()).unwrap(),
            challenge_id: None,
            payload_commitment: AdmissionHash32::from_hex(
                source["payload_commitment"].as_str().unwrap(),
            )
            .unwrap(),
            locator_commitment: AdmissionHash32::from_hex(
                source["locator_commitment"].as_str().unwrap(),
            )
            .unwrap(),
            declared_bytes: source["declared_bytes"].as_str().unwrap().parse().unwrap(),
            expiry_height: source["expiry_height"].as_str().unwrap().parse().unwrap(),
            entry_signature: AdmissionSignature64(signature),
        };
        assert_eq!(
            hex::encode(entry.canonical_bytes()),
            entry_vector["wire_hex"]
        );
        assert_eq!(entry.entry_id().to_hex(), entry_vector["subject_id"]);
        assert_eq!(
            entry.signing_subject().to_hex(),
            entry_vector["signing_subject"]
        );
        entry.validate(&entry.context, 100).unwrap();

        let header_vector = find("PermissionlessAdmissionHeaderV1");
        let source = &header_vector["source"];
        let header = PermissionlessAdmissionHeaderV1 {
            context: parse_context(source),
            admission_era: source["admission_era"].as_str().unwrap().parse().unwrap(),
            log_height: source["log_height"].as_str().unwrap().parse().unwrap(),
            parent_header: AdmissionHash32::from_hex(source["parent_header"].as_str().unwrap())
                .unwrap(),
            ledger_anchor_block: AdmissionHash32::from_hex(
                source["ledger_anchor_block"].as_str().unwrap(),
            )
            .unwrap(),
            access_work_id: AdmissionHash32::from_hex(source["access_work_id"].as_str().unwrap())
                .unwrap(),
            entries_root: AdmissionHash32::from_hex(source["entries_root"].as_str().unwrap())
                .unwrap(),
            entries_count: source["entries_count"].as_str().unwrap().parse().unwrap(),
            cumulative_work: AdmissionWork::from_hex(source["cumulative_work"].as_str().unwrap())
                .unwrap(),
            prior_era_terminal: None,
        };
        assert_eq!(
            hex::encode(header.canonical_bytes()),
            header_vector["wire_hex"]
        );
        assert_eq!(header.header_id().to_hex(), header_vector["subject_id"]);
    }

    #[test]
    fn u256_work_and_delayed_target_adjustment_are_exact() {
        assert_eq!(header_work(AdmissionWork::MAX), AdmissionWork::ZERO);
        assert_eq!(header_work(AdmissionWork::ZERO), AdmissionWork::MAX);
        assert_eq!(
            header_work(work_u64(1)),
            AdmissionWork::from_hex(
                "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            )
            .unwrap()
        );
        let minimum = work_u64(100);
        let maximum = work_u64(10_000);
        assert_eq!(
            adjusted_admission_target(work_u64(1000), [64; 4], minimum, maximum).unwrap(),
            work_u64(1000)
        );
        assert_eq!(
            adjusted_admission_target(work_u64(1000), [1; 4], minimum, maximum).unwrap(),
            work_u64(4000)
        );
        assert_eq!(
            adjusted_admission_target(work_u64(1000), [256; 4], minimum, maximum).unwrap(),
            work_u64(250)
        );
        let mut zero_work_config = config();
        zero_work_config.maximum_target = AdmissionWork::MAX;
        assert_eq!(
            zero_work_config.validate().unwrap_err().code(),
            "ERR_CONTEXT_MISMATCH"
        );
    }

    #[test]
    fn admission_log_confirms_only_complete_available_bounded_prefixes() {
        let genesis = label("admission-genesis");
        let mut log = PermissionlessAdmissionLogV1::new(context(), config(), genesis).unwrap();
        let identity = generate_identity();
        let first_entry = signed_entry(&identity, "first-payload");
        let mut parent = genesis;
        for height in 1..=33u128 {
            let entries = if height == 1 {
                vec![first_entry.clone()]
            } else {
                Vec::new()
            };
            let batch = make_batch(&log, parent, entries, height, true);
            parent = log.append_header(batch).unwrap();
        }
        let prepared = log.build_confirmed_checkpoint(5).unwrap();
        assert_eq!(prepared.checkpoint.log_height, 1);
        assert_eq!(prepared.checkpoint.confirmations, 32);
        assert_eq!(prepared.checkpoint.descendant_work, work_u64(32));
        assert_eq!(prepared.entry_ids, vec![first_entry.entry_id()]);
        let expected_availability = admission_availability_root(&[AdmissionAvailableEntryV1 {
            entry_id: first_entry.entry_id(),
            locator_commitment: first_entry.locator_commitment,
            declared_bytes: first_entry.declared_bytes,
        }])
        .unwrap();
        assert_eq!(prepared.checkpoint.availability_root, expected_availability);
        log.apply_finalized_checkpoint(&prepared).unwrap();
        assert_eq!(log.committed_header(), prepared.checkpoint.header_id);
        log.validate_recovered().unwrap();

        let encoded = serde_json::to_vec(&log).unwrap();
        let restored: PermissionlessAdmissionLogV1 = serde_json::from_slice(&encoded).unwrap();
        restored.validate_recovered().unwrap();
        assert!(!String::from_utf8_lossy(&encoded).contains("amount"));
        assert!(!String::from_utf8_lossy(&encoded).contains("reward"));
        assert!(!String::from_utf8_lossy(&encoded).contains("stake"));

        let mut tampered = restored;
        tampered
            .headers
            .get_mut(&tampered.canonical_tip)
            .unwrap()
            .header_work = AdmissionWork::MAX;
        assert!(tampered.validate_recovered().is_err());
    }

    #[test]
    fn competing_forks_may_repeat_an_entry_but_one_ancestry_may_not() {
        let genesis = label("fork-genesis");
        let mut log = PermissionlessAdmissionLogV1::new(context(), config(), genesis).unwrap();
        let identity = generate_identity();
        let entry = signed_entry(&identity, "fork-entry");
        let first = log
            .append_header(make_batch(&log, genesis, vec![entry.clone()], 1, true))
            .unwrap();
        let competing = log
            .append_header(make_batch(&log, genesis, vec![entry.clone()], 1000, true))
            .unwrap();
        assert_eq!(log.canonical_tip(), first.min(competing));
        let duplicate = make_batch(&log, first, vec![entry], 2000, true);
        assert_eq!(
            log.append_header(duplicate).unwrap_err().code(),
            "ERR_DUPLICATE_OR_NULLIFIER"
        );

        let mut weaker_tip = log.clone();
        weaker_tip.canonical_tip = first.max(competing);
        assert_eq!(
            weaker_tip.validate_recovered().unwrap_err().code(),
            "ERR_PARENT_OR_PRESTATE"
        );

        let mut alternate_root = log.clone();
        alternate_root.headers.insert(
            label("forged-alternate-root"),
            StoredAdmissionHeaderV1 {
                header: None,
                access_work: None,
                entries: Vec::new(),
                header_work: AdmissionWork::ZERO,
                entry_ids: Vec::new(),
                available_entries: Vec::new(),
                all_available: true,
            },
        );
        assert_eq!(
            alternate_root.validate_recovered().unwrap_err().code(),
            "ERR_PARENT_OR_PRESTATE"
        );
    }

    #[test]
    fn unavailable_confirmed_data_fails_before_checkpoint_creation() {
        let genesis = label("unavailable-genesis");
        let mut log = PermissionlessAdmissionLogV1::new(context(), config(), genesis).unwrap();
        let identity = generate_identity();
        let first_entry = signed_entry(&identity, "unavailable-entry");
        let mut parent = genesis;
        for height in 1..=33u128 {
            let entries = if height == 1 {
                vec![first_entry.clone()]
            } else {
                Vec::new()
            };
            let batch = make_batch(&log, parent, entries, height, height != 1);
            parent = log.append_header(batch).unwrap();
        }
        assert_eq!(
            log.build_confirmed_checkpoint(5).unwrap_err().code(),
            "ERR_RESOURCE_OR_AVAILABILITY"
        );
    }

    #[test]
    fn censorship_stall_is_deterministic_fail_closed_and_not_admin_clearable() {
        let root5 = label("asset-root-5");
        let root6 = label("asset-root-6");
        let root7 = label("asset-root-7");
        let root8 = label("asset-root-8");
        let root9 = label("asset-root-9");
        let root10 = label("asset-root-10");
        let entry = label("omitted-entry");
        let prepared = PreparedAdmissionCheckpointV1 {
            checkpoint: AdmissionCheckpointV1 {
                context: context(),
                admission_era: 0,
                header_id: label("confirmed-header"),
                log_height: 64,
                cumulative_work: work_u64(64),
                confirmations: 32,
                descendant_work: work_u64(32),
                entries_root: admission_entry_root([entry]).unwrap(),
                availability_root: label("availability-root"),
                observed_ledger_epoch: 5,
                committed_ledger_epoch: 7,
            },
            prior_committed_header: label("prior-committed-header"),
            entry_ids: vec![entry],
            observed_ledger_height: 10,
            committing_ledger_height: 14,
        };
        let checkpoint = prepared.checkpoint.checkpoint_id();
        let mut guard = AdmissionCensorshipGuardV1::new(context(), 5, root5).unwrap();
        guard.observe_confirmed_prefix(5, &prepared, root5).unwrap();
        guard.advance_epoch(6, root6).unwrap();
        guard.advance_epoch(7, root7).unwrap();
        assert_eq!(guard.status(), AdmissionCensorshipStatusV1::Healthy);
        guard.advance_epoch(8, root8).unwrap();
        assert_eq!(
            guard.status(),
            AdmissionCensorshipStatusV1::CensorshipStalled
        );
        assert!(!guard.may_sign_consensus());
        assert!(!guard.may_accept_value_eligible_finality());
        assert!(!guard.may_raise_value_cap());
        assert_eq!(guard.last_value_eligible_asset_root(), root7);
        assert_eq!(guard.history().len(), 1);

        let before_wrong_checkpoint = guard.clone();
        assert_eq!(
            guard
                .record_ledger_resolution(
                    &AdmissionLedgerResolutionV1 {
                        ledger_epoch: 8,
                        checkpoint_id: label("unrelated-checkpoint"),
                        included_entries: BTreeSet::from([entry]),
                        rejection_proofs: BTreeMap::new(),
                    },
                    root8,
                )
                .unwrap_err()
                .code(),
            "ERR_PARENT_OR_PRESTATE"
        );
        assert_eq!(guard, before_wrong_checkpoint);

        guard
            .record_ledger_resolution(
                &AdmissionLedgerResolutionV1 {
                    ledger_epoch: 8,
                    checkpoint_id: checkpoint,
                    included_entries: BTreeSet::from([entry]),
                    rejection_proofs: BTreeMap::new(),
                },
                root8,
            )
            .unwrap();
        assert_eq!(
            guard.status(),
            AdmissionCensorshipStatusV1::RecoveryChallenge
        );
        assert!(!guard.may_sign_consensus());
        guard.advance_epoch(9, root9).unwrap();
        assert_eq!(
            guard.status(),
            AdmissionCensorshipStatusV1::RecoveryChallenge
        );
        assert!(!guard.may_sign_consensus());
        guard.advance_epoch(10, root10).unwrap();
        assert_eq!(guard.status(), AdmissionCensorshipStatusV1::Healthy);
        assert!(guard.may_sign_consensus());
        assert_eq!(guard.last_value_eligible_asset_root(), root10);
        assert_eq!(guard.history().len(), 3);
        guard.validate_recovered().unwrap();

        let mut tampered = guard.clone();
        tampered.history[0].event_hash = AdmissionHash32::ZERO;
        assert_eq!(
            tampered.validate_recovered().unwrap_err().code(),
            "ERR_PARENT_OR_PRESTATE"
        );

        let mut impossible_history = guard.clone();
        impossible_history.history[0].kind = AdmissionCensorshipEventKindV1::RecoveryStarted;
        let mut prior = AdmissionHash32::ZERO;
        for event in &mut impossible_history.history {
            event.prior_event_hash = prior;
            event.event_hash = event.expected_hash();
            prior = event.event_hash;
        }
        assert_eq!(
            impossible_history.validate_recovered().unwrap_err().code(),
            "ERR_PARENT_OR_PRESTATE"
        );

        let mut hidden_overdue = before_wrong_checkpoint;
        hidden_overdue.status = AdmissionCensorshipStatusV1::Healthy;
        hidden_overdue.stalled_scope.clear();
        hidden_overdue.history.clear();
        assert_eq!(
            hidden_overdue.validate_recovered().unwrap_err().code(),
            "ERR_PARENT_OR_PRESTATE"
        );
    }
}
